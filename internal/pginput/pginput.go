// Package pginput — вход сборщика «PostgreSQL»: до-образы строк, которые
// меняют наблюдаемые роли (ИИ-агенты), прямо из журнала базы.
//
// Вход читает журнал через логическую репликацию (встроенный плагин pgoutput),
// internal/pgtap превращает транзакции в сжатые записи, и они сразу ложатся в
// буфер сборщика — без промежуточного файла и второй программы. Дальше их везёт
// та же доставка, что и строки файлов: номера, обещания хранилища, пульс.
//
// ПОДТВЕРЖДЕНИЕ БАЗЕ. Позицию в журнале вход подтверждает базе только после
// того, как транзакция легла в буфер сборщика на диск (fsync). Пока хранилище
// недоступно, записи ждут в буфере сборщика, а база свой журнал не копит.
// Пока стоит сам сборщик, база держит журнал для слота, но не дольше
// max_slot_wal_keep_size.
//
// ОБРЫВ СВЯЗИ — не остановка: вход говорит об этом в журнал, закрывает
// соединения и пробует снова с растущей паузой; сборщик тем временем шлёт
// накопленное и пульс. Транзакцию, оборванную посередине, база присылает
// заново целиком.
//
// ПОТЕРЯ. Если база стёрла журнал, который слот не успел прочитать (сборщик
// стоял дольше, чем позволяет max_slot_wal_keep_size), или слот удалили,
// изменения за это время не вернуть. Вход не молчит: сборщик пропускает номер
// записи, хранилище записывает в цепь пропуск, слот заводится заново, и чтение
// идёт дальше.
//
// ТРЕВОГИ. Поводы по транзакциям находит internal/pgtap; вход добавляет свои,
// служебные: связи с базой нет дольше down_after, связь вернулась, записи
// потеряны. Все они ложатся в alerts.jsonl, а оттуда, если в настройках есть
// "notify", уходят человеку (internal/alert): в Telegram, в Slack-совместимый
// веб-хук или на свой адрес.
//
// ОТСТАВАНИЕ СЛОТА. Слот теряется не вдруг: сначала база копит для него
// журнал. Вход раз в slotEvery спрашивает у базы, сколько журнала она держит
// для слота и сколько ей позволено (max_slot_wal_keep_size), и поднимает
// тревогу slot-lag на половине предела и снова на 80 %, а slot-ok — когда
// журнал отпущен. Причина бывает и при исправном сборщике: долгая открытая
// транзакция в базе не даёт слоту отпустить журнал. Те же числа — в
// показателях сборщика (Metrics). Упавший сборщик о себе не скажет: о нём
// говорит хранилище (источник замолчал).
package pginput

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"time"

	"github.com/Nikolay1994Kaz/evidencestore/internal/alert"
	"github.com/Nikolay1994Kaz/evidencestore/internal/config"
	"github.com/Nikolay1994Kaz/evidencestore/internal/input"
	"github.com/Nikolay1994Kaz/evidencestore/internal/metrics"
	"github.com/Nikolay1994Kaz/evidencestore/internal/pgoutput"
	"github.com/Nikolay1994Kaz/evidencestore/internal/pgtap"
	"github.com/Nikolay1994Kaz/evidencestore/internal/pgwire"
)

// Config — раздел "postgres" настроек сборщика.
type Config struct {
	// DSN — подключение к базе ролью с правом REPLICATION:
	// "host=db port=5432 user=evidence_tap dbname=shop sslmode=verify-full".
	// Пароль — здесь или в PGPASSWORD.
	DSN         string `json:"dsn"`
	Slot        string `json:"slot"`        // слот репликации; по умолчанию evidence_tap
	Publication string `json:"publication"` // публикация; по умолчанию evidence_pub
	// Dir — каталог справочника: index.jsonl (какая транзакция под какими
	// номерами записей), alerts.jsonl (тревоги), slot.json. По умолчанию —
	// spool_dir сборщика. Справочник читают esundo и esmcp.
	Dir string `json:"dir"`
	// Roles — роли агентов: их транзакции идут в хранилище. Tables — таблицы
	// ("schema.table"), которые агентам разрешено менять: по ним -setup-sql
	// выдаёт права, ставит триггер отметки и собирает публикацию.
	Roles  []string `json:"roles"`
	Tables []string `json:"tables"`
	// AlertRows — тревога «массовое изменение» от стольких изменений строк в
	// одной транзакции; 0 — не следить.
	AlertRows int `json:"alert_rows"`
	// RequireAction — тревога, если транзакция агента пришла без отметки
	// действия, то есть в обход MCP-сервера.
	RequireAction bool           `json:"require_action"`
	Canaries      []pgtap.Canary `json:"canaries"`
	// StatusEvery — как часто сообщать базе подтверждённую позицию, когда
	// изменений нет. По умолчанию 5s; должно быть меньше wal_sender_timeout (60 с).
	StatusEvery config.Duration `json:"status_every"`
	// DownAfter — связи с базой нет дольше этого — тревога db-down (и db-up,
	// когда связь вернётся). По умолчанию 1m.
	DownAfter config.Duration `json:"down_after"`
	// SlotAlertMB — тревога slot-lag, когда база держит для слота столько
	// мегабайт журнала, — в дополнение к долям предела базы (50 % и 80 % от
	// max_slot_wal_keep_size), которые проверяются всегда. Нужна, когда предел
	// в базе не задан или велик. 0 — только доли предела.
	SlotAlertMB int `json:"slot_alert_mb"`
	// Notify — кому нести тревоги. Нет раздела — тревоги только в alerts.jsonl
	// и в журнале сборщика.
	Notify *Notify `json:"notify"`
}

// Notify — раздел "notify": получатели тревог.
type Notify struct {
	// To — получатели: {"type": "telegram", "token": "…", "chat": "…"},
	// {"type": "slack", "url": "…"} (и совместимые веб-хуки), {"type": "json",
	// "url": "…"}. У каждого своя очередь: недоступность одного не держит
	// остальных.
	To []alert.Target `json:"to"`
	// UndoHint — команда в тексте тревоги, которой оператор смотрит откат
	// транзакции; {xid} заменяется её номером. По умолчанию
	// "esundo check -config undo.json -xid {xid}".
	UndoHint string `json:"undo_hint"`
}

// DefaultUndoHint — команда отката в тексте тревоги, если не задана своя.
const DefaultUndoHint = "esundo check -config undo.json -xid {xid}"

// Validate ставит умолчания и проверяет настройки.
func (c *Config) Validate() error {
	if c.Slot == "" {
		c.Slot = "evidence_tap"
	}
	if c.Publication == "" {
		c.Publication = "evidence_pub"
	}
	if c.StatusEvery == 0 {
		c.StatusEvery = config.Duration(5 * time.Second)
	}
	var errs []error
	if c.DSN == "" {
		errs = append(errs, errors.New("postgres.dsn is required"))
	} else if _, err := pgwire.ParseDSN(c.DSN); err != nil {
		errs = append(errs, fmt.Errorf("postgres.dsn: %w", err))
	}
	if len(c.Roles) == 0 {
		errs = append(errs, errors.New("postgres.roles: name at least one agent role"))
	}
	if len(c.Tables) == 0 {
		errs = append(errs, errors.New("postgres.tables: name at least one table"))
	}
	for _, t := range c.Tables {
		if _, _, err := splitTable(t); err != nil {
			errs = append(errs, err)
		}
	}
	if d := c.StatusEvery.D(); d < time.Second || d > 30*time.Second {
		errs = append(errs, fmt.Errorf("postgres.status_every %v: from 1s to 30s (the server drops a silent client after wal_sender_timeout)", d))
	}
	if c.AlertRows < 0 {
		errs = append(errs, fmt.Errorf("postgres.alert_rows %d: must not be negative", c.AlertRows))
	}
	if c.DownAfter == 0 {
		c.DownAfter = config.Duration(time.Minute)
	}
	if c.DownAfter.D() < time.Second {
		errs = append(errs, fmt.Errorf("postgres.down_after %v: a second at least", c.DownAfter.D()))
	}
	if c.SlotAlertMB < 0 {
		errs = append(errs, fmt.Errorf("postgres.slot_alert_mb %d: must not be negative", c.SlotAlertMB))
	}
	if n := c.Notify; n != nil {
		if n.UndoHint == "" {
			n.UndoHint = DefaultUndoHint
		}
		if !strings.Contains(n.UndoHint, "{xid}") {
			errs = append(errs, errors.New("postgres.notify.undo_hint: write {xid} where the transaction number goes"))
		}
		if len(n.To) == 0 {
			errs = append(errs, errors.New("postgres.notify.to: name at least one target"))
		}
		if err := alert.ValidateTargets(n.To); err != nil {
			errs = append(errs, fmt.Errorf("postgres.notify: %w", err))
		}
	}
	return errors.Join(errs...)
}

func splitTable(t string) (schema, table string, err error) {
	schema, table, ok := strings.Cut(t, ".")
	if !ok || schema == "" || table == "" || strings.Contains(table, ".") {
		return "", "", fmt.Errorf("postgres.tables: %q: write it as schema.table", t)
	}
	return schema, table, nil
}

// SetupSQL — настройка базы под запись до-образов (escollect -setup-sql).
// Скрипт не исполняется сборщиком: его читает и запускает владелец таблиц.
func SetupSQL(c *Config) (string, error) {
	dsn, err := pgwire.ParseDSN(c.DSN)
	if err != nil {
		return "", err
	}
	tapRole := dsn.User
	var b strings.Builder
	p := func(format string, args ...any) { fmt.Fprintf(&b, format+"\n", args...) }
	lit, id := pgwire.Literal, pgwire.Ident
	var schemas, tables, regclasses []string
	for _, t := range c.Tables {
		s, n, err := splitTable(t)
		if err != nil {
			return "", err
		}
		if !slices.Contains(schemas, s) {
			schemas = append(schemas, s)
		}
		tables = append(tables, id(s)+"."+id(n))
		regclasses = append(regclasses, lit(id(s)+"."+id(n))+"::regclass")
	}
	// named — названные таблицы и все их секции: (relid, level). Сама таблица —
	// отдельной строкой: pg_partition_tree обычную таблицу не отдаёт вовсе.
	array := "unnest(ARRAY[" + strings.Join(regclasses, ", ") + "]) AS t(oid)"
	named := "(SELECT t.oid AS relid, 0 AS level FROM " + array + " UNION\n" +
		"      SELECT tree.relid, tree.level FROM " + array + " CROSS JOIN LATERAL pg_partition_tree(t.oid) AS tree) AS part"
	p("-- evidencestore: настройка базы под запись до-образов (escollect -setup-sql).")
	p("-- Выполняет владелец таблиц или суперпользователь. Нужен wal_level = logical")
	p("-- (меняется с перезапуском базы) и предел журнала для слота: max_slot_wal_keep_size.")
	p("BEGIN;")
	p("")
	p("-- Чего по записи не вернуть, под запись не берём. Проверка — до любых изменений:")
	p("-- скрипт — одна транзакция, и отказ здесь не оставляет в базе ничего.")
	p("-- Виртуальная генерируемая колонка (PostgreSQL 18+): таблице с ней под REPLICA IDENTITY FULL")
	p("-- база отказывает в UPDATE и DELETE — любой роли, не только агенту.")
	p("DO $evidence$ DECLARE bad text; BEGIN")
	p("  SELECT string_agg(format('%%I.%%I.%%I', n.nspname, c.relname, a.attname), ', ' ORDER BY n.nspname, c.relname, a.attnum) INTO bad")
	p("    FROM %s", named)
	p("    JOIN pg_class c ON c.oid = part.relid JOIN pg_namespace n ON n.oid = c.relnamespace")
	p("    JOIN pg_attribute a ON a.attrelid = part.relid AND a.attnum > 0 AND NOT a.attisdropped AND a.attgenerated = 'v';")
	p("  IF bad IS NOT NULL THEN")
	p("    RAISE EXCEPTION 'evidencestore: a virtual generated column: %%', bad USING HINT =")
	p("      'With REPLICA IDENTITY FULL PostgreSQL refuses UPDATE and DELETE of a table that has a virtual generated column. '")
	p("      'Take the table out of \"tables\" in the collector config, or make the column STORED.';")
	p("  END IF;")
	p("END $evidence$;")
	p("-- Таблица (или секция) без первичного ключа: строки отката не найти, и агент писал бы туда,")
	p("-- откуда его не вернуть (P-253).")
	p("DO $evidence$ DECLARE bad text; BEGIN")
	p("  SELECT string_agg(format('%%I.%%I', n.nspname, c.relname), ', ' ORDER BY n.nspname, c.relname) INTO bad")
	p("    FROM %s", named)
	p("    JOIN pg_class c ON c.oid = part.relid JOIN pg_namespace n ON n.oid = c.relnamespace")
	p("    WHERE c.relkind IN ('r', 'p') AND NOT EXISTS (SELECT FROM pg_index i WHERE i.indrelid = c.oid AND i.indisprimary);")
	p("  IF bad IS NOT NULL THEN")
	p("    RAISE EXCEPTION 'evidencestore: a table without a primary key: %%', bad USING HINT =")
	p("      'The undo finds rows by their primary key: without one the changes of the agent cannot be put back. '")
	p("      'Give the table a primary key, or take it out of \"tables\" in the collector config.';")
	p("  END IF;")
	p("END $evidence$;")
	p("")
	p("-- Отметки в журнале: кто менял (ставит триггер), какое это действие (ставит MCP-сервер)")
	p("-- и что транзакция — откат (ставит esundo или MCP-сервер).")
	p("CREATE SCHEMA IF NOT EXISTS evidence;")
	p("REVOKE ALL ON SCHEMA evidence FROM PUBLIC;")
	p("CREATE OR REPLACE FUNCTION evidence.mark_who() RETURNS trigger")
	p("  LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog AS $evidence$")
	p("BEGIN")
	p("  PERFORM pg_logical_emit_message(true, %s, json_build_object(", lit(pgtap.PrefixWho))
	p("    'role', session_user, 'app', current_setting('application_name', true),")
	p("    'op', TG_OP, 'table', TG_TABLE_SCHEMA || '.' || TG_TABLE_NAME)::text);")
	p("  RETURN NULL;")
	p("END $evidence$;")
	p("REVOKE ALL ON FUNCTION evidence.mark_who() FROM PUBLIC;")
	p("CREATE OR REPLACE FUNCTION evidence.mark_action(info json) RETURNS void")
	p("  LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog AS $evidence$")
	p("BEGIN")
	p("  PERFORM pg_logical_emit_message(true, %s, json_build_object('role', session_user, 'info', info)::text);", lit(pgtap.PrefixAction))
	p("END $evidence$;")
	p("REVOKE ALL ON FUNCTION evidence.mark_action(json) FROM PUBLIC;")
	p("CREATE OR REPLACE FUNCTION evidence.mark_undo(info json) RETURNS void")
	p("  LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog AS $evidence$")
	p("BEGIN")
	p("  PERFORM pg_logical_emit_message(true, %s, json_build_object('role', session_user, 'info', info)::text);", lit(pgtap.PrefixUndo))
	p("END $evidence$;")
	p("REVOKE ALL ON FUNCTION evidence.mark_undo(json) FROM PUBLIC;")
	p("-- Отказ: MCP-сервер остановил действие пределом строк и откатывает его. Сообщение не")
	p("-- транзакционное (false): откат транзакции его из журнала не убирает, и сборщик о нём узнаёт.")
	p("CREATE OR REPLACE FUNCTION evidence.mark_refused(info json) RETURNS void")
	p("  LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog AS $evidence$")
	p("BEGIN")
	p("  PERFORM pg_logical_emit_message(false, %s, json_build_object('role', session_user, 'info', info)::text);", lit(pgtap.PrefixRefused))
	p("END $evidence$;")
	p("REVOKE ALL ON FUNCTION evidence.mark_refused(json) FROM PUBLIC;")
	p("")
	p("-- Напрямую писать отметки больше не может никто, кроме владельца функций выше:")
	p("-- иначе агент подложил бы отметку с чужой ролью.")
	p("DO $evidence$ DECLARE f regprocedure; BEGIN")
	p("  FOR f IN SELECT p.oid::regprocedure FROM pg_proc p")
	p("    WHERE p.proname = 'pg_logical_emit_message' AND p.pronamespace = 'pg_catalog'::regnamespace LOOP")
	p("    EXECUTE format('REVOKE EXECUTE ON FUNCTION %%s FROM PUBLIC', f);")
	p("    EXECUTE format('GRANT EXECUTE ON FUNCTION %%s TO %%I', f, current_user);")
	p("  END LOOP;")
	p("END $evidence$;")
	p("")
	p("-- Роли агентов: только строки названных таблиц. Ни TRUNCATE, ни владения —")
	p("-- значит, ни TRUNCATE, ни DROP: то, что по записи не вернуть, агенту недоступно.")
	var roles []string
	for _, r := range c.Roles {
		roles = append(roles, id(r))
		p("DO $evidence$ BEGIN IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname = %s) THEN CREATE ROLE %s LOGIN; END IF; END $evidence$;", lit(r), id(r))
		for _, s := range schemas {
			p("GRANT USAGE ON SCHEMA %s TO %s;", id(s), id(r))
		}
		p("GRANT SELECT, INSERT, UPDATE, DELETE ON %s TO %s;", strings.Join(tables, ", "), id(r))
		p("GRANT USAGE ON SCHEMA evidence TO %s;", id(r))
		p("GRANT EXECUTE ON FUNCTION evidence.mark_action(json), evidence.mark_undo(json), evidence.mark_refused(json) TO %s;", id(r))
		// Таймауты роли — значения по умолчанию для любых её сессий, в том
		// числе в обход MCP-сервера. Сессия может сменить их командой SET:
		// жёсткий предел — таймер MCP-сервера (esmcp, statement_timeout).
		p("ALTER ROLE %s SET statement_timeout = '60s';", id(r))
		p("ALTER ROLE %s SET lock_timeout = '10s';", id(r))
		p("ALTER ROLE %s SET idle_in_transaction_session_timeout = '5min';", id(r))
	}
	lits := make([]string, len(c.Roles))
	for i, r := range c.Roles {
		lits[i] = lit(r)
	}
	p("-- Своих объектов агенту заводить нельзя: схемы, функции, типы и таблицы в журнал базы не идут")
	p("-- (это DDL), а функция или оператор под системным именем в схеме из его search_path заслонили бы")
	p("-- системные (P-242). PostgreSQL 14 и старше даёт PUBLIC право CREATE на схеме public.")
	p("DO $evidence$ DECLARE bad text; BEGIN")
	p("  SELECT string_agg(x, ', ') INTO bad FROM (")
	p("    SELECT format('%%I can CREATE in schema %%I', r.rolname, n.nspname) AS x FROM pg_roles r CROSS JOIN pg_namespace n")
	p("      WHERE r.rolname IN (%s) AND left(n.nspname, 3) <> 'pg_' AND n.nspname <> 'information_schema'", strings.Join(lits, ", "))
	p("        AND has_schema_privilege(r.oid, n.oid, 'CREATE')")
	p("    UNION ALL SELECT format('%%I can CREATE schemas in this database', r.rolname) FROM pg_roles r")
	p("      WHERE r.rolname IN (%s) AND has_database_privilege(r.oid, current_database(), 'CREATE')", strings.Join(lits, ", "))
	p("    ORDER BY 1) AS rights;")
	p("  IF bad IS NOT NULL THEN")
	p("    RAISE EXCEPTION 'evidencestore: %%', bad USING HINT =")
	p("      'An agent role must not create objects: its DDL is not in the database log, and a function or operator of its own '")
	p("      'named like a system one would stand in for it. REVOKE CREATE ON SCHEMA … FROM PUBLIC (or from the role the right comes through); '")
	p("      'PostgreSQL 14 and older grant it on schema public to PUBLIC.';")
	p("  END IF;")
	p("END $evidence$;")
	p("")
	p("-- Таблицы: старая строка в журнал целиком, отметка «кто» перед каждым оператором.")
	for _, t := range tables {
		p("ALTER TABLE %s REPLICA IDENTITY FULL;", t)
		p("DROP TRIGGER IF EXISTS evidence_who ON %s;", t)
		p("CREATE TRIGGER evidence_who BEFORE INSERT OR UPDATE OR DELETE OR TRUNCATE ON %s", t)
		p("  FOR EACH STATEMENT EXECUTE FUNCTION evidence.mark_who();")
	}
	p("")
	p("-- Секции секционированных таблиц. Изменения идут в журнал под именем секции, и старую")
	p("-- строку пишет она: каждой секции — то же, что самой таблице, и те же права агентам.")
	p("-- Секцию, созданную позже, этот скрипт не знает: после неё его выполняют снова")
	p("-- (сборщик при подключении называет секции, которым не хватает настройки).")
	p("DO $evidence$ DECLARE leaf regclass; BEGIN")
	p("  FOR leaf IN SELECT part.relid FROM %s", named)
	p("      JOIN pg_class c ON c.oid = part.relid WHERE part.level > 0 AND c.relkind = 'r' LOOP")
	p("    EXECUTE format('ALTER TABLE %%s REPLICA IDENTITY FULL', leaf);")
	p("    EXECUTE format('DROP TRIGGER IF EXISTS evidence_who ON %%s', leaf);")
	p("    EXECUTE format('CREATE TRIGGER evidence_who BEFORE INSERT OR UPDATE OR DELETE OR TRUNCATE ON %%s '")
	p("      'FOR EACH STATEMENT EXECUTE FUNCTION evidence.mark_who()', leaf);")
	// Имена ролей попадают в строку формата: знак процента в имени удваивается.
	p("    EXECUTE format(%s, leaf);", lit("GRANT SELECT, INSERT, UPDATE, DELETE ON %s TO "+strings.ReplaceAll(strings.Join(roles, ", "), "%", "%%")))
	p("  END LOOP;")
	p("END $evidence$;")
	p("")
	p("-- Публикация: в поток репликации идут только эти таблицы. С PostgreSQL 18 в неё входят и")
	p("-- хранимые генерируемые колонки: иначе таблице с такой колонкой под REPLICA IDENTITY FULL")
	p("-- база отказывает в UPDATE и DELETE.")
	publication := "CREATE PUBLICATION " + id(c.Publication) + " FOR TABLE " + strings.Join(tables, ", ")
	p("DROP PUBLICATION IF EXISTS %s;", id(c.Publication))
	p("DO $evidence$ BEGIN")
	p("  IF current_setting('server_version_num')::int >= 180000 THEN")
	p("    EXECUTE %s;", lit(publication+" WITH (publish_generated_columns = stored)"))
	p("  ELSE")
	p("    EXECUTE %s;", lit(publication))
	p("  END IF;")
	p("END $evidence$;")
	p("")
	p("-- Роль сборщика: читает поток репликации, к таблицам доступа не имеет.")
	p("DO $evidence$ BEGIN IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname = %s) THEN CREATE ROLE %s LOGIN REPLICATION; END IF; END $evidence$;", lit(tapRole), id(tapRole))
	p("COMMIT;")
	return b.String(), nil
}

const (
	// drainIdle — столько вход ждёт следующего сообщения между транзакциями,
	// прежде чем отдать ход отправке: поток пуст.
	drainIdle = 5 * time.Millisecond
	// passBudget — дольше этого один проход не читает (между транзакциями):
	// накопленное надо отправлять, а хранилищу — слышать пульс.
	passBudget = time.Second
	// dialTimeout — на подключение и вопросы к каталогу при (пере)подключении.
	dialTimeout = 15 * time.Second
	// maxBackoff — предел паузы между попытками подключиться.
	maxBackoff = 30 * time.Second
	// onceIdle — escollect -once: поток молчит столько — считаем, что всё,
	// что было в журнале базы к началу, прочитано.
	onceIdle = 2 * time.Second
)

// SlotFile — файл в Config.Dir: слот, который этот сборщик уже читал. Слота в
// базе нет, а файл есть — слот удалили, и изменения с тех пор потеряны.
const SlotFile = "slot.json"

type slotState struct {
	Slot string `json:"slot"`
}

// Source — вход «PostgreSQL» (input.Input).
type Source struct {
	cfg  Config
	dsn  pgwire.Config
	log  *slog.Logger
	sink input.Sink
	tap  *pgtap.Tap

	cat, repl *pgwire.Conn
	// flushed — до этой позиции журнала базы всё нужное лежит в буфере
	// сборщика; reported — что из этого уже сказано базе.
	flushed, reported pgwire.LSN
	lastReport        time.Time
	retryAt           time.Time
	backoff           time.Duration

	emitted int   // записей легло в буфер за проход
	sinkErr error // буфер отказал: дальше только выход

	// notifier несёт тревоги получателям (nil — не настроен или ещё не начат).
	notifier *alert.Notifier
	// downSince — с каких пор нет связи с базой (ноль — связь есть); downErr —
	// последняя причина; downSaid — тревога db-down об этом уже поднята.
	downSince time.Time
	downErr   error
	downSaid  bool
	// identitySaid — о каких таблицах без REPLICA IDENTITY FULL тревога уже поднята.
	identitySaid string
	// slot — что база сказала о слоте в последний раз; slotLevel — о каком
	// уровне отставания уже поднята тревога (0 — в норме, 1 — половина
	// предела, 2 — 80 %).
	slot      SlotState
	slotLevel int

	partSize int // размер части pgtap; 0 — его умолчание (меняют тесты)
}

// New готовит вход; к базе он подключится при первом чтении.
func New(cfg Config, log *slog.Logger) (*Source, error) {
	if log == nil {
		log = slog.New(slog.DiscardHandler)
	}
	if cfg.Dir == "" {
		return nil, errors.New("pginput: no directory for the index")
	}
	dsn, err := pgwire.ParseDSN(cfg.DSN)
	if err != nil {
		return nil, err
	}
	dsn.AppName = "escollect"
	dsn.Timeout = dialTimeout
	return &Source{cfg: cfg, dsn: dsn, log: log}, nil
}

// Open — input.Input: справочник открыт, место входа принято.
func (s *Source) Open(cursor uint64, sink input.Sink) (err error) {
	s.sink = sink
	s.tap, err = pgtap.Open(pgtap.Config{Dir: s.cfg.Dir, Roles: s.cfg.Roles, AlertRows: s.cfg.AlertRows,
		RequireAction: s.cfg.RequireAction, Canaries: s.cfg.Canaries, PartSize: s.partSize}, catalog{s}, counted{s}, cursor, s.log)
	return err
}

// counted — буфер сборщика для pgtap: считает записи прохода и запоминает отказ.
type counted struct{ s *Source }

func (c counted) Next() uint64 { return c.s.sink.Next() }

func (c counted) Emit(bodies [][]byte, cursor uint64) (uint64, error) {
	first, err := c.s.sink.Emit(bodies, cursor)
	if err != nil {
		c.s.sinkErr = err
		return 0, err
	}
	c.s.emitted += len(bodies)
	return first, nil
}

// catalog отвечает pgtap на вопросы о таблицах по обычному соединению.
type catalog struct{ s *Source }

func (k catalog) Describe(rel pgoutput.Relation) (pgtap.RelInfo, error) {
	var info pgtap.RelInfo
	c := k.s.cat
	if c == nil {
		return info, errors.New("no catalog connection")
	}
	if len(rel.Columns) > 0 {
		// Имена типов — по OID и модификатору из самого сообщения: таблицу к
		// этому времени могли изменить, а запись говорит о строках как они были.
		var vals []string
		for i, col := range rel.Columns {
			vals = append(vals, fmt.Sprintf("(%d, %d::oid, %d)", i, col.TypeOID, col.TypeMod))
		}
		res, err := c.Query("SELECT format_type(t.o, t.m) FROM (VALUES " + strings.Join(vals, ", ") + ") AS t(n, o, m) ORDER BY t.n")
		if err != nil {
			return info, err
		}
		for _, row := range res[0].Rows {
			if row[0] == nil {
				return info, fmt.Errorf("a column type of %s.%s is unknown to the catalog", rel.Namespace, rel.Name)
			}
			info.Types = append(info.Types, *row[0])
		}
	}
	// Первичный ключ — из каталога: при REPLICA IDENTITY FULL поток помечает
	// ключевыми все колонки. Таблицы уже нет — ключа нет, откат её не возьмёт.
	res, err := c.Query(fmt.Sprintf("SELECT a.attname FROM pg_index i JOIN pg_attribute a ON a.attrelid = i.indrelid AND a.attnum = ANY(i.indkey) "+
		"WHERE i.indrelid = %d AND i.indisprimary ORDER BY array_position(i.indkey::int2[], a.attnum)", rel.ID))
	if err != nil {
		return info, err
	}
	info.PK = []string{}
	for _, row := range res[0].Rows {
		info.PK = append(info.PK, *row[0])
	}
	return info, nil
}

// connect подключается к базе, если ещё не подключён: проверяет настройку,
// находит (или заводит) слот и начинает поток.
func (s *Source) connect(ctx context.Context) (err error) {
	if s.repl != nil {
		return nil
	}
	ctx, cancel := context.WithTimeout(ctx, dialTimeout)
	defer cancel()
	cat, err := pgwire.Dial(ctx, s.dsn)
	if err != nil {
		return err
	}
	defer func() {
		if err != nil {
			cat.Close()
		}
	}()
	if row, _, err := cat.QueryRow("SHOW wal_level"); err != nil {
		return err
	} else if *row[0] != "logical" {
		return fmt.Errorf("wal_level is %s: logical decoding needs wal_level = logical (a restart)", *row[0])
	}
	if _, ok, err := cat.QueryRow("SELECT 1 FROM pg_publication WHERE pubname = " + pgwire.Literal(s.cfg.Publication)); err != nil {
		return err
	} else if !ok {
		return fmt.Errorf("publication %s does not exist: run the script printed by escollect -setup-sql", s.cfg.Publication)
	}
	s.watchIdentity(cat)
	start, err := s.ensureSlot(cat)
	if err != nil {
		return err
	}
	rdsn := s.dsn
	rdsn.Replication = true
	repl, err := pgwire.Dial(ctx, rdsn)
	if err != nil {
		return err
	}
	// Откуда слать, говорит не только слот, но и буфер сборщика: его место —
	// фиксация последней транзакции, которая лежит в нём целиком, и всё не
	// новее сервер может не присылать. Слот это место знает не всегда:
	// подтверждение могло не дойти (сборщик упал сразу после записи в буфер),
	// а PostgreSQL до 17-й версии при перезапуске ещё и забывает
	// подтверждённую позицию, если слот с тех пор не сохранялся.
	// messages — с PostgreSQL 14: без отметок не узнать, чья транзакция.
	from := pgwire.LSN(0)
	if c := s.tap.Cursor(); c != 0 {
		from = pgwire.LSN(c + 1)
	}
	if err := repl.StartReplication(s.cfg.Slot, from, "proto_version", "1", "publication_names", s.cfg.Publication, "messages", "true"); err != nil {
		repl.Close()
		return fmt.Errorf("start replication: %w", err)
	}
	s.tap.Reset()
	if s.downSaid {
		s.raise(alert.KindDBUp, fmt.Sprintf("the connection to the database is back after %s", time.Since(s.downSince).Round(time.Second)))
	}
	s.downSince, s.downErr, s.downSaid = time.Time{}, nil, false
	s.cat, s.repl = cat, repl
	start = max(start, from)
	s.flushed, s.reported, s.lastReport = start, start, time.Now()
	s.backoff, s.retryAt = 0, time.Time{}
	s.log.Info("reading the database log", "slot", s.cfg.Slot, "publication", s.cfg.Publication, "from", start.String(), "roles", strings.Join(s.cfg.Roles, ","))
	return nil
}

// watchIdentity называет таблицы и секции из настроек, у которых нет REPLICA
// IDENTITY FULL: старых строк их изменений в журнале базы не будет. Обычный
// случай — секция, созданная после настройки базы. Сказать об этом надо при
// подключении, а не после первого действия агента над такой секцией.
func (s *Source) watchIdentity(cat *pgwire.Conn) {
	// По каталогу, а не по именам: у роли сборщика нет прав на схемы таблиц, и
	// разбор имени ('schema.table'::regclass) ей отказал бы.
	var names []string
	for _, t := range s.cfg.Tables {
		if schema, table, err := splitTable(t); err == nil {
			names = append(names, "("+pgwire.Literal(schema)+", "+pgwire.Literal(table)+")")
		}
	}
	// Сама таблица — отдельной строкой: pg_partition_tree обычную таблицу не отдаёт вовсе.
	row, _, err := cat.QueryRow("SELECT string_agg(part.relid::text, ', ' ORDER BY part.relid::text) " +
		"FROM pg_class t JOIN pg_namespace n ON n.oid = t.relnamespace " +
		"CROSS JOIN LATERAL (SELECT t.oid::regclass AS relid UNION SELECT tree.relid FROM pg_partition_tree(t.oid) AS tree) AS part " +
		"JOIN pg_class c ON c.oid = part.relid WHERE (n.nspname, t.relname) IN (" + strings.Join(names, ", ") + ") AND c.relkind = 'r' AND c.relreplident <> 'f'")
	if err != nil {
		s.log.Warn("the replica identity of the watched tables could not be checked", "err", err)
		return
	}
	bad := ""
	if row != nil && row[0] != nil {
		bad = *row[0]
	}
	if bad == s.identitySaid {
		return
	}
	if s.identitySaid = bad; bad == "" {
		return
	}
	detail := "no REPLICA IDENTITY FULL on " + bad + ": old rows of their changes are not in the database log, such changes cannot be undone. " +
		"Run the script of escollect -setup-sql again (a partition made after the setup needs it)"
	s.log.Error("alert", "kind", alert.KindIdentity, "detail", detail)
	s.raise(alert.KindIdentity, detail)
}

// ensureSlot находит слот и отдаёт позицию, которую он подтвердил. Нет слота
// при первом подключении — заводит: с этого места база копит для нас журнал.
// Слот пропал или база стёрла его непрочитанный журнал — потеря: пропуск
// номера, слот заново.
func (s *Source) ensureSlot(cat *pgwire.Conn) (pgwire.LSN, error) {
	var known slotState
	knownPath := filepath.Join(s.cfg.Dir, SlotFile)
	if data, err := os.ReadFile(knownPath); err == nil {
		if err := json.Unmarshal(data, &known); err != nil {
			return 0, fmt.Errorf("%s: %w", knownPath, err)
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return 0, err
	}
	name := pgwire.Literal(s.cfg.Slot)
	row, exists, err := cat.QueryRow("SELECT plugin, wal_status, confirmed_flush_lsn FROM pg_replication_slots WHERE slot_name = " + name)
	if err != nil {
		return 0, err
	}
	lost := ""
	switch {
	case exists && (row[0] == nil || *row[0] != "pgoutput"):
		return 0, fmt.Errorf("replication slot %s exists, but it is not a pgoutput slot", s.cfg.Slot)
	case exists && row[1] != nil && *row[1] == "lost":
		lost = "the server removed the log that replication slot " + s.cfg.Slot + " had not read yet (max_slot_wal_keep_size): changes made meanwhile are lost"
	case !exists && known.Slot == s.cfg.Slot:
		lost = "replication slot " + s.cfg.Slot + " is gone from the server: changes made since the collector last read are lost"
	}
	if lost != "" {
		// Сначала пропуск — в буфер, потом новый слот: упасть между ними —
		// пропуск запишется второй раз, но не пропадёт.
		if err := s.sink.Gap(lost); err != nil {
			s.sinkErr = err
			return 0, err
		}
		s.raise(alert.KindGap, lost+": the store records a gap in the numbering of this source")
		if exists {
			if _, err := cat.Query("SELECT pg_drop_replication_slot(" + name + ")"); err != nil {
				return 0, fmt.Errorf("drop the lost slot %s: %w", s.cfg.Slot, err)
			}
			exists = false
		}
	}
	if !exists {
		if _, err := cat.Query("SELECT pg_create_logical_replication_slot(" + name + ", 'pgoutput')"); err != nil {
			return 0, fmt.Errorf("create slot %s: %w", s.cfg.Slot, err)
		}
		s.log.Info("replication slot created: the server keeps its log for the collector from here", "slot", s.cfg.Slot)
		if row, _, err = cat.QueryRow("SELECT plugin, wal_status, confirmed_flush_lsn FROM pg_replication_slots WHERE slot_name = " + name); err != nil {
			return 0, err
		}
	}
	if known.Slot != s.cfg.Slot {
		if known.Slot != "" {
			s.log.Warn("the slot name in the config changed: if the old slot is still on the server, it holds the server's log until it is dropped",
				"old", known.Slot, "new", s.cfg.Slot)
		}
		if err := writeFile(knownPath, slotState{Slot: s.cfg.Slot}); err != nil {
			return 0, err
		}
	}
	if r, _, err := cat.QueryRow("SHOW max_slot_wal_keep_size"); err == nil && *r[0] == "-1" {
		s.log.Warn("max_slot_wal_keep_size is unlimited: while this collector is down the server keeps its log for the slot without a bound")
	}
	if row == nil || row[2] == nil {
		return 0, nil
	}
	return pgwire.ParseLSN(*row[2])
}

// writeFile заменяет файл целиком: временный файл, fsync, переименование.
func writeFile(path string, v any) error {
	data, err := json.Marshal(v)
	if err != nil {
		return err
	}
	tmp := path + ".tmp"
	f, err := os.OpenFile(tmp, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	_, err = f.Write(data)
	if err = errors.Join(err, f.Sync(), f.Close()); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

// drop закрывает соединения после ошибки; следующая попытка — после паузы.
func (s *Source) drop(why error) {
	for _, c := range []*pgwire.Conn{s.repl, s.cat} {
		if c != nil {
			c.Close()
		}
	}
	s.repl, s.cat = nil, nil
	if s.downSince.IsZero() {
		s.downSince = time.Now()
	}
	s.downErr = why
	s.backoff = min(max(s.backoff*2, time.Second), maxBackoff)
	s.retryAt = time.Now().Add(s.backoff)
	s.log.Warn("the database connection is down; what is spooled is still delivered", "err", why, "retry_in", s.backoff)
}

// report говорит базе подтверждённую позицию: сразу (force), иначе — когда
// она сдвинулась, но не чаще пяти раз в секунду.
func (s *Source) report(force bool) error {
	if !force && (s.flushed == s.reported || time.Since(s.lastReport) < 200*time.Millisecond) {
		return nil
	}
	s.reported, s.lastReport = s.flushed, time.Now()
	return s.repl.SendStandbyStatus(s.flushed)
}

// step читает и обрабатывает одно сообщение потока; ждёт его не дольше wait.
// idle — сообщения не было.
func (s *Source) step(wait time.Duration) (idle bool, err error) {
	m, err := s.repl.ReadReplication(wait)
	switch {
	case errors.Is(err, pgwire.ErrTimeout):
		return true, nil
	case errors.Is(err, io.EOF):
		return false, errors.New("the server ended the replication stream")
	case err != nil:
		return false, err
	}
	if m.Keepalive {
		// Между транзакциями всё до конца журнала сервера нам уже отдано.
		if !s.tap.InTransaction() && m.WALEnd > s.flushed {
			s.flushed = m.WALEnd
		}
		return false, s.report(m.ReplyRequested)
	}
	msg, err := pgoutput.Parse(m.Data)
	if err != nil {
		return false, fmt.Errorf("at %s: %w", m.WALStart, err)
	}
	done, err := s.tap.Handle(msg)
	if err != nil {
		return false, fmt.Errorf("at %s: %w", m.WALStart, err)
	}
	if done != 0 {
		s.flushed = max(s.flushed, pgwire.LSN(done))
		return false, s.report(false)
	}
	return false, nil
}

// pump читает поток, пока stop не скажет «хватит». stop зовётся после каждого
// сообщения (или ожидания без сообщения — idle); inTx — поток стоит посреди
// транзакции. Внутри транзакции вход ждёт следующее сообщение дольше: отдай он
// ход отправке посреди транзакции, база за время отправки могла бы оборвать
// молчащее соединение, и транзакция пошла бы заново.
func (s *Source) pump(stop func(idle, inTx bool) bool) error {
	for {
		wait := drainIdle
		if s.tap.InTransaction() {
			wait = s.cfg.StatusEvery.D()
		}
		idle, err := s.step(wait)
		if err != nil {
			return err
		}
		inTx := s.tap.InTransaction()
		if idle && inTx {
			// Сервер молчит посреди транзакции: сказать ему, что мы живы.
			if err := s.report(true); err != nil {
				return err
			}
		}
		if stop(idle, inTx) {
			// Конец прохода: сдвинувшуюся позицию база узнаёт сразу, а не
			// через status_every, — её журнал до этой позиции больше не нужен.
			return s.report(s.flushed != s.reported || time.Since(s.lastReport) >= s.cfg.StatusEvery.D())
		}
	}
}

// fail разбирает ошибку прохода: отказ буфера — наружу, сборщик выйдет;
// остальное — беда соединения или потока: закрыть и попробовать снова.
func (s *Source) fail(err error) error {
	if s.sinkErr != nil {
		return s.sinkErr
	}
	s.drop(err)
	return nil
}

// slotEvery — как часто спрашивать базу о слоте. Переменная — чтобы тест не
// ждал.
var slotEvery = 10 * time.Second

// SlotState — что база говорит о слоте репликации.
type SlotState struct {
	At       time.Time // когда спрашивали; ноль — ещё не спрашивали
	Status   string    // wal_status: reserved, extended, unreserved, lost
	Retained int64     // столько байт журнала база держит для слота
	Lag      int64     // на столько байт подтверждённая позиция отстаёт от конца журнала
	Limit    int64     // max_slot_wal_keep_size в байтах; -1 — без предела
	Safe     int64     // сколько байт журнала можно написать, пока слот не под угрозой; -1 — база не говорит
}

// watchSlot раз в slotEvery спрашивает базу о слоте и поднимает тревогу, когда
// журнал для него дорос до половины предела, и снова — до 80 %.
func (s *Source) watchSlot() error {
	if time.Since(s.slot.At) < slotEvery {
		return nil
	}
	row, ok, err := s.cat.QueryRow("SELECT s.wal_status, pg_wal_lsn_diff(pg_current_wal_lsn(), s.restart_lsn)::bigint, " +
		"pg_wal_lsn_diff(pg_current_wal_lsn(), s.confirmed_flush_lsn)::bigint, coalesce(s.safe_wal_size, -1), " +
		"(SELECT setting::bigint FROM pg_settings WHERE name = 'max_slot_wal_keep_size') " +
		"FROM pg_replication_slots s WHERE s.slot_name = " + pgwire.Literal(s.cfg.Slot))
	if err != nil {
		return err
	}
	if !ok {
		return fmt.Errorf("replication slot %s is gone from the server", s.cfg.Slot)
	}
	num := func(v *string) int64 {
		if v == nil {
			return 0
		}
		var n int64
		fmt.Sscan(*v, &n)
		return n
	}
	st := SlotState{At: time.Now(), Retained: num(row[1]), Lag: num(row[2]), Safe: num(row[3]), Limit: num(row[4])}
	if row[0] != nil {
		st.Status = *row[0]
	}
	if st.Limit > 0 {
		st.Limit <<= 20 // настройка — в мегабайтах
	}
	s.slot = st

	level, calm := grade(st, s.cfg.SlotAlertMB)
	switch {
	case level > s.slotLevel:
		s.slotLevel = level
		detail := fmt.Sprintf("the server holds %s of its log for slot %s", human(st.Retained), s.cfg.Slot)
		switch {
		case st.Limit > 0 && st.Retained >= st.Limit:
			detail += fmt.Sprintf(", more than the %s allowed (max_slot_wal_keep_size): at its next checkpoint it drops the slot and changes are lost", human(st.Limit))
		case st.Limit > 0:
			detail += fmt.Sprintf(", %d%% of the %s allowed (max_slot_wal_keep_size); at 100%% it drops the slot and changes are lost", st.Retained*100/st.Limit, human(st.Limit))
		default:
			detail += " and has no limit for it (max_slot_wal_keep_size): it grows until the disk is full"
		}
		if own := int64(s.cfg.SlotAlertMB) << 20; own > 0 && st.Retained >= own {
			detail += fmt.Sprintf(" [alert threshold %d MB]", s.cfg.SlotAlertMB)
		}
		detail += fmt.Sprintf(". The collector is %s behind. Usual causes: a long open transaction on the server, or the collector cannot keep up", human(st.Lag))
		s.log.Error("alert", "kind", alert.KindSlotLag, "detail", detail)
		s.raise(alert.KindSlotLag, detail)
	case s.slotLevel > 0 && level == 0 && calm:
		s.slotLevel = 0
		s.raise(alert.KindSlotOK, fmt.Sprintf("the server's log held for slot %s is back to %s", s.cfg.Slot, human(st.Retained)))
	}
	return nil
}

// grade — уровень отставания слота: 0 — в норме, 1 — журнал для слота дорос до
// половины предела базы или до своего порога (ownMB мегабайт), 2 — до 80 %
// предела. calm — можно сказать «снова в норме»: с запасом ниже порогов (40 %
// предела и 80 % своего порога), чтобы тревоги не мигали у самой границы.
func grade(st SlotState, ownMB int) (level int, calm bool) {
	calm = true
	if st.Limit > 0 {
		switch pct := st.Retained * 100 / st.Limit; {
		case pct >= 80:
			level = 2
		case pct >= 50:
			level = 1
		}
		calm = st.Retained*100/st.Limit < 40
	}
	if own := int64(ownMB) << 20; own > 0 {
		if st.Retained >= own {
			level = max(level, 1)
		}
		calm = calm && st.Retained < own*8/10
	}
	return level, calm
}

// human — число байт словами.
func human(n int64) string {
	switch {
	case n >= 1<<30:
		return fmt.Sprintf("%.1f GB", float64(n)/(1<<30))
	case n >= 1<<20:
		return fmt.Sprintf("%.0f MB", float64(n)/(1<<20))
	case n >= 1<<10:
		return fmt.Sprintf("%.0f kB", float64(n)/(1<<10))
	}
	return fmt.Sprintf("%d bytes", n)
}

// Slot — что база сказала о слоте в последний раз.
func (s *Source) Slot() SlotState { return s.slot }

// Metrics — показатели входа для страницы /metrics сборщика. Зовётся из цикла
// сборщика, как и остальные методы.
func (s *Source) Metrics() []metrics.Family {
	fams := []metrics.Family{
		metrics.One("escollect_postgres_connected", "1 while the replication stream from the database is open", metrics.Gauge, metrics.Bool(s.repl != nil)),
	}
	if s.tap != nil {
		st := s.tap.Stats()
		fams = append(fams,
			metrics.One("escollect_postgres_transactions_captured_total", "transactions of the watched roles put into the spool since the collector started", metrics.Counter, float64(st.Captured)),
			metrics.One("escollect_postgres_transactions_skipped_total", "transactions of other roles passed by since the collector started", metrics.Counter, float64(st.Skipped)),
			metrics.One("escollect_postgres_row_changes_total", "row changes put into the spool since the collector started", metrics.Counter, float64(st.Changes)),
			metrics.One("escollect_postgres_alerts_total", "alert signals raised since the collector started", metrics.Counter, float64(st.Alerts)))
	}
	if !s.slot.At.IsZero() {
		fams = append(fams,
			metrics.One("escollect_postgres_slot_checked_timestamp_seconds", "when the collector last asked the server about its replication slot", metrics.Gauge, float64(s.slot.At.Unix())),
			metrics.One("escollect_postgres_slot_retained_bytes", "the server's log held for the replication slot; at max_slot_wal_keep_size the server drops the slot", metrics.Gauge, float64(s.slot.Retained)),
			metrics.One("escollect_postgres_slot_lag_bytes", "how far the position confirmed by the collector is behind the end of the server's log", metrics.Gauge, float64(s.slot.Lag)),
			metrics.One("escollect_postgres_slot_lost", "1 when the server reports the slot as lost", metrics.Gauge, metrics.Bool(s.slot.Status == "lost")))
		if s.slot.Limit > 0 {
			fams = append(fams, metrics.One("escollect_postgres_slot_limit_bytes", "max_slot_wal_keep_size of the server", metrics.Gauge, float64(s.slot.Limit)))
		}
		if s.slot.Safe >= 0 {
			fams = append(fams, metrics.One("escollect_postgres_slot_safe_bytes", "how much log the server can still write before the slot is in danger (safe_wal_size)", metrics.Gauge, float64(s.slot.Safe)))
		}
	}
	if s.notifier != nil {
		waiting := metrics.Family{Name: "escollect_alerts_waiting", Help: "alerts not yet delivered to a notify target", Type: metrics.Gauge}
		failing := metrics.Family{Name: "escollect_alerts_target_failing", Help: "1 while a notify target refuses or cannot be reached", Type: metrics.Gauge}
		for _, t := range s.notifier.Stats() {
			label := [][2]string{{"target", t.Name}}
			waiting.Samples = append(waiting.Samples, metrics.Sample{Labels: label, Value: float64(t.Waiting)})
			failing.Samples = append(failing.Samples, metrics.Sample{Labels: label, Value: metrics.Bool(t.Failing)})
		}
		fams = append(fams, waiting, failing)
	}
	return fams
}

// raise пишет служебную тревогу входа в alerts.jsonl; оттуда её несёт
// получателям notifier.
func (s *Source) raise(kind, detail string) {
	ev := alert.Event{}
	ev.Add(kind, detail)
	if err := s.tap.Alerts().Append(ev); err != nil {
		s.log.Error("alert not written", "kind", kind, "detail", detail, "err", err)
	}
}

// watchDown поднимает тревогу, когда связи с базой нет дольше down_after.
func (s *Source) watchDown() {
	if s.downSaid || s.downSince.IsZero() || time.Since(s.downSince) < s.cfg.DownAfter.D() {
		return
	}
	s.downSaid = true
	detail := fmt.Sprintf("no connection to the database for %s (%v): changes made meanwhile are read when it is back, as long as the server keeps its log for the slot",
		time.Since(s.downSince).Round(time.Second), s.downErr)
	s.log.Error("alert", "kind", alert.KindDBDown, "detail", detail)
	s.raise(alert.KindDBDown, detail)
}

// notify начинает доставку тревог — при первом чтении, а не в Open: к этому
// времени у входа уже его окончательный журнал (SetLogger).
func (s *Source) notify() {
	if s.notifier != nil || s.cfg.Notify == nil {
		return
	}
	n, err := alert.Start(alert.Options{File: s.tap.Alerts().Path(), Dir: s.cfg.Dir, Targets: s.cfg.Notify.To,
		Text: alert.TextOptions{Title: "database " + s.dsn.Database, UndoHint: s.cfg.Notify.UndoHint}}, s.log)
	if err != nil {
		// Тревоги остаются в файле; сбор записей из-за доставки не встаёт.
		s.log.Error("alerts are not delivered: the notifier did not start", "err", err)
		s.cfg.Notify = nil
		return
	}
	s.notifier = n
	s.tap.Alerts().OnAppend(n.Wake)
}

// Read — input.Input: один проход без ожидания.
func (s *Source) Read() (int, error) {
	s.emitted = 0
	s.notify()
	if s.repl == nil {
		s.watchDown()
		if time.Now().Before(s.retryAt) {
			return 0, nil
		}
		if err := s.connect(context.Background()); err != nil {
			return s.emitted, s.fail(err)
		}
	}
	start := time.Now()
	// Поток пуст — ход отправке. Посреди транзакции ход отдаётся, только когда
	// сервер замолчал надолго (step ждал status_every); между транзакциями —
	// ещё и по времени: накопленное надо слать, а хранилищу — слышать пульс.
	if err := s.pump(func(idle, inTx bool) bool { return idle || !inTx && time.Since(start) >= passBudget }); err != nil {
		return s.emitted, s.fail(err)
	}
	if err := s.watchSlot(); err != nil {
		return s.emitted, s.fail(err)
	}
	return s.emitted, nil
}

// ReadAll — input.Input: всё, что было в журнале базы к моменту вызова.
func (s *Source) ReadAll(ctx context.Context) (int, error) {
	s.emitted = 0
	s.notify()
	if err := s.connect(ctx); err != nil {
		if s.sinkErr == nil {
			s.drop(err)
		}
		return s.emitted, err
	}
	row, _, err := s.cat.QueryRow("SELECT pg_current_wal_flush_lsn()")
	if err != nil {
		s.drop(err)
		return s.emitted, err
	}
	target, err := pgwire.ParseLSN(*row[0])
	if err != nil {
		return s.emitted, err
	}
	// Дочитали до цели — готово сразу. Цель может и не прийти точь-в-точь
	// (сервер называет конец последней записи журнала, а не страницы):
	// тогда — когда поток молчит onceIdle.
	quiet := time.Now()
	err = s.pump(func(idle, inTx bool) bool {
		if ctx.Err() != nil {
			return true
		}
		if !idle || inTx {
			quiet = time.Now()
			return !inTx && s.flushed >= target
		}
		// Отчёт будит сервер: в ответ он называет конец своего журнала.
		if err := s.report(true); err != nil {
			return true
		}
		time.Sleep(20 * time.Millisecond)
		return s.flushed >= target || time.Since(quiet) >= onceIdle
	})
	if err != nil {
		if s.sinkErr == nil {
			s.drop(err)
		}
		return s.emitted, err
	}
	return s.emitted, ctx.Err()
}

// Wait — input.Input: ждёт данных в потоке не дольше d.
func (s *Source) Wait(ctx context.Context, d time.Duration) {
	deadline := time.Now().Add(d)
	for ctx.Err() == nil {
		left := time.Until(deadline)
		if left <= 0 {
			return
		}
		slice := min(left, 500*time.Millisecond) // отмена ctx замечается за полсекунды
		if s.repl == nil {
			select {
			case <-ctx.Done():
			case <-time.After(slice):
			}
			continue
		}
		err := s.repl.WaitReplication(slice)
		if err == nil {
			return
		}
		if !errors.Is(err, pgwire.ErrTimeout) {
			s.drop(err)
			continue
		}
		if time.Since(s.lastReport) >= s.cfg.StatusEvery.D() {
			if err := s.report(true); err != nil {
				s.drop(err)
			}
		}
	}
}

// Stats — счётчики pgtap с запуска.
func (s *Source) Stats() pgtap.Stats { return s.tap.Stats() }

// Close — input.Input: последняя подтверждённая позиция — базе, соединения и
// справочник закрыты.
func (s *Source) Close() error {
	if s.repl != nil {
		s.report(true)
	}
	for _, c := range []*pgwire.Conn{s.repl, s.cat} {
		if c != nil {
			c.Close()
		}
	}
	s.repl, s.cat = nil, nil
	if s.notifier != nil {
		s.notifier.Close() // неотправленное ждёт в файле до следующего запуска
		s.notifier = nil
	}
	if s.tap == nil {
		return nil
	}
	st := s.tap.Stats()
	s.log.Info("database input closed", "captured", st.Captured, "skipped", st.Skipped, "changes", st.Changes, "parts", st.Parts, "alerts", st.Alerts)
	return s.tap.Close()
}

// SetLogger меняет журнал входа (до первого чтения).
func (s *Source) SetLogger(log *slog.Logger) {
	s.log = log
	if s.tap != nil {
		s.tap.SetLogger(log)
	}
}
