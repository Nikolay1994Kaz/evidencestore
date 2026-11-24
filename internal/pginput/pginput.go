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
	"math"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/Nikolay1994Kaz/evidencestore/internal/alert"
	"github.com/Nikolay1994Kaz/evidencestore/internal/config"
	"github.com/Nikolay1994Kaz/evidencestore/internal/input"
	"github.com/Nikolay1994Kaz/evidencestore/internal/metrics"
	"github.com/Nikolay1994Kaz/evidencestore/internal/pgoutput"
	"github.com/Nikolay1994Kaz/evidencestore/internal/pgrole"
	"github.com/Nikolay1994Kaz/evidencestore/internal/pgtap"
	"github.com/Nikolay1994Kaz/evidencestore/internal/pgundo"
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
	// MCPRoles — роли MCP-серверов (esmcp): только они пишут в Tables; ни
	// одна другая роль со входом не может ими стать. Roles — роли агентов для
	// прямого доступа: только чтение. UndoRoles — роли, которыми откатывает
	// esundo. Роли — второй рубеж (DECISIONS, п. 39–40): по ним -setup-sql
	// выдаёт права, а чья транзакция, решает квитанция шлюза (п. 42). Tables —
	// таблицы ("schema.table") под запись: по ним -setup-sql выдаёт права и
	// собирает публикацию.
	MCPRoles  []string `json:"mcp_roles"`
	Roles     []string `json:"roles"`
	UndoRoles []string `json:"undo_roles"`
	Tables    []string `json:"tables"`
	// Receipts — файлы квитанций шлюзов и их ключи. Транзакция, чей xid
	// назван в подписанном намерении, — действие шлюза: целиком, с
	// до-образами для отката; остальные — отпечатком в пачке: ключи строк и
	// хеши, без строк. Раздела нет — шлюза нет: каждая транзакция целиком, и
	// чья она, записи не говорят.
	Receipts *ReceiptsConfig `json:"receipts"`
	// RequireGateway — тревога not-via-gateway на каждую транзакцию по Tables
	// без намерения шлюза: для базы, где пишет только шлюз.
	RequireGateway bool `json:"require_gateway"`
	// AlertRows — тревога «массовое изменение» от стольких изменений строк в
	// одной транзакции; 0 — не следить.
	AlertRows int            `json:"alert_rows"`
	Canaries  []pgtap.Canary `json:"canaries"`
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
	if len(c.MCPRoles) == 0 {
		errs = append(errs, errors.New("postgres.mcp_roles: name the role of the MCP server; the agent's own role (postgres.roles) is a different one, and only the server writes the tables"))
	}
	seen := map[string]string{}
	for _, l := range []struct {
		name  string
		roles []string
	}{{"mcp_roles", c.MCPRoles}, {"roles", c.Roles}, {"undo_roles", c.UndoRoles}} {
		for _, r := range l.roles {
			// PostgreSQL режет имя до 63 байт и в скрипте, и при входе, а
			// сборщик сравнивает роль сеанса с именем целиком: транзакции
			// такой роли он бы молча пропускал (R2-8).
			if r == "" || len(r) > maxIdent {
				errs = append(errs, fmt.Errorf("postgres.%s: role %q: a name from 1 to %d bytes (PostgreSQL cuts a longer one)", l.name, r, maxIdent))
			}
			if was, ok := seen[r]; ok && was != l.name {
				errs = append(errs, fmt.Errorf("postgres.%s: role %q is in postgres.%s too: the agent, the MCP server and the undo each have a role of their own", l.name, r, was))
			}
			seen[r] = l.name
		}
	}
	if dsn, err := pgwire.ParseDSN(c.DSN); err == nil {
		if _, ok := seen[dsn.User]; ok {
			errs = append(errs, fmt.Errorf("postgres.dsn: the collector's role %q is also a role of the agent, the server or the undo", dsn.User))
		}
	}
	if c.Receipts != nil {
		if err := c.Receipts.validate(); err != nil {
			errs = append(errs, fmt.Errorf("postgres.%w", err))
		}
	} else if c.RequireGateway {
		errs = append(errs, errors.New("postgres.require_gateway needs postgres.receipts: without the gateway's receipts every transaction would be past it"))
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

// EvidenceOwner — владелец функций отметок прежних версий скрипта. Отметок
// больше нет (DECISIONS, п. 42): скрипт убирает его вместе с ними.
const EvidenceOwner = "evidence_owner"

// maxIdent — длина имени в PostgreSQL (NAMEDATALEN − 1).
const maxIdent = 63

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
	p("-- Выполняет суперпользователь: скрипт заводит роли, выдаёт и проверяет права, отзывает у PUBLIC")
	p("-- обрыв чужих сеансов и собирает публикацию. Нужен wal_level = logical (меняется с перезапуском")
	p("-- базы) и предел журнала для слота: max_slot_wal_keep_size. Чья транзакция, решает не база, а")
	p("-- подписанная квитанция шлюза (DECISIONS, п. 42): отметок в журнале и триггеров на таблицах нет.")
	p("BEGIN;")
	p("-- Путь поиска — только pg_catalog: скрипт выполняет владелец, а функция агента с точным")
	p("-- совпадением типов (left(name, integer) в public) выиграла бы у системной при любом порядке")
	p("-- пути. Все имена ниже — со схемой.")
	p("SET LOCAL search_path = pg_catalog, pg_temp;")
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
	p("-- Отметки «кто» и действия прежних версий (функции, ключ и схема evidence у роли evidence_owner,")
	p("-- триггеры evidence_who на таблицах) убираются: из базы «кто» больше не берётся (DECISIONS, п. 42),")
	p("-- а секрет внутри базы видели журнал, копии и роли с REPLICATION (P-322). Снимается только то, чем")
	p("-- владеет evidence_owner: схему evidence с данными приложения скрипт раньше снимал целиком (R2-5).")
	p("-- Схема, где есть объекты других ролей, остаётся у владельца базы. Роль снимается, когда ни одна")
	p("-- база сервера на неё больше не ссылается: прежняя установка могла стоять в нескольких (R2-8).")
	p("-- Право писать сообщения в журнал прежний скрипт забрал у PUBLIC и отдал владельцу отметок — оно")
	p("-- возвращается как было.")
	p("DO $evidence$ DECLARE f regprocedure; t record; o oid; BEGIN")
	p("  SELECT oid INTO o FROM pg_roles WHERE rolname = %s;", lit(EvidenceOwner))
	p("  IF o IS NULL THEN RETURN; END IF;")
	p("  FOR f IN SELECT p.oid::regprocedure FROM pg_proc p")
	p("    WHERE p.proname = 'pg_logical_emit_message' AND p.pronamespace = 'pg_catalog'::regnamespace")
	p("      AND has_function_privilege(o, p.oid, 'EXECUTE') LOOP")
	p("    EXECUTE format('GRANT EXECUTE ON FUNCTION %%s TO PUBLIC', f);")
	p("  END LOOP;")
	p("  FOR t IN SELECT tg.tgname, tg.tgrelid::regclass AS rel FROM pg_trigger tg JOIN pg_proc p ON p.oid = tg.tgfoid")
	p("    WHERE p.proowner = o AND NOT tg.tgisinternal LOOP")
	p("    EXECUTE format('DROP TRIGGER %%I ON %%s', t.tgname, t.rel);")
	p("  END LOOP;")
	p("  -- Объект схемы любого вида (таблица, функция, тип, правило сортировки, словарь поиска, оператор…)")
	p("  -- лежит в pg_depend ссылкой на схему, а владелец его, если это не evidence_owner, — без строки")
	p("  -- владельца на неё в pg_shdepend: так видны все виды, а не три (R2-7 второго захода).")
	p("  IF EXISTS (SELECT FROM pg_namespace n WHERE n.nspname = 'evidence' AND n.nspowner = o) AND EXISTS (")
	p("      SELECT FROM pg_depend d WHERE d.refclassid = 'pg_namespace'::regclass")
	p("        AND d.refobjid = (SELECT n.oid FROM pg_namespace n WHERE n.nspname = 'evidence')")
	p("        AND NOT EXISTS (SELECT FROM pg_shdepend sd WHERE sd.dbid = (SELECT oid FROM pg_database WHERE datname = current_database())")
	p("          AND sd.classid = d.classid AND sd.objid = d.objid AND sd.deptype = 'o' AND sd.refobjid = o)) THEN")
	p("    EXECUTE format('ALTER SCHEMA evidence OWNER TO %%I', (SELECT pg_get_userbyid(datdba) FROM pg_database WHERE datname = current_database()));")
	p("    RAISE WARNING 'evidencestore: schema evidence holds objects of other roles: it stays, and the owner of the database owns it now';")
	p("  END IF;")
	p("  EXECUTE format('DROP OWNED BY %%I', %s);", lit(EvidenceOwner))
	p("  IF EXISTS (SELECT FROM pg_shdepend d WHERE d.refclassid = 'pg_authid'::regclass AND d.refobjid = o")
	p("      AND d.dbid <> 0 AND d.dbid <> (SELECT oid FROM pg_database WHERE datname = current_database())) THEN")
	p("    RAISE WARNING 'evidencestore: role evidence_owner still owns objects or has rights in other databases of this server: run this script there as well; the last one drops the role';")
	p("  ELSE")
	p("    EXECUTE format('DROP ROLE %%I', %s);", lit(EvidenceOwner))
	p("  END IF;")
	p("END $evidence$;")
	p("-- Обрывать и отменять чужие сеансы — только суперпользователям и членам pg_signal_backend.")
	p("-- Сеансы своей роли PostgreSQL даёт обрывать всегда, а SQL агента идёт ролью сервера: так он")
	p("-- обрывал бы сеанс сервера посреди действия или на его COMMIT (R2-6).")
	p("DO $evidence$ DECLARE f regprocedure; BEGIN")
	p("  FOR f IN SELECT p.oid::regprocedure FROM pg_proc p")
	p("    WHERE p.proname IN ('pg_terminate_backend', 'pg_cancel_backend') AND p.pronamespace = 'pg_catalog'::regnamespace LOOP")
	p("    EXECUTE format('REVOKE EXECUTE ON FUNCTION %%s FROM PUBLIC', f);")
	p("    EXECUTE format('GRANT EXECUTE ON FUNCTION %%s TO pg_signal_backend', f);")
	p("  END LOOP;")
	p("END $evidence$;")
	p("")
	// Роли: сервер и откат пишут, агент читает (DECISIONS, п. 39).
	create := func(r string) {
		p("DO $evidence$ BEGIN IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname = %s) THEN CREATE ROLE %s LOGIN; END IF; END $evidence$;", lit(r), id(r))
		for _, s := range schemas {
			p("GRANT USAGE ON SCHEMA %s TO %s;", id(s), id(r))
		}
	}
	timeouts := func(r string) {
		// Таймауты роли — значения по умолчанию для её сессий; у MCP-сервера
		// свои — параметры входа (P-259), здесь — второй рубеж.
		p("ALTER ROLE %s SET statement_timeout = '60s';", id(r))
		p("ALTER ROLE %s SET lock_timeout = '10s';", id(r))
		p("ALTER ROLE %s SET idle_in_transaction_session_timeout = '5min';", id(r))
	}
	var writers []string
	p("-- Роли MCP-серверов: только строки названных таблиц. Ни TRUNCATE, ни владения — значит, ни")
	p("-- TRUNCATE, ни DROP: то, что по записи не вернуть, недоступно и SQL агента.")
	for _, r := range c.MCPRoles {
		writers = append(writers, id(r))
		create(r)
		p("GRANT SELECT, INSERT, UPDATE, DELETE ON %s TO %s;", strings.Join(tables, ", "), id(r))
		timeouts(r)
	}
	p("-- Роли отката (esundo): строки названных таблиц.")
	for _, r := range c.UndoRoles {
		writers = append(writers, id(r))
		create(r)
		p("GRANT SELECT, INSERT, UPDATE, DELETE ON %s TO %s;", strings.Join(tables, ", "), id(r))
	}
	var readers []string
	p("-- Роли агентов для прямого доступа: только чтение. Запись, выданная раньше (до п. 39 агент и")
	p("-- сервер ходили одной ролью), отзывается.")
	for _, r := range c.Roles {
		readers = append(readers, id(r))
		create(r)
		p("GRANT SELECT ON %s TO %s;", strings.Join(tables, ", "), id(r))
		p("REVOKE INSERT, UPDATE, DELETE, TRUNCATE, TRIGGER, REFERENCES ON %s FROM %s;", strings.Join(tables, ", "), id(r))
		timeouts(r)
	}
	// Права на секции — до проверок: старая установка давала роли агента
	// запись и на секциях, и проверка ниже отказала бы вместо перевода (R2-4).
	// Имена ролей попадают в строку формата: знак процента в имени удваивается.
	if len(writers) > 0 || len(readers) > 0 {
		p("DO $evidence$ DECLARE leaf regclass; BEGIN")
		p("  FOR leaf IN SELECT part.relid FROM %s", named)
		p("      JOIN pg_class c ON c.oid = part.relid WHERE part.level > 0 AND c.relkind = 'r' LOOP")
		if len(writers) > 0 {
			p("    EXECUTE format(%s, leaf);", lit("GRANT SELECT, INSERT, UPDATE, DELETE ON %s TO "+strings.ReplaceAll(strings.Join(writers, ", "), "%", "%%")))
		}
		if len(readers) > 0 {
			p("    EXECUTE format(%s, leaf);", lit("GRANT SELECT ON %s TO "+strings.ReplaceAll(strings.Join(readers, ", "), "%", "%%")))
			p("    EXECUTE format(%s, leaf);", lit("REVOKE INSERT, UPDATE, DELETE, TRUNCATE, TRIGGER, REFERENCES ON %s FROM "+strings.ReplaceAll(strings.Join(readers, ", "), "%", "%%")))
		}
		p("  END LOOP;")
		p("END $evidence$;")
	}
	// Проверки ниже. Роли агента и сервера проверяются разрешённым перечнем:
	// всё, что им можно, выдаёт этот скрипт, им самим. Членство в любой роли и
	// владение любым объектом — отказ: через них приходят права, которых
	// скрипт не знает (группа с UPDATE, pg_signal_backend, pg_read_server_files,
	// владелец схемы — R1, R2, T, заход 1 после п. 39). Роли отката членства
	// можно: её SQL — свой, не агента.
	var lits, agents, servers, pairs []string
	for _, r := range slices.Concat(c.Roles, c.MCPRoles, c.UndoRoles) {
		lits = append(lits, lit(r))
	}
	for _, r := range c.Roles {
		agents = append(agents, lit(r))
	}
	for _, r := range c.MCPRoles {
		servers = append(servers, lit(r))
	}
	pairs = slices.Concat(agents, servers)
	agentsOrNull := "NULL"
	if len(agents) > 0 {
		agentsOrNull = strings.Join(agents, ", ")
	}
	as := "CASE WHEN g.oid <> r.oid THEN format(' (as %%I)', g.rolname) ELSE '' END"
	member := "pg_roles r JOIN pg_roles g ON pg_has_role(r.oid, g.oid, 'MEMBER')"
	check := func(comment, query, hint string, args ...any) {
		p("-- %s", comment)
		p("DO $evidence$ DECLARE bad text; BEGIN")
		p("  SELECT string_agg(DISTINCT x, ', ') INTO bad FROM (")
		p(query, args...)
		p("  ) AS rights;")
		p("  IF bad IS NOT NULL THEN")
		p("    RAISE EXCEPTION 'evidencestore: %%', bad USING HINT = %s;", lit(hint))
		p("  END IF;")
		p("END $evidence$;")
	}
	check("Суперпользователь, REPLICATION (удалить слот сборщика) и CREATEROLE (стать кем угодно) — ни у одной из трёх ролей.",
		"    SELECT format('%%I is a superuser, may replicate or create roles', r.rolname) || "+as+" AS x\n"+
			"      FROM "+member+" WHERE r.rolname IN (%s) AND (g.rolsuper OR g.rolreplication OR g.rolcreaterole)\n"+
			// Суперпользователь «член» любой роли: называть его по каждой — шум (R2-6).
			"        AND (g.oid = r.oid OR NOT r.rolsuper)",
		"A role in mcp_roles, roles or undo_roles must be a role of its own, without these attributes: the script creates it and grants it what it needs. "+
			"Take a superuser out of the list and name a new role; ALTER ROLE … NOREPLICATION NOCREATEROLE for the others.",
		strings.Join(lits, ", "))
	// Что роли агента и сервера могут сверх выданного им самим: членства,
	// права через PUBLIC и прямые выдачи (pgrole.Rights) — то же проверяет
	// esmcp на каждом соединении.
	check("Роли агента и сервера могут только выданное им самим: ни членств, ни чужих SECURITY DEFINER, ни того, что\n"+
		"-- initdb или расширение оставили суперпользователям, ни сторонних серверов (pgrole.Rights).",
		"    "+pgrole.Escape(pgrole.Rights(strings.Join(pairs, ", "))), pgrole.Hint)
	check("Ролью сервера не может стать никто другой со входом, кроме суперпользователей.",
		"    SELECT format('%%I can become %%I', x.rolname, m.rolname) AS x\n"+
			"      FROM pg_roles m JOIN pg_roles x ON x.oid <> m.oid AND x.rolcanlogin AND NOT x.rolsuper AND x.rolname <> current_user\n"+
			"        AND pg_has_role(x.oid, m.oid, 'MEMBER')\n"+
			"      WHERE m.rolname IN (%s)",
		"The role of the MCP server must be its own: whoever can become it sets its defaults, ends its sessions "+
			"and writes the tables past the gateway. Revoke the membership.",
		strings.Join(servers, ", "))
	check("Роли агента и сервера ничем не владеют: владелец удаляет и меняет своё мимо журнала (DROP SCHEMA … CASCADE,\n"+
		"-- ALTER DATABASE … SET) и возвращает себе любое право, которое скрипт отзывает (R1-5).",
		"    SELECT format('%%I owns %%s', r.rolname, pg_describe_object(s.classid, s.objid, s.objsubid)) AS x\n"+
			"      FROM pg_shdepend s JOIN pg_roles r ON r.oid = s.refobjid AND s.refclassid = 'pg_authid'::regclass\n"+
			"      CROSS JOIN (SELECT oid FROM pg_database WHERE datname = current_database()) AS db\n"+
			"      WHERE s.deptype = 'o' AND r.rolname IN (%s)\n"+
			"        AND (s.dbid = db.oid OR s.classid = 'pg_database'::regclass AND s.objid = db.oid)\n"+
			// Не в счёт то, что улик не касается и что роль заводит без всяких
			// прав: большие объекты (lo_from_bytea), свои умолчания прав (ALTER
			// DEFAULT PRIVILEGES FOR ROLE себе) и временные объекты сеанса. Иначе
			// агент в любой момент ломал бы повторный запуск скрипта (R2-3, заход 2).
			"        AND s.classid NOT IN ('pg_largeobject'::regclass, 'pg_default_acl'::regclass)\n"+
			"        AND NOT (s.classid = 'pg_class'::regclass AND EXISTS (SELECT FROM pg_class t WHERE t.oid = s.objid AND t.relpersistence = 't'))\n"+
			"        AND NOT (s.classid = 'pg_type'::regclass AND EXISTS (SELECT FROM pg_type t JOIN pg_namespace tn ON tn.oid = t.typnamespace\n"+
			"          WHERE t.oid = s.objid AND (tn.nspname LIKE 'pg\\_temp\\_%%' OR tn.nspname LIKE 'pg\\_toast\\_temp\\_%%')))\n"+
			"        AND NOT (s.classid = 'pg_proc'::regclass AND EXISTS (SELECT FROM pg_proc t JOIN pg_namespace tn ON tn.oid = t.pronamespace\n"+
			"          WHERE t.oid = s.objid AND tn.nspname LIKE 'pg\\_temp\\_%%'))",
		"The owner of an object alters and drops it past the log and may grant itself any right back. "+
			"What a role of the agent or of the server made is not to be trusted: look at it and drop it (DROP OWNED BY <role> drops its objects "+
			"and revokes its rights; this script grants the rights again). Do not REASSIGN it to another role: a SECURITY DEFINER function "+
			"of the agent would run as that role, and its operator would be taken for that role's own.",
		strings.Join(pairs, ", "))
	check("TRUNCATE (строк в журнале нет), TRIGGER (свой триггер пишет правами того, чей оператор его зовёт) и владение\n"+
		"-- таблицей — ни у одной из трёх ролей, ни через PUBLIC, ни через роль, которой она может стать.",
		"    SELECT format('%%I can %%s %%I.%%I', r.rolname, lower(pr.p), n.nspname, c.relname) || "+as+" AS x\n"+
			"      FROM "+member+" CROSS JOIN %s\n"+
			"      JOIN pg_class c ON c.oid = part.relid JOIN pg_namespace n ON n.oid = c.relnamespace\n"+
			"      CROSS JOIN (VALUES ('TRUNCATE'), ('TRIGGER')) AS pr(p)\n"+
			"      WHERE r.rolname IN (%s) AND has_table_privilege(g.oid, c.oid, pr.p)\n"+
			"    UNION ALL SELECT format('%%I owns %%I.%%I', r.rolname, n.nspname, c.relname) || "+as+"\n"+
			"      FROM "+member+" CROSS JOIN %s\n"+
			"      JOIN pg_class c ON c.oid = part.relid JOIN pg_namespace n ON n.oid = c.relnamespace\n"+
			"      WHERE r.rolname IN (%s) AND c.relowner = g.oid",
		"With these rights rows go past the log (TRUNCATE), a trigger of the role's own writes in the name of whoever fires it (TRIGGER), "+
			"or the table is altered past the log (ownership). Revoke them, from PUBLIC too; the undo role is not the owner of the tables.",
		named, strings.Join(lits, ", "), named, strings.Join(lits, ", "))
	if len(agents) > 0 {
		// Право на колонку has_table_privilege не видит (R1-1, R2-2, T-4); вид над
		// таблицей пишет в неё правами своего владельца (R1-1) — и вид над видом.
		check("Агент своей ролью не пишет — ни в таблицы, ни в их колонки, ни через виды над ними, ни через PUBLIC.",
			"    WITH RECURSIVE over(oid) AS (SELECT part.relid FROM %s\n"+
				"      UNION SELECT rw.ev_class FROM pg_rewrite rw JOIN pg_depend d ON d.classid = 'pg_rewrite'::regclass AND d.objid = rw.oid\n"+
				"        AND d.refclassid = 'pg_class'::regclass JOIN over o ON o.oid = d.refobjid)\n"+
				"    SELECT format('%%I can %%s %%I.%%I', r.rolname, lower(pr.p), n.nspname, c.relname) AS x\n"+
				"      FROM pg_roles r CROSS JOIN over JOIN pg_class c ON c.oid = over.oid JOIN pg_namespace n ON n.oid = c.relnamespace\n"+
				"      CROSS JOIN (VALUES ('INSERT'), ('UPDATE'), ('DELETE')) AS pr(p)\n"+
				"      WHERE r.rolname IN (%s) AND CASE WHEN pr.p = 'DELETE' THEN has_table_privilege(r.oid, c.oid, pr.p) ELSE has_any_column_privilege(r.oid, c.oid, pr.p) END",
			"The agent writes only through the MCP server, and the server has a role of its own. Revoke the right from the agent role and from PUBLIC "+
				"(a right on a column too: REVOKE UPDATE (col) …; a view over the table too).",
			named, agentsOrNull)
	}
	// Умолчания прав (ALTER DEFAULT PRIVILEGES): выданное ими получит и
	// секция, созданная после скрипта (R2-3).
	check("Умолчания прав на новые таблицы: агенту — ни записи, никому из трёх ролей — ни TRUNCATE, ни TRIGGER.",
		"    SELECT format('%%I gets %%s on new tables (default privileges of %%I%%s)', r.rolname, a.privilege_type, pg_get_userbyid(d.defaclrole),\n"+
			"        CASE WHEN d.defaclnamespace <> 0 THEN format(' in schema %%s', d.defaclnamespace::regnamespace) ELSE '' END)\n"+
			"        || CASE WHEN a.grantee = 0 THEN ' (as PUBLIC)' WHEN a.grantee <> r.oid THEN format(' (as %%I)', pg_get_userbyid(a.grantee)) ELSE '' END AS x\n"+
			"      FROM pg_roles r CROSS JOIN pg_default_acl d CROSS JOIN LATERAL aclexplode(d.defaclacl) a\n"+
			"      WHERE r.rolname IN (%s) AND d.defaclobjtype = 'r' AND (a.grantee = 0 OR pg_has_role(r.oid, a.grantee, 'MEMBER'))\n"+
			"        AND (a.privilege_type IN ('TRUNCATE', 'TRIGGER') OR r.rolname IN (%s) AND a.privilege_type IN ('INSERT', 'UPDATE', 'DELETE'))",
		"A partition or table created later would get these rights without this script: the agent could write it, or rows would go past the log. "+
			"ALTER DEFAULT PRIVILEGES … REVOKE them.",
		strings.Join(lits, ", "), agentsOrNull)
	// Своих объектов заводить нельзя: DDL в журнал не идёт, а функция или
	// оператор под системным именем в схеме из пути заслонили бы системные
	// (P-242). PostgreSQL 14 и старше даёт PUBLIC CREATE на схеме public.
	check("Роли агента и сервера своих объектов не заводят: ни CREATE на схеме, ни CREATE в базе. Роли отката можно:\n"+
		"-- её объекты сверка и откат и так считают своими.",
		"    SELECT format('%%I can CREATE in schema %%I', r.rolname, n.nspname) || "+as+" AS x\n"+
			"      FROM "+member+" CROSS JOIN pg_namespace n\n"+
			"      WHERE r.rolname IN (%s) AND left(n.nspname, 3) <> 'pg_' AND n.nspname <> 'information_schema'\n"+
			"        AND has_schema_privilege(g.oid, n.oid, 'CREATE')\n"+
			"    UNION ALL SELECT format('%%I can CREATE schemas in this database', r.rolname) || "+as+"\n"+
			"      FROM "+member+" WHERE r.rolname IN (%s) AND has_database_privilege(g.oid, current_database(), 'CREATE')",
		"Their DDL is not in the database log, and a function or operator of their own named like a system one would stand in for it. "+
			"REVOKE CREATE ON SCHEMA … FROM PUBLIC (or from the role, if the role is not the owner: an owner is refused above); "+
			"PostgreSQL 14 and older grant it on schema public to PUBLIC.",
		strings.Join(pairs, ", "), strings.Join(pairs, ", "))
	p("-- С PostgreSQL 15 право на параметр выдают отдельно: SET session_replication_role = replica")
	p("-- выключает триггеры и внешние ключи (R1, R2, заход 3); track_counts = off — счёт строк (R1-6).")
	p("DO $evidence$ DECLARE bad text; BEGIN")
	p("  IF current_setting('server_version_num')::int < 150000 THEN RETURN; END IF;")
	p("  EXECUTE $q$SELECT string_agg(DISTINCT x, ', ') FROM (%s) AS rights$q$ INTO bad;", pgrole.Params(strings.Join(lits, ", ")))
	p("  IF bad IS NOT NULL THEN")
	p("    RAISE EXCEPTION 'evidencestore: %%', bad USING HINT =")
	p("      'With such a parameter the SQL switches off triggers and foreign keys (session_replication_role), the row count (track_counts) or the server settings. Revoke it.';")
	p("  END IF;")
	p("END $evidence$;")
	p("")
	p("-- Таблицы и их секции: старая строка в журнал целиком. Изменения секции идут в журнал под её")
	p("-- именем, и старую строку пишет она. Секцию, созданную позже, этот скрипт не знает: после неё его")
	p("-- выполняют снова (сборщик при подключении называет таблицы без REPLICA IDENTITY FULL).")
	for _, t := range tables {
		p("ALTER TABLE %s REPLICA IDENTITY FULL;", t)
	}
	p("DO $evidence$ DECLARE leaf regclass; BEGIN")
	p("  FOR leaf IN SELECT part.relid FROM %s", named)
	p("      JOIN pg_class c ON c.oid = part.relid WHERE part.level > 0 AND c.relkind = 'r' LOOP")
	p("    EXECUTE format('ALTER TABLE %%s REPLICA IDENTITY FULL', leaf);")
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
	// Confirmed — последняя позиция, которую сборщик подтвердил серверу:
	// пишется до подтверждения. Слот дальше неё — его сдвинул кто-то другой
	// (T-3).
	Confirmed string `json:"confirmed,omitempty"`
	// System и Timeline — чья база и какая её линия времени (IDENTIFY_SYSTEM):
	// другая — база ушла назад или её место заняла реплика (R2-1).
	System   string `json:"system,omitempty"`
	Timeline string `json:"timeline,omitempty"`
	// Rewound и RewoundStart — место сборщика, от которого вход уже отступил
	// назад, и запуск базы (микросекунды), у которой он это увидел: тот же
	// откат после перезапуска не называется второй раз, а база, поднятая из
	// копии снова (другой запуск, место то же), — называется (T-1 третьего
	// захода: второй подъём подряд глушился, и намерение из первой поднятой
	// базы решало чужую транзакцию во второй).
	Rewound      string `json:"rewound,omitempty"`
	RewoundStart int64  `json:"rewound_start,omitempty"`
	// XID8 — старший номер транзакции с эпохой, прочитанный в потоке: база,
	// которая выдаст следующим номер не выше, ушла назад, даже если её
	// журнал уже за местом сборщика (T-1 второго захода).
	XID8 uint64 `json:"xid8,omitempty"`
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

	// receipts — квитанции шлюза: намерения для pgtap и тревоги по исходам
	// (nil — раздела receipts нет).
	receipts *receipts
	// known — slot.json; persisted — Confirmed из него: до какой позиции
	// подтверждать серверу можно, не дописав файла.
	known     slotState
	persisted pgwire.LSN
	// next8 — номер, который база выдаст следующим, на миг подключения: по
	// нему 32-битный xid потока — с эпохой; xid8 — старший из них.
	next8, xid8 uint64
	// knownLost — slot.json не было, а сборщик эту базу уже читал: сдвинут
	// ли слот, пока его не было, не сказать (T-7 второго захода).
	knownLost bool
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
	// slot.json — раз, при запуске: испорченный — ясная ошибка, а не
	// ежесекундная ложная тревога db-down на каждом подключении (T-7).
	knownPath := filepath.Join(s.cfg.Dir, SlotFile)
	if data, err := os.ReadFile(knownPath); err == nil {
		if err := json.Unmarshal(data, &s.known); err != nil {
			return fmt.Errorf("%s: %w", knownPath, err)
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	} else if cursor != 0 {
		s.knownLost = true
	}
	s.persisted, _ = pgwire.ParseLSN(s.known.Confirmed)
	s.xid8 = s.known.XID8
	cfg := pgtap.Config{Dir: s.cfg.Dir, AlertRows: s.cfg.AlertRows, RequireGateway: s.cfg.RequireGateway, Canaries: s.cfg.Canaries, PartSize: s.partSize,
		Diverged: s.diverged}
	if s.cfg.Receipts != nil {
		// Тревоги по квитанциям идут в тот же файл тревог, что и о транзакциях.
		if s.receipts, err = openReceipts(*s.cfg.Receipts, s.cfg.Dir, func(ev alert.Event) error { return s.tap.Raise(ev) }); err != nil {
			return err
		}
		cfg.Intents = s.receipts
	}
	if s.tap, err = pgtap.Open(cfg, catalog{s}, counted{s}, cursor, s.log); err != nil {
		if s.receipts != nil {
			s.receipts.close()
		}
		return err
	}
	if s.receipts != nil {
		// Файл квитанций — с начала: намерения для транзакций, которые база
		// пришлёт заново, и тревоги об исходах, которых ещё не было.
		return s.receipts.poll()
	}
	return nil
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
	// Путь обоих соединений — только pg_catalog (и pg_temp последним):
	// format_type называет тогда любой тип не из pg_catalog со схемой, а поток
	// так же пишет значения regclass, regtype и подобных — откат читает их с
	// путём своего сеанса, и имя без схемы там нашлось бы не то (R2 заход 2,
	// R1 заход 3).
	// TimeZone и bytea_output — ещё и ради хеша отпечатка: текст значения не
	// зависит от умолчаний сервера, базы и роли, и строку из бэкапа сверяют с
	// ним в сеансе с теми же настройками (README; R2-4, T-4). DateStyle,
	// IntervalStyle и extra_float_digits ставит pgwire у любого соединения.
	pinned := map[string]string{"search_path": "pg_catalog, pg_temp", "TimeZone": "UTC", "bytea_output": "hex"}
	catDSN := s.dsn
	catDSN.Params = pinned
	cat, err := pgwire.Dial(ctx, catDSN)
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
	rdsn.Params = pinned
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
	// Сообщений журнала (messages) вход не просит: чья транзакция, говорит
	// квитанция шлюза, а не база (DECISIONS, п. 42).
	// Пачка отпечатков, прочитанная до обрыва, — в буфер сейчас: эти
	// транзакции целы, а слота, от которого сервер прислал бы их снова, после
	// переключения на реплику может уже не быть (T-8 второго захода). Сервер
	// всё равно пришлёт их — повтором (resend.go).
	if _, err := s.tap.Flush(); err != nil {
		repl.Close()
		return err
	}
	from, err := s.identify(cat, repl, start)
	if err != nil {
		repl.Close()
		return err
	}
	if err := repl.StartReplication(s.cfg.Slot, from, "proto_version", "1", "publication_names", s.cfg.Publication); err != nil {
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
	receipts := "none: every transaction whole"
	if s.cfg.Receipts != nil {
		receipts = strings.Join(s.cfg.Receipts.Files, ", ")
	}
	s.log.Info("reading the database log", "slot", s.cfg.Slot, "publication", s.cfg.Publication, "from", start.String(), "gateway receipts", receipts)
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
	known := s.known
	name := pgwire.Literal(s.cfg.Slot)
	row, exists, err := cat.QueryRow("SELECT plugin, wal_status, confirmed_flush_lsn FROM pg_replication_slots WHERE slot_name = " + name)
	if err != nil {
		return 0, err
	}
	lost, moved := "", false
	confirmed, _ := pgwire.ParseLSN(known.Confirmed)
	var at pgwire.LSN
	if exists && row[2] != nil {
		at, _ = pgwire.ParseLSN(*row[2])
	}
	switch {
	case exists && (row[0] == nil || *row[0] != "pgoutput"):
		return 0, fmt.Errorf("replication slot %s exists, but it is not a pgoutput slot", s.cfg.Slot)
	case exists && row[1] != nil && *row[1] == "lost":
		lost = "the server removed the log that replication slot " + s.cfg.Slot + " had not read yet (max_slot_wal_keep_size): changes made meanwhile are lost"
	case !exists && (known.Slot == s.cfg.Slot || s.knownLost):
		s.knownLost = false // пропуск назван; слот дальше — свой (R2-5 третьего захода)
		lost = "replication slot " + s.cfg.Slot + " is gone from the server: changes made since the collector last read are lost"
	case exists && known.Slot == s.cfg.Slot && confirmed != 0 && at > confirmed && at > pgwire.LSN(s.tap.Cursor()):
		// Слот ушёл дальше, чем сборщик ему подтверждал: пока сборщик не был
		// подключён, его сдвинули (pg_replication_slot_advance ролью с
		// REPLICATION) или пересоздали. Транзакций между ними сервер уже не
		// пришлёт, и без этой проверки они пропадали без следа (T-3). Не
		// дальше места сборщика — ничего не потеряно, как бы слот туда ни
		// попал (slot.json из старой копии каталога).
		lost = fmt.Sprintf("replication slot %s was moved past where the collector had confirmed it (from %s to %s) while the collector was not connected: "+
			"a role with REPLICATION advanced or re-created it, and the changes made in between are lost", s.cfg.Slot, confirmed, at)
		moved = true
	case s.knownLost && exists:
		s.knownLost = false
		s.raise(alert.KindSlotUnknown, fmt.Sprintf("the collector's %s is gone, and the store holds this source up to %s: whether replication slot %s (now at %s) was moved while the collector was away cannot be told — "+
			"if it was, the changes made in between are lost without a gap in the store", SlotFile, pgwire.LSN(s.tap.Cursor()), s.cfg.Slot, at))
	}
	if lost != "" {
		// Сначала пропуск — в буфер, потом новый слот: упасть между ними —
		// пропуск запишется второй раз, но не пропадёт.
		if err := s.sink.Gap(lost); err != nil {
			s.sinkErr = err
			return 0, err
		}
		s.raise(alert.KindGap, lost+": the store records a gap in the numbering of this source")
		// Сдвинутый слот читается дальше, от своего места: пересоздать его —
		// потерять ещё и всё, что база записала с его сдвига до этого мига
		// (R2-1 второго захода). Пересоздаётся только слот, чей журнал стёрт.
		if exists && !moved {
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
		known = slotState{Slot: s.cfg.Slot}
	}
	// Отсюда сервер шлёт: это место сборщику подтверждено (новый слот или
	// пропуск уже назван).
	if row != nil && row[2] != nil {
		if at, err := pgwire.ParseLSN(*row[2]); err == nil && (lost != "" || at > confirmed) {
			known.Confirmed = at.String()
		}
	}
	s.known = known
	if err := s.saveKnown(); err != nil {
		return 0, err
	}
	if r, _, err := cat.QueryRow("SHOW max_slot_wal_keep_size"); err == nil && *r[0] == "-1" {
		s.log.Warn("max_slot_wal_keep_size is unlimited: while this collector is down the server keeps its log for the slot without a bound")
	}
	if row == nil || row[2] == nil {
		return 0, nil
	}
	return pgwire.ParseLSN(*row[2])
}

// saveKnown пишет slot.json.
func (s *Source) saveKnown() error {
	s.known.XID8 = s.xid8
	s.persisted, _ = pgwire.ParseLSN(s.known.Confirmed)
	return writeFile(filepath.Join(s.cfg.Dir, SlotFile), s.known)
}

// identify сверяет, та ли это база и та ли её линия времени, и не ушла ли
// она назад от места сборщика (R2-1, R2-2, T-7). Ушла — поднята из копии или
// её место заняла отставшая реплика: всё, что сборщик прочёл после конца её
// журнала, в ней больше нет, номера транзакций, названные в намерениях
// шлюза, она выдаст снова другим транзакциям, а свои новые транзакции —
// с позициями ниже места сборщика, которые раньше пропускались как повторы.
// Тогда намерения до сих пор — не в счёт, вход читает от слота заново, и
// людям — тревога. from — откуда просить поток; next8 — номер транзакции,
// который база выдаст следующим.
func (s *Source) identify(cat, repl *pgwire.Conn, slotAt pgwire.LSN) (from pgwire.LSN, err error) {
	row, ok, err := repl.QueryRow("IDENTIFY_SYSTEM")
	if err != nil {
		return 0, fmt.Errorf("IDENTIFY_SYSTEM: %w", err)
	}
	if !ok || len(row) < 3 || row[0] == nil || row[1] == nil || row[2] == nil {
		return 0, errors.New("IDENTIFY_SYSTEM: no answer")
	}
	system, timeline := *row[0], *row[1]
	end, err := pgwire.ParseLSN(*row[2])
	if err != nil {
		return 0, fmt.Errorf("IDENTIFY_SYSTEM: %w", err)
	}
	var next8 uint64
	if r, ok, err := cat.QueryRow("SELECT pg_snapshot_xmax(pg_current_snapshot())::text"); err != nil {
		return 0, err
	} else if ok && r[0] != nil {
		next8, _ = strconv.ParseUint(*r[0], 10, 64)
	}
	cursor := pgwire.LSN(s.tap.Cursor())
	var why string
	switch {
	case s.known.System != "" && system != s.known.System:
		why = fmt.Sprintf("this is another database cluster (system %s, the collector read %s)", system, s.known.System)
	case cursor != 0 && end < cursor:
		why = fmt.Sprintf("its log ends at %s, and the collector has read up to %s: it was restored from a copy, or a replica that lagged behind took over", end, cursor)
	case s.known.Timeline != "" && timeline != s.known.Timeline:
		why = fmt.Sprintf("its timeline is %s, and the collector read timeline %s: a replica took over", timeline, s.known.Timeline)
	case next8 != 0 && s.xid8 != 0 && next8 <= s.xid8:
		why = fmt.Sprintf("the next transaction number it gives is %d, and the collector has read transaction %d: it was restored from a copy, or a replica that lagged behind took over", next8, s.xid8)
	}
	// Поток — всегда от слота, а не от места сборщика: база, поднятая из
	// копии, пишет новые транзакции на места журнала, которые сборщик уже
	// прочёл, и по месту сервер бы их не прислал (T-1, R2-3 второго захода).
	// Повторы того, что уже в буфере, pgtap узнаёт по справочнику.
	from = slotAt
	s.next8 = next8
	if err := s.tap.Resume(uint64(slotAt), why != ""); err != nil {
		return 0, err
	}
	started := dbStarted(cat)
	if why != "" && (cursor.String() != s.known.Rewound || started != s.known.RewoundStart) {
		v := s.voidSpec(cat, uint64(cursor), started, cursor.String() == s.known.Rewound)
		if s.receipts != nil {
			if err := s.receipts.void(v); err != nil {
				return 0, err
			}
		}
		s.raise(alert.KindRewound, "the database went back: "+why+". Whatever the collector read past the end of its log is no longer in it (the store keeps it); "+
			voidText(v)+"; the collector reads again from replication slot "+s.cfg.Slot+" ("+slotAt.String()+"), and a transaction it already has is not recorded twice")
		s.known.Rewound, s.known.RewoundStart = cursor.String(), started
	}
	if why != "" {
		s.xid8 = 0 // номера с эпохой — с этой базы заново
		if s.receipts != nil {
			s.receipts.ref8 = next8
		}
	} else if s.receipts != nil {
		s.receipts.setRef(next8)
	}
	s.known.System, s.known.Timeline = system, timeline
	return from, s.saveKnown()
}

// diverged — pgtap.Config.Diverged: в потоке ниже места сборщика транзакция,
// которой у него на этом месте нет. База ушла назад, а её журнал успел уйти
// за место сборщика, пока его не было: по концу журнала при подключении
// этого не видно (T-1 второго захода). Дальше — как при подъёме, увиденном
// при подключении: намерения шлюза до сих пор не в счёт, людям — тревога.
func (s *Source) diverged(xid uint32, final, place uint64) error {
	started := dbStarted(s.cat)
	v := s.voidSpec(s.cat, place, started, pgwire.LSN(place).String() == s.known.Rewound)
	if s.receipts != nil {
		if err := s.receipts.void(v); err != nil {
			return err
		}
		s.receipts.ref8 = s.next8
	}
	s.xid8 = 0
	if s.known.Rewound != pgwire.LSN(place).String() || s.known.RewoundStart != started {
		s.raise(alert.KindRewound, fmt.Sprintf("the database went back: transaction %d committed at %s, below the place the collector has read up to (%s), is not the transaction it read there — "+
			"it was restored from a copy, or a replica that lagged behind took over, and its log went past the collector's place before the collector connected. "+
			"Whatever the collector read past the end of its copy is no longer in it (the store keeps it); %s; the database's new transactions are recorded from here",
			xid, pgwire.LSN(final), pgwire.LSN(place), voidText(v)))
		s.known.Rewound, s.known.RewoundStart = pgwire.LSN(place).String(), started
	}
	return s.saveKnown()
}

// voidText — что тревога db-rewound говорит о намерениях шлюза.
func voidText(v voidSpec) string {
	if v.since.IsZero() {
		return "the gateway's intents written so far are void, because the database gives their transaction numbers to other transactions again: " +
			"transactions of the gateway made since it went back come as fingerprints"
	}
	return "the gateway's intents written in the database before it went back are void, because it gives their transaction numbers to other transactions again " +
		"(by the start of the database in the intent; for intents without it — those written before the database started again, " + v.since.UTC().Format(time.RFC3339) +
		"); the gateway's actions in the database since then stay actions"
}

// dbStarted — когда запущена база (pg_postmaster_start_time), микросекунды;
// 0 — не узнать.
func dbStarted(cat *pgwire.Conn) int64 {
	if cat == nil {
		return 0
	}
	row, ok, err := cat.QueryRow("SELECT " + pgundo.StartedSQL)
	if err != nil || !ok || row[0] == nil {
		return 0
	}
	us, _ := strconv.ParseInt(*row[0], 10, 64)
	return us
}

// voidSpec — что снять, когда база ушла назад, а последняя транзакция её
// прежней истории, прочитанная сборщиком, — на месте place; started — запуск
// базы сейчас (микросекунды). again — на этом месте база уже уходила назад,
// а сейчас это другой её запуск: её снова подняли из копии (или прежнюю
// поднятую перезапустили, а сборщик с тех пор ничего не прочёл — не
// отличить): не в счёт всё, что писалось не в нынешнем запуске.
func (s *Source) voidSpec(cat *pgwire.Conn, place uint64, started int64, again bool) voidSpec {
	v := voidSpec{}
	last, known := s.tap.PlaceTime(place)
	switch {
	case known && !again:
		// Намерение, чья база запущена не позже последней транзакции прежней
		// истории, — из прежней истории: её база тогда уже шла.
		v.startedBefore = last.UnixMicro()
		if t := time.UnixMicro(started); started != 0 && t.After(last) {
			v.since = t // база запущена после неё: копия, поднятая после
		}
	case started != 0:
		// Снова на том же месте (again) или время места не узнать: не в
		// счёт всё, что писалось не в нынешнем запуске.
		v.startedBefore = started - 1
	default:
		v.startedBefore = math.MaxInt64 - 1
	}
	return v
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
	if err := os.Rename(tmp, path); err != nil {
		return err
	}
	// Без fsync каталога переименование после пропажи питания может
	// откатиться: в slot.json — прежняя позиция, и сборщик принял бы свои же
	// подтверждения за сдвиг слота чужой рукой (R2-1 второго захода).
	return syncDir(filepath.Dir(path))
}

// syncDir — fsync каталога: переименование в нём легло на диск.
func syncDir(dir string) error {
	d, err := os.Open(dir)
	if err != nil {
		return err
	}
	defer d.Close()
	return d.Sync()
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
	if s.flushed > s.persisted {
		// Сначала на диск, потом серверу: слот дальше записанного — значит,
		// его сдвинул не сборщик (T-3).
		s.known.Confirmed = s.flushed.String()
		if err := s.saveKnown(); err != nil {
			return err
		}
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
		if !s.tap.InTransaction() && !s.tap.Pending() && m.WALEnd > s.flushed {
			s.flushed = m.WALEnd
		}
		return false, s.report(m.ReplyRequested)
	}
	msg, err := pgoutput.Parse(m.Data)
	if err != nil {
		return false, fmt.Errorf("at %s: %w", m.WALStart, err)
	}
	if b, ok := msg.(pgoutput.Begin); ok && s.next8 != 0 {
		s.xid8 = max(s.xid8, fullXID(s.next8, b.XID))
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
//
// final — разовый проход (-once): в его конце в буфер идёт и неполная пачка
// отпечатков. У постоянного сборщика пачка ждёт, пока ей не станет PackWait
// (Tick), — иначе при редких правках каждая шла бы своей записью.
func (s *Source) pump(stop func(idle, inTx bool) bool, final bool) error {
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
		if idle && !inTx && s.receipts != nil {
			// Квитанции шлюза — и без транзакций в потоке: отказ действия
			// пределом в базе ничего не меняет, а людям о нём сказать надо.
			if err := s.receipts.poll(); err != nil {
				return err
			}
		}
		if idle && !inTx {
			// Поток молчит: пачка отпечатков, которая ждёт дольше PackWait, — в
			// буфер. У -once — любая: проход ждёт её позиции, чтобы закончиться.
			flush := s.tap.Tick
			if final {
				flush = s.tap.Flush
			}
			done, err := flush()
			if err != nil {
				return err
			}
			if done != 0 {
				s.flushed = max(s.flushed, pgwire.LSN(done))
			}
		}
		if idle && inTx {
			// Сервер молчит посреди транзакции: сказать ему, что мы живы.
			if err := s.report(true); err != nil {
				return err
			}
		}
		if stop(idle, inTx) {
			if !inTx {
				// Конец прохода: пачка, которой пора, — в буфер; у -once — любая.
				flush := s.tap.Tick
				if final {
					flush = s.tap.Flush
				}
				done, err := flush()
				if err != nil {
					return err
				}
				if done != 0 {
					s.flushed = max(s.flushed, pgwire.LSN(done))
				}
			}
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
			metrics.One("escollect_postgres_transactions_captured_total", "transactions put into the spool whole since the collector started: the gateway's actions, or every one without postgres.receipts", metrics.Counter, float64(st.Captured)),
			metrics.One("escollect_postgres_row_changes_total", "row changes of whole transactions put into the spool since the collector started", metrics.Counter, float64(st.Changes)),
			metrics.One("escollect_postgres_transactions_fingerprinted_total", "transactions without the gateway's intent kept as fingerprints since the collector started", metrics.Counter, float64(st.Fingerprinted)),
			metrics.One("escollect_postgres_fingerprint_packs_total", "records of fingerprint packs put into the spool since the collector started", metrics.Counter, float64(st.Packs)),
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
	if err := s.pump(func(idle, inTx bool) bool { return idle || !inTx && time.Since(start) >= passBudget }, false); err != nil {
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
	}, true)
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
	s.log.Info("database input closed", "captured", st.Captured, "fingerprinted", st.Fingerprinted, "packs", st.Packs, "changes", st.Changes, "parts", st.Parts, "alerts", st.Alerts)
	if s.receipts != nil {
		s.receipts.close()
	}
	return s.tap.Close()
}

// SetLogger меняет журнал входа (до первого чтения).
func (s *Source) SetLogger(log *slog.Logger) {
	s.log = log
	if s.tap != nil {
		s.tap.SetLogger(log)
	}
}
