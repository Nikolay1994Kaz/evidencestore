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

	"github.com/Nikolay1994Kaz/evidencestore/internal/config"
	"github.com/Nikolay1994Kaz/evidencestore/internal/input"
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
}

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
	p("-- evidencestore: настройка базы под запись до-образов (escollect -setup-sql).")
	p("-- Выполняет владелец таблиц или суперпользователь. Нужен wal_level = logical")
	p("-- (меняется с перезапуском базы) и предел журнала для слота: max_slot_wal_keep_size.")
	p("BEGIN;")
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
	var schemas, tables []string
	for _, t := range c.Tables {
		s, n, err := splitTable(t)
		if err != nil {
			return "", err
		}
		if !slices.Contains(schemas, s) {
			schemas = append(schemas, s)
		}
		tables = append(tables, id(s)+"."+id(n))
	}
	for _, r := range c.Roles {
		p("DO $evidence$ BEGIN IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname = %s) THEN CREATE ROLE %s LOGIN; END IF; END $evidence$;", lit(r), id(r))
		for _, s := range schemas {
			p("GRANT USAGE ON SCHEMA %s TO %s;", id(s), id(r))
		}
		p("GRANT SELECT, INSERT, UPDATE, DELETE ON %s TO %s;", strings.Join(tables, ", "), id(r))
		p("GRANT USAGE ON SCHEMA evidence TO %s;", id(r))
		p("GRANT EXECUTE ON FUNCTION evidence.mark_action(json), evidence.mark_undo(json) TO %s;", id(r))
	}
	p("")
	p("-- Таблицы: старая строка в журнал целиком, отметка «кто» перед каждым оператором.")
	for _, t := range tables {
		p("ALTER TABLE %s REPLICA IDENTITY FULL;", t)
		p("DROP TRIGGER IF EXISTS evidence_who ON %s;", t)
		p("CREATE TRIGGER evidence_who BEFORE INSERT OR UPDATE OR DELETE OR TRUNCATE ON %s", t)
		p("  FOR EACH STATEMENT EXECUTE FUNCTION evidence.mark_who();")
	}
	p("")
	p("-- Публикация: в поток репликации идут только эти таблицы.")
	p("DROP PUBLICATION IF EXISTS %s;", id(c.Publication))
	p("CREATE PUBLICATION %s FOR TABLE %s;", id(c.Publication), strings.Join(tables, ", "))
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
	s.cat, s.repl = cat, repl
	start = max(start, from)
	s.flushed, s.reported, s.lastReport = start, start, time.Now()
	s.backoff, s.retryAt = 0, time.Time{}
	s.log.Info("reading the database log", "slot", s.cfg.Slot, "publication", s.cfg.Publication, "from", start.String(), "roles", strings.Join(s.cfg.Roles, ","))
	return nil
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

// Read — input.Input: один проход без ожидания.
func (s *Source) Read() (int, error) {
	s.emitted = 0
	if s.repl == nil {
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
	return s.emitted, nil
}

// ReadAll — input.Input: всё, что было в журнале базы к моменту вызова.
func (s *Source) ReadAll(ctx context.Context) (int, error) {
	s.emitted = 0
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
