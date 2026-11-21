// espgtap — сборщик до-образов из PostgreSQL для хранилища улик.
//
// Читает журнал базы через логическую репликацию (встроенный плагин pgoutput),
// берёт транзакции наблюдаемых ролей (ИИ-агентов) и транзакции отката и пишет
// их сжатыми записями в journal.jsonl (internal/pgtap). Этот файл читает
// обычный escollect и везёт в хранилище как источник с "subject_field": "xid".
// Позиция подтверждается базе только после fsync журнала: если сборщик стоит,
// база держит свой журнал для слота, но не дольше max_slot_wal_keep_size.
//
//	espgtap -config pgtap.json -setup-sql   # SQL настройки базы: показать DBA и выполнить
//	espgtap -config pgtap.json              # работать
package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"os"
	"os/signal"
	"path/filepath"
	"slices"
	"strings"
	"syscall"
	"time"

	"github.com/Nikolay1994Kaz/evidencestore/internal/config"
	"github.com/Nikolay1994Kaz/evidencestore/internal/pgoutput"
	"github.com/Nikolay1994Kaz/evidencestore/internal/pgtap"
	"github.com/Nikolay1994Kaz/evidencestore/internal/pgwire"
	"github.com/Nikolay1994Kaz/evidencestore/internal/version"
)

// Config — настройки сборщика.
type Config struct {
	// DSN — подключение к базе ролью с правом REPLICATION:
	// "host=db port=5432 user=evidence_tap dbname=shop sslmode=verify-full".
	// Пароль — здесь или в PGPASSWORD.
	DSN         string `json:"dsn"`
	Slot        string `json:"slot"`        // слот репликации; по умолчанию evidence_tap
	Publication string `json:"publication"` // публикация; по умолчанию evidence_pub
	Dir         string `json:"dir"`         // каталог журнала
	// Roles — роли агентов: их транзакции идут в журнал. Tables — таблицы
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

func loadConfig(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var c Config
	dec := json.NewDecoder(strings.NewReader(string(data)))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&c); err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	if c.Slot == "" {
		c.Slot = "evidence_tap"
	}
	if c.Publication == "" {
		c.Publication = "evidence_pub"
	}
	if c.StatusEvery == 0 {
		c.StatusEvery = config.Duration(5 * time.Second)
	}
	if c.Dir == "" {
		c.Dir = "pgtap"
	}
	if !filepath.IsAbs(c.Dir) {
		c.Dir = filepath.Join(filepath.Dir(path), c.Dir)
	}
	var errs []error
	if c.DSN == "" {
		errs = append(errs, errors.New("dsn is required"))
	}
	if len(c.Roles) == 0 {
		errs = append(errs, errors.New("roles: name at least one agent role"))
	}
	if len(c.Tables) == 0 {
		errs = append(errs, errors.New("tables: name at least one table"))
	}
	for _, t := range c.Tables {
		if _, _, err := splitTable(t); err != nil {
			errs = append(errs, err)
		}
	}
	if d := c.StatusEvery.D(); d < time.Second || d > 30*time.Second {
		errs = append(errs, fmt.Errorf("status_every %v: from 1s to 30s (the server drops a silent client after wal_sender_timeout)", d))
	}
	if err := errors.Join(errs...); err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	return &c, nil
}

func splitTable(t string) (schema, table string, err error) {
	schema, table, ok := strings.Cut(t, ".")
	if !ok || schema == "" || table == "" || strings.Contains(table, ".") {
		return "", "", fmt.Errorf("table %q: write it as schema.table", t)
	}
	return schema, table, nil
}

// setupSQL — настройка базы под журнал до-образов. Скрипт не исполняется
// сборщиком: его читает и запускает владелец таблиц.
func setupSQL(c *Config, tapRole string) string {
	var b strings.Builder
	p := func(format string, args ...any) { fmt.Fprintf(&b, format+"\n", args...) }
	lit, id := pgwire.Literal, pgwire.Ident
	p("-- evidencestore: настройка базы под журнал до-образов (espgtap -setup-sql).")
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
	p("-- значит, ни TRUNCATE, ни DROP: то, что по журналу не вернуть, агенту недоступно.")
	var schemas, tables []string
	for _, t := range c.Tables {
		s, n, _ := splitTable(t)
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
	return b.String()
}

// catalog отвечает сборщику на вопросы о таблицах по обычному соединению.
type catalog struct{ c *pgwire.Conn }

func (k catalog) Describe(rel pgoutput.Relation) (pgtap.RelInfo, error) {
	var info pgtap.RelInfo
	if len(rel.Columns) > 0 {
		// Имена типов — по OID и модификатору из самого сообщения: таблицу к
		// этому времени могли изменить, а запись говорит о строках как они были.
		var vals []string
		for i, c := range rel.Columns {
			vals = append(vals, fmt.Sprintf("(%d, %d::oid, %d)", i, c.TypeOID, c.TypeMod))
		}
		res, err := k.c.Query("SELECT format_type(t.o, t.m) FROM (VALUES " + strings.Join(vals, ", ") + ") AS t(n, o, m) ORDER BY t.n")
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
	res, err := k.c.Query(fmt.Sprintf("SELECT a.attname FROM pg_index i JOIN pg_attribute a ON a.attrelid = i.indrelid AND a.attnum = ANY(i.indkey) "+
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

func run(ctx context.Context, cfg *Config, log *slog.Logger) error {
	dsn, err := pgwire.ParseDSN(cfg.DSN)
	if err != nil {
		return err
	}
	dsn.AppName = "espgtap"
	cat, err := pgwire.Dial(ctx, dsn)
	if err != nil {
		return err
	}
	defer cat.Close()
	if row, _, err := cat.QueryRow("SHOW wal_level"); err != nil {
		return err
	} else if *row[0] != "logical" {
		return fmt.Errorf("wal_level is %s: logical decoding needs wal_level = logical (a restart)", *row[0])
	}
	if _, ok, err := cat.QueryRow("SELECT 1 FROM pg_publication WHERE pubname = " + pgwire.Literal(cfg.Publication)); err != nil {
		return err
	} else if !ok {
		return fmt.Errorf("publication %s does not exist: run the script printed by -setup-sql", cfg.Publication)
	}
	if _, ok, err := cat.QueryRow("SELECT 1 FROM pg_replication_slots WHERE slot_name = " + pgwire.Literal(cfg.Slot)); err != nil {
		return err
	} else if !ok {
		// Слот заводится один раз: с этого места база копит для нас журнал.
		if _, err := cat.Query("SELECT pg_create_logical_replication_slot(" + pgwire.Literal(cfg.Slot) + ", 'pgoutput')"); err != nil {
			return fmt.Errorf("create slot %s: %w", cfg.Slot, err)
		}
		log.Info("replication slot created", "slot", cfg.Slot)
	}
	if row, _, err := cat.QueryRow("SHOW max_slot_wal_keep_size"); err == nil && *row[0] == "-1" {
		log.Warn("max_slot_wal_keep_size is unlimited: while this collector is down the server keeps its WAL for the slot without a bound")
	}

	tap, err := pgtap.Open(pgtap.Config{Dir: cfg.Dir, Roles: cfg.Roles, AlertRows: cfg.AlertRows, RequireAction: cfg.RequireAction, Canaries: cfg.Canaries},
		catalog{cat}, log)
	if err != nil {
		return err
	}
	defer tap.Close()

	dsn.Replication = true
	repl, err := pgwire.Dial(ctx, dsn)
	if err != nil {
		return err
	}
	defer repl.Close()
	// messages — с PostgreSQL 14: без отметок не узнать, чья транзакция.
	if err := repl.StartReplication(cfg.Slot, "proto_version", "1", "publication_names", cfg.Publication, "messages", "true"); err != nil {
		return fmt.Errorf("start replication: %w", err)
	}
	log.Info("streaming", "slot", cfg.Slot, "publication", cfg.Publication, "journal", cfg.Dir, "roles", strings.Join(cfg.Roles, ","))

	var flushed, reported pgwire.LSN
	lastReport := time.Now()
	report := func(force bool) error {
		if !force && (flushed == reported || time.Since(lastReport) < 200*time.Millisecond) {
			return nil
		}
		reported, lastReport = flushed, time.Now()
		return repl.SendStandbyStatus(flushed)
	}
	for ctx.Err() == nil {
		m, err := repl.ReadReplication(cfg.StatusEvery.D())
		switch {
		case errors.Is(err, pgwire.ErrTimeout):
			if err := report(true); err != nil {
				return err
			}
			continue
		case errors.Is(err, io.EOF):
			return errors.New("the server ended the replication stream")
		case err != nil:
			return err
		}
		if m.Keepalive {
			// Между транзакциями всё до конца журнала сервера нам уже отдано.
			if !tap.InTransaction() && m.WALEnd > flushed {
				flushed = m.WALEnd
			}
			if err := report(m.ReplyRequested); err != nil {
				return err
			}
			continue
		}
		msg, err := pgoutput.Parse(m.Data)
		if err != nil {
			return fmt.Errorf("at %s: %w", m.WALStart, err)
		}
		done, err := tap.Handle(msg)
		if err != nil {
			return fmt.Errorf("at %s: %w", m.WALStart, err)
		}
		if done != 0 {
			flushed = max(flushed, pgwire.LSN(done))
			if err := report(false); err != nil {
				return err
			}
		}
	}
	s := tap.Stats()
	log.Info("stopped", "captured", s.Captured, "skipped", s.Skipped, "changes", s.Changes, "parts", s.Parts, "alerts", s.Alerts)
	return report(true)
}

func main() {
	path := flag.String("config", "pgtap.json", "collector config")
	setup := flag.Bool("setup-sql", false, "print the SQL that prepares the database (roles, grants, marker trigger, publication) and exit")
	showVersion := flag.Bool("version", false, "print the version and the commit it was built from")
	flag.Parse()
	if *showVersion {
		fmt.Println(version.String("espgtap"))
		return
	}
	cfg, err := loadConfig(*path)
	fail(err)
	if *setup {
		dsn, err := pgwire.ParseDSN(cfg.DSN)
		fail(err)
		fmt.Print(setupSQL(cfg, dsn.User))
		return
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	fail(run(ctx, cfg, slog.New(slog.NewTextHandler(os.Stderr, nil))))
}

func fail(err error) {
	if err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
}
