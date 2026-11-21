package pginput

import (
	"strings"
	"testing"
	"time"

	"github.com/Nikolay1994Kaz/evidencestore/internal/alert"
	"github.com/Nikolay1994Kaz/evidencestore/internal/config"
)

func good() Config {
	return Config{DSN: "host=db user=evidence_tap dbname=shop", Roles: []string{"agent_bot"}, Tables: []string{"public.accounts", "sales.orders"}}
}

func TestConfigDefaultsAndRefusals(t *testing.T) {
	c := good()
	if err := c.Validate(); err != nil {
		t.Fatal(err)
	}
	if c.Slot != "evidence_tap" || c.Publication != "evidence_pub" || c.StatusEvery.D() != 5*time.Second || c.DownAfter.D() != time.Minute {
		t.Fatalf("defaults: %+v", c)
	}
	n := good()
	n.Notify = &Notify{To: []alert.Target{{Type: alert.TypeTelegram, Token: "1:T", Chat: "5"}}}
	if err := n.Validate(); err != nil || n.Notify.UndoHint != DefaultUndoHint || n.Notify.To[0].Name != "telegram" {
		t.Fatalf("notify defaults: %v %+v", err, n.Notify)
	}
	for name, spoil := range map[string]func(*Config){
		"no dsn":               func(c *Config) { c.DSN = "" },
		"dsn that is not one":  func(c *Config) { c.DSN = "host" },
		"no roles":             func(c *Config) { c.Roles = nil },
		"no tables":            func(c *Config) { c.Tables = nil },
		"table without schema": func(c *Config) { c.Tables = []string{"accounts"} },
		"three-part table":     func(c *Config) { c.Tables = []string{"db.public.accounts"} },
		"status_every 100ms":   func(c *Config) { c.StatusEvery = config.Duration(100 * time.Millisecond) },
		"status_every 2m":      func(c *Config) { c.StatusEvery = config.Duration(2 * time.Minute) },
		"alert_rows -1":        func(c *Config) { c.AlertRows = -1 },
		"down_after 10ms":      func(c *Config) { c.DownAfter = config.Duration(10 * time.Millisecond) },
		"notify to nobody":     func(c *Config) { c.Notify = &Notify{} },
		"notify to a bad target": func(c *Config) {
			c.Notify = &Notify{To: []alert.Target{{Type: alert.TypeSlack, URL: "http://example.com/hook"}}}
		},
		"undo hint without {xid}": func(c *Config) {
			c.Notify = &Notify{UndoHint: "esundo check", To: []alert.Target{{Type: alert.TypeSlack, URL: "https://example.com/hook"}}}
		},
	} {
		c := good()
		spoil(&c)
		if err := c.Validate(); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	if _, err := New(good(), nil); err == nil {
		t.Error("a source without a directory for its index was created")
	}
}

// Скрипт настройки базы: права агента — только строки названных таблиц,
// отметку «кто» ставит триггер, прямой вызов pg_logical_emit_message закрыт,
// имена берутся в кавычки.
func TestSetupSQL(t *testing.T) {
	c := good()
	c.Roles = []string{`agent "x"`}
	if err := c.Validate(); err != nil {
		t.Fatal(err)
	}
	sql, err := SetupSQL(&c)
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		`CREATE ROLE "agent ""x""" LOGIN;`,
		`GRANT SELECT, INSERT, UPDATE, DELETE ON "public"."accounts", "sales"."orders" TO "agent ""x""";`,
		`GRANT USAGE ON SCHEMA "sales" TO "agent ""x""";`,
		`ALTER TABLE "sales"."orders" REPLICA IDENTITY FULL;`,
		`CREATE TRIGGER evidence_who BEFORE INSERT OR UPDATE OR DELETE OR TRUNCATE ON "public"."accounts"`,
		`REVOKE EXECUTE ON FUNCTION %s FROM PUBLIC`,
		`PERFORM pg_logical_emit_message(false, 'evidence/refused',`,
		`evidence.mark_refused(json) TO "agent ""x""";`,
		`CREATE PUBLICATION "evidence_pub" FOR TABLE "public"."accounts", "sales"."orders";`,
		`CREATE ROLE "evidence_tap" LOGIN REPLICATION;`,
	} {
		if !strings.Contains(sql, want) {
			t.Errorf("the script lacks %s", want)
		}
	}
	if strings.Contains(sql, "TRUNCATE ON") && strings.Contains(sql, "GRANT TRUNCATE") {
		t.Error("the agent role is granted TRUNCATE")
	}
	if !strings.HasPrefix(strings.TrimSpace(sql[strings.Index(sql, "BEGIN;"):]), "BEGIN;") || !strings.HasSuffix(strings.TrimSpace(sql), "COMMIT;") {
		t.Error("the script is not one transaction")
	}
}
