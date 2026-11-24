package pginput

import (
	"strings"
	"testing"
	"time"

	"github.com/Nikolay1994Kaz/evidencestore/internal/alert"
	"github.com/Nikolay1994Kaz/evidencestore/internal/config"
)

func good() Config {
	return Config{DSN: "host=db user=evidence_tap dbname=shop", MCPRoles: []string{"esmcp_bot"}, Roles: []string{"agent_bot"}, Tables: []string{"public.accounts", "sales.orders"}}
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
		"no dsn":              func(c *Config) { c.DSN = "" },
		"dsn that is not one": func(c *Config) { c.DSN = "host" },
		"no mcp roles":        func(c *Config) { c.MCPRoles = nil },
		// У агента, сервера и отката — по своей роли (DECISIONS, п. 39).
		"agent = server":       func(c *Config) { c.Roles = []string{"esmcp_bot"} },
		"undo = server":        func(c *Config) { c.UndoRoles = []string{"esmcp_bot"} },
		"agent = collector":    func(c *Config) { c.Roles = []string{"evidence_tap"} },
		"no tables":            func(c *Config) { c.Tables = nil },
		"table without schema": func(c *Config) { c.Tables = []string{"accounts"} },
		"three-part table":     func(c *Config) { c.Tables = []string{"db.public.accounts"} },
		"status_every 100ms":   func(c *Config) { c.StatusEvery = config.Duration(100 * time.Millisecond) },
		"status_every 2m":      func(c *Config) { c.StatusEvery = config.Duration(2 * time.Minute) },
		"alert_rows -1":        func(c *Config) { c.AlertRows = -1 },
		"down_after 10ms":      func(c *Config) { c.DownAfter = config.Duration(10 * time.Millisecond) },
		"slot_alert_mb -1":     func(c *Config) { c.SlotAlertMB = -1 },
		"notify to nobody":     func(c *Config) { c.Notify = &Notify{} },
		"notify to a bad target": func(c *Config) {
			c.Notify = &Notify{To: []alert.Target{{Type: alert.TypeSlack, URL: "http://example.com/hook"}}}
		},
		// PostgreSQL режет имя до 63 байт, а сборщик сравнивал бы целиком (R2-8).
		"a role of 64 bytes": func(c *Config) { c.MCPRoles = []string{strings.Repeat("s", 64)} },
		"an empty role":      func(c *Config) { c.UndoRoles = []string{""} },
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
	ok := good()
	ok.MCPRoles = []string{strings.Repeat("s", 63)}
	if err := ok.Validate(); err != nil {
		t.Errorf("a role of 63 bytes: %v", err)
	}
	// Квитанции шлюзов: файлы и ключи обязательны, require_gateway — только с
	// ними (DECISIONS, п. 42).
	key := strings.Repeat("ab", 32)
	r := good()
	r.Receipts, r.RequireGateway = &ReceiptsConfig{Files: []string{"/var/lib/esmcp/receipts.jsonl", "/var/lib/esundo/receipts.jsonl"}, GatewayKeys: []string{key}}, true
	if err := r.Validate(); err != nil || r.Receipts.Source != "postgres" {
		t.Fatalf("receipts: %v %+v", err, r.Receipts)
	}
	for name, spoil := range map[string]func(*Config){
		"require_gateway without receipts": func(c *Config) { c.Receipts = nil },
		"no receipts files":                func(c *Config) { c.Receipts.Files = nil },
		"an empty receipts file":           func(c *Config) { c.Receipts.Files = []string{""} },
		"one file twice":                   func(c *Config) { c.Receipts.Files = []string{"/a/r.jsonl", "/a/../a/r.jsonl"} },
		"no gateway keys":                  func(c *Config) { c.Receipts.GatewayKeys = nil },
		"a key that is not one":            func(c *Config) { c.Receipts.GatewayKeys = []string{"abc"} },
	} {
		c := good()
		c.Receipts, c.RequireGateway = &ReceiptsConfig{Files: []string{"/a/r.jsonl"}, GatewayKeys: []string{key}}, true
		spoil(&c)
		if err := c.Validate(); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

// Скрипт настройки базы: права сервера — только строки названных таблиц,
// агента — только чтение, отката — строки; ни отметок, ни триггеров, ни
// ключа в базе (п. 42): прежние снимаются; имена берутся в кавычки.
func TestSetupSQL(t *testing.T) {
	c := good()
	c.MCPRoles = []string{`agent "x"`, "50% off"}
	c.UndoRoles = []string{"undo_op"}
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
		`REVOKE EXECUTE ON FUNCTION %s FROM PUBLIC`,
		`ALTER ROLE "agent ""x""" SET statement_timeout = '60s';`,
		`ALTER ROLE "agent ""x""" SET lock_timeout = '10s';`,
		`ALTER ROLE "agent ""x""" SET idle_in_transaction_session_timeout = '5min';`,
		// Агент — только чтение; запись и отметки, выданные раньше, отозваны.
		`GRANT SELECT ON "public"."accounts", "sales"."orders" TO "agent_bot";`,
		`REVOKE INSERT, UPDATE, DELETE, TRUNCATE, TRIGGER, REFERENCES ON "public"."accounts", "sales"."orders" FROM "agent_bot";`,
		`EXECUTE format('REVOKE INSERT, UPDATE, DELETE, TRUNCATE, TRIGGER, REFERENCES ON %s FROM "agent_bot"', leaf);`,
		// Откат — строки.
		`GRANT SELECT, INSERT, UPDATE, DELETE ON "public"."accounts", "sales"."orders" TO "undo_op";`,
		// Прежние отметки сняты: триггеры, функции, ключ и схема — то, чем
		// владеет evidence_owner, и сама роль, когда на неё не ссылается ни одна
		// база; право писать в журнал возвращено, как было. Схему целиком
		// (CASCADE) — нет: в ней могут быть данные приложения (R2-5).
		`AND has_function_privilege(o, p.oid, 'EXECUTE') LOOP`,
		`EXECUTE format('GRANT EXECUTE ON FUNCTION %s TO PUBLIC', f);`,
		`EXECUTE format('DROP TRIGGER %I ON %s', t.tgname, t.rel);`,
		`it stays, and the owner of the database owns it now`,
		`EXECUTE format('DROP OWNED BY %I', 'evidence_owner');`,
		`run this script there as well; the last one drops the role`,
		// Роли агента и сервера — разрешённым перечнем: ни членств, ни владения;
		// ролью сервера не может стать никто другой.
		`SELECT format('%I is a member of %I', r.rolname, g.rolname)`,
		`a SECURITY DEFINER function of %I`,
		`JOIN pg_foreign_server s ON has_server_privilege(g.oid, s.oid, 'USAGE')`,
		`has_column_privilege(g.oid, c.oid, a.attnum, 'SELECT')`,
		`EXECUTE $q$SELECT string_agg(DISTINCT x, ', ') FROM (SELECT format('%I can %s parameter %s', r.rolname, pr.p, a.parname) AS x`,
		`WHERE r.rolname IN ('agent_bot', 'agent "x"', '50% off', 'undo_op') AND NOT g.rolsuper AND has_parameter_privilege`,
		`WHERE r.rolname IN ('agent_bot', 'agent "x"', '50% off') AND g.oid <> r.oid`,
		`SELECT format('%I owns %s', r.rolname, pg_describe_object(s.classid, s.objid, s.objsubid)) AS x`,
		`SELECT format('%I can become %I', x.rolname, m.rolname) AS x`,
		`WHERE m.rolname IN ('agent "x"', '50% off')`,
		// Обрывать сеансы — только суперпользователям и pg_signal_backend; что initdb
		// оставил суперпользователям, остаётся им. Чужая SECURITY DEFINER — любая вне pg_catalog.
		`EXECUTE format('GRANT EXECUTE ON FUNCTION %s TO pg_signal_backend', f);`,
		`f.proname IN ('pg_terminate_backend', 'pg_cancel_backend')`,
		`AND f.pronamespace <> 'pg_catalog'::regnamespace`,
		`AND NOT EXISTS (SELECT FROM aclexplode(i.initprivs) a WHERE a.grantee = 0 AND a.privilege_type = 'EXECUTE'))`,
		// Запись агента — и в колонку, и через вид; умолчания прав.
		`has_any_column_privilege(r.oid, c.oid, pr.p)`,
		`WITH RECURSIVE over(oid) AS`,
		`CROSS JOIN pg_default_acl d CROSS JOIN LATERAL aclexplode(d.defaclacl) a`,
		// Публикация: с PostgreSQL 18 — вместе с хранимыми генерируемыми колонками.
		`EXECUTE 'CREATE PUBLICATION "evidence_pub" FOR TABLE "public"."accounts", "sales"."orders" WITH (publish_generated_columns = stored)';`,
		`EXECUTE 'CREATE PUBLICATION "evidence_pub" FOR TABLE "public"."accounts", "sales"."orders"';`,
		`CREATE ROLE "evidence_tap" LOGIN REPLICATION;`,
		// Виртуальная генерируемая колонка — отказ до любых изменений.
		`AND a.attgenerated = 'v';`,
		`RAISE EXCEPTION 'evidencestore: a virtual generated column: %', bad USING HINT =`,
		// Секции: названные таблицы и всё их дерево; секции — то же, что таблице, и права агентам.
		`(SELECT t.oid AS relid, 0 AS level FROM unnest(ARRAY['"public"."accounts"'::regclass, '"sales"."orders"'::regclass]) AS t(oid) UNION`,
		`CROSS JOIN LATERAL pg_partition_tree(t.oid) AS tree) AS part`,
		`EXECUTE format('ALTER TABLE %s REPLICA IDENTITY FULL', leaf);`,
		`EXECUTE format('GRANT SELECT, INSERT, UPDATE, DELETE ON %s TO "agent ""x""", "50%% off", "undo_op"', leaf);`,
	} {
		if !strings.Contains(sql, want) {
			t.Errorf("the script lacks %s", want)
		}
	}
	if strings.Contains(sql, "TRUNCATE ON") && strings.Contains(sql, "GRANT TRUNCATE") {
		t.Error("the agent role is granted TRUNCATE")
	}
	// Из базы «кто» не берётся: ни триггеров, ни функций отметок, ни ключа.
	for _, gone := range []string{"CREATE TRIGGER", "CREATE FUNCTION", "CREATE SCHEMA", "mark_", "marker_key", "CREATE ROLE \"evidence_owner\"", "ROW LEVEL SECURITY", "DROP SCHEMA IF EXISTS evidence CASCADE"} {
		if strings.Contains(sql, gone) {
			t.Errorf("the script still has %s", gone)
		}
	}
	if !strings.HasPrefix(strings.TrimSpace(sql[strings.Index(sql, "BEGIN;"):]), "BEGIN;") || !strings.HasSuffix(strings.TrimSpace(sql), "COMMIT;") {
		t.Error("the script is not one transaction")
	}
	// Проверка — раньше первого изменения базы.
	if guard, first := strings.Index(sql, "RAISE EXCEPTION"), strings.Index(sql, "DROP OWNED BY"); guard < 0 || first < 0 || guard > first {
		t.Error("the refusal comes after the script has begun to change the database")
	}
}

// Уровни отставания слота: половина предела базы, 80 % предела, свой порог в
// мегабайтах; назад в норму — с запасом, чтобы тревоги не мигали у границы.
func TestSlotGrade(t *testing.T) {
	const mb = 1 << 20
	for _, tc := range []struct {
		name            string
		retained, limit int64
		own             int
		level           int
		calm            bool
	}{
		{"далеко от предела", 100 * mb, 2048 * mb, 0, 0, true},
		{"половина предела", 1024 * mb, 2048 * mb, 0, 1, false},
		{"80 % предела", 1700 * mb, 2048 * mb, 0, 2, false},
		{"чуть ниже половины: не тревога, но и не «в норме»", 900 * mb, 2048 * mb, 0, 0, false},
		{"предела в базе нет, порога нет", 500000 * mb, -1, 0, 0, true},
		{"предела в базе нет, свой порог", 600 * mb, -1, 512, 1, false},
		{"свой порог ниже половины предела", 600 * mb, 2048 * mb, 512, 1, false},
		{"чуть ниже своего порога", 450 * mb, 2048 * mb, 512, 0, false},
		{"заметно ниже своего порога", 300 * mb, 2048 * mb, 512, 0, true},
		{"свой порог выше, чем 80 % предела", 1700 * mb, 2048 * mb, 4096, 2, false},
	} {
		level, calm := grade(SlotState{Retained: tc.retained, Limit: tc.limit}, tc.own)
		if level != tc.level || calm != tc.calm {
			t.Errorf("%s: level %d, calm %v; want %d, %v", tc.name, level, calm, tc.level, tc.calm)
		}
	}
	for n, want := range map[int64]string{512: "512 bytes", 2048: "2 kB", 5 * mb: "5 MB", 1536 * mb: "1.5 GB"} {
		if got := human(n); got != want {
			t.Errorf("human(%d) = %q, want %q", n, got, want)
		}
	}
}
