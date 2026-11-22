package pginput

import (
	"context"
	"encoding/json"
	"os"
	"strings"
	"testing"

	"github.com/Nikolay1994Kaz/evidencestore/internal/mcpserver"
	"github.com/Nikolay1994Kaz/evidencestore/internal/pgwire"
)

// TestLiveMCP — MCP-сервер на настоящем PostgreSQL ролью агента после
// -setup-sql. Запуск — как у TestLive (PGINPUT_TEST_DSN); всё своё тест держит
// в схеме pgm, роли — с приставкой pgm_.
//
// Что проверено: SQL агента не выходит из транзакции сервера (P-239: раньше
// `BEGIN; DELETE …; COMMIT;` при пределе в 1 строку удалял всё, а агент
// слышал «nothing changed»); строки действия — свои, а не всего сеанса
// (P-240); сеанс между вызовами чист (P-241).
func TestLiveMCP(t *testing.T) {
	base := os.Getenv("PGINPUT_TEST_DSN")
	if base == "" {
		t.Skip("PGINPUT_TEST_DSN is not set")
	}
	super := os.Getenv("PGINPUT_TEST_SUPERUSER")
	if super == "" {
		super = "postgres"
	}
	ctx := context.Background()
	acfg, err := pgwire.ParseDSN(base + " user=" + super)
	if err != nil {
		t.Fatal(err)
	}
	admin, err := pgwire.Dial(ctx, acfg)
	if err != nil {
		t.Fatal(err)
	}
	defer admin.Close()
	exec := func(sql string) {
		t.Helper()
		if _, err := admin.Query(sql); err != nil {
			t.Fatalf("%s: %v", sql, err)
		}
	}
	one := func(sql string) string {
		t.Helper()
		row, ok, err := admin.QueryRow(sql)
		if err != nil {
			t.Fatalf("%s: %v", sql, err)
		}
		if !ok || row[0] == nil {
			return ""
		}
		return *row[0]
	}
	exec("SET client_min_messages = warning")
	exec("DROP PUBLICATION IF EXISTS pgm_pub")
	exec("DROP SCHEMA IF EXISTS pgm CASCADE")
	exec(`CREATE SCHEMA pgm; CREATE TABLE pgm.docs (id int PRIMARY KEY, body text); INSERT INTO pgm.docs SELECT g, 'doc ' || g FROM generate_series(1, 5) g;
-- Правка строки 5 пишет ещё и в журнал таблицы: по ответу «UPDATE 1», по статистике — две строки.
CREATE TABLE pgm.audit (id int, at timestamptz DEFAULT now());
CREATE FUNCTION pgm.audit() RETURNS trigger LANGUAGE plpgsql SECURITY DEFINER AS $f$ BEGIN INSERT INTO pgm.audit (id) VALUES (NEW.id); RETURN NEW; END $f$;
CREATE TRIGGER audit AFTER UPDATE ON pgm.docs FOR EACH ROW WHEN (NEW.id = 5) EXECUTE FUNCTION pgm.audit()`)
	defer func() {
		admin.Query("DROP PUBLICATION IF EXISTS pgm_pub")
		admin.Query("DROP SCHEMA IF EXISTS pgm CASCADE")
	}()
	cfg := Config{DSN: base + " user=pgm_tap", Slot: "pgm_slot", Publication: "pgm_pub", Dir: t.TempDir(), Roles: []string{"pgm_agent"}, Tables: []string{"pgm.docs"}}
	if err := cfg.Validate(); err != nil {
		t.Fatal(err)
	}
	script, err := SetupSQL(&cfg)
	if err != nil {
		t.Fatal(err)
	}
	exec(script)

	dcfg, err := pgwire.ParseDSN(base + " user=pgm_agent application_name=esmcp/live-bot")
	if err != nil {
		t.Fatal(err)
	}
	s := mcpserver.New(mcpserver.Config{Agent: "live-bot", RowLimit: 1, Version: "test",
		Dial: func() (mcpserver.DB, error) { return pgwire.Dial(ctx, dcfg) }}, nil)
	tool := func(name, args string) (string, bool) {
		t.Helper()
		var m struct {
			Result struct {
				Content []struct{ Text string } `json:"content"`
				IsError bool                    `json:"isError"`
			} `json:"result"`
		}
		out := s.Handle([]byte(`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"` + name + `","arguments":` + args + `}}`))
		if err := json.Unmarshal(out, &m); err != nil || len(m.Result.Content) != 1 {
			t.Fatalf("%s %s: %s", name, args, out)
		}
		return m.Result.Content[0].Text, m.Result.IsError
	}
	docs := func() string {
		t.Helper()
		return one("SELECT string_agg(id || '=' || body, ',' ORDER BY id) FROM pgm.docs")
	}
	before := docs()

	// Выйти из транзакции сервера нельзя: команды, которые её закрыли бы, база
	// отвергает при подготовке, и не исполняется ни одна команда действия.
	for _, args := range []string{
		`{"sql":"BEGIN; DELETE FROM pgm.docs; COMMIT;"}`,
		`{"statements":["BEGIN","DELETE FROM pgm.docs","COMMIT"]}`,
		`{"statements":["DELETE FROM pgm.docs","COMMIT"]}`,
		`{"statements":["DELETE FROM pgm.docs","END"]}`,
		`{"sql":"COMMIT; UPDATE pgm.docs SET body = 'x' WHERE id = 1"}`,
		`{"statements":["UPDATE pgm.docs SET body = 'x' WHERE id = 1","ROLLBACK","DELETE FROM pgm.docs"]}`,
		`{"statements":["SET statement_timeout = 0","UPDATE pgm.docs SET body = 'x' WHERE id = 1"]}`,
		`{"sql":"DO $$ BEGIN DELETE FROM pgm.docs; END $$"}`,
		`{"sql":"PREPARE TRANSACTION 'x'"}`,
	} {
		text, isErr := tool("execute", args)
		if !isErr || !strings.Contains(text, "was not taken, nothing ran") || strings.Contains(text, "escaped") {
			t.Fatalf("%s: %v %s", args, isErr, text)
		}
		if now := docs(); now != before {
			t.Fatalf("%s changed the table: %s", args, now)
		}
	}
	// Чтение так же: одна команда, и запись ей недоступна.
	for args, want := range map[string]string{
		`{"sql":"COMMIT; INSERT INTO pgm.docs VALUES (10, 'q')"}`: "`query` takes one SELECT",
		`{"sql":"INSERT INTO pgm.docs VALUES (10, 'q')"}`:         "read-only transaction",
	} {
		if text, isErr := tool("query", args); !isErr || !strings.Contains(text, want) {
			t.Fatalf("%s: %v %s", args, isErr, text)
		}
		if now := docs(); now != before {
			t.Fatalf("%s changed the table: %s", args, now)
		}
	}
	text, isErr := tool("query", `{"sql":"SELECT id, body FROM pgm.docs WHERE id < 3 ORDER BY id"}`)
	if isErr || text != `{"columns":["id","body"],"rows":[["1","doc 1"],["2","doc 2"]]}` {
		t.Fatalf("%v %s", isErr, text)
	}
	if text, isErr := tool("query", `{"sql":"SELECT id FROM pgm.docs WHERE false"}`); isErr || text != `{"columns":["id"],"rows":[]}` {
		t.Fatalf("%v %s", isErr, text)
	}

	// Обычное действие: квитанция называет ту транзакцию, в которой строка.
	text, isErr = tool("execute", `{"statements":["UPDATE pgm.docs SET body = 'y' WHERE id = 1"],"reason":"fix"}`)
	var out struct{ XID, Outcome string }
	json.Unmarshal([]byte(text), &out)
	if isErr || out.Outcome != "committed" || out.XID != one("SELECT xmin FROM pgm.docs WHERE id = 1") {
		t.Fatalf("%v %s", isErr, text)
	}
	// Действия подряд в одном сеансе: у каждого — одна своя строка. Раньше
	// второе получало строки первого к своим и шло в отказ (P-240).
	for i := 0; i < 20; i++ {
		if text, isErr := tool("execute", `{"sql":"UPDATE pgm.docs SET body = 'z' WHERE id = 2"}`); isErr {
			t.Fatalf("action %d: %s", i+1, text)
		}
	}
	before = docs()
	if text, isErr := tool("execute", `{"statements":["UPDATE pgm.docs SET body = 'w' WHERE id = 3","UPDATE pgm.docs SET body = 'w' WHERE id = 4"]}`); !isErr ||
		!strings.Contains(text, "would change 2 rows") || docs() != before {
		t.Fatalf("%v %s", isErr, text)
	}
	// Строки, изменённые триггером, — тоже строки действия: их видно только по
	// статистике базы.
	if text, isErr := tool("execute", `{"sql":"UPDATE pgm.docs SET body = 'w' WHERE id = 5"}`); !isErr ||
		!strings.Contains(text, "would change 2 rows") || docs() != before || one("SELECT count(*) FROM pgm.audit") != "0" {
		t.Fatalf("%v %s", isErr, text)
	}

	// Сеанс между вызовами чист: что SQL агента сменил на весь сеанс,
	// следующий вызов уже не видит (P-241).
	if _, isErr := tool("query", `{"sql":"SELECT set_config('application_name', 'spoofed', false), pg_advisory_lock(4242)"}`); isErr {
		t.Fatal("set_config and an advisory lock in a read")
	}
	if n := one("SELECT count(*) FROM pg_locks WHERE locktype = 'advisory' AND objid = 4242 AND granted"); n != "1" {
		t.Fatalf("the advisory lock is not held between calls: %s", n)
	}
	if text, isErr := tool("query", `{"sql":"SELECT current_setting('application_name') AS app"}`); isErr || !strings.Contains(text, `"esmcp/live-bot"`) {
		t.Fatalf("%v %s", isErr, text)
	}
	if n := one("SELECT count(*) FROM pg_locks WHERE locktype = 'advisory' AND objid = 4242"); n != "0" {
		t.Fatalf("the advisory lock outlived the call: %s", n)
	}
}
