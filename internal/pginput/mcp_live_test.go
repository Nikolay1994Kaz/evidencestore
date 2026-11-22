package pginput

import (
	"context"
	"encoding/json"
	"os"
	"strings"
	"testing"
	"time"

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
	// Уборка — и до теста: прогон, упавший посреди (мутации), оставляет слот,
	// функции агента в public, его search_path и право CREATE. Ошибки не в
	// счёт: роли в первый прогон ещё нет.
	tidy := func() {
		admin.Query("ROLLBACK")
		admin.Query("SELECT pg_drop_replication_slot(slot_name) FROM pg_replication_slots WHERE slot_name = 'pgm_peek'")
		admin.Query("DROP FUNCTION IF EXISTS public.pg_stat_get_xact_tuples_inserted(oid), public.pg_stat_get_xact_tuples_updated(oid), public.pg_stat_get_xact_tuples_deleted(oid), public.pg_current_xact_id()")
		admin.Query("ALTER ROLE pgm_agent RESET search_path")
		admin.Query("ALTER ROLE pgm_agent RESET standard_conforming_strings")
		admin.Query("REVOKE CREATE ON SCHEMA public FROM pgm_agent")
		admin.Query("DROP ROLE IF EXISTS pgm_group")
	}
	tidy()
	defer tidy()
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

	// Отложенный триггер (DEFERRABLE INITIALLY DEFERRED) срабатывает на COMMIT —
	// раньше после счёта строк, и его изменения в предел не шли (P-246).
	exec("CREATE CONSTRAINT TRIGGER audit_later AFTER UPDATE ON pgm.docs DEFERRABLE INITIALLY DEFERRED FOR EACH ROW WHEN (NEW.id = 4) EXECUTE FUNCTION pgm.audit()")
	before = docs()
	if text, isErr := tool("execute", `{"sql":"UPDATE pgm.docs SET body = 'later' WHERE id = 4"}`); !isErr ||
		!strings.Contains(text, "would change 2 rows") || docs() != before || one("SELECT count(*) FROM pgm.audit") != "0" {
		t.Fatalf("a deferred trigger: %v %s", isErr, text)
	}

	// Отметка об отказе ложится, что бы SQL агента ни сменил в сеансе: раньше
	// standard_conforming_strings = off ломал JSON с кавычкой в причине,
	// client_encoding — причину не в ASCII, а отказ по частоте шёл по сеансу
	// прошлого вызова; квитанция при этом писала «тревога ушла» (P-243).
	// Роль агента в группе без права на отметки: SQL агента входит в неё
	// (set_config('role', …)), и отметка своей ролью легла бы с отказом.
	exec("CREATE ROLE pgm_group NOLOGIN; GRANT pgm_group TO pgm_agent")
	exec("SELECT pg_create_logical_replication_slot('pgm_peek', 'test_decoding')")
	for _, args := range []string{
		`{"statements":["DELETE FROM pgm.docs","SELECT set_config('standard_conforming_strings', 'off', true)"],"reason":"close \"dormant\" docs"}`,
		`{"statements":["DELETE FROM pgm.docs","SELECT set_config('client_encoding', 'EUC_JP', true)"],"reason":"очистка документов"}`,
		`{"statements":["DELETE FROM pgm.docs","SELECT set_config('role', 'pgm_group', true)"],"reason":"another role"}`,
	} {
		if text, isErr := tool("execute", args); !isErr || !strings.Contains(text, "would change 5 rows") {
			t.Fatalf("%s: %v %s", args, isErr, text)
		}
	}
	// Значения по умолчанию своей роли агент ставит сам (ALTER ROLE … SET — в
	// обход MCP-сервера), и DISCARD ALL возвращает сеанс к ним: отметка отказа
	// вне транзакции идёт со своими настройками сеанса.
	exec("ALTER ROLE pgm_agent SET standard_conforming_strings = off")
	rated := mcpserver.New(mcpserver.Config{Agent: "live-bot", ActionsPerMinute: 1, Version: "test",
		Dial: func() (mcpserver.DB, error) { return pgwire.Dial(ctx, dcfg) }}, nil)
	call := func(s *mcpserver.Server, args string) string {
		var m struct {
			Result struct {
				Content []struct{ Text string } `json:"content"`
			} `json:"result"`
		}
		json.Unmarshal(s.Handle([]byte(`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"execute","arguments":`+args+`}}`)), &m)
		return m.Result.Content[0].Text
	}
	if text := call(rated, `{"statements":["UPDATE pgm.docs SET body = 'r' WHERE id = 1","SELECT set_config('client_encoding', 'EUC_JP', false)"]}`); !strings.Contains(text, `"committed"`) {
		t.Fatal(text)
	}
	if text := call(rated, `{"sql":"UPDATE pgm.docs SET body = 'r' WHERE id = 2","reason":"ещё раз: \"dormant\" docs"}`); !strings.Contains(text, "was refused: 1 actions in the last minute") {
		t.Fatal(text)
	}
	// Отказ по частоте — вне транзакции, и сообщение не транзакционное: в
	// слот оно попадает, когда журнал сброшен на диск (walwriter, доли секунды).
	var marks string
	for wait := time.Now().Add(5 * time.Second); time.Now().Before(wait); time.Sleep(50 * time.Millisecond) {
		marks = one(`SELECT string_agg(substring(data from '"cause":"[a-z-]+"'), ' ' ORDER BY lsn) FROM pg_logical_slot_peek_changes('pgm_peek', NULL, NULL) WHERE data LIKE '%evidence/refused%'`)
		if strings.Count(marks, "cause") == 4 {
			break
		}
	}
	if marks != `"cause":"row-limit" "cause":"row-limit" "cause":"row-limit" "cause":"rate"` {
		t.Fatalf("refusal markers in the database log: %q", marks)
	}
	exec("ALTER ROLE pgm_agent RESET standard_conforming_strings")

	// Подмена системных функций: у агента схема, где можно CREATE, в ней —
	// функции счёта строк и номера транзакции, и его search_path ставит её
	// раньше pg_catalog (set_config в действии, а для своих запросов сервера —
	// ALTER ROLE). Раньше счёт брал его функции: 0 строк, действие сверх
	// предела проходило с квитанцией без строк (P-242).
	exec("GRANT CREATE ON SCHEMA public TO pgm_agent")
	agent, err := pgwire.Dial(ctx, dcfg)
	if err != nil {
		t.Fatal(err)
	}
	defer agent.Close()
	for _, f := range []string{"inserted", "updated", "deleted"} {
		if _, err := agent.Query("CREATE FUNCTION public.pg_stat_get_xact_tuples_" + f + "(oid) RETURNS bigint LANGUAGE sql AS 'SELECT 0::bigint'"); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := agent.Query("CREATE FUNCTION public.pg_current_xact_id() RETURNS xid8 LANGUAGE sql AS $$SELECT '7'::xid8$$; ALTER ROLE pgm_agent SET search_path = public, pg_catalog"); err != nil {
		t.Fatal(err)
	}
	s = mcpserver.New(mcpserver.Config{Agent: "live-bot", RowLimit: 1, Version: "test",
		Dial: func() (mcpserver.DB, error) { return pgwire.Dial(ctx, dcfg) }}, nil)
	before = docs()
	if text, isErr := tool("execute", `{"statements":["SELECT set_config('search_path', 'public, pg_catalog', true)","WITH d AS (DELETE FROM pgm.docs RETURNING 1) SELECT count(*) FROM d"]}`); !isErr ||
		!strings.Contains(text, "would change 5 rows") || docs() != before {
		t.Fatalf("functions of the agent stood in for the system ones: %v %s", isErr, text)
	}
	text, isErr = tool("execute", `{"sql":"UPDATE pgm.docs SET body = 'own' WHERE id = 1"}`)
	json.Unmarshal([]byte(text), &out)
	if isErr || out.XID != one("SELECT xmin FROM pgm.docs WHERE id = 1") {
		t.Fatalf("the transaction id: %v %s", isErr, text)
	}
	// А -setup-sql такую роль теперь не берёт: своих объектов агенту нельзя.
	if _, err := admin.Query(script); err == nil || !strings.Contains(err.Error(), "pgm_agent can CREATE in schema public") {
		t.Fatalf("the setup script took an agent role that can CREATE: %v", err)
	}
	exec("ROLLBACK; REVOKE CREATE ON SCHEMA public FROM pgm_agent")
	// И таблицу без первичного ключа — тоже: строки отката не найти (P-253).
	nopk := cfg
	nopk.Tables = []string{"pgm.docs", "pgm.audit"}
	if script, err := SetupSQL(&nopk); err != nil {
		t.Fatal(err)
	} else if _, err := admin.Query(script); err == nil || !strings.Contains(err.Error(), "a table without a primary key: pgm.audit") {
		t.Fatalf("the setup script took a table without a primary key: %v", err)
	}
	exec("ROLLBACK")
}
