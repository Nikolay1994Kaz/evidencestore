package pginput

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strconv"
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
		admin.Query("DROP SCHEMA IF EXISTS pgm CASCADE")
		admin.Query("DROP OWNED BY pgm_group, pgm_maker")
		admin.Query("SELECT pg_drop_replication_slot(slot_name) FROM pg_replication_slots WHERE slot_name = 'pgm_peek'")
		admin.Query("DROP FUNCTION IF EXISTS public.pg_stat_get_xact_tuples_inserted(oid), public.pg_stat_get_xact_tuples_updated(oid), public.pg_stat_get_xact_tuples_deleted(oid), public.pg_current_xact_id(), public.left(name, integer)")
		admin.Query("ALTER ROLE pgm_agent RESET ALL")
		admin.Query("ALTER ROLE pgm_agent INHERIT")
		admin.Query("REVOKE CREATE ON SCHEMA public FROM pgm_maker")
		admin.Query("DROP ROLE IF EXISTS pgm_maker")
		admin.Query("REVOKE SET ON PARAMETER session_replication_role FROM pgm_agent")
		admin.Query("REVOKE pg_execute_server_program FROM pgm_agent")
		admin.Query("ALTER ROLE pgm_agent NOCREATEROLE")
		admin.Query("ALTER ROLE pgm_agent RESET search_path")
		admin.Query("ALTER ROLE pgm_agent RESET standard_conforming_strings")
		admin.Query("REVOKE CREATE ON SCHEMA public FROM pgm_agent")
		admin.Query("DROP ROLE IF EXISTS pgm_group")
		admin.Query("DROP OWNED BY pgm_writer")
		admin.Query("DROP ROLE IF EXISTS pgm_writer")
		admin.Query("REVOKE pgm_agent FROM pgm_ai")
		admin.Query("REVOKE pg_signal_backend FROM pgm_ai")
		admin.Query("REVOKE evidence_owner FROM pgm_agent")
		admin.Query("REVOKE pgm_tap FROM pgm_ai")
		admin.Query("DROP ROLE IF EXISTS pgm_other")
		admin.Query("DROP ROLE IF EXISTS pgm_dba")
		admin.Query("DROP SCHEMA IF EXISTS pgm_own")
		admin.Query("REVOKE pg_signal_backend, pg_read_server_files FROM pgm_ai, pgm_agent")
		admin.Query("ALTER DEFAULT PRIVILEGES IN SCHEMA pgm REVOKE UPDATE ON TABLES FROM pgm_ai")
		// Права из случаев отказа скрипта: прогон, оборванный посреди случая, их оставил бы.
		admin.Query("REVOKE EXECUTE ON FUNCTION pg_read_binary_file(text) FROM pgm_ai")
		admin.Query("REVOKE SELECT ON pg_authid FROM pgm_ai")
		admin.Query("REVOKE EXECUTE ON FUNCTION pg_terminate_backend(integer, bigint) FROM pgm_agent")
		admin.Query("DROP EXTENSION IF EXISTS dblink")
		admin.Query("DROP SCHEMA IF EXISTS pgm_ext")
		admin.Query("DROP EXTENSION IF EXISTS pgstattuple")
		admin.Query("DROP SCHEMA IF EXISTS pgm_ext2")
		admin.Query("DROP SERVER IF EXISTS pgm_loop")
		admin.Query("DROP FOREIGN DATA WRAPPER IF EXISTS pgm_fdw")
		admin.Query("DROP FUNCTION IF EXISTS public.pgm_end(int)")
		admin.Query("REVOKE SET ON PARAMETER track_counts FROM pgm_agent")
		admin.Query("REVOKE SELECT (rolname, rolpassword) ON pg_authid FROM pgm_ai")
		admin.Query("REVOKE EXECUTE ON FUNCTION pg_logical_emit_message(bool, text, text) FROM pgm_agent")
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
	cfg := Config{DSN: base + " user=pgm_tap", Slot: "pgm_slot", Publication: "pgm_pub", Dir: t.TempDir(), MCPRoles: []string{"pgm_agent"}, Roles: []string{"pgm_ai"}, Tables: []string{"pgm.docs"}}
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
		Dial: func(params map[string]string) (mcpserver.DB, error) {
			c := dcfg
			c.Params = params
			return pgwire.Dial(ctx, c)
		}}, nil)

	// Граница — роли базы (DECISIONS, п. 39): у сервера pgm_agent своя роль, у
	// агента pgm_ai — своя, только чтение. Агент своей ролью не пишет, не
	// ставит отметок, не обрывает сеансы сервера и не меняет умолчаний его
	// роли — то, чем он пользовался в заходах 1–3 (P-255, P-259, P-275).
	if err := s.CheckRole(); err != nil {
		t.Fatalf("the role of the server: %v", err)
	}
	// Суперпользователь — не своя роль: он может стать любой.
	su := mcpserver.New(mcpserver.Config{Agent: "live-bot", Version: "test",
		Dial: func(params map[string]string) (mcpserver.DB, error) {
			c, err := pgwire.ParseDSN(base + " user=postgres")
			if err != nil {
				return nil, err
			}
			c.Params = params
			return pgwire.Dial(ctx, c)
		}}, nil)
	if err := su.CheckRole(); !errors.Is(err, mcpserver.ErrSharedRole) || !strings.Contains(err.Error(), "postgres is a superuser") {
		t.Fatalf("esmcp as a superuser: %v", err)
	}
	aicfg, err := pgwire.ParseDSN(base + " user=pgm_ai")
	if err != nil {
		t.Fatal(err)
	}
	ai, err := pgwire.Dial(ctx, aicfg)
	if err != nil {
		t.Fatal(err)
	}
	defer ai.Close()
	server := one("SELECT pid::text FROM pg_stat_activity WHERE usename = 'pgm_agent' AND application_name = 'esmcp/live-bot'")
	if one("SELECT count(*) FROM pgm.docs") != "5" {
		t.Fatal("the docs")
	}
	if _, _, err := ai.QueryRow("SELECT count(*) FROM pgm.docs"); err != nil {
		t.Fatalf("the agent cannot read: %v", err)
	}
	for _, sql := range []string{
		"UPDATE pgm.docs SET body = 'direct' WHERE id = 1",
		"DELETE FROM pgm.docs",
		"SELECT evidence.mark_action('{}')",
		"SELECT evidence.mark_refused('{\"cause\":\"rate\"}')",
		"SELECT pg_logical_emit_message(false, 'evidence/refused', '{\"cause\":\"rate\"}')",
		"SELECT pg_terminate_backend(" + server + ")",
		"ALTER ROLE pgm_agent SET statement_timeout = 1",
	} {
		if _, err := ai.Query(sql); err == nil || !strings.Contains(err.Error(), "42501") {
			t.Fatalf("the agent's own role: %s: %v", sql, err)
		}
	}
	// -setup-sql и esmcp не берут общей роли: агент — член роли сервера; агент
	// в pg_signal_backend; запись через группу. Писать в журнал базы мимо
	// отметок не может и сервер: SQL агента идёт в его сеансе. А права,
	// выданные раньше (до п. 39 агент и сервер ходили одной ролью), скрипт отзывает.
	// c[3] — что тогда отвечает esmcp (CheckRole); пусто — роль сервера своя.
	// Ролям агента и сервера — ни членств, ни владения: через них приходят
	// права, которых скрипт не знает (заход 1 после п. 39: R1, R2, T).
	for _, c := range [][4]string{
		{"GRANT pgm_agent TO pgm_ai", "pgm_ai is a member of pgm_agent", "REVOKE pgm_agent FROM pgm_ai", "pgm_ai can become pgm_agent"},
		{"CREATE ROLE pgm_other LOGIN; GRANT pgm_agent TO pgm_other", "pgm_other can become pgm_agent", "DROP ROLE pgm_other", "pgm_other can become pgm_agent"},
		{"CREATE ROLE pgm_other LOGIN; GRANT evidence_owner TO pgm_other", "pgm_other can become evidence_owner", "DROP ROLE pgm_other", ""},
		{"GRANT pgm_tap TO pgm_ai", "pgm_ai is a superuser, may replicate or create roles (as pgm_tap)", "REVOKE pgm_tap FROM pgm_ai", ""},
		{"GRANT pg_signal_backend TO pgm_ai", "pgm_ai is a member of pg_signal_backend", "REVOKE pg_signal_backend FROM pgm_ai", ""},
		{"GRANT pg_read_server_files TO pgm_ai", "pgm_ai is a member of pg_read_server_files", "REVOKE pg_read_server_files FROM pgm_ai", ""},
		{"CREATE ROLE pgm_writer NOLOGIN; GRANT UPDATE ON pgm.docs TO pgm_writer; GRANT pgm_writer TO pgm_ai", "pgm_ai is a member of pgm_writer", "REVOKE UPDATE ON pgm.docs FROM pgm_writer; DROP ROLE pgm_writer", ""},
		// Запись без членства: право на колонку у PUBLIC, вид над таблицей.
		{"GRANT UPDATE (body) ON pgm.docs TO PUBLIC", "pgm_ai can update pgm.docs", "REVOKE UPDATE (body) ON pgm.docs FROM PUBLIC", ""},
		{"CREATE VIEW pgm.docs_v AS SELECT * FROM pgm.docs; CREATE VIEW pgm.docs_vv AS SELECT * FROM pgm.docs_v; GRANT DELETE ON pgm.docs_vv TO pgm_ai", "pgm_ai can delete pgm.docs_vv", "DROP VIEW pgm.docs_vv, pgm.docs_v", ""},
		// Владение: схемой — DROP SCHEMA … CASCADE мимо журнала (R1-5).
		{"CREATE SCHEMA pgm_own AUTHORIZATION pgm_ai; REVOKE CREATE ON SCHEMA pgm_own FROM pgm_ai", "pgm_ai owns schema pgm_own", "DROP SCHEMA pgm_own", ""},
		// Умолчания прав: секция, созданная позже, — без триггера «кто» (R2-3).
		{"ALTER DEFAULT PRIVILEGES IN SCHEMA pgm GRANT UPDATE ON TABLES TO pgm_ai", "pgm_ai gets UPDATE on new tables (default privileges of postgres in schema pgm)", "ALTER DEFAULT PRIVILEGES IN SCHEMA pgm REVOKE UPDATE ON TABLES FROM pgm_ai", ""},
		// То, что initdb оставил суперпользователям: файлы сервера (R1-2).
		{"GRANT EXECUTE ON FUNCTION pg_read_binary_file(text) TO pgm_ai", "pgm_ai can call pg_read_binary_file(text)", "REVOKE EXECUTE ON FUNCTION pg_read_binary_file(text) FROM pgm_ai", ""},
		{"GRANT SELECT ON pg_authid TO pgm_ai", "pgm_ai can read pg_authid", "REVOKE SELECT ON pg_authid FROM pgm_ai", ""},
		// Роль сервера: SQL агента идёт ею (R2-6, T-1, T-3, T-5).
		{"GRANT EXECUTE ON FUNCTION pg_logical_emit_message(bool, text, text) TO pgm_agent", "pgm_agent can call pg_logical_emit_message(boolean,text,text)", "REVOKE EXECUTE ON FUNCTION pg_logical_emit_message(bool, text, text) FROM pgm_agent", "pgm_agent can call pg_logical_emit_message(boolean,text,text)"},
		{"GRANT EXECUTE ON FUNCTION pg_terminate_backend(integer, bigint) TO pgm_agent", "pgm_agent can call pg_terminate_backend(integer,bigint)", "REVOKE EXECUTE ON FUNCTION pg_terminate_backend(integer, bigint) FROM pgm_agent", "pgm_agent can call pg_terminate_backend(integer,bigint)"},
		{"GRANT pg_signal_backend TO pgm_agent", "pgm_agent is a member of pg_signal_backend", "REVOKE pg_signal_backend FROM pgm_agent", "pgm_agent is a member of pg_signal_backend"},
		{"GRANT evidence_owner TO pgm_agent", "pgm_agent is a member of evidence_owner", "REVOKE evidence_owner FROM pgm_agent", "pgm_agent is a member of evidence_owner"},
		{"CREATE ROLE pgm_dba SUPERUSER; GRANT pgm_dba TO pgm_agent", "pgm_agent is a superuser, may replicate or create roles (as pgm_dba)", "DROP ROLE pgm_dba", "pgm_agent is a superuser, may replicate or create roles (as pgm_dba)"},
		// Заход 2: права без членства и владения, через PUBLIC и прямые выдачи.
		// Функция расширения вне pg_catalog, оставленная суперпользователям:
		// dblink_connect_u входит любой ролью (R1-1).
		{"CREATE SCHEMA pgm_ext; CREATE EXTENSION dblink SCHEMA pgm_ext; GRANT EXECUTE ON FUNCTION pgm_ext.dblink_connect_u(text, text) TO pgm_agent",
			"pgm_agent can call pgm_ext.dblink_connect_u(text,text)", "DROP EXTENSION dblink; DROP SCHEMA pgm_ext", "pgm_agent can call pgm_ext.dblink_connect_u(text,text)"},
		// То же правило без SECURITY DEFINER: функция pgstattuple, которую расширение
		// оставило pg_stat_scan_tables (dblink_connect_u ловит и проверка SECURITY DEFINER).
		{"CREATE SCHEMA pgm_ext2; CREATE EXTENSION pgstattuple SCHEMA pgm_ext2; GRANT EXECUTE ON FUNCTION pgm_ext2.pg_relpages(text) TO pgm_ai",
			"pgm_ai can call pgm_ext2.pg_relpages(text)", "DROP EXTENSION pgstattuple; DROP SCHEMA pgm_ext2", ""},
		// Сторонний сервер с сопоставлением FOR PUBLIC: SQL ролью владельца, мимо сборщика (R1-2).
		{"CREATE FOREIGN DATA WRAPPER pgm_fdw; CREATE SERVER pgm_loop FOREIGN DATA WRAPPER pgm_fdw; GRANT USAGE ON FOREIGN SERVER pgm_loop TO PUBLIC",
			"pgm_ai can use foreign server pgm_loop", "DROP SERVER pgm_loop; DROP FOREIGN DATA WRAPPER pgm_fdw", "pgm_agent can use foreign server pgm_loop"},
		// Чужая функция SECURITY DEFINER, открытая PUBLIC по умолчанию: P-276 снова (R1-3, R2-4).
		{"CREATE FUNCTION public.pgm_end(int) RETURNS bool LANGUAGE sql SECURITY DEFINER AS 'SELECT pg_terminate_backend($1)'",
			"pgm_agent can call public.pgm_end(integer), a SECURITY DEFINER function of postgres", "DROP FUNCTION public.pgm_end(int)", "a SECURITY DEFINER function of postgres"},
		// Параметр уровня суперпользователя: track_counts = off — и счёт строк молчит (R1-6).
		{"GRANT SET ON PARAMETER track_counts TO pgm_agent", "pgm_agent can SET parameter track_counts", "REVOKE SET ON PARAMETER track_counts FROM pgm_agent", "pgm_agent can SET parameter track_counts"},
		// Право на колонку таблицы, которую initdb оставил суперпользователям (R1-7).
		{"GRANT SELECT (rolname, rolpassword) ON pg_authid TO pgm_ai", "pgm_ai can read pg_authid.rolpassword", "REVOKE SELECT (rolname, rolpassword) ON pg_authid FROM pgm_ai", ""},
	} {
		if strings.Contains(c[0], "ON PARAMETER") && one("SELECT current_setting('server_version_num')::int >= 150000") != "t" {
			continue
		}
		exec(c[0])
		if _, err := admin.Query(script); err == nil || !strings.Contains(err.Error(), c[1]) {
			t.Fatalf("the setup script took the roles after %s: %v", c[0], err)
		}
		exec("ROLLBACK")
		s.Close() // новое соединение — новая проверка роли
		err := s.CheckRole()
		if c[3] == "" && err != nil || c[3] != "" && (!errors.Is(err, mcpserver.ErrSharedRole) || !strings.Contains(err.Error(), c[3])) {
			t.Fatalf("esmcp after %s: %v", c[0], err)
		}
		exec(c[2])
	}
	// Большой объект и временная функция агента улик не касаются и прав не
	// требуют: повторный скрипт из-за них не отказывает (R2-3, R1-8, заход 2).
	if _, err := ai.Query("SELECT lo_from_bytea(0, 'x'); CREATE FUNCTION pg_temp.pgm_f() RETURNS int LANGUAGE sql AS 'SELECT 1'"); err != nil {
		t.Fatal(err)
	}
	exec(script)
	exec("SELECT lo_unlink(oid) FROM pg_largeobject_metadata WHERE lomowner = 'pgm_ai'::regrole")
	// Установка до п. 39: у роли агента запись и отметки, функции отметок — у
	// того, кто запускал скрипт, pg_logical_emit_message открыта PUBLIC (так в
	// PostgreSQL по умолчанию). Скрипт переводит её на новую.
	exec("GRANT UPDATE ON pgm.docs TO pgm_ai; GRANT USAGE ON SCHEMA evidence TO pgm_ai; GRANT EXECUTE ON FUNCTION evidence.mark_action(json) TO pgm_ai; " +
		"GRANT EXECUTE ON FUNCTION pg_logical_emit_message(bool, text, text) TO PUBLIC; ALTER FUNCTION evidence.mark_action(json) OWNER TO postgres; " +
		// Схема отметок — агента, роль evidence_owner — со входом и паролем: так
		// агент удалял функции отметок, а с паролем писал в журнал сам (R1-6, R1-7).
		"ALTER SCHEMA evidence OWNER TO pgm_ai; ALTER ROLE evidence_owner LOGIN PASSWORD 'pw'; " +
		"GRANT EXECUTE ON FUNCTION pg_terminate_backend(integer, bigint), pg_cancel_backend(integer) TO PUBLIC")
	exec(script)
	if got := one("SELECT pg_get_userbyid(nspowner) || ' ' || (SELECT rolcanlogin || ' ' || (rolpassword IS NULL) FROM pg_authid WHERE rolname = 'evidence_owner') FROM pg_namespace WHERE nspname = 'evidence'"); got != "evidence_owner false true" {
		t.Fatalf("the schema of the marks and its owner after the setup script: %s", got)
	}
	if got := one("SELECT has_function_privilege('pgm_agent', 'pg_terminate_backend(integer, bigint)', 'EXECUTE')::text || has_function_privilege('pgm_agent', 'pg_cancel_backend(integer)', 'EXECUTE')::text"); got != "falsefalse" {
		t.Fatalf("the server may end or cancel sessions: %s", got)
	}
	for _, sql := range []string{"UPDATE pgm.docs SET body = 'direct' WHERE id = 1", "SELECT evidence.mark_action('{}')", "SELECT pg_logical_emit_message(false, 'evidence/refused', '{}')"} {
		if _, err := ai.Query(sql); err == nil {
			t.Fatalf("the setup script left the agent a right of the old setup: %s", sql)
		}
	}
	if got := one("SELECT has_schema_privilege('pgm_ai', 'evidence', 'USAGE')::text"); got != "false" {
		t.Fatalf("the agent still uses the schema of the marks: %s", got)
	}
	// Владелец отметок — роль без входа и без прав суперпользователя.
	if got := one("SELECT string_agg(DISTINCT pg_get_userbyid(p.proowner) || ' ' || r.rolsuper || ' ' || r.rolcanlogin, ',') FROM pg_proc p JOIN pg_roles r ON r.oid = p.proowner WHERE p.pronamespace = 'evidence'::regnamespace"); got != "evidence_owner false false" {
		t.Fatalf("the owner of the marks: %s", got)
	}

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
	// Сеансов роли сервера не обрывает и сама роль сервера: SQL агента идёт
	// ею, и так он гасил отметки вне транзакции (R1-3, R2-6, T-1).
	if text, isErr := tool("query", `{"sql":"SELECT pg_terminate_backend(pid) FROM pg_stat_activity WHERE usename = 'pgm_agent'"}`); !isErr || !strings.Contains(text, "permission denied for function pg_terminate_backend") {
		t.Fatalf("the SQL of the agent ends the sessions of the server: %v %s", isErr, text)
	}

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
	// Роль сервера в группе без права на отметки (SQL агента входил в неё —
	// set_config('role', …) — и отметка ложилась с отказом) теперь не берут
	// ни -setup-sql, ни esmcp: членств у роли сервера нет (п. 39).
	exec("SELECT pg_create_logical_replication_slot('pgm_peek', 'test_decoding')")
	for _, args := range []string{
		`{"statements":["DELETE FROM pgm.docs","SELECT set_config('standard_conforming_strings', 'off', true)"],"reason":"close \"dormant\" docs"}`,
		`{"statements":["DELETE FROM pgm.docs","SELECT set_config('client_encoding', 'EUC_JP', true)"],"reason":"очистка документов"}`,
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
		Dial: func(params map[string]string) (mcpserver.DB, error) {
			c := dcfg
			c.Params = params
			return pgwire.Dial(ctx, c)
		}}, nil)
	call := func(s *mcpserver.Server, args string) string {
		var m struct {
			Result struct {
				Content []struct{ Text string } `json:"content"`
			} `json:"result"`
		}
		json.Unmarshal(s.Handle([]byte(`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"execute","arguments":`+args+`}}`)), &m)
		return m.Result.Content[0].Text
	}
	// Последняя команда действия ставит простою в транзакции 1 мс: по сети
	// между запросами сервера больше, и база рвала сеанс раньше, чем ложилась
	// отметка об отказе, — тревоги не было (T заход 2). Здесь сеть — задержка
	// перед каждым запросом; сервер возвращает и таймауты (ownTimeouts).
	idle := mcpserver.New(mcpserver.Config{Agent: "live-bot-idle", RowLimit: 1, Version: "test",
		Dial: func(params map[string]string) (mcpserver.DB, error) {
			c := dcfg
			c.Params = params
			conn, err := pgwire.Dial(ctx, c)
			if err != nil {
				return nil, err
			}
			return laggy{conn}, nil
		}}, nil)
	if text := call(idle, `{"statements":["DELETE FROM pgm.docs","SELECT set_config('idle_in_transaction_session_timeout', '1', true)"],"reason":"idle"}`); !strings.Contains(text, "would change 5 rows") {
		t.Fatal(text)
	}
	if text := call(rated, `{"statements":["UPDATE pgm.docs SET body = 'r' WHERE id = 1","SELECT set_config('client_encoding', 'EUC_JP', false)"]}`); !strings.Contains(text, `"committed"`) {
		t.Fatal(text)
	}
	if text := call(rated, `{"sql":"UPDATE pgm.docs SET body = 'r' WHERE id = 2","reason":"ещё раз: \"dormant\" docs"}`); !strings.Contains(text, "was refused: 1 actions in the last minute") {
		t.Fatal(text)
	}
	exec("ALTER ROLE pgm_agent RESET standard_conforming_strings")
	// Умолчания роли, с которыми отметка вне транзакции не ложилась вовсе:
	// statement_timeout = 1 мс (и jit, чтобы не успеть). Тревоги не было ни о
	// частоте, ни о таймауте; теперь параметры входа сервера сильнее умолчаний
	// роли (R2, T заход 2).
	exec("ALTER ROLE pgm_agent SET statement_timeout = 1; ALTER ROLE pgm_agent SET jit_above_cost = 0")
	dial := func(params map[string]string) (mcpserver.DB, error) {
		c := dcfg
		c.Params = params
		return pgwire.Dial(ctx, c)
	}
	rated = mcpserver.New(mcpserver.Config{Agent: "live-bot-2", ActionsPerMinute: 1, Version: "test", Dial: dial}, nil)
	if text := call(rated, `{"sql":"UPDATE pgm.docs SET body = 'r' WHERE id = 3"}`); !strings.Contains(text, `"committed"`) {
		t.Fatal(text)
	}
	if text := call(rated, `{"sql":"UPDATE pgm.docs SET body = 'r' WHERE id = 4"}`); !strings.Contains(text, "was refused: 1 actions in the last minute") {
		t.Fatal(text)
	}
	slow := mcpserver.New(mcpserver.Config{Agent: "live-bot-3", StatementTimeout: 200 * time.Millisecond, Version: "test", Dial: dial}, nil)
	if text := call(slow, `{"sql":"SELECT pg_sleep(2)"}`); !strings.Contains(text, "longer than 200ms") {
		t.Fatal(text)
	}
	exec("ALTER ROLE pgm_agent RESET statement_timeout; ALTER ROLE pgm_agent RESET jit_above_cost")
	// Отказ вне транзакции — сообщение не транзакционное: в слот оно
	// попадает, когда журнал сброшен на диск (walwriter, доли секунды).
	want := `"cause":"row-limit" "cause":"row-limit" "cause":"row-limit" "cause":"rate" "cause":"rate" "cause":"timeout"`
	var marks string
	for wait := time.Now().Add(5 * time.Second); time.Now().Before(wait); time.Sleep(50 * time.Millisecond) {
		marks = one(`SELECT string_agg(substring(data from '"cause":"[a-z-]+"'), ' ' ORDER BY lsn) FROM pg_logical_slot_peek_changes('pgm_peek', NULL, NULL) WHERE data LIKE '%evidence/refused%'`)
		if marks == want {
			break
		}
	}
	if marks != want {
		t.Fatalf("refusal markers in the database log: %q", marks)
	}

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
	// И функция для скрипта настройки, который выполнит владелец: точное
	// совпадение типов выигрывает у pg_catalog.left(text, integer) при любом
	// порядке пути (R2 заход 2).
	if _, err := agent.Query("CREATE FUNCTION public.left(name, integer) RETURNS text LANGUAGE plpgsql AS $$BEGIN RAISE EXCEPTION 'the function of the agent ran as %', current_user; END$$"); err != nil {
		t.Fatal(err)
	}
	s = mcpserver.New(mcpserver.Config{Agent: "live-bot", RowLimit: 1, Version: "test",
		Dial: func(params map[string]string) (mcpserver.DB, error) {
			c := dcfg
			c.Params = params
			return pgwire.Dial(ctx, c)
		}}, nil)
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
	// А -setup-sql такую роль теперь не берёт: ни своих объектов (роль
	// сервера ничем не владеет), ни права их заводить.
	if _, err := admin.Query(script); err == nil || !strings.Contains(err.Error(), `pgm_agent owns function public."left"(name,integer)`) {
		t.Fatalf("the setup script took a role of the server that owns functions: %v", err)
	}
	exec("ROLLBACK; DROP FUNCTION public.pg_stat_get_xact_tuples_inserted(oid), public.pg_stat_get_xact_tuples_updated(oid), public.pg_stat_get_xact_tuples_deleted(oid), " +
		"public.pg_current_xact_id(), public.left(name, integer); ALTER ROLE pgm_agent RESET search_path")
	if _, err := admin.Query(script); err == nil || !strings.Contains(err.Error(), "pgm_agent can CREATE in schema public") {
		t.Fatalf("the setup script took an agent role that can CREATE: %v", err)
	}
	exec("ROLLBACK; REVOKE CREATE ON SCHEMA public FROM pgm_agent")
	// Право — через роль, которой агент может стать, но не наследует
	// (NOINHERIT; с PostgreSQL 16 — и WITH INHERIT FALSE): has_schema_privilege
	// его не видит, а SET ROLE агенту доступен (R2 заход 2).
	// NOINHERIT — до GRANT: с PostgreSQL 16 атрибут роли задаёт наследование
	// только членствам, выданным после него.
	exec("CREATE ROLE pgm_maker NOLOGIN; GRANT CREATE ON SCHEMA public TO pgm_maker; ALTER ROLE pgm_agent NOINHERIT; GRANT pgm_maker TO pgm_agent")
	if one("SELECT has_schema_privilege('pgm_agent', 'public', 'CREATE')::text") != "false" {
		t.Fatal("the right is inherited: the case is not the one under test")
	}
	if _, err := admin.Query(script); err == nil || !strings.Contains(err.Error(), "pgm_agent is a member of pgm_maker") {
		t.Fatalf("the setup script took an agent role that can become a role that can CREATE: %v", err)
	}
	exec("ROLLBACK; ALTER ROLE pgm_agent INHERIT; REVOKE CREATE ON SCHEMA public FROM pgm_maker; DROP ROLE pgm_maker")
	// Права, с которыми записи не вернуть или их не будет: TRUNCATE, TRIGGER,
	// владение таблицей — и через группу (T заход 2).
	exec("GRANT TRUNCATE, TRIGGER ON pgm.docs TO pgm_agent")
	if _, err := admin.Query(script); err == nil || !strings.Contains(err.Error(), "pgm_agent can trigger pgm.docs") || !strings.Contains(err.Error(), "pgm_agent can truncate pgm.docs") {
		t.Fatalf("the setup script took an agent role with TRUNCATE and TRIGGER: %v", err)
	}
	exec("ROLLBACK; REVOKE TRUNCATE, TRIGGER ON pgm.docs FROM pgm_agent")
	owner := one("SELECT current_user")
	exec("ALTER TABLE pgm.docs OWNER TO pgm_agent")
	if _, err := admin.Query(script); err == nil || !strings.Contains(err.Error(), "pgm_agent owns table pgm.docs") {
		t.Fatalf("the setup script took an agent role that owns a table: %v", err)
	}
	// Владение переходит вместе с правами прежнего владельца: права роли
	// сервера ушли с ним, и скрипт выдаёт их снова.
	exec("ROLLBACK; ALTER TABLE pgm.docs OWNER TO " + pgwire.Ident(owner))
	exec(script)
	// И права, с которыми агент выключает триггеры или становится
	// суперпользователем: SET на session_replication_role (PostgreSQL 15+),
	// программы сервера, CREATEROLE (R1, R2 заход 3).
	for _, c := range [][3]string{
		{"GRANT SET ON PARAMETER session_replication_role TO pgm_agent", "pgm_agent can SET parameter session_replication_role", "REVOKE SET ON PARAMETER session_replication_role FROM pgm_agent"},
		{"GRANT pg_execute_server_program TO pgm_agent", "pgm_agent is a member of pg_execute_server_program", "REVOKE pg_execute_server_program FROM pgm_agent"},
		{"ALTER ROLE pgm_agent CREATEROLE", "pgm_agent is a superuser, may replicate or create roles", "ALTER ROLE pgm_agent NOCREATEROLE"},
	} {
		if c[0][:9] == "GRANT SET" && one("SELECT current_setting('server_version_num')::int >= 150000") != "t" {
			continue
		}
		exec(c[0])
		if _, err := admin.Query(script); err == nil || !strings.Contains(err.Error(), c[1]) {
			t.Fatalf("the setup script took an agent role after %s: %v", c[0], err)
		}
		exec("ROLLBACK; " + c[2])
	}

	// Отметки идут правами владельца: временный домен агента pg_temp.text с
	// проверкой на его функцию — не названный в пути pg_temp ищется первым для
	// типов — срабатывал в приведении ::text внутри отметки, и функция агента
	// шла правами того, кто выполнил -setup-sql (R2, заход 3).
	temp, err := pgwire.Dial(ctx, dcfg)
	if err != nil {
		t.Fatal(err)
	}
	defer temp.Close()
	if _, err := temp.Query(`CREATE FUNCTION pg_temp.pwn(v pg_catalog.text) RETURNS boolean LANGUAGE plpgsql AS $f$BEGIN
  IF current_user <> session_user THEN RAISE EXCEPTION 'the function of the agent ran as %', current_user; END IF; RETURN true; END$f$;
CREATE DOMAIN pg_temp.text AS pg_catalog.text CHECK (pg_temp.pwn(VALUE))`); err != nil {
		t.Fatal(err)
	}
	for _, sql := range []string{"SELECT evidence.mark_refused('{}')", "SELECT evidence.mark_action('{}')", "UPDATE pgm.docs SET body = body WHERE id = 1"} {
		if _, err := temp.Query(sql); err != nil {
			t.Fatalf("%s under a temporary domain of the agent: %v", sql, err)
		}
	}
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

// TestLiveMCPLostCommit — COMMIT действия ждёт синхронную реплику, а роль
// агента своей сессией обрывает сеанс сервера (pg_terminate_backend своей
// роли): база у себя уже зафиксировала. Агенту — «может быть зафиксировано»,
// строки идут в окно, людям — отметка unknown. Раньше строки таких действий в
// окно не шли, и окно обходилось сколько угодно раз, а тревоги не было (P-258,
// R1 заход 2). Тест на время ставит synchronous_standby_names на весь кластер:
// фиксации чужих сеансов в это время ждут.
func TestLiveMCPLostCommit(t *testing.T) {
	base := os.Getenv("PGINPUT_TEST_DSN")
	if base == "" {
		t.Skip("PGINPUT_TEST_DSN is not set")
	}
	ctx := context.Background()
	dial := func(dsn string) *pgwire.Conn {
		t.Helper()
		cfg, err := pgwire.ParseDSN(dsn)
		if err != nil {
			t.Fatal(err)
		}
		c, err := pgwire.Dial(ctx, cfg)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { c.Close() })
		return c
	}
	admin := dial(base + " user=postgres")
	exec := func(c *pgwire.Conn, sql string) {
		t.Helper()
		if _, err := c.Query(sql); err != nil {
			t.Fatalf("%s: %v", sql, err)
		}
	}
	one := func(sql string) string {
		t.Helper()
		row, ok, err := admin.QueryRow(sql)
		if err != nil || !ok || row[0] == nil {
			t.Fatalf("%s: %v", sql, err)
		}
		return *row[0]
	}
	tidy := func() {
		admin.Query("ROLLBACK")
		admin.Query("ALTER SYSTEM RESET synchronous_standby_names")
		admin.Query("SELECT pg_reload_conf()")
		admin.Query("SELECT pg_drop_replication_slot(slot_name) FROM pg_replication_slots WHERE slot_name = 'pgl_peek'")
		admin.Query("DROP PUBLICATION IF EXISTS pgl_pub")
		admin.Query("DROP SCHEMA IF EXISTS pgl CASCADE")
	}
	exec(admin, "SET client_min_messages = warning")
	tidy()
	defer tidy()
	exec(admin, "CREATE SCHEMA pgl; CREATE TABLE pgl.docs (id int PRIMARY KEY, body text); INSERT INTO pgl.docs SELECT g, 'v' FROM generate_series(1, 5) g")
	cfg := Config{DSN: base + " user=pgl_tap", Slot: "pgl_slot", Publication: "pgl_pub", Dir: t.TempDir(), MCPRoles: []string{"pgl_agent"}, Tables: []string{"pgl.docs"}}
	if err := cfg.Validate(); err != nil {
		t.Fatal(err)
	}
	script, err := SetupSQL(&cfg)
	if err != nil {
		t.Fatal(err)
	}
	exec(admin, script)
	exec(admin, "SELECT pg_create_logical_replication_slot('pgl_peek', 'test_decoding')")

	path := filepath.Join(t.TempDir(), "receipts.jsonl")
	f, err := os.OpenFile(path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	dcfg, err := pgwire.ParseDSN(base + " user=pgl_agent application_name=esmcp/pgl-bot")
	if err != nil {
		t.Fatal(err)
	}
	// Окно — одна строка в час.
	s := mcpserver.New(mcpserver.Config{Agent: "pgl-bot", WindowRows: 1, Window: time.Hour, Version: "test", Receipts: f, ReceiptsPath: path,
		Dial: func(params map[string]string) (mcpserver.DB, error) {
			c := dcfg
			c.Params = params
			return pgwire.Dial(ctx, c)
		}}, nil)
	tool := func(args string) (string, bool) {
		var m struct {
			Result struct {
				Content []struct{ Text string } `json:"content"`
				IsError bool                    `json:"isError"`
			} `json:"result"`
		}
		out := s.Handle([]byte(`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"execute","arguments":` + args + `}}`))
		if json.Unmarshal(out, &m) != nil || len(m.Result.Content) != 1 {
			return string(out), true
		}
		return m.Result.Content[0].Text, m.Result.IsError
	}

	// Синхронная реплика, которой нет (стоит или отстаёт): COMMIT ждёт её.
	exec(admin, "ALTER SYSTEM SET synchronous_standby_names = 'pgl_missing_standby'")
	exec(admin, "SELECT pg_reload_conf()")
	for wait := time.Now().Add(5 * time.Second); one("SHOW synchronous_standby_names") != "pgl_missing_standby"; time.Sleep(20 * time.Millisecond) {
		if time.Now().After(wait) {
			t.Fatal("the setting did not take")
		}
	}
	// Ответ на COMMIT теряется: сессию сервера, пока COMMIT ждёт реплику, рвут
	// извне — как обрыв сети или администратор. Сам агент этого не может: его
	// роль не член роли сервера (DECISIONS, п. 39; проверено в TestLiveMCP).
	killer := admin
	var told []string
	for i := 1; i <= 3; i++ {
		done := make(chan string, 1)
		go func() {
			text, _ := tool(`{"sql":"UPDATE pgl.docs SET body = 'agent' WHERE id = ` + strconv.Itoa(i) + `","reason":"again"}`)
			done <- text
		}()
		var text string
	wait:
		for {
			select {
			case text = <-done:
				break wait
			case <-time.After(20 * time.Millisecond):
				killer.Query("SELECT pg_terminate_backend(pid) FROM pg_stat_activity WHERE usename = 'pgl_agent' AND application_name = 'esmcp/pgl-bot' AND wait_event = 'SyncRep'")
			}
		}
		told = append(told, text)
	}
	exec(admin, "ALTER SYSTEM RESET synchronous_standby_names")
	exec(admin, "SELECT pg_reload_conf()")
	if !strings.Contains(told[0], "may have been committed") || !strings.Contains(told[0], "the operators are alerted") ||
		!strings.Contains(told[1], "would have changed 2 rows in the last 1h0m0s") || !strings.Contains(told[2], "would have changed 2 rows") {
		t.Fatalf("the agent was told:\n%s", strings.Join(told, "\n"))
	}
	if got := one("SELECT string_agg(id || '=' || body, ',' ORDER BY id) FROM pgl.docs"); got != "1=agent,2=v,3=v,4=v,5=v" {
		t.Fatalf("the table: %s", got)
	}
	var marks string
	for wait := time.Now().Add(5 * time.Second); time.Now().Before(wait); time.Sleep(50 * time.Millisecond) {
		marks = one(`SELECT coalesce(string_agg(substring(data from '"cause":"[a-z-]+"'), ' ' ORDER BY lsn), '') FROM pg_logical_slot_peek_changes('pgl_peek', NULL, NULL) WHERE data LIKE '%evidence/refused%'`)
		if strings.Count(marks, "cause") == 3 {
			break
		}
	}
	if marks != `"cause":"unknown" "cause":"window-rows" "cause":"window-rows"` {
		t.Fatalf("markers in the database log: %q", marks)
	}
}

// laggy — соединение, как по сети: каждый запрос уходит с задержкой.
type laggy struct{ *pgwire.Conn }

func (c laggy) Query(sql string) ([]pgwire.Result, error) {
	time.Sleep(10 * time.Millisecond)
	return c.Conn.Query(sql)
}
