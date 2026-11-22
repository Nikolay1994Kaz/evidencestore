package pginput

import (
	"context"
	"encoding/json"
	"log/slog"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/Nikolay1994Kaz/evidencestore/internal/mcpserver"
	"github.com/Nikolay1994Kaz/evidencestore/internal/pgtap"
	"github.com/Nikolay1994Kaz/evidencestore/internal/pgundo"
	"github.com/Nikolay1994Kaz/evidencestore/internal/pgwire"
)

// TestLiveUndoUnderOddSessionDefaults — откат при умолчаниях базы и ролей,
// которые меняют, как читается текст значений (P-257, R1 заход 2). Образы
// строк сборщик получает текстом в своём сеансе, откат читает их в своём:
//   - сборщик с IntervalStyle = sql_standard пишет «−1 день −2 часа» как
//     '-1 2:00:00', а сеанс со стилем postgres читает это как «−1 день +2 часа»;
//   - при array_nulls = off (умолчание базы у старых приложений; роли агента —
//     он сам) '{NULL,a}' читается со строкой "NULL" вместо NULL.
//
// Сверка после отката сравнивает две одинаково прочитанные стороны и порчу
// не видела: esundo писал «every row is as it was», undo_apply — успех без
// differs_from_before. Запуск — как у TestLive (PGINPUT_TEST_DSN); всё своё —
// в схеме pgs, роли — с приставкой pgs_.
func TestLiveUndoUnderOddSessionDefaults(t *testing.T) {
	base := os.Getenv("PGINPUT_TEST_DSN")
	if base == "" {
		t.Skip("PGINPUT_TEST_DSN is not set")
	}
	ctx := context.Background()
	dial := func(user, app string) *pgwire.Conn {
		t.Helper()
		cfg, err := pgwire.ParseDSN(base + " user=" + user)
		if err != nil {
			t.Fatal(err)
		}
		cfg.AppName = app
		c, err := pgwire.Dial(ctx, cfg)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { c.Close() })
		return c
	}
	admin := dial("postgres", "")
	exec := func(c *pgwire.Conn, sql string) {
		t.Helper()
		if _, err := c.Query(sql); err != nil {
			t.Fatalf("%s: %v", sql, err)
		}
	}
	one := func(c *pgwire.Conn, sql string) string {
		t.Helper()
		row, ok, err := c.QueryRow(sql)
		if err != nil || !ok || row[0] == nil {
			t.Fatalf("%s: %v", sql, err)
		}
		return *row[0]
	}
	db := pgwire.Ident(one(admin, "SELECT current_database()"))
	tidy := func() {
		admin.Query("ROLLBACK")
		admin.Query("ALTER DATABASE " + db + " RESET array_nulls")
		admin.Query("ALTER ROLE pgs_tap RESET IntervalStyle")
		admin.Query("ALTER ROLE pgs_agent RESET ALL")
		admin.Query("DROP OPERATOR IF EXISTS public.= (varchar, varchar)")
		admin.Query("DROP FUNCTION IF EXISTS public.pgs_eq(varchar, varchar)")
		admin.Query("REVOKE CREATE ON SCHEMA public FROM pgs_agent")
		admin.Query("SELECT pg_drop_replication_slot(slot_name) FROM pg_replication_slots WHERE slot_name = 'pgs_slot'")
		admin.Query("DROP PUBLICATION IF EXISTS pgs_pub")
		admin.Query("DROP SCHEMA IF EXISTS pgs CASCADE")
	}
	exec(admin, "SET client_min_messages = warning")
	tidy()
	defer tidy()
	exec(admin, `CREATE SCHEMA pgs; CREATE TABLE pgs.vals (id int PRIMARY KEY, tags text[], span interval);
INSERT INTO pgs.vals VALUES (1, '{NULL,a}', '-1 days -02:00:00'), (2, '{NULL,b}', '-2 days -03:00:00'), (3, '{c}', '3 days');
-- Ключ varchar: у pg_catalog нет =(varchar, varchar), сравнение идёт через text.
CREATE TABLE pgs.tick (id varchar PRIMARY KEY, note text); INSERT INTO pgs.tick VALUES ('k1', 'human');
-- Триггер владельца: вставка в vals пишет 50 строк журнала таблицы.
CREATE TABLE pgs.fanout (n int);
CREATE FUNCTION pgs.fan() RETURNS trigger LANGUAGE plpgsql SECURITY DEFINER AS $f$ BEGIN INSERT INTO pgs.fanout SELECT g FROM generate_series(1, 50) g; RETURN NEW; END $f$;
CREATE TRIGGER fan AFTER INSERT ON pgs.vals FOR EACH ROW EXECUTE FUNCTION pgs.fan()`)
	cfg := Config{DSN: base + " user=pgs_tap", Slot: "pgs_slot", Publication: "pgs_pub", Dir: t.TempDir(), Roles: []string{"pgs_agent"}, Tables: []string{"pgs.vals", "pgs.tick"}}
	if err := cfg.Validate(); err != nil {
		t.Fatal(err)
	}
	script, err := SetupSQL(&cfg)
	if err != nil {
		t.Fatal(err)
	}
	exec(admin, script)
	// Сборщик пишет интервалы стилем sql_standard (умолчание его роли).
	exec(admin, "ALTER ROLE pgs_tap SET IntervalStyle = sql_standard")
	sink := &memSink{}
	src, err := New(cfg, slog.New(slog.NewTextHandler(logTo{t}, nil)))
	if err != nil {
		t.Fatal(err)
	}
	if err := src.Open(sink.cursor, sink); err != nil {
		t.Fatal(err)
	}
	defer src.Close()
	if _, err := src.ReadAll(ctx); err != nil {
		t.Fatal(err)
	}
	bodies := func(xid uint32) ([][]byte, error) {
		if _, err := src.ReadAll(ctx); err != nil {
			return nil, err
		}
		e, found, err := pgtap.Lookup(filepath.Join(cfg.Dir, pgtap.IndexFile), xid)
		if err != nil || !found {
			t.Fatalf("transaction %d is not in the index: %v", xid, err)
		}
		return sink.bodies[e.FirstSeq-1 : e.LastSeq], nil
	}
	row := func(id string) string {
		return one(admin, "SELECT tags::text || ' ' || ((tags)[1] IS NULL)::text || ' ' || span::text FROM pgs.vals WHERE id = "+id)
	}

	// 1. Человек, esundo: база с array_nulls = off, сеанс — новый, правами владельца.
	agent := dial("pgs_agent", "")
	res, err := agent.Query("BEGIN; UPDATE pgs.vals SET tags = '{c}', span = '1 day' WHERE id = 1; SELECT pg_current_xact_id()::xid::text; COMMIT")
	if err != nil {
		t.Fatal(err)
	}
	xid, _ := strconv.ParseUint(*res[len(res)-2].Rows[0][0], 10, 32)
	lines, _ := bodies(uint32(xid))
	p, err := pgundo.Build(uint32(xid), lines)
	if err != nil {
		t.Fatal(err)
	}
	exec(admin, "ALTER DATABASE "+db+" SET array_nulls = off")
	human := dial("postgres", "esundo")
	statuses, err := p.Check(human)
	if err != nil {
		t.Fatal(err)
	}
	if ok, _, bad := pgundo.Tally(statuses); ok != 1 || bad != 0 {
		t.Fatalf("check: %d steps to apply, %d conflicts", ok, bad)
	}
	done, err := p.Apply(human, map[string]any{"by": "test"})
	if err != nil {
		t.Fatal(err)
	}
	if got := row("1"); got != "{NULL,a} true -1 days -02:00:00" || done.Differ != nil {
		t.Fatalf("the undo by a person: row %q (want {NULL,a} true -1 days -02:00:00), differs %v", got, done.Differ)
	}

	// 2. Агент, undo_apply: своей сессией мимо сервера ставит своей роли
	// array_nulls = off и обрывает сеанс сервера — следующий вызов войдёт
	// заново, с новым умолчанием.
	path := filepath.Join(t.TempDir(), "receipts.jsonl")
	f, err := os.OpenFile(path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	dcfg, err := pgwire.ParseDSN(base + " user=pgs_agent application_name=esmcp/pgs-bot")
	if err != nil {
		t.Fatal(err)
	}
	s := mcpserver.New(mcpserver.Config{Agent: "pgs-bot", RowLimit: 5, Version: "test", Receipts: f, ReceiptsPath: path, Fetch: bodies,
		Dial: func(params map[string]string) (mcpserver.DB, error) {
			c := dcfg
			c.Params = params
			return pgwire.Dial(ctx, c)
		}}, nil)
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
	text, isErr := tool("execute", `{"sql":"UPDATE pgs.vals SET tags = '{d}', span = '2 days' WHERE id = 2","reason":"test"}`)
	if isErr {
		t.Fatal(text)
	}
	var action struct {
		ID string `json:"action_id"`
	}
	json.Unmarshal([]byte(text), &action)
	exec(agent, "ALTER ROLE pgs_agent SET array_nulls = off")
	exec(agent, "SELECT pg_terminate_backend(pid) FROM pg_stat_activity WHERE usename = 'pgs_agent' AND application_name = 'esmcp/pgs-bot'")
	for wait := time.Now().Add(5 * time.Second); one(admin, "SELECT count(*) FROM pg_stat_activity WHERE application_name = 'esmcp/pgs-bot'") != "0"; time.Sleep(20 * time.Millisecond) {
		if time.Now().After(wait) {
			t.Fatal("the session of the server is still there")
		}
	}
	text, isErr = tool("undo_apply", `{"action_id":"`+action.ID+`","reason":"put it back"}`)
	if isErr || strings.Contains(text, "differs_from_before") {
		t.Fatalf("undo_apply: %v %s", isErr, text)
	}
	if got := row("2"); got != "{NULL,b} true -2 days -03:00:00" {
		t.Fatalf("the undo by the agent: row %q (want {NULL,b} true -2 days -03:00:00)", got)
	}
	exec(admin, "ALTER ROLE pgs_agent RESET array_nulls")

	// 3. Откат — под таймаутами сервера: агент снимает своей роли lock_timeout
	// и statement_timeout и держит замок строки своей сессией. Раньше откат
	// висел на нём сколько угодно, и под замком агента стояли все его
	// действия (R2 заход 2).
	exec(agent, "ALTER ROLE pgs_agent SET lock_timeout = 0; ALTER ROLE pgs_agent SET statement_timeout = 0")
	locked := mcpserver.New(mcpserver.Config{Agent: "pgs-bot", LockTimeout: 300 * time.Millisecond, Version: "test", Receipts: f, ReceiptsPath: path, Fetch: bodies,
		Dial: func(params map[string]string) (mcpserver.DB, error) {
			c := dcfg
			c.Params = params
			return pgwire.Dial(ctx, c)
		}}, nil)
	s = locked
	text, isErr = tool("execute", `{"sql":"UPDATE pgs.vals SET tags = '{e}' WHERE id = 1","reason":"test"}`)
	if isErr {
		t.Fatal(text)
	}
	json.Unmarshal([]byte(text), &action)
	exec(agent, "BEGIN; SELECT 1 FROM pgs.vals WHERE id = 1 FOR UPDATE")
	done2 := make(chan string, 1)
	go func() {
		text, _ := tool("undo_apply", `{"action_id":"`+action.ID+`","reason":"put it back"}`)
		done2 <- text
	}()
	select {
	case text = <-done2:
		if !strings.Contains(text, "lock timeout") {
			t.Fatalf("the undo on a held lock: %s", text)
		}
	case <-time.After(5 * time.Second):
		exec(agent, "ROLLBACK")
		<-done2
		t.Fatal("the undo waited on the lock of the agent for 5 s")
	}
	exec(agent, "ROLLBACK")
	exec(admin, "ALTER ROLE pgs_agent RESET lock_timeout; ALTER ROLE pgs_agent RESET statement_timeout")

	// 4. Свой оператор агента в сеансе человека: агенту позже дали CREATE на
	// public, и он завёл =(varchar, varchar) — точное совпадение, которого в
	// pg_catalog нет, выигрывало при любом порядке пути, и esundo звал функцию
	// агента правами владельца (R2 заход 2). Путь сверки и отката — только
	// pg_catalog (pgundo.Path), типы у сборщика — со схемой.
	res, err = agent.Query("BEGIN; UPDATE pgs.tick SET note = 'agent' WHERE id = 'k1'; SELECT pg_current_xact_id()::xid::text; COMMIT")
	if err != nil {
		t.Fatal(err)
	}
	xid, _ = strconv.ParseUint(*res[len(res)-2].Rows[0][0], 10, 32)
	lines, _ = bodies(uint32(xid))
	if p, err = pgundo.Build(uint32(xid), lines); err != nil {
		t.Fatal(err)
	}
	exec(admin, "GRANT CREATE ON SCHEMA public TO pgs_agent")
	exec(agent, `CREATE FUNCTION public.pgs_eq(varchar, varchar) RETURNS bool LANGUAGE plpgsql AS $f$BEGIN RAISE EXCEPTION 'the function of the agent ran as %', current_user; END$f$;
CREATE OPERATOR public.= (LEFTARG = varchar, RIGHTARG = varchar, FUNCTION = public.pgs_eq)`)
	human = dial("postgres", "esundo")
	if statuses, err = p.Check(human); err != nil {
		t.Fatalf("the check by a person: %v", err)
	}
	if done, err = p.Apply(human, map[string]any{"by": "test"}); err != nil {
		t.Fatalf("the undo by a person: %v", err)
	}
	// Свой запрос — тоже после того, как оператора не стало: он перехватил бы
	// и его.
	exec(admin, "DROP OPERATOR public.= (varchar, varchar); DROP FUNCTION public.pgs_eq(varchar, varchar); REVOKE CREATE ON SCHEMA public FROM pgs_agent")
	if got := one(admin, "SELECT note FROM pgs.tick WHERE id = 'k1'"); got != "human" {
		t.Fatalf("pgs.tick after the undo: %q", got)
	}

	// 5. Строки отката — по статистике его транзакции: вернуть удалённую
	// строку — одна по шагам, а триггер владельца на вставку пишет ещё 50.
	// Раньше откат шёл как одна строка мимо предела 5 (T заход 2).
	s = mcpserver.New(mcpserver.Config{Agent: "pgs-bot", RowLimit: 5, Version: "test", Receipts: f, ReceiptsPath: path, Fetch: bodies,
		Dial: func(params map[string]string) (mcpserver.DB, error) {
			c := dcfg
			c.Params = params
			return pgwire.Dial(ctx, c)
		}}, nil)
	text, isErr = tool("execute", `{"sql":"DELETE FROM pgs.vals WHERE id = 3","reason":"test"}`)
	if isErr {
		t.Fatal(text)
	}
	json.Unmarshal([]byte(text), &action)
	text, isErr = tool("undo_apply", `{"action_id":"`+action.ID+`","reason":"put it back"}`)
	if !isErr || !strings.Contains(text, "it changed 51 rows") || one(admin, "SELECT count(*) FROM pgs.vals WHERE id = 3") != "0" {
		t.Fatalf("the undo past the row limit: %v %s", isErr, text)
	}
}
