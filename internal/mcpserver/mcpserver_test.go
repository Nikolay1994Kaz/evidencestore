package mcpserver

import (
	"bytes"
	"compress/gzip"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/Nikolay1994Kaz/evidencestore/internal/pgwire"
)

// fakeDB записывает запросы и отвечает по подстроке.
type fakeDB struct {
	log     []string
	fail    map[string]error
	answers func(sql string) ([]pgwire.Result, bool)
	tx      byte // состояние транзакции, как его сказала бы база
	// prepared — команды агента по именам PREPARE: EXECUTE отвечает за них.
	prepared map[string]string
}

func (d *fakeDB) Query(sql string) ([]pgwire.Result, error) {
	d.log = append(d.log, sql)
	res, err := d.answer(sql)
	d.track(sql, err)
	return res, err
}

// track ведёт состояние транзакции: BEGIN открывает, COMMIT и ROLLBACK
// закрывают, ошибка внутри ломает.
func (d *fakeDB) track(sql string, err error) {
	switch {
	case strings.HasPrefix(sql, "BEGIN") && err == nil:
		d.tx = pgwire.TxOpen
	case sql == "COMMIT" || sql == "ROLLBACK":
		d.tx = pgwire.TxIdle
	case err != nil && d.tx == pgwire.TxOpen:
		d.tx = pgwire.TxFailed
	}
}

// Pipeline — пачка, как её исполнила бы база: PREPARE запоминает команду
// (или отвергает её, если в тексте есть подстрока из fail), EXECUTE отвечает
// за неё; первая ошибка останавливает пачку.
func (d *fakeDB) Pipeline(sqls []string) ([]pgwire.Result, error) {
	var out []pgwire.Result
	for _, sql := range sqls {
		d.log = append(d.log, sql)
		res, err := d.step(sql)
		if err != nil {
			if d.tx == pgwire.TxOpen {
				d.tx = pgwire.TxFailed
			}
			return out, err
		}
		out = append(out, res...)
	}
	return out, nil
}

func (d *fakeDB) step(sql string) ([]pgwire.Result, error) {
	rest, isPrepare := strings.CutPrefix(sql, "PREPARE ")
	if !isPrepare {
		if name, ok := strings.CutPrefix(sql, "EXECUTE "); ok {
			return d.answer(d.prepared[name])
		}
		return d.answer(sql)
	}
	for sub, err := range d.fail {
		if strings.Contains(sql, sub) {
			return nil, err
		}
	}
	name, body, _ := strings.Cut(rest, " AS ")
	if d.prepared == nil {
		d.prepared = map[string]string{}
	}
	d.prepared[name] = body
	return []pgwire.Result{{Tag: "PREPARE"}}, nil
}

func (d *fakeDB) TxStatus() byte {
	if d.tx == 0 {
		return pgwire.TxIdle
	}
	return d.tx
}

func (d *fakeDB) answer(sql string) ([]pgwire.Result, error) {
	if d.answers != nil {
		if res, ok := d.answers(sql); ok {
			return res, nil
		}
	}
	for sub, err := range d.fail {
		if strings.Contains(sql, sub) {
			return nil, err
		}
	}
	v := "751"
	switch {
	case strings.Contains(sql, "pg_current_xact_id()::xid::text, pg_current_xact_id()::text"):
		// Номер транзакции (32 бита и с эпохой), при пределах — счёт строк до SQL агента.
		cols, row := []string{"xid", "xid8"}, []*string{&v, &v}
		if strings.Contains(sql, "pg_stat_get_xact_tuples") {
			zero := "0"
			cols, row = append(cols, "rows"), append(row, &zero)
		}
		return []pgwire.Result{{Columns: cols, Rows: [][]*string{row}, Tag: "SELECT 1"}}, nil
	case strings.Contains(sql, "pg_current_xact_id"):
		return []pgwire.Result{{Columns: []string{"xid"}, Rows: [][]*string{{&v}}, Tag: "SELECT 1"}}, nil
	case strings.HasPrefix(sql, "SELECT id"):
		a, b := "1", "2"
		return []pgwire.Result{{Columns: []string{"id", "note"}, Rows: [][]*string{{&a, nil}, {&b, &a}}, Tag: "SELECT 2"}}, nil
	case strings.HasPrefix(sql, "UPDATE"):
		return []pgwire.Result{{Tag: "UPDATE 3"}}, nil
	}
	return []pgwire.Result{{Tag: strings.Fields(sql)[0]}}, nil
}

func newServer(t *testing.T, db *fakeDB) (*Server, string) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "receipts.jsonl")
	f, err := os.OpenFile(path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { f.Close() })
	s := New(Config{Agent: "support-bot", Receipts: f, Version: "test", MaxRows: 1, Dial: func() (DB, error) { return db, nil }}, nil)
	s.newID = func() string { return "a-1" }
	return s, path
}

func ask(t *testing.T, s *Server, msg string) map[string]any {
	t.Helper()
	out := s.Handle([]byte(msg))
	if out == nil {
		t.Fatalf("no answer to %s", msg)
	}
	if bytes.ContainsRune(out, '\n') {
		t.Fatalf("an answer with a newline inside: %q", out)
	}
	var m map[string]any
	if err := json.Unmarshal(out, &m); err != nil {
		t.Fatal(err)
	}
	return m
}

const meta = `"_meta":{"io.modelcontextprotocol/protocolVersion":"2026-07-28","io.modelcontextprotocol/clientInfo":{"name":"c","version":"1"}}`

func callText(t *testing.T, s *Server, name, args string) (string, bool) {
	t.Helper()
	m := ask(t, s, `{"jsonrpc":"2.0","id":7,"method":"tools/call","params":{"name":"`+name+`","arguments":`+args+`,`+meta+`}}`)
	res, ok := m["result"].(map[string]any)
	if !ok {
		t.Fatalf("no result: %v", m)
	}
	return res["content"].([]any)[0].(map[string]any)["text"].(string), res["isError"].(bool)
}

func TestModernDiscoverAndList(t *testing.T) {
	s, _ := newServer(t, &fakeDB{})
	m := ask(t, s, `{"jsonrpc":"2.0","id":"d1","method":"server/discover","params":{`+meta+`}}`)
	res := m["result"].(map[string]any)
	if m["id"] != "d1" || res["resultType"] != "complete" || res["supportedVersions"].([]any)[0] != "2026-07-28" ||
		res["capabilities"].(map[string]any)["tools"] == nil || res["_meta"].(map[string]any)[metaServer] == nil {
		t.Fatalf("%v", m)
	}
	res = ask(t, s, `{"jsonrpc":"2.0","id":2,"method":"tools/list","params":{`+meta+`}}`)["result"].(map[string]any)
	if len(res["tools"].([]any)) != 3 || res["resultType"] != "complete" || res["cacheScope"] != "public" || res["ttlMs"] == nil {
		t.Fatalf("%v", res)
	}
	// В ревизии 2026-07-28 ping нет.
	if e := ask(t, s, `{"jsonrpc":"2.0","id":3,"method":"ping","params":{`+meta+`}}`)["error"].(map[string]any); e["code"] != float64(-32601) {
		t.Fatalf("%v", e)
	}
}

func TestUnsupportedVersionNamesTheSupported(t *testing.T) {
	s, _ := newServer(t, &fakeDB{})
	m := ask(t, s, `{"jsonrpc":"2.0","id":1,"method":"tools/list","params":{"_meta":{"io.modelcontextprotocol/protocolVersion":"1900-01-01"}}}`)
	e := m["error"].(map[string]any)
	data := e["data"].(map[string]any)
	if e["code"] != float64(-32022) || data["requested"] != "1900-01-01" || data["supported"].([]any)[0] != "2026-07-28" {
		t.Fatalf("%v", m)
	}
}

func TestLegacyHandshake(t *testing.T) {
	s, _ := newServer(t, &fakeDB{})
	res := ask(t, s, `{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"old","version":"0"}}}`)["result"].(map[string]any)
	if res["protocolVersion"] != "2025-06-18" || res["serverInfo"] == nil || res["resultType"] != nil {
		t.Fatalf("%v", res)
	}
	// Незнакомую версию не повторяем: предлагаем свою последнюю прежней эпохи.
	res = ask(t, s, `{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2020-01-01"}}`)["result"].(map[string]any)
	if res["protocolVersion"] != "2025-11-25" {
		t.Fatalf("%v", res)
	}
	if out := s.Handle([]byte(`{"jsonrpc":"2.0","method":"notifications/initialized"}`)); out != nil {
		t.Fatalf("a notification was answered: %s", out)
	}
	if r := ask(t, s, `{"jsonrpc":"2.0","id":2,"method":"ping"}`)["result"]; r == nil {
		t.Fatal("legacy ping not answered")
	}
	res = ask(t, s, `{"jsonrpc":"2.0","id":3,"method":"tools/list"}`)["result"].(map[string]any)
	if len(res["tools"].([]any)) != 3 || res["resultType"] != nil {
		t.Fatalf("%v", res)
	}
}

func TestExecuteMarksTheActionAndKeepsAReceipt(t *testing.T) {
	db := &fakeDB{}
	s, path := newServer(t, db)
	text, isErr := callText(t, s, "execute", `{"sql":"UPDATE accounts SET note = 'it''s' WHERE id = 6","reason":"cleanup"}`)
	if isErr {
		t.Fatal(text)
	}
	var out map[string]any
	json.Unmarshal([]byte(text), &out)
	if out["action_id"] != "a-1" || out["xid"] != "751" || out["outcome"] != "committed" || out["statements"].([]any)[0] != "UPDATE 3" {
		t.Fatalf("%v", out)
	}
	// Порядок: чистый сеанс, транзакция, свои настройки сеанса, отметка
	// действия первой, номер транзакции; пачка — путь агента, команда агента
	// подготовкой и исполнением, отложенное — сразу, свои настройки снова;
	// фиксация.
	if len(db.log) != 13 || db.log[0] != "DISCARD ALL" || db.log[1] != "BEGIN" || !strings.HasPrefix(db.log[2], "SET LOCAL search_path = pg_catalog, pg_temp; ") ||
		!strings.HasPrefix(db.log[3], "SELECT evidence.mark_action('{") ||
		!strings.Contains(db.log[3], `"action_id":"a-1"`) || !strings.Contains(db.log[3], `"agent":"support-bot"`) ||
		db.log[5] != "SET LOCAL search_path TO DEFAULT" ||
		db.log[6] != "PREPARE es_agent_0 AS UPDATE accounts SET note = 'it''s' WHERE id = 6" || db.log[7] != "EXECUTE es_agent_0" ||
		db.log[8] != "SET CONSTRAINTS ALL IMMEDIATE" || db.log[9] != "SET LOCAL search_path = pg_catalog, pg_temp" || db.log[12] != "COMMIT" {
		t.Fatalf("%q", db.log)
	}
	data, _ := os.ReadFile(path)
	var rc Receipt
	if err := json.Unmarshal(bytes.TrimSpace(data), &rc); err != nil {
		t.Fatal(err)
	}
	if rc.ActionID != "a-1" || rc.XID != "751" || rc.Outcome != "committed" || rc.Reason != "cleanup" || !strings.Contains(string(rc.Client), `"name":"c"`) {
		t.Fatalf("%+v", rc)
	}
	list, _ := callText(t, s, "actions", `{}`)
	if !strings.Contains(list, `"action_id":"a-1"`) {
		t.Fatal(list)
	}
}

func TestExecuteFailureRollsBackAndIsRecorded(t *testing.T) {
	db := &fakeDB{fail: map[string]error{"TRUNCATE": &pgwire.PgError{Severity: "ERROR", Code: "42501", Message: "permission denied for table accounts"}}}
	s, path := newServer(t, db)
	text, isErr := callText(t, s, "execute", `{"sql":"TRUNCATE accounts"}`)
	if !isErr || !strings.Contains(text, "permission denied") || !strings.Contains(text, "rolled back") {
		t.Fatalf("%v %s", isErr, text)
	}
	if db.log[len(db.log)-1] != "ROLLBACK" {
		t.Fatalf("%q", db.log)
	}
	data, _ := os.ReadFile(path)
	if !strings.Contains(string(data), `"outcome":"failed"`) || !strings.Contains(string(data), "42501") {
		t.Fatalf("%s", data)
	}
}

func TestQueryIsReadOnlyAndBounded(t *testing.T) {
	db := &fakeDB{}
	s, path := newServer(t, db)
	text, isErr := callText(t, s, "query", `{"sql":"SELECT id, note FROM accounts"}`)
	if isErr || text != `{"columns":["id","note"],"rows":[["1",null]],"truncated":true}` {
		t.Fatalf("%v %s", isErr, text)
	}
	if db.log[0] != "DISCARD ALL" || db.log[1] != "BEGIN TRANSACTION READ ONLY" || !strings.HasPrefix(db.log[2], "SET LOCAL search_path = pg_catalog, pg_temp; ") ||
		db.log[3] != "SET LOCAL search_path TO DEFAULT" || db.log[4] != "PREPARE es_agent_0 AS SELECT id, note FROM accounts" ||
		db.log[5] != "EXECUTE es_agent_0" || db.log[len(db.log)-1] != "ROLLBACK" || slices.Contains(db.log, "SET CONSTRAINTS ALL IMMEDIATE") {
		t.Fatalf("%q", db.log)
	}
	if data, _ := os.ReadFile(path); len(data) != 0 {
		t.Fatal("a read left a receipt")
	}
	if text, isErr := callText(t, s, "query", `{"sql":"UPDATE accounts SET note = 'x'"}`); !isErr || !strings.Contains(text, "execute") {
		t.Fatalf("%v %s", isErr, text)
	}
}

func TestBrokenConnectionIsReopened(t *testing.T) {
	db := &fakeDB{fail: map[string]error{"BEGIN": errors.New("broken pipe")}}
	dials := 0
	s := New(Config{Agent: "a", Dial: func() (DB, error) { dials++; return db, nil }}, nil)
	s.execute([]string{"UPDATE t SET a = 1"}, "")
	db.fail = nil
	if _, err := s.execute([]string{"UPDATE t SET a = 1"}, ""); err != nil || dials != 2 {
		t.Fatalf("%v, dials %d", err, dials)
	}
}

func TestBadInput(t *testing.T) {
	s, _ := newServer(t, &fakeDB{})
	for msg, code := range map[string]float64{
		`not json`: -32700,
		`{"jsonrpc":"2.0","id":1,"method":"nope"}`:                                                          -32601,
		`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"drop_everything","arguments":{}}}`: -32602,
		`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{}}`:                                        -32602,
	} {
		if e, _ := ask(t, s, msg)["error"].(map[string]any); e == nil || e["code"] != code {
			t.Errorf("%s: %v", msg, e)
		}
	}
	if text, isErr := callText(t, s, "execute", `{"sql":"  "}`); !isErr || !strings.Contains(text, "empty") {
		t.Fatalf("%v %s", isErr, text)
	}
}

func TestServeAnswersLineByLine(t *testing.T) {
	s, _ := newServer(t, &fakeDB{})
	in := strings.NewReader(`{"jsonrpc":"2.0","id":1,"method":"tools/list"}` + "\n\n" + `{"jsonrpc":"2.0","method":"notifications/initialized"}` + "\n" + `{"jsonrpc":"2.0","id":2,"method":"ping"}`)
	var out bytes.Buffer
	if err := s.Serve(in, &out); err != nil {
		t.Fatal(err)
	}
	if lines := strings.Split(strings.TrimSpace(out.String()), "\n"); len(lines) != 2 || !strings.Contains(lines[1], `"id":2`) {
		t.Fatalf("%q", out.String())
	}
}

// journalLine — транзакция 751 одной записью сборщика: строка 6 была "a", стала "b".
func journalLine() []byte {
	stream := `{"t":"H","v":1,"xid":751,"actions":[{"role":"support_bot","info":{"action_id":"a-1","agent":"support-bot","tool":"execute"}}]}
{"t":"R","id":1,"schema":"public","table":"accounts","identity":"f","columns":["id","note"],"types":["integer","text"],"pk":["id"]}
{"t":"U","r":1,"old":["6","a"],"new":["6","b"]}
{"t":"U","r":1,"old":["7","a"],"new":["7","b"]}
{"t":"C","changes":2}
`
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	gz.Write([]byte(stream))
	gz.Close()
	return fmt.Appendf(nil, `{"xid":751,"part":1,"last":true,"gz":"%s"}`, base64.StdEncoding.EncodeToString(buf.Bytes()))
}

func TestUndoPreviewAndApply(t *testing.T) {
	text := func(s string) *string { return &s }
	db := &fakeDB{}
	s, path := newServer(t, db)
	s.cfg.ReceiptsPath = path
	fetched := 0
	s.cfg.Fetch = func(xid uint32) ([][]byte, error) {
		fetched++
		if xid != 751 {
			return nil, errors.New("wrong xid")
		}
		return [][]byte{journalLine()}, nil
	}
	// Без настройки хранилища инструментов отката нет вовсе.
	if n := len(ask(t, New(Config{Agent: "a"}, nil), `{"jsonrpc":"2.0","id":1,"method":"tools/list"}`)["result"].(map[string]any)["tools"].([]any)); n != 3 {
		t.Fatalf("%d tools without a store", n)
	}
	if n := len(ask(t, s, `{"jsonrpc":"2.0","id":1,"method":"tools/list"}`)["result"].(map[string]any)["tools"].([]any)); n != 5 {
		t.Fatalf("%d tools", n)
	}
	if _, isErr := callText(t, s, "execute", `{"sql":"UPDATE accounts SET note = 'b'"}`); isErr {
		t.Fatal("execute failed")
	}
	// База: строка 7 всё ещё такая, какой её оставило действие; строку 6 потом поправил человек.
	db.answers = func(sql string) ([]pgwire.Result, bool) {
		switch {
		case strings.Contains(sql, "pg_attribute"):
			return []pgwire.Result{{Rows: [][]*string{{text("id"), text("")}, {text("note"), text("")}}}}, true
		case strings.HasPrefix(sql, "SELECT count(*) FILTER"):
			// Сверка после отката: строка на месте, но note в ней переписал триггер таблицы.
			return []pgwire.Result{{Rows: [][]*string{{text("0"), text("0"), text("1")}}}}, true
		case strings.HasPrefix(sql, "SELECT w.step"):
			return []pgwire.Result{{Rows: [][]*string{{text("1"), text("ok"), nil}, {text("2"), text("changed"), text(`{"id":6,"note":"human"}`)}}}}, true
		case strings.HasPrefix(sql, `UPDATE "public"."accounts" t SET`):
			return []pgwire.Result{{Tag: "UPDATE 1"}}, true
		}
		return nil, false
	}
	out, isErr := callText(t, s, "undo_preview", `{"action_id":"a-1"}`)
	if isErr {
		t.Fatal(out)
	}
	var pv map[string]any
	json.Unmarshal([]byte(out), &pv)
	c := pv["conflicts"].([]any)[0].(map[string]any)
	if pv["to_apply"] != float64(1) || pv["conflicts_total"] != float64(1) || c["key"] != "id=6" || c["state"] != "changed" ||
		c["columns"].([]any)[0].(map[string]any)["now"] != "human" {
		t.Fatalf("%s", out)
	}
	before := len(db.log)
	s.newID = func() string { return "u-1" }
	out, isErr = callText(t, s, "undo_apply", `{"action_id":"a-1","reason":"wrong rows"}`)
	if isErr || !strings.Contains(out, `"undo_action_id":"u-1"`) || !strings.Contains(out, `"applied":1`) ||
		!strings.Contains(out, `"differs_from_before":[{"table":"public.accounts","column":"note","rows":1}]`) {
		t.Fatalf("%v %s", isErr, out)
	}
	// Откат — отметка с номером своего действия и того, что он возвращает; одна команда на годный шаг.
	var mark, update string
	for _, q := range db.log[before:] {
		if strings.Contains(q, "evidence.mark_undo") {
			mark = q
		}
		if strings.HasPrefix(q, "UPDATE") {
			update = q
		}
	}
	if !strings.Contains(mark, `"action_id":"u-1"`) || !strings.Contains(mark, `"undoes_action":"a-1"`) || !strings.Contains(update, "(1, '7'::integer") || strings.Contains(update, "'6'") {
		t.Fatalf("mark %s\nupdate %s", mark, update)
	}
	// Сверка и откат — с чистого сеанса и pg_catalog первым в пути: функции и
	// операторы под системными именами из схем роли агента их не подменят.
	var path0, catalog int = -1, -1
	for i, q := range db.log[before:] {
		if q == "DISCARD ALL" && path0 < 0 {
			path0 = i
		}
		if strings.Contains(q, "set_config('search_path', pg_catalog.concat_ws(', ', 'pg_catalog', ") && catalog < 0 {
			catalog = i
		}
	}
	if path0 < 0 || catalog < path0 || !strings.Contains(db.log[before+catalog+1], "pg_attribute") {
		t.Fatalf("the session of the undo: %q", db.log[before:])
	}
	data, _ := os.ReadFile(path)
	if !strings.Contains(string(data), `"tool":"undo_apply"`) || !strings.Contains(string(data), `"undoes":"a-1"`) || fetched != 2 {
		t.Fatalf("fetched %d\n%s", fetched, data)
	}
	// Чужое и несостоявшееся действие откатить нельзя.
	if out, isErr := callText(t, s, "undo_apply", `{"action_id":"nope"}`); !isErr || !strings.Contains(out, "not in this server's receipts") {
		t.Fatalf("%v %s", isErr, out)
	}
}

// limited — сервер с пределом строк на действие; stat — что база отвечает на
// вопрос, сколько строк изменила транзакция (после SQL агента; до него — 0).
func limited(t *testing.T, limit int, stat string) (*Server, *fakeDB, string) {
	t.Helper()
	return limitedFrom(t, limit, "0", stat)
}

// limitedFrom — то же, но до SQL агента статистика сеанса уже показывает
// before строк: изменения прошлых транзакций, не сброшенные базой.
func limitedFrom(t *testing.T, limit int, before, stat string) (*Server, *fakeDB, string) {
	t.Helper()
	xid := "751"
	db := &fakeDB{answers: func(sql string) ([]pgwire.Result, bool) {
		switch {
		case stat == "":
		case strings.Contains(sql, "pg_current_xact_id") && strings.Contains(sql, "pg_stat_get_xact_tuples"):
			return []pgwire.Result{{Columns: []string{"xid", "xid8", "rows"}, Rows: [][]*string{{&xid, &xid, &before}}, Tag: "SELECT 1"}}, true
		case strings.Contains(sql, "pg_stat_get_xact_tuples"):
			return []pgwire.Result{{Columns: []string{"sum"}, Rows: [][]*string{{&stat}}, Tag: "SELECT 1"}}, true
		}
		return nil, false
	}}
	s, path := newServer(t, db)
	s.cfg.RowLimit = limit
	return s, db, path
}

// Предохранитель: действие, которое меняет больше строк, чем разрешено,
// откатывается до фиксации. Агент получает отказ, в журнале базы остаётся
// отметка для тревоги, в квитанциях — исход refused.
func TestRowLimitRefusesBeforeCommit(t *testing.T) {
	s, db, path := limited(t, 500, "700")
	text, isErr := callText(t, s, "execute", `{"sql":"UPDATE accounts SET balance = 0","reason":"close inactive accounts"}`)
	if !isErr {
		t.Fatalf("an action over the limit went through: %s", text)
	}
	for _, want := range []string{"action a-1 was refused and rolled back, nothing changed", "would change 700 rows", "at most 500", "Do not split"} {
		if !strings.Contains(text, want) {
			t.Fatalf("the refusal lacks %q: %s", want, text)
		}
	}
	// Порядок: изменения, счёт строк, отметка об отказе, откат. Фиксации нет.
	n := len(db.log)
	if db.log[n-4] != "SET LOCAL ROLE NONE" || !strings.Contains(db.log[n-3], "pg_stat_get_xact_tuples") ||
		!strings.Contains(db.log[n-2], "SELECT evidence.mark_refused('{") || db.log[n-1] != "ROLLBACK" || slices.Contains(db.log, "COMMIT") {
		t.Fatalf("%q", db.log)
	}
	for _, want := range []string{`"action_id":"a-1"`, `"agent":"support-bot"`, `"rows":700`, `"limit":500`, `"reason":"close inactive accounts"`} {
		if !strings.Contains(db.log[n-2], want) {
			t.Fatalf("the refusal marker lacks %s: %s", want, db.log[n-2])
		}
	}
	data, _ := os.ReadFile(path)
	var rc Receipt
	if err := json.Unmarshal(bytes.TrimSpace(data), &rc); err != nil {
		t.Fatal(err)
	}
	if rc.Outcome != "refused" || rc.Rows != 700 || !strings.Contains(rc.Error, "at most 500") || rc.Tags[0] != "UPDATE 3" {
		t.Fatalf("receipt %+v", rc)
	}
	// Отменять нечего: действие не зафиксировано.
	s.cfg.Fetch = func(uint32) ([][]byte, error) { return nil, errors.New("must not be asked") }
	if text, isErr := callText(t, s, "undo_preview", `{"action_id":"a-1"}`); !isErr || !strings.Contains(text, "did not commit (refused)") {
		t.Fatalf("%v %s", isErr, text)
	}
}

func TestRowLimitLetsSmallActionsThrough(t *testing.T) {
	s, db, path := limited(t, 500, "500") // ровно предел — можно
	text, isErr := callText(t, s, "execute", `{"sql":"UPDATE accounts SET note = 'x' WHERE id < 501"}`)
	if isErr || !strings.Contains(text, `"outcome":"committed"`) {
		t.Fatalf("%v %s", isErr, text)
	}
	if db.log[len(db.log)-1] != "COMMIT" || strings.Contains(strings.Join(db.log, "\n"), "mark_refused") {
		t.Fatalf("%q", db.log)
	}
	data, _ := os.ReadFile(path)
	if !strings.Contains(string(data), `"rows":500`) {
		t.Fatalf("%s", data)
	}
	// Агент узнаёт о пределе из описания инструмента, а не из первого отказа.
	list := ask(t, s, `{"jsonrpc":"2.0","id":1,"method":"tools/list","params":{"_meta":{"io.modelcontextprotocol/protocolVersion":"2026-07-28"}}}`)
	raw, _ := json.Marshal(list)
	if !strings.Contains(string(raw), "at most 500 rows") {
		t.Fatalf("the tool description does not name the limit: %s", raw)
	}
	plain, _ := newServer(t, &fakeDB{})
	raw, _ = json.Marshal(ask(t, plain, `{"jsonrpc":"2.0","id":1,"method":"tools/list","params":{"_meta":{"io.modelcontextprotocol/protocolVersion":"2026-07-28"}}}`))
	if strings.Contains(string(raw), "at most") {
		t.Fatal("a server without a limit names one")
	}
}

// Статистика в базе выключена и говорит «ноль»: тогда считают ответы на
// операторы. А если сосчитать нельзя вовсе, действие не фиксируется.
func TestRowLimitDoesNotFailOpen(t *testing.T) {
	s, db, _ := limited(t, 2, "0")
	if text, isErr := callText(t, s, "execute", `{"sql":"UPDATE accounts SET note = 'x'"}`); !isErr || !strings.Contains(text, "would change 3 rows") {
		t.Fatalf("%v %s", isErr, text)
	}
	if db.log[len(db.log)-1] != "ROLLBACK" {
		t.Fatalf("%q", db.log)
	}

	s, db, path := limited(t, 2, "")
	db.fail = map[string]error{"pg_stat_get_xact_tuples": &pgwire.PgError{Severity: "ERROR", Code: "42501", Message: "permission denied for view pg_stat_xact_user_tables"}}
	text, isErr := callText(t, s, "execute", `{"sql":"UPDATE accounts SET note = 'x'"}`)
	if !isErr || !strings.Contains(text, "could not be counted") || !strings.Contains(text, "rolled back") {
		t.Fatalf("%v %s", isErr, text)
	}
	if db.log[len(db.log)-1] != "ROLLBACK" || strings.Contains(strings.Join(db.log, "\n"), "COMMIT") {
		t.Fatalf("%q", db.log)
	}
	data, _ := os.ReadFile(path)
	if !strings.Contains(string(data), `"outcome":"failed"`) {
		t.Fatalf("%s", data)
	}
}

// Статистика сеанса держит изменения прошлых транзакций, пока база их не
// сбросит: правка одной строки вслед за правкой сорока — это одна строка, а не
// сорок одна. До исправления P-240 действие отказывалось чужими строками.
func TestRowCountIsTheActionsOwn(t *testing.T) {
	s, db, path := limitedFrom(t, 5, "40", "41")
	text, isErr := callText(t, s, "execute", `{"sql":"UPDATE accounts SET note = 'x' WHERE id = 1"}`)
	if isErr || !strings.Contains(text, `"outcome":"committed"`) {
		t.Fatalf("%v %s", isErr, text)
	}
	// Счёт «до» — в одном запросе с номером транзакции, лишнего обмена нет.
	if !strings.Contains(db.log[4], "pg_current_xact_id") || !strings.Contains(db.log[4], "pg_stat_get_xact_tuples") {
		t.Fatalf("%q", db.log)
	}
	data, _ := os.ReadFile(path)
	if !strings.Contains(string(data), `"rows":3`) { // 41 − 40 = 1, но ответ на оператор — UPDATE 3: берётся большее
		t.Fatalf("%s", data)
	}
	// И наоборот: своих строк больше предела — отказ, как раньше.
	s, _, _ = limitedFrom(t, 5, "40", "50")
	if text, isErr := callText(t, s, "execute", `{"sql":"UPDATE accounts SET note = 'x'"}`); !isErr || !strings.Contains(text, "would change 10 rows") {
		t.Fatalf("%v %s", isErr, text)
	}
}
