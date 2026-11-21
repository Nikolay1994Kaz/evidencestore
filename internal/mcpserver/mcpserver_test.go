package mcpserver

import (
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Nikolay1994Kaz/evidencestore/internal/pgwire"
)

// fakeDB записывает запросы и отвечает по подстроке.
type fakeDB struct {
	log  []string
	fail map[string]error
}

func (d *fakeDB) Query(sql string) ([]pgwire.Result, error) {
	d.log = append(d.log, sql)
	for sub, err := range d.fail {
		if strings.Contains(sql, sub) {
			return nil, err
		}
	}
	v := "751"
	switch {
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
	// Порядок: транзакция, отметка действия первой, номер транзакции, запрос, фиксация.
	if len(db.log) != 5 || db.log[0] != "BEGIN" || !strings.HasPrefix(db.log[1], "SELECT evidence.mark_action('{") ||
		!strings.Contains(db.log[1], `"action_id":"a-1"`) || !strings.Contains(db.log[1], `"agent":"support-bot"`) ||
		!strings.HasPrefix(db.log[3], "UPDATE") || db.log[4] != "COMMIT" {
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
	if db.log[0] != "BEGIN TRANSACTION READ ONLY" || db.log[2] != "ROLLBACK" {
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
	s.execute("UPDATE t SET a = 1", "")
	db.fail = nil
	if _, err := s.execute("UPDATE t SET a = 1", ""); err != nil || dials != 2 {
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
