package mcpserver

import (
	"encoding/json"
	"errors"
	"fmt"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Nikolay1994Kaz/evidencestore/internal/pgwire"
)

// Команды агента — одной пачкой: сначала все PREPARE, потом все EXECUTE.
// Отказ любой из них при подготовке останавливает пачку до исполнения первой.
func TestStatementsArePreparedFirstInOneBatch(t *testing.T) {
	db := &fakeDB{}
	path := filepath.Join(t.TempDir(), "receipts.jsonl")
	s := serverOn(t, db, path, nil)
	text, isErr := callText(t, s, "execute", `{"statements":["UPDATE accounts SET balance = balance - 1 WHERE id = 1","UPDATE accounts SET balance = balance + 1 WHERE id = 2"],"reason":"move"}`)
	if isErr || !strings.Contains(text, `"statements":["UPDATE 3","UPDATE 3"]`) {
		t.Fatalf("%v %s", isErr, text)
	}
	want := []string{"PREPARE es_agent_0 AS UPDATE accounts SET balance = balance - 1 WHERE id = 1", "PREPARE es_agent_1 AS UPDATE accounts SET balance = balance + 1 WHERE id = 2",
		"EXECUTE es_agent_0", "EXECUTE es_agent_1", "COMMIT"}
	if got := db.log[len(db.log)-5:]; strings.Join(got, "\n") != strings.Join(want, "\n") {
		t.Fatalf("%q", got)
	}
	rc := receipts(t, path)
	if len(rc) != 1 || len(rc[0].Statements) != 2 || rc[0].SQL != rc[0].Statements[0]+";\n"+rc[0].Statements[1] {
		t.Fatalf("receipt %+v", rc)
	}
}

// База отвергла команду при подготовке (COMMIT, SET, две в одном тексте —
// синтаксическая ошибка): ничего не исполнено, агент узнаёт, какая команда и
// почему, транзакция откатывается.
func TestRefusedStatementIsNamedAndNothingRuns(t *testing.T) {
	syntax := &pgwire.PgError{Severity: "ERROR", Code: "42601", Message: `syntax error at or near "COMMIT"`}
	db := &fakeDB{fail: map[string]error{"AS COMMIT": syntax}}
	path := filepath.Join(t.TempDir(), "receipts.jsonl")
	s := serverOn(t, db, path, nil)
	text, isErr := callText(t, s, "execute", `{"statements":["DELETE FROM accounts","COMMIT"]}`)
	if !isErr || !strings.Contains(text, "action a-1 failed and was rolled back: statement 2 was not taken, nothing ran") ||
		!strings.Contains(text, "BEGIN, COMMIT, ROLLBACK, SET") || !strings.Contains(text, "42601") {
		t.Fatalf("%v %s", isErr, text)
	}
	log := strings.Join(db.log, "\n")
	if strings.Contains(log, "EXECUTE") || db.log[len(db.log)-1] != "ROLLBACK" {
		t.Fatalf("%q", db.log)
	}
	if rc := receipts(t, path); len(rc) != 1 || rc[0].Outcome != "failed" {
		t.Fatalf("receipt %+v", rc)
	}
	// Одна команда — без номера; другая ошибка при подготовке — как есть.
	db.fail = map[string]error{"nope": &pgwire.PgError{Severity: "ERROR", Code: "42P01", Message: `relation "nope" does not exist`}}
	if text, _ := callText(t, s, "execute", `{"sql":"DELETE FROM nope"}`); !strings.Contains(text, `failed and was rolled back: the statement: postgres: ERROR: relation "nope"`) {
		t.Fatal(text)
	}
	// Ошибка при исполнении второй команды — с её номером.
	db.fail = map[string]error{"DELETE FROM orders": &pgwire.PgError{Severity: "ERROR", Code: "42501", Message: "permission denied for table orders"}}
	db.answers = func(sql string) ([]pgwire.Result, bool) { return nil, false }
	if text, _ := callText(t, s, "execute", `{"statements":["UPDATE accounts SET note = 'x' WHERE id = 1","DELETE FROM orders"]}`); !strings.Contains(text, "statement 2") {
		t.Fatal(text)
	}
	// Чтение — свой совет.
	db.fail = map[string]error{"; ": &pgwire.PgError{Severity: "ERROR", Code: "42601", Message: "cannot insert multiple commands into a prepared statement"}}
	if text, _ := callText(t, s, "query", `{"sql":"SELECT 1; SELECT 2"}`); !strings.Contains(text, "`query` takes one SELECT") {
		t.Fatal(text)
	}
}

func TestStatementArguments(t *testing.T) {
	s, _ := newServer(t, &fakeDB{})
	many, _ := json.Marshal(map[string]any{"statements": make([]string, maxStatements+1)})
	for args, want := range map[string]string{
		`{"sql":"UPDATE t SET a = 1","statements":["UPDATE t SET a = 2"]}`: "not both",
		`{"statements":["UPDATE t SET a = 1","  "]}`:                       "statement 2 is empty",
		`{"statements":[]}`: "sql is empty",
		`{}`:                "sql is empty",
		string(many):        fmt.Sprintf("at most %d", maxStatements),
	} {
		if text, isErr := callText(t, s, "execute", args); !isErr || !strings.Contains(text, want) {
			t.Errorf("%s: %v %s", args, isErr, text)
		}
	}
	if text, isErr := callText(t, s, "query", `{"statements":["SELECT 1"]}`); !isErr || !strings.Contains(text, "one statement in `sql`") {
		t.Fatalf("%v %s", isErr, text)
	}
	// Агент узнаёт о списке и о том, чего нельзя, из описания инструмента.
	raw, _ := json.Marshal(ask(t, s, `{"jsonrpc":"2.0","id":1,"method":"tools/list"}`))
	if !strings.Contains(string(raw), `"statements"`) || !strings.Contains(string(raw), "BEGIN, COMMIT, ROLLBACK, SET, DO, CALL") {
		t.Fatalf("%s", raw)
	}
}

// Каждый вызов — с чистого сеанса. DISCARD ALL не прошёл — соединение
// бросается и открывается новое.
func TestEveryCallStartsWithACleanSession(t *testing.T) {
	db := &fakeDB{fail: map[string]error{"DISCARD ALL": &pgwire.PgError{Severity: "ERROR", Code: "25001", Message: "DISCARD ALL cannot run inside a transaction block"}}}
	dials := 0
	s := serverOn(t, db, filepath.Join(t.TempDir(), "receipts.jsonl"), nil)
	s.cfg.Dial = func() (DB, error) { dials++; return db, nil }
	if text, isErr := callText(t, s, "query", `{"sql":"SELECT id FROM accounts"}`); isErr {
		t.Fatal(text)
	}
	if dials != 2 || db.log[0] != "DISCARD ALL" || db.log[1] != "BEGIN TRANSACTION READ ONLY" {
		t.Fatalf("dials %d, %q", dials, db.log)
	}
	db.fail = nil
	db.log = nil
	s.cfg.Dial = func() (DB, error) { return nil, errors.New("must not dial") }
	if text, isErr := callText(t, s, "execute", `{"sql":"UPDATE accounts SET note = 'x' WHERE id = 1"}`); isErr || db.log[0] != "DISCARD ALL" {
		t.Fatalf("%v %s %q", isErr, text, db.log)
	}
}
