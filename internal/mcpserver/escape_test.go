package mcpserver

import (
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/Nikolay1994Kaz/evidencestore/internal/pgwire"
)

// textDB — база, где команды агента (со словом docs) отвечают заданными
// тегами и оставляют транзакцию в заданном состоянии: так вела себя база,
// когда текст агента шёл простым протоколом и COMMIT в нём закрывал
// транзакцию сервера (P-239). С PREPARE до этого не дойти; эти тесты держат
// страховку, которая заметит выход, если он всё же найдётся.
type textDB struct {
	fakeDB
	tags  []string
	err   error
	after byte   // состояние транзакции после команд агента
	xid   string // номер открытой транзакции после команд агента
}

func (d *textDB) Pipeline(sqls []string) ([]pgwire.Result, error) {
	if !strings.Contains(strings.Join(sqls, "\n"), "docs") {
		return d.fakeDB.Pipeline(sqls)
	}
	d.log = append(d.log, sqls...)
	// Голова и подготовка — как всегда; команда агента отвечает заданными
	// тегами (первый — её ответ) и оставляет транзакцию как задано.
	var res []pgwire.Result
	for _, sql := range sqls {
		if strings.HasPrefix(sql, "EXECUTE ") {
			break
		}
		tag := "SET"
		if strings.HasPrefix(sql, "PREPARE ") {
			tag = "PREPARE"
		}
		res = append(res, pgwire.Result{Tag: tag})
	}
	for _, tag := range d.tags {
		res = append(res, pgwire.Result{Tag: tag})
	}
	d.tx = d.after
	return res, d.err
}

func (d *textDB) Query(sql string) ([]pgwire.Result, error) {
	switch {
	case strings.Contains(sql, "pg_current_xact_id_if_assigned"):
		d.log = append(d.log, sql)
		return []pgwire.Result{{Columns: []string{"xid"}, Rows: [][]*string{{&d.xid}}, Tag: "SELECT 1"}}, nil
	}
	return d.fakeDB.Query(sql)
}

// Текст агента закрыл транзакцию сервера: исход escaped, агенту и людям —
// что изменения могли зафиксироваться, а не «ничего не изменилось». До
// исправления P-239 так выходило «refused and rolled back, nothing changed»,
// а база уже держала удаление.
func TestSQLThatEndsTheTransactionIsNotReportedAsRolledBack(t *testing.T) {
	for _, tc := range []struct {
		name  string
		db    textDB
		check bool // сервер переспросил номер транзакции
	}{
		{"BEGIN … COMMIT around the change", textDB{tags: []string{"BEGIN", "DELETE 2", "COMMIT"}, after: pgwire.TxIdle}, false},
		{"COMMIT, a change, then its own BEGIN", textDB{tags: []string{"COMMIT", "UPDATE 1", "BEGIN"}, after: pgwire.TxOpen, xid: "752"}, true},
		{"COMMIT, then an error", textDB{tags: []string{"COMMIT"}, err: &pgwire.PgError{Severity: "ERROR", Code: "42P01", Message: "relation \"nope\" does not exist"}, after: pgwire.TxIdle}, false},
		{"COMMIT, a change, a new transaction broken by an error", textDB{tags: []string{"COMMIT", "UPDATE 1", "BEGIN"},
			err: &pgwire.PgError{Severity: "ERROR", Code: "22012", Message: "division by zero"}, after: pgwire.TxFailed}, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			db := tc.db
			path := filepath.Join(t.TempDir(), "receipts.jsonl")
			dials := 0
			s := serverOn(t, &db, path, func(c *Config) { c.RowLimit = 1 })
			s.cfg.Dial = func() (DB, error) { dials++; return &db, nil }
			text, isErr := callText(t, s, "execute", `{"sql":"UPDATE docs SET body = 'x'","reason":"tidy"}`)
			if !isErr || !strings.Contains(text, "action a-1 left the server's transaction") || !strings.Contains(text, "may be committed") ||
				strings.Contains(text, "nothing changed") || strings.Contains(text, "rolled back") {
				t.Fatalf("%v %s", isErr, text)
			}
			log := strings.Join(db.log, "\n")
			if strings.Contains(log, "COMMIT\n") || strings.HasSuffix(log, "\nCOMMIT") {
				t.Fatalf("the server committed after the agent left its transaction:\n%s", log)
			}
			if got := strings.Contains(log, "pg_current_xact_id_if_assigned"); got != tc.check {
				t.Fatalf("asked for the transaction id: %v\n%s", got, log)
			}
			var mark string
			for _, q := range db.log {
				if strings.Contains(q, "mark_refused") {
					mark = q
				}
			}
			if !strings.Contains(mark, `"cause":"escaped"`) || !strings.Contains(mark, `"xid":"751"`) || !strings.Contains(mark, `"tool":"execute"`) {
				t.Fatalf("the marker for the alert: %q", mark)
			}
			rc := receipts(t, path)
			if len(rc) != 1 || rc[0].Outcome != "escaped" || rc[0].Cause != CauseEscaped || rc[0].XID != "751" {
				t.Fatalf("receipt %+v", rc)
			}
			// Сеанс брошен: следующий вызов — по новому соединению.
			db.tags, db.err, db.after = []string{"UPDATE 1"}, nil, pgwire.TxOpen
			one := "1"
			db.answers = func(sql string) ([]pgwire.Result, bool) {
				if strings.Contains(sql, "pg_stat_get_xact_tuples") && !strings.Contains(sql, "pg_current_xact_id") {
					return []pgwire.Result{{Columns: []string{"sum"}, Rows: [][]*string{{&one}}, Tag: "SELECT 1"}}, true
				}
				return nil, false
			}
			if text, isErr := callText(t, s, "execute", `{"sql":"UPDATE docs SET body = 'y' WHERE id = 1"}`); isErr || dials != 2 {
				t.Fatalf("dials %d: %v %s", dials, isErr, text)
			}
			// Откатывать сервер не берётся: действие не зафиксировано им.
			s.cfg.ReceiptsPath = path
			s.cfg.Fetch = func(uint32) ([][]byte, error) { t.Fatal("must not be asked"); return nil, nil }
			if text, isErr := callText(t, s, "undo_preview", `{"action_id":"a-1"}`); !isErr || !strings.Contains(text, "did not commit (escaped)") {
				t.Fatalf("%v %s", isErr, text)
			}
		})
	}
}

// ROLLBACK TO SAVEPOINT даёт тег ROLLBACK, но транзакцию не закрывает: номер
// тот же, действие идёт обычным путём.
func TestRollbackToSavepointStaysInTheTransaction(t *testing.T) {
	db := &textDB{tags: []string{"ROLLBACK"}, after: pgwire.TxOpen, xid: "751"}
	s := serverOn(t, db, filepath.Join(t.TempDir(), "receipts.jsonl"), nil)
	text, isErr := callText(t, s, "execute", `{"sql":"UPDATE docs SET body = 'x' WHERE id = 1"}`)
	if isErr || !strings.Contains(text, `"outcome":"committed"`) || db.log[len(db.log)-1] != "COMMIT" ||
		!slices.ContainsFunc(db.log, func(q string) bool { return strings.Contains(q, "pg_current_xact_id_if_assigned") }) {
		t.Fatalf("%v %s %q", isErr, text, db.log)
	}
}

// Чтение закрыло свою транзакцию «только для чтения»: всё после COMMIT шло с
// правами роли. Агенту — ошибка, людям — тревога, в квитанциях — запись.
func TestReadThatEndsItsTransactionIsAnAction(t *testing.T) {
	for _, after := range []byte{pgwire.TxIdle, pgwire.TxOpen} { // открыта — агент начал свою
		db := &textDB{tags: []string{"COMMIT", "INSERT 0 1", "BEGIN"}, after: after}
		path := filepath.Join(t.TempDir(), "receipts.jsonl")
		s := serverOn(t, db, path, nil)
		text, isErr := callText(t, s, "query", `{"sql":"SELECT 1 FROM docs"}`)
		if !isErr || !strings.Contains(text, "the read a-1 left the server's transaction") {
			t.Fatalf("%c: %v %s", after, isErr, text)
		}
		if !strings.Contains(strings.Join(db.log, "\n"), `"cause":"escaped"`) {
			t.Fatalf("%c: no marker for the alert: %q", after, db.log)
		}
		if rc := receipts(t, path); len(rc) != 1 || rc[0].Tool != "query" || rc[0].Outcome != "escaped" {
			t.Fatalf("%c: receipt %+v", after, rc)
		}
	}
}
