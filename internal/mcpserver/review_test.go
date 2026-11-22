package mcpserver

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/Nikolay1994Kaz/evidencestore/internal/pgwire"
)

// undoAnswers — ответы базы на сверку и откат журнала journalLine: обе строки
// годны, правка применяется.
func undoAnswers(sql string) ([]pgwire.Result, bool) {
	text := func(s string) *string { return &s }
	switch {
	case strings.Contains(sql, "pg_attribute"):
		return []pgwire.Result{{Rows: [][]*string{{text("id"), text("")}, {text("note"), text("")}}}}, true
	case strings.HasPrefix(sql, "SELECT count(*) FILTER"):
		return []pgwire.Result{{Rows: [][]*string{{text("0"), text("0"), text("0")}}}}, true
	case strings.HasPrefix(sql, "SELECT w.step"):
		return []pgwire.Result{{Rows: [][]*string{{text("1"), text("ok"), nil}, {text("2"), text("ok"), nil}}}}, true
	case strings.HasPrefix(sql, `UPDATE "public"."accounts" t SET`):
		return []pgwire.Result{{Tag: "UPDATE 2"}}, true
	}
	return nil, false
}

// Откат через MCP — только своих действий и только той транзакции, что несёт
// отметку действия. До исправления P-247 агент видел в `actions` и откатывал
// действия другого агента из общего файла квитанций, а транзакцию брал по
// номеру без сверки: номер, занятый заново (база из копии, оборот счётчика),
// давал откат чужой транзакции под именем этого действия. Номер с эпохой
// (квитанции до 22.11) отказывал «has no transaction id».
func TestUndoTakesOnlyItsOwnActionsAndTheirTransactions(t *testing.T) {
	path := filepath.Join(t.TempDir(), "receipts.jsonl")
	db := &fakeDB{}
	other := serverOn(t, db, path, func(c *Config) { c.Agent = "batch-bot" })
	other.newID = func() string { return "b-1" }
	if out, isErr := callText(t, other, "execute", `{"sql":"UPDATE accounts SET note = 'b'"}`); isErr {
		t.Fatal(out)
	}
	s := serverOn(t, db, path, nil) // support-bot
	s.newID = func() string { return "a-2" }
	var fetched []uint32
	s.cfg.Fetch = func(xid uint32) ([][]byte, error) {
		fetched = append(fetched, xid)
		return [][]byte{journalLine()}, nil
	}
	db.answers = undoAnswers
	if list, _ := callText(t, s, "actions", `{}`); strings.Contains(list, "b-1") {
		t.Fatalf("another agent's action is listed: %s", list)
	}
	if out, isErr := callText(t, s, "undo_apply", `{"action_id":"b-1"}`); !isErr || !strings.Contains(out, "not in this server's receipts") {
		t.Fatalf("%v %s", isErr, out)
	}
	// Своё действие, а хранилище по его номеру отдаёт транзакцию без его
	// отметки (в journalLine — отметка a-1).
	if out, isErr := callText(t, s, "execute", `{"sql":"UPDATE accounts SET note = 'c'"}`); isErr {
		t.Fatal(out)
	}
	if out, isErr := callText(t, s, "undo_apply", `{"action_id":"a-2"}`); !isErr || !strings.Contains(out, "carries no marker of action a-2") {
		t.Fatalf("%v %s", isErr, out)
	}
	// Квитанция до 22.11: номер с эпохой. Хранилище знает младшие 32 бита.
	rc, _ := json.Marshal(Receipt{ActionID: "a-1", Time: time.Now().UTC().Format(time.RFC3339Nano), Agent: "support-bot", Tool: "execute",
		SQL: "UPDATE accounts SET note = 'b'", XID: fmt.Sprint(uint64(1)<<32 + 751), Outcome: "committed"})
	appendLine(t, path, rc)
	if out, isErr := callText(t, s, "undo_preview", `{"action_id":"a-1"}`); isErr || !strings.Contains(out, `"to_apply":2`) || fetched[len(fetched)-1] != 751 {
		t.Fatalf("%v %s %v", isErr, out, fetched)
	}
}

// Откат — действие под теми же пределами, что execute, а откат отката не
// берётся. До исправления P-249 агент повторял плохое действие откатом
// отката, без отказа по частоте, окну и строкам, и откаты в счёт не шли.
func TestUndoIsAnActionUnderTheLimits(t *testing.T) {
	path := filepath.Join(t.TempDir(), "receipts.jsonl")
	db := &fakeDB{answers: undoAnswers}
	s := serverOn(t, db, path, func(c *Config) { c.ActionsPerMinute = 2 })
	s.cfg.Fetch = func(uint32) ([][]byte, error) { return [][]byte{journalLine()}, nil }
	if out, isErr := callText(t, s, "execute", `{"sql":"UPDATE accounts SET note = 'b'"}`); isErr {
		t.Fatal(out)
	}
	out, isErr := callText(t, s, "undo_apply", `{"action_id":"a-1"}`)
	if isErr || !strings.Contains(out, `"undo_action_id":"a-2"`) {
		t.Fatalf("%v %s", isErr, out)
	}
	if out, isErr := callText(t, s, "undo_apply", `{"action_id":"a-2"}`); !isErr || !strings.Contains(out, "is itself an undo (of a-1)") {
		t.Fatalf("%v %s", isErr, out)
	}
	// Действие и откат — два действия в минуту: третье отказано.
	if out, isErr := callText(t, s, "execute", `{"sql":"UPDATE accounts SET note = 'd'"}`); !isErr || !strings.Contains(out, "2 actions in the last minute") {
		t.Fatalf("%v %s", isErr, out)
	}
	// Предел строк — по шагам отката.
	path = filepath.Join(t.TempDir(), "receipts.jsonl")
	s = serverOn(t, &fakeDB{answers: undoAnswers}, path, func(c *Config) { c.RowLimit = 1 })
	s.cfg.Fetch = func(uint32) ([][]byte, error) { return [][]byte{journalLine()}, nil }
	rc, _ := json.Marshal(Receipt{ActionID: "a-1", Time: time.Now().UTC().Format(time.RFC3339Nano), Agent: "support-bot", Tool: "execute",
		SQL: "UPDATE accounts SET note = 'b'", XID: "751", Outcome: "committed"})
	appendLine(t, path, rc)
	if out, isErr := callText(t, s, "undo_apply", `{"action_id":"a-1"}`); !isErr || !strings.Contains(out, "it would change 2 rows, and one action may change at most 1") {
		t.Fatalf("%v %s", isErr, out)
	}
	if got := receipts(t, path); got[len(got)-1].Tool != "undo_apply" || got[len(got)-1].Outcome != "refused" || got[len(got)-1].Cause != CauseRowLimit {
		t.Fatalf("receipt %+v", got[len(got)-1])
	}
}

// Связь оборвалась на COMMIT: исход неизвестен, а не «откатилось». До
// исправления P-250 агент слышал «failed and was rolled back», а база держала
// изменение; агент повторил бы действие, а откатить его не мог.
func TestLostCommitIsUnknownNotRolledBack(t *testing.T) {
	db := &fakeDB{fail: map[string]error{"COMMIT": io.ErrUnexpectedEOF}}
	path := filepath.Join(t.TempDir(), "receipts.jsonl")
	s := serverOn(t, db, path, nil)
	text, isErr := callText(t, s, "execute", `{"sql":"UPDATE accounts SET note = 'x' WHERE id = 1"}`)
	if !isErr || !strings.Contains(text, "may have been committed (transaction 751)") || strings.Contains(text, "rolled back") {
		t.Fatalf("%v %s", isErr, text)
	}
	if rc := receipts(t, path); len(rc) != 1 || rc[0].Outcome != "unknown" {
		t.Fatalf("receipt %+v", rc)
	}
	// Ошибка базы на COMMIT (отложенное ограничение) — честный откат, как раньше.
	db.fail = map[string]error{"COMMIT": &pgwire.PgError{Severity: "ERROR", Code: "23503", Message: "violates foreign key constraint"}}
	if text, isErr := callText(t, s, "execute", `{"sql":"UPDATE accounts SET note = 'x' WHERE id = 1"}`); !isErr || !strings.Contains(text, "failed and was rolled back") {
		t.Fatalf("%v %s", isErr, text)
	}
}

// Одновременные сеансы одного агента проходят проверку частоты по одному: при
// пределе 4 в минуту из 30 одновременных действий проходят 4. До исправления
// P-252 проходило до 30. Замок занят дольше, чем может идти действие, —
// отказ с объяснением, а не ожидание без конца.
func TestParallelSessionsKeepTheRateLimit(t *testing.T) {
	path := filepath.Join(t.TempDir(), "receipts.jsonl")
	var wg sync.WaitGroup
	var mu sync.Mutex
	passed := 0
	for i := 0; i < 30; i++ {
		s := serverOn(t, &fakeDB{}, path, func(c *Config) { c.ActionsPerMinute = 4 })
		s.newID = func() string { return fmt.Sprintf("p-%d", i) }
		wg.Add(1)
		go func() {
			defer wg.Done()
			if _, err := s.execute([]string{"UPDATE accounts SET note = 'x' WHERE id = 1"}, "parallel"); err == nil {
				mu.Lock()
				passed++
				mu.Unlock()
			}
		}()
	}
	wg.Wait()
	if passed != 4 {
		t.Fatalf("%d of 30 simultaneous actions passed the limit of 4 a minute", passed)
	}
	old := lockWait
	lockWait = 100 * time.Millisecond
	t.Cleanup(func() { lockWait = old })
	holder := serverOn(t, &fakeDB{}, path, nil)
	unlock, err := holder.actionLock()
	if err != nil {
		t.Fatal(err)
	}
	s := serverOn(t, &fakeDB{}, path, nil)
	if _, err := s.execute([]string{"UPDATE accounts SET note = 'y'"}, ""); err == nil || !strings.Contains(err.Error(), "another action of this agent has been running") {
		t.Fatalf("%v", err)
	}
	unlock()
	if _, err := s.execute([]string{"UPDATE accounts SET note = 'y'"}, ""); err != nil {
		t.Fatalf("after the lock is free: %v", err)
	}
}

func appendLine(t *testing.T, path string, line []byte) {
	t.Helper()
	f, err := os.OpenFile(path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	f.Write(append(line, '\n'))
}
