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

// Откат через MCP — только своих действий и только той транзакции, что
// сборщик взял по намерению этого действия. До исправления P-247 агент видел в `actions` и откатывал
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
	// Своё действие, а хранилище по его номеру отдаёт транзакцию другого
	// действия (в journalLine — намерение a-1).
	if out, isErr := callText(t, s, "execute", `{"sql":"UPDATE accounts SET note = 'c'"}`); isErr {
		t.Fatal(out)
	}
	if out, isErr := callText(t, s, "undo_apply", `{"action_id":"a-2"}`); !isErr || !strings.Contains(out, "is not action a-2 of this server") {
		t.Fatalf("%v %s", isErr, out)
	}
	// Номер с эпохой в квитанции: хранилище знает младшие 32 бита.
	appendReceipt(t, path, Receipt{ActionID: "a-1", Time: time.Now().UTC().Format(time.RFC3339Nano), Agent: "support-bot", Tool: "execute",
		SQL: "UPDATE accounts SET note = 'b'", XID: fmt.Sprint(uint64(1)<<32 + 751), Outcome: "committed"})
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
	appendReceipt(t, path, Receipt{ActionID: "a-1", Time: time.Now().UTC().Format(time.RFC3339Nano), Agent: "support-bot", Tool: "execute",
		SQL: "UPDATE accounts SET note = 'b'", XID: "751", Outcome: "committed"})
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
	if rc := receipts(t, path); len(rc) != 1 || rc[0].Outcome != "unknown" || rc[0].Cause != CauseUnknown {
		t.Fatalf("receipt %+v", rc)
	}
	// Людям — тревога по квитанции исхода: причина unknown, номер и строки
	// (P-258).
	if o := outcomes(t, path); o[0]["cause"] != CauseUnknown || o[0]["xid"] != "751" || o[0]["outcome"] != "unknown" {
		t.Fatalf("no alert about the lost COMMIT: %v", o[0])
	}
	// Такое действие могло зафиксироваться: откат его берёт, если хранилище
	// знает транзакцию, взятую по его намерению (в journalLine — a-1).
	s.cfg.Fetch = func(uint32) ([][]byte, error) { return [][]byte{journalLine()}, nil }
	db.answers = undoAnswers
	if out, isErr := callText(t, s, "undo_preview", `{"action_id":"a-1"}`); isErr || !strings.Contains(out, `"to_apply":2`) {
		t.Fatalf("the undo of an action whose COMMIT was lost: %v %s", isErr, out)
	}
	db.answers = nil
	// Ошибка базы на COMMIT (отложенное ограничение) — честный откат, как раньше.
	db.fail = map[string]error{"COMMIT": &pgwire.PgError{Severity: "ERROR", Code: "23503", Message: "violates foreign key constraint"}}
	if text, isErr := callText(t, s, "execute", `{"sql":"UPDATE accounts SET note = 'x' WHERE id = 1"}`); !isErr || !strings.Contains(text, "failed and was rolled back") {
		t.Fatalf("%v %s", isErr, text)
	}
	// База закрыла сеанс на COMMIT (FATAL: так отвечает сеанс, прерванный в
	// ожидании синхронной реплики, — у себя он уже зафиксирован): тоже
	// unknown. И строки таких действий идут в окно: раньше агент обрывал
	// сеанс сервера своей ролью и обходил окно сколько угодно раз (P-258).
	s, db, path = limited(t, 0, "3")
	s.cfg.WindowRows, s.cfg.Window = 3, time.Hour
	db.fail = map[string]error{"COMMIT": &pgwire.PgError{Severity: "FATAL", Code: "57P01", Message: "terminating connection due to administrator command"}}
	if text, isErr := callText(t, s, "execute", `{"sql":"UPDATE accounts SET note = 'x' WHERE id = 1"}`); !isErr || !strings.Contains(text, "may have been committed") {
		t.Fatalf("%v %s", isErr, text)
	}
	if text, isErr := callText(t, s, "execute", `{"sql":"UPDATE accounts SET note = 'y' WHERE id = 1"}`); !isErr || !strings.Contains(text, "the agent would have changed 6 rows in the last 1h0m0s") {
		t.Fatalf("the window after a lost COMMIT: %v %s", isErr, text)
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

// Квитанция после обрывка (запись прервалась без перевода строки) — с новой
// строки: её видят и идущий сеанс, и новый. Раньше она приклеивалась к
// обрывку, и её строки в окно не шли ни у кого (R1 заход 2: регрессия от
// P-244 — идущий сеанс до неё считал).
func TestTornReceiptDoesNotHideTheNext(t *testing.T) {
	path := filepath.Join(t.TempDir(), "receipts.jsonl")
	s, _, _ := limited(t, 0, "40")
	s.cfg.WindowRows, s.cfg.Window = 50, 10*time.Minute
	f, err := os.OpenFile(path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	gatewayOn(&s.cfg, path)
	if _, rows, _, err := s.usage(time.Now(), ""); err != nil || rows != 0 {
		t.Fatal(rows, err)
	}
	torn, _ := json.Marshal(Receipt{ActionID: "a-torn", Time: time.Now().UTC().Format(time.RFC3339Nano), Agent: "support-bot", Tool: "execute", Outcome: "committed", Rows: 5})
	f.Write(torn[:len(torn)/2])
	if _, _, _, err := s.usage(time.Now(), ""); err != nil {
		t.Fatal(err)
	}
	if out, isErr := callText(t, s, "execute", `{"sql":"UPDATE accounts SET note = 'x'"}`); isErr {
		t.Fatal(out)
	}
	fresh := serverOn(t, &fakeDB{}, path, func(c *Config) { c.WindowRows, c.Window = 50, 10*time.Minute })
	_, running, _, err1 := s.usage(time.Now(), "")
	_, again, _, err2 := fresh.usage(time.Now(), "")
	if err1 != nil || err2 != nil || running != 40 || again != 40 {
		t.Fatalf("after a torn line: the running session counts %d rows, a new one %d (want 40): %v %v", running, again, err1, err2)
	}
}

// Время квитанции — после замка: действия, прождавшие в очереди за долгим
// (откат висит на замке строки, часы уходят на 65 с), считаются по тому,
// когда пошли, а не когда пришли. Раньше время ставилось до ожидания, они
// были записаны в прошлое, и при пределе 2 в минуту проходили все 6 (R2,
// T заход 2).
func TestQueuedActionsAreCountedWhenTheyRun(t *testing.T) {
	path := filepath.Join(t.TempDir(), "receipts.jsonl")
	var mu sync.Mutex
	base, off := time.Now(), time.Duration(0)
	now := func() time.Time { mu.Lock(); defer mu.Unlock(); return base.Add(off) }
	advance := func(d time.Duration) { mu.Lock(); off += d; mu.Unlock() }
	mod := func(c *Config) { c.ActionsPerMinute = 2; c.StatementTimeout = time.Minute }
	first := serverOn(t, &fakeDB{}, path, mod)
	first.now = now
	if out, isErr := callText(t, first, "execute", `{"sql":"UPDATE accounts SET note = 'b'"}`); isErr { // a-1
		t.Fatal(out)
	}
	advance(2 * time.Minute)
	started := make(chan struct{})
	stalled := func(sql string) ([]pgwire.Result, bool) {
		if strings.HasPrefix(sql, `UPDATE "public"."accounts" t SET`) {
			close(started)
			time.Sleep(300 * time.Millisecond)
			advance(65 * time.Second)
		}
		return undoAnswers(sql)
	}
	holder := serverOn(t, &fakeDB{answers: stalled}, path, mod)
	holder.now = now
	holder.newID = func() string { return "u-1" }
	holder.cfg.Fetch = func(uint32) ([][]byte, error) { return [][]byte{journalLine()}, nil }
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		if out, isErr := callText(t, holder, "undo_apply", `{"action_id":"a-1"}`); isErr {
			t.Errorf("undo: %s", out)
		}
	}()
	<-started
	var pm sync.Mutex
	passed := 0
	for i := 0; i < 6; i++ {
		s := serverOn(t, &fakeDB{}, path, mod)
		s.now = now
		s.newID = func() string { return fmt.Sprintf("q-%d", i) }
		wg.Add(1)
		go func() {
			defer wg.Done()
			if _, err := s.execute([]string{"UPDATE accounts SET note = 'q' WHERE id = 1"}, "queued"); err == nil {
				pm.Lock()
				passed++
				pm.Unlock()
			}
		}()
	}
	wg.Wait()
	if passed > 2 {
		t.Fatalf("%d of 6 actions queued behind a long undo passed the limit of 2 a minute", passed)
	}
}

// Обрыв на COMMIT отката — как у execute: исход unknown, строки в окно,
// людям — отметка. Раньше квитанция писала failed без строк, отметки не было,
// агенту — просто EOF, и окно обходилось откатами, которые на деле
// зафиксированы (R1, R2 заход 3).
func TestLostCommitOfAnUndoIsUnknown(t *testing.T) {
	path := filepath.Join(t.TempDir(), "receipts.jsonl")
	db := &fakeDB{answers: undoAnswers}
	s := serverOn(t, db, path, func(c *Config) { c.WindowRows, c.Window = 3, time.Hour })
	s.cfg.Fetch = func(uint32) ([][]byte, error) { return [][]byte{journalLine()}, nil }
	appendReceipt(t, path, Receipt{ActionID: "a-1", Time: time.Now().UTC().Format(time.RFC3339Nano), Agent: "support-bot", Tool: "execute",
		SQL: "UPDATE accounts SET note = 'b'", XID: "751", Outcome: "committed"})
	db.fail = map[string]error{"COMMIT": io.ErrUnexpectedEOF}
	out, isErr := callText(t, s, "undo_apply", `{"action_id":"a-1"}`)
	if !isErr || !strings.Contains(out, "the undo may have been committed") {
		t.Fatalf("%v %s", isErr, out)
	}
	got := receipts(t, path)
	if last := got[len(got)-1]; last.Tool != "undo_apply" || last.Outcome != "unknown" || last.Rows != 2 {
		t.Fatalf("receipt %+v", last)
	}
	if o := outcomes(t, path); o[len(o)-1]["cause"] != CauseUnknown || o[len(o)-1]["tool"] != "undo_apply" {
		t.Fatalf("no alert about the lost COMMIT of the undo: %v", o[len(o)-1])
	}
	if _, rows, _, err := s.usage(time.Now(), ""); err != nil || rows != 2 {
		t.Fatalf("the window counts %d rows: %v", rows, err)
	}
}

// Сведения о клиенте — имя и версия, не длиннее 200 байт каждое: их шлёт
// агент, и в 17 МБ они делали тревогу dropped вместо настоящей (R1, R2, T
// заход 3).
func TestClientInfoIsCut(t *testing.T) {
	got := clientInfo(json.RawMessage(`{"name":"` + strings.Repeat("я", 5000) + `","version":"1","extra":"` + strings.Repeat("x", 9000) + `"}`))
	var c map[string]string
	if json.Unmarshal(got, &c) != nil || len(c["name"]) > 200 || !strings.HasPrefix(c["name"], "яя") || c["version"] != "1" || len(got) > 300 {
		t.Fatalf("%d bytes: %.120s", len(got), got)
	}
	// И так — оба пути, которыми их шлёт клиент: рукопожатие и _meta запроса.
	db := &fakeDB{}
	s := serverOn(t, db, filepath.Join(t.TempDir(), "receipts.jsonl"), nil)
	huge := `{"name":"` + strings.Repeat("x", 100000) + `","version":"1"}`
	s.Handle([]byte(`{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":` + huge + `}}`))
	s.Handle([]byte(`{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"execute","arguments":{"sql":"UPDATE accounts SET note = 'x'"}}}`))
	s.Handle([]byte(`{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"_meta":{"io.modelcontextprotocol/protocolVersion":"` + modernVersion + `","io.modelcontextprotocol/clientInfo":` + huge + `},"name":"execute","arguments":{"sql":"UPDATE accounts SET note = 'y'"}}}`))
	n := 0
	for _, r := range chain(t, s.cfg.ReceiptsPath) {
		if r.Step == "intent" {
			n++
		}
		if len(r.Body) > 2000 {
			t.Fatalf("a receipt body of %d bytes", len(r.Body))
		}
	}
	if n != 2 {
		t.Fatalf("%d intents", n)
	}
}

// Статистика молчит (track_counts = off) — строки отката по шагам, как у
// execute по ответам операторов: раньше откат шёл в окно нулём (R1, R2 заход 3).
func TestUndoRowsWithoutStatistics(t *testing.T) {
	path := filepath.Join(t.TempDir(), "receipts.jsonl")
	db := &fakeDB{answers: undoAnswers, noStats: true}
	s := serverOn(t, db, path, func(c *Config) { c.WindowRows, c.Window = 10, time.Hour })
	s.cfg.Fetch = func(uint32) ([][]byte, error) { return [][]byte{journalLine()}, nil }
	appendReceipt(t, path, Receipt{ActionID: "a-1", Time: time.Now().UTC().Format(time.RFC3339Nano), Agent: "support-bot", Tool: "execute",
		SQL: "UPDATE accounts SET note = 'b'", XID: "751", Outcome: "committed"})
	if out, isErr := callText(t, s, "undo_apply", `{"action_id":"a-1"}`); isErr {
		t.Fatal(out)
	}
	if got := receipts(t, path); got[len(got)-1].Rows != 2 {
		t.Fatalf("the undo went into the window with %d rows", got[len(got)-1].Rows)
	}
}
