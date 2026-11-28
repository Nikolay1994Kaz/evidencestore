package mcpserver

import (
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/Nikolay1994Kaz/evidencestore/internal/pgwire"
)

// Через пулер (Config.Pooler) сервер не шлёт параметров входа и не зовёт
// DISCARD ALL вне транзакции: в режиме по транзакциям он ушёл бы на чужое
// соединение базы. Чистка и настройки — внутри транзакции, дважды: в её
// начале и после команд агента, перед своими запросами и COMMIT.
func TestPoolerKeepsTheSessionInsideTheTransaction(t *testing.T) {
	db := &fakeDB{}
	s, _ := newServer(t, db)
	s.cfg.Pooler, s.cfg.AppName = true, "esmcp/support-bot"
	s.cfg.StatementTimeout, s.cfg.LockTimeout = 60e9, 10e9
	var params []map[string]string
	s.cfg.Dial = func(p map[string]string) (DB, error) { params = append(params, p); return db, nil }
	if text, isErr := callText(t, s, "execute", `{"sql":"UPDATE accounts SET note = 'x' WHERE id = 6"}`); isErr {
		t.Fatal(text)
	}
	if len(params) != 1 || params[0] != nil {
		t.Fatalf("login parameters through a pooler: %v", params)
	}
	if slices.Contains(db.log, "DISCARD ALL") || db.log[0] != "BEGIN" {
		t.Fatalf("%q", db.log)
	}
	head := db.log[1]
	for _, want := range []string{
		"SET SESSION AUTHORIZATION DEFAULT; RESET ALL; DEALLOCATE ALL; CLOSE ALL; UNLISTEN *; SELECT pg_catalog.pg_advisory_unlock_all(); DISCARD PLANS; DISCARD TEMP; DISCARD SEQUENCES; ",
		"SET LOCAL DateStyle = 'ISO, YMD'; SET LOCAL extra_float_digits = '3'; SET LOCAL IntervalStyle = 'postgres'; SET LOCAL array_nulls = 'on'; ",
		"SET LOCAL application_name = 'esmcp/support-bot'; SET LOCAL search_path = pg_catalog, pg_temp; SET LOCAL client_encoding = 'UTF8'; SET LOCAL ROLE NONE; ",
		"WHEN 'statement_timeout' THEN '65000' WHEN 'lock_timeout' THEN '10000' WHEN 'idle_in_transaction_session_timeout' THEN '300000' ELSE '0' END, true)",
	} {
		if !strings.Contains(head, want) {
			t.Fatalf("the head of the transaction lacks %q:\n%s", want, head)
		}
	}
	// «Как при входе» у соединения пула — умолчания роли: таймауты — числами.
	if strings.Contains(strings.Join(db.log, "\n"), "reset_val") {
		t.Fatalf("a timeout is taken from the session defaults of a pooled connection: %q", db.log)
	}
	// После команд агента — снова чистка и свои настройки, потом COMMIT.
	exec, reset, commit := slices.Index(db.log, "EXECUTE es_agent_0"), slices.Index(db.log, "RESET ALL"), slices.Index(db.log, "COMMIT")
	dealloc, role := slices.Index(db.log, "DEALLOCATE ALL"), slices.Index(db.log, "SET LOCAL ROLE NONE")
	if exec < 0 || !(exec < reset && reset < dealloc && dealloc < role && role < commit) || commit != len(db.log)-1 {
		t.Fatalf("the order after the agent's statement: %q", db.log)
	}
	// Чтение — тоже одной транзакцией, без DISCARD ALL.
	db.log = nil
	if text, isErr := callText(t, s, "query", `{"sql":"SELECT id FROM accounts"}`); isErr {
		t.Fatal(text)
	}
	if db.log[0] != "BEGIN TRANSACTION READ ONLY" || !strings.HasPrefix(db.log[1], "SET SESSION AUTHORIZATION DEFAULT; RESET ALL; ") ||
		slices.Index(db.log, "DEALLOCATE ALL") < slices.Index(db.log, "EXECUTE es_agent_0") || db.log[len(db.log)-1] != "ROLLBACK" {
		t.Fatalf("%q", db.log)
	}
}

// Соединение, оставшееся внутри транзакции, через пулер не используется
// снова: BEGIN в открытой транзакции база приняла бы с предупреждением, и
// действие пошло бы в чужой транзакции. Прямому соединению это ловит
// DISCARD ALL.
func TestPoolerDropsAConnectionLeftInATransaction(t *testing.T) {
	db := &fakeDB{}
	s, _ := newServer(t, db)
	s.cfg.Pooler = true
	dials := 0
	s.cfg.Dial = func(map[string]string) (DB, error) { dials++; return db, nil }
	if text, isErr := callText(t, s, "query", `{"sql":"SELECT id FROM accounts"}`); isErr || dials != 1 {
		t.Fatalf("%d %s", dials, text)
	}
	db.tx = pgwire.TxOpen // транзакция осталась открытой
	if text, isErr := callText(t, s, "query", `{"sql":"SELECT id FROM accounts"}`); isErr || dials != 2 {
		t.Fatalf("dials %d: %s", dials, text)
	}
}

// Прямое соединение — как было: параметры входа и DISCARD ALL.
func TestDirectConnectionKeepsLoginParameters(t *testing.T) {
	db := &fakeDB{}
	s, _ := newServer(t, db)
	var params map[string]string
	s.cfg.Dial = func(p map[string]string) (DB, error) { params = p; return db, nil }
	if text, isErr := callText(t, s, "execute", `{"sql":"UPDATE accounts SET note = 'x' WHERE id = 6"}`); isErr {
		t.Fatal(text)
	}
	if params["role"] != "none" || params["idle_in_transaction_session_timeout"] != "300000" || db.log[0] != "DISCARD ALL" ||
		strings.Contains(strings.Join(db.log, "\n"), "RESET ALL") {
		t.Fatalf("%v %q", params, db.log)
	}
}

// Намерение несёт линию времени базы (db_timeline) — и без пределов строк, и
// с ними, когда в том же ответе базы идёт счёт строк: одно за другое не
// принимается.
func TestIntentCarriesTheTimeline(t *testing.T) {
	for _, limit := range []int{0, 100} {
		db := &fakeDB{}
		s, path := newServer(t, db)
		s.cfg.RowLimit = limit
		if text, isErr := callText(t, s, "execute", `{"sql":"UPDATE accounts SET note = 'x' WHERE id = 6"}`); isErr {
			t.Fatal(text)
		}
		rcs := receipts(t, path)
		if len(rcs) != 1 || rcs[0].DBTimeline != "3" || rcs[0].DBStarted != "1795400000000000" || rcs[0].XID != "751" {
			t.Fatalf("row limit %d: %+v", limit, rcs)
		}
		// База не ответила про линию (колонки нет): отметки нет — запуск базы
		// или счёт строк за неё не принимаются.
		db = &fakeDB{}
		db.answers = func(sql string) ([]pgwire.Result, bool) {
			if !strings.Contains(sql, "pg_current_xact_id()::xid::text, pg_current_xact_id()::text") {
				return nil, false
			}
			xid, started, zero := "751", "1795400000000000", "0"
			row := []*string{&xid, &xid, &started}
			if strings.Contains(sql, "pg_stat_get_xact_tuples") {
				row = append(row, &zero)
			}
			return []pgwire.Result{{Rows: [][]*string{row}, Tag: "SELECT 1"}}, true
		}
		s, path = newServer(t, db)
		s.cfg.RowLimit = limit
		if text, isErr := callText(t, s, "execute", `{"sql":"UPDATE accounts SET note = 'x' WHERE id = 6"}`); isErr {
			t.Fatal(text)
		}
		if rcs := receipts(t, path); len(rcs) != 1 || rcs[0].DBTimeline != "" || rcs[0].DBStarted != "1795400000000000" {
			t.Fatalf("row limit %d, no timeline in the answer: %+v", limit, rcs)
		}
	}
}

// Сверка и откат через пулер (P-393). В пуле по транзакциям запрос вне
// транзакции уходит на соединение базы, которое пулер даёт только ему: путь
// поиска, поставленный сеансу, до следующего запроса не доживал, и откат шёл
// бы с путём роли. Теперь каждый запрос сверки и отката — внутри транзакции,
// и каждая начинается с того же, с чего сервер начинает транзакцию действия:
// чистка соединения, вид текста значений, роль, таймауты числами.
func TestPoolerUndoStaysInsideItsTransactions(t *testing.T) {
	db := &fakeDB{answers: undoAnswers}
	s, path := newServer(t, db)
	s.cfg.Pooler, s.cfg.AppName = true, "esmcp/support-bot"
	s.cfg.StatementTimeout, s.cfg.LockTimeout = 60e9, 10e9
	s.cfg.UndoSearchPath = []string{"app"}
	s.cfg.Fetch = func(uint32) ([][]byte, error) { return [][]byte{journalLine()}, nil }
	appendReceipt(t, path, Receipt{ActionID: "a-1", Time: time.Now().UTC().Format(time.RFC3339Nano), Agent: "support-bot", Tool: "execute",
		SQL: "UPDATE accounts SET note = 'b'", XID: "751", Outcome: "committed"})
	s.newID = func() string { return "u-1" }

	if out, isErr := callText(t, s, "undo_preview", `{"action_id":"a-1"}`); isErr || !strings.Contains(out, `"to_apply":2`) {
		t.Fatalf("%v %s", isErr, out)
	}
	preview := len(db.log)
	if out, isErr := callText(t, s, "undo_apply", `{"action_id":"a-1","reason":"wrong rows"}`); isErr || !strings.Contains(out, `"applied":2`) {
		t.Fatalf("%v %s", isErr, out)
	}
	if slices.Contains(db.log, "DISCARD ALL") {
		t.Fatalf("DISCARD ALL through a pooler: %q", db.log)
	}
	// Вне транзакции — ни одного запроса; транзакций три: сверка просмотра,
	// сверка перед откатом (обе — только для чтения, обе откатаны) и откат.
	var begins []int
	in := false
	for i, q := range db.log {
		switch {
		case strings.HasPrefix(q, "BEGIN"):
			if in {
				t.Fatalf("BEGIN inside a transaction at %d: %q", i, db.log)
			}
			in = true
			begins = append(begins, i)
		case q == "COMMIT" || q == "ROLLBACK":
			if !in {
				t.Fatalf("%s outside a transaction at %d: %q", q, i, db.log)
			}
			in = false
		case !in:
			t.Fatalf("a query of the undo outside a transaction, where a pooler gives it a connection of its own:\n%s\n%q", q, db.log)
		}
	}
	if in || len(begins) != 3 || db.log[begins[0]] != "BEGIN TRANSACTION READ ONLY" || db.log[begins[1]] != "BEGIN TRANSACTION READ ONLY" || db.log[begins[2]] != "BEGIN" ||
		db.log[preview-1] != "ROLLBACK" || db.log[begins[2]-1] != "ROLLBACK" || db.log[len(db.log)-1] != "COMMIT" {
		t.Fatalf("the transactions of the undo: %v\n%q", begins, db.log)
	}
	for _, b := range begins {
		head := db.log[b+1]
		for _, want := range []string{
			"SET SESSION AUTHORIZATION DEFAULT; RESET ALL; DEALLOCATE ALL; CLOSE ALL; UNLISTEN *; SELECT pg_catalog.pg_advisory_unlock_all(); DISCARD PLANS; DISCARD TEMP; DISCARD SEQUENCES; ",
			"SET LOCAL DateStyle = 'ISO, YMD'; SET LOCAL extra_float_digits = '3'; SET LOCAL IntervalStyle = 'postgres'; SET LOCAL array_nulls = 'on'; ",
			"SET LOCAL application_name = 'esmcp/support-bot'; SET LOCAL search_path = pg_catalog, pg_temp; SET LOCAL client_encoding = 'UTF8'; SET LOCAL ROLE NONE; ",
			"WHEN 'statement_timeout' THEN '65000' WHEN 'lock_timeout' THEN '10000' WHEN 'idle_in_transaction_session_timeout' THEN '300000' ELSE '0' END, true)",
		} {
			if !strings.Contains(head, want) {
				t.Fatalf("a transaction of the undo does not start as the server's own do: it lacks %q:\n%s", want, head)
			}
		}
		// Путь отката — после своих настроек сервера: последнее слово за ним.
		if db.log[b+2] != "SELECT pg_catalog.set_config('search_path', 'pg_catalog, pg_temp', true)" {
			t.Fatalf("after the head of the transaction: %q", db.log[b+2])
		}
	}
	if n := strings.Count(strings.Join(db.log, "\n"), `set_config('search_path', 'pg_catalog, "app", pg_temp', true)`); n != 3 {
		t.Fatalf("the search path of the undo is set in %d of its 3 transactions: %q", n, db.log)
	}
	// Прямое соединение начинает с DISCARD ALL и своих команд в транзакцию
	// отката не добавляет: вид текста и таймауты ему дали параметры входа.
	direct := &fakeDB{answers: undoAnswers}
	s2, path2 := newServer(t, direct)
	s2.cfg.Fetch = s.cfg.Fetch
	appendReceipt(t, path2, Receipt{ActionID: "a-1", Time: time.Now().UTC().Format(time.RFC3339Nano), Agent: "support-bot", Tool: "execute",
		SQL: "UPDATE accounts SET note = 'b'", XID: "751", Outcome: "committed"})
	if out, isErr := callText(t, s2, "undo_preview", `{"action_id":"a-1"}`); isErr {
		t.Fatal(out)
	}
	if direct.log[0] != "DISCARD ALL" || direct.log[1] != "BEGIN TRANSACTION READ ONLY" || direct.log[2] != "SELECT pg_catalog.set_config('search_path', 'pg_catalog, pg_temp', true)" ||
		strings.Contains(strings.Join(direct.log, "\n"), "RESET ALL") {
		t.Fatalf("the undo over a direct connection: %q", direct.log)
	}
}
