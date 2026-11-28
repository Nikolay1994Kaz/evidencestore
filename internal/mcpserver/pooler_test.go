package mcpserver

import (
	"slices"
	"strings"
	"testing"

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
