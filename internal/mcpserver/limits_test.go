package mcpserver

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/Nikolay1994Kaz/evidencestore/internal/gateway"
	"github.com/Nikolay1994Kaz/evidencestore/internal/pgwire"
)

// slowDB — база, в которой запрос со словом slow висит, пока его не отменят
// (Cancel) или не закроют соединение (Close).
type slowDB struct {
	fakeDB
	slow      string
	cancelErr error

	mu               sync.Mutex
	cancels, closes  int
	cancelled, close chan struct{}
}

func newSlowDB(slow string) *slowDB {
	return &slowDB{slow: slow, cancelled: make(chan struct{}), close: make(chan struct{})}
}

func (d *slowDB) Query(sql string) ([]pgwire.Result, error) {
	if !strings.Contains(sql, d.slow) {
		return d.fakeDB.Query(sql)
	}
	d.log = append(d.log, sql)
	return d.hang()
}

// hang ждёт отмены или закрытия соединения.
func (d *slowDB) hang() ([]pgwire.Result, error) {
	d.mu.Lock()
	cancelled, closed := d.cancelled, d.close
	d.mu.Unlock()
	select {
	case <-cancelled:
		return nil, &pgwire.PgError{Severity: "ERROR", Code: "57014", Message: "canceling statement due to user request"}
	case <-closed:
		return nil, io.ErrUnexpectedEOF
	case <-time.After(10 * time.Second):
		return nil, errors.New("the test never stopped the slow query")
	}
}

// Pipeline: пачка, где есть медленная команда, висит так же.
func (d *slowDB) Pipeline(sqls []string) ([]pgwire.Result, error) {
	if !slices.ContainsFunc(sqls, func(sql string) bool { return strings.Contains(sql, d.slow) }) {
		return d.fakeDB.Pipeline(sqls)
	}
	d.log = append(d.log, sqls...)
	return d.hang()
}

func (d *slowDB) Cancel() error {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.cancels++
	if d.cancelErr != nil {
		return d.cancelErr
	}
	close(d.cancelled)
	d.cancelled = make(chan struct{})
	return nil
}

func (d *slowDB) Close() error {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.closes++
	close(d.close)
	d.close = make(chan struct{})
	return nil
}

func (d *slowDB) counts() (cancels, closes int) {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.cancels, d.closes
}

// serverOn — сервер над базой db с файлом квитанций path (общим для
// «сеансов»): каждый вызов — новый сеанс агента.
func serverOn(t *testing.T, db DB, path string, mod func(*Config)) *Server {
	t.Helper()
	cfg := Config{Agent: "support-bot", Version: "test", Dial: func(map[string]string) (DB, error) { return db, nil }}
	gatewayOn(&cfg, path)
	if mod != nil {
		mod(&cfg)
	}
	s := New(cfg, nil)
	n := 0
	s.newID = func() string { n++; return fmt.Sprintf("a-%d", n) }
	return s
}

// Запрос агента идёт дольше предела: он отменяется на сервере базы,
// соединение закрывается, действие откатывается. В квитанции — причина, в
// журнале базы — отметка для тревоги. Таймер — у сервера, а не в сессии базы:
// SET в запросе агента его не снимает.
func TestStatementTimeoutCancelsAndDropsTheConnection(t *testing.T) {
	db := newSlowDB("pg_sleep")
	path := filepath.Join(t.TempDir(), "receipts.jsonl")
	s := serverOn(t, db, path, func(c *Config) { c.StatementTimeout = 30 * time.Millisecond })
	start := time.Now()
	// SET агенту не дают, но set_config — обычный SELECT: таймаут базы он
	// себе снимет. Таймер сервера ему недоступен.
	text, isErr := callText(t, s, "execute", `{"statements":["SELECT set_config('statement_timeout', '0', true)","UPDATE accounts SET note = pg_sleep(3600)::text"],"reason":"slow"}`)
	if !isErr || !strings.Contains(text, "action a-1 failed and was rolled back") || !strings.Contains(text, "ran longer than 30ms and was cancelled") {
		t.Fatalf("%v %s", isErr, text)
	}
	if took := time.Since(start); took > 3*time.Second {
		t.Fatalf("the timeout took %v", took)
	}
	if cancels, closes := db.counts(); cancels != 1 || closes != 1 {
		t.Fatalf("cancels %d, closes %d", cancels, closes)
	}
	// После зависшей пачки в закрытое соединение ничего не шло: ни ROLLBACK,
	// ни COMMIT, ни что-то ещё. Тревога — по квитанции исхода.
	sleep := slices.IndexFunc(db.log, func(q string) bool { return strings.Contains(q, "pg_sleep") })
	if sleep < 0 || slices.Contains(db.log[sleep:], "ROLLBACK") || slices.Contains(db.log[sleep:], "COMMIT") {
		t.Fatalf("%q", db.log)
	}
	rc := receipts(t, path)
	if len(rc) != 1 || rc[0].Outcome != "failed" || rc[0].Cause != CauseTimeout || !strings.Contains(rc[0].Error, "cancelled") {
		t.Fatalf("receipt %+v", rc)
	}
	if o := outcomes(t, path); o[0]["timeout"] != "30ms" {
		t.Fatalf("the outcome lacks what the alert says: %v", o[0])
	}
	// Сервер жив: следующее действие идёт по новому соединению.
	if text, isErr := callText(t, s, "execute", `{"sql":"UPDATE accounts SET note = 'x' WHERE id = 1"}`); isErr {
		t.Fatal(text)
	}
	// Чтение — под тем же таймером.
	text, isErr = callText(t, s, "query", `{"sql":"SELECT pg_sleep(3600)"}`)
	if !isErr || !strings.Contains(text, "was cancelled") || db.log[len(db.log)-1] == "ROLLBACK" {
		t.Fatalf("%v %s %q", isErr, text, db.log[len(db.log)-3:])
	}
}

// Отмена не дошла до базы: соединение закрывается, и сервер агента не висит.
func TestStatementTimeoutWhenTheCancelFails(t *testing.T) {
	db := newSlowDB("pg_sleep")
	db.cancelErr = errors.New("connection refused")
	s := serverOn(t, db, filepath.Join(t.TempDir(), "receipts.jsonl"), func(c *Config) { c.StatementTimeout = 30 * time.Millisecond })
	text, isErr := callText(t, s, "execute", `{"sql":"SELECT pg_sleep(3600)"}`)
	if !isErr || !strings.Contains(text, "was cancelled") {
		t.Fatalf("%v %s", isErr, text)
	}
	if cancels, closes := db.counts(); cancels != 1 || closes < 1 {
		t.Fatalf("cancels %d, closes %d", cancels, closes)
	}
}

// Быстрому запросу таймер не мешает, а lock_timeout ставится в начале
// транзакции — раньше номера транзакции и SQL агента.
func TestTimeoutsLeaveFastActionsAlone(t *testing.T) {
	db := newSlowDB("pg_sleep")
	s := serverOn(t, db, filepath.Join(t.TempDir(), "receipts.jsonl"), func(c *Config) {
		c.StatementTimeout, c.LockTimeout = time.Minute, 5*time.Second
	})
	text, isErr := callText(t, s, "execute", `{"sql":"UPDATE accounts SET note = 'x' WHERE id = 1"}`)
	if isErr || !strings.Contains(text, `"outcome":"committed"`) {
		t.Fatalf("%v %s", isErr, text)
	}
	if db.log[1] != "BEGIN" || !strings.HasSuffix(db.log[2], "; SET LOCAL statement_timeout = 65000; SET LOCAL lock_timeout = 5000") ||
		!strings.Contains(db.log[3], "pg_current_xact_id") || db.log[len(db.log)-1] != "COMMIT" {
		t.Fatalf("%q", db.log)
	}
	if cancels, closes := db.counts(); cancels != 0 || closes != 0 {
		t.Fatalf("cancels %d, closes %d", cancels, closes)
	}
	raw, _ := json.Marshal(ask(t, s, `{"jsonrpc":"2.0","id":1,"method":"tools/list","params":{"_meta":{"io.modelcontextprotocol/protocolVersion":"2026-07-28"}}}`))
	if !strings.Contains(string(raw), "runs longer than 1m0s is cancelled") {
		t.Fatalf("the tool description does not name the timeout: %s", raw)
	}
}

// Предел действий в минуту считается по файлу квитанций, общему для сеансов:
// новый сеанс агента счёт не обнуляет. Отказ — раньше, чем действие пойдёт в
// базу; тревога — на первый отказ, а не на каждый; отказы в счёт не идут.
func TestActionsPerMinuteAcrossSessions(t *testing.T) {
	path := filepath.Join(t.TempDir(), "receipts.jsonl")
	now := time.Date(2026, 11, 22, 12, 0, 0, 0, time.UTC)
	limit := func(c *Config) { c.ActionsPerMinute = 3 }
	clock := func(s *Server) *Server { s.now = func() time.Time { return now }; return s }
	exec := func(s *Server) (string, bool) {
		return callText(t, s, "execute", `{"sql":"UPDATE accounts SET note = 'x' WHERE id = 1","reason":"loop"}`)
	}
	db := &fakeDB{}
	first := clock(serverOn(t, db, path, limit))
	for i := 0; i < 2; i++ {
		if text, isErr := exec(first); isErr {
			t.Fatal(text)
		}
		now = now.Add(time.Second)
	}
	// Чужой агент пишет в тот же файл: его действия — не в счёт.
	other := clock(serverOn(t, &fakeDB{}, path, func(c *Config) { c.Agent = "other-bot"; c.ActionsPerMinute = 3 }))
	for i := 0; i < 5; i++ {
		exec(other)
	}
	// Новый сеанс того же агента.
	second := clock(serverOn(t, db, path, limit))
	if text, isErr := exec(second); isErr {
		t.Fatal(text)
	}
	// alerted — отказы за частоту, о которых ушла тревога людям: сборщик
	// поднимает её по квитанции исхода с alerted (pginput, receipts.go).
	alerted := func() (n int) {
		for _, o := range outcomes(t, path) {
			if o["agent"] == "support-bot" && o["cause"] == CauseRate && o["alerted"] == true {
				n++
			}
		}
		return n
	}
	before := len(db.log)
	text, isErr := exec(second)
	if !isErr || !strings.Contains(text, "was refused: 3 actions in the last minute, and the limit is 3") || !strings.Contains(text, "do not retry in a loop") {
		t.Fatalf("the fourth action in a minute: %v %s", isErr, text)
	}
	// В базу не ушло ничего; в квитанции исхода — тревога и её подробности.
	o := outcomes(t, path)
	if last := o[len(o)-1]; len(db.log) != before || alerted() != 1 || last["actions"] != float64(3) || last["limit"] != float64(3) {
		t.Fatalf("%q %v", db.log[before:], last)
	}
	for i := 0; i < 5; i++ { // агент в цикле: отказы есть, новых тревог нет
		now = now.Add(time.Second)
		if _, isErr := exec(second); !isErr {
			t.Fatal("a looping agent got through")
		}
	}
	if len(db.log) != before || alerted() != 1 {
		t.Fatalf("each refusal raised an alert: %d alerts, %q", alerted(), db.log[before:])
	}
	// И новый сеанс в ту же минуту тревогу не повторяет: когда она была, видно
	// по квитанциям. Минута с неё прошла, а агент всё в цикле — тревога снова.
	third := clock(serverOn(t, db, path, limit))
	if _, isErr := exec(third); !isErr || alerted() != 1 {
		t.Fatalf("a new session raised the alert again: %d alerts", alerted())
	}
	now = now.Add(56 * time.Second) // с первой тревоги — 62 с; действия первой минуты уже не в счёт
	for i := 0; i < 3; i++ {
		if text, isErr := exec(third); isErr {
			t.Fatalf("the window moved on, but action %d is refused: %s", i+1, text)
		}
		now = now.Add(time.Second)
	}
	if _, isErr := exec(third); !isErr || alerted() != 2 {
		t.Fatalf("a minute after the alert the agent loops again, and nobody is told: %d alerts", alerted())
	}
	// Счёт минуты — от последней тревоги, а не от первой.
	now = now.Add(time.Second)
	if _, isErr := exec(third); !isErr || alerted() != 2 {
		t.Fatalf("an alert a second after the previous one: %d alerts", alerted())
	}
	if _, isErr := exec(clock(serverOn(t, db, path, limit))); !isErr || alerted() != 2 {
		t.Fatalf("an alert a second after the previous one, from a new session: %d alerts", alerted())
	}
	var refused int
	for _, rc := range receipts(t, path) {
		if rc.Agent == "support-bot" && rc.Outcome == "refused" && rc.Cause == CauseRate {
			refused++
		}
	}
	if refused != 10 {
		t.Fatalf("%d refusals in the receipts, expected every one of 10", refused)
	}
	// Минута прошла: отказы в счёт не шли, действие проходит.
	now = now.Add(61 * time.Second)
	if text, isErr := exec(second); isErr {
		t.Fatalf("after a minute: %s", text)
	}
}

// Предел строк за окно: каждое действие мало, вместе — больше, чем можно.
// Агент, который дробит изменение на части, упирается в него.
func TestWindowRowsStopsAnAgentThatSplitsItsChange(t *testing.T) {
	path := filepath.Join(t.TempDir(), "receipts.jsonl")
	now := time.Date(2026, 11, 22, 12, 0, 0, 0, time.UTC)
	stat := "400"
	db := &fakeDB{answers: func(sql string) ([]pgwire.Result, bool) {
		if strings.Contains(sql, "pg_stat_get_xact_tuples") && !strings.Contains(sql, "pg_current_xact_id") {
			return []pgwire.Result{{Columns: []string{"sum"}, Rows: [][]*string{{&stat}}, Tag: "SELECT 1"}}, true
		}
		return nil, false
	}}
	session := func() *Server {
		s := serverOn(t, db, path, func(c *Config) { c.RowLimit, c.WindowRows, c.Window = 500, 1000, 10*time.Minute })
		s.now = func() time.Time { return now }
		return s
	}
	exec := func(s *Server) (string, bool) {
		return callText(t, s, "execute", `{"sql":"UPDATE accounts SET balance = 0 WHERE id % 5 = 0","reason":"part of a big change"}`)
	}
	for i := 0; i < 2; i++ { // каждое — в новом сеансе
		if text, isErr := exec(session()); isErr {
			t.Fatal(text)
		}
		now = now.Add(time.Minute)
	}
	s := session()
	text, isErr := exec(s)
	if !isErr || !strings.Contains(text, "was refused and rolled back, nothing changed") ||
		!strings.Contains(text, "with its 400 rows the agent would have changed 1200 rows in the last 10m0s, and the limit is 1000") {
		t.Fatalf("%v %s", isErr, text)
	}
	o := outcomes(t, path)
	if n := len(db.log); db.log[n-1] != "ROLLBACK" || o[2]["cause"] != CauseWindowRows || o[2]["window_rows"] != float64(800) ||
		o[2]["rows"] != float64(400) || o[2]["window"] != "10m0s" || o[2]["limit"] != float64(1000) {
		t.Fatalf("%q %v", db.log[n-3:], o[2])
	}
	if rc := receipts(t, path); rc[2].Outcome != "refused" || rc[2].Cause != CauseWindowRows || rc[2].Rows != 400 {
		t.Fatalf("receipt %+v", rc[2])
	}
	// Действие поменьше в остаток окна влезает.
	stat = "200"
	if text, isErr := exec(s); isErr {
		t.Fatal(text)
	}
	// Окно ушло: первые действия старше десяти минут.
	stat = "400"
	now = now.Add(9 * time.Minute)
	if text, isErr := exec(session()); isErr {
		t.Fatalf("after the window: %s", text)
	}
	raw, _ := json.Marshal(ask(t, s, `{"jsonrpc":"2.0","id":1,"method":"tools/list","params":{"_meta":{"io.modelcontextprotocol/protocolVersion":"2026-07-28"}}}`))
	if !strings.Contains(string(raw), "at most 1000 rows in 10m0s") {
		t.Fatalf("the tool description does not name the window limit: %s", raw)
	}
}

// Файл квитанций большой и старый: читается только хвост, покрывающий окно,
// потом — только дописанное. Обрывок последней строки и замена файла счёт не
// ломают.
func TestLedgerReadsOnlyWhatTheWindowNeeds(t *testing.T) {
	path := filepath.Join(t.TempDir(), "receipts.jsonl")
	now := time.Date(2026, 11, 22, 12, 0, 0, 0, time.UTC)
	var buf bytes.Buffer
	signer, _ := gateway.NewSigner(testKey, "esmcp", nil)
	line := func(at time.Time, agent, outcome, cause string, rows int) {
		buf.Write(signedLine(t, signer, Receipt{ActionID: "x", Time: at.Format(time.RFC3339Nano), Agent: agent, Tool: "execute",
			SQL: strings.Repeat("update t set v = 1; ", 20), Outcome: outcome, Cause: cause, Rows: rows}))
	}
	for i := 0; i < 3000; i++ { // больше мегабайта старых квитанций
		line(now.Add(-48*time.Hour).Add(time.Duration(i)*time.Second), "support-bot", "committed", "", 1000)
	}
	line(now.Add(-9*time.Minute), "support-bot", "committed", "", 70)
	line(now.Add(-8*time.Minute), "support-bot", "failed", "", 50)         // не зафиксировано: строк нет
	line(now.Add(-30*time.Second), "support-bot", "refused", CauseRate, 0) // отказ за частоту — не действие
	line(now.Add(-20*time.Second), "other-bot", "committed", "", 500)
	line(now.Add(-10*time.Second), "support-bot", "committed", "", 30)
	if err := os.WriteFile(path, buf.Bytes(), 0o600); err != nil {
		t.Fatal(err)
	}
	s := serverOn(t, &fakeDB{}, path, func(c *Config) { c.ActionsPerMinute, c.WindowRows, c.Window = 10, 1000, 10*time.Minute })
	actions, rows, _, err := s.usage(now, "")
	if err != nil || actions != 1 || rows != 100 {
		t.Fatalf("usage: %d actions, %d rows, %v", actions, rows, err)
	}
	if len(s.ledger.items) != 3 {
		t.Fatalf("the ledger keeps %d items", len(s.ledger.items))
	}
	// Другой сеанс дописал квитанцию и не дописал следующую.
	buf.Reset()
	line(now, "support-bot", "committed", "", 5)
	f, _ := os.OpenFile(path, os.O_APPEND|os.O_WRONLY, 0)
	f.Write(buf.Bytes())
	f.WriteString(`{"action_id":"torn","time":"` + now.Format(time.RFC3339Nano) + `","agent":"support-bot","tool":"exe`)
	f.Close()
	if actions, rows, _, _ := s.usage(now, ""); actions != 2 || rows != 105 {
		t.Fatalf("after an append: %d actions, %d rows", actions, rows)
	}
	// Файл переписали коротким (copytruncate): в нём всё новое, а счёт до
	// ротации остаётся в окне (R2-9 второго захода).
	buf.Reset()
	signer, _ = gateway.NewSigner(testKey, "esmcp", nil)
	line(now, "support-bot", "committed", "", 7)
	os.WriteFile(path, buf.Bytes(), 0o600)
	if actions, rows, _, _ := s.usage(now.Add(time.Second), ""); actions != 3 || rows != 112 {
		t.Fatalf("after the file was replaced: %d actions, %d rows", actions, rows)
	}
}

// Файл квитанций не прочитать: предел частоты не проверить — действие не
// идёт в базу.
func TestRateLimitDoesNotFailOpen(t *testing.T) {
	dir := t.TempDir()
	db := &fakeDB{}
	s := serverOn(t, db, filepath.Join(dir, "receipts.jsonl"), func(c *Config) { c.ActionsPerMinute = 3 })
	s.cfg.ReceiptsPath = dir // каталог вместо файла: чтение не удастся
	text, isErr := callText(t, s, "execute", `{"sql":"UPDATE accounts SET note = 'x'"}`)
	if !isErr || !strings.Contains(text, "cannot be checked") || len(db.log) != 0 {
		t.Fatalf("%v %s %q", isErr, text, db.log)
	}
}

// Квитанция другого сеанса, застигнутая недописанной, входит в счёт, когда её
// допишут. До исправления P-244 чтение продолжалось с конца файла, и остаток
// строки не разбирался: квитанция пропадала из счёта сеанса насовсем, а
// предел за окно пропускал действие сверх себя.
func TestLedgerCountsAReceiptCaughtMidWrite(t *testing.T) {
	path := filepath.Join(t.TempDir(), "receipts.jsonl")
	now := time.Date(2026, 11, 22, 12, 0, 0, 0, time.UTC)
	stat := "40"
	db := &fakeDB{answers: func(sql string) ([]pgwire.Result, bool) {
		if strings.Contains(sql, "pg_stat_get_xact_tuples") && !strings.Contains(sql, "pg_current_xact_id") {
			return []pgwire.Result{{Columns: []string{"sum"}, Rows: [][]*string{{&stat}}, Tag: "SELECT 1"}}, true
		}
		return nil, false
	}}
	b := serverOn(t, db, path, func(c *Config) { c.WindowRows, c.Window = 50, 10*time.Minute })
	b.now = func() time.Time { return now }
	if _, rows, _, err := b.usage(now, ""); err != nil || rows != 0 {
		t.Fatal(rows, err)
	}
	// Другой сеанс этого агента дописывает квитанцию о действии в 40 строк;
	// этот читает, когда в файле лишь её начало.
	signer, _ := gateway.NewSigner(testKey, "esmcp", nil)
	line := signedLine(t, signer, Receipt{ActionID: "a-x", Time: now.Add(-time.Second).Format(time.RFC3339Nano), Agent: "support-bot", Tool: "execute",
		SQL: "UPDATE accounts SET note = 'x' WHERE id <= 40", Outcome: "committed", Rows: 40, XID: "900"})
	f, err := os.OpenFile(path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	f.Write(line[:len(line)/2])
	if _, rows, _, err := b.usage(now, ""); err != nil || rows != 0 {
		t.Fatalf("half a receipt counted: %d rows, %v", rows, err)
	}
	f.Write(line[len(line)/2:])
	if _, rows, _, err := b.usage(now, ""); err != nil || rows != 40 {
		t.Fatalf("the receipt completed after a read: %d rows counted, want 40 (%v)", rows, err)
	}
	// И предел за окно держит: ещё 40 строк при пределе 50 — отказ.
	if text, isErr := callText(t, b, "execute", `{"sql":"UPDATE accounts SET note = 'y' WHERE id > 40"}`); !isErr || !strings.Contains(text, "would have changed 80 rows") {
		t.Fatalf("%v %s", isErr, text)
	}
}
