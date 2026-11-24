package mcpserver

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Nikolay1994Kaz/evidencestore/internal/alert"
	"github.com/Nikolay1994Kaz/evidencestore/internal/gateway"
	"github.com/Nikolay1994Kaz/evidencestore/internal/pgwire"
)

// testKey — ключ шлюза в тестах: один на все серверы над одним файлом, как у
// сеансов одного esmcp.
var testKey = func() ed25519.PrivateKey {
	_, k, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		panic(err)
	}
	return k
}()

// gatewayOn — квитанции шлюза в файл path, подписанные testKey.
func gatewayOn(c *Config, path string) {
	c.ReceiptsPath, c.HeadPath, c.Key, c.Gateway, c.PGSource = path, path+".head", testKey, "esmcp", "postgres"
}

// chain — все квитанции файла по порядку; каждая обязана быть квитанцией
// шлюза с его подписью.
func chain(t *testing.T, path string) []gateway.Receipt {
	t.Helper()
	data, _ := os.ReadFile(path)
	var out []gateway.Receipt
	for i, line := range bytes.Split(bytes.TrimSpace(data), []byte("\n")) {
		if len(line) == 0 {
			continue
		}
		r, err := gateway.ParseReceipt(line)
		if err != nil || r.Verify(testKey.Public().(ed25519.PublicKey)) != nil {
			t.Fatalf("line %d of the receipts is not a signed receipt: %v\n%s", i+1, err, line)
		}
		out = append(out, r)
	}
	return out
}

// receipts — исходы действий: тела квитанций шага outcome по порядку.
func receipts(t *testing.T, path string) []Receipt {
	t.Helper()
	var out []Receipt
	for _, r := range chain(t, path) {
		if r.Step != alert.StepOutcome {
			continue
		}
		var rc Receipt
		if err := json.Unmarshal(r.Body, &rc); err != nil {
			t.Fatal(err)
		}
		out = append(out, rc)
	}
	return out
}

// outcomes — тела квитанций исхода как есть: с подробностями отказа (Info),
// по которым сборщик поднимает тревогу.
func outcomes(t *testing.T, path string) []map[string]any {
	t.Helper()
	var out []map[string]any
	for _, r := range chain(t, path) {
		if r.Step != alert.StepOutcome {
			continue
		}
		var m map[string]any
		if err := json.Unmarshal(r.Body, &m); err != nil {
			t.Fatal(err)
		}
		out = append(out, m)
	}
	return out
}

// appendReceipt дописывает исход rc подписанной квитанцией шлюза: так его
// записал бы другой сеанс сервера.
func appendReceipt(t *testing.T, path string, rc Receipt) {
	t.Helper()
	at, err := time.Parse(time.RFC3339Nano, rc.Time)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := gateway.Append(path, testKey, "esmcp", gateway.Draft{Time: at, Action: rc.ActionID, Step: alert.StepOutcome, Body: bodyOf(rc)}); err != nil {
		t.Fatal(err)
	}
}

// signedLine — исход rc подписанной строкой цепочки s (с переводом строки),
// не записанной в файл.
func signedLine(t *testing.T, s *gateway.Signer, rc Receipt) []byte {
	t.Helper()
	at, _ := time.Parse(time.RFC3339Nano, rc.Time)
	line, err := s.Sign(gateway.Draft{Time: at, Action: rc.ActionID, Step: alert.StepOutcome, Body: bodyOf(rc)})
	if err != nil {
		t.Fatal(err)
	}
	return append(line, '\n')
}

// Намерение — до SQL агента: шагом intent, со ссылкой на транзакцию в
// источнике базы, подписанное ключом шлюза, с исходом pending; исход —
// следующим звеном той же цепочки после COMMIT (DECISIONS, п. 42).
func TestIntentGoesBeforeTheAgentsSQL(t *testing.T) {
	path := filepath.Join(t.TempDir(), "receipts.jsonl")
	var atSQL int // квитанций в файле, когда база получила SQL агента
	db := &fakeDB{answers: func(sql string) ([]pgwire.Result, bool) {
		if strings.HasPrefix(sql, "UPDATE accounts") {
			data, _ := os.ReadFile(path)
			atSQL = bytes.Count(data, []byte("\n"))
		}
		return nil, false
	}}
	s := serverOn(t, db, path, nil)
	if text, isErr := callText(t, s, "execute", `{"sql":"UPDATE accounts SET note = 'x' WHERE id = 1","reason":"tidy"}`); isErr {
		t.Fatal(text)
	}
	c := chain(t, path)
	if len(c) != 2 || atSQL != 1 {
		t.Fatalf("%d receipts, %d of them before the agent's SQL", len(c), atSQL)
	}
	in, out := c[0], c[1]
	if in.Step != alert.StepIntent || in.Gateway != "esmcp" || in.Action != "a-1" || in.Seq != 1 ||
		len(in.Refs) != 1 || in.Refs[0] != (gateway.Ref{Source: "postgres", Subject: "751"}) {
		t.Fatalf("the intent: %+v", in)
	}
	var body Receipt
	if err := json.Unmarshal(in.Body, &body); err != nil || body.Outcome != OutcomePending || body.Reason != "tidy" || body.Agent != "support-bot" || body.XID != "751" {
		t.Fatalf("the intent's body: %+v %v", body, err)
	}
	if out.Step != alert.StepOutcome || out.Seq != 2 || out.Prev != in.Hash || len(out.Refs) != 0 {
		t.Fatalf("the outcome: %+v", out)
	}
	if rc := receipts(t, path); len(rc) != 1 || rc[0].Outcome != "committed" {
		t.Fatalf("%+v", rc)
	}
	// Намерение не записалось — действия нет: SQL агента в базу не ушёл.
	s.cfg.ReceiptsPath = t.TempDir() // каталог вместо файла: квитанция не запишется
	db.log = nil
	if text, isErr := callText(t, s, "execute", `{"sql":"UPDATE accounts SET note = 'y' WHERE id = 1"}`); !isErr || !strings.Contains(text, "receipt could not be written") {
		t.Fatalf("%v %s", isErr, text)
	}
	for _, q := range db.log {
		if strings.Contains(q, "UPDATE accounts") {
			t.Fatalf("the agent's SQL went to the database without its intent: %q", db.log)
		}
	}
}

// Сервер упал между намерением и исходом: действие — pending, и откат его
// не отвергает с порога — его транзакцию сборщик мог взять по намерению.
func TestPendingActionCanBeUndone(t *testing.T) {
	path := filepath.Join(t.TempDir(), "receipts.jsonl")
	db := &fakeDB{answers: undoAnswers}
	s := serverOn(t, db, path, nil)
	if _, err := gateway.Append(path, testKey, "esmcp", gateway.Draft{Action: "a-1", Step: alert.StepIntent,
		Refs: []gateway.Ref{{Source: "postgres", Subject: "751"}},
		Body: bodyOf(Receipt{ActionID: "a-1", Time: time.Now().UTC().Format(time.RFC3339Nano), Agent: "support-bot", Tool: "execute", XID: "751", Outcome: OutcomePending})}); err != nil {
		t.Fatal(err)
	}
	s.cfg.Fetch = func(uint32) ([][]byte, error) { return [][]byte{journalLine()}, nil }
	if out, isErr := callText(t, s, "undo_preview", `{"action_id":"a-1"}`); isErr || !strings.Contains(out, `"to_apply":2`) {
		t.Fatalf("%v %s", isErr, out)
	}
}

// Строка от имени шлюза и агента, подписанная не ключом шлюза, — не его: ни в
// списке действий, ни в счёте пределов, ни в откате. Её дописал тот, у кого
// ключа нет (сборщик о ней поднимет forged-receipt).
func TestForeignReceiptsAreNotOwn(t *testing.T) {
	path := filepath.Join(t.TempDir(), "receipts.jsonl")
	s := serverOn(t, &fakeDB{}, path, func(c *Config) { c.WindowRows, c.Window = 50, time.Hour })
	s.cfg.Fetch = func(uint32) ([][]byte, error) { return [][]byte{journalLine()}, nil }
	if text, isErr := callText(t, s, "execute", `{"sql":"UPDATE accounts SET note = 'x' WHERE id = 1"}`); isErr {
		t.Fatal(text)
	}
	_, other, _ := ed25519.GenerateKey(rand.Reader)
	forger, _ := gateway.NewSigner(other, "esmcp", nil)
	line := signedLine(t, forger, Receipt{ActionID: "forged-1", Time: time.Now().UTC().Format(time.RFC3339Nano), Agent: "support-bot", Tool: "execute",
		SQL: "UPDATE accounts SET balance = 0", XID: "751", Outcome: "committed", Rows: 49})
	f, err := os.OpenFile(path, os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	f.Write(line)
	f.Close()
	if list, _ := callText(t, s, "actions", `{}`); strings.Contains(list, "forged-1") {
		t.Fatalf("a forged receipt is in the actions: %s", list)
	}
	if _, rows, _, err := s.usage(time.Now(), ""); err != nil || rows != 3 {
		t.Fatalf("the window counts %d rows (a forged receipt of 49 must not count): %v", rows, err)
	}
	if out, isErr := callText(t, s, "undo_preview", `{"action_id":"forged-1"}`); !isErr || !strings.Contains(out, "not in this server's receipts") {
		t.Fatalf("%v %s", isErr, out)
	}
	// Своё действие после подделки — следующим звеном своей цепочки.
	if text, isErr := callText(t, s, "execute", `{"sql":"UPDATE accounts SET note = 'y' WHERE id = 1"}`); isErr {
		t.Fatal(text)
	}
}

// oversizedArgs — вызов execute: 100 команд, первая с длинным литералом.
// Тело квитанции несёт текст дважды (sql и statements), а исход длиннее
// намерения на теги ответов.
func oversizedArgs(pad int) string {
	stmts := []string{fmt.Sprintf(`"UPDATE accounts SET balance = 0 WHERE id = 0 AND '%s' <> ''"`, strings.Repeat("p", pad))}
	for i := 1; i < 100; i++ {
		stmts = append(stmts, fmt.Sprintf(`"UPDATE accounts SET balance = 0 WHERE id = %d"`, i))
	}
	return `{"statements":[` + strings.Join(stmts, ",") + `],"reason":"tidy"}`
}

// Агент подбирал длину текста так, что намерение ещё влезало в квитанцию, а
// исход — уже нет: действие фиксировалось, исход не писался, и счёт пределов
// (по исходам) и тревоги refused его действий не видели — 10 действий по 400
// строк в минуту при пределах 3 в минуту и 1000 строк за 10 минут (R2-4).
// Теперь исход ложится всегда: текст SQL в нём заменяется его SHA-256.
func TestOversizedActionKeepsItsOutcome(t *testing.T) {
	now := time.Date(2026, 11, 23, 12, 0, 0, 0, time.UTC)
	stat := "400"
	db := &fakeDB{answers: func(sql string) ([]pgwire.Result, bool) {
		if strings.Contains(sql, "pg_stat_get_xact_tuples") && !strings.Contains(sql, "pg_current_xact_id") {
			return []pgwire.Result{{Columns: []string{"sum"}, Rows: [][]*string{{&stat}}, Tag: "SELECT 1"}}, true
		}
		return nil, false
	}}
	// Подбор, как сделал бы агент: наибольшая длина, при которой действие идёт.
	scratch := filepath.Join(t.TempDir(), "probe.jsonl")
	runs := func(pad int) bool {
		s := serverOn(t, db, scratch, nil)
		s.now = func() time.Time { return now }
		text, _ := callText(t, s, "execute", oversizedArgs(pad))
		return !strings.Contains(text, "did not run")
	}
	lo, hi := 0, gateway.MaxReceiptLen
	for lo < hi {
		if mid := (lo + hi + 1) / 2; runs(mid) {
			lo = mid
		} else {
			hi = mid - 1
		}
	}
	path := filepath.Join(t.TempDir(), "receipts.jsonl")
	limits := func(c *Config) {
		c.RowLimit, c.WindowRows, c.Window, c.ActionsPerMinute = 500, 1000, 10*time.Minute, 3
	}
	commits := 0
	for range 10 {
		s := serverOn(t, db, path, limits)
		s.now = func() time.Time { return now }
		before := len(db.log)
		callText(t, s, "execute", oversizedArgs(lo-50))
		for _, q := range db.log[before:] {
			if q == "COMMIT" {
				commits++
			}
		}
	}
	if commits > 2 {
		t.Fatalf("%d actions of 400 rows committed in one minute, past 3 a minute and 1000 rows in 10 minutes", commits)
	}
	hashed := 0
	for _, o := range outcomes(t, path) {
		if o["sql_sha256"] != nil && o["sql"] == "" {
			hashed++
		}
	}
	if hashed == 0 {
		t.Fatal("no outcome carries the hash of the SQL in place of its text")
	}
	// Отказ пределом строк при той же длине — с квитанцией исхода: по ней
	// сборщик поднимает тревогу.
	stat = "3000"
	s := serverOn(t, db, path, limits)
	s.now = func() time.Time { return now.Add(time.Hour) }
	text, _ := callText(t, s, "execute", oversizedArgs(lo-50))
	refused := 0
	for _, o := range outcomes(t, path) {
		if o["outcome"] == "refused" && o["cause"] == CauseRowLimit {
			refused++
		}
	}
	if !strings.Contains(text, "refused") || refused != 1 {
		t.Fatalf("over the row limit: %d refused outcomes; %.200s", refused, text)
	}
}

// Сервер убит между COMMIT и квитанцией исхода: намерение в файле есть,
// исхода нет, и зафиксированное в счёт пределов не шло — при окне 50 строк
// прошло 80 (T-8). Теперь намерение без исхода — действие с худшим случаем
// строк (предел действия); пришёл исход — в счёте его строки.
func TestIntentWithoutOutcomeCountsAtWorst(t *testing.T) {
	now := time.Now()
	path := filepath.Join(t.TempDir(), "receipts.jsonl")
	s := serverOn(t, &fakeDB{}, path, func(c *Config) {
		c.RowLimit, c.WindowRows, c.Window, c.ActionsPerMinute = 40, 50, 10*time.Minute, 30
	})
	rc := Receipt{ActionID: "a-1", Time: now.UTC().Format(time.RFC3339Nano), Agent: "support-bot", Tool: "execute", XID: "751", Outcome: OutcomePending}
	if _, err := gateway.Append(path, testKey, "esmcp", gateway.Draft{Time: now, Action: "a-1", Step: alert.StepIntent, Body: bodyOf(rc)}); err != nil {
		t.Fatal(err)
	}
	if actions, rows, _, err := s.usage(now, ""); err != nil || actions != 1 || rows != 40 {
		t.Fatalf("an intent without an outcome: %d actions, %d rows, %v", actions, rows, err)
	}
	// Идущее сейчас действие свои строки считает само.
	if _, rows, _, _ := s.usage(now, "a-1"); rows != 0 {
		t.Fatalf("the action's own intent is counted: %d rows", rows)
	}
	rc.Outcome, rc.Rows = "committed", 7
	appendReceipt(t, path, rc)
	if actions, rows, _, err := s.usage(now, ""); err != nil || actions != 1 || rows != 7 {
		t.Fatalf("after the outcome: %d actions, %d rows, %v", actions, rows, err)
	}
}
