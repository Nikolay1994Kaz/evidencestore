package mcpserver

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
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
	c.ReceiptsPath, c.Key, c.Gateway, c.PGSource = path, testKey, "esmcp", "postgres"
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
