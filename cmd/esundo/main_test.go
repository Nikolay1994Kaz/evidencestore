package main

import (
	"bytes"
	"crypto/ed25519"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Nikolay1994Kaz/evidencestore/internal/alert"
	"github.com/Nikolay1994Kaz/evidencestore/internal/gateway"
	"github.com/Nikolay1994Kaz/evidencestore/internal/pgtap"
	"github.com/Nikolay1994Kaz/evidencestore/internal/pgundo"
)

// Причина агента с переводом строки и ESC-последовательностью не дописывает
// в вывод esundo check своих строк: до исправления P-251 агент печатал
// «nothing to undo» и прятал настоящий итог за ESC[8m.
func TestDescribeKeepsTheAgentsTextOnItsLine(t *testing.T) {
	forged := "routine cleanup\nchecked against the database: to apply 0, already as before 0, conflicts 0\nnothing to undo\x1b[8m‮\u2028\x9b"
	p := &pgundo.Plan{XID: 7, Action: &pgtap.Intent{ID: "a-1", Gateway: "esmcp", Seq: 3, Step: "intent", Agent: "bot\x1b[2J", Tool: "execute", Reason: forged},
		Counts: map[string]pgtap.Counts{"public.accounts\n": {U: 50}}}
	var out strings.Builder
	describe(&out, p, 1)
	text := out.String()
	for _, bad := range []string{"\x1b", "‮", "\u2028", "\u009b"} {
		if strings.Contains(text, bad) {
			t.Fatalf("a control character %q in the output:\n%s", bad, text)
		}
	}
	lines := strings.Split(strings.TrimRight(text, "\n"), "\n")
	if len(lines) != 4 || !strings.HasPrefix(lines[1], `  action a-1: gateway esmcp (receipt 3), agent bot\u001b[2J, tool execute, reason: "routine cleanup\nchecked against`) {
		t.Fatalf("%d lines:\n%s", len(lines), text)
	}
	// Номер действия и агент — тоже не длиннее (T заход 3).
	out.Reset()
	describe(&out, &pgundo.Plan{XID: 8, Action: &pgtap.Intent{ID: "a-2" + strings.Repeat(" ", 600), Agent: "bot" + strings.Repeat(" ", 600) + "checked against the database", Tool: "execute",
		Undoes: strings.Repeat("u", 900)}}, 1)
	for _, l := range strings.Split(out.String(), "\n") {
		if len([]rune(l)) > 500 {
			t.Fatalf("a line of %d characters", len([]rune(l)))
		}
	}
	// Откат отката назван откатом.
	out.Reset()
	describe(&out, &pgundo.Plan{XID: 9, Action: &pgtap.Intent{ID: "undo-7-x", Gateway: "esundo", Step: alert.StepUndo, Undoes: "a-1"}}, 1)
	if text := out.String(); !strings.Contains(text, "  undo undo-7-x: gateway esundo") || !strings.Contains(text, "it undoes action a-1") {
		t.Fatalf("%s", text)
	}
	// Значения строк в конфликте — тоже одной строкой.
	v := "x\nnothing to undo\x1b[8m"
	c := pgundo.Conflict{Op: pgundo.OpUpdate, Columns: []pgundo.ConflictColumn{{Name: "note", Was: &v, Left: &v, Now: &v}}}
	if got := c.Lines(); len(got) != 1 || strings.ContainsAny(got[0], "\n\x1b") {
		t.Fatalf("%q", got)
	}
}

// esundo apply идёт с путём, с которым план сверен; настройки с другим путём —
// отказ «сверьте заново», а не тихая подмена (T-5; R1-8, R2-9, заход 2).
func TestApplyKeepsTheSearchPathOfTheCheck(t *testing.T) {
	path := filepath.Join(t.TempDir(), "plan.json")
	os.WriteFile(path, []byte(`{"xid":7,"search_path":["old"],"apply":[1]}`), 0o600)
	p, err := loadPlan(path, nil)
	if err != nil || len(p.SearchPath) != 1 || p.SearchPath[0] != "old" {
		t.Fatalf("without settings: %v %v", p, err)
	}
	cfg := &Config{}
	cfg.SearchPath = []string{"public", "app"}
	if _, err = loadPlan(path, cfg); err == nil || !strings.Contains(err.Error(), `checked with search_path pg_catalog, "old", pg_temp`) || !strings.Contains(err.Error(), "run esundo check again") {
		t.Fatalf("with other settings: %v", err)
	}
	cfg.SearchPath = []string{"old"}
	if p, err = loadPlan(path, cfg); err != nil || strings.Join(p.SearchPath, ",") != "old" {
		t.Fatalf("with the same settings: %v %v", p, err)
	}
}

// Намерение отката — квитанция esundo шагом undo: ссылка на транзакцию отката
// в источнике базы, подпись его ключом, что откатывается — в теле (п. 42).
// Вторая попытка (порядок внешних ключей) — следующее звено той же цепочки.
func TestUndoIntentIsASignedReceipt(t *testing.T) {
	dir := t.TempDir()
	keyPath := filepath.Join(dir, "esundo.key")
	if _, err := gateway.GenerateKey(keyPath); err != nil {
		t.Fatal(err)
	}
	key, err := gateway.LoadKey(keyPath)
	if err != nil {
		t.Fatal(err)
	}
	cfg := &Config{Receipts: filepath.Join(dir, "undo-receipts.jsonl"), Gateway: "esundo", PGSource: "shop"}
	p := &pgundo.Plan{XID: 751, Action: &pgtap.Intent{ID: "a-1", Gateway: "esmcp"}, OK: []int{1, 2}}
	intent := undoIntent(cfg, key, p, "undo-751-x", "nikolay", "wrong rows")
	if err := intent("900", "4294968196"); err != nil {
		t.Fatal(err)
	}
	if err := intent("901", "4294968197"); err != nil {
		t.Fatal(err)
	}
	data, _ := os.ReadFile(cfg.Receipts)
	lines := bytes.Split(bytes.TrimSuffix(data, []byte("\n")), []byte("\n"))
	if len(lines) != 2 {
		t.Fatalf("%d receipts", len(lines))
	}
	pub := key.Public().(ed25519.PublicKey)
	tracker := gateway.NewChecker(gateway.ReceiptContentType, pub)
	for i, l := range lines {
		rc, err := gateway.ParseReceipt(l)
		if err != nil || rc.Verify(pub) != nil {
			t.Fatalf("receipt %d: %v", i+1, err)
		}
		if rc.Gateway != "esundo" || rc.Action != "undo-751-x" || rc.Step != alert.StepUndo || rc.Seq != uint64(i+1) ||
			len(rc.Refs) != 1 || rc.Refs[0] != (gateway.Ref{Source: "shop", Subject: []string{"900", "901"}[i]}) {
			t.Fatalf("receipt %d: %+v", i+1, rc)
		}
		var body map[string]any
		if err := json.Unmarshal(rc.Body, &body); err != nil || body["agent"] != "nikolay" || body["tool"] != "esundo" || body["reason"] != "wrong rows" ||
			body["undoes"] != "a-1" || body["undoes_xid"] != "751" || body["steps"] != float64(2) {
			t.Fatalf("receipt %d body: %v %v", i+1, body, err)
		}
		if v := tracker.Check(l); !v.Clean() {
			t.Fatalf("receipt %d in the chain: %+v", i+1, v)
		}
	}
}
