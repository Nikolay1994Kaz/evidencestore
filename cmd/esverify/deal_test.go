package main

import (
	"bytes"
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Nikolay1994Kaz/evidencestore/internal/config"
	"github.com/Nikolay1994Kaz/evidencestore/internal/gateway"
)

// Пакет по сделке (DECISIONS, п. 42): квитанции действия a-1 называют
// транзакцию 754 источника базы, и esverify сводит пакет квитанций с пакетом
// транзакции: оба проходят, связь — по открытой квитанции. Пакет чужой
// транзакции, пропавший пакет, пакет не того вида — отказ.
func TestDealBundle(t *testing.T) {
	key := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{7}, ed25519.SeedSize))
	pub := hex.EncodeToString(key.Public().(ed25519.PublicKey))
	w := openWorld(t, []config.Source{
		{Name: "agent-mcp", ContentType: config.ReceiptContentType, GatewayKey: pub, SubjectField: config.ReceiptSubjectField},
		{Name: "pg-agent", ContentType: "pg/before-images-v1", SubjectField: "xid"},
	})
	gw, _ := gateway.NewSigner(key, "esmcp", nil)
	receipt := func(action, step string, refs ...gateway.Ref) string {
		line, err := gw.Sign(gateway.Draft{Time: time.Date(2026, 10, 26, 10, 0, 0, 0, time.UTC), Action: action, Step: step, Refs: refs, Body: json.RawMessage(`{"agent":"bot"}`)})
		if err != nil {
			t.Fatal(err)
		}
		return string(line)
	}
	w.line(t, "agent-mcp", 1, receipt("a-0", "intent", gateway.Ref{Source: "pg-agent", Subject: "700"}))
	w.stamp(t)
	w.advance(5 * time.Minute)
	w.line(t, "agent-mcp", 2, receipt("a-1", "intent", gateway.Ref{Source: "pg-agent", Subject: "754"}))
	w.line(t, "pg-agent", 1, `{"xid":754,"part":1,"last":true,"gz":""}`)
	w.line(t, "pg-agent", 2, `{"xid":755,"part":1,"last":true,"gz":""}`)
	w.line(t, "agent-mcp", 3, receipt("a-1", "outcome"))
	w.advance(5 * time.Minute)
	w.closeUp(t)
	bundle := func(source, subject string) string {
		b, err := w.s.ProofSubject(source, subject, w.from, w.to, 0)
		if err != nil {
			t.Fatal(err)
		}
		return w.file(t, source+"-"+subject+".json", b)
	}
	receipts, tx, other := bundle("agent-mcp", "a-1"), bundle("pg-agent", "754"), bundle("pg-agent", "755")

	bodies := filepath.Join(w.dir, "bodies")
	code, out, errOut := w.run(t, receipts, "-linked", tx, "-gateway-key", pub, "-bodies", bodies)
	if code != exitValid || !strings.HasPrefix(out, "VERIFIED\n\nDeal: action \"a-1\" of gateway \"esmcp\", 2 receipts open\n") ||
		!strings.Contains(out, `named by receipts [2]: "pg-agent" "754" — linked bundle 1: 1 records, 1 open`) ||
		!strings.Contains(out, "2 signatures checked with your gateway key") || !strings.Contains(out, "=== linked bundle 1 ("+tx+") ===") {
		t.Fatalf("код %d:\n%s\n%s", code, out, errOut)
	}
	files, _ := os.ReadDir(bodies)
	var names []string
	for _, f := range files {
		names = append(names, f.Name())
	}
	if strings.Join(names, " ") != "agent-mcp-2 agent-mcp-3 pg-agent-1" {
		t.Fatalf("файлы %v", names)
	}
	code, out, _ = w.run(t, receipts, "-linked", tx, "-json")
	var rep map[string]any
	if err := json.Unmarshal([]byte(out), &rep); code != exitValid || err != nil || rep["kind"] != "deal" || rep["action"] != "a-1" ||
		rep["gateway_key_checked"] != false || len(rep["bundles"].([]any)) != 2 || len(rep["links"].([]any)) != 1 {
		t.Fatalf("код %d, %v:\n%s", code, err, out)
	}

	for name, c := range map[string]struct {
		args []string
		code int
		want string
	}{
		"another transaction":             {[]string{"-linked", other}, exitInvalid, `linked bundle 1 (pg-agent "755") is named by no receipt of the action`},
		"no linked bundle of it":          {[]string{"-linked", other}, exitInvalid, `names pg-agent "754", and no linked bundle is of it`},
		"the deal starts at the receipts": {[]string{"-linked", receipts}, exitInvalid, "holds no gateway receipts"},
		"a missing file":                  {[]string{"-linked", filepath.Join(w.dir, "nope.json")}, exitUsage, "-linked"},
		"not a source bundle":             {[]string{"-linked", w.file(t, "single.json", []byte(`{"v":1}`))}, exitUsage, "a bundle by subject of one source"},
	} {
		proofFile := receipts
		if name == "the deal starts at the receipts" {
			proofFile = tx
		}
		code, out, errOut := w.run(t, proofFile, c.args...)
		if code != c.code || !strings.Contains(out+errOut, c.want) {
			t.Errorf("%s: код %d:\n%s\n%s", name, code, out, errOut)
		}
	}
	// С -linked пакет одной улики — неверный вызов.
	single := w.file(t, "one.json", []byte(`{"v":3,"evidence":""}`))
	if code, _, errOut := w.run(t, single, "-linked", tx); code != exitUsage || !strings.Contains(errOut, "-linked are for a bundle over a window") {
		t.Fatalf("код %d: %s", code, errOut)
	}
}
