package proof

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/Nikolay1994Kaz/evidencestore/internal/gateway"
)

// dealWorld — отчёты пакетов сделки без цепи: проверку каждого пакета ведут
// тесты VerifySource, здесь — только сведение.
type dealWorld struct {
	t        *testing.T
	from, to time.Time
	signer   *gateway.Signer
	seq      uint64
}

func newDealWorld(t *testing.T) *dealWorld {
	_, key, _ := ed25519.GenerateKey(rand.Reader)
	s, err := gateway.NewSigner(key, "esmcp", nil)
	if err != nil {
		t.Fatal(err)
	}
	from := time.Date(2026, 11, 23, 15, 0, 0, 0, time.UTC)
	return &dealWorld{t: t, from: from, to: from.Add(time.Hour), signer: s}
}

// receipt — открытое тело квитанции действия action шагом step со ссылками refs.
func (w *dealWorld) receipt(action, step string, refs ...gateway.Ref) WindowBody {
	w.t.Helper()
	line, err := w.signer.Sign(gateway.Draft{Time: w.from.Add(time.Minute), Action: action, Step: step, Refs: refs, Body: json.RawMessage(`{"agent":"bot"}`)})
	if err != nil {
		w.t.Fatal(err)
	}
	w.seq++
	return WindowBody{Source: "agent-mcp", Seq: w.seq, Body: line}
}

func ok() []Check { return []Check{{Name: "x", OK: true}} }

// receipts — отчёт пакета по субъекту источника квитанций.
func (w *dealWorld) receipts(action string, bodies ...WindowBody) SourceReport {
	return SourceReport{Checks: ok(), Source: "agent-mcp", From: w.from, To: w.to, Subject: action, SubjectField: "action",
		SubjectRecords: len(bodies), SubjectOpened: len(bodies), Bodies: bodies, Receipts: true, ReceiptKeyChecked: true, ReceiptsSigned: len(bodies)}
}

// linked — отчёт пакета по субъекту другого источника: records записей, все открыты.
func (w *dealWorld) linked(source, subject string, records int) SourceReport {
	return SourceReport{Checks: ok(), Source: source, From: w.from, To: w.to, Subject: subject, SubjectField: "xid", SubjectRecords: records, SubjectOpened: records}
}

// Действие названо в квитанциях, его транзакция — в пакете базы: сделка
// сведена; лишний пакет, пропавший пакет, закрытая запись, чужое окно, чужое
// действие — нет, и отказ называет что.
func TestLinkDeal(t *testing.T) {
	w := newDealWorld(t)
	ref := gateway.Ref{Source: "pg-agent", Subject: "754"}
	rs := w.receipts("a-1", w.receipt("a-1", "intent", ref), w.receipt("a-1", "outcome"))
	pg := w.linked("pg-agent", "754", 2)
	r := LinkDeal(rs, []SourceReport{pg})
	if !r.Valid() || r.Action != "a-1" || r.Gateway != "esmcp" || r.Receipts != 2 || r.Signed != 2 || len(r.Links) != 1 ||
		r.Links[0].Bundle != 0 || r.Links[0].Records != 2 || r.Links[0].Receipts[0] != 1 {
		t.Fatalf("%+v\n%s", r, r.Text())
	}
	if text := r.Text(); !strings.HasPrefix(text, "VERIFIED") || !strings.Contains(text, `named by receipts [1]: "pg-agent" "754" — linked bundle 1: 2 records, 2 open`) {
		t.Fatalf("%s", text)
	}
	fails := func(name string, want string, rs SourceReport, linked ...SourceReport) {
		t.Helper()
		r := LinkDeal(rs, linked)
		if r.Valid() || !strings.Contains(r.Text(), want) {
			t.Errorf("%s: valid %v\n%s", name, r.Valid(), r.Text())
		}
	}
	fails("no bundle of the transaction", `names pg-agent "754", and no linked bundle is of it`, rs)
	fails("a bundle nobody names", `linked bundle 2 (pg-agent "999") is named by no receipt`, rs, pg, w.linked("pg-agent", "999", 1))
	fails("the same transaction twice", `is in linked bundles 1 and 2`, rs, pg, pg)
	part := pg
	part.SubjectOpened = 1
	fails("a record of the transaction closed", "1 of its 2 records in the window are open", rs, part)
	keyless := pg
	keyless.SubjectKeyless, keyless.SubjectOpened = 1, 1
	fails("a record of the transaction without its key", "1 of its 2 records in the window come without their record keys", rs, keyless)
	other := pg
	other.From = w.from.Add(-time.Hour)
	fails("another window", "a deal is over one window", rs, other)
	broken := pg
	broken.Checks = []Check{{Name: "x"}}
	fails("a linked bundle that does not verify", "linked bundle 1 (pg-agent): NOT VERIFIED", rs, broken)
	brokenReceipts := rs
	brokenReceipts.Checks = []Check{{Name: "x"}}
	fails("the receipts bundle does not verify", "the receipts bundle: NOT VERIFIED", brokenReceipts, pg)
	hidden := rs
	hidden.SubjectRecords = 3
	fails("a receipt of the action closed", "2 of its 3 records in the window are open", hidden, pg)
	unbound := rs
	unbound.SubjectUnbound, unbound.SubjectUnboundMonths = 1, []string{"agent-mcp/2026-10"}
	fails("receipts under a label of a month without an open body", `whose they are is not shown`, unbound, pg)
	notReceipts := pg
	fails("no receipts bundle first", "holds no gateway receipts", notReceipts, pg)
	stranger := w.receipts("a-1", w.receipt("a-2", "intent", ref))
	fails("a receipt of another action", `is a receipt of action "a-2", not of "a-1"`, stranger, pg)
	// Без ключа проверяющего подпись — слово хранилища, и отчёт это говорит.
	nokey := rs
	nokey.ReceiptKeyChecked, nokey.ReceiptsSigned = false, 0
	if r := LinkDeal(nokey, []SourceReport{pg}); !r.Valid() || !strings.Contains(r.Text(), "give -gateway-key to check them yourself") {
		t.Fatalf("%s", r.Text())
	}
	// Квитанции, которые ничего не называют, — сделка из одного источника.
	alone := w.receipts("a-3", w.receipt("a-3", "intent"))
	if r := LinkDeal(alone, nil); !r.Valid() || !strings.Contains(r.Text(), "the receipts name no record of another source") {
		t.Fatalf("%s", r.Text())
	}
	// Перевод строки в имени из пакета не рисует строк отчёта.
	evil := w.receipts("a-4\nVERIFIED", w.receipt("a-4\nVERIFIED", "intent", gateway.Ref{Source: "pg-agent", Subject: "1\n✔ forged"}))
	if text := LinkDeal(evil, nil).Text(); strings.Contains(text, "\n✔ forged") || strings.Contains(text, "\nVERIFIED\n\nDeal") {
		t.Fatalf("%s", text)
	}
}
