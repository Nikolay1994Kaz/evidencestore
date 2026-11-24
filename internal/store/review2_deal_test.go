package store

// Регрессия второго захода проверки шагов 2–3 (24.11): тесты R1, R2 и T,
// которые падали на 7643a65 и проходят после исправлений (FINDINGS, P-357…).

// Второй заход проверки (R1, rev7): пакет по сделке и правило stale на
// настоящем хранилище.

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Nikolay1994Kaz/evidencestore/internal/gateway"
	"github.com/Nikolay1994Kaz/evidencestore/internal/proof"
)

// R1-5. Копия настоящей квитанции действия, дописанная в файл без ключа
// (её номер действия виден в файле): хранилище честно называет её stale —
// подпись верна, тело то же, метка та же. Не чиста — тело в пакете не
// вскрывается; под меткой действия — сделка «2 of its 3 records are open».
// P-348 убрал из счёта только строки с чужой подписью (SigInvalid); копия с
// верной подписью держит сделку по-прежнему — та же P-348 другим путём.
func TestR1ReplayedCopyHoldsTheDeal(t *testing.T) {
	key, pub := receiptGateway(t, 31)
	c := newClock()
	s := openStore(t, testConfig(t, withReceipts(pub)), c)
	gw, _ := gateway.NewSigner(key, "shop-gw", nil)
	ingest(t, s, "abs-core", 1, 1)
	mustStamp(t, s) // 10:00
	c.add(time.Minute)
	mandate := sign(t, gw, "p-1", "mandate")
	ingestShop(t, s, 1, mandate)
	ingestShop(t, s, 2, sign(t, gw, "p-2", "mandate"))
	ingestShop(t, s, 3, sign(t, gw, "p-1", "cart"))
	ingestShop(t, s, 4, bytes.Clone(mandate)) // копия, дописанная без ключа
	ingestShop(t, s, 5, sign(t, gw, "p-2", "cart"))
	c.add(5 * time.Minute)
	mustStamp(t, s) // 10:06
	mustStampNow(t, s)
	b, err := s.ProofSubject("shop", "p-1", clockAt(10, 0, 30), clockAt(10, 3, 30), 0)
	if err != nil {
		t.Fatal(err)
	}
	r := proof.VerifySource(sourceRoundTrip(t, b), receiptTrust(t, s, pub), time.Time{}, time.Time{})
	if !r.Valid() {
		t.Fatalf("пакет по p-1:\n%s", r.Text())
	}
	d := proof.LinkDeal(r, nil)
	if !d.Valid() {
		var why string
		for _, ch := range d.Checks {
			if !ch.OK && why == "" {
				why = ch.Detail
			}
		}
		t.Fatalf("копия квитанции p-1 с верной подписью (stale, %v поломаны) держит сделку честного действия: %s", r.GatewayBroken, why)
	}
	if d.Receipts != 2 || d.Copies != 1 || len(r.GatewayRepeats) != 1 {
		t.Fatalf("квитанций в сделке %d, копий %d, повторов в отчёте %v: копия — та же квитанция", d.Receipts, d.Copies, r.GatewayRepeats)
	}
	if !strings.Contains(r.Text(), "stale") {
		t.Logf("%s", r.Text())
	}
}

// R1-1 у хранилища. Шлюз (gateway.Append) после обрезки файла раздваивает
// цепочку: квитанции новых действий — с seq, которые хранилище уже видело.
// Хранилище называет их stale, тела в пакете не вскрываются — сделка
// честного действия, сделанного после обрезки, не сводится.
func TestR1ForkAfterTruncationRefusesTheDeal(t *testing.T) {
	key, pub := receiptGateway(t, 32)
	c := newClock()
	s := openStore(t, testConfig(t, withReceipts(pub)), c)
	path := filepath.Join(t.TempDir(), "receipts.jsonl")
	appendOne := func(action, step string) []byte {
		a, err := gateway.Append(path, key, "shop-gw", gateway.Draft{Time: time.Date(2026, 9, 25, 10, 0, 0, 0, time.UTC), Action: action, Step: step})
		if err != nil {
			t.Fatal(err)
		}
		return a.Line
	}
	ingest(t, s, "abs-core", 1, 1)
	mustStamp(t, s) // 10:00
	c.add(time.Minute)
	var seq uint64
	var ends []int64
	for i := 1; i <= 4; i++ {
		seq++
		ingestShop(t, s, seq, appendOne(fmt.Sprintf("p-%d", i), "mandate"))
		fi, _ := os.Stat(path)
		ends = append(ends, fi.Size())
	}
	// Писатель без ключа обрезает файл до первой квитанции; дальше — новое
	// честное действие p-new из двух шагов.
	if err := os.Truncate(path, ends[0]); err != nil {
		t.Fatal(err)
	}
	for _, step := range []string{"mandate", "cart"} {
		seq++
		ingestShop(t, s, seq, appendOne("p-new", step))
	}
	c.add(5 * time.Minute)
	mustStamp(t, s) // 10:06
	mustStampNow(t, s)
	b, err := s.ProofSubject("shop", "p-new", clockAt(10, 0, 30), clockAt(10, 3, 30), 0)
	if err != nil {
		t.Fatal(err)
	}
	r := proof.VerifySource(sourceRoundTrip(t, b), receiptTrust(t, s, pub), time.Time{}, time.Time{})
	d := proof.LinkDeal(r, nil)
	if !r.Valid() || !d.Valid() {
		var why string
		for _, ch := range d.Checks {
			if !ch.OK && why == "" {
				why = ch.Detail
			}
		}
		t.Fatalf("честное действие после обрезки файла: пакет %s, поломаны %v, сделка — %s", r.Verdict(), r.GatewayBroken, why)
	}
}

// Повтор открывается, только если подпись — шлюза: копия, собранная чужим
// ключом (seq не новее последней — тоже stale у хранилища), — подделка, её
// тело не вскрывается, и сделку она не держит.
func TestForgedRepeatIsNotOpened(t *testing.T) {
	key, pub := receiptGateway(t, 33)
	forgerKey, _ := receiptGateway(t, 34)
	c := newClock()
	s := openStore(t, testConfig(t, withReceipts(pub)), c)
	gw, _ := gateway.NewSigner(key, "shop-gw", nil)
	ingest(t, s, "abs-core", 1, 1)
	mustStamp(t, s) // 10:00
	c.add(time.Minute)
	first := sign(t, gw, "p-1", "mandate")
	ingestShop(t, s, 1, first)
	ingestShop(t, s, 2, sign(t, gw, "p-2", "mandate"))
	prev, _ := gateway.ParseReceipt(first)
	ingestShop(t, s, 3, forgeAfter(t, forgerKey, prev, "p-1", "cancel")) // seq 2 после seq 2
	ingestShop(t, s, 4, sign(t, gw, "p-1", "cart"))
	c.add(5 * time.Minute)
	mustStamp(t, s) // 10:06
	mustStampNow(t, s)
	b, err := s.ProofSubject("shop", "p-1", clockAt(10, 0, 30), clockAt(10, 3, 30), 0)
	if err != nil {
		t.Fatal(err)
	}
	r := proof.VerifySource(sourceRoundTrip(t, b), receiptTrust(t, s, pub), time.Time{}, time.Time{})
	if !r.Valid() || len(r.GatewayRepeats) != 0 || len(r.GatewayForged) != 1 || r.Withheld() != 1 {
		t.Fatalf("повторы %v, подделки %v, не вскрыто %d:\n%s", r.GatewayRepeats, r.GatewayForged, r.Withheld(), r.Text())
	}
	if d := proof.LinkDeal(r, nil); !d.Valid() || d.Receipts != 2 {
		t.Fatalf("сделка по p-1:\n%s", d.Text())
	}
}
