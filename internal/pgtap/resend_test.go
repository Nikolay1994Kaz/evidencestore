package pgtap

import (
	"os"
	"strconv"
	"testing"
	"time"

	"github.com/Nikolay1994Kaz/evidencestore/internal/alert"
	"github.com/Nikolay1994Kaz/evidencestore/internal/pgoutput"
)

// tx подаёт транзакцию с явным временем фиксации; flushed — что подтвердить.
func (h *harness) tx(xid uint32, final uint64, at time.Time, msgs ...any) uint64 {
	h.t.Helper()
	all := append([]any{pgoutput.Begin{FinalLSN: final, CommitTime: at, XID: xid}}, h.intents(xid, msgs)...)
	all = append(all, pgoutput.Commit{CommitLSN: final, EndLSN: final + 50})
	var flushed uint64
	for _, m := range all {
		f, err := h.tap.Handle(m)
		if err != nil {
			h.t.Fatalf("%T: %v", m, err)
		}
		if f != 0 {
			flushed = f
		}
	}
	return flushed
}

// T-1, R2-3, R2-8 второго захода: поток идёт от слота. Ниже места входа
// повтор того, что в буфере (тот же xid и время на том же месте), не пишется
// снова; другая транзакция на этом месте или на месте, которого в буфере нет,
// — новая: она пишется, а первая такая зовёт Diverged.
func TestResentBelowThePlace(t *testing.T) {
	dir := t.TempDir()
	ins := pgoutput.Insert{RelID: 7, New: []pgoutput.Value{txt("1"), txt("x")}}
	t0 := time.Date(2026, 11, 24, 10, 0, 0, 0, time.UTC)
	h := open(t, dir, func(c *Config) { c.PackTx = 1 })
	h.tx(10, 2000, t0, who("agent"), accounts, ins)
	h.tx(11, 2100, t0.Add(time.Second), accounts, ins) // отпечаток
	h.tx(12, 2200, t0.Add(2*time.Second), who("agent"), accounts, ins)
	h.tap.Close()
	spooled := len(h.sink.bodies)

	var diverged []uint64
	h = openOn(t, dir, h.sink, func(c *Config) {
		c.PackTx = 1
		c.Diverged = func(xid uint32, final, place uint64) error {
			diverged = append(diverged, final, place)
			return nil
		}
	})
	if err := h.tap.Resume(1500, false); err != nil {
		t.Fatal(err)
	}
	// Сервер шлёт от слота: повторы — не в буфер.
	h.tx(10, 2000, t0, who("agent"), accounts, ins)
	h.tx(11, 2100, t0.Add(time.Second), accounts, ins)
	if len(h.sink.bodies) != spooled || len(diverged) != 0 {
		t.Fatalf("repeats: %d records spooled again, diverged %v", len(h.sink.bodies)-spooled, diverged)
	}
	// Дальше база пошла другой историей (поднята из копии): на месте 2150
	// у сборщика ничего, на месте 2200 — другая транзакция.
	h.tx(40, 2150, t0.Add(time.Hour), who("agent"), accounts, ins)
	h.tx(12, 2200, t0.Add(time.Hour+time.Second), accounts, ins)
	if len(diverged) != 2 || diverged[0] != 2150 || diverged[1] != 2200 {
		t.Fatalf("diverged %v", diverged)
	}
	idx := h.index()
	if n := len(idx); n != 5 || idx[3].XID != 40 || idx[3].Action == nil || idx[4].XID != 12 || idx[4].Kind != KindFingerprint {
		t.Fatalf("index %+v", idx)
	}
	if s := h.tap.Stats(); s.Duplicates != 2 {
		t.Fatalf("%+v", s)
	}
}

// Подъём виден при подключении (rewound): ниже места, где сверить не с чем,
// транзакция — новая, а не повтор по месту.
func TestRewoundTakesWhatItCannotCheck(t *testing.T) {
	dir := t.TempDir()
	ins := pgoutput.Insert{RelID: 7, New: []pgoutput.Value{txt("1"), txt("x")}}
	t0 := time.Date(2026, 11, 24, 10, 0, 0, 0, time.UTC)
	h := open(t, dir, nil)
	h.tx(10, 2000, t0, who("agent"), accounts, ins)
	h.tap.Close()
	h = openOn(t, dir, h.sink, func(c *Config) { c.PackTx = 1 })
	if err := h.tap.Resume(1000, true); err != nil {
		t.Fatal(err)
	}
	h.tap.floor = 1900 // ниже 1900 справочник не помнит
	before := len(h.index())
	h.tx(10, 1500, t0.Add(time.Hour), accounts, ins)
	if len(h.index()) != before+1 {
		t.Fatal("a transaction below what the index remembers was taken for a repeat after the database went back")
	}
}

// T-9 второго захода: отпечаток с тревогой лёг в пачку, пачка в буфер не
// легла (связь оборвалась) — сервер шлёт транзакцию снова, тревога людям —
// одна.
func TestPendingFingerprintAlertsOnce(t *testing.T) {
	h := open(t, t.TempDir(), func(c *Config) { c.AlertRows = 1; c.PackTx = 100 })
	ins := pgoutput.Insert{RelID: 7, New: []pgoutput.Value{txt("1"), txt("x")}}
	t0 := time.Date(2026, 11, 24, 10, 0, 0, 0, time.UTC)
	for range 3 {
		h.tx(20, 3000, t0, accounts, ins)
		h.tap.Reset()
	}
	var mass int
	for _, ev := range h.alerts() {
		for _, k := range ev.Kinds() {
			if k == alert.KindMassChange {
				mass++
			}
		}
	}
	if mass != 1 {
		t.Fatalf("%d mass-change alerts after 3 broken connections", mass)
	}
}

// LookupTail — последняя строка с xid в хвосте справочника; строка, начатая
// до хвоста, не разбирается.
func TestLookupTail(t *testing.T) {
	path := t.TempDir() + "/index.jsonl"
	var b []byte
	for i := 0; i < 50; i++ {
		b = append(b, []byte(`{"xid":`+strconv.Itoa(700+i%5)+`,"first_seq":`+strconv.Itoa(i+1)+`,"last_seq":`+strconv.Itoa(i+1)+`,"changes":1}`+"\n")...)
	}
	os.WriteFile(path, b, 0o600)
	e, ok, err := LookupTail(path, 703, 1<<20)
	if err != nil || !ok || e.FirstSeq != 49 {
		t.Fatalf("%+v %v %v", e, ok, err)
	}
	if _, ok, _ := LookupTail(path, 703, 100); ok {
		t.Fatal("found outside the tail")
	}
	if _, ok, _ := LookupTail(path, 799, 1<<20); ok {
		t.Fatal("found a transaction that is not there")
	}
}
