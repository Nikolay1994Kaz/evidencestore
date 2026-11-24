package pginput

// Регрессия второго захода проверки шагов 2–3 (24.11): тесты R1, R2 и T,
// которые падали на 7643a65 и проходят после исправлений (FINDINGS, P-357…).

// Тестировщик T, второй заход 24.11 (находка T-1): подъём из копии, сборщик
// ничего не задолжал; после подъёма — правка человека и действие шлюза ниже
// прежнего места сборщика, потом обычная запись (транзакция вне tables)
// уводит журнал дальше этого места, и только тогда сборщик подключается.
// По концу журнала (IDENTIFY_SYSTEM) подъём уже не виден: сервер не шлёт
// транзакций ниже cursor+1 — правка и действие пропадают без записи, без
// отпечатка и без тревоги.
//
//	PGINPUT_RESTORE_DSN=… PGINPUT_RESTORE_DATA=… go test ./internal/pginput -run TestLiveRestoredT1 -v

import (
	"context"
	"os"
	"testing"
	"time"

	"github.com/Nikolay1994Kaz/evidencestore/internal/alert"
	"github.com/Nikolay1994Kaz/evidencestore/internal/pgtap"
)

func TestLiveRestoredT1WritesBelowThePlaceThenTraffic(t *testing.T) {
	dsn, data := os.Getenv("PGINPUT_RESTORE_DSN"), os.Getenv("PGINPUT_RESTORE_DATA")
	if dsn == "" || data == "" {
		t.Skip("PGINPUT_RESTORE_DSN and PGINPUT_RESTORE_DATA are not set")
	}
	t.Setenv("PGINPUT_TEST_DSN", dsn)
	r := newReviewRig(t)
	s := r.open()
	s.Close()
	pgctl(t, data, "stop")
	shell(t, "rm -rf "+data+".bak && cp -a "+data+" "+data+".bak")
	pgctl(t, data, "start")
	r.admin = r.dial("postgres")
	mcp := r.dial("rv_mcp")
	s = r.open()
	for i := 1; i <= 3; i++ {
		r.gw.act(mcp, "UPDATE public.rv_acc SET note = 'by the agent' WHERE id = 1")
	}
	if _, err := s.ReadAll(context.Background()); err != nil {
		t.Fatal(err)
	}
	cursor := r.sink.cursor
	before := len(r.sink.bodies)
	s.Close()
	pgctl(t, data, "stop")
	shell(t, "rm -rf "+data+" && cp -a "+data+".bak "+data)
	pgctl(t, data, "start")
	r.admin = r.dial("postgres")
	owner, mcp := r.dial("rv_owner"), r.dial("rv_mcp")
	xHuman := r.xact(owner, "DELETE FROM public.rv_acc WHERE id = 10")
	xAgent := r.gw.act(mcp, "UPDATE public.rv_acc SET note = 'by the agent after the restore' WHERE id = 2")
	below := r.lsn() < cursor
	// Обычная запись базы, с новыми xid: таблица вне tables.
	for i := 0; i < 50 && r.lsn() <= cursor; i++ {
		r.exec(r.admin, "CREATE TABLE IF NOT EXISTS t1_pad (t text)")
		r.exec(r.admin, "INSERT INTO t1_pad SELECT repeat('x', 1000) FROM generate_series(1, 2000)")
	}
	s = r.open()
	for i := 0; i < 10; i++ {
		s.ReadAll(context.Background())
		time.Sleep(200 * time.Millisecond)
	}
	// Номера после подъёма выдаются снова: в счёт — только записи новее прежних.
	eh, okH, _ := pgtap.Lookup(r.index(), xHuman)
	ea, okA, _ := pgtap.Lookup(r.index(), xAgent)
	foundH, foundA := okH && eh.LastSeq > uint64(before), okA && ea.LastSeq > uint64(before)
	rewound, gap := 0, 0
	for _, ev := range r.alerts() {
		for _, k := range ev.Kinds() {
			switch k {
			case alert.KindRewound:
				rewound++
			case alert.KindGap:
				gap++
			}
		}
	}
	t.Logf("writes below the collector's place: %v; records before %d, after %d; the person's xid %d in the index: %v; the agent's xid %d: %v; db-rewound %d, gap %d",
		below, before, len(r.sink.bodies), xHuman, foundH, xAgent, foundA, rewound, gap)
	if !foundH || !foundA || rewound == 0 {
		t.Fatalf("after the restore the person's transaction %d (found %v) and the agent's %d (found %v) were lost, db-rewound alerts %d", xHuman, foundH, xAgent, foundA, rewound)
	}
}
