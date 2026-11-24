package pginput

// Регрессия третьего захода проверки шагов 2–3 (24.11), находка T-1: база
// дважды поднята из одной и той же копии. Первый подъём сборщик увидел, потом
// он стоял, агент сделал действие в первой поднятой базе, и её снова подняли
// из копии. Место сборщика с первого подъёма то же: прежде второй подъём
// глушился («этот откат уже назван»), намерение действия из первой поднятой
// базы оставалось в силе и решало правку человека во второй — тем же номером
// транзакции, с откатом.
//
//	PGINPUT_RESTORE_DSN=… PGINPUT_RESTORE_DATA=… go test ./internal/pginput -run TestLiveRestoredTwice -v

import (
	"context"
	"os"
	"strconv"
	"testing"
	"time"

	"github.com/Nikolay1994Kaz/evidencestore/internal/alert"
	"github.com/Nikolay1994Kaz/evidencestore/internal/pgtap"
)

func TestLiveRestoredTwiceFromOneCopy(t *testing.T) {
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
	restore := func() {
		t.Helper()
		pgctl(t, data, "stop")
		shell(t, "rm -rf "+data+" && cp -a "+data+".bak "+data)
		pgctl(t, data, "start")
		time.Sleep(1100 * time.Millisecond) // другой запуск базы — другая секунда
		r.admin = r.dial("postgres")
	}
	read := func(s *Source) {
		t.Helper()
		for i := 0; i < 5; i++ {
			s.ReadAll(context.Background())
			time.Sleep(100 * time.Millisecond)
		}
	}
	r.admin = r.dial("postgres")
	mcp := r.dial("rv_mcp")
	s = r.open()
	for i := 1; i <= 3; i++ {
		r.gw.act(mcp, "UPDATE public.rv_acc SET note = 'by the agent' WHERE id = 1")
	}
	read(s)
	s.Close()

	restore() // подъём 1: сборщик его видит
	s = r.open()
	read(s)
	s.Close() // сборщик стоит

	mcp = r.dial("rv_mcp")
	xA1 := r.gw.act(mcp, "UPDATE public.rv_acc SET note = 'by the agent in the first restored database' WHERE id = 3")

	restore() // подъём 2 из той же копии: действия A1 больше нет
	owner := r.dial("rv_owner")
	for i := 0; i < 1000; i++ { // правке человека — тот же номер, что у A1
		next, _ := strconv.ParseUint(r.one(r.admin, "SELECT pg_snapshot_xmax(pg_current_snapshot())::text"), 10, 64)
		if uint32(next) >= xA1 {
			break
		}
		r.one(r.admin, "SELECT pg_current_xact_id()::text")
	}
	xHuman := r.xact(owner, "UPDATE public.rv_acc SET note = 'by a person in the second restored database' WHERE id = 4")
	if xHuman != xA1 {
		t.Skipf("the person's transaction got xid %d, the agent's action in the first restored database had %d", xHuman, xA1)
	}
	s = r.open()
	read(s)
	e, found, _ := pgtap.Lookup(r.index(), xHuman)
	rewound := 0
	for _, ev := range r.alerts() {
		for _, k := range ev.Kinds() {
			if k == alert.KindRewound {
				rewound++
			}
		}
	}
	t.Logf("db-rewound %d; the person's transaction %d in the index: %v, kind %q, action %v", rewound, xHuman, found, e.Kind, e.Action != nil)
	if !found || e.Action != nil {
		t.Errorf("the person's transaction %d in the second restored database went in as the agent's action from the first one (%+v)", xHuman, e.Action)
	}
	if rewound < 2 {
		t.Errorf("the second restore from the same copy is not named: db-rewound %d", rewound)
	}
}
