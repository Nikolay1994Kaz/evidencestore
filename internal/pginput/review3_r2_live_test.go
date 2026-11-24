package pginput

// Третий заход проверки (R2, 24.11): как сломать исправления второго захода
// (P-359…P-367). Живые опыты; подъём из копии — на кластере PGINPUT_RESTORE_*:
//
//	go test ./internal/pginput -run R2Rev8 -count=1 -v

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Nikolay1994Kaz/evidencestore/internal/alert"
	"github.com/Nikolay1994Kaz/evidencestore/internal/gateway"
	"github.com/Nikolay1994Kaz/evidencestore/internal/pgtap"
	"github.com/Nikolay1994Kaz/evidencestore/internal/pgwire"
)

// restoreRig — обзорный стенд на кластере для подъёма из копии.
func restoreRig(t *testing.T) (*reviewRig, string) {
	t.Helper()
	dsn, data := os.Getenv("PGINPUT_RESTORE_DSN"), os.Getenv("PGINPUT_RESTORE_DATA")
	if dsn == "" || data == "" {
		t.Skip("PGINPUT_RESTORE_DSN and PGINPUT_RESTORE_DATA are not set")
	}
	t.Setenv("PGINPUT_TEST_DSN", dsn)
	return newReviewRig(t), data
}

// skewedAct — действие шлюза, чьи часы впереди часов базы на skew: время в
// квитанции — его (шлюз подписывает своё время).
func skewedAct(r *reviewRig, c *pgwire.Conn, sql string, skew time.Duration) (uint32, string) {
	r.t.Helper()
	g := r.gw
	if _, err := c.Query("BEGIN; " + sql); err != nil {
		c.Query("ROLLBACK")
		r.t.Fatalf("%s: %v", sql, err)
	}
	row, ok, err := c.QueryRow("SELECT pg_current_xact_id()::xid::text, pg_current_xact_id()::text")
	if err != nil || !ok || row[0] == nil || row[1] == nil {
		r.t.Fatalf("the transaction id: %v", err)
	}
	var xid uint32
	fmt.Sscan(*row[0], &xid)
	g.n++
	id := fmt.Sprintf("%s-%d", g.name, g.n)
	g.append(gateway.Draft{Time: time.Now().Add(skew), Action: id, Step: alert.StepIntent, Refs: []gateway.Ref{{Source: "postgres", Subject: *row[0]}},
		Body: json.RawMessage(`{"agent":"live-bot","tool":"execute","reason":"test","xid8":"` + *row[1] + `"}`)}) // как esmcp: с xid8
	if _, err := c.Query("COMMIT"); err != nil {
		r.t.Fatalf("COMMIT of %s: %v", sql, err)
	}
	return xid, id
}

func countKind(evs []alert.Event, kind string) (n int, details []string) {
	for _, ev := range evs {
		for _, s := range ev.Signals {
			if s.Kind == kind {
				n++
				details = append(details, s.Detail)
			}
		}
	}
	return n, details
}

// R2-1. Граница void — запуск поднятой базы по её часам
// (pg_postmaster_start_time), а намерения сверяются с ней по времени шлюза,
// которое он подписал: часы двух машин сравниваются напрямую. Часы шлюза
// впереди на минуту. Сборщик прочёл прежнюю историю за копией (подъём виден:
// конец журнала ниже его места), последнее действие агента перед подъёмом он
// не успел прочесть. Подъём занял секунды — время в намерении этого действия
// позже запуска поднятой базы, и void его не снимает. Поднятая база выдаёт
// его номер правке человека — та ложится ДЕЙСТВИЕМ агента, целиком, и
// MCP-откат действия откатил бы правку человека. Ожидание: намерения прежней
// истории сняты, правка человека — отпечаток.
func TestR2Rev8GatewayClockAheadOutlivesTheVoid(t *testing.T) {
	r, data := restoreRig(t)
	const skew = time.Minute
	s := r.open()
	if _, err := s.ReadAll(context.Background()); err != nil {
		t.Fatal(err)
	}
	s.Close()
	pgctl(t, data, "stop")
	shell(t, "rm -rf "+data+".bak && cp -a "+data+" "+data+".bak") // копия
	pgctl(t, data, "start")
	r.admin = r.dial("postgres")
	owner, mcp := r.dial("rv_owner"), r.dial("rv_mcp")
	s = r.open()
	skewedAct(r, mcp, "UPDATE public.rv_acc SET note = 'by the agent after the copy' WHERE id = 1", skew)
	r.xact(owner, "UPDATE public.rv_acc SET note = 'a batch after the copy' WHERE id BETWEEN 100 AND 3000")
	if _, err := s.ReadAll(context.Background()); err != nil {
		t.Fatal(err)
	}
	s.Close()
	// Последнее действие агента — сборщик стоит и его не читает.
	lost, lostID := skewedAct(r, mcp, "UPDATE public.rv_acc SET note = 'by the agent, lost with the restore' WHERE id = 2", skew)
	cursor := r.sink.cursor
	pgctl(t, data, "stop")
	shell(t, "rm -rf "+data+" && cp -a "+data+".bak "+data) // подъём из копии
	pgctl(t, data, "start")
	r.admin = r.dial("postgres")
	owner = r.dial("rv_owner")
	started := r.one(r.admin, "SELECT pg_postmaster_start_time()::text")
	s = r.open() // подъём виден при подключении: конец журнала ниже места
	// Обычная работа поднятой базы: правки человека, пока одна не получит
	// номер потерянного действия агента.
	var human uint32
	for i := 0; i < 20 && human != lost; i++ {
		human = r.xact(owner, fmt.Sprintf("UPDATE public.rv_acc SET note = 'a person after the restore %d' WHERE id = 20", i))
	}
	if human != lost {
		t.Fatalf("no transaction got xid %d after the restore", lost)
	}
	for i := 0; i < 3; i++ {
		s.ReadAll(context.Background())
	}
	rewound, det := countKind(r.alerts(), alert.KindRewound)
	e, found, _ := pgtap.Lookup(r.index(), human)
	t.Logf("cursor %s, restored database started %s; db-rewound %d %q; the person's transaction %d: found %v kind %q action %+v",
		pgwire.LSN(cursor), started, rewound, det, human, found, e.Kind, e.Action)
	if rewound == 0 {
		t.Fatal("the restore was not seen at all: not the case this test is about")
	}
	if found && e.Action != nil && e.Action.ID == lostID {
		t.Errorf("a person's transaction %d after the restore is recorded as the agent's action %s (whole, undoable): the intent of the lost action outlived the void because the gateway's clock is %v ahead", human, lostID, skew)
	}
}

// R2-2. Граница void — последний запуск базы, а не начало её
// новой истории. Поднятую базу перезапустили (настройка, падение) до того,
// как сборщик к ней подключился: запуск теперь позже действия агента,
// сделанного после подъёма, и void снимает его намерение — действие ложится
// отпечатком, откат отказывает. P-359 обещает: «действия шлюза после подъёма
// остаются действиями».
func TestR2Rev8RestartAfterTheRestoreVoidsLiveActions(t *testing.T) {
	r, data := restoreRig(t)
	s := r.open()
	if _, err := s.ReadAll(context.Background()); err != nil {
		t.Fatal(err)
	}
	s.Close()
	pgctl(t, data, "stop")
	shell(t, "rm -rf "+data+".bak && cp -a "+data+" "+data+".bak")
	pgctl(t, data, "start")
	r.admin = r.dial("postgres")
	owner := r.dial("rv_owner")
	s = r.open()
	r.xact(owner, "UPDATE public.rv_acc SET note = 'a batch after the copy' WHERE id BETWEEN 100 AND 3000")
	if _, err := s.ReadAll(context.Background()); err != nil {
		t.Fatal(err)
	}
	s.Close()
	pgctl(t, data, "stop")
	shell(t, "rm -rf "+data+" && cp -a "+data+".bak "+data) // подъём из копии
	pgctl(t, data, "start")
	mcp := r.dial("rv_mcp")
	g := r.gw.act(mcp, "UPDATE public.rv_acc SET note = 'by the agent after the restore' WHERE id = 1")
	time.Sleep(1100 * time.Millisecond)
	pgctl(t, data, "stop") // перезапуск поднятой базы, пока сборщик стоит
	pgctl(t, data, "start")
	r.admin = r.dial("postgres")
	s = r.open()
	for i := 0; i < 3; i++ {
		s.ReadAll(context.Background())
	}
	rewound, det := countKind(r.alerts(), alert.KindRewound)
	e, found, _ := pgtap.Lookup(r.index(), g)
	t.Logf("db-rewound %d %q; the agent's action after the restore, xid %d: found %v kind %q action %v", rewound, det, g, found, e.Kind, e.Action != nil)
	if rewound == 0 {
		t.Fatal("the restore was not seen: not the case this test is about")
	}
	if !found || e.Action == nil {
		t.Errorf("the agent's action %d made after the restore is a fingerprint (%+v): the restart of the restored database moved the void past it, and its undo is refused", g, e)
	}
}

// R2-3 живьём. Оператор очистил справочник (README: «не улика, а удобство»,
// «не ротируется»), потом обычный перезапуск базы: PostgreSQL 16 забывает
// подтверждённое место слота, сервер шлёт заново уже взятое. Ожидание: ни
// db-rewound, ни второй записи; действие агента остаётся действием.
// На деле — ложная db-rewound, void всех намерений, действие агента ложится
// вторым разом отпечатком, и последняя строка справочника о нём —
// отпечаток: esundo и MCP-откат отказывают.
func TestR2Rev8ClearedIndexThenRestartIsARewind(t *testing.T) {
	r, data := restoreRig(t)
	mcp := r.dial("rv_mcp")
	s := r.open()
	a1 := r.gw.act(mcp, "UPDATE public.rv_acc SET note = 'by the agent' WHERE id = 1")
	if _, err := s.ReadAll(context.Background()); err != nil {
		t.Fatal(err)
	}
	if e, _, _ := pgtap.Lookup(r.index(), a1); e.Action == nil {
		t.Fatalf("the agent's action: %+v", e)
	}
	before := len(r.sink.bodies)
	s.Close()                                         // сборщик остановлен на обслуживание
	if err := os.Truncate(r.index(), 0); err != nil { // ': > index.jsonl'
		t.Fatal(err)
	}
	pgctl(t, data, "stop") // обычный перезапуск базы
	pgctl(t, data, "start")
	r.admin = r.dial("postgres")
	s = r.open()
	for i := 0; i < 3; i++ {
		s.ReadAll(context.Background())
	}
	rewound, det := countKind(r.alerts(), alert.KindRewound)
	e, found, err := pgtap.Lookup(r.index(), a1)
	t.Logf("records before %d, after %d; db-rewound %d %q; the agent's action %d: found %v kind %q action %v (%v)",
		before, len(r.sink.bodies), rewound, det, a1, found, e.Kind, e.Action != nil, err)
	if rewound != 0 {
		t.Errorf("a cleared index and a database restart give a false db-rewound (%d), and the gateway's intents are void", rewound)
	}
	if found && e.Kind == pgtap.KindFingerprint {
		t.Errorf("the agent's action %d, taken whole before, now resolves to a fingerprint: esundo and the MCP undo refuse it", a1)
	}
}

// R2-5. slot.json пропал, и слота нет: пропуск назван, слот заведён заново
// (верно). Но knownLost не снят — на следующем же переподключении (обрыв
// связи) тревога slot-unknown: «сдвинут ли слот, пока сборщика не было, не
// сказать» — о слоте, который сборщик сам только что завёл. Ожидание: ни
// одной slot-unknown.
func TestR2Rev8SlotGoneWithoutSlotFileFalseUnknown(t *testing.T) {
	r := newReviewRig(t)
	s := r.open()
	owner := r.dial("rv_owner")
	r.xact(owner, "UPDATE public.rv_acc SET note = 'read' WHERE id = 1")
	if _, err := s.ReadAll(context.Background()); err != nil {
		t.Fatal(err)
	}
	s.Close()
	os.Remove(filepath.Join(r.cfg.Dir, SlotFile))
	// Процесс сервера, отдававший поток, после закрытия соединения уходит не
	// сразу: пока слот занят им, его не удалить (тест так падал).
	for i := 0; r.one(r.admin, "SELECT active::text FROM pg_replication_slots WHERE slot_name = 'rv_slot'") == "true"; i++ {
		if i == 250 {
			t.Fatal("the slot stays active after the collector closed")
		}
		time.Sleep(20 * time.Millisecond)
	}
	r.exec(r.admin, "SELECT pg_drop_replication_slot('rv_slot')")
	s = r.open() // пропуск и новый слот
	r.exec(r.admin, "SELECT pg_terminate_backend(active_pid) FROM pg_replication_slots WHERE slot_name = 'rv_slot' AND active")
	time.Sleep(300 * time.Millisecond)
	for i := 0; i < 3; i++ {
		s.ReadAll(context.Background())
	}
	gaps, _ := countKind(r.alerts(), alert.KindGap)
	unknown, det := countKind(r.alerts(), alert.KindSlotUnknown)
	t.Logf("gap alerts %d, slot-unknown %d %q", gaps, unknown, det)
	if gaps != 1 {
		t.Fatalf("gaps %d", gaps)
	}
	if unknown != 0 {
		t.Errorf("a false slot-unknown after a reconnect: the slot was created by this collector (%s)", strings.Join(det, " | "))
	}
}
