package pginput

// База поднята из копии (снимок тома, холодная копия, переход на отставшую
// реплику): счётчик xid идёт назад, и номера, которые шлюз назвал в
// намерениях, получают чужие транзакции; журнал базы — позади места
// сборщика (R2-1, R2-2, T-7; проверка R2 цикла 23.11).
//
// Запуск — на отдельном кластере, который тест останавливает и
// восстанавливает из копии каталога (общий не трогается); порт — 55452:
//
//	PGINPUT_RESTORE_DSN="host=/path/sock port=55452 dbname=live" PGINPUT_RESTORE_DATA=/path/data \
//	go test ./internal/pginput -run TestLiveRestored -v

import (
	"context"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/Nikolay1994Kaz/evidencestore/internal/alert"
	"github.com/Nikolay1994Kaz/evidencestore/internal/pgtap"
	"github.com/Nikolay1994Kaz/evidencestore/internal/pgundo"
)

func pgctl(t *testing.T, data string, args ...string) {
	t.Helper()
	sock := strings.TrimSuffix(data, "/data") + "/sock"
	base := []string{"-u", "postgres", "--", "/usr/lib/postgresql/16/bin/pg_ctl", "-D", data, "-w"}
	if args[0] == "start" {
		base = append(base, "-l", strings.TrimSuffix(data, "/data")+"/log", "-o",
			"-c wal_level=logical -c port=55452 -c unix_socket_directories="+sock+" -c listen_addresses='' -c max_replication_slots=10 -c max_wal_senders=10 -c autovacuum=off")
	}
	if args[0] == "stop" {
		base = append(base, "-m", "fast")
	}
	if out, err := exec.Command("runuser", append(base, args...)...).CombinedOutput(); err != nil {
		t.Fatalf("pg_ctl %v: %v\n%s", args, err, out)
	}
}

func shell(t *testing.T, script string) {
	t.Helper()
	if out, err := exec.Command("bash", "-c", script).CombinedOutput(); err != nil {
		t.Fatalf("%s: %v\n%s", script, err, out)
	}
}

// Журнал после подъёма уходит дальше места сборщика раньше, чем он
// подключится (без новых xid), — по месту журнала подъём не виден, а
// транзакция человека получает номер действия агента. Сборщик брал её
// целиком как действие агента, а MCP-откат этого действия проходил сверку
// plan.Action и откатывал правку человека. Теперь намерение решает одну
// транзакцию (ReceiptsSpent): вторая с тем же номером — отпечаток и
// not-via-gateway, а откат её не берёт.
func TestLiveRestoredDatabase(t *testing.T) {
	dsn, data := os.Getenv("PGINPUT_RESTORE_DSN"), os.Getenv("PGINPUT_RESTORE_DATA")
	if dsn == "" || data == "" {
		t.Skip("PGINPUT_RESTORE_DSN and PGINPUT_RESTORE_DATA are not set")
	}
	t.Setenv("PGINPUT_TEST_DSN", dsn)
	r := newReviewRig(t) // require_gateway = true
	s := r.open()        // слот заведён
	if _, err := s.ReadAll(context.Background()); err != nil {
		t.Fatal(err)
	}
	// Копия базы (холодная: снимок тома).
	s.Close()
	pgctl(t, data, "stop")
	shell(t, "rm -rf "+data+".bak && cp -a "+data+" "+data+".bak")
	pgctl(t, data, "start")
	r.admin = r.dial("postgres")
	mcp, owner := r.dial("rv_mcp"), r.dial("rv_owner")
	s = r.open()
	// Действие агента через шлюз: намерение до COMMIT, транзакция целиком.
	xAgent := r.gw.act(mcp, "UPDATE public.rv_acc SET note = 'by the agent' WHERE id = 1")
	if _, err := s.ReadAll(context.Background()); err != nil {
		t.Fatal(err)
	}
	ea, _, _ := pgtap.Lookup(r.index(), xAgent)
	if ea.Action == nil || ea.Action.ID != "esmcp-1" {
		t.Fatalf("the agent's action: %+v", ea)
	}
	cursor := r.sink.cursor
	// База восстановлена из копии.
	s.Close()
	pgctl(t, data, "stop")
	shell(t, "rm -rf "+data+" && cp -a "+data+".bak "+data)
	pgctl(t, data, "start")
	r.admin = r.dial("postgres")
	owner = r.dial("rv_owner")
	// Журнал после подъёма уходит дальше места сборщика (обычная работа базы;
	// здесь — без новых xid: переключение сегмента и сообщения без транзакции).
	for i := 0; i < 50 && r.lsn() <= cursor; i++ {
		r.exec(r.admin, "SELECT pg_logical_emit_message(false, 'pad', repeat('x', 1000000))")
		r.exec(r.admin, "SELECT pg_switch_wal()")
	}
	// Человек, владелец таблиц, мимо шлюза — его транзакция получает тот же xid.
	xHuman := r.xact(owner, "UPDATE public.rv_acc SET note = 'by a person, not through the gateway' WHERE id = 2")
	t.Logf("agent's xid %d, the person's xid after the restore %d", xAgent, xHuman)
	if xHuman != xAgent {
		t.Skipf("the xid was not taken again (%d, %d)", xAgent, xHuman)
	}
	s = r.open()
	for i := 0; i < 30; i++ {
		if _, err := s.ReadAll(context.Background()); err != nil {
			t.Fatal(err)
		}
		if e, ok, _ := pgtap.Lookup(r.index(), xHuman); ok && e.LastSeq > ea.LastSeq {
			break
		}
		time.Sleep(300 * time.Millisecond)
	}
	eh, _, _ := pgtap.Lookup(r.index(), xHuman)
	var notVia bool
	for _, ev := range r.alerts() {
		if ev.XID == xHuman && strings.Contains(strings.Join(ev.Kinds(), ","), "not-via-gateway") {
			notVia = true
		}
	}
	t.Logf("the person's transaction in the index: kind=%q action=%+v seq %d-%d; not-via-gateway alert: %v", eh.Kind, eh.Action, eh.FirstSeq, eh.LastSeq, notVia)
	if eh.LastSeq <= ea.LastSeq {
		t.Fatalf("the person's transaction did not reach the collector: %+v", eh)
	}
	if eh.Kind != pgtap.KindFingerprint || eh.Action != nil || !notVia {
		t.Fatalf("a person's transaction past the gateway went in as %q, action %+v, not-via-gateway %v (require_gateway is on)", eh.Kind, eh.Action, notVia)
	}
	// Откат действия esmcp-1 по записям xid берёт только транзакцию агента:
	// пачка отпечатков — отказ, правка человека не трогается.
	var lines [][]byte
	lines = append(lines, r.sink.bodies[ea.FirstSeq-1:ea.LastSeq]...)
	lines = append(lines, r.sink.bodies[eh.FirstSeq-1:eh.LastSeq]...)
	if _, err := pgundo.Build(xAgent, lines); err == nil || !strings.Contains(err.Error(), "pack of fingerprints") {
		t.Fatalf("the undo with the person's fingerprint: %v", err)
	}
	plan, err := pgundo.Build(xAgent, r.sink.bodies[ea.FirstSeq-1:ea.LastSeq])
	if err != nil {
		t.Fatal(err)
	}
	if plan.Action == nil || plan.Action.ID != "esmcp-1" || len(plan.Steps) != 1 || plan.Steps[0].Old == nil || plan.Steps[0].Old[0] == nil || *plan.Steps[0].Old[0] != "1" {
		t.Fatalf("the undo of esmcp-1: %+v", plan)
	}
}

// lsn — позиция журнала базы числом.
func (r *reviewRig) lsn() uint64 {
	r.t.Helper()
	var hi, lo uint64
	v := r.one(r.admin, "SELECT pg_current_wal_lsn()::text")
	h, l, _ := strings.Cut(v, "/")
	for _, c := range h {
		hi = hi*16 + uint64(hexval(c))
	}
	for _, c := range l {
		lo = lo*16 + uint64(hexval(c))
	}
	return hi<<32 | lo
}

func hexval(c rune) int {
	switch {
	case c >= '0' && c <= '9':
		return int(c - '0')
	case c >= 'A' && c <= 'F':
		return int(c-'A') + 10
	case c >= 'a' && c <= 'f':
		return int(c-'a') + 10
	}
	return 0
}

// Тот же подъём из копии, но журнал после него ещё не дошёл до места
// сборщика (обычный случай: копия отстала на минуты). Каждая транзакция,
// зафиксированная ниже прежнего места, пропускалась — сервер не слал её с
// места cursor+1, а pgtap считал повтором; ни записи, ни отпечатка, ни
// тревоги. Теперь подъём виден по концу журнала (IDENTIFY_SYSTEM): тревога
// db-rewound, намерения до неё не в счёт, вход читает от слота.
func TestLiveRestoredDatabaseLosesNoWrites(t *testing.T) {
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
		r.gw.act(mcp, "UPDATE public.rv_acc SET note = 'by the agent' WHERE id = "+strconv.Itoa(i))
	}
	if _, err := s.ReadAll(context.Background()); err != nil {
		t.Fatal(err)
	}
	before := len(r.sink.bodies)
	s.Close()
	pgctl(t, data, "stop")
	shell(t, "rm -rf "+data+" && cp -a "+data+".bak "+data)
	pgctl(t, data, "start")
	r.admin = r.dial("postgres")
	owner := r.dial("rv_owner")
	x := r.xact(owner, "DELETE FROM public.rv_acc WHERE id = 10")
	s = r.open()
	for i := 0; i < 10; i++ {
		s.ReadAll(context.Background())
		time.Sleep(200 * time.Millisecond)
	}
	e, found, _ := pgtap.Lookup(r.index(), x)
	rewound := 0
	for _, ev := range r.alerts() {
		for _, k := range ev.Kinds() {
			if k == alert.KindRewound {
				rewound++
			}
		}
	}
	if len(r.sink.bodies) == before || !found || e.Kind != pgtap.KindFingerprint || e.Action != nil || rewound != 1 {
		t.Fatalf("records before %d, after %d; xid %d in the index: %v %+v; db-rewound alerts %d", before, len(r.sink.bodies), x, found, e, rewound)
	}
	// Перезапуск сборщика: тот же откат второй раз не называется.
	s.Close()
	s = r.open()
	s.ReadAll(context.Background())
	n := 0
	for _, ev := range r.alerts() {
		for _, k := range ev.Kinds() {
			if k == alert.KindRewound {
				n++
			}
		}
	}
	if n != 1 {
		t.Fatalf("db-rewound alerts after a restart: %d", n)
	}
}
