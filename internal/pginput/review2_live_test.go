package pginput

// Регрессия второго захода проверки шагов 2–3 (24.11): тесты R1, R2 и T,
// которые падали на 7643a65 и проходят после исправлений (FINDINGS, P-357…).

// Проверка исправлений шагов 2–3 (R2, второй заход): живые опыты на своей базе.
// PGINPUT_TEST_DSN=… go test ./internal/pginput -run R2Rev -count=1 -v

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/Nikolay1994Kaz/evidencestore/internal/alert"
	"github.com/Nikolay1994Kaz/evidencestore/internal/pgtap"
)

// R2-1. Роль с REPLICATION сдвинула слот совсем немного — ровно за одну свою
// транзакцию, — пока сборщик стоял. Слот жив и держит всё, что было после
// этого места. Ожидание: пропуск за спрятанную транзакцию — и только за неё;
// действие агента и правка человека ПОСЛЕ сдвига приходят (слот их держит).
// На деле сборщик удаляет живой слот и заводит новый с конца журнала: всё,
// что база написала, пока сборщик стоял, пропадает (действие агента — без
// до-образов, без отката).
func TestR2RevSlotMovedLosesEverythingAfter(t *testing.T) {
	r := newReviewRig(t)
	r.exec(r.admin, "DO $$ BEGIN IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname = 'rv_repl') THEN CREATE ROLE rv_repl LOGIN REPLICATION; END IF; END $$")
	repl := r.dial("rv_repl")
	owner, mcp := r.dial("rv_owner"), r.dial("rv_mcp")
	s := r.open()
	r.xact(owner, "UPDATE public.rv_acc SET note = 'before' WHERE id = 1")
	if _, err := s.ReadAll(context.Background()); err != nil {
		t.Fatal(err)
	}
	s.Close()
	hidden := r.xact(owner, "UPDATE public.rv_acc SET note = 'hidden by the advance' WHERE id = 3")
	at := r.one(r.admin, "SELECT pg_current_wal_lsn()::text")
	r.exec(repl, "SELECT pg_replication_slot_advance('rv_slot', '"+at+"')")
	// После сдвига: слот их держит.
	g := r.gw.act(mcp, "UPDATE public.rv_acc SET note = 'by the agent after the advance' WHERE id = 2")
	x := r.xact(owner, "UPDATE public.rv_acc SET note = 'by a person after the advance' WHERE id = 4")
	held := r.one(r.admin, "SELECT confirmed_flush_lsn::text FROM pg_replication_slots WHERE slot_name = 'rv_slot'")
	t.Logf("hidden xid %d, slot advanced to %s (still there, confirmed %s); after it: agent xid %d, person xid %d", hidden, at, held, g, x)
	s = r.open()
	if _, err := s.ReadAll(context.Background()); err != nil {
		t.Fatal(err)
	}
	if len(r.sink.gaps) != 1 {
		t.Fatalf("gaps %q", r.sink.gaps)
	}
	eg, foundG, _ := pgtap.Lookup(r.index(), g)
	ex, foundX, _ := pgtap.Lookup(r.index(), x)
	var kinds []string
	for _, ev := range r.alerts() {
		for _, sig := range ev.Signals {
			if sig.Kind == alert.KindGap {
				kinds = append(kinds, sig.Detail)
			}
		}
	}
	t.Logf("gap alert: %s", strings.Join(kinds, " | "))
	if !foundG || eg.Action == nil {
		t.Errorf("the agent's action after the advance (xid %d) is not in the store: %+v found=%v — the collector dropped a live slot", g, eg, foundG)
	}
	if !foundX {
		t.Errorf("the person's change after the advance (xid %d) is not in the store: %+v — lost with the dropped slot", x, ex)
	}
}

// R2-3. Подъём из копии, журнал которой до подключения сборщика ушёл дальше
// его места — не «без новых xid» (известное), а обычной работой базы: новыми
// транзакциями. Подъём не виден (конец журнала выше места, линия времени и
// кластер те же): (а) транзакция, зафиксированная после подъёма ниже места
// сборщика, пропадает — ни записи, ни отпечатка, ни пропуска, ни тревоги
// (P-345 снова); (б) транзакция человека, получившая номер действия агента,
// которого сборщик не успел прочесть, ложится действием агента (P-344).
func TestR2RevRestoredWALPastCursorByNewTransactions(t *testing.T) {
	dsn, data := os.Getenv("PGINPUT_RESTORE_DSN"), os.Getenv("PGINPUT_RESTORE_DATA")
	if dsn == "" || data == "" {
		t.Skip("PGINPUT_RESTORE_DSN and PGINPUT_RESTORE_DATA are not set")
	}
	t.Setenv("PGINPUT_TEST_DSN", dsn)
	r := newReviewRig(t)
	s := r.open()
	if _, err := s.ReadAll(context.Background()); err != nil {
		t.Fatal(err)
	}
	s.Close()
	pgctl(t, data, "stop")
	shell(t, "rm -rf "+data+".bak && cp -a "+data+" "+data+".bak") // копия
	pgctl(t, data, "start")
	r.admin = r.dial("postgres")
	mcp := r.dial("rv_mcp")
	s = r.open()
	var agent []uint32
	for i := 1; i <= 3; i++ {
		agent = append(agent, r.gw.act(mcp, "UPDATE public.rv_acc SET note = 'by the agent' WHERE id = "+strconv.Itoa(i)))
	}
	if _, err := s.ReadAll(context.Background()); err != nil {
		t.Fatal(err)
	}
	s.Close()
	// Сборщик стоит (или отстал): четвёртое действие агента он не прочёл.
	x4 := r.gw.act(mcp, "UPDATE public.rv_acc SET note = 'by the agent, not read yet' WHERE id = 4")
	cursor := r.sink.cursor
	pgctl(t, data, "stop")
	shell(t, "rm -rf "+data+" && cp -a "+data+".bak "+data) // подъём из копии
	pgctl(t, data, "start")
	r.admin = r.dial("postgres")
	owner := r.dial("rv_owner")
	// Обычная работа после подъёма: правка человека, потом пакетная правка
	// приложения — журнал уходит дальше места сборщика.
	h1 := r.xact(owner, "UPDATE public.rv_acc SET note = 'a person right after the restore' WHERE id = 10")
	h1lsn := r.lsn()
	// И действие агента через шлюз сразу после подъёма: намерение — после него.
	mcp = r.dial("rv_mcp")
	g1 := r.gw.act(mcp, "UPDATE public.rv_acc SET note = 'by the agent right after the restore' WHERE id = 11")
	var others []uint32
	for r.lsn() <= cursor {
		others = append(others, r.xact(owner, "UPDATE public.rv_acc SET note = note || '.' WHERE id BETWEEN 1000 AND 3000"))
	}
	var h4 uint32
	for h4 < x4 {
		h4 = r.xact(owner, "UPDATE public.rv_acc SET note = 'a person, later' WHERE id = 20")
		others = append(others, h4)
	}
	t.Logf("agent xids %v and %d (not read); cursor %X; after the restore: person %d (WAL %X < cursor), batch and later %v, WAL now %X",
		agent, x4, cursor, h1, h1lsn, others, r.lsn())
	s = r.open()
	for i := 0; i < 5; i++ {
		if _, err := s.ReadAll(context.Background()); err != nil {
			t.Fatal(err)
		}
		time.Sleep(200 * time.Millisecond)
	}
	rewound := 0
	for _, ev := range r.alerts() {
		for _, k := range ev.Kinds() {
			if k == alert.KindRewound {
				rewound++
			}
		}
	}
	e1, found1, _ := pgtap.Lookup(r.index(), h1)
	e4, _, _ := pgtap.Lookup(r.index(), x4)
	t.Logf("db-rewound alerts %d, gaps %q; the person's xid %d in the index: %v %+v; xid %d in the index: kind %q action %+v",
		rewound, r.sink.gaps, h1, found1, e1, x4, e4.Kind, e4.Action)
	// Lookup отдаёт последнюю строку справочника с этим xid: прежняя — действие
	// агента до подъёма (тот же номер); у правки человека была бы своя строка.
	idx, _ := os.ReadFile(r.index())
	t.Logf("index lines of xid %d: %d", h1, strings.Count(string(idx), fmt.Sprintf(`"xid":%d,`, h1)))
	if (!found1 || e1.Action != nil) && rewound == 0 && len(r.sink.gaps) == 0 {
		t.Errorf("(а) the person's change after the restore (xid %d) is lost: no record, no fingerprint, no gap, no alert", h1)
	}
	eg1, _, _ := pgtap.Lookup(r.index(), g1)
	t.Logf("the agent's action right after the restore (xid %d, action esmcp-5): the last index line of the xid is action %+v", g1, eg1.Action)
	if eg1.Action == nil || eg1.Action.ID != "esmcp-5" {
		t.Errorf("(в) the agent's action made right after the restore (xid %d) is not in the store: its receipts are, its row images are not (no undo)", g1)
	}
	if h4 == x4 && e4.Action != nil {
		t.Errorf("(б) a person's transaction (xid %d after the restore) went in as the agent's action %s", h4, e4.Action.ID)
	}
}

// R2-1б. Без всякой роли с REPLICATION: slot.json отстал от того, что сборщик
// подтвердил серверу. writeFile — временный файл, fsync, rename, без fsync
// каталога: после пропажи питания последний rename может не дожить, и в
// slot.json остаётся прежняя позиция (так же — каталог сборщика из снимка
// машины). Тогда «слот сдвинул кто-то другой»: пропуск, тревога о роли с
// REPLICATION — и живой слот удалён вместе со всем, что база написала, пока
// сборщик стоял.
func TestR2RevStaleSlotFileDropsTheSlot(t *testing.T) {
	r := newReviewRig(t)
	owner, mcp := r.dial("rv_owner"), r.dial("rv_mcp")
	s := r.open()
	r.xact(owner, "UPDATE public.rv_acc SET note = 'one' WHERE id = 1")
	if _, err := s.ReadAll(context.Background()); err != nil {
		t.Fatal(err)
	}
	old, err := os.ReadFile(filepath.Join(r.cfg.Dir, SlotFile))
	if err != nil {
		t.Fatal(err)
	}
	r.xact(owner, "UPDATE public.rv_acc SET note = 'two' WHERE id = 2")
	if _, err := s.ReadAll(context.Background()); err != nil {
		t.Fatal(err)
	}
	s.Close() // подтвердил серверу последнее место
	// Питание пропало: последний rename slot.json не дожил.
	if err := os.WriteFile(filepath.Join(r.cfg.Dir, SlotFile), old, 0o600); err != nil {
		t.Fatal(err)
	}
	g := r.gw.act(mcp, "UPDATE public.rv_acc SET note = 'by the agent while the collector was down' WHERE id = 5")
	s = r.open()
	if _, err := s.ReadAll(context.Background()); err != nil {
		t.Fatal(err)
	}
	e, found, _ := pgtap.Lookup(r.index(), g)
	t.Logf("gaps %q; the agent's action (xid %d) in the index: %v %+v", r.sink.gaps, g, found, e)
	// slot.json из старой копии каталога от сдвига слота не отличить: пропуск
	// назван, но слот читается дальше, и ничего не потеряно. После пропажи
	// питания такой копии больше нет: переименование slot.json ложится на
	// диск вместе с fsync каталога (R2-1).
	if len(r.sink.gaps) > 1 {
		t.Errorf("gaps %q", r.sink.gaps)
	}
	if !found || e.Action == nil {
		t.Errorf("the agent's action made while the collector was down is lost with the dropped slot")
	}
}

// Держится ли: обычная работа базы без ложных db-rewound и gap — падение базы
// (immediate) с восстановлением, транзакции с synchronous_commit = off перед
// падением, обрыв связи, перезапуск сборщика.
func TestR2RevNoFalseRewindOnCrash(t *testing.T) {
	dsn, data := os.Getenv("PGINPUT_RESTORE_DSN"), os.Getenv("PGINPUT_RESTORE_DATA")
	if dsn == "" || data == "" {
		t.Skip("PGINPUT_RESTORE_DSN and PGINPUT_RESTORE_DATA are not set")
	}
	t.Setenv("PGINPUT_TEST_DSN", dsn)
	r := newReviewRig(t)
	owner, mcp := r.dial("rv_owner"), r.dial("rv_mcp")
	s := r.open()
	for round := 1; round <= 3; round++ {
		r.gw.act(mcp, "UPDATE public.rv_acc SET note = 'agent "+strconv.Itoa(round)+"' WHERE id = 1")
		r.xact(owner, "SET LOCAL synchronous_commit = off; UPDATE public.rv_acc SET note = 'async' WHERE id BETWEEN 1 AND 500")
		if _, err := s.ReadAll(context.Background()); err != nil {
			t.Fatal(err)
		}
		r.xact(owner, "SET LOCAL synchronous_commit = off; UPDATE public.rv_acc SET note = 'async, unread' WHERE id BETWEEN 1 AND 500")
		shell(t, "runuser -u postgres -- /usr/lib/postgresql/16/bin/pg_ctl -D "+data+" -w -m immediate stop")
		pgctl(t, data, "start")
		r.admin = r.dial("postgres")
		owner, mcp = r.dial("rv_owner"), r.dial("rv_mcp")
		g := r.gw.act(mcp, "UPDATE public.rv_acc SET note = 'agent after the crash' WHERE id = 2")
		for i := 0; i < 3; i++ {
			s.ReadAll(context.Background()) // первый — об оборванном соединении
		}
		if e, _, _ := pgtap.Lookup(r.index(), g); e.Action == nil {
			t.Fatalf("round %d: the agent's action after the crash: %+v", round, e)
		}
		if round == 2 {
			s.Close()
			s = r.open()
		}
	}
	for _, ev := range r.alerts() {
		for _, k := range ev.Kinds() {
			if k == alert.KindRewound || k == alert.KindGap {
				t.Errorf("a false %s: %+v", k, ev.Signals)
			}
		}
	}
	if len(r.sink.gaps) != 0 {
		t.Errorf("false gaps %q", r.sink.gaps)
	}
}

// -setup-sql: схема evidence у evidence_owner, а в ней — объект приложения
// того вида, которого проверка «чужих объектов» не видит (она смотрит
// pg_class, pg_proc, pg_type): правило сортировки, словарь поиска, оператор.
func TestR2RevSetupSQLSchemaWithOtherKinds(t *testing.T) {
	r := newReviewRig(t)
	for _, q := range []string{
		"DROP SCHEMA IF EXISTS evidence CASCADE",
		"DO $$ BEGIN IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname = 'evidence_owner') THEN CREATE ROLE evidence_owner NOLOGIN; END IF; END $$",
		"CREATE SCHEMA evidence AUTHORIZATION evidence_owner",
		"CREATE TABLE evidence.marker_key (k text)", "ALTER TABLE evidence.marker_key OWNER TO evidence_owner",
		"CREATE TEXT SEARCH CONFIGURATION evidence.app_search (COPY = pg_catalog.simple)",
		"ALTER TEXT SEARCH CONFIGURATION evidence.app_search OWNER TO rv_owner",
		"CREATE COLLATION evidence.app_ci FROM pg_catalog.\"C\"",
		"ALTER COLLATION evidence.app_ci OWNER TO rv_owner",
	} {
		r.exec(r.admin, q)
	}
	setup, err := SetupSQL(&r.cfg)
	if err != nil {
		t.Fatal(err)
	}
	_, err = r.admin.Query(setup)
	t.Logf("the script: %v", err)
	r.admin.Query("ROLLBACK")
	left := r.one(r.admin, "SELECT count(*)::text FROM pg_ts_config c JOIN pg_namespace n ON n.oid = c.cfgnamespace WHERE n.nspname = 'evidence'") +
		" " + r.one(r.admin, "SELECT count(*)::text FROM pg_collation c JOIN pg_namespace n ON n.oid = c.collnamespace WHERE n.nspname = 'evidence'")
	t.Logf("application objects left in schema evidence (ts config, collation): %s", left)
	if err != nil {
		t.Errorf("the migration fails as a whole on an application object in schema evidence: %v", err)
	}
	r.exec(r.admin, "DROP SCHEMA IF EXISTS evidence CASCADE")
	r.exec(r.admin, "DO $$ BEGIN IF EXISTS (SELECT FROM pg_roles WHERE rolname = 'evidence_owner') THEN DROP OWNED BY evidence_owner; DROP ROLE evidence_owner; END IF; END $$")
}

// R2-8. Подъём из снимка работающей базы (снимок тома — та же копия, что
// после падения). Подъём виден (db-rewound), вход читает от слота. Но место
// слота в снимке PostgreSQL 16 хранит не то, что сборщик подтвердил, а то,
// что было на диске (подтверждение пишется на диск только со сдвигом
// restart_lsn/xmin): сервер шлёт заново транзакции, которые сборщик уже взял
// целиком. Их намерения сняты (void) — они ложатся отпечатком, и последняя
// строка справочника о них — отпечаток: esundo и MCP-откат (pgundo.Fetch по
// справочнику) отказывают «не через шлюз» действию агента, которое в
// поднятой базе есть и было взято целиком.
func TestR2RevRewindBlocksTheUndoOfSurvivingActions(t *testing.T) {
	dsn, data := os.Getenv("PGINPUT_RESTORE_DSN"), os.Getenv("PGINPUT_RESTORE_DATA")
	if dsn == "" || data == "" {
		t.Skip("PGINPUT_RESTORE_DSN and PGINPUT_RESTORE_DATA are not set")
	}
	t.Setenv("PGINPUT_TEST_DSN", dsn)
	r := newReviewRig(t)
	mcp := r.dial("rv_mcp")
	s := r.open()
	a1 := r.gw.act(mcp, "UPDATE public.rv_acc SET note = 'by the agent, kept by the snapshot' WHERE id = 1")
	if _, err := s.ReadAll(context.Background()); err != nil {
		t.Fatal(err)
	}
	e1, _, _ := pgtap.Lookup(r.index(), a1)
	if e1.Action == nil {
		t.Fatalf("the agent's action: %+v", e1)
	}
	slotThen := r.one(r.admin, "SELECT confirmed_flush_lsn::text FROM pg_replication_slots WHERE slot_name = 'rv_slot'")
	// Снимок тома работающей базы: копия, какой её оставляет падение.
	shell(t, "runuser -u postgres -- /usr/lib/postgresql/16/bin/pg_ctl -D "+data+" -w -m immediate stop")
	shell(t, "rm -rf "+data+".bak && cp -a "+data+" "+data+".bak")
	pgctl(t, data, "start")
	r.admin = r.dial("postgres")
	mcp = r.dial("rv_mcp")
	for i := 0; i < 3; i++ {
		s.ReadAll(context.Background())
	}
	r.gw.act(mcp, "UPDATE public.rv_acc SET note = 'by the agent, lost with the restore' WHERE id = 2")
	if _, err := s.ReadAll(context.Background()); err != nil {
		t.Fatal(err)
	}
	// Подъём из снимка.
	s.Close()
	pgctl(t, data, "stop")
	shell(t, "rm -rf "+data+" && cp -a "+data+".bak "+data)
	pgctl(t, data, "start")
	r.admin = r.dial("postgres")
	slotNow := r.one(r.admin, "SELECT confirmed_flush_lsn::text FROM pg_replication_slots WHERE slot_name = 'rv_slot'")
	note := r.one(r.admin, "SELECT note FROM public.rv_acc WHERE id = 1")
	s = r.open()
	for i := 0; i < 5; i++ {
		s.ReadAll(context.Background())
		time.Sleep(200 * time.Millisecond)
	}
	rewound := 0
	for _, ev := range r.alerts() {
		for _, k := range ev.Kinds() {
			if k == alert.KindRewound {
				rewound++
			}
		}
	}
	last, _, _ := pgtap.Lookup(r.index(), a1)
	t.Logf("slot confirmed when the agent's action was read %s, in the restored snapshot %s; the row in the restored database: %q; db-rewound %d; the last index line of xid %d: kind %q action %v",
		slotThen, slotNow, note, rewound, a1, last.Kind, last.Action != nil)
	if rewound == 1 && last.Kind == pgtap.KindFingerprint {
		t.Errorf("the agent's action %d, still in the restored database and taken whole before, now resolves to a fingerprint: esundo and the MCP undo refuse it", a1)
	}
}
