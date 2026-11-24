package pginput

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/Nikolay1994Kaz/evidencestore/internal/pgtap"
	"github.com/Nikolay1994Kaz/evidencestore/internal/pgundo"
	"github.com/Nikolay1994Kaz/evidencestore/internal/pgwire"
)

// TestLiveUndo — путь целиком на настоящем PostgreSQL (14+, wal_level =
// logical): настройка базы скриптом -setup-sql, действие агента, чтение журнала
// базы входом, план отката, сверка, откат, сравнение базы с тем, что было.
// Запуск — как у TestLive: PGINPUT_TEST_DSN, суперпользователь, вход без пароля.
// Всё своё тест держит в схеме pgu, роли и слот — с приставкой pgu_.
//
// Что здесь проверено и чего нет в стенде из трёх таблиц: каскады внешних
// ключей, секционированная таблица, колонки без оператора равенства,
// генерируемые колонки и колонка-номер, триггер, который переписывает строку
// при правке, строки, которые сослались на вставленную после транзакции.
func TestLiveUndo(t *testing.T) {
	base := os.Getenv("PGINPUT_TEST_DSN")
	if base == "" {
		t.Skip("PGINPUT_TEST_DSN is not set")
	}
	super := os.Getenv("PGINPUT_TEST_SUPERUSER")
	if super == "" {
		super = "postgres"
	}
	ctx := context.Background()
	dial := func(user string) *pgwire.Conn {
		t.Helper()
		cfg, err := pgwire.ParseDSN(base + " user=" + user)
		if err != nil {
			t.Fatal(err)
		}
		c, err := pgwire.Dial(ctx, cfg)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { c.Close() })
		return c
	}
	admin := dial(super)
	exec := func(c *pgwire.Conn, sql string) {
		t.Helper()
		if _, err := c.Query(sql); err != nil {
			t.Fatalf("%s: %v", sql, err)
		}
	}
	one := func(sql string) string {
		t.Helper()
		row, ok, err := admin.QueryRow(sql)
		if err != nil {
			t.Fatalf("%s: %v", sql, err)
		}
		if !ok || row[0] == nil {
			return ""
		}
		return *row[0]
	}

	// Следы прошлого прогона.
	exec(admin, "SELECT pg_terminate_backend(active_pid) FROM pg_replication_slots WHERE slot_name = 'pgu_slot' AND active")
	for i := 0; one("SELECT 1 FROM pg_replication_slots WHERE slot_name = 'pgu_slot' AND active") != ""; i++ {
		if i > 100 {
			t.Fatal("the slot stays active")
		}
		time.Sleep(20 * time.Millisecond)
	}
	exec(admin, "SELECT pg_drop_replication_slot(slot_name) FROM pg_replication_slots WHERE slot_name = 'pgu_slot'")
	exec(admin, "SET client_min_messages = warning")
	exec(admin, "DROP PUBLICATION IF EXISTS pgu_pub")
	exec(admin, "DROP SCHEMA IF EXISTS pgu CASCADE")
	exec(admin, `CREATE SCHEMA pgu;
CREATE TABLE pgu.parent (id int PRIMARY KEY, name text);
-- Дети: каскад на удаление и на смену ключа; триггер переписывает touched при каждой правке.
CREATE TABLE pgu.child (id int PRIMARY KEY, parent_id int NOT NULL REFERENCES pgu.parent ON UPDATE CASCADE ON DELETE CASCADE,
  note text, touched timestamptz NOT NULL DEFAULT '2026-01-01 00:00:00+00');
CREATE FUNCTION pgu.touch() RETURNS trigger LANGUAGE plpgsql AS $f$ BEGIN NEW.touched = clock_timestamp(); RETURN NEW; END $f$;
CREATE TRIGGER touch BEFORE UPDATE ON pgu.child FOR EACH ROW EXECUTE FUNCTION pgu.touch();
-- Ссылка, которую удаление родителя обнуляет.
CREATE TABLE pgu.loose (id int PRIMARY KEY, parent_id int REFERENCES pgu.parent ON UPDATE CASCADE ON DELETE SET NULL, note text);
CREATE TABLE pgu.part (id int, day date, amount numeric(8,2), PRIMARY KEY (id, day)) PARTITION BY RANGE (day);
CREATE TABLE pgu.part_1 PARTITION OF pgu.part FOR VALUES FROM ('2026-01-01') TO ('2026-02-01');
CREATE TABLE pgu.part_2 PARTITION OF pgu.part FOR VALUES FROM ('2026-02-01') TO ('2026-03-01');
-- Типы без оператора равенства.
CREATE TABLE pgu.place (id int PRIMARY KEY, spot point, doc json, label text);
CREATE TABLE pgu.calc (id int PRIMARY KEY, a int, twice int GENERATED ALWAYS AS (a * 2) STORED);
-- Номер строки выдаёт база и писать его не даёт: ни вставкой, ни правкой.
CREATE TABLE pgu.ident (id int GENERATED ALWAYS AS IDENTITY PRIMARY KEY, v text);
-- Равенство грубее значения: 'alice' = 'ALICE' у citext (в public, как его
-- обычно ставят: оператор = виден), 1.0 = 1.00 у numeric.
CREATE EXTENSION IF NOT EXISTS citext SCHEMA public;
CREATE TABLE pgu.tag (id int PRIMARY KEY, name public.citext, amount numeric);
INSERT INTO pgu.tag VALUES (1, 'Alice', 1), (2, 'Bob', 2);
INSERT INTO pgu.ident (v) VALUES ('a'), ('b'), ('c');
INSERT INTO pgu.parent SELECT g, 'parent ' || g FROM generate_series(1, 4) g;
INSERT INTO pgu.child (id, parent_id, note) SELECT g * 10 + k, g, 'child ' || k FROM generate_series(1, 4) g, generate_series(0, 1) k;
INSERT INTO pgu.loose SELECT g * 100, g, 'loose ' || g FROM generate_series(1, 4) g;
INSERT INTO pgu.part VALUES (1, '2026-01-05', 10), (2, '2026-01-06', 20), (3, '2026-02-07', 30), (4, '2026-02-08', 40);
INSERT INTO pgu.place VALUES (1, '(1.5,2.5)', '{"a": 1,  "b": [1, 2]}', 'one'), (2, '(3,4)', '{"z": null}', 'two'), (3, NULL, NULL, 'three');
INSERT INTO pgu.calc (id, a) VALUES (1, 5), (2, 7)`)
	version, _ := strconv.Atoi(one("SELECT current_setting('server_version_num')"))

	gw, undoGW := newLiveGateway(t, "esmcp"), newLiveGateway(t, "esundo")
	cfg := Config{DSN: base + " user=pgu_tap", Slot: "pgu_slot", Publication: "pgu_pub", Dir: t.TempDir(), Receipts: liveReceipts(gw, undoGW),
		MCPRoles: []string{"pgu_agent"}, Roles: []string{"pgu_ai"}, Tables: []string{"pgu.parent", "pgu.child", "pgu.loose", "pgu.part", "pgu.place", "pgu.calc", "pgu.ident", "pgu.tag"}}
	if err := cfg.Validate(); err != nil {
		t.Fatal(err)
	}

	// Таблица с виртуальной генерируемой колонкой (PostgreSQL 18+): скрипт
	// отказывает, называет колонку и не оставляет в базе ничего. Раньше он
	// проходил, и таблица переставала принимать UPDATE и DELETE.
	if version >= 180000 {
		exec(admin, "CREATE TABLE pgu.virt (id int PRIMARY KEY, a int, twice int GENERATED ALWAYS AS (a * 2) VIRTUAL); INSERT INTO pgu.virt (id, a) VALUES (1, 1)")
		with := cfg
		with.Tables = append(slices.Clone(cfg.Tables), "pgu.virt")
		script, err := SetupSQL(&with)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := admin.Query(script); err == nil || !strings.Contains(err.Error(), "a virtual generated column: pgu.virt.twice") {
			t.Fatalf("the setup script took a table with a virtual generated column: %v", err)
		}
		exec(admin, "ROLLBACK")
		if one("SELECT count(*) FROM pg_publication WHERE pubname = 'pgu_pub'") != "0" || one("SELECT relreplident FROM pg_class WHERE oid = 'pgu.parent'::regclass") != "d" {
			t.Fatal("the refused setup script left changes in the database")
		}
		exec(admin, "UPDATE pgu.virt SET a = a + 1; DELETE FROM pgu.virt")
	}

	script, err := SetupSQL(&cfg)
	if err != nil {
		t.Fatal(err)
	}
	// Старая установка (до п. 39): у роли агента — запись и на секциях. Скрипт
	// переводит её, а не отказывает: права на секции снимаются до проверок (R2-4).
	exec(admin, "DO $$BEGIN IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname = 'pgu_ai') THEN CREATE ROLE pgu_ai LOGIN; END IF; END$$; "+
		"GRANT USAGE ON SCHEMA pgu TO pgu_ai; GRANT INSERT, UPDATE, DELETE ON pgu.part, pgu.part_1, pgu.part_2 TO pgu_ai")
	exec(admin, script)
	if got := one("SELECT string_agg(c.relname || ':' || has_table_privilege('pgu_ai', c.oid, 'SELECT') || ':' || has_table_privilege('pgu_ai', c.oid, 'UPDATE'), ' ' ORDER BY c.relname) " +
		"FROM pg_class c WHERE c.relname IN ('part', 'part_1', 'part_2') AND c.relnamespace = 'pgu'::regnamespace"); got != "part:true:false part_1:true:false part_2:true:false" {
		t.Fatalf("the rights of the agent on the partitions after the old setup: %s", got)
	}
	// Секциям — то же, что таблице: старая строка целиком, права сервера;
	// триггеров нет ни на ком (п. 42).
	if got := one("SELECT string_agg(c.relname || ':' || c.relreplident::text || ':' || (SELECT count(*) FROM pg_trigger g WHERE g.tgrelid = c.oid AND NOT g.tgisinternal) " +
		"|| ':' || has_table_privilege('pgu_agent', c.oid, 'UPDATE'), ' ' ORDER BY c.relname) FROM pg_class c WHERE c.relname IN ('part_1', 'part_2')"); got != "part_1:f:0:true part_2:f:0:true" {
		t.Fatalf("partitions after the setup: %s", got)
	}
	agent := dial("pgu_agent")

	sink := &memSink{}
	open := func() *Source {
		t.Helper()
		s, err := New(cfg, slog.New(slog.NewTextHandler(logTo{t}, nil)))
		if err != nil {
			t.Fatal(err)
		}
		if err := s.Open(sink.cursor, sink); err != nil {
			t.Fatal(err)
		}
		return s
	}
	s := open()
	defer func() { s.Close() }()
	read := func() {
		t.Helper()
		if _, err := s.ReadAll(ctx); err != nil {
			t.Fatal(err)
		}
	}
	read() // первое подключение заводит слот: журнал копится с этого места

	// act — действие шлюза одной транзакцией (намерение — до COMMIT); отдаёт
	// её номер.
	act := func(sql string) uint32 {
		t.Helper()
		return gw.act(agent, sql)
	}
	// plan — план отката транзакции по записям, которые вход положил в буфер.
	plan := func(xid uint32) (*pgundo.Plan, error) {
		t.Helper()
		read()
		e, found, err := pgtap.Lookup(filepath.Join(cfg.Dir, pgtap.IndexFile), xid)
		if err != nil || !found {
			t.Fatalf("transaction %d is not in the index: %v", xid, err)
		}
		return pgundo.Build(xid, sink.bodies[e.FirstSeq-1:e.LastSeq])
	}
	// undo — сверка и откат от имени владельца; конфликтов быть не должно.
	undo := func(xid uint32) (*pgundo.Plan, *pgundo.Applied) {
		t.Helper()
		p, err := plan(xid)
		if err != nil {
			t.Fatal(err)
		}
		statuses, err := p.Check(admin)
		if err != nil {
			t.Fatal(err)
		}
		if ok, _, bad := pgundo.Tally(statuses); ok != len(p.Steps) || bad != 0 {
			t.Fatalf("check: %d of %d steps to apply, %d conflicts", ok, len(p.Steps), bad)
		}
		done, err := p.Apply(admin, undoGW.undo(xid))
		if err != nil {
			t.Fatal(err)
		}
		return p, done
	}
	// state — вся схема текстом. touched у детей — отдельно: его переписывает триггер.
	dump := func(query string) string {
		return query + "\n" + one("SELECT coalesce(string_agg(x::text, E'\\n' ORDER BY x::text), '') FROM ("+query+") x") + "\n"
	}
	state := func(touched bool) string {
		out := dump("SELECT * FROM pgu.parent") + dump("SELECT id, parent_id, note FROM pgu.child") + dump("SELECT * FROM pgu.loose") +
			dump("SELECT tableoid::regclass, * FROM pgu.part") + dump("SELECT * FROM pgu.place") + dump("SELECT * FROM pgu.calc") + dump("SELECT * FROM pgu.ident") + dump("SELECT * FROM pgu.tag")
		if touched {
			out += dump("SELECT id, touched FROM pgu.child")
		}
		return out
	}
	// roundTrip — действие и его откат; база после отката равна базе до действия.
	roundTrip := func(name, sql string, touched bool) (*pgundo.Plan, *pgundo.Applied) {
		t.Helper()
		before := state(touched)
		xid := act(sql)
		if state(touched) == before {
			t.Fatalf("%s: the action changed nothing", name)
		}
		p, done := undo(xid)
		if after := state(touched); after != before {
			t.Fatalf("%s: the database after the undo is not what it was\nbefore:\n%s\nafter:\n%s", name, before, after)
		}
		t.Logf("%s: %d row changes, %d steps, order %s, differs %v", name, p.Changes, done.Steps, done.Order, done.Differ)
		return p, done
	}
	differs := func(done *pgundo.Applied) string {
		var parts []string
		for _, d := range done.Differ {
			parts = append(parts, fmt.Sprintf("%s.%s:%d", d.Table, d.Column, d.Rows))
		}
		return strings.Join(parts, " ")
	}

	// 1. Удаление родителя: каскад удаляет детей и обнуляет ссылку. В журнале
	// родитель раньше, и порядок, обратный журналу, база отвергает: откат идёт
	// по внешним ключам. Вернувшиеся строки триггер правки не задевает.
	p, done := roundTrip("cascade on delete", "DELETE FROM pgu.parent WHERE id = 1", true)
	if p.Changes != 4 || done.Order != pgundo.OrderKeys || done.Steps != 4 || done.Differ != nil {
		t.Fatalf("cascade on delete: %d changes, %+v", p.Changes, done)
	}
	// Откат — тоже действие: по намерению esundo сборщик взял его транзакцию
	// целиком (п. 42). Первая попытка в порядке журнала отменена, её намерение
	// — о транзакции, которой в журнале нет.
	read()
	undoXID, _ := strconv.ParseUint(done.XID, 10, 32)
	if e, found, err := pgtap.Lookup(filepath.Join(cfg.Dir, pgtap.IndexFile), uint32(undoXID)); err != nil || !found || e.Kind != "" ||
		e.Action == nil || e.Action.Gateway != "esundo" || e.Action.Step != "undo" {
		t.Fatalf("the undo transaction %s in the index: %+v %v %v", done.XID, e, found, err)
	}

	// 2. Смена ключа родителя: каскад переписывает ссылки, а агент ещё и правит
	// детей. Родитель откатывается первым, его каскад возвращает ссылки, свои
	// правки детям возвращает их шаг. touched переписал триггер — откат это называет.
	p, done = roundTrip("cascade on update", "UPDATE pgu.parent SET id = 200, name = 'renumbered' WHERE id = 2; UPDATE pgu.child SET note = 'agent' WHERE parent_id = 200", false)
	if done.Order != pgundo.OrderKeys || differs(done) != "pgu.child.touched:2" {
		t.Fatalf("cascade on update: %+v", done)
	}

	// 3. Правка без каскадов идёт в порядке журнала; триггер и тут переписывает touched.
	_, done = roundTrip("a trigger rewrites the row", "UPDATE pgu.child SET note = 'x' WHERE id = 30", false)
	if done.Order != pgundo.OrderJournal || differs(done) != "pgu.child.touched:1" {
		t.Fatalf("a trigger rewrites the row: %+v", done)
	}

	// 4. Секционированная таблица: в журнале — имена секций, старые строки на месте.
	p, done = roundTrip("a partitioned table", "UPDATE pgu.part SET amount = amount + 1 WHERE id IN (1, 3); DELETE FROM pgu.part WHERE id = 2", true)
	if p.Tables["pgu.part_1"] == nil || p.Tables["pgu.part_2"] == nil || done.Order != pgundo.OrderJournal || done.Differ != nil {
		t.Fatalf("a partitioned table: tables %v, %+v", p.Tables, done)
	}
	// Агент пишет прямо в секцию: отметку «кто» ставит её собственный триггер.
	roundTrip("straight into a partition", "UPDATE pgu.part_1 SET amount = 0 WHERE id = 1", true)

	// 5. point и json оператора равенства не имеют: сверяются текстом.
	p, done = roundTrip("types without equality", "UPDATE pgu.place SET label = 'moved' WHERE id IN (1, 3); DELETE FROM pgu.place WHERE id = 2", true)
	if fmt.Sprint(p.Tables["pgu.place"].AsText) != "[spot doc]" || done.Differ != nil {
		t.Fatalf("types without equality: as text %v, %+v", p.Tables["pgu.place"].AsText, done)
	}
	// Правка самой такой колонки — тоже: сверка видит, что стало и что было.
	roundTrip("a change of such a column", `UPDATE pgu.place SET spot = '(9,9)', doc = '{"a":1}' WHERE id = 1`, true)

	// 6. Генерируемая колонка: откат её не пишет, база считает сама. До 18-й
	// версии её нет в журнале, с 18-й — есть.
	p, done = roundTrip("a generated column", "UPDATE pgu.calc SET a = a + 10 WHERE id = 1; DELETE FROM pgu.calc WHERE id = 2", true)
	if in := slices.Contains(p.Tables["pgu.calc"].Columns, "twice"); in != (version >= 180000) || in != (len(p.Tables["pgu.calc"].Generated) == 1) || done.Differ != nil {
		t.Fatalf("a generated column: columns %v, generated %v, %+v", p.Tables["pgu.calc"].Columns, p.Tables["pgu.calc"].Generated, done)
	}

	// 7. Между сверкой и откатом строку правит человек: откат не применён вовсе.
	xid := act("UPDATE pgu.loose SET note = 'agent' WHERE id IN (300, 400)")
	raced, err := plan(xid)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := raced.Check(admin); err != nil {
		t.Fatal(err)
	}
	exec(admin, "UPDATE pgu.loose SET note = 'human' WHERE id = 400")
	held := state(true)
	if _, err := raced.Apply(admin, undoGW.undo(xid)); !errors.Is(err, pgundo.ErrChanged) || state(true) != held {
		t.Fatalf("a row changed after the check: %v", err)
	}
	// То же, когда откат идёт по внешним ключам: порядок журнала база отвергает
	// (ссылку возвращать ещё не на кого), а под замок строка ребёнка не встаёт.
	xid = act("UPDATE pgu.parent SET id = 33 WHERE id = 3")
	if raced, err = plan(xid); err != nil {
		t.Fatal(err)
	}
	if _, err := raced.Check(admin); err != nil {
		t.Fatal(err)
	}
	exec(admin, "UPDATE pgu.child SET note = 'human' WHERE id = 30")
	held = state(true)
	if _, err := raced.Apply(admin, undoGW.undo(xid)); !errors.Is(err, pgundo.ErrChanged) || !strings.Contains(err.Error(), "in the order of the journal") || state(true) != held {
		t.Fatalf("a row changed after the check, the order of foreign keys: %v", err)
	}

	// Строки после агента правит человек, и его правка равна правке агента
	// по равенству типа (регистр у citext, шкала у numeric): сверка видит
	// изменение, откат не применён. Раньше сверка шла через =, правка
	// человека считалась строкой, какой её оставил агент, и откат молча её
	// затирал (P-248).
	xid = act("UPDATE pgu.tag SET name = 'alice' WHERE id = 1; UPDATE pgu.tag SET amount = 1.0 WHERE id = 2")
	if raced, err = plan(xid); err != nil {
		t.Fatal(err)
	}
	exec(admin, "UPDATE pgu.tag SET name = 'ALICE' WHERE id = 1; UPDATE pgu.tag SET amount = 1.00 WHERE id = 2")
	statuses, err := raced.Check(admin)
	if err != nil {
		t.Fatal(err)
	}
	if ok, _, bad := pgundo.Tally(statuses); ok != 0 || bad != 2 {
		t.Fatalf("equality coarser than the value: %d steps to apply, %d conflicts: %+v", ok, bad, statuses)
	}
	held = state(true)
	if _, err := raced.Apply(admin, undoGW.undo(xid)); err == nil || state(true) != held ||
		one("SELECT name || ' ' || amount FROM pgu.tag WHERE id = 1") != "ALICE 1" || one("SELECT amount::text FROM pgu.tag WHERE id = 2") != "1.00" {
		t.Fatalf("the undo overwrote the change of a person: %v", err)
	}
	// А сама правка агента в таких колонках откатывается как обычно.
	roundTrip("citext and numeric", "UPDATE pgu.tag SET name = 'BOB', amount = 2.000 WHERE id = 2", true)

	// 8. Секция, созданная после настройки базы: вход говорит о ней при
	// подключении, откат её правки отказан. Скрипт, выполненный заново, это чинит.
	exec(admin, "CREATE TABLE pgu.part_3 PARTITION OF pgu.part FOR VALUES FROM ('2026-03-01') TO ('2026-04-01'); INSERT INTO pgu.part VALUES (9, '2026-03-05', 1)")
	s.Close()
	s = open()
	read()
	said := func() string {
		data, err := os.ReadFile(filepath.Join(cfg.Dir, pgtap.AlertsFile))
		if err != nil {
			t.Fatal(err)
		}
		return string(data)
	}
	if !strings.Contains(said(), "no REPLICA IDENTITY FULL on pgu.part_3:") {
		t.Fatalf("no alert about the new partition:\n%s", said())
	}
	// Обычная таблица, у которой настройку сняли, названа так же.
	exec(admin, "ALTER TABLE pgu.calc REPLICA IDENTITY DEFAULT")
	s.Close()
	s = open()
	read()
	if !strings.Contains(said(), "no REPLICA IDENTITY FULL on pgu.calc, pgu.part_3:") {
		t.Fatalf("no alert about the plain table:\n%s", said())
	}
	xid = act("UPDATE pgu.part SET amount = 2 WHERE id = 9")
	if _, err := plan(xid); !errors.Is(err, pgundo.ErrRefused) || !strings.Contains(err.Error(), "pgu.part_3 is not REPLICA IDENTITY FULL") {
		t.Fatalf("an undo without old rows: %v", err)
	}
	exec(admin, script)
	alerts := strings.Count(said(), "no REPLICA IDENTITY FULL on")
	s.Close()
	s = open()
	roundTrip("the partition after the setup ran again", "UPDATE pgu.part SET amount = 3 WHERE id = 9", true)
	if strings.Count(said(), "no REPLICA IDENTITY FULL on") != alerts {
		t.Fatal("the alert about the partition came again after the setup")
	}

	// 9. Колонка GENERATED ALWAYS AS IDENTITY: правка её не пишет, удалённая строка
	// возвращается со своим прежним номером.
	_, done = roundTrip("an identity column", "UPDATE pgu.ident SET v = 'x' WHERE id = 1; DELETE FROM pgu.ident WHERE id = 2", true)
	if done.Differ != nil {
		t.Fatalf("an identity column: %+v", done)
	}

	// 10. Агент вставил строку, а потом на неё сослались другие: человек добавил
	// ребёнка (ON DELETE CASCADE) и ссылку (ON DELETE SET NULL). Убрать строку —
	// молча удалить одно и обнулить другое. Сверка называет шаг конфликтом и
	// говорит, кто ссылается; откату нечего применять.
	xid = act("INSERT INTO pgu.parent VALUES (50, 'agent')")
	exec(admin, "INSERT INTO pgu.child (id, parent_id, note) VALUES (500, 50, 'human'); INSERT INTO pgu.loose VALUES (5000, 50, 'human')")
	held = state(true)
	referred, err := plan(xid)
	if err != nil {
		t.Fatal(err)
	}
	statuses, err = referred.Check(admin)
	if err != nil {
		t.Fatal(err)
	}
	if len(statuses) != 1 || statuses[0].State != pgundo.StateReferenced || referred.OK != nil ||
		statuses[0].Detail != "1 rows of pgu.child refer to it: ON DELETE CASCADE would delete them; 1 rows of pgu.loose refer to it: ON DELETE SET NULL would clear their reference" {
		t.Fatalf("a row others refer to: %+v", statuses)
	}
	if _, err := referred.Apply(admin, undoGW.undo(xid)); err == nil || state(true) != held {
		t.Fatalf("a row others refer to was removed: %v", err)
	}

	// 11. То же, но сослались между сверкой и откатом: откат проверяет это сам,
	// под замком, прямо перед уборкой. Не убрано ничего.
	xid = act("INSERT INTO pgu.parent VALUES (60, 'agent')")
	if referred, err = plan(xid); err != nil {
		t.Fatal(err)
	}
	if statuses, err = referred.Check(admin); err != nil || statuses[0].State != pgundo.StateOK {
		t.Fatalf("%+v %v", statuses, err)
	}
	exec(admin, "INSERT INTO pgu.child (id, parent_id, note) VALUES (600, 60, 'human')")
	held = state(true)
	if _, err := referred.Apply(admin, undoGW.undo(xid)); !errors.Is(err, pgundo.ErrChanged) || !strings.Contains(err.Error(), "have rows of pgu.child referring to them") || state(true) != held {
		t.Fatalf("a row someone referred to after the check: %v", err)
	}

	// 12. Свои ссылки откату не мешают. Агент вставил родителя и детей одной
	// транзакцией: дети уходят раньше родителя. Агент перенаправил на новую
	// строку чужую ссылку: откат сначала вернёт ссылку, потом уберёт строку.
	p, done = roundTrip("the transaction's own children", "INSERT INTO pgu.parent VALUES (70, 'agent'); INSERT INTO pgu.child (id, parent_id, note) VALUES (700, 70, 'a'), (701, 70, 'b')", true)
	if done.Steps != 3 || done.Differ != nil {
		t.Fatalf("the transaction's own children: %+v", done)
	}
	p, done = roundTrip("a reference the transaction moved", "INSERT INTO pgu.parent VALUES (80, 'agent'); UPDATE pgu.loose SET parent_id = 80 WHERE id = 100", true)
	if p.Changes != 2 || done.Steps != 2 || done.Differ != nil {
		t.Fatalf("a reference the transaction moved: %d changes, %+v", p.Changes, done)
	}
}
