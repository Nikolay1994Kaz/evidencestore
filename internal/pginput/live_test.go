package pginput

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Nikolay1994Kaz/evidencestore/internal/pgtap"
	"github.com/Nikolay1994Kaz/evidencestore/internal/pgwire"
)

// memSink — буфер сборщика в памяти: записи, место, пропуски. onEmit, если
// задан, зовётся после каждой записи в буфер.
type memSink struct {
	bodies [][]byte // nil на месте пропущенного номера
	cursor uint64
	gaps   []string
	onEmit func(records int)
}

func (s *memSink) Next() uint64 { return uint64(len(s.bodies)) + 1 }

func (s *memSink) Emit(bodies [][]byte, cursor uint64) (uint64, error) {
	if s.onEmit != nil {
		defer func() { s.onEmit(len(s.bodies)) }()
	}
	first := s.Next()
	for _, b := range bodies {
		s.bodies = append(s.bodies, bytes.Clone(b))
	}
	s.cursor = cursor
	return first, nil
}

func (s *memSink) Gap(why string) error {
	s.bodies = append(s.bodies, nil)
	s.gaps = append(s.gaps, why)
	return nil
}

// logTo — журнал входа в журнал теста (виден с -v).
type logTo struct{ t *testing.T }

func (l logTo) Write(p []byte) (int, error) {
	l.t.Log(strings.TrimSpace(string(p)))
	return len(p), nil
}

// TestLive гоняет вход на настоящем PostgreSQL (14+, wal_level = logical):
//
//	PGINPUT_TEST_DSN="host=/tmp/pglive/sock port=55440 dbname=live" go test ./internal/pginput/ -run Live -v
//
// В DSN — без пользователя: суперпользователь — PGINPUT_TEST_SUPERUSER
// (по умолчанию postgres), роли теста входят без пароля (trust). Тест заводит
// таблицу, роли и слот с приставкой pgin_ и меняет max_slot_wal_keep_size.
func TestLive(t *testing.T) {
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
	dropSlot := func() {
		t.Helper()
		exec(admin, "SELECT pg_terminate_backend(active_pid) FROM pg_replication_slots WHERE slot_name = 'pgin_slot' AND active")
		for i := 0; one("SELECT 1 FROM pg_replication_slots WHERE slot_name = 'pgin_slot' AND active") != ""; i++ {
			if i > 100 {
				t.Fatal("the slot stays active")
			}
			time.Sleep(20 * time.Millisecond)
		}
		exec(admin, "SELECT pg_drop_replication_slot(slot_name) FROM pg_replication_slots WHERE slot_name = 'pgin_slot'")
	}
	dropSlot()
	exec(admin, "ALTER SYSTEM RESET max_slot_wal_keep_size")
	exec(admin, "SELECT pg_reload_conf()")
	t.Cleanup(func() {
		admin.Query("ALTER SYSTEM RESET max_slot_wal_keep_size")
		admin.Query("SELECT pg_reload_conf()")
	})
	exec(admin, "DROP TABLE IF EXISTS public.pgin_accounts, public.pgin_churn")
	exec(admin, "CREATE TABLE public.pgin_accounts (id int PRIMARY KEY, note text)")
	exec(admin, "CREATE TABLE public.pgin_churn (pad text)")
	exec(admin, "INSERT INTO public.pgin_accounts SELECT g, 'note ' || g FROM generate_series(1, 20) g")

	cfg := Config{DSN: base + " user=pgin_tap", Slot: "pgin_slot", Publication: "pgin_pub", Dir: t.TempDir(),
		Roles: []string{"pgin_agent"}, Tables: []string{"public.pgin_accounts"}}
	if err := cfg.Validate(); err != nil {
		t.Fatal(err)
	}
	setup, err := SetupSQL(&cfg)
	if err != nil {
		t.Fatal(err)
	}
	exec(admin, "SET client_min_messages = warning")
	exec(admin, setup)
	agent := dial("pgin_agent")

	sink := &memSink{}
	partSize := 0
	open := func() *Source {
		t.Helper()
		s, err := New(cfg, slog.New(slog.NewTextHandler(logTo{t}, nil)))
		if err != nil {
			t.Fatal(err)
		}
		s.partSize = partSize
		if err := s.Open(sink.cursor, sink); err != nil {
			t.Fatal(err)
		}
		return s
	}
	// change — агент меняет строку id; возвращает xid транзакции.
	change := func(id int, note string) uint32 {
		t.Helper()
		res, err := agent.Query(fmt.Sprintf("BEGIN; UPDATE public.pgin_accounts SET note = %s WHERE id = %d; SELECT pg_current_xact_id()::text; COMMIT", pgwire.Literal(note), id))
		if err != nil {
			t.Fatal(err)
		}
		var xid uint32
		fmt.Sscan(*res[2].Rows[0][0], &xid)
		return xid
	}
	// last — последняя запись буфера как транзакция: её xid и старое значение note.
	last := func() (uint32, string) {
		t.Helper()
		body := sink.bodies[len(sink.bodies)-1]
		var head struct {
			XID uint32 `json:"xid"`
		}
		if err := json.Unmarshal(body, &head); err != nil {
			t.Fatal(err)
		}
		recs, err := pgtap.ReadTransaction(head.XID, [][]byte{body})
		if err != nil {
			t.Fatal(err)
		}
		for _, r := range recs {
			if r["t"] == "U" {
				return head.XID, r["old"].([]any)[1].(string)
			}
		}
		t.Fatalf("no update in %v", recs)
		return 0, ""
	}
	readAll := func(s *Source, want int) {
		t.Helper()
		n, err := s.ReadAll(ctx)
		if err != nil {
			t.Fatal(err)
		}
		if n != want {
			t.Fatalf("read %d records, expected %d", n, want)
		}
	}

	// 1. Транзакция агента ложится в буфер; транзакция владельца — нет.
	s := open()
	readAll(s, 0) // первое подключение заводит слот: журнал копится с этого места
	x1 := change(1, "one")
	exec(admin, "UPDATE public.pgin_accounts SET note = 'owner' WHERE id = 2")
	readAll(s, 1)
	if xid, old := last(); xid != x1 || old != "note 1" {
		t.Fatalf("got transaction %d with old note %q", xid, old)
	}
	if e, found, err := pgtap.Lookup(filepath.Join(cfg.Dir, pgtap.IndexFile), x1); err != nil || !found || e.FirstSeq != 1 || e.LastSeq != 1 || !strings.Contains(string(e.Who), "pgin_agent") {
		t.Fatalf("index: %+v %v %v", e, found, err)
	}
	if st := s.Stats(); st.Captured != 1 || st.Skipped < 1 {
		t.Fatalf("stats %+v", st)
	}

	// 2. База оборвала соединение: вход не останавливается, подключается
	// снова и продолжает с места — без повторов и без потерь.
	exec(admin, "SELECT pg_terminate_backend(active_pid) FROM pg_replication_slots WHERE slot_name = 'pgin_slot'")
	x2 := change(1, "two")
	deadline := time.Now().Add(15 * time.Second)
	for len(sink.bodies) < 2 {
		if _, err := s.Read(); err != nil {
			t.Fatal(err)
		}
		if time.Now().After(deadline) {
			t.Fatal("the input did not come back after the server dropped the connection")
		}
		s.Wait(ctx, 100*time.Millisecond)
	}
	if xid, old := last(); xid != x2 || old != "one" {
		t.Fatalf("after the reconnect: transaction %d with old note %q", xid, old)
	}

	// 3. Перезапуск сборщика: новый вход с местом из буфера.
	s.Close()
	x3 := change(1, "three")
	s = open()
	readAll(s, 1)
	if xid, old := last(); xid != x3 || old != "two" || len(sink.bodies) != 3 {
		t.Fatalf("after the restart: transaction %d, old note %q, %d records", xid, old, len(sink.bodies))
	}

	// 4. Пока сборщик стоял, слот удалили: изменение за это время не вернуть.
	// Вход говорит о потере — пропуск номера — и заводит слот заново.
	s.Close()
	dropSlot()
	change(1, "lost with the slot")
	s = open()
	readAll(s, 0)
	if len(sink.gaps) != 1 || !strings.Contains(sink.gaps[0], "is gone") {
		t.Fatalf("gaps %q", sink.gaps)
	}
	x5 := change(1, "five")
	readAll(s, 1)
	if xid, old := last(); xid != x5 || old != "lost with the slot" {
		t.Fatalf("after the slot came back: transaction %d, old note %q", xid, old)
	}

	// 5. Пока сборщик стоял, база стёрла журнал, который слот не прочитал
	// (max_slot_wal_keep_size): то же — пропуск и новый слот.
	s.Close()
	change(1, "lost with the log")
	exec(admin, "ALTER SYSTEM SET max_slot_wal_keep_size = '1MB'")
	exec(admin, "SELECT pg_reload_conf()")
	for i := 0; one("SELECT wal_status FROM pg_replication_slots WHERE slot_name = 'pgin_slot'") != "lost"; i++ {
		if i > 20 {
			t.Fatalf("the slot is still %s", one("SELECT wal_status FROM pg_replication_slots WHERE slot_name = 'pgin_slot'"))
		}
		exec(admin, "INSERT INTO public.pgin_churn SELECT repeat('x', 1000) FROM generate_series(1, 2000)")
		exec(admin, "SELECT pg_switch_wal()")
		exec(admin, "CHECKPOINT")
	}
	s = open()
	readAll(s, 0)
	if len(sink.gaps) != 2 || !strings.Contains(sink.gaps[1], "max_slot_wal_keep_size") {
		t.Fatalf("gaps %q", sink.gaps)
	}
	if status := one("SELECT wal_status FROM pg_replication_slots WHERE slot_name = 'pgin_slot'"); status == "lost" || status == "" {
		t.Fatalf("the new slot is %q", status)
	}
	x7 := change(1, "seven")
	readAll(s, 1)
	if xid, old := last(); xid != x7 || old != "lost with the log" {
		t.Fatalf("after the log was lost: transaction %d, old note %q", xid, old)
	}
	s.Close()

	// 6. Связь оборвалась посреди большой транзакции: её первые части уже в
	// буфере. База присылает транзакцию заново, она ложится целиком под новыми
	// номерами, справочник называет именно их, а читатель, которому по метке
	// xid достались и обрывки, берёт целый набор.
	before := len(sink.bodies)
	partSize = 64 << 10
	s = open()
	readAll(s, 0)
	res, err := agent.Query("BEGIN; UPDATE public.pgin_accounts SET note = (SELECT string_agg(md5(random()::text || g), '') FROM generate_series(1, 30000) g); SELECT pg_current_xact_id()::text; COMMIT")
	if err != nil {
		t.Fatal(err)
	}
	var big uint32
	fmt.Sscan(*res[2].Rows[0][0], &big)
	sink.onEmit = func(records int) {
		if records == before+3 { // три части в буфере: база рвёт соединение
			sink.onEmit = nil
			exec(admin, "SELECT pg_terminate_backend(active_pid) FROM pg_replication_slots WHERE slot_name = 'pgin_slot'")
		}
	}
	deadline = time.Now().Add(60 * time.Second)
	var entry pgtap.IndexEntry
	for {
		if _, err := s.Read(); err != nil {
			t.Fatal(err)
		}
		e, found, err := pgtap.Lookup(filepath.Join(cfg.Dir, pgtap.IndexFile), big)
		if err != nil {
			t.Fatal(err)
		}
		if found && int(e.LastSeq) <= len(sink.bodies) {
			entry = e
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("the big transaction did not arrive whole")
		}
		s.Wait(ctx, 100*time.Millisecond)
	}
	s.Close()
	torn := int(entry.FirstSeq) - 1 - before
	if sink.onEmit != nil || torn < 3 {
		t.Fatalf("the connection did not break inside the transaction: %d torn parts before record %d", torn, entry.FirstSeq)
	}
	t.Logf("transaction %d: %d torn parts, then records %d-%d", big, torn, entry.FirstSeq, entry.LastSeq)
	for name, bodies := range map[string][][]byte{"by the index": sink.bodies[entry.FirstSeq-1 : entry.LastSeq], "by the xid label": sink.bodies[before:]} {
		recs, err := pgtap.ReadTransaction(big, bodies)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if n := recs[len(recs)-1]["changes"]; n != float64(20) {
			t.Fatalf("%s: %v changes", name, n)
		}
	}
	if _, err := pgtap.ReadTransaction(big, sink.bodies[before:before+torn]); err == nil {
		t.Fatal("the torn copy alone was read as a whole transaction")
	}
	sink.bodies = sink.bodies[:before] // для итога ниже

	// Итог в буфере: 1, 2, 3, пропуск, 5, пропуск, 7.
	var shape []string
	for _, b := range sink.bodies {
		if b == nil {
			shape = append(shape, "gap")
		} else {
			shape = append(shape, "tx")
		}
	}
	if got := strings.Join(shape, " "); got != "tx tx tx gap tx gap tx" {
		t.Fatalf("spool: %s", got)
	}
}
