package pginput

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/Nikolay1994Kaz/evidencestore/internal/alert"
	"github.com/Nikolay1994Kaz/evidencestore/internal/config"
	"github.com/Nikolay1994Kaz/evidencestore/internal/metrics"
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

	// Получатель тревог: веб-хук на этой же машине.
	var hookMu sync.Mutex
	var hooked []string
	hook := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var body struct {
			Text string `json:"text"`
		}
		json.NewDecoder(r.Body).Decode(&body)
		hookMu.Lock()
		hooked = append(hooked, body.Text)
		hookMu.Unlock()
	}))
	defer hook.Close()
	// message ждёт сообщение со словом want и отдаёт его; пока ждёт, вход src
	// (если задан) читает базу, как в цикле сборщика.
	message := func(src *Source, want string) string {
		t.Helper()
		for deadline := time.Now().Add(10 * time.Second); ; time.Sleep(10 * time.Millisecond) {
			if src != nil {
				if _, err := src.Read(); err != nil {
					t.Fatal(err)
				}
			}
			hookMu.Lock()
			for _, text := range hooked {
				if strings.Contains(text, want) {
					hookMu.Unlock()
					return text
				}
			}
			n := len(hooked)
			hookMu.Unlock()
			if time.Now().After(deadline) {
				t.Fatalf("no alert with %q among %d delivered", want, n)
			}
		}
	}

	cfg := Config{DSN: base + " user=pgin_tap", Slot: "pgin_slot", Publication: "pgin_pub", Dir: t.TempDir(),
		Roles: []string{"pgin_agent"}, Tables: []string{"public.pgin_accounts"}, RequireAction: true, SlotAlertMB: 4,
		Notify: &Notify{To: []alert.Target{{Type: alert.TypeSlack, URL: hook.URL}}}}
	if err := cfg.Validate(); err != nil {
		t.Fatal(err)
	}
	cfg.DownAfter = config.Duration(200 * time.Millisecond) // в жизни — не меньше секунды
	savedEvery := slotEvery
	slotEvery = 50 * time.Millisecond // в жизни — 10 с
	defer func() { slotEvery = savedEvery }()
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
	// Агент пришёл мимо MCP-сервера (отметки действия нет): тревога дошла до
	// получателя одним сообщением — с ролью, числом строк, номером записи и
	// командой, которой смотрят откат.
	text := message(nil, fmt.Sprintf("agent transaction %d", x1))
	for _, want := range []string{"evidencestore, database live:", "• no-action:", "who: role pgin_agent", "changed: 1 row — public.pgin_accounts (updated 1)",
		"store record: 1", fmt.Sprintf("undo preview: esundo check -config undo.json -xid %d", x1)} {
		if !strings.Contains(text, want) {
			t.Fatalf("the alert lacks %q:\n%s", want, text)
		}
	}
	// MCP-сервер остановил действие пределом строк: отметка об отказе — не
	// транзакционное сообщение, и откат транзакции её не стирает. Сборщик
	// узнаёт о том, чего в базе не случилось.
	// (Откат не сбрасывает журнал базы на диск сразу — это делает её фоновый
	// процесс за доли секунды, — поэтому сообщение приходит чуть погодя.)
	exec(agent, `BEGIN; UPDATE public.pgin_accounts SET note = 'too many'; SELECT evidence.mark_refused('{"action_id":"act-9","agent":"bot","rows":20,"limit":5}'::json); ROLLBACK`)
	if text := message(s, "• refused:"); !strings.Contains(text, "would change 20 rows (the limit for one action is 5)") || !strings.Contains(text, "action: act-9, agent bot") {
		t.Fatalf("refused alert:\n%s", text)
	}
	if one("SELECT count(*) FROM public.pgin_accounts WHERE note = 'too many'") != "0" {
		t.Fatal("the refused action changed rows")
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
	// Связи не было дольше down_after: тревога, и вторая — когда вернулась.
	if text := message(nil, "• db-down:"); !strings.Contains(text, "no connection to the database for") || strings.Contains(text, "undo preview") {
		t.Fatalf("db-down alert:\n%s", text)
	}
	message(nil, "• db-up: the connection to the database is back after")

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
	message(nil, "• gap: replication slot pgin_slot is gone from the server")
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
	exec(admin, "ALTER SYSTEM RESET max_slot_wal_keep_size") // дальше — с пределом кластера
	exec(admin, "SELECT pg_reload_conf()")

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

	// 7. Слот отстаёт при исправном сборщике: долгая открытая транзакция в базе
	// не даёт слоту отпустить журнал, и он копится. Тревога slot-lag — раньше,
	// чем база упрётся в предел; транзакция закрылась — slot-ok. Те же числа —
	// в показателях входа.
	partSize = 0
	s = open()
	readAll(s, 0)
	hookMu.Lock()
	hooked = nil // прежние сообщения — не об этом шаге
	hookMu.Unlock()
	holder := dial(super)
	exec(holder, "BEGIN; INSERT INTO public.pgin_churn VALUES ('a transaction somebody forgot to close')")
	exec(admin, "INSERT INTO public.pgin_churn SELECT repeat(md5(g::text), 30) FROM generate_series(1, 9000) g") // около 10 МБ журнала
	if text := message(s, "• slot-lag:"); !strings.Contains(text, "of its log for slot pgin_slot") || !strings.Contains(text, "[alert threshold 4 MB]") ||
		!strings.Contains(text, "% of the 2.0 GB allowed") ||
		!strings.Contains(text, "a long open transaction on the server") {
		t.Fatalf("slot-lag alert:\n%s", text)
	}
	if st := s.Slot(); st.Retained < 4<<20 || st.Status == "" || st.Status == "lost" {
		t.Fatalf("slot state %+v", st)
	}
	var page strings.Builder
	metrics.Write(&page, s.Metrics())
	for _, want := range []string{"escollect_postgres_connected 1\n", "escollect_postgres_slot_retained_bytes ", "escollect_postgres_slot_lag_bytes ",
		"escollect_postgres_slot_lost 0\n", "escollect_postgres_slot_checked_timestamp_seconds ", `escollect_alerts_waiting{target="slack"} `,
		`escollect_alerts_target_failing{target="slack"} 0`, "escollect_postgres_transactions_captured_total "} {
		if !strings.Contains(page.String(), want) {
			t.Fatalf("the metrics lack %q:\n%s", want, page.String())
		}
	}
	exec(holder, "COMMIT")
	// Слот отпускает журнал, когда база запишет в него список открытых
	// транзакций (это делает и CHECKPOINT), а сборщик подтвердит позицию.
	deadline = time.Now().Add(30 * time.Second)
	for {
		exec(admin, "CHECKPOINT")
		if _, err := s.Read(); err != nil {
			t.Fatal(err)
		}
		hookMu.Lock()
		ok := slices.ContainsFunc(hooked, func(text string) bool { return strings.Contains(text, "• slot-ok:") })
		hookMu.Unlock()
		if ok {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("no slot-ok after the long transaction ended; the slot: %+v", s.Slot())
		}
		s.Wait(ctx, 100*time.Millisecond)
	}
	if st := s.Slot(); st.Retained >= 4<<20 {
		t.Fatalf("slot state after it was released: %+v", st)
	}
	s.Close()

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
