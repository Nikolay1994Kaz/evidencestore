package pginput

// Находки захода 1 по эталону Postgres (FINDINGS, P-299…), на живой базе:
// PGINPUT_TEST_DSN="host=… port=… dbname=…" go test ./internal/pginput -run Review.
// Опыты R1 (R1-1…R1-6), ожидания — исправленные.

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Nikolay1994Kaz/evidencestore/internal/alert"
	"github.com/Nikolay1994Kaz/evidencestore/internal/evidence"
	"github.com/Nikolay1994Kaz/evidencestore/internal/pgtap"
	"github.com/Nikolay1994Kaz/evidencestore/internal/pgwire"
)

// limitSink — memSink с пределом тела записи, как у буфера сборщика
// (collector/input.go, sink.Emit).
type limitSink struct{ memSink }

func (s *limitSink) Emit(bodies [][]byte, cursor uint64) (uint64, error) {
	for _, b := range bodies {
		if len(b) > evidence.MaxBodyLen {
			return 0, fmt.Errorf("collector: an input emitted a record of %d bytes: the store takes %d at most", len(b), evidence.MaxBodyLen)
		}
	}
	return s.memSink.Emit(bodies, cursor)
}

type reviewRig struct {
	t     *testing.T
	admin *pgwire.Conn
	cfg   Config
	sink  *limitSink
	base  string
}

func (r *reviewRig) dial(user string) *pgwire.Conn {
	r.t.Helper()
	cfg, err := pgwire.ParseDSN(r.base + " user=" + user)
	if err != nil {
		r.t.Fatal(err)
	}
	c, err := pgwire.Dial(context.Background(), cfg)
	if err != nil {
		r.t.Fatal(err)
	}
	r.t.Cleanup(func() { c.Close() })
	return c
}

func (r *reviewRig) exec(c *pgwire.Conn, sql string) {
	r.t.Helper()
	if _, err := c.Query(sql); err != nil {
		r.t.Fatalf("%s: %v", sql, err)
	}
}

func (r *reviewRig) one(c *pgwire.Conn, sql string) string {
	r.t.Helper()
	row, ok, err := c.QueryRow(sql)
	if err != nil || !ok || row[0] == nil {
		r.t.Fatalf("%s: %v", sql, err)
	}
	return *row[0]
}

// xact — транзакция соединением c; её xid.
func (r *reviewRig) xact(c *pgwire.Conn, sql string) uint32 {
	r.t.Helper()
	res, err := c.Query("BEGIN; " + sql + "; SELECT pg_current_xact_id()::text; COMMIT")
	if err != nil {
		r.t.Fatalf("%s: %v", sql, err)
	}
	var xid uint32
	fmt.Sscan(*res[len(res)-2].Rows[0][0], &xid)
	return xid
}

func (r *reviewRig) open() *Source {
	r.t.Helper()
	s, err := New(r.cfg, slog.New(slog.NewTextHandler(logTo{r.t}, nil)))
	if err != nil {
		r.t.Fatal(err)
	}
	if err := s.Open(r.sink.cursor, r.sink); err != nil {
		r.t.Fatal(err)
	}
	r.t.Cleanup(func() { s.Close() })
	if _, err := s.ReadAll(context.Background()); err != nil { // слот
		r.t.Fatal(err)
	}
	return s
}

func (r *reviewRig) index() string { return filepath.Join(r.cfg.Dir, pgtap.IndexFile) }

func (r *reviewRig) alerts() []alert.Event {
	data, _ := os.ReadFile(filepath.Join(r.cfg.Dir, pgtap.AlertsFile))
	var out []alert.Event
	for _, l := range strings.Split(strings.TrimSpace(string(data)), "\n") {
		var e alert.Event
		if json.Unmarshal([]byte(l), &e) == nil {
			out = append(out, e)
		}
	}
	return out
}

// newReviewRig: владелец таблиц rv_owner (не суперпользователь), приложение
// rv_app, роль сервера rv_mcp.
func newReviewRig(t *testing.T) *reviewRig {
	base := os.Getenv("PGINPUT_TEST_DSN")
	if base == "" {
		t.Skip("PGINPUT_TEST_DSN is not set")
	}
	r := &reviewRig{t: t, sink: &limitSink{}, base: base}
	r.admin = r.dial("postgres")
	for _, q := range []string{
		"SET client_min_messages = warning",
		"SELECT pg_terminate_backend(active_pid) FROM pg_replication_slots WHERE slot_name = 'rv_slot' AND active",
		"SELECT pg_sleep(0.2)",
		"SELECT pg_drop_replication_slot(slot_name) FROM pg_replication_slots WHERE slot_name = 'rv_slot'",
		"DROP TABLE IF EXISTS public.rv_acc, public.rv_part, public.rv_doc, public.rv_ts",
		// Таблица ключа — заново: её свойства (RLS) не должны доживать с прошлого прогона.
		"DROP TABLE IF EXISTS evidence.marker_key",
		"DO $$ BEGIN IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname = 'rv_owner') THEN CREATE ROLE rv_owner LOGIN; END IF; END $$",
		"DO $$ BEGIN IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname = 'rv_app') THEN CREATE ROLE rv_app LOGIN; END IF; END $$",
		"REVOKE EXECUTE ON FUNCTION pg_catalog.pg_logical_emit_message(boolean, text, text) FROM rv_app",
		"CREATE TABLE public.rv_acc (id int PRIMARY KEY, note text)",
		"INSERT INTO public.rv_acc SELECT g, 'note ' || g FROM generate_series(1, 30000) g",
		"CREATE TABLE public.rv_part (id int PRIMARY KEY, note text) PARTITION BY RANGE (id)",
		"CREATE TABLE public.rv_part_1 PARTITION OF public.rv_part FOR VALUES FROM (0) TO (100)",
		"CREATE TABLE public.rv_doc (id int PRIMARY KEY, note text, big text) PARTITION BY RANGE (id)",
		"CREATE TABLE public.rv_doc_1 PARTITION OF public.rv_doc FOR VALUES FROM (0) TO (100)",
		"CREATE TABLE public.rv_ts (id int PRIMARY KEY, at timestamptz, f float8, b bytea, n numeric, flag bool, code char(4), ip inet, rel regclass, note text, " +
			"twice int GENERATED ALWAYS AS (id * 2) STORED)",
		"INSERT INTO public.rv_ts VALUES (1, '2026-11-23 15:00:00+05', 0.1, '\\x00ff', 1.50, true, 'ab', '10.0.0.1', 'public.rv_acc', 'a&b <c>')",
		"ALTER TABLE public.rv_acc OWNER TO rv_owner", "ALTER TABLE public.rv_part OWNER TO rv_owner",
		"ALTER TABLE public.rv_part_1 OWNER TO rv_owner", "ALTER TABLE public.rv_doc OWNER TO rv_owner",
		"ALTER TABLE public.rv_doc_1 OWNER TO rv_owner", "ALTER TABLE public.rv_ts OWNER TO rv_owner",
		"GRANT USAGE ON SCHEMA public TO rv_owner, rv_app",
		"GRANT SELECT, UPDATE ON public.rv_acc TO rv_app",
	} {
		r.exec(r.admin, q)
	}
	r.cfg = Config{DSN: base + " user=rv_tap", Slot: "rv_slot", Publication: "rv_pub", Dir: t.TempDir(), MCPRoles: []string{"rv_mcp"},
		Tables: []string{"public.rv_acc", "public.rv_part", "public.rv_doc", "public.rv_ts"}, RequireAction: true, AlertRows: 500}
	if err := r.cfg.Validate(); err != nil {
		t.Fatal(err)
	}
	setup, err := SetupSQL(&r.cfg)
	if err != nil {
		t.Fatal(err)
	}
	r.exec(r.admin, setup)
	return r
}

// R1-1, R2-1, T-1: TRUNCATE без отметки «кто» — целиком, с T и тревогами.
func TestReviewTruncateWithoutWho(t *testing.T) {
	r := newReviewRig(t)
	owner := r.dial("rv_owner")
	s := r.open()
	r.exec(r.admin, "CREATE TABLE public.rv_part_2 PARTITION OF public.rv_part FOR VALUES FROM (100) TO (200)") // секция после -setup-sql
	r.exec(r.admin, "ALTER TABLE public.rv_part_2 OWNER TO rv_owner")
	r.xact(owner, "INSERT INTO public.rv_part_2 VALUES (150, 'x')")
	xTrunc := r.xact(owner, "TRUNCATE public.rv_part_2")
	r.exec(owner, "ALTER TABLE public.rv_acc DISABLE TRIGGER evidence_who")
	xMix := r.xact(owner, "TRUNCATE public.rv_acc; INSERT INTO public.rv_acc VALUES (1, 'after truncate')")
	r.exec(owner, "ALTER TABLE public.rv_acc ENABLE TRIGGER evidence_who")
	if _, err := s.ReadAll(context.Background()); err != nil {
		t.Fatal(err)
	}
	for _, x := range []uint32{xTrunc, xMix} {
		e, found, _ := pgtap.Lookup(r.index(), x)
		if !found || e.Kind != "" || len(e.Truncated) != 1 {
			t.Fatalf("TRUNCATE without a who marker, xid %d: %+v %v", x, e, found)
		}
	}
	var kinds []string
	for _, e := range r.alerts() {
		if e.XID == xMix {
			kinds = e.Kinds()
		}
	}
	if k := strings.Join(kinds, ","); !strings.Contains(k, "truncate") || !strings.Contains(k, alert.KindNoWho) {
		t.Fatalf("alerts of xid %d: %s", xMix, k)
	}
}

// R1-2, R2-2, T-2: отпечаток на 30 000 строк — записями не больше предела, и
// вход не встаёт.
func TestReviewBigFingerprint(t *testing.T) {
	r := newReviewRig(t)
	owner := r.dial("rv_owner")
	s := r.open()
	x := r.xact(owner, "UPDATE public.rv_acc SET note = md5(id::text)")
	if _, err := s.ReadAll(context.Background()); err != nil {
		t.Fatalf("xid %d: %v", x, err)
	}
	e, found, _ := pgtap.Lookup(r.index(), x)
	if !found || e.Kind != pgtap.KindFingerprint || e.LastSeq <= e.FirstSeq || e.Changes != 30000 {
		t.Fatalf("the big fingerprint in the index: %+v", e)
	}
	recs, err := pgtap.ReadTransaction(x, r.sink.bodies[e.FirstSeq-1:e.LastSeq])
	if err != nil || recs[0]["fingerprint"] != true || strings.Contains(string(r.sink.bodies[e.FirstSeq-1]), "note 1") {
		t.Fatalf("its records: %v", err)
	}
}

// R1-3, T-3: роль с pg_logical_emit_message называет себя сервером и ставит
// действие — отметки без ключа не решают, чья транзакция.
func TestReviewForgedMarkers(t *testing.T) {
	r := newReviewRig(t)
	r.exec(r.admin, "GRANT EXECUTE ON FUNCTION pg_catalog.pg_logical_emit_message(boolean, text, text) TO rv_app")
	defer r.exec(r.admin, "REVOKE EXECUTE ON FUNCTION pg_catalog.pg_logical_emit_message(boolean, text, text) FROM rv_app")
	app := r.dial("rv_app")
	s := r.open()
	x := r.xact(app, `SELECT pg_logical_emit_message(true, 'evidence/who', '{"role":"rv_mcp","app":"esmcp/bot"}'); `+
		`SELECT pg_logical_emit_message(true, 'evidence/action', '{"role":"rv_mcp","info":{"action_id":"act-77","agent":"bot","tool":"execute"}}'); `+
		`UPDATE public.rv_acc SET note = 'by app' WHERE id = 3`)
	if _, err := s.ReadAll(context.Background()); err != nil {
		t.Fatal(err)
	}
	e, _, _ := pgtap.Lookup(r.index(), x)
	if e.Kind != "" || !strings.Contains(string(e.Who), `"role":"rv_app"`) || len(e.Actions) != 0 {
		t.Fatalf("the forged transaction: %+v", e)
	}
	recs, err := pgtap.ReadTransaction(x, r.sink.bodies[e.FirstSeq-1:e.LastSeq])
	if err != nil || len(recs[0]["forged"].([]any)) != 2 {
		t.Fatalf("the forged markers in the record: %v %v", recs[0], err)
	}
	var kinds []string
	for _, a := range r.alerts() {
		if a.XID == x {
			kinds = a.Kinds()
		}
	}
	if k := strings.Join(kinds, ","); !strings.Contains(k, alert.KindForged) || strings.Contains(k, alert.KindNoAction) {
		t.Fatalf("alerts: %s", k)
	}
	// Ключа нет ни в записи, ни в справочнике.
	key := r.one(r.admin, "SELECT k FROM evidence.marker_key")
	idx, _ := os.ReadFile(r.index())
	for _, b := range append(r.sink.bodies, idx) {
		if strings.Contains(string(b), key) {
			t.Fatal("the marker key went to the store or the index")
		}
	}
}

// R1-4: значение в TOAST без REPLICA IDENTITY FULL — хеша новой строки нет,
// тревога identity.
func TestReviewHashWithoutTheWholeRow(t *testing.T) {
	r := newReviewRig(t)
	owner := r.dial("rv_owner")
	s := r.open()
	r.exec(r.admin, "CREATE TABLE public.rv_doc_2 PARTITION OF public.rv_doc FOR VALUES FROM (100) TO (200)")
	r.exec(r.admin, "ALTER TABLE public.rv_doc_2 OWNER TO rv_owner")
	r.xact(owner, "INSERT INTO public.rv_doc SELECT 150, 'v1', string_agg(md5(random()::text), '') FROM generate_series(1, 2000)")
	x := r.xact(owner, "UPDATE public.rv_doc SET note = 'v2' WHERE id = 150")
	if _, err := s.ReadAll(context.Background()); err != nil {
		t.Fatal(err)
	}
	e, _, _ := pgtap.Lookup(r.index(), x)
	pack, _ := pgtap.ReadPack(r.sink.bodies[e.FirstSeq-1])
	row := pack[len(pack)-1]["rows"].([]any)[0].(map[string]any)
	var kinds []string
	for _, a := range r.alerts() {
		if a.XID == x {
			kinds = a.Kinds()
		}
	}
	if row["n"] != nil || row["partial"] != true || !strings.Contains(strings.Join(kinds, ","), "identity") {
		t.Fatalf("fingerprint %v, alerts %v", row, kinds)
	}
}

// R2-4, T-4, R1-7: хеш строки пересчитывается по рецепту README в любом
// сеансе с теми же настройками вывода, что закрепляет сборщик, — какими бы
// ни были умолчания сервера, базы и роли сборщика.
func TestReviewHashRecipe(t *testing.T) {
	r := newReviewRig(t)
	r.exec(r.admin, "ALTER ROLE rv_tap SET TimeZone = 'Asia/Almaty'; ALTER ROLE rv_tap SET bytea_output = 'escape'")
	defer r.exec(r.admin, "ALTER ROLE rv_tap RESET TimeZone; ALTER ROLE rv_tap RESET bytea_output")
	owner := r.dial("rv_owner")
	s := r.open()
	x := r.xact(owner, "UPDATE public.rv_ts SET note = note || '!' WHERE id = 1")
	if _, err := s.ReadAll(context.Background()); err != nil {
		t.Fatal(err)
	}
	e, _, _ := pgtap.Lookup(r.index(), x)
	pack, _ := pgtap.ReadPack(r.sink.bodies[e.FirstSeq-1])
	row := pack[len(pack)-1]["rows"].([]any)[0].(map[string]any)
	// Рецепт README («Что сборщик берёт и что обещает»): текст — функцией
	// вывода (format), не приведением ::text (bool, char(n), inet — заход 2,
	// R1-4, R2-5); генерируемой колонки до PostgreSQL 18 в журнале нет.
	col := func(c string) string {
		return fmt.Sprintf("CASE WHEN %[1]s IS NULL THEN '-' ELSE octet_length(convert_to(format('%%s', %[1]s), 'UTF8')) || ':' || format('%%s', %[1]s) END", c)
	}
	cols := []string{"id", "at", "f", "b", "n", "flag", "code", "ip", "rel", "note"}
	if r.one(r.admin, "SHOW server_version_num") >= "180000" {
		cols = append(cols, "twice")
	}
	var parts []string
	for _, c := range cols {
		parts = append(parts, col(c))
	}
	recipe := "SET TimeZone = 'UTC'; SET DateStyle = 'ISO, YMD'; SET IntervalStyle = 'postgres'; SET extra_float_digits = 3; SET bytea_output = 'hex'; " +
		"SET search_path = pg_catalog, pg_temp; SELECT rtrim(encode(substr(sha256(convert_to(concat(" + strings.Join(parts, ", ") +
		"), 'UTF8')), 1, 16), 'base64'), '=') FROM public.rv_ts WHERE id = 1"
	human := r.dial("postgres")
	res, err := human.Query(recipe)
	if err != nil {
		t.Fatal(err)
	}
	if got := *res[len(res)-1].Rows[0][0]; row["n"] != got {
		t.Fatalf("the hash of the new row %v, by the recipe %s", row["n"], got)
	}
}

// R1-6, T-6: тревога отпечатка не называет транзакцию агентской и не
// предлагает её откатить.
func TestReviewFingerprintAlertText(t *testing.T) {
	r := newReviewRig(t)
	owner := r.dial("rv_owner")
	s := r.open()
	x := r.xact(owner, "UPDATE public.rv_acc SET note = 'batch' WHERE id <= 600")
	if _, err := s.ReadAll(context.Background()); err != nil {
		t.Fatal(err)
	}
	for _, e := range r.alerts() {
		if e.XID != x {
			continue
		}
		text := alert.Text(e, alert.TextOptions{Title: "database live", UndoHint: "esundo check -xid {xid}"})
		if strings.Contains(text, "agent transaction") || strings.Contains(text, "undo preview") || !strings.Contains(text, "only its fingerprint is kept") {
			t.Fatalf("the alert of a fingerprint:\n%s", text)
		}
		return
	}
	t.Fatalf("no alert of xid %d", x)
}

// Заход 2 (R1-2, R2-1): ключа отметок нет в журнале — роль с REPLICATION
// видит в своём слоте только метки; член pg_read_all_data таблицу ключа не
// читает (RLS). Метку из журнала к своей транзакции не приложить: она — от
// xid. Сообщения outbox — не отметки (R1-3).
func TestReviewMarkerKeyStaysSecret(t *testing.T) {
	r := newReviewRig(t)
	for _, q := range []string{
		"SELECT pg_drop_replication_slot(slot_name) FROM pg_replication_slots WHERE slot_name = 'rv_cdc'",
		"DO $$ BEGIN IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname = 'rv_cdc') THEN CREATE ROLE rv_cdc LOGIN REPLICATION; END IF; END $$",
		"DO $$ BEGIN IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname = 'rv_bi') THEN CREATE ROLE rv_bi LOGIN; END IF; END $$",
		"GRANT pg_read_all_data TO rv_bi",
		"GRANT EXECUTE ON FUNCTION pg_catalog.pg_logical_emit_message(boolean, text, text) TO rv_app",
	} {
		r.exec(r.admin, q)
	}
	t.Cleanup(func() {
		r.admin.Query("SELECT pg_drop_replication_slot('rv_cdc')")
		r.admin.Query("REVOKE EXECUTE ON FUNCTION pg_catalog.pg_logical_emit_message(boolean, text, text) FROM rv_app")
	})
	key := r.one(r.admin, "SELECT k FROM evidence.marker_key")
	if n := r.one(r.dial("rv_bi"), "SELECT count(*) FROM evidence.marker_key"); n != "0" {
		t.Fatalf("a member of pg_read_all_data sees %s rows of the marker key", n)
	}
	cdc := r.dial("rv_cdc")
	r.exec(cdc, "SELECT pg_create_logical_replication_slot('rv_cdc', 'test_decoding')")
	owner := r.dial("rv_owner")
	s := r.open()
	seen := r.xact(owner, "UPDATE public.rv_acc SET note = 'seen' WHERE id = 1")
	log := r.one(cdc, "SELECT string_agg(data, E'\\n') FROM pg_logical_slot_get_changes('rv_cdc', NULL, NULL)")
	if strings.Contains(log, key) {
		t.Fatal("the marker key is in the database log")
	}
	// Метка отметки триггера из журнала — в чужой транзакции.
	i := strings.Index(log, "evidence/who")
	j := strings.Index(log[i:], "content: ")
	genuine := strings.SplitN(log[i+j+len("content: "):], "\n", 2)[0]
	if len(genuine) < 65 || !strings.Contains(genuine, `"rv_owner"`) {
		t.Fatalf("no marked marker in the log: %q", genuine)
	}
	forged := strings.Replace(genuine, `"rv_owner"`, `"rv_mcp"`, 1)
	app := r.dial("rv_app")
	x := r.xact(app, "SELECT pg_logical_emit_message(true, 'evidence/who', "+pgwire.Literal(genuine)+"); SELECT pg_logical_emit_message(true, 'evidence/who', "+
		pgwire.Literal(forged)+"); SELECT pg_logical_emit_message(true, 'outbox.orders', '{\"order\":1}'); UPDATE public.rv_acc SET note = 'by app' WHERE id = 3")
	y := r.xact(app, "SELECT pg_logical_emit_message(true, 'outbox.orders', '{\"order\":2}'); UPDATE public.rv_acc SET note = 'paid' WHERE id = 4")
	if _, err := s.ReadAll(context.Background()); err != nil {
		t.Fatal(err)
	}
	e, _, _ := pgtap.Lookup(r.index(), x)
	if e.Kind != "" || !strings.Contains(string(e.Who), `"role":"rv_app"`) {
		t.Fatalf("a transaction with markers copied from the log of transaction %d: %+v", seen, e)
	}
	ey, _, _ := pgtap.Lookup(r.index(), y)
	for _, a := range r.alerts() {
		if a.XID == y {
			t.Fatalf("an outbox message raised %v", a.Kinds())
		}
	}
	if ey.Kind != pgtap.KindFingerprint {
		t.Fatalf("a transaction of rv_app with an outbox message: %+v", ey)
	}
}

// Заход 2 (R2-1): таблица ключа, заведённая до скрипта не им, — заменяется:
// её ключ мог быть известен тому, кто её завёл.
func TestReviewForeignMarkerKeyIsReplaced(t *testing.T) {
	r := newReviewRig(t)
	r.exec(r.admin, "DROP TABLE evidence.marker_key; CREATE TABLE evidence.marker_key (k text NOT NULL); INSERT INTO evidence.marker_key VALUES ('known-to-the-owner'); "+
		"ALTER TABLE evidence.marker_key OWNER TO rv_owner")
	setup, err := SetupSQL(&r.cfg)
	if err != nil {
		t.Fatal(err)
	}
	r.exec(r.admin, setup)
	if k := r.one(r.admin, "SELECT k FROM evidence.marker_key"); k == "known-to-the-owner" || len(k) != 64 {
		t.Fatalf("the key after the script: %q", k)
	}
	if o := r.one(r.admin, "SELECT relowner::regrole::text FROM pg_class WHERE oid = 'evidence.marker_key'::regclass"); o != EvidenceOwner {
		t.Fatalf("the owner of the key table: %s", o)
	}
}

// Заход 2 (R1-5, R2-8): отметки функций прежней версии (без метки) — тревога
// с объяснением, транзакция целиком, а не тихая потеря роли.
func TestReviewMarkersOfOlderFunctions(t *testing.T) {
	r := newReviewRig(t)
	r.exec(r.admin, `CREATE OR REPLACE FUNCTION evidence.mark_action(info json) RETURNS void LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $f$
BEGIN PERFORM pg_logical_emit_message(true, 'evidence/action', json_build_object('role', session_user, 'info', info)::text); END $f$`)
	mcp := r.dial("rv_mcp")
	s := r.open()
	x := r.xact(mcp, `SELECT evidence.mark_action('{"action_id":"a-1","agent":"bot","tool":"execute"}'); UPDATE public.rv_acc SET note = 'by the server' WHERE id = 8`)
	if _, err := s.ReadAll(context.Background()); err != nil {
		t.Fatal(err)
	}
	e, _, _ := pgtap.Lookup(r.index(), x)
	var detail string
	for _, a := range r.alerts() {
		if a.XID == x {
			for _, sg := range a.Signals {
				if sg.Kind == alert.KindForged {
					detail = sg.Detail
				}
			}
		}
	}
	if e.Kind != "" || !strings.Contains(string(e.Who), `"rv_mcp"`) || len(e.Actions) != 0 || !strings.Contains(detail, "older escollect -setup-sql") {
		t.Fatalf("a transaction marked by older functions: %+v, alert %q", e, detail)
	}
}

// Заход 2 (R1-5, R2-8, T-5): обновление. Транзакция, зафиксированная до
// появления ключа (функции прежней версии, без метки), — как раньше: роль и
// действие верны, тревоги о подделке нет.
func TestReviewUpgradeKeepsOlderMarkers(t *testing.T) {
	r := newReviewRig(t)
	s := r.open()
	s.Close()
	setup, _ := SetupSQL(&r.cfg)
	r.exec(r.admin, `DROP TABLE evidence.marker_key;
CREATE OR REPLACE FUNCTION evidence.mark_who() RETURNS trigger LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $f$
BEGIN PERFORM pg_logical_emit_message(true, 'evidence/who', json_build_object('role', session_user, 'app', current_setting('application_name', true),
 'op', TG_OP, 'table', TG_TABLE_SCHEMA || '.' || TG_TABLE_NAME)::text); RETURN NULL; END $f$;
CREATE OR REPLACE FUNCTION evidence.mark_action(info json) RETURNS void LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $f$
BEGIN PERFORM pg_logical_emit_message(true, 'evidence/action', json_build_object('role', session_user, 'info', info)::text); END $f$`)
	mcp := r.dial("rv_mcp")
	x := r.xact(mcp, `SELECT evidence.mark_action('{"action_id":"a-1","agent":"bot","tool":"execute"}'); UPDATE public.rv_acc SET note = 'by the server' WHERE id = 8`)
	r.exec(r.admin, setup)
	s = r.open()
	e, found, _ := pgtap.Lookup(r.index(), x)
	for _, a := range r.alerts() {
		if a.XID == x {
			t.Fatalf("alerts of a transaction of the older version: %v", a.Kinds())
		}
	}
	if !found || !strings.Contains(string(e.Who), `"rv_mcp"`) || len(e.Actions) != 1 {
		t.Fatalf("a transaction marked by the older functions before the upgrade: %+v", e)
	}
	// После скрипта — уже с метками.
	y := r.xact(mcp, `SELECT evidence.mark_action('{"action_id":"a-2","agent":"bot","tool":"execute"}'); UPDATE public.rv_acc SET note = 'after' WHERE id = 8`)
	if _, err := s.ReadAll(context.Background()); err != nil {
		t.Fatal(err)
	}
	if e, _, _ := pgtap.Lookup(r.index(), y); len(e.Actions) != 1 {
		t.Fatalf("after the upgrade: %+v", e)
	}
}
