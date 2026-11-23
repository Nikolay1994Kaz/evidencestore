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
	gw    *liveGateway
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
// rv_app, роль сервера rv_mcp, шлюз esmcp со своими квитанциями.
func newReviewRig(t *testing.T) *reviewRig {
	base := os.Getenv("PGINPUT_TEST_DSN")
	if base == "" {
		t.Skip("PGINPUT_TEST_DSN is not set")
	}
	r := &reviewRig{t: t, sink: &limitSink{}, base: base, gw: newLiveGateway(t, "esmcp")}
	r.admin = r.dial("postgres")
	for _, q := range []string{
		"SET client_min_messages = warning",
		"SELECT pg_terminate_backend(active_pid) FROM pg_replication_slots WHERE slot_name = 'rv_slot' AND active",
		"SELECT pg_sleep(0.2)",
		"SELECT pg_drop_replication_slot(slot_name) FROM pg_replication_slots WHERE slot_name = 'rv_slot'",
		"DROP TABLE IF EXISTS public.rv_acc, public.rv_part, public.rv_doc, public.rv_ts",
		"DO $$ BEGIN IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname = 'rv_owner') THEN CREATE ROLE rv_owner LOGIN; END IF; END $$",
		"DO $$ BEGIN IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname = 'rv_app') THEN CREATE ROLE rv_app LOGIN; END IF; END $$",
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
		Tables: []string{"public.rv_acc", "public.rv_part", "public.rv_doc", "public.rv_ts"}, Receipts: liveReceipts(r.gw), RequireGateway: true, AlertRows: 500}
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

// R1-1, R2-1, T-1: TRUNCATE не через шлюз — отпечатком, со строкой T на
// своём месте и тревогами truncate и not-via-gateway; секция, созданная
// после -setup-sql, — тоже.
func TestReviewTruncateNotViaGateway(t *testing.T) {
	r := newReviewRig(t)
	owner := r.dial("rv_owner")
	s := r.open()
	r.exec(r.admin, "CREATE TABLE public.rv_part_2 PARTITION OF public.rv_part FOR VALUES FROM (100) TO (200)") // секция после -setup-sql
	r.exec(r.admin, "ALTER TABLE public.rv_part_2 OWNER TO rv_owner")
	r.xact(owner, "INSERT INTO public.rv_part_2 VALUES (150, 'x')")
	xTrunc := r.xact(owner, "TRUNCATE public.rv_part_2")
	xMix := r.xact(owner, "TRUNCATE public.rv_acc; INSERT INTO public.rv_acc VALUES (1, 'after truncate')")
	if _, err := s.ReadAll(context.Background()); err != nil {
		t.Fatal(err)
	}
	for x, want := range map[uint32]string{xTrunc: "T", xMix: "T I"} {
		e, found, _ := pgtap.Lookup(r.index(), x)
		if !found || e.Kind != pgtap.KindFingerprint {
			t.Fatalf("TRUNCATE not through the gateway, xid %d: %+v %v", x, e, found)
		}
		pack, err := pgtap.ReadPack(r.sink.bodies[e.FirstSeq-1])
		if err != nil {
			t.Fatal(err)
		}
		for _, entry := range pack {
			if uint32(entry["xid"].(float64)) != x {
				continue
			}
			var kinds []string
			for _, row := range entry["rows"].([]any) {
				kinds = append(kinds, row.(map[string]any)["t"].(string))
			}
			if got := strings.Join(kinds, " "); got != want || len(entry["truncated"].([]any)) != 1 {
				t.Fatalf("the fingerprint of xid %d: %s, %v", x, got, entry["truncated"])
			}
		}
	}
	var kinds []string
	for _, e := range r.alerts() {
		if e.XID == xMix {
			kinds = e.Kinds()
		}
	}
	if k := strings.Join(kinds, ","); !strings.Contains(k, "truncate") || !strings.Contains(k, alert.KindNotViaGateway) {
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

// Транзакция роли сервера с намерением шлюза — целиком, с действием в
// справочнике. Роль с pg_logical_emit_message называет себя сервером и ставит
// действие сообщениями журнала (так ставили отметки прежние версии, R1-3,
// T-3), а outbox приложения шлёт своё: сообщения ничего не решают —
// отпечаток, тревога not-via-gateway, в хранилище от них ничего нет.
func TestReviewLogMessagesDecideNothing(t *testing.T) {
	r := newReviewRig(t)
	r.exec(r.admin, "GRANT EXECUTE ON FUNCTION pg_catalog.pg_logical_emit_message(boolean, text, text) TO rv_app")
	defer r.exec(r.admin, "REVOKE EXECUTE ON FUNCTION pg_catalog.pg_logical_emit_message(boolean, text, text) FROM rv_app")
	app, mcp := r.dial("rv_app"), r.dial("rv_mcp")
	s := r.open()
	g := r.gw.act(mcp, "UPDATE public.rv_acc SET note = 'by the server' WHERE id = 2")
	x := r.xact(app, `SELECT pg_logical_emit_message(true, 'evidence/who', '{"role":"rv_mcp","app":"esmcp/bot"}'); `+
		`SELECT pg_logical_emit_message(true, 'evidence/action', '{"role":"rv_mcp","info":{"action_id":"act-77","agent":"bot","tool":"execute"}}'); `+
		`SELECT pg_logical_emit_message(true, 'outbox.orders', '{"order":1}'); `+
		`UPDATE public.rv_acc SET note = 'by app' WHERE id = 3`)
	if _, err := s.ReadAll(context.Background()); err != nil {
		t.Fatal(err)
	}
	eg, _, _ := pgtap.Lookup(r.index(), g)
	if eg.Kind != "" || eg.Action == nil || eg.Action.Gateway != "esmcp" || eg.Action.ID != "esmcp-1" {
		t.Fatalf("the gateway's transaction: %+v", eg)
	}
	e, _, _ := pgtap.Lookup(r.index(), x)
	if e.Kind != pgtap.KindFingerprint || e.Action != nil {
		t.Fatalf("a transaction with markers of the older versions: %+v", e)
	}
	for _, b := range r.sink.bodies {
		if strings.Contains(string(b), "act-77") || strings.Contains(string(b), "order") {
			t.Fatal("a log message went to the store")
		}
	}
	var kinds []string
	for _, a := range r.alerts() {
		if a.XID == x {
			kinds = a.Kinds()
		}
		if a.XID == g {
			t.Fatalf("an alert of the gateway's transaction: %v", a.Kinds())
		}
	}
	if k := strings.Join(kinds, ","); k != alert.KindNotViaGateway {
		t.Fatalf("alerts: %s", k)
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

// Обновление с прежней установки (отметки «кто», заморожены 23.11): её схема
// evidence с ключом и функциями, триггеры на таблицах, владелец отметок и
// отозванное у PUBLIC право писать в журнал. Скрипт снимает всё это и
// возвращает право, как было (п. 42); секрета в базе не остаётся.
func TestReviewUpgradeDropsTheMarkers(t *testing.T) {
	r := newReviewRig(t)
	r.exec(r.admin, `DO $$ BEGIN IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname = 'evidence_owner') THEN CREATE ROLE evidence_owner NOLOGIN; END IF; END $$;
CREATE SCHEMA evidence AUTHORIZATION evidence_owner;
CREATE TABLE evidence.marker_key (k text NOT NULL); INSERT INTO evidence.marker_key VALUES (md5(random()::text));
ALTER TABLE evidence.marker_key OWNER TO evidence_owner;
CREATE FUNCTION evidence.mark_who() RETURNS trigger LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $f$
BEGIN PERFORM pg_logical_emit_message(true, 'evidence/who', json_build_object('role', session_user)::text); RETURN NULL; END $f$;
ALTER FUNCTION evidence.mark_who() OWNER TO evidence_owner;
CREATE TRIGGER evidence_who AFTER INSERT OR UPDATE OR DELETE ON public.rv_acc FOR EACH STATEMENT EXECUTE FUNCTION evidence.mark_who();
REVOKE EXECUTE ON FUNCTION pg_catalog.pg_logical_emit_message(boolean, text, text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION pg_catalog.pg_logical_emit_message(boolean, text, text) TO evidence_owner`)
	setup, err := SetupSQL(&r.cfg)
	if err != nil {
		t.Fatal(err)
	}
	r.exec(r.admin, setup)
	for q, want := range map[string]string{
		"SELECT count(*) FROM pg_namespace WHERE nspname = 'evidence'":                                                                            "0",
		"SELECT count(*) FROM pg_roles WHERE rolname = 'evidence_owner'":                                                                          "0",
		"SELECT count(*) FROM pg_trigger WHERE tgname = 'evidence_who'":                                                                           "0",
		"SELECT has_function_privilege('rv_app', 'pg_logical_emit_message(boolean, text, text)', 'EXECUTE')::text":                                "true",
		"SELECT count(*) FROM pg_proc p JOIN pg_namespace n ON n.oid = p.pronamespace WHERE p.proname LIKE 'mark\\_%' AND n.nspname = 'evidence'": "0",
	} {
		if got := r.one(r.admin, q); got != want {
			t.Errorf("%s: %s, want %s", q, got, want)
		}
	}
	// И вход после обновления — как всегда: шлюз целиком, остальное отпечатком.
	owner, mcp := r.dial("rv_owner"), r.dial("rv_mcp")
	s := r.open()
	g := r.gw.act(mcp, "UPDATE public.rv_acc SET note = 'after' WHERE id = 8")
	x := r.xact(owner, "UPDATE public.rv_acc SET note = 'owner' WHERE id = 9")
	if _, err := s.ReadAll(context.Background()); err != nil {
		t.Fatal(err)
	}
	if e, _, _ := pgtap.Lookup(r.index(), g); e.Kind != "" || e.Action == nil {
		t.Fatalf("the gateway's transaction after the upgrade: %+v", e)
	}
	if e, _, _ := pgtap.Lookup(r.index(), x); e.Kind != pgtap.KindFingerprint {
		t.Fatalf("the owner's transaction after the upgrade: %+v", e)
	}
}
