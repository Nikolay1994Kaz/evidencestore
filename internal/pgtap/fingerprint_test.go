package pgtap

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/Nikolay1994Kaz/evidencestore/internal/alert"
	"github.com/Nikolay1994Kaz/evidencestore/internal/evidence"
	"github.com/Nikolay1994Kaz/evidencestore/internal/pgoutput"
)

func all(c *Config) { c.All, c.PackTx = true, 3 }

// Config.All: другая роль — отпечаток в пачке, роль из списка — целиком,
// изменения без отметки «кто» — целиком и с тревогой no-who (DECISIONS, п. 41).
func TestAllTakesEveryTransaction(t *testing.T) {
	h := open(t, t.TempDir(), all)
	upd := pgoutput.Update{RelID: 7, OldKind: 'O', Old: []pgoutput.Value{txt("1"), txt("before")}, New: []pgoutput.Value{txt("1"), txt("after")}}

	// Две транзакции приложения: в пачке, базе пока не подтверждены.
	if f := h.run(1, who("app"), accounts, upd); f != 0 {
		t.Fatalf("a fingerprint not yet in the spool was confirmed at %d", f)
	}
	if !h.tap.Pending() {
		t.Fatal("no pending pack")
	}
	h.run(2, who("app"), accounts, pgoutput.Delete{RelID: 7, OldKind: 'O', Old: []pgoutput.Value{txt("2"), txt("gone")}})
	if n := len(h.parts()); n != 0 {
		t.Fatalf("%d records before the pack is full", n)
	}
	// Транзакция агента — целиком; пачка перед ней уходит в буфер первой.
	if f := h.run(3, who("agent"), action("agent", "a-1"), accounts, upd); f == 0 {
		t.Fatal("the agent's transaction was not confirmed")
	}
	if n := len(h.parts()); n != 2 {
		t.Fatalf("records: %d, want the pack and the agent's part", n)
	}
	entries, err := ReadPack(h.parts()[0])
	if err != nil || len(entries) != 2 {
		t.Fatalf("the pack: %v %v", entries, err)
	}
	if v, ok := evidence.SubjectOf(h.parts()[0], "xid"); !ok || v != PackSubject {
		t.Fatalf("the subject of the pack in the store: %q %v", v, ok)
	}
	// Отпечаток: кто, ключ, хеши; самих строк нет.
	rows := entries[0]["rows"].([]any)
	r := rows[0].(map[string]any)
	if r["t"] != "U" || r["r"] != "public.accounts" || r["k"].([]any)[0] != "1" || strings.Contains(string(h.parts()[0]), "before") {
		t.Fatalf("the fingerprint: %v", r)
	}
	// Хеш — по рецепту README: «длина:байты» каждой колонки подряд, NULL — «-».
	sum := sha256.Sum256([]byte("1:16:before"))
	if r["o"] != base64.RawStdEncoding.EncodeToString(sum[:16]) {
		t.Fatalf("the old row's hash is not the one of its values: %v", r["o"])
	}
	if who := entries[0]["who"].(map[string]any)["role"]; who != "app" {
		t.Fatalf("who: %v", who)
	}
	// Справочник: отпечатки — на записи пачки, с видом fingerprint.
	idx := h.index()
	if len(idx) != 3 || idx[0].Kind != KindFingerprint || idx[0].FirstSeq != 1 || idx[1].FirstSeq != 1 || idx[2].Kind != "" || idx[2].FirstSeq != 2 {
		t.Fatalf("the index: %+v", idx)
	}
	// Изменение без отметки «кто» — целиком и с тревогой.
	h.run(4, accounts, upd)
	if k := h.alertKinds(); !strings.Contains(strings.Join(k, ","), alert.KindNoWho) || strings.Contains(strings.Join(k, ","), alert.KindNoAction) {
		t.Fatalf("alerts: %v", k)
	}
	if idx := h.index(); len(h.parts()) != 3 || idx[len(idx)-1].XID != 4 || idx[len(idx)-1].Kind != "" {
		t.Fatalf("the transaction without a who marker is not whole in the journal: %d records, %+v", len(h.parts()), idx)
	}
	if s := h.tap.Stats(); s.Fingerprinted != 2 || s.Captured != 2 || s.Packs != 1 {
		t.Fatalf("%+v", s)
	}
}

// Пачка уходит в буфер полной, по Tick после PackWait и по Flush; до этого её
// конец базе не подтверждается, а Reset её бросает: сервер пришлёт снова.
func TestPackIsFlushedAndOnlyThenConfirmed(t *testing.T) {
	h := open(t, t.TempDir(), all)
	ins := func(id string) pgoutput.Insert {
		return pgoutput.Insert{RelID: 7, New: []pgoutput.Value{txt(id), txt("x")}}
	}
	h.run(1, who("app"), accounts, ins("1"))
	h.run(2, who("app"), accounts, ins("2"))
	f := h.run(3, who("app"), accounts, ins("3")) // PackTx = 3: пачка полная
	if f == 0 || len(h.parts()) != 1 || h.sink.cursor != h.lsn {
		t.Fatalf("a full pack: confirmed %d, records %d, cursor %d (want %d)", f, len(h.parts()), h.sink.cursor, h.lsn)
	}
	h.run(4, who("app"), accounts, ins("4"))
	if f, _ := h.tap.Tick(); f != 0 {
		t.Fatal("a fresh pack went out on Tick")
	}
	h.tap.now = func() time.Time { return time.Now().Add(2 * DefaultPackWait) }
	if f, err := h.tap.Tick(); f == 0 || err != nil || len(h.parts()) != 2 {
		t.Fatalf("an old pack on Tick: %d %v, records %d", f, err, len(h.parts()))
	}
	h.run(5, who("app"), accounts, ins("5"))
	h.tap.Reset()
	if h.tap.Pending() {
		t.Fatal("Reset kept a pack the server will send again")
	}
	h.run(5, who("app"), accounts, ins("5"))
	if f, err := h.tap.Flush(); f == 0 || err != nil || len(h.parts()) != 3 {
		t.Fatalf("Flush: %d %v", f, err)
	}
	if entries, _ := ReadPack(h.parts()[2]); len(entries) != 1 {
		t.Fatalf("the resent transaction is in the pack %d times", len(entries))
	}
}

// Без Config.All — как раньше: другие роли пропускаются.
func TestRolesModeSkipsOthers(t *testing.T) {
	h := open(t, t.TempDir(), nil)
	h.run(1, who("app"), accounts, pgoutput.Insert{RelID: 7, New: []pgoutput.Value{txt("1"), txt("x")}})
	if len(h.parts()) != 0 || h.tap.Pending() || h.tap.Stats().Fingerprinted != 0 {
		t.Fatal("a transaction of another role was taken")
	}
}

// Пачка — запись с меткой субъекта PackSubject: в пакете по окну она «чужая
// закрытая», а не «без метки» (тогда окно не доказало бы полноту транзакции
// агента). Как часть транзакции её не прочесть.
func TestPackCarriesItsOwnSubject(t *testing.T) {
	body := []byte(`{"xid":"pack","pack":1,"v":1,"gz":""}`)
	if v, ok := evidence.SubjectOf(body, "xid"); !ok || v != PackSubject {
		t.Fatalf("subject of a pack: %q %v", v, ok)
	}
	if _, err := ReadTransaction(7, [][]byte{body}); err == nil || !strings.Contains(err.Error(), "pack of fingerprints") {
		t.Fatalf("a pack read as a transaction: %v", err)
	}
}

// Пачка ждёт: транзакция после неё, не тронувшая названных таблиц, базе
// ничего не подтверждает — её конец позже отпечатков, которых нет в буфере.
// Тревоги у отпечатка — как у полной транзакции (ловушка, массовое изменение,
// TRUNCATE), без номеров записей: пачка ещё не в буфере, откатить её нельзя.
func TestFingerprintWaitsAndAlerts(t *testing.T) {
	h := open(t, t.TempDir(), func(c *Config) {
		all(c)
		c.AlertRows = 2
		c.Canaries = []Canary{{Table: "public.accounts", Column: "id", Value: "3"}}
	})
	h.run(1, who("app"), accounts, pgoutput.Insert{RelID: 7, New: []pgoutput.Value{txt("1"), txt("x")}})
	if f := h.run(2); f != 0 {
		t.Fatalf("an empty transaction after a pending pack confirmed %d", f)
	}
	if len(h.alerts()) != 0 {
		t.Fatalf("alerts on an ordinary fingerprint: %v", h.alertKinds())
	}
	h.run(3, who("app"), accounts,
		pgoutput.Update{RelID: 7, OldKind: 'O', Old: []pgoutput.Value{txt("3"), txt("a")}, New: []pgoutput.Value{txt("3"), txt("b")}},
		pgoutput.Insert{RelID: 7, New: []pgoutput.Value{txt("4"), txt("x")}})
	h.run(4, who("app"), accounts, pgoutput.Truncate{RelIDs: []uint32{7}}) // пачка полна (PackTx = 3)
	got := h.alerts()
	if len(got) != 2 || strings.Join(got[0].Kinds(), ",") != "canary,mass-change" || strings.Join(got[1].Kinds(), ",") != "truncate" {
		t.Fatalf("alerts: %+v", got)
	}
	if got[0].XID != 3 || got[0].FirstSeq != 0 || got[0].Changes != 2 || !strings.Contains(string(got[0].Who), "app") {
		t.Fatalf("the alert of a fingerprint: %+v", got[0])
	}
}

// TRUNCATE без отметки «кто» — целиком и с тревогами no-who и truncate, как
// изменение строки без неё; место за ним не подтверждается раньше записи
// (R1-1, R2-1, T-1).
func TestTruncateWithoutWho(t *testing.T) {
	h := open(t, t.TempDir(), all)
	f := h.run(1, accounts, pgoutput.Truncate{RelIDs: []uint32{7}}, pgoutput.Insert{RelID: 7, New: []pgoutput.Value{txt("1"), txt("again")}})
	idx := h.index()
	if f == 0 || len(h.parts()) != 1 || len(idx) != 1 || idx[0].Kind != "" || len(idx[0].Truncated) != 1 {
		t.Fatalf("confirmed %d, records %d, index %+v", f, len(h.parts()), idx)
	}
	recs, err := ReadTransaction(1, h.parts())
	if err != nil || recs[1]["t"] != "T" {
		t.Fatalf("the stream: %v %v", recs, err)
	}
	if k := strings.Join(h.alertKinds(), ","); !strings.Contains(k, "truncate") || !strings.Contains(k, alert.KindNoWho) {
		t.Fatalf("alerts: %s", k)
	}
}

func fpUpdates(base, n int) []any {
	msgs := []any{who("app"), accounts}
	for i := 0; i < n; i++ {
		id := fmt.Sprint(base + i)
		msgs = append(msgs, pgoutput.Update{RelID: 7, OldKind: 'O', Old: []pgoutput.Value{txt(id), txt("a")}, New: []pgoutput.Value{txt(id), txt("b")}})
	}
	return msgs
}

// Запись пачки не больше части: большой отпечаток пишется своими частями,
// как полная транзакция, а пачка уходит раньше, чем перерастёт часть. Раньше
// запись в 1,5 МБ отвергал буфер сборщика, и вход вставал (R1-2, R2-2, T-2).
func TestFingerprintNeverOutgrowsAPart(t *testing.T) {
	h := open(t, t.TempDir(), func(c *Config) { c.All = true })
	small := h.run(1, fpUpdates(0, 10)...)
	f := h.run(2, fpUpdates(100, 30000)...)
	if small != 0 || f == 0 {
		t.Fatalf("confirmed %d and %d", small, f)
	}
	for i, b := range h.parts() {
		if len(b) > evidence.MaxBodyLen {
			t.Fatalf("record %d: %d bytes, the spool takes %d", i+1, len(b), evidence.MaxBodyLen)
		}
	}
	idx := h.index()
	last := idx[len(idx)-1]
	if len(idx) != 2 || idx[0].FirstSeq != 1 || last.XID != 2 || last.Kind != KindFingerprint || last.FirstSeq != 2 || last.LastSeq < 3 || int(last.LastSeq) != len(h.parts()) {
		t.Fatalf("index %+v, %d records", idx, len(h.parts()))
	}
	recs, err := ReadTransaction(2, h.parts()[1:])
	if err != nil || recs[0]["fingerprint"] != true || len(recs) != 30002 || recs[1]["o"] == nil || recs[1]["old"] != nil {
		t.Fatalf("the stream of a big fingerprint: %d lines, %v, %v", len(recs), err, recs[0])
	}
	if s := h.tap.Stats(); s.Fingerprinted != 2 || s.Captured != 0 {
		t.Fatalf("%+v", s)
	}
	// Пачка из многих отпечатков поменьше тоже не перерастает часть.
	h = open(t, t.TempDir(), func(c *Config) { c.All = true })
	for x, n := range []int{2500, 2500, 2500, 2500, 2500, 2500, 2500, 2500, 2500} {
		h.run(uint32(x+1), fpUpdates(x*10000, n)...)
	}
	h.tap.Flush()
	for i, b := range h.parts() {
		if len(b) > evidence.MaxBodyLen {
			t.Fatalf("pack %d: %d bytes", i+1, len(b))
		}
	}
	if n := len(h.parts()); n < 2 {
		t.Fatalf("%d records for nine transactions of 2500 rows", n)
	}
}

// Значение в TOAST, которого нет в журнале (таблица без REPLICA IDENTITY
// FULL), — хеша новой строки нет, а не хеш заглушки, и тревога identity (R1-4).
func TestFingerprintWithoutTheWholeRow(t *testing.T) {
	h := open(t, t.TempDir(), all)
	keyOnly := accounts
	keyOnly.Identity = 'd'
	h.run(1, who("app"), keyOnly, pgoutput.Update{RelID: 7, OldKind: 'K', Old: []pgoutput.Value{txt("1"), {Kind: pgoutput.Null}},
		New: []pgoutput.Value{txt("1"), {Kind: pgoutput.Unchanged}}})
	h.tap.Flush()
	entries, _ := ReadPack(h.parts()[0])
	r := entries[0]["rows"].([]any)[0].(map[string]any)
	if r["n"] != nil || r["o"] != nil || r["partial"] != true || !strings.Contains(strings.Join(h.alertKinds(), ","), "identity") {
		t.Fatalf("the fingerprint %v, alerts %v", r, h.alertKinds())
	}
}

// Отметки — от функций evidence, с меткой по ключу и xid. Отметка без неё
// (её пишет любая роль с pg_logical_emit_message) не решает, чья транзакция:
// та берётся целиком, поддельная отметка — в заголовке, тревога
// forged-marker (R1-3, T-3). Метка в хранилище и справочник не идёт; чужое
// сообщение (outbox) — не отметка вовсе.
func TestForgedMarkers(t *testing.T) {
	keyed := func(xid uint32, prefix, content string) pgoutput.Message {
		return pgoutput.Message{Transactional: true, Prefix: prefix, Content: []byte(MarkerMAC("k-1", xid, prefix, []byte(content)) + content)}
	}
	h := open(t, t.TempDir(), func(c *Config) { all(c); c.MarkerKey = "k-1"; c.RequireAction = true })
	upd := pgoutput.Update{RelID: 7, OldKind: 'O', Old: []pgoutput.Value{txt("1"), txt("a")}, New: []pgoutput.Value{txt("1"), txt("b")}}
	// Подлинные отметки агента: ключ снят.
	h.run(1, keyed(1, PrefixWho, `{"role":"agent","app":"esmcp/bot"}`), keyed(1, PrefixAction, `{"role":"agent","info":{"action_id":"a-1"}}`), accounts, upd)
	// Приложение называет себя агентом и ставит действие; подлинная отметка
	// триггера — его роль.
	h.run(2, who("agent"), action("agent", "a-2"), keyed(2, PrefixWho, `{"role":"app"}`), accounts, upd)
	idx := h.index()
	if len(idx) != 2 || string(idx[0].Who) != `{"role":"agent","app":"esmcp/bot"}` || len(idx[0].Actions) != 1 || strings.Contains(string(idx[0].Actions[0]), "k-1") {
		t.Fatalf("the genuine markers: %+v", idx[0])
	}
	if idx[1].Kind != "" || string(idx[1].Who) != `{"role":"app"}` || len(idx[1].Actions) != 0 {
		t.Fatalf("a forged transaction: %+v", idx[1])
	}
	recs, err := ReadTransaction(2, h.parts()[1:2])
	if err != nil || len(recs[0]["forged"].([]any)) != 2 || bytes.Contains(h.parts()[0], []byte("k-1")) {
		t.Fatalf("the forged markers in the record: %v %v", recs[0], err)
	}
	k := strings.Join(h.alertKinds(), ",")
	if strings.Count(k, alert.KindForged) != 2 || strings.Contains(k, alert.KindNoAction) {
		t.Fatalf("alerts: %s", k)
	}
	// Метка другой транзакции не подходит: отметку из журнала не переложить.
	h.run(3, keyed(1, PrefixWho, `{"role":"agent","app":"esmcp/bot"}`), accounts, upd)
	if idx := h.index(); string(idx[len(idx)-1].Who) == `{"role":"agent","app":"esmcp/bot"}` {
		t.Fatalf("a marker of transaction 1 counted in transaction 3: %+v", idx[len(idx)-1])
	}
	// Outbox приложения — не отметка: ни тревоги, ни транзакции целиком.
	n := len(h.alerts())
	h.run(4, keyed(4, PrefixWho, `{"role":"app"}`), pgoutput.Message{Transactional: true, Prefix: "outbox.orders", Content: []byte(`{"order":1}`)}, accounts, upd)
	if k := h.alerts(); len(k) != n || !h.tap.Pending() {
		t.Fatalf("an outbox message raised %v", k[n:])
	}
	// Поддельный отказ — тревога forged-marker, а не refused.
	h.tap.Handle(pgoutput.Message{Prefix: PrefixRefused, LSN: 99999, Content: []byte(`{"role":"agent","info":{"rows":9,"limit":1}}`)})
	if k := h.alertKinds(); k[len(k)-1] != alert.KindForged {
		t.Fatalf("a forged refusal: %v", k)
	}
}

func inserts(base, n int) []any {
	var out []any
	for i := 0; i < n; i++ {
		out = append(out, pgoutput.Insert{RelID: 7, New: []pgoutput.Value{txt(fmt.Sprint(base + i)), txt(fmt.Sprintf("%032x", base+i))}})
	}
	return out
}

var other = pgoutput.Relation{ID: 8, Namespace: "public", Name: "other", Identity: 'f',
	Columns: []pgoutput.Column{{Key: true, Name: "id"}, {Key: true, Name: "note"}}}

// Заход 2 (R1-1, R2-2): TRUNCATE в отпечатке, перешедшем на свои части, —
// строкой T в потоке, на своём месте, до строк и после них. Счёт по таблицам
// у такого отпечатка — всей транзакции (R1-7, R2-6).
func TestTruncateInAFingerprintOfItsOwnParts(t *testing.T) {
	for _, first := range []bool{true, false} {
		h := open(t, t.TempDir(), func(c *Config) { c.All = true })
		msgs := []any{who("app"), accounts, other}
		if first {
			msgs = append(msgs, pgoutput.Truncate{RelIDs: []uint32{8}})
		}
		msgs = append(msgs, inserts(0, 10000)...)
		if !first {
			msgs = append(msgs, pgoutput.Truncate{RelIDs: []uint32{8}})
		}
		h.run(1, msgs...)
		idx := h.index()
		e := idx[len(idx)-1]
		recs, err := ReadTransaction(1, h.parts()[e.FirstSeq-1:e.LastSeq])
		if err != nil || e.Kind != KindFingerprint || recs[0]["fingerprint"] != true {
			t.Fatalf("%+v %v", e, err)
		}
		at := -1
		for i, r := range recs {
			if r["t"] == "T" {
				at = i
			}
		}
		if want := map[bool]int{true: 1, false: len(recs) - 2}[first]; at != want || e.Tables["public.accounts"].I != 10000 || e.Changes != 10000 {
			t.Fatalf("truncate first %v: T at line %d of %d (want %d), counts %v", first, at, len(recs), want, e.Tables)
		}
	}
}

// Заход 2 (R1-6, R2-3): поддельная отметка в транзакции, решённой
// отпечатком. Строк ещё нет — транзакция целиком; строки уже пошли — отпечаток,
// и поддельная отметка в нём.
func TestForgedMarkerInAFingerprint(t *testing.T) {
	keyed := func(xid uint32, prefix, content string) pgoutput.Message {
		return pgoutput.Message{Transactional: true, Prefix: prefix, Content: []byte(MarkerMAC("k-1", xid, prefix, []byte(content)) + content)}
	}
	h := open(t, t.TempDir(), func(c *Config) { all(c); c.MarkerKey = "k-1"; c.RequireAction = true })
	upd := pgoutput.Update{RelID: 7, OldKind: 'O', Old: []pgoutput.Value{txt("1"), txt("a")}, New: []pgoutput.Value{txt("1"), txt("b")}}
	h.run(1, keyed(1, PrefixWho, `{"role":"app"}`), who("agent"), action("agent", "a-9"), accounts, upd)
	h.run(2, keyed(2, PrefixWho, `{"role":"app"}`), accounts, upd, action("agent", "a-10"))
	h.tap.Flush()
	idx := h.index()
	if len(idx) != 2 || idx[0].Kind != "" || string(idx[0].Who) != `{"role":"app"}` || len(idx[0].Actions) != 0 || idx[1].Kind != KindFingerprint {
		t.Fatalf("index %+v", idx)
	}
	var pack []map[string]any
	for _, b := range h.parts() {
		if p, err := ReadPack(b); err == nil {
			pack = p
		}
	}
	if len(pack) != 1 || !strings.Contains(fmt.Sprint(pack[0]["forged"]), "a-10") {
		t.Fatalf("the forged marker is not in the fingerprint: %v", pack)
	}
	for _, a := range h.alerts() {
		if a.XID == 2 && !strings.Contains(a.Signals[0].Detail, "kept as a fingerprint") {
			t.Fatalf("the alert of xid 2: %v", a.Signals)
		}
	}
}

// Заход 2 (T-1, T-6): отметок в памяти до заголовка — не больше maxMarks,
// каждая не длиннее maxMarkBytes; лишние — счёт, тревога many-markers. В
// справочнике и тревоге — не больше восьми, по 2 КБ. Раньше сто тысяч отметок
// действия одним SELECT агента роняли сборщик по памяти.
func TestMarkersAreBounded(t *testing.T) {
	h := open(t, t.TempDir(), func(c *Config) { all(c); c.RequireAction = true })
	pad := strings.Repeat("z", 40<<10)
	msgs := []any{who("agent")}
	for i := 0; i < 20000; i++ {
		msgs = append(msgs, action("agent", fmt.Sprint("a-", i)))
	}
	msgs = append(msgs, pgoutput.Message{Transactional: true, Prefix: PrefixUndo, Content: []byte(`{"role":"agent","info":{"pad":"` + pad + `"}}`)})
	msgs = append(msgs, accounts, pgoutput.Update{RelID: 7, OldKind: 'O', Old: []pgoutput.Value{txt("1"), txt("a")}, New: []pgoutput.Value{txt("1"), txt("b")}})
	for i := 0; i < 100; i++ {
		msgs = append(msgs, action("agent", fmt.Sprint("after-", i))) // после заголовка — в поток
	}
	h.run(1, msgs...)
	recs, err := ReadTransaction(1, h.parts())
	if err != nil {
		t.Fatal(err)
	}
	head := recs[0]
	if n := len(head["actions"].([]any)); n != maxMarks || head["markers_dropped"] != float64(20000-maxMarks) {
		t.Fatalf("the header: %d actions, %v dropped", n, head["markers_dropped"])
	}
	if u := fmt.Sprint(head["undo"]); len(u) > maxMarkBytes+200 || !strings.Contains(u, "cut") {
		t.Fatalf("a marker of %d bytes is not cut: %d", len(pad), len(u))
	}
	m := 0
	for _, r := range recs {
		if r["t"] == "M" {
			m++
		}
	}
	idx := h.index()
	if m != 100 || len(idx[0].Actions) != 8 {
		t.Fatalf("%d markers after the header in the stream, %d in the index", m, len(idx[0].Actions))
	}
	var big int
	for _, a := range h.alerts() {
		b, _ := json.Marshal(a)
		big = max(big, len(b))
	}
	if k := strings.Join(h.alertKinds(), ","); !strings.Contains(k, "many-markers") || big > 8<<10 {
		t.Fatalf("alerts %s, the largest %d bytes", k, big)
	}
}
