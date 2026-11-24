package pgtap

import (
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/Nikolay1994Kaz/evidencestore/internal/evidence"
	"github.com/Nikolay1994Kaz/evidencestore/internal/pgoutput"
)

// pack3 — пачка из трёх отпечатков.
func pack3(c *Config) { c.PackTx = 3 }

// Транзакция без намерения шлюза — отпечаток в пачке, с намерением — целиком
// (DECISIONS, п. 42). Сообщения журнала (outbox приложения) ничего не решают.
func TestGatewayDecidesWholeOrFingerprint(t *testing.T) {
	h := open(t, t.TempDir(), pack3)
	upd := pgoutput.Update{RelID: 7, OldKind: 'O', Old: []pgoutput.Value{txt("1"), txt("before")}, New: []pgoutput.Value{txt("1"), txt("after")}}
	outbox := pgoutput.Message{Transactional: true, Prefix: "outbox.orders", Content: []byte(`{"order":1}`)}

	// Две транзакции приложения: в пачке, базе пока не подтверждены.
	if f := h.run(1, who("app"), outbox, accounts, upd); f != 0 {
		t.Fatalf("a fingerprint not yet in the spool was confirmed at %d", f)
	}
	if !h.tap.Pending() {
		t.Fatal("no pending pack")
	}
	h.run(2, accounts, pgoutput.Delete{RelID: 7, OldKind: 'O', Old: []pgoutput.Value{txt("2"), txt("gone")}})
	if n := len(h.parts()); n != 0 {
		t.Fatalf("%d records before the pack is full", n)
	}
	// Транзакция шлюза — целиком; пачка перед ней уходит в буфер первой.
	if f := h.run(3, action("agent", "a-1"), outbox, accounts, upd); f == 0 {
		t.Fatal("the gateway's transaction was not confirmed")
	}
	if n := len(h.parts()); n != 2 {
		t.Fatalf("records: %d, want the pack and the gateway's part", n)
	}
	entries, err := ReadPack(h.parts()[0])
	if err != nil || len(entries) != 2 {
		t.Fatalf("the pack: %v %v", entries, err)
	}
	if v, ok := evidence.SubjectOf(h.parts()[0], "xid"); !ok || v != PackSubject {
		t.Fatalf("the subject of the pack in the store: %q %v", v, ok)
	}
	// Отпечаток: ключ, хеши; самих строк нет, и чья транзакция — тоже.
	rows := entries[0]["rows"].([]any)
	r := rows[0].(map[string]any)
	if r["t"] != "U" || r["r"] != "public.accounts" || r["k"].([]any)[0] != "1" || strings.Contains(string(h.parts()[0]), "before") {
		t.Fatalf("the fingerprint: %v", r)
	}
	if entries[0]["who"] != nil || entries[0]["action"] != nil || strings.Contains(string(h.parts()[0]), "order") {
		t.Fatalf("the fingerprint says whose it is: %v", entries[0])
	}
	// Хеш — по рецепту README: «длина:байты» каждой колонки подряд, NULL — «-».
	sum := sha256.Sum256([]byte("1:16:before"))
	if r["o"] != base64.RawStdEncoding.EncodeToString(sum[:16]) {
		t.Fatalf("the old row's hash is not the one of its values: %v", r["o"])
	}
	// Справочник: отпечатки — на записи пачки, с видом fingerprint; у
	// транзакции шлюза — его действие.
	idx := h.index()
	if len(idx) != 3 || idx[0].Kind != KindFingerprint || idx[0].FirstSeq != 1 || idx[1].FirstSeq != 1 || idx[0].Action != nil ||
		idx[2].Kind != "" || idx[2].FirstSeq != 2 || idx[2].Action == nil || idx[2].Action.ID != "a-1" {
		t.Fatalf("the index: %+v", idx)
	}
	recs, err := ReadTransaction(3, h.parts()[1:])
	if err != nil || len(recs) != 4 || recs[1]["t"] != "R" || recs[2]["t"] != "U" {
		t.Fatalf("an outbox message in the gateway's stream: %v %v", recs, err)
	}
	if s := h.tap.Stats(); s.Fingerprinted != 2 || s.Captured != 1 || s.Packs != 1 {
		t.Fatalf("%+v", s)
	}
}

// Пачка уходит в буфер полной, по Tick после PackWait и по Flush; до этого её
// конец базе не подтверждается, а Reset её бросает: сервер пришлёт снова.
func TestPackIsFlushedAndOnlyThenConfirmed(t *testing.T) {
	h := open(t, t.TempDir(), pack3)
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
		pack3(c)
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
	if got[0].XID != 3 || got[0].FirstSeq != 0 || got[0].Changes != 2 || !got[0].Fingerprint || got[0].Action != nil {
		t.Fatalf("the alert of a fingerprint: %+v", got[0])
	}
}

// TRUNCATE не через шлюз — отпечатком: строкой T среди его строк, по порядку
// журнала, и с тревогой truncate; место за ним не подтверждается раньше
// пачки (R1-1, R2-1, T-1).
func TestTruncateNotViaGateway(t *testing.T) {
	h := open(t, t.TempDir(), pack3)
	f := h.run(1, accounts, pgoutput.Truncate{RelIDs: []uint32{7}}, pgoutput.Insert{RelID: 7, New: []pgoutput.Value{txt("1"), txt("again")}})
	if f != 0 || len(h.parts()) != 0 {
		t.Fatalf("confirmed %d before the pack, %d records", f, len(h.parts()))
	}
	if f, err := h.tap.Flush(); f == 0 || err != nil {
		t.Fatalf("Flush: %d %v", f, err)
	}
	entries, err := ReadPack(h.parts()[0])
	if err != nil || len(entries) != 1 {
		t.Fatalf("the pack: %v %v", entries, err)
	}
	rows := entries[0]["rows"].([]any)
	if len(rows) != 2 || rows[0].(map[string]any)["t"] != "T" || rows[1].(map[string]any)["t"] != "I" || fmt.Sprint(entries[0]["truncated"]) != "[public.accounts]" {
		t.Fatalf("the fingerprint: %v", entries[0])
	}
	if idx := h.index(); len(idx) != 1 || idx[0].Kind != KindFingerprint {
		t.Fatalf("index %+v", idx)
	}
	if k := strings.Join(h.alertKinds(), ","); k != "truncate" {
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
	h := open(t, t.TempDir(), nil)
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
	h = open(t, t.TempDir(), nil)
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
	h := open(t, t.TempDir(), pack3)
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
		h := open(t, t.TempDir(), nil)
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
