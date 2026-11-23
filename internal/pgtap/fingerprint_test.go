package pgtap

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
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
	b, _ := json.Marshal([]any{"1", "before"})
	sum := sha256.Sum256(b)
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
