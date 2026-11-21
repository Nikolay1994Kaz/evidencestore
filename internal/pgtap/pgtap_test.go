package pgtap

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Nikolay1994Kaz/evidencestore/internal/pgoutput"
)

type fakeCatalog struct{ calls int }

func (c *fakeCatalog) Describe(rel pgoutput.Relation) (RelInfo, error) {
	c.calls++
	types := make([]string, len(rel.Columns))
	for i := range types {
		types[i] = "text"
	}
	return RelInfo{Types: types, PK: []string{rel.Columns[0].Name}}, nil
}

func txt(s string) pgoutput.Value { return pgoutput.Value{Kind: pgoutput.Text, Data: []byte(s)} }

var accounts = pgoutput.Relation{ID: 7, Namespace: "public", Name: "accounts", Identity: 'f',
	Columns: []pgoutput.Column{{Key: true, Name: "id"}, {Key: true, Name: "note"}}}

func who(role string) pgoutput.Message {
	return pgoutput.Message{Transactional: true, Prefix: PrefixWho, Content: []byte(`{"role":"` + role + `"}`)}
}

func action(role, id string) pgoutput.Message {
	return pgoutput.Message{Transactional: true, Prefix: PrefixAction, Content: []byte(`{"role":"` + role + `","info":{"action_id":"` + id + `"}}`)}
}

type harness struct {
	t   *testing.T
	dir string
	tap *Tap
	cat *fakeCatalog
	lsn uint64
}

func open(t *testing.T, dir string, mod func(*Config)) *harness {
	t.Helper()
	cfg := Config{Dir: dir, Roles: []string{"agent"}}
	if mod != nil {
		mod(&cfg)
	}
	cat := &fakeCatalog{}
	tap, err := Open(cfg, cat, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { tap.Close() })
	return &harness{t: t, dir: dir, tap: tap, cat: cat, lsn: 1000}
}

// run подаёт транзакцию: Begin, сообщения, Commit; отдаёт подтверждённую позицию.
func (h *harness) run(xid uint32, msgs ...any) uint64 {
	h.t.Helper()
	h.lsn += 100
	return h.runAt(xid, h.lsn, msgs...)
}

func (h *harness) runAt(xid uint32, commit uint64, msgs ...any) uint64 {
	h.t.Helper()
	all := append([]any{pgoutput.Begin{FinalLSN: commit, CommitTime: time.Unix(1_800_000_000, 0), XID: xid}}, msgs...)
	all = append(all, pgoutput.Commit{CommitLSN: commit, EndLSN: commit + 50})
	var flushed uint64
	for _, m := range all {
		f, err := h.tap.Handle(m)
		if err != nil {
			h.t.Fatalf("%T: %v", m, err)
		}
		if f != 0 {
			flushed = f
		}
	}
	return flushed
}

func (h *harness) lines(name string) [][]byte {
	h.t.Helper()
	data, err := os.ReadFile(filepath.Join(h.dir, name))
	if err != nil {
		h.t.Fatal(err)
	}
	var out [][]byte
	for _, l := range bytes.Split(bytes.TrimSuffix(data, []byte("\n")), []byte("\n")) {
		if len(l) > 0 {
			out = append(out, l)
		}
	}
	return out
}

func (h *harness) index() []IndexEntry {
	h.t.Helper()
	var out []IndexEntry
	for _, l := range h.lines("index.jsonl") {
		var e IndexEntry
		if err := json.Unmarshal(l, &e); err != nil {
			h.t.Fatal(err)
		}
		out = append(out, e)
	}
	return out
}

func (h *harness) alertKinds() []string {
	h.t.Helper()
	var out []string
	for _, l := range h.lines("alerts.jsonl") {
		var a Alert
		json.Unmarshal(l, &a)
		out = append(out, a.Kind)
	}
	return out
}

func TestAgentTransactionIsJournaled(t *testing.T) {
	h := open(t, t.TempDir(), nil)
	flushed := h.run(751, action("agent", "42"), who("agent"), accounts,
		pgoutput.Update{RelID: 7, OldKind: 'O', Old: []pgoutput.Value{txt("6"), txt("a")}, New: []pgoutput.Value{txt("6"), txt("b")}},
		who("agent"), // второй оператор той же транзакции
		pgoutput.Delete{RelID: 7, OldKind: 'O', Old: []pgoutput.Value{txt("5"), {Kind: pgoutput.Null}}},
		pgoutput.Insert{RelID: 7, New: []pgoutput.Value{txt("9"), txt("n")}})
	if flushed != h.lsn+50 {
		t.Fatalf("flushed %d", flushed)
	}
	lines := h.lines("journal.jsonl")
	if len(lines) != 1 || !bytes.HasPrefix(lines[0], []byte(`{"xid":751,"part":1,"last":true,"gz":"`)) {
		t.Fatalf("journal: %d lines, %.60s", len(lines), lines[0])
	}
	recs, err := ReadTransaction(751, lines)
	if err != nil {
		t.Fatal(err)
	}
	var kinds []string
	for _, r := range recs {
		kinds = append(kinds, r["t"].(string))
	}
	if got := strings.Join(kinds, ""); got != "HRUDIC" {
		t.Fatalf("stream %s", got)
	}
	if recs[0]["who"].(map[string]any)["role"] != "agent" || len(recs[0]["actions"].([]any)) != 1 {
		t.Fatalf("header %v", recs[0])
	}
	if r := recs[1]; r["schema"] != "public" || r["identity"] != "f" || r["pk"].([]any)[0] != "id" || r["types"].([]any)[1] != "text" {
		t.Fatalf("relation %v", r)
	}
	if u := recs[2]; u["old"].([]any)[1] != "a" || u["new"].([]any)[1] != "b" {
		t.Fatalf("update %v", u)
	}
	if d := recs[3]; d["old"].([]any)[1] != nil || d["new"] != nil {
		t.Fatalf("delete %v", d)
	}
	idx := h.index()
	if len(idx) != 1 || idx[0].XID != 751 || idx[0].FirstLine != 1 || idx[0].LastLine != 1 || idx[0].Changes != 3 ||
		idx[0].Tables["public.accounts"] != (Counts{I: 1, U: 1, D: 1}) || len(idx[0].Actions) != 1 {
		t.Fatalf("index %+v", idx)
	}
	if h.cat.calls != 1 {
		t.Fatalf("catalog asked %d times", h.cat.calls)
	}
}

func TestOtherTransactionsAreSkipped(t *testing.T) {
	h := open(t, t.TempDir(), nil)
	ins := pgoutput.Insert{RelID: 7, New: []pgoutput.Value{txt("1"), txt("x")}}
	if f := h.run(1, who("postgres"), accounts, ins); f == 0 {
		t.Fatal("a skipped transaction must still move the confirmed position")
	}
	h.run(2, accounts, ins)                // без отметки вовсе
	h.run(3, action("postgres", "1"), ins) // отметка действия не от наблюдаемой роли
	if n := len(h.lines("journal.jsonl")); n != 0 {
		t.Fatalf("%d journal lines", n)
	}
	if s := h.tap.Stats(); s.Skipped != 3 || s.SkippedChanges != 3 || s.Captured != 0 {
		t.Fatalf("%+v", s)
	}
	if h.cat.calls != 0 {
		t.Fatal("the catalog was asked about a skipped transaction")
	}
}

func TestBigValueSpansParts(t *testing.T) {
	h := open(t, t.TempDir(), func(c *Config) { c.PartSize = 4096 })
	// Плохо сжимаемое значение: 200 КБ псевдослучайных шестнадцатеричных цифр.
	var big strings.Builder
	x := uint64(88172645463325252)
	for big.Len() < 200_000 {
		x ^= x << 13
		x ^= x >> 7
		x ^= x << 17
		big.WriteString(strings.Repeat("0", 16)[len(strconvHex(x)):] + strconvHex(x))
	}
	h.run(9, who("agent"), accounts, pgoutput.Update{RelID: 7, OldKind: 'O',
		Old: []pgoutput.Value{txt("1"), txt("small")}, New: []pgoutput.Value{txt("1"), txt(big.String())}})
	lines := h.lines("journal.jsonl")
	if len(lines) < 10 {
		t.Fatalf("%d parts", len(lines))
	}
	for i, l := range lines {
		var p struct {
			Part int
			Last bool
			GZ   []byte
		}
		if err := json.Unmarshal(l, &p); err != nil || p.Part != i+1 || p.Last != (i == len(lines)-1) || len(p.GZ) > 4096 || len(p.GZ) == 0 {
			t.Fatalf("part %d: %v %+v", i+1, err, struct{ Part, N int }{p.Part, len(p.GZ)})
		}
	}
	recs, err := ReadTransaction(9, lines)
	if err != nil {
		t.Fatal(err)
	}
	if recs[2]["new"].([]any)[1] != big.String() {
		t.Fatal("the big value did not survive the parts")
	}
	if idx := h.index(); idx[0].FirstLine != 1 || idx[0].LastLine != uint64(len(lines)) {
		t.Fatalf("index %+v", idx[0])
	}
	// Без любой из частей транзакция не читается.
	for drop := range lines {
		rest := append(append([][]byte{}, lines[:drop]...), lines[drop+1:]...)
		if _, err := ReadTransaction(9, rest); err == nil {
			t.Fatalf("read without part %d", drop+1)
		}
	}
}

func strconvHex(x uint64) string {
	const d = "0123456789abcdef"
	var b [16]byte
	i := 16
	for x > 0 {
		i--
		b[i] = d[x&15]
		x >>= 4
	}
	return string(b[i:])
}

func TestUnchangedToastComesFromTheOldRow(t *testing.T) {
	h := open(t, t.TempDir(), nil)
	h.run(5, who("agent"), accounts, pgoutput.Update{RelID: 7, OldKind: 'O',
		Old: []pgoutput.Value{txt("1"), txt("long text")}, New: []pgoutput.Value{txt("2"), {Kind: pgoutput.Unchanged}}})
	recs, _ := ReadTransaction(5, h.lines("journal.jsonl"))
	if got := recs[2]["new"].([]any); got[0] != "2" || got[1] != "long text" {
		t.Fatalf("new %v", got)
	}
}

func TestKeyOnlyOldRowIsMarkedPartial(t *testing.T) {
	h := open(t, t.TempDir(), nil)
	rel := accounts
	rel.Identity = 'd'
	h.run(5, who("agent"), rel,
		pgoutput.Update{RelID: 7, New: []pgoutput.Value{txt("1"), txt("b")}},
		pgoutput.Delete{RelID: 7, OldKind: 'K', Old: []pgoutput.Value{txt("1"), {Kind: pgoutput.Null}}})
	recs, _ := ReadTransaction(5, h.lines("journal.jsonl"))
	for _, r := range recs[2:4] {
		if r["partial"] != true || r["old"] != nil {
			t.Fatalf("%v", r)
		}
	}
	if k := h.alertKinds(); len(k) != 1 || k[0] != "identity" {
		t.Fatalf("alerts %v", k)
	}
}

func TestRestartSkipsWhatIsJournaledAndCutsATornTail(t *testing.T) {
	dir := t.TempDir()
	h := open(t, dir, nil)
	up := pgoutput.Update{RelID: 7, OldKind: 'O', Old: []pgoutput.Value{txt("1"), txt("a")}, New: []pgoutput.Value{txt("1"), txt("b")}}
	h.runAt(10, 2000, who("agent"), accounts, up)
	h.tap.Close()
	// Падение посреди следующей транзакции: в журнале обрывок строки.
	f, _ := os.OpenFile(filepath.Join(dir, "journal.jsonl"), os.O_APPEND|os.O_WRONLY, 0)
	f.WriteString(`{"xid":11,"part":1,"last":fal`)
	f.Close()

	h = open(t, dir, nil)
	// Сервер шлёт заново с подтверждённой позиции: транзакция 10 уже в журнале.
	if f := h.runAt(10, 2000, who("agent"), accounts, up); f != 2050 {
		t.Fatalf("flushed %d", f)
	}
	h.runAt(11, 2100, who("agent"), accounts, up)
	lines := h.lines("journal.jsonl")
	if len(lines) != 2 {
		t.Fatalf("%d journal lines: the duplicate or the torn tail stayed", len(lines))
	}
	if _, err := ReadTransaction(11, lines[1:]); err != nil {
		t.Fatal(err)
	}
	idx := h.index()
	if len(idx) != 2 || idx[1].XID != 11 || idx[1].FirstLine != 2 {
		t.Fatalf("index %+v", idx)
	}
	if s := h.tap.Stats(); s.Duplicates != 1 || s.Captured != 1 {
		t.Fatalf("%+v", s)
	}
}

func TestResentTransactionReadsFromItsLastWholeCopy(t *testing.T) {
	h := open(t, t.TempDir(), func(c *Config) { c.PartSize = 64 })
	h.run(4, who("agent"), accounts, pgoutput.Insert{RelID: 7, New: []pgoutput.Value{txt("1"), txt(strings.Repeat("abcdefgh", 60))}})
	lines := h.lines("journal.jsonl")
	if len(lines) < 3 {
		t.Fatalf("%d parts", len(lines))
	}
	// Первая копия оборвана на второй части, затем транзакция целиком.
	resent := append(append([][]byte{}, lines[:2]...), lines...)
	if _, err := ReadTransaction(4, resent); err != nil {
		t.Fatal(err)
	}
	if _, err := ReadTransaction(4, lines[:len(lines)-1]); err == nil {
		t.Fatal("read a transaction without its last part")
	}
	if _, err := ReadTransaction(5, lines); err == nil {
		t.Fatal("read the lines of another transaction")
	}
}

func TestAlerts(t *testing.T) {
	h := open(t, t.TempDir(), func(c *Config) {
		c.AlertRows = 2
		c.RequireAction = true
		c.Canaries = []Canary{{Table: "public.accounts", Column: "id", Value: "7"}}
	})
	ins := func(id string) pgoutput.Insert {
		return pgoutput.Insert{RelID: 7, New: []pgoutput.Value{txt(id), txt("x")}}
	}
	h.run(1, action("agent", "1"), who("agent"), accounts, ins("1")) // тихо
	if k := h.alertKinds(); len(k) != 0 {
		t.Fatalf("alerts %v", k)
	}
	h.run(2, who("agent"), accounts, ins("1"), ins("7"), pgoutput.Truncate{RelIDs: []uint32{7}})
	want := "canary truncate mass-change no-action"
	if got := strings.Join(h.alertKinds(), " "); got != want {
		t.Fatalf("alerts %q, want %q", got, want)
	}
	// Отметка после пропущенных изменений: транзакция в журнале была бы не вся.
	h.run(3, accounts, ins("1"), who("agent"), ins("2"))
	if k := h.alertKinds(); k[len(k)-1] != "late-marker" {
		t.Fatalf("alerts %v", k)
	}
	if len(h.index()) != 2 {
		t.Fatal("the late-marked transaction was journaled in part")
	}
}

func TestUndoTransactionIsJournaled(t *testing.T) {
	h := open(t, t.TempDir(), func(c *Config) { c.RequireAction = true })
	h.run(8, pgoutput.Message{Transactional: true, Prefix: PrefixUndo, Content: []byte(`{"undoes_xid":"751"}`)}, who("postgres"), accounts,
		pgoutput.Insert{RelID: 7, New: []pgoutput.Value{txt("5"), txt("back")}})
	idx := h.index()
	if len(idx) != 1 || string(idx[0].Undo) != `{"undoes_xid":"751"}` || idx[0].Who != nil {
		t.Fatalf("index %+v", idx)
	}
	if k := h.alertKinds(); len(k) != 0 {
		t.Fatalf("alerts %v", k)
	}
}

func TestTransactionWithoutChangesIsStillRecorded(t *testing.T) {
	h := open(t, t.TempDir(), nil)
	h.run(6, action("agent", "7"), who("agent")) // UPDATE, не тронувший ни одной строки
	recs, err := ReadTransaction(6, h.lines("journal.jsonl"))
	if err != nil || len(recs) != 2 || recs[1]["changes"] != float64(0) {
		t.Fatalf("%v %v", recs, err)
	}
}

func TestOpenRefusesBadConfig(t *testing.T) {
	for _, cfg := range []Config{{Dir: t.TempDir()}, {Dir: t.TempDir(), Roles: []string{"a"}, PartSize: MaxPartSize + 1}} {
		if _, err := Open(cfg, &fakeCatalog{}, nil); err == nil {
			t.Errorf("opened with %+v", cfg)
		}
	}
}
