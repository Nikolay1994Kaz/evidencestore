package pgtap

import (
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Nikolay1994Kaz/evidencestore/internal/alert"
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

// fakeSink — буфер сборщика: помнит записи, номера с единицы и место входа.
// failAt — на этом по счёту вызове Emit «процесс падает»: запись не ложится.
type fakeSink struct {
	bodies [][]byte
	cursor uint64
	emits  int
	failAt int
}

var errCrash = errors.New("crash")

func (s *fakeSink) Next() uint64 { return uint64(len(s.bodies)) + 1 }

func (s *fakeSink) Emit(bodies [][]byte, cursor uint64) (uint64, error) {
	if s.emits++; s.emits == s.failAt {
		return 0, errCrash
	}
	first := s.Next()
	for _, b := range bodies {
		s.bodies = append(s.bodies, bytes.Clone(b))
	}
	s.cursor = cursor
	return first, nil
}

type harness struct {
	t    *testing.T
	dir  string
	tap  *Tap
	cat  *fakeCatalog
	sink *fakeSink
	lsn  uint64
}

func open(t *testing.T, dir string, mod func(*Config)) *harness {
	t.Helper()
	return openOn(t, dir, &fakeSink{}, mod)
}

// openOn поднимает Tap над буфером, который пережил «падение»: место входа —
// то, что в нём лежит.
func openOn(t *testing.T, dir string, sink *fakeSink, mod func(*Config)) *harness {
	t.Helper()
	cfg := Config{Dir: dir, Roles: []string{"agent"}}
	if mod != nil {
		mod(&cfg)
	}
	cat := &fakeCatalog{}
	tap, err := Open(cfg, cat, sink, sink.cursor, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { tap.Close() })
	return &harness{t: t, dir: dir, tap: tap, cat: cat, sink: sink, lsn: 1000}
}

// feed подаёт транзакцию и отдаёт ошибку Handle, если она была.
func (h *harness) feed(xid uint32, commit uint64, msgs ...any) error {
	all := append([]any{pgoutput.Begin{FinalLSN: commit, CommitTime: time.Unix(1_800_000_000, 0), XID: xid}}, msgs...)
	all = append(all, pgoutput.Commit{CommitLSN: commit, EndLSN: commit + 50})
	for _, m := range all {
		if _, err := h.tap.Handle(m); err != nil {
			return err
		}
	}
	return nil
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

// parts — записи, которые легли в буфер сборщика.
func (h *harness) parts() [][]byte { return h.sink.bodies }

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

// alerts — строки alerts.jsonl: по событию на транзакцию.
func (h *harness) alerts() []alert.Event {
	h.t.Helper()
	var out []alert.Event
	for _, l := range h.lines("alerts.jsonl") {
		var e alert.Event
		if err := json.Unmarshal(l, &e); err != nil {
			h.t.Fatal(err)
		}
		out = append(out, e)
	}
	return out
}

// alertKinds — поводы всех тревог подряд.
func (h *harness) alertKinds() []string {
	h.t.Helper()
	var out []string
	for _, e := range h.alerts() {
		out = append(out, e.Kinds()...)
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
	lines := h.parts()
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
	if len(idx) != 1 || idx[0].XID != 751 || idx[0].FirstSeq != 1 || idx[0].LastSeq != 1 || idx[0].Changes != 3 ||
		idx[0].Tables["public.accounts"] != (Counts{I: 1, U: 1, D: 1}) || len(idx[0].Actions) != 1 {
		t.Fatalf("index %+v", idx)
	}
	if h.cat.calls != 1 {
		t.Fatalf("catalog asked %d times", h.cat.calls)
	}
	if h.sink.cursor != h.lsn {
		t.Fatalf("cursor %d, the commit is at %d", h.sink.cursor, h.lsn)
	}
	if bytes.HasSuffix(lines[0], []byte("\n")) {
		t.Fatal("a record body ends with a newline")
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
	if n := len(h.parts()); n != 0 {
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
	lines := h.parts()
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
	if idx := h.index(); idx[0].FirstSeq != 1 || idx[0].LastSeq != uint64(len(lines)) {
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
	recs, _ := ReadTransaction(5, h.parts())
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
	recs, _ := ReadTransaction(5, h.parts())
	for _, r := range recs[2:4] {
		if r["partial"] != true || r["old"] != nil {
			t.Fatalf("%v", r)
		}
	}
	if k := h.alertKinds(); len(k) != 1 || k[0] != "identity" {
		t.Fatalf("alerts %v", k)
	}
}

// Падение посреди транзакции: её первые части остались в буфере без последней,
// место входа не сдвинулось. После перезапуска база шлёт заново с подтверждённой
// позиции: уже лежащая целиком транзакция пропускается, оборванная ложится
// целиком под новыми номерами, и справочник называет именно их.
func TestRestartSkipsWhatIsSpooledAndResendsTheTornTransaction(t *testing.T) {
	dir := t.TempDir()
	small := func(c *Config) { c.PartSize = 64 }
	h := open(t, dir, small)
	up := pgoutput.Update{RelID: 7, OldKind: 'O', Old: []pgoutput.Value{txt("1"), txt("a")}, New: []pgoutput.Value{txt("1"), txt("b")}}
	big := pgoutput.Insert{RelID: 7, New: []pgoutput.Value{txt("2"), txt(strings.Repeat("abcdefgh", 60))}}
	h.runAt(10, 2000, who("agent"), accounts, up)
	whole := len(h.sink.bodies)
	h.sink.failAt = h.sink.emits + 3 // третья часть транзакции 11 не ляжет
	if err := h.feed(11, 2100, who("agent"), accounts, big); !errors.Is(err, errCrash) {
		t.Fatalf("no crash: %v", err)
	}
	h.tap.Close()
	torn := len(h.sink.bodies) - whole
	if torn != 2 || h.sink.cursor != 2000 {
		t.Fatalf("%d torn parts in the spool, cursor %d", torn, h.sink.cursor)
	}
	if len(h.index()) != 1 {
		t.Fatal("the torn transaction is in the index")
	}

	h = openOn(t, dir, h.sink, small)
	if f := h.runAt(10, 2000, who("agent"), accounts, up); f != 2050 {
		t.Fatalf("flushed %d", f)
	}
	if len(h.sink.bodies) != whole+torn {
		t.Fatal("the transaction already in the spool was spooled again")
	}
	h.runAt(11, 2100, who("agent"), accounts, big)
	idx := h.index()
	if len(idx) != 2 || idx[1].XID != 11 || idx[1].FirstSeq != uint64(whole+torn+1) || idx[1].LastSeq != uint64(len(h.sink.bodies)) {
		t.Fatalf("index %+v, %d records in the spool", idx, len(h.sink.bodies))
	}
	// По номерам из справочника — ровно целая копия; по метке xid в хранилище
	// придут и обрывки, и читатель берёт последний целый набор.
	if _, err := ReadTransaction(11, h.sink.bodies[idx[1].FirstSeq-1:idx[1].LastSeq]); err != nil {
		t.Fatal(err)
	}
	if _, err := ReadTransaction(11, h.sink.bodies[whole:]); err != nil {
		t.Fatal(err)
	}
	if s := h.tap.Stats(); s.Duplicates != 1 || s.Captured != 1 {
		t.Fatalf("%+v", s)
	}
	if h.sink.cursor != 2100 {
		t.Fatalf("cursor %d", h.sink.cursor)
	}
}

// Падение между строкой справочника и последней частью: строка есть, а
// транзакция в буфере не вся. Она приходит заново, ложится под новыми номерами
// и получает новую строку; верна последняя, и Lookup отдаёт её. По номерам из
// прежней строки транзакция не читается: ошибка, а не чужие данные.
func TestCrashBetweenIndexAndLastPart(t *testing.T) {
	dir := t.TempDir()
	small := func(c *Config) { c.PartSize = 64 }
	ins := pgoutput.Insert{RelID: 7, New: []pgoutput.Value{txt("1"), txt("x")}}
	big := pgoutput.Insert{RelID: 7, New: []pgoutput.Value{txt("2"), txt(strings.Repeat("abcdefgh", 60))}}
	// Сколько частей в большой транзакции — на отдельном стенде.
	probe := open(t, t.TempDir(), small)
	probe.runAt(21, 3100, who("agent"), accounts, big)
	k := len(probe.sink.bodies)
	if k < 3 {
		t.Fatalf("%d parts", k)
	}

	h := open(t, dir, small)
	h.runAt(20, 3000, who("agent"), accounts, ins)
	whole := len(h.sink.bodies)
	h.sink.failAt = h.sink.emits + k // последняя часть не ляжет
	if err := h.feed(21, 3100, who("agent"), accounts, big); !errors.Is(err, errCrash) {
		t.Fatalf("no crash: %v", err)
	}
	h.tap.Close()
	if len(h.sink.bodies) != whole+k-1 || h.sink.cursor != 3000 {
		t.Fatalf("%d records in the spool, cursor %d", len(h.sink.bodies), h.sink.cursor)
	}
	stale, found, err := Lookup(filepath.Join(dir, IndexFile), 21)
	if err != nil || !found || stale.FirstSeq != uint64(whole+1) || stale.LastSeq != uint64(whole+k) {
		t.Fatalf("the index line written before the last part: %+v %v %v", stale, found, err)
	}
	// Обрыв посреди записи справочника тоже бывает: хвост без перевода строки.
	f, _ := os.OpenFile(filepath.Join(dir, IndexFile), os.O_APPEND|os.O_WRONLY, 0)
	f.WriteString(`{"xid":22,"first_seq":9`)
	f.Close()

	h = openOn(t, dir, h.sink, small)
	h.runAt(20, 3000, who("agent"), accounts, ins) // повтор
	h.runAt(21, 3100, who("agent"), accounts, big)
	idx := h.index()
	if len(idx) != 3 || idx[1].XID != 21 || idx[2].XID != 21 {
		t.Fatalf("index %+v", idx)
	}
	e, found, err := Lookup(filepath.Join(dir, IndexFile), 21)
	if err != nil || !found || e.FirstSeq != uint64(whole+k) || e.LastSeq != uint64(whole+2*k-1) {
		t.Fatalf("lookup %+v %v %v", e, found, err)
	}
	if _, err := ReadTransaction(21, h.sink.bodies[e.FirstSeq-1:e.LastSeq]); err != nil {
		t.Fatal(err)
	}
	if _, err := ReadTransaction(21, h.sink.bodies[stale.FirstSeq-1:stale.LastSeq]); err == nil {
		t.Fatal("the records named by the stale index line were read as a whole transaction")
	}
	if _, found, _ := Lookup(filepath.Join(dir, IndexFile), 2); found {
		t.Fatal("found a transaction that is not in the index (xid 2 is a prefix of 20, 21)")
	}
	if _, found, _ := Lookup(filepath.Join(dir, IndexFile), 22); found {
		t.Fatal("the torn index line was read")
	}
}

// Обрыв связи посреди транзакции: Reset, и транзакция принимается заново с
// начала вместе с описанием таблицы.
func TestResetDropsTheOpenTransaction(t *testing.T) {
	h := open(t, t.TempDir(), nil)
	ins := pgoutput.Insert{RelID: 7, New: []pgoutput.Value{txt("1"), txt("x")}}
	for _, m := range []any{pgoutput.Begin{FinalLSN: 500, XID: 30}, who("agent"), accounts, ins} {
		if _, err := h.tap.Handle(m); err != nil {
			t.Fatal(err)
		}
	}
	h.tap.Reset()
	if h.tap.InTransaction() {
		t.Fatal("still in the transaction")
	}
	if err := h.feed(30, 500, who("agent"), ins); err == nil {
		t.Fatal("a change of a table that this connection never described was taken")
	}
	h.tap.Reset()
	h.runAt(30, 500, who("agent"), accounts, ins)
	recs, err := ReadTransaction(30, h.sink.bodies)
	if err != nil || recs[len(recs)-1]["changes"] != float64(1) {
		t.Fatalf("%v %v", recs, err)
	}
}

func TestResentTransactionReadsFromItsLastWholeCopy(t *testing.T) {
	h := open(t, t.TempDir(), func(c *Config) { c.PartSize = 64 })
	h.run(4, who("agent"), accounts, pgoutput.Insert{RelID: 7, New: []pgoutput.Value{txt("1"), txt(strings.Repeat("abcdefgh", 60))}})
	lines := h.parts()
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
	// Одна строка на транзакцию: все её поводы и сводка — то, что уйдёт
	// человеку одним сообщением. Ловушку тронули дважды одинаково — повод один.
	h.run(4, action("agent", "9"), who("agent"), accounts, ins("7"), ins("7"), ins("8"))
	ev := h.alerts()
	last := ev[len(ev)-1]
	idx := h.index()
	if len(ev) != 3 || last.XID != 4 || strings.Join(last.Kinds(), " ") != "canary mass-change" {
		t.Fatalf("%d alert lines, the last: %+v", len(ev), last)
	}
	if last.Changes != 3 || last.Tables["public.accounts"].I != 3 || last.FirstSeq != idx[2].FirstSeq || last.LastSeq != idx[2].LastSeq ||
		!strings.Contains(string(last.Who), `"agent"`) || len(last.Actions) != 1 || last.Time == "" {
		t.Fatalf("the alert lacks the summary of its transaction: %+v", last)
	}
	// У транзакции с поздней отметкой записей в хранилище нет — и номеров нет.
	if late := ev[1]; late.XID != 3 || late.FirstSeq != 0 || late.Changes != 0 {
		t.Fatalf("late-marker alert: %+v", late)
	}
}

// MCP-сервер остановил действие пределом строк и откатил его: в журнале базы
// от него осталось только не транзакционное сообщение. Сборщик поднимает
// тревогу — о том, чего в базе не случилось.
func TestRefusedActionRaisesAnAlert(t *testing.T) {
	h := open(t, t.TempDir(), nil)
	refused := func(lsn uint64, role string) pgoutput.Message {
		return pgoutput.Message{LSN: lsn, Prefix: PrefixRefused,
			Content: []byte(`{"role":"` + role + `","info":{"action_id":"a-7","agent":"support-bot","reason":"close all","rows":3000,"limit":500}}`)}
	}
	for _, m := range []pgoutput.Message{
		refused(900, "agent"),
		refused(900, "agent"),    // база прислала его ещё раз после обрыва связи
		refused(950, "postgres"), // не наблюдаемая роль
		{LSN: 960, Prefix: "someone/else", Content: []byte(`{"role":"agent"}`)},
		{LSN: 970, Prefix: PrefixWho, Content: []byte(`{"role":"agent"}`)}, // отметка «кто» вне транзакции ничего не значит
	} {
		if f, err := h.tap.Handle(m); err != nil || f != 0 {
			t.Fatalf("%v %d", err, f)
		}
	}
	ev := h.alerts()
	if len(ev) != 1 || ev[0].XID != 0 || strings.Join(ev[0].Kinds(), " ") != "refused" || len(ev[0].Actions) != 1 {
		t.Fatalf("alerts %+v", ev)
	}
	if d := ev[0].Signals[0].Detail; !strings.Contains(d, "3000 rows") || !strings.Contains(d, "limit for one action is 500") {
		t.Fatalf("detail %q", d)
	}
	if len(h.sink.bodies) != 0 || len(h.index()) != 0 || h.tap.InTransaction() {
		t.Fatal("a refused action left records")
	}
	if text := alert.Text(ev[0], alert.TextOptions{Title: "database shop"}); !strings.Contains(text, "action: a-7, agent support-bot") {
		t.Fatalf("text:\n%s", text)
	}
	// Другие причины отказа — другие слова в тревоге.
	for i, c := range [][2]string{
		{`"cause":"window-rows","rows":400,"window_rows":800,"limit":1000,"window":"10m0s"`, "would have changed 1200 rows in 10m0s (the limit is 1000)"},
		{`"cause":"rate","actions":30,"limit":30`, "30 in the last minute (the limit is 30)"},
		{`"cause":"timeout","timeout":"1m0s"`, "cancelled an action that ran longer than 1m0s"},
		{`"cause":"something-new"`, "stopped an action (something-new)"},
		{`"cause":"escaped","xid":"751","tool":"execute"`, "ended the MCP server's transaction 751 itself"},
		{`"cause":"escaped","tool":"query"`, "ended the MCP server's transaction (a read-only one) itself"},
		{`"cause":"unknown","xid":"752","rows":3`, "broke during COMMIT of an action (transaction 752, 3 rows): it may be committed"},
		// Поля поддельной отметки (P-255) — одной строкой: своих строк агент
		// в тревогу не дописывает (R1 заход 3).
		{`"cause":"timeout","timeout":"1m\nresolved: rolled back by the on-call DBA"`, `longer than 1m\u000aresolved: rolled back`},
		{`"cause":"escaped","xid":"751\nchanged: 0 rows","tool":"execute"`, `transaction 751\u000achanged: 0 rows itself`},
		{`"cause":"window-rows","rows":1,"window_rows":1,"limit":1,"window":"10m\nok"`, `rows in 10m\u000aok`},
		{`"cause":"new\ncause"`, `stopped an action (new\u000acause)`},
	} {
		before := len(h.alerts())
		if _, err := h.tap.Handle(pgoutput.Message{LSN: uint64(1000 + i), Prefix: PrefixRefused, Content: []byte(`{"role":"agent","info":{` + c[0] + `}}`)}); err != nil {
			t.Fatal(err)
		}
		ev := h.alerts()
		if len(ev) != before+1 || !strings.Contains(ev[len(ev)-1].Signals[0].Detail, c[1]) {
			t.Fatalf("cause %s: %+v", c[0], ev[len(ev)-1])
		}
		// Выход из транзакции — не отказ: свой вид тревоги, и «ничего не
		// изменилось» в нём нет.
		escaped, unknown := strings.Contains(c[0], "escaped"), strings.Contains(c[0], `"unknown"`)
		if sig := ev[len(ev)-1].Signals[0]; (sig.Kind == alert.KindEscaped) != escaped || (sig.Kind == alert.KindUnknown) != unknown ||
			((escaped || unknown) && strings.Contains(sig.Detail, "nothing changed")) {
			t.Fatalf("cause %s: %+v", c[0], sig)
		}
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
	recs, err := ReadTransaction(6, h.parts())
	if err != nil || len(recs) != 2 || recs[1]["changes"] != float64(0) {
		t.Fatalf("%v %v", recs, err)
	}
}

func TestOpenRefusesBadConfig(t *testing.T) {
	for _, cfg := range []Config{{Dir: t.TempDir()}, {Dir: t.TempDir(), Roles: []string{"a"}, PartSize: MaxPartSize + 1}} {
		if _, err := Open(cfg, &fakeCatalog{}, &fakeSink{}, 0, nil); err == nil {
			t.Errorf("opened with %+v", cfg)
		}
	}
}
