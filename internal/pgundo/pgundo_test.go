package pgundo

import (
	"bytes"
	"compress/gzip"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/Nikolay1994Kaz/evidencestore/internal/pgwire"
)

type m = map[string]any

func rel(id int, table string, mod ...func(m)) m {
	r := m{"t": "R", "id": id, "schema": "public", "table": table, "identity": "f", "columns": []string{"id", "v"}, "types": []string{"integer", "text"}, "pk": []string{"id"}}
	for _, f := range mod {
		f(r)
	}
	return r
}

func ch(kind string, r int, old, fresh []any) m {
	line := m{"t": kind, "r": r}
	if old != nil {
		line["old"] = old
	}
	if fresh != nil {
		line["new"] = fresh
	}
	return line
}

// journal — строки журнала espgtap для транзакции 7: поток в gzip, порезанный по size байт.
func journal(size int, header m, lines ...m) [][]byte {
	n := 0
	for _, l := range lines {
		if k := l["t"]; k == "I" || k == "U" || k == "D" {
			n++
		}
	}
	head := m{"t": "H", "v": 1, "xid": 7}
	for k, v := range header {
		head[k] = v
	}
	tail := m{"t": "C", "changes": n}
	if c, ok := header["_count"]; ok {
		tail["changes"] = c
		delete(head, "_count")
	}
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	for _, l := range append(append([]m{head}, lines...), tail) {
		b, _ := json.Marshal(l)
		gz.Write(append(b, '\n'))
	}
	gz.Close()
	data := buf.Bytes()
	var out [][]byte
	for i := 1; len(data) > 0; i++ {
		k := min(size, len(data))
		out = append(out, fmt.Appendf(nil, `{"xid":7,"part":%d,"last":%t,"gz":"%s"}`, i, k == len(data), base64.StdEncoding.EncodeToString(data[:k])))
		data = data[k:]
	}
	return out
}

func build(t *testing.T, lines ...m) *Plan {
	t.Helper()
	p, err := Build(7, journal(1<<30, nil, lines...))
	if err != nil {
		t.Fatal(err)
	}
	return p
}

func v(vals ...any) []any { return vals }

func str(s []*string) string {
	var parts []string
	for _, x := range s {
		parts = append(parts, deref(x))
	}
	return strings.Join(parts, ",")
}

func TestBuild(t *testing.T) {
	cases := []struct {
		name  string
		lines []m
		want  string // шаги: вид таблица старый→новый
		noop  int
	}{
		{"parent before children", []m{rel(1, "child"), ch("D", 1, v("1", "c"), nil), rel(2, "parent"), ch("D", 2, v("9", "p"), nil)},
			"insert parent 9,p→; insert child 1,c→", 0},
		{"a row touched twice is one step", []m{rel(1, "t"), ch("U", 1, v("1", "a"), v("1", "b")), ch("U", 1, v("1", "b"), v("1", "c"))}, "update t 1,a→1,c", 0},
		{"insert then delete is nothing", []m{rel(1, "t"), ch("I", 1, nil, v("1", "a")), ch("D", 1, v("1", "a"), nil)}, "", 1},
		{"insert then update removes the final row", []m{rel(1, "t"), ch("I", 1, nil, v("1", "a")), ch("U", 1, v("1", "a"), v("1", "b"))}, "delete t →1,b", 0},
		{"update then delete restores the first image", []m{rel(1, "t"), ch("U", 1, v("1", "a"), v("1", "b")), ch("D", 1, v("1", "b"), nil)}, "insert t 1,a→", 0},
		{"delete then insert of one key is an update", []m{rel(1, "t"), ch("D", 1, v("1", "a"), nil), ch("I", 1, nil, v("1", "z"))}, "update t 1,a→1,z", 0},
		{"a key change is followed", []m{rel(1, "t"), ch("U", 1, v("1", "a"), v("2", "a")), ch("U", 1, v("2", "a"), v("2", "b"))}, "update t 1,a→2,b", 0},
		{"values put back by the transaction itself", []m{rel(1, "t"), ch("U", 1, v("1", "a"), v("1", "b")), ch("U", 1, v("1", "b"), v("1", "a"))}, "", 1},
		{"null survives", []m{rel(1, "t"), ch("U", 1, v("1", nil), v("1", "b"))}, "update t 1,NULL→1,b", 0},
	}
	for _, c := range cases {
		p := build(t, c.lines...)
		var got []string
		for _, s := range p.Steps {
			got = append(got, fmt.Sprintf("%s %s %s→%s", s.Op, strings.TrimPrefix(s.Table, "public."), str(s.Old), str(s.New)))
		}
		if g := strings.Join(got, "; "); g != c.want || p.Noop != c.noop {
			t.Errorf("%s:\n got %q (noop %d)\nwant %q (noop %d)", c.name, g, p.Noop, c.want, c.noop)
		}
	}
}

func TestBuildMarkersAndCounts(t *testing.T) {
	p, err := Build(7, journal(1<<30, m{"who": m{"role": "agent"}, "actions": []m{{"info": m{"action_id": "42"}}}},
		rel(1, "t"), ch("I", 1, nil, v("1", "a")), ch("U", 1, v("1", "a"), v("1", "b")), m{"t": "M", "prefix": "evidence/action", "content": m{"info": m{"action_id": "43"}}}))
	if err != nil {
		t.Fatal(err)
	}
	if len(p.Actions) != 2 || !strings.Contains(string(p.Actions[1]), "43") || !strings.Contains(string(p.Who), "agent") || p.Changes != 2 || p.Counts["public.t"].U != 1 {
		t.Fatalf("%+v", p)
	}
	if p.Key(p.Steps[0]) != "id=1" {
		t.Fatal(p.Key(p.Steps[0]))
	}
}

func TestBuildFromManyPartsAndAResentCopy(t *testing.T) {
	lines := []m{rel(1, "t")}
	for i := 0; i < 200; i++ {
		lines = append(lines, ch("I", 1, nil, v(fmt.Sprint(i), strings.Repeat("x", 40)+fmt.Sprint(i*7919))))
	}
	parts := journal(64, nil, lines...)
	if len(parts) < 5 {
		t.Fatalf("%d parts", len(parts))
	}
	if p, err := Build(7, parts); err != nil || len(p.Steps) != 200 {
		t.Fatal(err)
	}
	// Первая копия оборвана на третьей части, потом транзакция целиком.
	if p, err := Build(7, append(append([][]byte{}, parts[:3]...), parts...)); err != nil || len(p.Steps) != 200 {
		t.Fatal(err)
	}
	for drop := range parts {
		rest := append(append([][]byte{}, parts[:drop]...), parts[drop+1:]...)
		if _, err := Build(7, rest); !errors.Is(err, ErrRefused) {
			t.Fatalf("built without part %d: %v", drop+1, err)
		}
	}
}

func TestBuildRefuses(t *testing.T) {
	up := ch("U", 1, v("1", "a"), v("1", "b"))
	cases := map[string][][]byte{
		"TRUNCATE":              journal(1<<30, nil, rel(1, "t"), m{"t": "T", "tables": []string{"public.t"}}),
		"REPLICA IDENTITY FULL": journal(1<<30, nil, rel(1, "t", func(r m) { r["identity"] = "d" }), up),
		"only a part":           journal(1<<30, nil, rel(1, "t"), m{"t": "U", "r": 1, "new": v("1", "b"), "partial": true}),
		"no primary key":        journal(1<<30, nil, rel(1, "t", func(r m) { r["pk"] = []string{} }), up),
		"another image":         journal(1<<30, nil, rel(1, "t"), up, ch("U", 1, v("1", "x"), v("1", "c"))),
		"not as text":           journal(1<<30, nil, rel(1, "t"), ch("U", 1, v("1", "a"), v("1", m{"b64": "AA=="}))),
		"not all here":          journal(1<<30, m{"_count": 2}, rel(1, "t"), up),
		"never described":       journal(1<<30, nil, ch("I", 9, nil, v("1", "a"))),
		"altered inside":        journal(1<<30, nil, rel(1, "t"), up, rel(1, "t", func(r m) { r["columns"] = []string{"id", "w"} })),
		"version":               journal(1<<30, m{"v": 2}, rel(1, "t"), up),
		"not 8":                 nil,
	}
	for want, lines := range cases {
		xid := uint32(7)
		if lines == nil {
			xid, lines = 8, journal(1<<30, nil, rel(1, "t"), up)
		}
		if _, err := Build(xid, lines); !errors.Is(err, ErrRefused) || !strings.Contains(err.Error(), want) {
			t.Errorf("%s: %v", want, err)
		}
	}
}

// fakeDB записывает запросы и отвечает заготовленным.
type fakeDB struct {
	log    []string
	answer func(sql string) ([]pgwire.Result, error)
}

func (d *fakeDB) Query(sql string) ([]pgwire.Result, error) {
	d.log = append(d.log, sql)
	return d.answer(sql)
}

func rows(vals ...[]string) []pgwire.Result {
	var out [][]*string
	for _, r := range vals {
		var row []*string
		for _, x := range r {
			if x == "<null>" {
				row = append(row, nil)
			} else {
				row = append(row, &x)
			}
		}
		out = append(out, row)
	}
	return []pgwire.Result{{Rows: out}}
}

func TestCheckAndApply(t *testing.T) {
	p := build(t, rel(1, "t"), ch("U", 1, v("1", "a"), v("1", "b")), ch("U", 1, v("2", "it's"), v("2", nil)), ch("D", 1, v("3", "c"), nil), ch("I", 1, nil, v("4", "d")))
	// Шаги в обратном порядке: 1 — убрать вставленную 4, 2 — вернуть удалённую 3, 3 — строка 2, 4 — строка 1.
	tag := map[string]string{"INSERT": "INSERT 0 1", "DELETE": "DELETE 1", "UPDATE": "UPDATE 1"}
	db := &fakeDB{answer: func(sql string) ([]pgwire.Result, error) {
		switch {
		case strings.Contains(sql, "to_regclass"):
			return rows([]string{"t", "t"}), nil
		case strings.HasPrefix(sql, "SELECT w.step") && strings.Contains(sql, "'exists'"):
			return rows([]string{"2", "ok", "<null>"}), nil
		case strings.HasPrefix(sql, "SELECT w.step") && strings.Contains(sql, "'key-taken'"):
			return rows([]string{"3", "changed", `{"id":2,"v":"human"}`}, []string{"4", "ok", "<null>"}), nil
		case strings.HasPrefix(sql, "SELECT w.step"):
			return rows([]string{"1", "done", "<null>"}), nil
		case strings.Contains(sql, "pg_current_xact_id"):
			return rows([]string{"900"}), nil
		}
		return []pgwire.Result{{Tag: tag[strings.Fields(sql)[0]]}}, nil
	}}
	st, err := p.Check(db)
	if err != nil {
		t.Fatal(err)
	}
	if len(st) != 4 || st[0].State != StateDone || st[1].State != StateOK || !st[2].Conflict() || string(st[2].Current) != `{"id":2,"v":"human"}` || st[3].State != StateOK {
		t.Fatalf("%+v", st)
	}
	if fmt.Sprint(p.OK) != "[2 4]" {
		t.Fatalf("apply %v", p.OK)
	}
	// Тип — в первой строке VALUES, кавычка удвоена, NULL без кавычек.
	var check string
	for _, q := range db.log {
		if strings.Contains(q, "'key-taken'") {
			check = q
		}
	}
	for _, want := range []string{"(3, '2'::integer, NULL::text, '2'::integer, 'it''s'::text)", "(4, '1', 'b', '1', 'a')", `LEFT JOIN "public"."t" t ON t."id" = w.n0`} {
		if !strings.Contains(check, want) {
			t.Errorf("check SQL lacks %q:\n%s", want, check)
		}
	}

	db.log = nil
	xid, err := p.Apply(db, m{"by": "nikolay"})
	if err != nil || xid != "900" {
		t.Fatal(xid, err)
	}
	// Транзакция, отметка первой, шаг 2 (вернуть удалённую), шаг 4 (вернуть значения), фиксация. Шаги 1 и 3 не тронуты.
	if len(db.log) != 6 || db.log[0] != "BEGIN" || !strings.HasPrefix(db.log[1], `SELECT evidence.mark_undo('{"by":"nikolay"}'`) ||
		!strings.HasPrefix(db.log[3], `INSERT INTO "public"."t"`) || !strings.HasPrefix(db.log[4], `UPDATE "public"."t" t SET "id" = w.o0, "v" = w.o1`) ||
		!strings.Contains(db.log[4], `WHERE t."id" = w.n0 AND t."id" IS NOT DISTINCT FROM w.n0 AND t."v" IS NOT DISTINCT FROM w.n1`) || db.log[5] != "COMMIT" {
		t.Fatalf("%q", db.log)
	}

	// Строка изменилась после сверки: команда тронула не столько строк — откат отменён целиком.
	tag["UPDATE"] = "UPDATE 0"
	db.log = nil
	if _, err := p.Apply(db, m{}); !errors.Is(err, ErrChanged) || db.log[len(db.log)-1] != "ROLLBACK" {
		t.Fatalf("%v %q", err, db.log)
	}
}

func TestCheckRefusesAChangedTable(t *testing.T) {
	p := build(t, rel(1, "t"), ch("U", 1, v("1", "a"), v("1", "b")))
	for want, answer := range map[string][]string{"no longer exists": {"f", "<null>"}, "other columns": {"t", "f"}} {
		db := &fakeDB{answer: func(string) ([]pgwire.Result, error) { return rows(answer), nil }}
		if _, err := p.Check(db); !errors.Is(err, ErrRefused) || !strings.Contains(err.Error(), want) {
			t.Errorf("%s: %v", want, err)
		}
	}
	if _, err := (&Plan{}).Apply(&fakeDB{}, nil); err == nil {
		t.Error("applied a plan that was not checked")
	}
}

func TestAffected(t *testing.T) {
	for tag, want := range map[string]int{"UPDATE 3": 3, "INSERT 0 5": 5, "DELETE 0": 0, "": -1, "BEGIN": -1} {
		if got := affected(tag); got != want {
			t.Errorf("%q: %d", tag, got)
		}
	}
}

func TestConflictsAreDescribed(t *testing.T) {
	p := build(t, rel(1, "t"), ch("U", 1, v("1", "a"), v("1", "b")), ch("D", 1, v("3", "c"), nil))
	// Шаг 1 — вернуть удалённую строку 3, шаг 2 — вернуть значения строке 1.
	cs := p.Conflicts([]Status{
		{Step: 1, State: StateExists, Current: json.RawMessage(`{"id":3,"v":"human"}`)},
		{Step: 2, State: StateChanged, Current: json.RawMessage(`{"id":1,"v":null}`)},
	})
	if len(cs) != 2 || cs[0].Op != OpInsert || cs[0].Key != "id=3" || cs[1].Key != "id=1" {
		t.Fatalf("%+v", cs)
	}
	if got := strings.Join(cs[0].Lines(), "|"); got != "the transaction deleted: id=«3», v=«c»|now under this key:      id=«3», v=«human»" {
		t.Error(got)
	}
	// У правки — только колонка, которую транзакция меняла; NULL в базе сейчас.
	if got := strings.Join(cs[1].Lines(), "|"); got != "v: was «a», the transaction left «b», now NULL" {
		t.Error(got)
	}
	if ok, done, bad := Tally([]Status{{State: StateOK}, {State: StateDone}, {State: StateGone}}); ok != 1 || done != 1 || bad != 1 {
		t.Error(ok, done, bad)
	}
	if s := p.Summary(); s.Steps != 2 || s.Restore != 1 || s.Reinsert != 1 {
		t.Errorf("%+v", s)
	}
}
