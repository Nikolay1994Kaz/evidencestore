package pgundo

import (
	"bytes"
	"compress/gzip"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"slices"
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

// journal — записи сборщика для транзакции 7: поток в gzip, порезанный по size байт.
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
		case strings.Contains(sql, "pg_attribute"):
			return rows([]string{"id", ""}, []string{"v", ""}), nil
		case strings.HasPrefix(sql, "SELECT count(*) FILTER"): // сверка после отката: все строки на месте и равны до-образам
			return rows([]string{"0", "0", "0"}), nil
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
	done, err := p.Apply(db, m{"by": "nikolay"})
	if err != nil || done.XID != "900" || done.Steps != 2 || done.Order != OrderJournal || done.Differ != nil {
		t.Fatal(done, err)
	}
	// Транзакция, отметка первой, шаг 2 (вернуть удалённую — со своим прежним номером, даже если колонка
	// GENERATED ALWAYS AS IDENTITY), шаг 4 (вернуть значения: пишется только колонка, которую транзакция
	// меняла), сверка обеих команд с до-образами, фиксация. Шаги 1 и 3 не тронуты.
	if len(db.log) != 8 || db.log[0] != "BEGIN" || !strings.HasPrefix(db.log[1], `SELECT evidence.mark_undo('{"by":"nikolay"}'`) ||
		!strings.HasPrefix(db.log[3], `INSERT INTO "public"."t" ("id", "v") OVERRIDING SYSTEM VALUE`) || !strings.HasPrefix(db.log[4], `UPDATE "public"."t" t SET "v" = w.o1`+"\n") ||
		!strings.Contains(db.log[4], `WHERE t."id" = w.n0 AND t."id"::text IS NOT DISTINCT FROM w.n0::text AND t."v"::text IS NOT DISTINCT FROM w.n1::text`) ||
		!strings.Contains(db.log[5], `LEFT JOIN "public"."t" t ON t."id" = w.o0`) || !strings.Contains(db.log[6], `NOT (t."v"::text IS NOT DISTINCT FROM w.o1::text)`) || db.log[7] != "COMMIT" {
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
	for want, answer := range map[string][][]string{
		"no longer exists": {},
		"other columns now than in the journal (v is gone)": {{"id", ""}, {"w", ""}},
		"other columns now than in the journal (w is new)":  {{"id", ""}, {"v", ""}, {"w", ""}},
	} {
		db := &fakeDB{answer: func(string) ([]pgwire.Result, error) { return rows(answer...), nil }}
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

// Что о таблице знает только каталог: колонку, которую база считает сама, откат
// не пишет; колонку типа без оператора равенства сравнивает текстом.
func TestCheckTakesGeneratedAndUncomparableColumnsFromTheCatalog(t *testing.T) {
	wide := func(r m) {
		r["columns"], r["types"] = []string{"id", "v", "double", "place"}, []string{"integer", "text", "integer", "point"}
	}
	p := build(t, rel(1, "t", wide), ch("U", 1, v("1", "a", "2", "(0,0)"), v("1", "b", "4", "(1,1)")), ch("D", 1, v("3", "c", "6", "(3,3)"), nil))
	db := &fakeDB{answer: func(sql string) ([]pgwire.Result, error) {
		switch {
		case strings.Contains(sql, "pg_attribute"):
			// В таблице есть ещё колонка, которой в журнале нет: генерируемая, до 18-й версии база их не шлёт.
			return rows([]string{"id", ""}, []string{"v", ""}, []string{"double", "s"}, []string{"place", ""}, []string{"shadow", "s"}), nil
		case sql == "SELECT NULL::point IS NOT DISTINCT FROM NULL::point":
			return nil, &pgwire.PgError{Severity: "ERROR", Code: "42883", Message: "operator does not exist: point = point"}
		case strings.HasPrefix(sql, "SELECT w.step") && strings.Contains(sql, "'exists'"):
			return rows([]string{"1", "ok", "<null>"}), nil
		case strings.HasPrefix(sql, "SELECT w.step"):
			return rows([]string{"2", "ok", "<null>"}), nil
		case strings.Contains(sql, "pg_current_xact_id"):
			return rows([]string{"900"}), nil
		case strings.HasPrefix(sql, "SELECT count(*) FILTER"):
			return rows([]string{"0", "0", "0", "0", "0"}), nil
		}
		return []pgwire.Result{{Tag: map[string]string{"INSERT": "INSERT 0 1", "UPDATE": "UPDATE 1"}[strings.Fields(sql)[0]]}}, nil
	}}
	if _, err := p.Check(db); err != nil {
		t.Fatal(err)
	}
	tab := p.Tables["public.t"]
	if fmt.Sprint(tab.Generated) != "[double]" || fmt.Sprint(tab.AsText) != "[place]" {
		t.Fatalf("generated %v, as text %v", tab.Generated, tab.AsText)
	}
	// План переживает запись в файл: apply читает его оттуда.
	data, _ := json.Marshal(p)
	p = &Plan{}
	if err := json.Unmarshal(data, p); err != nil {
		t.Fatal(err)
	}
	db.log = nil
	if _, err := p.Apply(db, m{}); err != nil {
		t.Fatal(err)
	}
	all := strings.Join(db.log, "\n")
	for _, want := range []string{
		`INSERT INTO "public"."t" ("id", "v", "place") OVERRIDING SYSTEM VALUE` + "\n  SELECT w.o0, w.o1, w.o3",
		`UPDATE "public"."t" t SET "v" = w.o1, "place" = w.o3` + "\n",
		`t."double"::text IS NOT DISTINCT FROM w.n2::text AND t."place"::text IS NOT DISTINCT FROM w.n3::text`,
		`NOT (t."place"::text IS NOT DISTINCT FROM w.o3::text)`,
	} {
		if !strings.Contains(all, want) {
			t.Errorf("the undo lacks %q:\n%s", want, all)
		}
	}
	if strings.Contains(all, `"double" = `) || strings.Contains(all, `"shadow"`) {
		t.Errorf("the undo writes a generated column:\n%s", all)
	}
}

// Каскад внешнего ключа: в журнале родитель удалён раньше детей, и порядок,
// обратный журналу, возвращает детей первыми — база отказывает. Вторая попытка
// идёт по внешним ключам: родитель, потом дети; правки — под замком и со сверкой
// заранее.
func TestApplyFallsBackToTheOrderOfForeignKeys(t *testing.T) {
	p := build(t,
		rel(2, "parent"), ch("D", 2, v("9", "p"), nil), // оператор агента
		rel(1, "child"), ch("D", 1, v("1", "c"), nil), ch("D", 1, v("2", "c"), nil), // каскад
		rel(3, "other"), ch("U", 3, v("5", "a"), v("6", "a")), ch("I", 3, nil, v("7", "new")))
	p.OK = []int{1, 2, 3, 4, 5}
	violation := &pgwire.PgError{Severity: "ERROR", Code: "23503", Message: `insert or update on table "child" violates foreign key constraint`}
	attempt, locked := 0, "1"
	db := &fakeDB{}
	db.answer = func(sql string) ([]pgwire.Result, error) {
		switch {
		case sql == "BEGIN":
			attempt++
		case strings.Contains(sql, "pg_current_xact_id"):
			return rows([]string{fmt.Sprint(900 + attempt)}), nil
		case strings.HasPrefix(sql, `INSERT INTO "public"."child"`) && attempt == 1:
			return nil, violation
		case strings.Contains(sql, "confdeltype"): // ключей с действием при удалении на таблицы плана нет
			return rows(), nil
		case strings.Contains(sql, "pg_constraint"):
			return rows([]string{"public.child", "public.parent"}), nil
		case strings.Contains(sql, "FOR UPDATE OF t"):
			return rows([]string{locked}), nil
		case strings.HasPrefix(sql, "SELECT count(*) FILTER"):
			return rows([]string{"0", "0", "0"}), nil
		case strings.HasPrefix(sql, "SELECT count(*) FROM"): // убранные строки: их нет
			return rows([]string{"0"}), nil
		case strings.HasPrefix(sql, `INSERT INTO "public"."child"`):
			return []pgwire.Result{{Tag: "INSERT 0 2"}}, nil
		case strings.HasPrefix(sql, "UPDATE") && attempt == 2 && !strings.Contains(sql, "NOT EXISTS"):
			return []pgwire.Result{{Tag: "UPDATE 0"}}, nil // под новым ключом строки уже нет: её вернул каскад
		}
		return []pgwire.Result{{Tag: map[string]string{"INSERT": "INSERT 0 1", "UPDATE": "UPDATE 1", "DELETE": "DELETE 1"}[strings.Fields(sql)[0]]}}, nil
	}
	done, err := p.Apply(db, m{})
	if err != nil || done.Order != OrderKeys || done.XID != "902" || done.Steps != 5 {
		t.Fatal(done, err)
	}
	// Что шло после отмены первой попытки: какая команда над какой таблицей.
	table := regexp.MustCompile(`"public"\."(\w+)"`)
	var second []string
	for _, q := range db.log[slices.Index(db.log, "ROLLBACK")+1:] {
		what := map[string]string{"INSERT": "insert", "UPDATE": "update", "DELETE": "delete"}[strings.Fields(q)[0]]
		switch {
		case strings.Contains(q, "confdeltype"):
			second = append(second, "references")
			continue
		case strings.Contains(q, "pg_constraint"):
			second = append(second, "keys")
			continue
		case strings.Contains(q, "FOR UPDATE OF t"):
			what = "lock"
		case strings.Contains(q, "NOT EXISTS"):
			what = "update-moved"
			// Строка под прежним ключом, ещё не равная до-образу, а под новым ключом её уже нет.
			if !strings.Contains(q, `WHERE ROW(w.o0) IS DISTINCT FROM ROW(w.n0) AND t."id" = w.o0 AND NOT (t."id"::text IS NOT DISTINCT FROM w.o0::text AND t."v"::text IS NOT DISTINCT FROM w.o1::text)`+
				` AND NOT EXISTS (SELECT 1 FROM "public"."other" x WHERE x."id" = w.n0)`) {
				t.Fatalf("the statement for rows a cascade moved back:\n%s", q)
			}
		case strings.HasPrefix(q, "SELECT count(*)"):
			what = "after"
		case what == "":
			continue
		}
		second = append(second, what+" "+table.FindStringSubmatch(q)[1])
	}
	// Замок и сверка заранее — у правки и уборки; родитель раньше детей; правка — двумя командами
	// (первая — по прежнему ключу); уборка вставленной — последней; в конце сверка с до-образами.
	want := "keys, lock other, lock other, references, insert parent, insert child, update-moved other, update other, delete other, after parent, after child, after other, after other"
	if got := strings.Join(second, ", "); got != want {
		t.Fatalf("the second attempt:\n got %s\nwant %s", got, want)
	}
	// Сверка в этом порядке — в замке, а не в условии команды: команда берёт строку по ключу.
	for _, q := range db.log[slices.Index(db.log, "ROLLBACK")+1:] {
		if (strings.HasPrefix(q, "UPDATE") && !strings.Contains(q, "NOT EXISTS") && !strings.HasSuffix(q, `WHERE t."id" = w.n0`)) ||
			(strings.HasPrefix(q, "DELETE") && !strings.HasSuffix(q, `WHERE t."id" = w.n0`)) {
			t.Fatalf("a statement of the second attempt carries a guard:\n%s", q)
		}
	}

	// Строка шага изменилась после сверки: под замок встало меньше строк — откат отменён.
	attempt, locked, db.log = 0, "0", nil
	if _, err := p.Apply(db, m{}); !errors.Is(err, ErrChanged) || db.log[len(db.log)-1] != "ROLLBACK" || !strings.Contains(err.Error(), "in the order of the journal") {
		t.Fatalf("%v %q", err, db.log[len(db.log)-1])
	}
	// Отказ не по ограничению второй попытки не даёт.
	db.answer = func(sql string) ([]pgwire.Result, error) {
		if strings.HasPrefix(sql, "INSERT") {
			return nil, &pgwire.PgError{Severity: "ERROR", Code: "42501", Message: "permission denied"}
		}
		return rows([]string{"900"}), nil
	}
	db.log = nil
	if _, err := p.Apply(db, m{}); err == nil || strings.Count(strings.Join(db.log, " "), "BEGIN") != 1 {
		t.Fatalf("%v %q", err, db.log)
	}
}

// Сверка после отката: строки на месте нет — откат отменён; значения переписал
// триггер — откат применён, а колонки названы.
func TestApplyChecksTheRowsAfterTheUndo(t *testing.T) {
	p := build(t, rel(1, "t"), ch("U", 1, v("1", "a"), v("1", "b")), ch("U", 1, v("2", "a"), v("2", "b")), ch("I", 1, nil, v("4", "d")))
	p.OK = []int{1, 2, 3}
	after, left := []string{"0", "0", "2"}, "0"
	db := &fakeDB{answer: func(sql string) ([]pgwire.Result, error) {
		switch {
		case strings.HasPrefix(sql, "SELECT count(*) FILTER"):
			return rows(after), nil
		case strings.HasPrefix(sql, "SELECT count(*) FROM"):
			return rows([]string{left}), nil
		case strings.Contains(sql, "pg_current_xact_id"):
			return rows([]string{"900"}), nil
		}
		return []pgwire.Result{{Tag: map[string]string{"UPDATE": "UPDATE 2", "DELETE": "DELETE 1"}[strings.Fields(sql)[0]]}}, nil
	}}
	done, err := p.Apply(db, m{})
	if err != nil || len(done.Differ) != 1 || done.Differ[0] != (Difference{Table: "public.t", Column: "v", Rows: 2}) || db.log[len(db.log)-1] != "COMMIT" {
		t.Fatalf("%+v %v", done, err)
	}
	// Каждый случай задаёт оба ответа базы сам: порядок случаев не важен, и
	// поломка одного не протекает в другой.
	for _, tc := range []struct {
		name  string
		after []string
		left  string
	}{
		{"put back are not there", []string{"1", "0", "0"}, "0"},
		{"removed are still there", []string{"0", "0", "0"}, "1"},
	} {
		after, left = tc.after, tc.left
		db.log = nil
		if _, err := p.Apply(db, m{}); err == nil || !strings.Contains(err.Error(), tc.name) || db.log[len(db.log)-1] != "ROLLBACK" {
			t.Errorf("%s: %v, then %s", tc.name, err, db.log[len(db.log)-1])
		}
	}
}

func TestRanks(t *testing.T) {
	// c → b → a; d ссылается на a и на c; e и f — друг на друга (круг); g — ни на кого.
	r := ranks([][2]string{{"b", "a"}, {"c", "b"}, {"d", "a"}, {"d", "c"}, {"e", "f"}, {"f", "e"}})
	if r["a"] != 0 || r["b"] != 1 || r["c"] != 2 || r["d"] != 3 || r["g"] != 0 || r["e"]+r["f"] != 1 {
		t.Fatalf("%v", r)
	}
}

// Строка, которую вставила транзакция, обросла ссылками: кто-то позже добавил
// строки, которые ссылаются на неё с ON DELETE CASCADE. Убрать её — молча удалить
// их. Сверка называет такой шаг конфликтом; строки, которые откат уберёт сам, не в счёт.
func TestCheckFlagsARowThatOthersReferTo(t *testing.T) {
	pet := func(r m) { r["columns"], r["types"] = []string{"id", "owner_id"}, []string{"integer", "integer"} }
	p := build(t, rel(2, "owner"), ch("I", 2, nil, v("9", "o")), rel(1, "pet", pet), ch("I", 1, nil, v("1", "9")))
	// Шаг 1 — убрать питомца 1, шаг 2 — убрать хозяина 9. На питомца ссылается таблица leaf, которой в плане нет.
	var asked []string
	db := &fakeDB{answer: func(sql string) ([]pgwire.Result, error) {
		switch {
		case strings.Contains(sql, "confdeltype"):
			return rows([]string{"public.owner", "pet", "n", `["owner_id"]`, `["id"]`, `["public.pet"]`},
				[]string{"public.pet", "leaf", "c", `["pet_id"]`, `["id"]`, `[]`}), nil
		case strings.Contains(sql, "pg_attribute") && strings.Contains(sql, `"pet"`):
			return rows([]string{"id", ""}, []string{"owner_id", ""}), nil
		case strings.Contains(sql, "pg_attribute"):
			return rows([]string{"id", ""}, []string{"v", ""}), nil
		case strings.HasPrefix(sql, "SELECT w.step, CASE") && strings.Contains(sql, `"pet"`):
			return rows([]string{"1", "ok", "<null>"}), nil
		case strings.HasPrefix(sql, "SELECT w.step, CASE"):
			return rows([]string{"2", "ok", "<null>"}), nil
		case strings.HasPrefix(sql, "SELECT w.step, count(*)"):
			asked = append(asked, sql)
			switch {
			case strings.Contains(sql, "JOIN leaf x"): // три чужие строки ссылаются на питомца 1
				return rows([]string{"1", "3"}), nil
			case strings.Contains(sql, "AS own("): // на хозяина ссылается только свой питомец: он не в счёт
				return rows(), nil
			}
			return rows([]string{"2", "1"}), nil // питомец стал конфликтом и хозяина больше не освобождает
		}
		return rows([]string{"t"}), nil
	}}
	st, err := p.Check(db)
	if err != nil {
		t.Fatal(err)
	}
	if st[0].State != StateReferenced || st[1].State != StateReferenced || p.OK != nil ||
		st[0].Detail != "3 rows of leaf refer to it: ON DELETE CASCADE would delete them" || st[1].Detail != "1 rows of pet refer to it: ON DELETE SET NULL would clear their reference" {
		t.Fatalf("%+v, apply %v", st, p.OK)
	}
	// Первый круг: хозяин — с оговоркой про своего питомца, питомец — без оговорок. Второй круг: хозяин уже без неё.
	if len(asked) != 3 ||
		!strings.Contains(asked[0], "(2, '9'::integer)\n) AS w(step, k0)\nJOIN pet x ON x.\"owner_id\" = w.k0\nWHERE NOT EXISTS (SELECT 1 FROM (VALUES\n  ('1'::integer)\n) AS own(p0) WHERE x.\"id\" = own.p0)") ||
		!strings.Contains(asked[1], "(1, '1'::integer)\n) AS w(step, k0)\nJOIN leaf x ON x.\"pet_id\" = w.k0\nGROUP BY") ||
		strings.Contains(asked[2], "AS own(") || !strings.Contains(asked[2], "JOIN pet x") {
		t.Fatalf("the questions about referring rows:\n%s", strings.Join(asked, "\n---\n"))
	}
	// Свои строки из двух секций одной таблицы: ключ один, а колонки у секций стоят по-разному.
	swapped := func(r m) { r["columns"], r["types"] = []string{"owner_id", "id"}, []string{"integer", "integer"} }
	parts := build(t, rel(2, "owner"), ch("I", 2, nil, v("9", "o")), rel(1, "pet_1", pet), ch("I", 1, nil, v("1", "9")), rel(3, "pet_2", swapped), ch("I", 3, nil, v("9", "2")))
	q := parts.dependents(reference{Table: "public.owner", Child: "pet", Cols: []string{"owner_id"}, RefCols: []string{"id"}}, parts.Steps[2:], parts.Steps[:2])
	if !strings.Contains(q, "(VALUES\n  ('2'::integer),\n  ('1')\n) AS own(p0) WHERE x.\"id\" = own.p0)") {
		t.Fatalf("own rows of two partitions:\n%s", q)
	}
	cs := p.Conflicts(st)
	if len(cs) != 2 || cs[1].Detail != st[1].Detail || strings.Join(cs[1].Lines(), "|") != "the transaction inserted: id=«9», v=«o»|1 rows of pet refer to it: ON DELETE SET NULL would clear their reference" {
		t.Fatalf("%+v", cs)
	}
}

// То же перед самой уборкой, в транзакции отката: на строку сослались между
// сверкой и откатом. Строки встают под замок, чужая ссылка отменяет откат целиком.
func TestApplyRefusesToRemoveARowThatOthersReferTo(t *testing.T) {
	p := build(t, rel(2, "parent"), ch("I", 2, nil, v("9", "p")))
	p.OK = []int{1}
	referring := [][]string{}
	db := &fakeDB{}
	db.answer = func(sql string) ([]pgwire.Result, error) {
		switch {
		case strings.Contains(sql, "confdeltype"):
			return rows([]string{"public.parent", "child", "c", `["parent_id"]`, `["id"]`, `[]`}), nil
		case strings.Contains(sql, "pg_constraint"):
			return rows(), nil
		case strings.Contains(sql, "FOR UPDATE OF t"):
			return rows([]string{"1"}), nil
		case strings.HasPrefix(sql, "SELECT w.step, count(*)"):
			return rows(referring...), nil
		case strings.HasPrefix(sql, "SELECT count(*) FROM"):
			return rows([]string{"0"}), nil
		case strings.Contains(sql, "pg_current_xact_id"):
			return rows([]string{"900"}), nil
		}
		return []pgwire.Result{{Tag: "DELETE 1"}}, nil
	}
	// Никто не ссылается: замок, вопрос о ссылках, уборка, сверка.
	if _, err := p.Apply(db, m{}); err != nil {
		t.Fatal(err)
	}
	var what []string
	for _, q := range db.log {
		switch {
		case strings.Contains(q, "confdeltype"):
			what = append(what, "references")
		case strings.Contains(q, "FOR UPDATE OF t"):
			what = append(what, "lock")
		case strings.HasPrefix(q, "SELECT w.step, count(*)"):
			what = append(what, "referring")
		case strings.HasPrefix(q, "DELETE"):
			what = append(what, "delete")
		}
	}
	if got := strings.Join(what, ", "); got != "references, lock, referring, delete" {
		t.Fatalf("the undo of an insert: %s", got)
	}
	// Сослались: не убрано ничего. Порядок по внешним ключам пробуется (ребёнок мог стоять в плане позже), итог тот же.
	referring, db.log = [][]string{{"1", "2"}}, nil
	_, err := p.Apply(db, m{})
	all := strings.Join(db.log, "\n")
	if !errors.Is(err, ErrChanged) || !strings.Contains(err.Error(), "have rows of child referring to them, and ON DELETE CASCADE would delete them") ||
		strings.Count(err.Error(), "referring to them") != 1 ||
		strings.Contains(all, "DELETE FROM") || strings.Count(all, "BEGIN") != 2 || db.log[len(db.log)-1] != "ROLLBACK" {
		t.Fatalf("%v\n%s", err, all)
	}
}
