// Package pgundo строит и применяет откат одной транзакции PostgreSQL по
// до-образам, которые сборщик записал из журнала базы (internal/pgtap).
//
// Три шага, каждый отдельно:
//
//	Build  — из записей журнала: какой каждая тронутая строка была до
//	         транзакции и какой стала после, обратные шаги в обратном порядке;
//	Check  — вопрос базе: что сейчас на месте каждой строки. Шаг годен, если
//	         строка та же, какой её оставила транзакция; изменённая позже —
//	         конфликт, его решает человек;
//	Apply  — годные шаги одной транзакцией. Каждая команда несёт ту же сверку в
//	         своём условии и обязана тронуть ровно столько строк, сколько в ней
//	         шагов: строка, изменённая между Check и Apply, отменяет откат целиком.
//
// Значения колонок идут текстом, как их отдал PostgreSQL, и возвращаются
// литералом с приведением к типу колонки. Отказ построить план — ErrRefused:
// TRUNCATE, таблица без REPLICA IDENTITY FULL или без первичного ключа,
// транзакция не вся.
package pgundo

import (
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"sort"
	"strconv"
	"strings"

	"github.com/Nikolay1994Kaz/evidencestore/internal/pgtap"
	"github.com/Nikolay1994Kaz/evidencestore/internal/pgwire"
)

// ErrRefused — по этим записям откат построить нельзя.
var ErrRefused = errors.New("pgundo: undo refused")

func refuse(format string, args ...any) error {
	return fmt.Errorf("%w: %s", ErrRefused, fmt.Sprintf(format, args...))
}

// Table — таблица, как она описана в журнале.
type Table struct {
	Schema  string   `json:"schema"`
	Name    string   `json:"table"`
	Columns []string `json:"columns"`
	Types   []string `json:"types"`
	PK      []string `json:"pk"`
}

func (t *Table) rel() string { return pgwire.Ident(t.Schema) + "." + pgwire.Ident(t.Name) }

func (t *Table) pkIndex() []int {
	out := make([]int, len(t.PK))
	for i, c := range t.PK {
		out[i] = slices.Index(t.Columns, c)
	}
	return out
}

// Виды шага.
const (
	OpUpdate = "update" // вернуть прежние значения
	OpInsert = "insert" // вернуть удалённую строку
	OpDelete = "delete" // убрать вставленную строку
)

// Step — один обратный шаг: строка таблицы до транзакции (Old) и после (New),
// значения по порядку колонок таблицы. nil — строки не было или не стало.
type Step struct {
	N       int       `json:"step"`
	Op      string    `json:"op"`
	Table   string    `json:"table"`
	Old     []*string `json:"old"`
	New     []*string `json:"new"`
	Touches int       `json:"touches"` // сколько раз транзакция меняла эту строку
}

// Plan — откат одной транзакции.
type Plan struct {
	XID     uint32                  `json:"xid"`
	Who     json.RawMessage         `json:"who,omitempty"`     // отметка роли из журнала
	Actions []json.RawMessage       `json:"actions,omitempty"` // отметки действий MCP
	Undo    json.RawMessage         `json:"undo,omitempty"`    // это сама транзакция отката
	Changes int                     `json:"changes"`           // изменений строк в транзакции
	Noop    int                     `json:"noop"`              // строк без итогового изменения
	Counts  map[string]pgtap.Counts `json:"counts"`
	Tables  map[string]*Table       `json:"tables"`
	Steps   []Step                  `json:"steps"` // в порядке применения
	// OK — номера шагов, которые Check счёл годными: их применит Apply.
	OK []int `json:"apply,omitempty"`
}

type row struct {
	table    string
	old, new []*string
	touches  int
}

// Build разбирает транзакцию xid из тел записей хранилища (частей, которые
// записал сборщик, по порядку номеров) и строит план.
func Build(xid uint32, lines [][]byte) (*Plan, error) {
	recs, err := pgtap.ReadTransaction(xid, lines)
	if err != nil {
		return nil, refuse("%v", err)
	}
	head := recs[0]
	if v, _ := head["v"].(float64); v != pgtap.FormatVersion {
		return nil, refuse("the journal stream is of version %v, this build reads %d", head["v"], pgtap.FormatVersion)
	}
	p := &Plan{XID: xid, Counts: map[string]pgtap.Counts{}, Tables: map[string]*Table{}}
	p.Who, _ = raw(head["who"])
	p.Undo, _ = raw(head["undo"])
	if list, ok := head["actions"].([]any); ok {
		for _, a := range list {
			r, _ := raw(a)
			p.Actions = append(p.Actions, r)
		}
	}
	rels := map[float64]string{}
	live, dead := map[string]*row{}, map[string]*row{}
	var order []*row
	var truncated []string
	for _, r := range recs[1 : len(recs)-1] {
		kind, _ := r["t"].(string)
		switch kind {
		case "R":
			data, _ := json.Marshal(r)
			var t Table
			var id struct {
				ID       float64 `json:"id"`
				Identity string  `json:"identity"`
			}
			if json.Unmarshal(data, &t) != nil || json.Unmarshal(data, &id) != nil || len(t.Columns) != len(t.Types) || len(t.Columns) == 0 {
				return nil, refuse("a table description in the journal is malformed")
			}
			name := t.Schema + "." + t.Name
			if len(t.PK) == 0 {
				return nil, refuse("%s has no primary key: its rows cannot be addressed", name)
			}
			if id.Identity != "f" {
				return nil, refuse("%s is not REPLICA IDENTITY FULL: the journal holds no old rows for it", name)
			}
			if slices.Contains(t.pkIndex(), -1) {
				return nil, refuse("%s: the primary key names a column the journal does not list", name)
			}
			if prev, ok := p.Tables[name]; ok && !slices.Equal(prev.Columns, t.Columns) {
				return nil, refuse("%s was altered inside the transaction (DDL): not handled", name)
			}
			rels[id.ID], p.Tables[name] = name, &t
			continue
		case "M":
			if r["prefix"] == pgtap.PrefixAction {
				a, _ := raw(r["content"])
				p.Actions = append(p.Actions, a)
			}
			continue
		case "T":
			if list, ok := r["tables"].([]any); ok {
				for _, n := range list {
					truncated = append(truncated, fmt.Sprint(n))
				}
			}
			continue
		case "I", "U", "D":
		default:
			return nil, refuse("a journal line of kind %q is unknown to this build", kind)
		}
		p.Changes++
		id, _ := r["r"].(float64)
		name, ok := rels[id]
		if !ok {
			return nil, refuse("change %d is of a table the journal never described", p.Changes)
		}
		t := p.Tables[name]
		if r["partial"] == true {
			return nil, refuse("%s: change %d carries only a part of the old row; the whole row is logged only under REPLICA IDENTITY FULL", name, p.Changes)
		}
		var old, fresh []*string
		if kind != "I" {
			if old, err = image(t, name, r["old"]); err != nil {
				return nil, err
			}
		}
		if kind != "D" {
			if fresh, err = image(t, name, r["new"]); err != nil {
				return nil, err
			}
		}
		c := p.Counts[name]
		key := func(img []*string) string {
			var b strings.Builder
			b.WriteString(name)
			for _, i := range t.pkIndex() {
				b.WriteByte(0)
				if img[i] != nil {
					b.WriteString(*img[i])
				}
			}
			return b.String()
		}
		var rw *row
		var k string
		switch kind {
		case "I":
			c.I++
			k = key(fresh)
			if live[k] != nil {
				return nil, refuse("%s: change %d inserts over a live row: the journal does not add up", name, p.Changes)
			}
			if rw = dead[k]; rw != nil {
				delete(dead, k)
			}
		case "U":
			c.U++
			ko := key(old)
			k = key(fresh)
			if rw = live[ko]; rw != nil {
				delete(live, ko)
				if !same(rw.new, old) {
					return nil, refuse("%s: change %d updates another image of the row than the previous change left", name, p.Changes)
				}
			}
			if k != ko && (live[k] != nil || dead[k] != nil) {
				return nil, refuse("%s: change %d moves a row onto a key used in the same transaction: not handled", name, p.Changes)
			}
		case "D":
			c.D++
			k = key(old)
			if rw = live[k]; rw != nil {
				delete(live, k)
				if !same(rw.new, old) {
					return nil, refuse("%s: change %d deletes another image of the row than the previous change left", name, p.Changes)
				}
			}
			if dead[k] != nil {
				return nil, refuse("%s: the key of change %d is deleted twice by different rows: not handled", name, p.Changes)
			}
		}
		p.Counts[name] = c
		if rw == nil {
			rw = &row{table: name, old: old}
			order = append(order, rw)
		}
		rw.new = fresh
		rw.touches++
		if kind == "D" {
			dead[k] = rw
		} else {
			live[k] = rw
		}
	}
	if n, _ := recs[len(recs)-1]["changes"].(float64); int(n) != p.Changes {
		return nil, refuse("the journal names %v changes in the transaction and holds %d: it is not all here", recs[len(recs)-1]["changes"], p.Changes)
	}
	if len(truncated) > 0 {
		sort.Strings(truncated)
		return nil, refuse("the transaction ran TRUNCATE on %s: the rows are not in the journal, a row-by-row undo is impossible (restore from a backup)",
			strings.Join(slices.Compact(truncated), ", "))
	}
	// Обратный порядок: что транзакция тронула последним, возвращается первым
	// (удалил детей, потом родителя — вернуть родителя, потом детей).
	for i := len(order) - 1; i >= 0; i-- {
		rw := order[i]
		st := Step{N: len(p.Steps) + 1, Table: rw.table, Old: rw.old, New: rw.new, Touches: rw.touches}
		switch {
		case rw.old == nil && rw.new == nil, rw.old != nil && rw.new != nil && same(rw.old, rw.new):
			p.Noop++ // вставил и удалил, или сам вернул прежние значения
			continue
		case rw.old == nil:
			st.Op = OpDelete
		case rw.new == nil:
			st.Op = OpInsert
		default:
			st.Op = OpUpdate
		}
		p.Steps = append(p.Steps, st)
	}
	return p, nil
}

func raw(v any) (json.RawMessage, bool) {
	if v == nil {
		return nil, false
	}
	b, err := json.Marshal(v)
	return b, err == nil
}

func image(t *Table, name string, v any) ([]*string, error) {
	list, ok := v.([]any)
	if !ok || len(list) != len(t.Columns) {
		return nil, refuse("%s: a row in the journal has %d values for %d columns", name, len(list), len(t.Columns))
	}
	out := make([]*string, len(list))
	for i, x := range list {
		switch x := x.(type) {
		case nil:
		case string:
			out[i] = &x
		default:
			return nil, refuse("%s.%s: the journal holds this value not as text (%v): not handled", name, t.Columns[i], x)
		}
	}
	return out, nil
}

func same(a, b []*string) bool {
	return slices.EqualFunc(a, b, func(x, y *string) bool { return (x == nil) == (y == nil) && (x == nil || *x == *y) })
}

// Key — первичный ключ строки шага текстом: "id=6".
func (p *Plan) Key(s Step) string {
	t := p.Tables[s.Table]
	img := s.New
	if s.Op == OpInsert {
		img = s.Old
	}
	var parts []string
	for _, i := range t.pkIndex() {
		parts = append(parts, t.Columns[i]+"="+deref(img[i]))
	}
	return strings.Join(parts, ", ")
}

func deref(s *string) string {
	if s == nil {
		return "NULL"
	}
	return *s
}

// ---------------------------------------------------------------- SQL

// group — соседние шаги одного вида над одной таблицей: одна команда.
type group struct {
	t     *Table
	op    string
	steps []Step
}

func (p *Plan) groups(only map[int]bool) []group {
	var out []group
	for _, s := range p.Steps {
		if only != nil && !only[s.N] {
			continue
		}
		if n := len(out); n > 0 && out[n-1].op == s.Op && out[n-1].t == p.Tables[s.Table] {
			out[n-1].steps = append(out[n-1].steps, s)
		} else {
			out = append(out, group{t: p.Tables[s.Table], op: s.Op, steps: []Step{s}})
		}
	}
	return out
}

// sides — какие образы нужны команде: правке оба, возврату удалённой старый,
// уборке вставленной новый.
func (g group) sides() string {
	switch g.op {
	case OpUpdate:
		return "no"
	case OpInsert:
		return "o"
	}
	return "n"
}

// values — шаги списком VALUES: step, новый образ (n0..), старый образ (o0..).
// Тип — в первой строке: остальные PostgreSQL приводит к нему сам.
func (g group) values() string {
	var b strings.Builder
	b.WriteString("(VALUES\n  ")
	for i, s := range g.steps {
		if i > 0 {
			b.WriteString(",\n  ")
		}
		b.WriteString("(" + strconv.Itoa(s.N))
		for _, side := range g.sides() {
			img := s.New
			if side == 'o' {
				img = s.Old
			}
			for c, v := range img {
				b.WriteString(", ")
				if v == nil {
					b.WriteString("NULL")
				} else {
					b.WriteString(pgwire.Literal(*v))
				}
				if i == 0 {
					b.WriteString("::" + g.t.Types[c])
				}
			}
		}
		b.WriteString(")")
	}
	b.WriteString("\n) AS w(step")
	for _, side := range g.sides() {
		for c := range g.t.Columns {
			fmt.Fprintf(&b, ", %c%d", side, c)
		}
	}
	b.WriteString(")")
	return b.String()
}

func (g group) join(alias string, side byte) string {
	var parts []string
	for _, i := range g.t.pkIndex() {
		parts = append(parts, fmt.Sprintf("%s.%s = w.%c%d", alias, pgwire.Ident(g.t.Columns[i]), side, i))
	}
	return strings.Join(parts, " AND ")
}

func (g group) same(side byte) string {
	var parts []string
	for i, c := range g.t.Columns {
		parts = append(parts, fmt.Sprintf("t.%s IS NOT DISTINCT FROM w.%c%d", pgwire.Ident(c), side, i))
	}
	return strings.Join(parts, " AND ")
}

func (g group) missing() string { return "t." + pgwire.Ident(g.t.PK[0]) + " IS NULL" }

// Состояния шага по ответу базы.
const (
	StateOK       = "ok"        // строка такая, какой её оставила транзакция: шаг годен
	StateDone     = "done"      // строка уже в прежнем виде
	StateGone     = "gone"      // конфликт: строки больше нет
	StateChanged  = "changed"   // конфликт: строку изменили после транзакции
	StateExists   = "exists"    // конфликт: под ключом удалённой строки снова есть строка
	StateKeyTaken = "key-taken" // конфликт: прежний ключ занят другой строкой
)

// Status — что база ответила про шаг. Current — строка, какая она сейчас
// (to_jsonb), у конфликтов.
type Status struct {
	Step    int
	State   string
	Current json.RawMessage
}

// Conflict — шаг не годен и не сделан: решать человеку.
func (s Status) Conflict() bool { return s.State != StateOK && s.State != StateDone }

// DB — соединение с базой (у *pgwire.Conn такой метод есть).
type DB interface {
	Query(sql string) ([]pgwire.Result, error)
}

// Check спрашивает базу про каждый шаг и запоминает годные в p.OK.
// Ответы — по порядку шагов. База не меняется.
func (p *Plan) Check(db DB) ([]Status, error) {
	for name, t := range p.Tables {
		cols := slices.Clone(t.Columns)
		sort.Strings(cols)
		var lits []string
		for _, c := range cols {
			lits = append(lits, pgwire.Literal(c))
		}
		reg := "to_regclass(" + pgwire.Literal(t.rel()) + ")"
		res, err := db.Query("SELECT " + reg + " IS NOT NULL, (SELECT array_agg(attname::text ORDER BY attname::text) FROM pg_attribute WHERE attrelid = " + reg +
			" AND attnum > 0 AND NOT attisdropped) = ARRAY[" + strings.Join(lits, ", ") + "]::text[]")
		if err != nil {
			return nil, err
		}
		if len(res) != 1 || len(res[0].Rows) != 1 {
			return nil, fmt.Errorf("pgundo: check of %s: unexpected answer", name)
		}
		switch r := res[0].Rows[0]; {
		case deref(r[0]) != "t":
			return nil, refuse("%s no longer exists: an undo by row images does not fit", name)
		case deref(r[1]) != "t":
			return nil, refuse("%s has other columns now than in the journal: an undo by row images does not fit", name)
		}
	}
	byStep := map[int]Status{}
	for _, g := range p.groups(nil) {
		var state, differs string
		side := byte('n')
		switch g.op {
		case OpUpdate:
			var o, n []string
			for _, i := range g.t.pkIndex() {
				o, n = append(o, fmt.Sprintf("w.o%d", i)), append(n, fmt.Sprintf("w.n%d", i))
			}
			taken := "(ROW(" + strings.Join(o, ", ") + ") IS DISTINCT FROM ROW(" + strings.Join(n, ", ") + ") AND EXISTS (SELECT 1 FROM " + g.t.rel() + " x WHERE " + g.join("x", 'o') + "))"
			state = "CASE WHEN " + g.missing() + " THEN 'gone' WHEN " + taken + " THEN 'key-taken' WHEN " + g.same('n') + " THEN 'ok' WHEN " + g.same('o') + " THEN 'done' ELSE 'changed' END"
			differs = "NOT (" + g.missing() + ") AND NOT (" + g.same('n') + ") AND NOT (" + g.same('o') + ")"
		case OpInsert:
			side = 'o'
			state = "CASE WHEN " + g.missing() + " THEN 'ok' WHEN " + g.same('o') + " THEN 'done' ELSE 'exists' END"
			differs = "NOT (" + g.missing() + ") AND NOT (" + g.same('o') + ")"
		default:
			state = "CASE WHEN " + g.missing() + " THEN 'done' WHEN " + g.same('n') + " THEN 'ok' ELSE 'changed' END"
			differs = "NOT (" + g.missing() + ") AND NOT (" + g.same('n') + ")"
		}
		res, err := db.Query("SELECT w.step, " + state + ", CASE WHEN " + differs + " THEN to_jsonb(t)::text END\nFROM " + g.values() +
			"\nLEFT JOIN " + g.t.rel() + " t ON " + g.join("t", side))
		if err != nil {
			return nil, err
		}
		if len(res) != 1 {
			return nil, errors.New("pgundo: check: unexpected answer")
		}
		for _, r := range res[0].Rows {
			n, err := strconv.Atoi(deref(r[0]))
			if err != nil || len(r) != 3 {
				return nil, errors.New("pgundo: check: unexpected row")
			}
			st := Status{Step: n, State: deref(r[1])}
			if r[2] != nil {
				st.Current = json.RawMessage(*r[2])
			}
			byStep[n] = st
		}
	}
	out := make([]Status, 0, len(p.Steps))
	p.OK = nil
	for _, s := range p.Steps {
		st, ok := byStep[s.N]
		if !ok {
			return nil, fmt.Errorf("pgundo: check: the database did not answer about step %d", s.N)
		}
		if st.State == StateOK {
			p.OK = append(p.OK, s.N)
		}
		out = append(out, st)
	}
	return out, nil
}

// ErrChanged — строка изменилась после Check: откат не применён вовсе.
var ErrChanged = errors.New("pgundo: a row changed after the check; nothing is applied")

// Apply применяет шаги p.OK одной транзакцией и отдаёт её номер. marker —
// кто и почему откатывает; он уходит в журнал базы отметкой evidence.mark_undo
// и делает сам откат записью хранилища. Команда, тронувшая не столько строк,
// сколько в ней шагов, отменяет всё: ErrChanged.
func (p *Plan) Apply(db DB, marker any) (xid string, err error) {
	if len(p.OK) == 0 {
		return "", errors.New("pgundo: no step to apply: run the check first")
	}
	only := map[int]bool{}
	for _, n := range p.OK {
		only[n] = true
	}
	mark, err := json.Marshal(marker)
	if err != nil {
		return "", err
	}
	if _, err := db.Query("BEGIN"); err != nil {
		return "", err
	}
	defer func() {
		if err != nil {
			db.Query("ROLLBACK")
		}
	}()
	// Отметка — первой: в журнале базы она встанет перед изменениями строк.
	if _, err := db.Query("SELECT evidence.mark_undo(" + pgwire.Literal(string(mark)) + "::json)"); err != nil {
		return "", fmt.Errorf("the undo marker could not be set (is the database prepared with escollect -setup-sql?): %w", err)
	}
	res, err := db.Query("SELECT pg_current_xact_id()::text")
	if err != nil {
		return "", err
	}
	if len(res) == 1 && len(res[0].Rows) == 1 {
		xid = deref(res[0].Rows[0][0])
	}
	for _, g := range p.groups(only) {
		var cols, olds, sets []string
		for i, c := range g.t.Columns {
			cols = append(cols, pgwire.Ident(c))
			olds = append(olds, fmt.Sprintf("w.o%d", i))
			sets = append(sets, fmt.Sprintf("%s = w.o%d", pgwire.Ident(c), i))
		}
		var stmt string
		switch g.op {
		case OpInsert:
			stmt = "INSERT INTO " + g.t.rel() + " (" + strings.Join(cols, ", ") + ")\n  SELECT " + strings.Join(olds, ", ") + "\n  FROM " + g.values()
		case OpDelete:
			stmt = "DELETE FROM " + g.t.rel() + " t\n  USING " + g.values() + "\n  WHERE " + g.join("t", 'n') + " AND " + g.same('n')
		default:
			stmt = "UPDATE " + g.t.rel() + " t SET " + strings.Join(sets, ", ") + "\n  FROM " + g.values() + "\n  WHERE " + g.join("t", 'n') + " AND " + g.same('n')
		}
		res, err := db.Query(stmt)
		if err != nil {
			return "", err
		}
		touched := -1
		if len(res) == 1 {
			touched = affected(res[0].Tag)
		}
		if touched != len(g.steps) {
			return "", fmt.Errorf("%w: %s.%s: steps %d–%d expected %d rows, the statement touched %d", ErrChanged,
				g.t.Schema, g.t.Name, g.steps[0].N, g.steps[len(g.steps)-1].N, len(g.steps), touched)
		}
	}
	if _, err := db.Query("COMMIT"); err != nil {
		return "", err
	}
	return xid, nil
}

// affected — число строк из метки команды: "UPDATE 3", "INSERT 0 3", "DELETE 3".
func affected(tag string) int {
	f := strings.Fields(tag)
	if len(f) == 0 {
		return -1
	}
	n, err := strconv.Atoi(f[len(f)-1])
	if err != nil {
		return -1
	}
	return n
}
