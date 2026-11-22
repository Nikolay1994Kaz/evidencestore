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
//	         В конце той же транзакции строки сверяются с до-образами: что после
//	         отката не равно им (значения переписал триггер таблицы), названо.
//
// Триггеры и внешние ключи при откате работают как обычно: откат — обычная
// транзакция владельца, целостность проверяет база. Порядок шагов — обратный
// журналу. Где база на нём отказывает по ограничению (часть изменений сделал
// каскад внешнего ключа: в журнале они идут после родителя), Apply пробует
// второй порядок — по внешним ключам из каталога.
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
	"maps"
	"slices"
	"sort"
	"strconv"
	"strings"

	"github.com/Nikolay1994Kaz/evidencestore/internal/pgtap"
	"github.com/Nikolay1994Kaz/evidencestore/internal/pgwire"
)

// ErrRefused — по этим записям откат построить нельзя.
var ErrRefused = errors.New("pgundo: undo refused")

// ErrCommitUnknown — связь оборвалась на COMMIT отката: он мог
// зафиксироваться. Applied, возвращённый с этой ошибкой, — то, что откат успел
// сделать в своей транзакции.
var ErrCommitUnknown = errors.New("pgundo: the connection broke during COMMIT of the undo: it may be committed; check the transaction before repeating it")

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
	// Что знает только каталог базы; дописывает Check.
	// Generated — колонки журнала, которые база считает сама (GENERATED …
	// STORED, с PostgreSQL 18 они идут в журнал): откат их не пишет.
	Generated []string `json:"generated,omitempty"`
	// AsText — колонки типа без оператора равенства (point, json, xml). С
	// образом текстом сравниваются все колонки (equal); эти — ещё и потому,
	// что иначе нельзя.
	AsText []string `json:"as_text,omitempty"`
}

func (t *Table) rel() string { return pgwire.Ident(t.Schema) + "." + pgwire.Ident(t.Name) }

// name — имя таблицы, как в плане: schema.table.
func (t *Table) name() string { return t.Schema + "." + t.Name }

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

	limit func(rows int) error
}

// XactRows — сколько строк, по статистике базы, изменили транзакции сеанса,
// ещё не сброшенные в общую статистику (вид pg_stat_xact_user_tables, взятый
// прямо из функций; таблицы — всё, что создано после initdb).
const XactRows = "(SELECT coalesce(sum(pg_stat_get_xact_tuples_inserted(oid) + pg_stat_get_xact_tuples_updated(oid) + pg_stat_get_xact_tuples_deleted(oid)), 0) " +
	"FROM pg_catalog.pg_class WHERE oid >= 16384 AND relkind IN ('r', 'm', 'p'))::bigint"

// LimitRows — проверка перед фиксацией отката: f получает, сколько строк он
// изменил по статистике транзакции — с тем, что изменили триггеры и каскады
// (отложенные срабатывают раньше счёта). Ошибка f — откат не зафиксирован.
// Так MCP-сервер держит откат под теми же пределами, что действие: по шагам
// плана триггер на вставку, менявший 500 строк, шёл как одна (T заход 2).
func (p *Plan) LimitRows(f func(rows int) error) { p.limit = f }

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

// values — шаги списком VALUES: step, новый образ (n0..), старый образ (o0..) —
// те, что нужны команде шага. Тип — в первой строке: остальные PostgreSQL
// приводит к нему сам.
func (g group) values() string { return g.valuesOf(g.sides()) }

// valuesOf — то же с названными образами: "n", "o" или "no".
func (g group) valuesOf(sides string) string {
	var b strings.Builder
	b.WriteString("(VALUES\n  ")
	for i, s := range g.steps {
		if i > 0 {
			b.WriteString(",\n  ")
		}
		b.WriteString("(" + strconv.Itoa(s.N))
		for _, side := range sides {
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
	for _, side := range sides {
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
	for i := range g.t.Columns {
		parts = append(parts, g.t.equal(i, side))
	}
	return strings.Join(parts, " AND ")
}

// equal — колонка i строки t такая же, как образ side. Сравнивается текст, а
// не равенство типа: у citext, недетерминированных правил сортировки, numeric
// (1.0 и 1.00), interval ('1 day' и '24 hours') равенство грубее значения, и
// правку человека, сменившую только регистр или шкалу, сверка считала
// «строкой, какой её оставила транзакция» — откат её перезаписывал (P-248).
// Образ в VALUES приведён к типу колонки, так что обе стороны пишет одна
// функция вывода в одном сеансе; у типа без оператора равенства (AsText)
// иначе и нельзя.
func (t *Table) equal(i int, side byte) string {
	col, img := "t."+pgwire.Ident(t.Columns[i]), fmt.Sprintf("w.%c%d", side, i)
	return col + "::text IS NOT DISTINCT FROM " + img + "::text"
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
	// StateReferenced — конфликт: на вставленную строку ссылаются строки, которые
	// откат не возвращает и не убирает. Убрать её — и внешний ключ удалит их
	// (ON DELETE CASCADE) или перепишет им ссылку (SET NULL, SET DEFAULT).
	StateReferenced = "referenced"
)

// Status — что база ответила про шаг. Current — строка, какая она сейчас
// (to_jsonb), у конфликтов. Detail — кто ссылается на строку (StateReferenced).
type Status struct {
	Step    int
	State   string
	Current json.RawMessage
	Detail  string
}

// Conflict — шаг не годен и не сделан: решать человеку.
func (s Status) Conflict() bool { return s.State != StateOK && s.State != StateDone }

// DB — соединение с базой (у *pgwire.Conn такой метод есть).
type DB interface {
	Query(sql string) ([]pgwire.Result, error)
}

// catalog сверяет таблицы плана с каталогом базы и дописывает в план то, что
// знает только каталог: какие колонки база считает сама и какие сравнивать
// текстом.
func (p *Plan) catalog(db DB) error {
	noEquality := map[string]bool{} // тип → оператора равенства у него нет
	for _, name := range p.tableNames() {
		t := p.Tables[name]
		res, err := db.Query("SELECT a.attname::text, a.attgenerated::text FROM pg_attribute a WHERE a.attrelid = to_regclass(" + pgwire.Literal(t.rel()) +
			") AND a.attnum > 0 AND NOT a.attisdropped ORDER BY a.attnum")
		if err != nil {
			return err
		}
		if len(res) != 1 {
			return fmt.Errorf("pgundo: check of %s: unexpected answer", name)
		}
		if len(res[0].Rows) == 0 {
			return refuse("%s no longer exists: an undo by row images does not fit", name)
		}
		// Колонки журнала должны быть в таблице все. В таблице сверх журнала —
		// только генерируемые: их база в журнал может не слать, а считает сама.
		generated, extra := map[string]bool{}, map[string]bool{}
		for _, r := range res[0].Rows {
			if len(r) != 2 {
				return fmt.Errorf("pgundo: check of %s: unexpected row", name)
			}
			generated[deref(r[0])] = deref(r[1]) != ""
			extra[deref(r[0])] = true
		}
		t.Generated, t.AsText = nil, nil
		for _, c := range t.Columns {
			if !extra[c] {
				return refuse("%s has other columns now than in the journal (%s is gone): an undo by row images does not fit", name, c)
			}
			delete(extra, c)
			if generated[c] {
				t.Generated = append(t.Generated, c)
			}
		}
		for _, c := range slices.Sorted(maps.Keys(extra)) {
			if !generated[c] {
				return refuse("%s has other columns now than in the journal (%s is new): an undo by row images does not fit", name, c)
			}
		}
		for i, typ := range t.Types {
			no, known := noEquality[typ]
			if !known {
				// Спрашиваем саму базу: оператор она ищет здесь так же, как в сверке.
				_, err := db.Query("SELECT NULL::" + typ + " IS NOT DISTINCT FROM NULL::" + typ)
				var pg *pgwire.PgError
				switch {
				case errors.As(err, &pg) && pg.Code == "42883": // undefined_function: оператора нет
					no = true
				case err != nil:
					return err
				}
				noEquality[typ] = no
			}
			if no {
				t.AsText = append(t.AsText, t.Columns[i])
			}
		}
	}
	return nil
}

func (p *Plan) tableNames() []string { return slices.Sorted(maps.Keys(p.Tables)) }

// keyChanged — транзакция сменила строке первичный ключ.
func (g group) keyChanged() string {
	var o, n []string
	for _, i := range g.t.pkIndex() {
		o, n = append(o, fmt.Sprintf("w.o%d", i)), append(n, fmt.Sprintf("w.n%d", i))
	}
	return "ROW(" + strings.Join(o, ", ") + ") IS DISTINCT FROM ROW(" + strings.Join(n, ", ") + ")"
}

// Path — путь поиска своих проверочных запросов сеанса: только pg_catalog и
// pg_temp последним (не названный pg_temp ищется первым для типов).
const Path = "pg_catalog, pg_temp"

// session готовит сеанс сверки и отката. Функция или оператор с точным
// совпадением типов выигрывает у системных при любом порядке пути (класс
// CVE-2018-1058): `=(varchar, varchar)` агента в public перехватывал сверку
// ключа, а esundo запускает человек правами владельца (R2 заход 2). Но и путь
// только из pg_catalog нельзя: триггеры таблиц владельца в откате идут с путём
// сеанса, и аудит с именем таблицы без схемы падал (R2 заход 3). Поэтому путь
// — pg_catalog, путь сеанса, pg_temp последним, — и откат отказывает, если в
// какой-либо схеме этого пути CREATE есть у кого-то, кроме её владельца (и
// суперпользователей): «добавить схему в путь — значит доверять всем, у кого
// там CREATE» (документация PostgreSQL после CVE-2018-1058). Проверять одну
// роль транзакции мало: она — роль MCP-сервера, а у агента своя (DECISIONS,
// п. 39). Типы колонок сборщик пишет со схемой. Путь ставится на весь сеанс:
// следующий запрос человека в esundo — тоже наш, MCP-сервер начинает вызов с
// DISCARD ALL.
func (p *Plan) session(db DB) error {
	res, err := db.Query("SELECT pg_catalog.array_to_string(pg_catalog.current_schemas(false), ',')")
	if err != nil {
		return err
	}
	var schemas []string
	if len(res) == 1 && len(res[0].Rows) == 1 && res[0].Rows[0][0] != nil && *res[0].Rows[0][0] != "" {
		schemas = strings.Split(*res[0].Rows[0][0], ",")
	}
	if _, err := db.Query("SELECT pg_catalog.set_config('search_path', '" + Path + "', false)"); err != nil {
		return err
	}
	path := []string{"pg_catalog"}
	for _, n := range schemas {
		if n != "pg_catalog" {
			path = append(path, pgwire.Ident(n))
		}
	}
	if len(path) == 1 {
		return nil // путь — только Path
	}
	lits := make([]string, 0, len(schemas))
	for _, n := range schemas {
		lits = append(lits, pgwire.Literal(n))
	}
	// Кто может CREATE в схеме пути — сам или через роль, которой может
	// стать (SET ROLE); владелец схемы может всегда (право у себя он вернёт
	// сам — R2-2, заход 2). В счёт — роли со входом: группа без входа сама не
	// действует, её члены — в счёт через неё (R2-8). Доверенные — те, чей код
	// и так идёт в этом сеансе или кому своя функция ничего не прибавит:
	// суперпользователи, владелец базы, владельцы таблиц плана (их триггеры
	// идут в откате) и те, кто может стать ролью этого сеанса. Владелец схемы
	// сам по себе — не доверенный: схему в пути (хоть с именем роли сеанса,
	// "$user") мог завести и агент, получив CREATE на базе (R1-4, заход 2), а
	// член роли-владельца — тоже владелец (R2-1). Имён хватит пяти.
	owners := make([]string, 0, len(p.Tables))
	for _, t := range p.Tables {
		owners = append(owners, "pg_catalog.to_regclass("+pgwire.Literal(t.rel())+")")
	}
	if len(owners) == 0 {
		owners = append(owners, "NULL")
	}
	res, err = db.Query("SELECT string_agg(x, ', ') FROM (SELECT DISTINCT format('%I can CREATE in schema %I', g.rolname, n.nspname) || " +
		"CASE WHEN h.oid <> g.oid THEN format(' (as %I)', h.rolname) ELSE '' END AS x " +
		"FROM pg_namespace n CROSS JOIN pg_roles g JOIN pg_roles h ON pg_has_role(g.oid, h.oid, 'MEMBER') " +
		"WHERE n.nspname IN (" + strings.Join(lits, ", ") + ") AND n.nspname <> 'pg_catalog' " +
		"AND (has_schema_privilege(h.oid, n.oid, 'CREATE') OR h.oid = n.nspowner) " +
		"AND g.rolcanlogin AND NOT g.rolsuper " +
		"AND g.oid <> (SELECT datdba FROM pg_database WHERE datname = current_database()) " +
		"AND g.oid NOT IN (SELECT relowner FROM pg_class WHERE oid IN (" + strings.Join(owners, ", ") + ")) " +
		"AND NOT pg_has_role(g.oid, current_user, 'MEMBER') ORDER BY 1 LIMIT 5) AS w")
	if err != nil {
		return err
	}
	if len(res) == 1 && len(res[0].Rows) == 1 && res[0].Rows[0][0] != nil {
		return refuse("%s, and that schema is on the search_path of this session: a function or operator created there would run in the check "+
			"and the undo with the rights of this session. Take the schema off the search_path of this role (ALTER ROLE … SET search_path) "+
			"or let only its owner create there. If such a role could create there before, look at what it made: its functions and operators "+
			"stay, whoever owns them now", *res[0].Rows[0][0])
	}
	path = append(path, "pg_temp")
	_, err = db.Query("SELECT pg_catalog.set_config('search_path', " + pgwire.Literal(strings.Join(path, ", ")) + ", false)")
	return err
}

// Check спрашивает базу про каждый шаг и запоминает годные в p.OK.
// Ответы — по порядку шагов. База не меняется.
func (p *Plan) Check(db DB) ([]Status, error) {
	if err := p.session(db); err != nil {
		return nil, err
	}
	if err := p.catalog(db); err != nil {
		return nil, err
	}
	byStep := map[int]Status{}
	for _, g := range p.groups(nil) {
		var state, differs string
		side := byte('n')
		switch g.op {
		case OpUpdate:
			taken := "(" + g.keyChanged() + " AND EXISTS (SELECT 1 FROM " + g.t.rel() + " x WHERE " + g.join("x", 'o') + "))"
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
	for _, s := range p.Steps {
		if _, ok := byStep[s.N]; !ok {
			return nil, fmt.Errorf("pgundo: check: the database did not answer about step %d", s.N)
		}
	}
	if err := p.referenced(db, byStep); err != nil {
		return nil, err
	}
	out := make([]Status, 0, len(p.Steps))
	p.OK = nil
	for _, s := range p.Steps {
		st := byStep[s.N]
		if st.State == StateOK {
			p.OK = append(p.OK, s.N)
		}
		out = append(out, st)
	}
	return out, nil
}

// ErrChanged — строка изменилась после Check: откат не применён вовсе.
var ErrChanged = errors.New("pgundo: a row changed after the check; nothing is applied")

// Порядок шагов в Apply.
const (
	OrderJournal = "journal" // обратный журналу
	OrderKeys    = "keys"    // по внешним ключам из каталога
)

// Applied — что сделал Apply.
type Applied struct {
	XID   string `json:"xid"`   // транзакция отката
	Steps int    `json:"steps"` // применено шагов
	// Rows — сколько строк изменила транзакция отката по статистике базы, с
	// триггерами и каскадами; считается, когда задан LimitRows.
	Rows  int    `json:"rows,omitempty"`
	Order string `json:"order"` // OrderJournal или OrderKeys
	// Differ — где строки после отката не равны до-образам: то, что откат
	// вернул, переписали триггеры таблицы. Пусто — строки равны до-образам.
	Differ []Difference `json:"differ,omitempty"`
}

// Difference — колонка, в которой строки после отката не равны до-образам.
type Difference struct {
	Table  string `json:"table"`
	Column string `json:"column"`
	Rows   int    `json:"rows"`
}

// Apply применяет шаги p.OK одной транзакцией. marker — кто и почему
// откатывает; он уходит в журнал базы отметкой evidence.mark_undo и делает сам
// откат записью хранилища. Строка, изменённая после Check, отменяет всё:
// ErrChanged.
//
// Сначала — порядок, обратный журналу: он верен всегда, когда каждое изменение
// транзакции делал её собственный оператор. Отказ базы по ограничению
// целостности (SQLSTATE класса 23) значит, что часть изменений сделал каскад
// внешнего ключа: тогда вторая попытка, по внешним ключам из каталога.
func (p *Plan) Apply(db DB, marker any) (*Applied, error) {
	if len(p.OK) == 0 {
		return nil, errors.New("pgundo: no step to apply: run the check first")
	}
	only := map[int]bool{}
	for _, n := range p.OK {
		only[n] = true
	}
	mark, err := json.Marshal(marker)
	if err != nil {
		return nil, err
	}
	if err := p.session(db); err != nil {
		return nil, err
	}
	out, err := p.apply(db, string(mark), p.groups(only), OrderJournal)
	var pg *pgwire.PgError
	// errReferenced в порядке журнала — ещё не приговор: при отложенном внешнем
	// ключе ребёнок мог быть вставлен раньше родителя, и его шаг стоит позже.
	if !(errors.As(err, &pg) && strings.HasPrefix(pg.Code, "23")) && !errors.Is(err, errReferenced) {
		return out, err
	}
	first := err
	ordered, err := p.byKeys(db, only)
	if err != nil {
		return nil, fmt.Errorf("%w (and the order by foreign keys could not be built: %v)", first, err)
	}
	if out, err = p.apply(db, string(mark), ordered, OrderKeys); err != nil {
		if errors.Is(err, errReferenced) && errors.Is(first, errReferenced) {
			return nil, err // обе попытки упёрлись в одно и то же: дважды не повторяем
		}
		return nil, fmt.Errorf("%w (in the order of the journal: %v)", err, first)
	}
	return out, nil
}

func (p *Plan) apply(db DB, mark string, groups []group, order string) (_ *Applied, err error) {
	if _, err := db.Query("BEGIN"); err != nil {
		return nil, err
	}
	defer func() {
		if err != nil {
			db.Query("ROLLBACK")
		}
	}()
	// Отметка — первой: в журнале базы она встанет перед изменениями строк.
	if _, err := db.Query("SELECT evidence.mark_undo(" + pgwire.Literal(mark) + "::json)"); err != nil {
		return nil, fmt.Errorf("the undo marker could not be set (is the database prepared with escollect -setup-sql?): %w", err)
	}
	out := &Applied{Order: order}
	res, err := db.Query("SELECT pg_current_xact_id()::xid::text") // 32 бита — как в журнале базы, справочнике и тревогах
	if err != nil {
		return nil, err
	}
	if len(res) == 1 && len(res[0].Rows) == 1 {
		out.XID = deref(res[0].Rows[0][0])
	}
	// Счёт до шагов: статистика сеанса держит и не сброшенные прошлые
	// транзакции, строки отката — разность.
	var before int
	if p.limit != nil {
		if before, err = count(db, "SELECT "+XactRows); err != nil {
			return nil, err
		}
	}
	if order == OrderKeys {
		// В этом порядке строку шага может изменить не её команда, а каскад от
		// команды родителя: сверка в условии команды и счёт тронутых строк уже
		// ничего не доказывают. Поэтому сверка — заранее и с замком: строки,
		// которые откат правит и убирает, сейчас такие, какими их оставила
		// транзакция, и до конца отката их не изменит никто, кроме него.
		for _, g := range groups {
			if g.op == OpInsert {
				continue
			}
			n, err := count(db, "SELECT count(*) FROM (SELECT 1 FROM "+g.t.rel()+" t\n  JOIN "+g.valuesOf("n")+"\n  ON "+g.join("t", 'n')+" AND "+g.same('n')+" FOR UPDATE OF t) locked")
			if err != nil {
				return nil, err
			}
			if n != len(g.steps) {
				return nil, g.changed(n)
			}
		}
	}
	// Внешние ключи, по которым уборка вставленной строки задела бы чужие.
	var tables []string
	for _, g := range groups {
		if g.op == OpDelete && !slices.Contains(tables, g.t.name()) {
			tables = append(tables, g.t.name())
		}
	}
	refs, err := p.references(db, tables)
	if err != nil {
		return nil, err
	}
	for _, g := range groups {
		if g.op == OpDelete {
			if err := p.guardReferences(db, g, refs, order); err != nil {
				return nil, err
			}
		}
		touched := 0
		for _, stmt := range g.statements(order) {
			res, err := db.Query(stmt)
			if err != nil {
				return nil, err
			}
			if len(res) != 1 || affected(res[0].Tag) < 0 {
				return nil, fmt.Errorf("pgundo: %s.%s: unexpected answer to an undo statement", g.t.Schema, g.t.Name)
			}
			touched += affected(res[0].Tag)
		}
		if order == OrderJournal && touched != len(g.steps) {
			return nil, g.changed(touched)
		}
		out.Steps += len(g.steps)
	}
	if p.limit != nil {
		if _, err := db.Query("SET CONSTRAINTS ALL IMMEDIATE"); err != nil {
			return nil, err
		}
		after, err := count(db, "SELECT "+XactRows)
		if err != nil {
			return nil, err
		}
		// Как у execute — большее из статистики и шагов: при track_counts =
		// off статистика молчит (R1, R2 заход 3).
		out.Rows = max(after-before, out.Steps)
		if err := p.limit(out.Rows); err != nil {
			return nil, err
		}
	}
	if out.Differ, err = verify(db, groups); err != nil {
		return nil, err
	}
	if _, err := db.Query("COMMIT"); err != nil {
		var pg *pgwire.PgError
		if !errors.As(err, &pg) || pg.Severity == "FATAL" || pg.Severity == "PANIC" {
			// Связь оборвалась на COMMIT (или база закрыла сеанс): зафиксировал
			// ли он, отсюда не узнать — при синхронной реплике сеанс, прерванный
			// в её ожидании, у себя уже зафиксирован (R1, R2 заход 3).
			return out, fmt.Errorf("%w (transaction %s): %v", ErrCommitUnknown, out.XID, err)
		}
		return nil, err
	}
	return out, nil
}

func (g group) changed(found int) error {
	return fmt.Errorf("%w: %s.%s: steps %d–%d expected %d rows as the transaction left them, found %d", ErrChanged,
		g.t.Schema, g.t.Name, g.steps[0].N, g.steps[len(g.steps)-1].N, len(g.steps), found)
}

// statements — команды шагов группы. Генерируемые колонки откат не пишет: их
// считает база.
//
// В порядке журнала команда несёт сверку в своём условии: трогает строку,
// только если та такая, какой её оставила транзакция. В порядке внешних
// ключей сверка уже сделана, и строки под замком (см. apply): команда берёт
// строку по ключу, какой бы та ни стала после каскада от команды родителя.
func (g group) statements(order string) []string {
	var cols, olds, sets []string
	for i, c := range g.t.Columns {
		if slices.Contains(g.t.Generated, c) {
			continue
		}
		cols = append(cols, pgwire.Ident(c))
		olds = append(olds, fmt.Sprintf("w.o%d", i))
		// Правка возвращает только то, что транзакция меняла: остальное и так на
		// месте. Колонку GENERATED ALWAYS AS IDENTITY база не даёт писать вовсе,
		// даже прежним значением.
		if g.op == OpUpdate && slices.ContainsFunc(g.steps, func(s Step) bool { return !same(s.Old[i:i+1], s.New[i:i+1]) }) {
			sets = append(sets, fmt.Sprintf("%s = w.o%d", pgwire.Ident(c), i))
		}
	}
	guard := ""
	if order == OrderJournal {
		guard = " AND " + g.same('n')
	}
	switch g.op {
	case OpInsert:
		// OVERRIDING SYSTEM VALUE — ради колонки GENERATED ALWAYS AS IDENTITY: строка
		// возвращается со своим прежним номером. Остальным таблицам слово безразлично.
		return []string{"INSERT INTO " + g.t.rel() + " (" + strings.Join(cols, ", ") + ") OVERRIDING SYSTEM VALUE\n  SELECT " + strings.Join(olds, ", ") + "\n  FROM " + g.values()}
	case OpDelete:
		return []string{"DELETE FROM " + g.t.rel() + " t\n  USING " + g.values() + "\n  WHERE " + g.join("t", 'n') + guard}
	}
	update := "UPDATE " + g.t.rel() + " t SET " + strings.Join(sets, ", ") + "\n  FROM " + g.values() + "\n  WHERE "
	byNewKey := update + g.join("t", 'n') + guard
	pk := g.t.pkIndex()
	moved := slices.ContainsFunc(g.steps, func(s Step) bool {
		return slices.ContainsFunc(pk, func(i int) bool { return !same(s.Old[i:i+1], s.New[i:i+1]) })
	})
	if order != OrderKeys || !moved {
		return []string{byNewKey}
	}
	// Строку, которой транзакция сменила ключ, каскад мог уже вернуть под
	// прежний: родитель откатился раньше, и под новым ключом её нет. Такие
	// строки — первой командой, по прежнему ключу; остальные — второй, по новому.
	return []string{
		update + g.keyChanged() + " AND " + g.join("t", 'o') + " AND NOT (" + g.same('o') + ")" +
			" AND NOT EXISTS (SELECT 1 FROM " + g.t.rel() + " x WHERE " + g.join("x", 'n') + ")",
		byNewKey,
	}
}

// verify сверяет строки с до-образами в конце транзакции отката. Строки нет
// там, куда её вернули, или она осталась там, откуда её убрали, — ошибка:
// откат отменяется. Строка на месте, а значения не те — их переписал триггер
// таблицы: такие колонки отдаются списком.
func verify(db DB, groups []group) ([]Difference, error) {
	type column struct{ table, name string }
	differ := map[column]int{}
	for _, g := range groups {
		table := g.t.Schema + "." + g.t.Name
		if g.op == OpDelete {
			n, err := count(db, "SELECT count(*) FROM "+g.valuesOf("n")+"\nJOIN "+g.t.rel()+" t ON "+g.join("t", 'n'))
			if err != nil {
				return nil, err
			}
			if n != 0 {
				return nil, fmt.Errorf("pgundo: %s: %d rows the undo removed are still there (steps %d–%d): a trigger or a rule of the table stood in the way; nothing is applied",
					table, n, g.steps[0].N, g.steps[len(g.steps)-1].N)
			}
			continue
		}
		q := "SELECT count(*) FILTER (WHERE " + g.missing() + ")"
		for i := range g.t.Columns {
			q += ", count(*) FILTER (WHERE NOT (" + g.missing() + ") AND NOT (" + g.t.equal(i, 'o') + "))"
		}
		res, err := db.Query(q + "\nFROM " + g.valuesOf("o") + "\nLEFT JOIN " + g.t.rel() + " t ON " + g.join("t", 'o'))
		if err != nil {
			return nil, err
		}
		if len(res) != 1 || len(res[0].Rows) != 1 || len(res[0].Rows[0]) != 1+len(g.t.Columns) {
			return nil, fmt.Errorf("pgundo: %s: unexpected answer to the check after the undo", table)
		}
		for i, v := range res[0].Rows[0] {
			n, err := strconv.Atoi(deref(v))
			switch {
			case err != nil:
				return nil, fmt.Errorf("pgundo: %s: unexpected answer to the check after the undo", table)
			case i == 0 && n != 0:
				return nil, fmt.Errorf("pgundo: %s: %d rows the undo put back are not there (steps %d–%d): a trigger or a rule of the table stood in the way; nothing is applied",
					table, n, g.steps[0].N, g.steps[len(g.steps)-1].N)
			case i > 0 && n != 0:
				differ[column{table, g.t.Columns[i-1]}] += n
			}
		}
	}
	var out []Difference
	for c, n := range differ {
		out = append(out, Difference{Table: c.table, Column: c.name, Rows: n})
	}
	sort.Slice(out, func(i, j int) bool {
		return out[i].Table < out[j].Table || out[i].Table == out[j].Table && out[i].Column < out[j].Column
	})
	return out, nil
}

func count(db DB, sql string) (int, error) {
	res, err := db.Query(sql)
	if err != nil {
		return 0, err
	}
	if len(res) != 1 || len(res[0].Rows) != 1 || len(res[0].Rows[0]) != 1 {
		return 0, errors.New("pgundo: unexpected answer to a count")
	}
	return strconv.Atoi(deref(res[0].Rows[0][0]))
}

// reference — внешний ключ, по которому уборка вставленной строки задевает
// строки другой таблицы: ON DELETE CASCADE удаляет их, SET NULL и SET DEFAULT
// переписывают им ссылку. Ключ без такого действия сюда не входит: с ним база
// просто откажет в удалении, и это видно.
type reference struct {
	Table   string   // таблица плана, на которую ссылаются
	Child   string   // кто ссылается: имя для запроса
	Action  string   // c — CASCADE, n — SET NULL, d — SET DEFAULT
	Cols    []string // колонки ссылки
	RefCols []string // колонки таблицы плана, на которые она указывает
	// Covered — таблицы плана, которые и есть ссылающаяся таблица (она сама или
	// её секции): строки их годных шагов откат уберёт или перенаправит сам.
	Covered []string
}

func (f reference) effect() string {
	switch f.Action {
	case "c":
		return "ON DELETE CASCADE would delete them"
	case "n":
		return "ON DELETE SET NULL would clear their reference"
	}
	return "ON DELETE SET DEFAULT would reset their reference"
}

// errReferenced — на строку, которую откат убирает, ссылаются чужие строки.
var errReferenced = errors.New("rows the undo does not own refer to a row it removes")

// references — внешние ключи с действием при удалении, которые указывают на
// названные таблицы плана. Секция отвечает за свою таблицу: ключ объявлен у неё.
func (p *Plan) references(db DB, tables []string) ([]reference, error) {
	if len(tables) == 0 {
		return nil, nil
	}
	var vals []string
	for _, name := range p.tableNames() {
		vals = append(vals, fmt.Sprintf("(%s, to_regclass(%s), %t)", pgwire.Literal(name), pgwire.Literal(p.Tables[name].rel()), slices.Contains(tables, name)))
	}
	columns := func(key, rel string) string {
		return "(SELECT json_agg(a.attname ORDER BY k.ord) FROM unnest(c." + key + ") WITH ORDINALITY AS k(num, ord) " +
			"JOIN pg_attribute a ON a.attrelid = c." + rel + " AND a.attnum = k.num)::text"
	}
	res, err := db.Query("WITH t(name, oid, removes) AS (VALUES " + strings.Join(vals, ", ") + "),\n" +
		"r AS (SELECT name, removes, coalesce(pg_partition_root(oid), oid)::oid AS root FROM t WHERE oid IS NOT NULL)\n" +
		"SELECT parent.name, c.conrelid::regclass::text, c.confdeltype::text, " + columns("conkey", "conrelid") + ", " + columns("confkey", "confrelid") + ",\n" +
		"  coalesce((SELECT json_agg(own.name ORDER BY own.name) FROM r own WHERE own.root = c.conrelid), '[]')::text\n" +
		"FROM pg_constraint c JOIN r parent ON parent.root = c.confrelid AND parent.removes\n" +
		"WHERE c.contype = 'f' AND c.conparentid = 0 AND c.confdeltype IN ('c', 'n', 'd') ORDER BY 1, 2, c.conname")
	if err != nil {
		return nil, err
	}
	if len(res) != 1 {
		return nil, errors.New("pgundo: unexpected answer about foreign keys with an action on delete")
	}
	var out []reference
	for _, r := range res[0].Rows {
		if len(r) != 6 {
			return nil, errors.New("pgundo: unexpected row about foreign keys with an action on delete")
		}
		f := reference{Table: deref(r[0]), Child: deref(r[1]), Action: deref(r[2])}
		if json.Unmarshal([]byte(deref(r[3])), &f.Cols) != nil || json.Unmarshal([]byte(deref(r[4])), &f.RefCols) != nil ||
			json.Unmarshal([]byte(deref(r[5])), &f.Covered) != nil || len(f.Cols) == 0 || len(f.Cols) != len(f.RefCols) {
			return nil, fmt.Errorf("pgundo: the foreign key of %s to %s is described in an unexpected way", f.Child, f.Table)
		}
		t := p.Tables[f.Table]
		if t == nil || slices.ContainsFunc(f.RefCols, func(c string) bool { return !slices.Contains(t.Columns, c) }) {
			return nil, refuse("%s: the foreign key of %s points at a column the journal does not list", f.Table, f.Child)
		}
		out = append(out, f)
	}
	return out, nil
}

// dependents — запрос: какие из строк rows (их новые образы — строки, которые
// откат убирает) держат на себе по ключу f строки вне covered и сколько их.
// Ответ: шаг, число строк.
func (p *Plan) dependents(f reference, rows, covered []Step) string {
	t := p.Tables[f.Table]
	var b strings.Builder
	b.WriteString("SELECT w.step, count(*) FROM (VALUES\n  ")
	for i, s := range rows {
		if i > 0 {
			b.WriteString(",\n  ")
		}
		b.WriteString("(" + strconv.Itoa(s.N))
		for _, c := range f.RefCols {
			k := slices.Index(t.Columns, c)
			b.WriteString(", " + literal(s.New[k]))
			if i == 0 {
				b.WriteString("::" + t.Types[k])
			}
		}
		b.WriteString(")")
	}
	b.WriteString("\n) AS w(step")
	var on []string
	for i, c := range f.Cols {
		fmt.Fprintf(&b, ", k%d", i)
		on = append(on, fmt.Sprintf("x.%s = w.k%d", pgwire.Ident(c), i))
	}
	b.WriteString(")\nJOIN " + f.Child + " x ON " + strings.Join(on, " AND "))
	if len(covered) > 0 {
		// Свои строки — по первичному ключу, под которым они сейчас. Шаги могут
		// быть из разных секций одной таблицы: ключ у них один, а порядок колонок
		// у каждой секции свой — место ключа берётся по таблице шага.
		b.WriteString("\nWHERE NOT EXISTS (SELECT 1 FROM (VALUES\n  ")
		for i, s := range covered {
			if i > 0 {
				b.WriteString(",\n  ")
			}
			b.WriteString("(")
			own := p.Tables[s.Table]
			for j, k := range own.pkIndex() {
				if j > 0 {
					b.WriteString(", ")
				}
				b.WriteString(literal(s.New[k]))
				if i == 0 {
					b.WriteString("::" + own.Types[k])
				}
			}
			b.WriteString(")")
		}
		b.WriteString("\n) AS own(")
		var match []string
		for j, c := range p.Tables[covered[0].Table].PK {
			if j > 0 {
				b.WriteString(", ")
			}
			fmt.Fprintf(&b, "p%d", j)
			match = append(match, fmt.Sprintf("x.%s = own.p%d", pgwire.Ident(c), j))
		}
		b.WriteString(") WHERE " + strings.Join(match, " AND ") + ")")
	}
	b.WriteString("\nGROUP BY w.step ORDER BY w.step")
	return b.String()
}

func literal(v *string) string {
	if v == nil {
		return "NULL"
	}
	return pgwire.Literal(*v)
}

// referenced — часть сверки: шаг «убрать вставленную строку» не годен, если на
// строку ссылаются строки, которых откат сам не убирает и не перенаправляет.
// Их добавили или перенаправили на неё после транзакции; убрать строку —
// значит молча удалить их или переписать им ссылку.
//
// «Свои» — строки годных шагов правки и уборки: правка вернёт ссылку туда,
// куда она смотрела до транзакции, уборка уберёт строку раньше родителя. Шаг,
// ставший конфликтом, свои строки уже не покрывает, поэтому сверка идёт
// кругами, пока есть что менять: конфликт ребёнка делает конфликтом и родителя.
func (p *Plan) referenced(db DB, byStep map[int]Status) error {
	removing := func() map[string][]Step {
		out := map[string][]Step{}
		for _, s := range p.Steps {
			if s.Op == OpDelete && byStep[s.N].State == StateOK {
				out[s.Table] = append(out[s.Table], s)
			}
		}
		return out
	}
	refs, err := p.references(db, slices.Sorted(maps.Keys(removing())))
	if err != nil || len(refs) == 0 {
		return err
	}
	for again := true; again; {
		again = false
		rows := removing()
		for _, f := range refs {
			if len(rows[f.Table]) == 0 {
				continue
			}
			var covered []Step
			for _, s := range p.Steps {
				if s.Op != OpInsert && byStep[s.N].State == StateOK && slices.Contains(f.Covered, s.Table) {
					covered = append(covered, s)
				}
			}
			res, err := db.Query(p.dependents(f, rows[f.Table], covered))
			if err != nil {
				return err
			}
			if len(res) != 1 {
				return errors.New("pgundo: check: unexpected answer about the rows that refer to a row")
			}
			for _, r := range res[0].Rows {
				n, err := strconv.Atoi(deref(r[0]))
				st, known := byStep[n]
				if err != nil || len(r) != 2 || !known {
					return errors.New("pgundo: check: unexpected row about the rows that refer to a row")
				}
				// На строку могут ссылаться по нескольким ключам: названы все.
				detail := fmt.Sprintf("%s rows of %s refer to it: %s", deref(r[1]), f.Child, f.effect())
				if st.State == StateReferenced {
					detail = st.Detail + "; " + detail
				}
				st.State, st.Detail = StateReferenced, detail
				byStep[n] = st
				again = true
			}
		}
	}
	return nil
}

// guardReferences — та же проверка перед самой уборкой, уже в транзакции
// отката и с замком: между сверкой и откатом на строку могли сослаться. Замок
// на строках не даёт сослаться на них и позже: проверка внешнего ключа у
// новой ссылки встанет в очередь и после уборки получит отказ.
// К этому времени свои строки откат уже убрал или перенаправил; не убраны
// только строки этой же команды, если таблица ссылается сама на себя.
func (p *Plan) guardReferences(db DB, g group, refs []reference, order string) error {
	locked := order == OrderKeys // в порядке внешних ключей замок взят в начале
	for _, f := range refs {
		if f.Table != g.t.name() {
			continue
		}
		if !locked {
			n, err := count(db, "SELECT count(*) FROM (SELECT 1 FROM "+g.t.rel()+" t\n  JOIN "+g.valuesOf("n")+"\n  ON "+g.join("t", 'n')+" AND "+g.same('n')+" FOR UPDATE OF t) locked")
			if err != nil {
				return err
			}
			if n != len(g.steps) {
				return g.changed(n)
			}
			locked = true
		}
		var own []Step
		if slices.Contains(f.Covered, f.Table) {
			own = g.steps
		}
		res, err := db.Query(p.dependents(f, g.steps, own))
		if err != nil {
			return err
		}
		if len(res) != 1 {
			return errors.New("pgundo: unexpected answer about the rows that refer to a row")
		}
		if len(res[0].Rows) > 0 {
			return fmt.Errorf("%w: %s: %w: %d of the rows have rows of %s referring to them, and %s (steps %d–%d)", ErrChanged,
				g.t.name(), errReferenced, len(res[0].Rows), f.Child, f.effect(), g.steps[0].N, g.steps[len(g.steps)-1].N)
		}
	}
	return nil
}

// byKeys раскладывает годные шаги по внешним ключам. Возврат удалённых строк —
// от родителей к детям; правки — так же (родитель, вернув себе ключ, каскадом
// вернёт его детям); уборка вставленных — последней и от детей к родителям.
// Шаги одной таблицы и одного вида — одна команда: ссылки внутри таблицы база
// проверяет в конце команды.
func (p *Plan) byKeys(db DB, only map[int]bool) ([]group, error) {
	edges, err := p.foreignKeys(db)
	if err != nil {
		return nil, err
	}
	rank := ranks(edges)
	type slot struct{ op, table string }
	bySlot := map[slot]*group{}
	var order []slot
	for _, s := range p.Steps {
		if !only[s.N] {
			continue
		}
		k := slot{s.Op, s.Table}
		if bySlot[k] == nil {
			bySlot[k] = &group{t: p.Tables[s.Table], op: s.Op}
			order = append(order, k)
		}
		bySlot[k].steps = append(bySlot[k].steps, s)
	}
	phase := map[string]int{OpInsert: 0, OpUpdate: 1, OpDelete: 2}
	sort.SliceStable(order, func(i, j int) bool {
		a, b := order[i], order[j]
		switch {
		case a.op != b.op:
			return phase[a.op] < phase[b.op]
		case a.op == OpDelete:
			return rank[a.table] > rank[b.table]
		}
		return rank[a.table] < rank[b.table]
	})
	out := make([]group, len(order))
	for i, k := range order {
		out[i] = *bySlot[k]
	}
	return out, nil
}

// foreignKeys — внешние ключи между таблицами плана: пары «кто ссылается, на
// кого». Секция отвечает за свою таблицу: в журнале стоит имя секции, а ключ
// объявлен у таблицы.
func (p *Plan) foreignKeys(db DB) ([][2]string, error) {
	var vals []string
	for _, name := range p.tableNames() {
		vals = append(vals, "("+pgwire.Literal(name)+", to_regclass("+pgwire.Literal(p.Tables[name].rel())+"))")
	}
	root := func(col string) string {
		return "coalesce(pg_partition_root(" + col + "::regclass), " + col + "::regclass)"
	}
	res, err := db.Query("WITH t(name, oid) AS (VALUES " + strings.Join(vals, ", ") + "),\n" +
		"r AS (SELECT name, " + root("oid") + " AS root FROM t WHERE oid IS NOT NULL)\n" +
		"SELECT DISTINCT child.name, parent.name FROM pg_constraint c\n" +
		"JOIN r child ON child.root = " + root("c.conrelid") + "\n" +
		"JOIN r parent ON parent.root = " + root("c.confrelid") + "\n" +
		"WHERE c.contype = 'f' AND child.root <> parent.root ORDER BY 1, 2")
	if err != nil {
		return nil, err
	}
	if len(res) != 1 {
		return nil, errors.New("pgundo: unexpected answer about foreign keys")
	}
	var out [][2]string
	for _, r := range res[0].Rows {
		if len(r) != 2 {
			return nil, errors.New("pgundo: unexpected row about foreign keys")
		}
		out = append(out, [2]string{deref(r[0]), deref(r[1])})
	}
	return out, nil
}

// ranks — глубина таблицы по внешним ключам: 0 — ни на кого не ссылается, у
// остальных — на единицу больше самого глубокого родителя. Круг ссылок глубины
// не даёт: ребро, которое его замыкает, не считается.
func ranks(edges [][2]string) map[string]int {
	parents := map[string][]string{}
	for _, e := range edges {
		parents[e[0]] = append(parents[e[0]], e[1])
	}
	rank := map[string]int{}
	const visiting, done = 1, 2
	state := map[string]int{}
	var visit func(string) int
	visit = func(t string) int {
		switch state[t] {
		case done:
			return rank[t]
		case visiting:
			return -1
		}
		state[t] = visiting
		depth := 0
		for _, parent := range parents[t] {
			if r := visit(parent); r >= depth {
				depth = r + 1
			}
		}
		state[t], rank[t] = done, depth
		return depth
	}
	for _, child := range slices.Sorted(maps.Keys(parents)) {
		visit(child)
	}
	return rank
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
