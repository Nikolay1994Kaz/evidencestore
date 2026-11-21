package pgundo

import (
	"bytes"
	"encoding/json"
	"fmt"
	"strings"
)

// Conflict — шаг, который откат не возьмёт сам: что было, что оставила
// транзакция и что на этом месте сейчас. Значение nil — NULL.
type Conflict struct {
	Step    int              `json:"step"`
	Op      string           `json:"op"` // что шаг должен был сделать: update, insert (вернуть удалённую), delete (убрать вставленную)
	Table   string           `json:"table"`
	Key     string           `json:"key"`
	State   string           `json:"state"`
	Why     string           `json:"why"`
	Columns []ConflictColumn `json:"columns"`
}

// ConflictColumn — одна колонка конфликта. У правки — только колонки, которые
// транзакция меняла; у вставки и удаления — вся строка.
type ConflictColumn struct {
	Name string  `json:"name"`
	Was  *string `json:"was"`            // до транзакции
	Left *string `json:"left"`           // после транзакции
	Now  *string `json:"now,omitempty"`  // сейчас в базе
	Gone bool    `json:"gone,omitempty"` // строки сейчас нет
}

var why = map[string]string{
	StateGone:     "the row is gone",
	StateChanged:  "the row was changed after the transaction",
	StateExists:   "a row with this key exists again",
	StateKeyTaken: "the old key is taken by another row",
}

// Conflicts отбирает из ответов Check шаги, которые решать человеку.
func (p *Plan) Conflicts(statuses []Status) []Conflict {
	steps := map[int]Step{}
	for _, s := range p.Steps {
		steps[s.N] = s
	}
	var out []Conflict
	for _, st := range statuses {
		if !st.Conflict() {
			continue
		}
		s := steps[st.Step]
		t := p.Tables[s.Table]
		c := Conflict{Step: s.N, Op: s.Op, Table: s.Table, Key: p.Key(s), State: st.State, Why: why[st.State]}
		var cur map[string]any
		if st.Current != nil {
			dec := json.NewDecoder(bytes.NewReader(st.Current))
			dec.UseNumber()
			dec.Decode(&cur)
		}
		for i, name := range t.Columns {
			col := ConflictColumn{Name: name, Gone: st.State == StateGone}
			if s.Old != nil {
				col.Was = s.Old[i]
			}
			if s.New != nil {
				col.Left = s.New[i]
			}
			if s.Op == OpUpdate && same([]*string{col.Was}, []*string{col.Left}) {
				continue // эту колонку транзакция не меняла
			}
			if cur != nil {
				col.Now = text(cur[name])
			}
			c.Columns = append(c.Columns, col)
		}
		out = append(out, c)
	}
	return out
}

// text — значение из to_jsonb текстом, как PostgreSQL пишет его в журнал.
func text(v any) *string {
	var s string
	switch v := v.(type) {
	case nil:
		return nil
	case bool:
		s = "f"
		if v {
			s = "t"
		}
	case string:
		s = v
	case json.Number:
		s = v.String()
	default:
		b, _ := json.Marshal(v)
		s = string(b)
	}
	return &s
}

// Summary — сколько шагов какого вида.
type Summary struct {
	Steps, Restore, Reinsert, Remove, Twice int
}

// Summary считает шаги плана по видам.
func (p *Plan) Summary() Summary {
	s := Summary{Steps: len(p.Steps)}
	for _, st := range p.Steps {
		switch st.Op {
		case OpUpdate:
			s.Restore++
		case OpInsert:
			s.Reinsert++
		case OpDelete:
			s.Remove++
		}
		if st.Touches > 1 {
			s.Twice++
		}
	}
	return s
}

// Tally — итог сверки: сколько шагов годно, сколько уже сделано, сколько конфликтов.
func Tally(statuses []Status) (ok, done, conflicts int) {
	for _, st := range statuses {
		switch {
		case st.State == StateOK:
			ok++
		case st.State == StateDone:
			done++
		default:
			conflicts++
		}
	}
	return
}

// Lines — конфликт строками для человека.
func (c Conflict) Lines() []string {
	q := func(s *string) string {
		if s == nil {
			return "NULL"
		}
		v := *s
		if len(v) > 60 {
			v = v[:57] + "…"
		}
		return "«" + v + "»"
	}
	row := func(pick func(ConflictColumn) *string) string {
		var parts []string
		for _, col := range c.Columns {
			parts = append(parts, col.Name+"="+q(pick(col)))
		}
		return strings.Join(parts, ", ")
	}
	now := func(col ConflictColumn) *string { return col.Now }
	switch c.Op {
	case OpInsert:
		return []string{"the transaction deleted: " + row(func(col ConflictColumn) *string { return col.Was }), "now under this key:      " + row(now)}
	case OpDelete:
		out := []string{"the transaction inserted: " + row(func(col ConflictColumn) *string { return col.Left })}
		if c.State != StateGone {
			out = append(out, "now:                      "+row(now))
		}
		return out
	}
	var out []string
	for _, col := range c.Columns {
		line := fmt.Sprintf("%s: was %s, the transaction left %s", col.Name, q(col.Was), q(col.Left))
		if !col.Gone {
			line += ", now " + q(col.Now)
		}
		out = append(out, line)
	}
	return out
}
