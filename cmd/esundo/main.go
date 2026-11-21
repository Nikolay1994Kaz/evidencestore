// esundo — откат одной транзакции PostgreSQL по до-образам из хранилища улик.
//
// Вход — каталог тел записей транзакции, выписанных esverify из проверенных
// пакетов (esverify -bodies DIR или -body по одной записи): части транзакции,
// записанные сборщиком. Проверку пакетов эта программа не повторяет и в
// хранилище не ходит.
//
//	esundo check -bodies DIR -xid N [-dsn DSN] [-out plan.json]
//	    разобрать транзакцию; с -dsn — спросить базу, что сейчас на месте
//	    каждой строки, показать конфликты и записать сверенный план
//	esundo apply -plan plan.json -dsn DSN -by WHO [-reason WHY]
//	    применить сверенный план одной транзакцией. Строка, изменившаяся
//	    после сверки, отменяет откат целиком: сверьте заново
//
// Коды выхода: 0 — готово, 1 — ошибка вызова или базы, 2 — откат построить
// нельзя (TRUNCATE, таблица без REPLICA IDENTITY FULL, транзакция не вся),
// 3 — строка изменилась после сверки, ничего не применено.
package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"

	"github.com/Nikolay1994Kaz/evidencestore/internal/pgundo"
	"github.com/Nikolay1994Kaz/evidencestore/internal/pgwire"
	"github.com/Nikolay1994Kaz/evidencestore/internal/version"
)

func main() {
	if len(os.Args) < 2 {
		usage()
	}
	switch os.Args[1] {
	case "check":
		check(os.Args[2:])
	case "apply":
		apply(os.Args[2:])
	case "version", "-version", "--version":
		fmt.Println(version.String("esundo"))
	default:
		usage()
	}
}

func usage() {
	fmt.Fprintln(os.Stderr, "usage:\n  esundo check -bodies DIR -xid N [-dsn DSN] [-out plan.json]\n  esundo apply -plan plan.json -dsn DSN -by WHO [-reason WHY]\n  esundo version")
	os.Exit(1)
}

func fail(err error) {
	if err == nil {
		return
	}
	fmt.Fprintln(os.Stderr, "error:", err)
	switch {
	case errors.Is(err, pgundo.ErrRefused):
		os.Exit(2)
	case errors.Is(err, pgundo.ErrChanged):
		os.Exit(3)
	}
	os.Exit(1)
}

// bodies читает тела записей по порядку номеров: имя файла — <источник>-<номер>.
func bodies(dir string) ([][]byte, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, err
	}
	type body struct {
		seq  uint64
		data []byte
	}
	var all []body
	for _, e := range entries {
		i := strings.LastIndexByte(e.Name(), '-')
		seq, err := strconv.ParseUint(e.Name()[i+1:], 10, 64)
		if i < 0 || err != nil {
			return nil, fmt.Errorf("%s: a file that is not <source>-<number> in the bodies directory", e.Name())
		}
		data, err := os.ReadFile(filepath.Join(dir, e.Name()))
		if err != nil {
			return nil, err
		}
		all = append(all, body{seq, data})
	}
	sort.Slice(all, func(i, j int) bool { return all[i].seq < all[j].seq })
	out := make([][]byte, len(all))
	for i, b := range all {
		out[i] = b.data
	}
	return out, nil
}

func dial(dsn string) *pgwire.Conn {
	cfg, err := pgwire.ParseDSN(dsn)
	fail(err)
	if cfg.AppName == "" {
		cfg.AppName = "esundo"
	}
	c, err := pgwire.Dial(context.Background(), cfg)
	fail(err)
	return c
}

func check(args []string) {
	fs := flag.NewFlagSet("check", flag.ExitOnError)
	dir := fs.String("bodies", "", "directory of record bodies written by esverify")
	xid := fs.Uint("xid", 0, "the transaction to undo")
	dsn := fs.String("dsn", "", "database to check the plan against; without it the plan is only printed")
	out := fs.String("out", "", "write the checked plan here, for esundo apply")
	show := fs.Int("show", 10, "how many conflicts to print")
	fs.Parse(args)
	if *dir == "" || *xid == 0 {
		usage()
	}
	lines, err := bodies(*dir)
	fail(err)
	p, err := pgundo.Build(uint32(*xid), lines)
	fail(err)

	fmt.Printf("transaction %d: %d store records, %d row changes\n", p.XID, len(lines), p.Changes)
	var who struct{ Role, App string }
	if json.Unmarshal(p.Who, &who) == nil && who.Role != "" {
		fmt.Printf("  who: role %s, session %q\n", who.Role, who.App)
	}
	if p.Undo != nil {
		fmt.Printf("  this is an undo transaction: %s\n", p.Undo)
	}
	for _, a := range p.Actions {
		var m struct {
			Info struct {
				ActionID string `json:"action_id"`
				Agent    string `json:"agent"`
				Tool     string `json:"tool"`
				Reason   string `json:"reason"`
			} `json:"info"`
		}
		json.Unmarshal(a, &m)
		fmt.Printf("  action %s: agent %s, tool %s, reason: %s\n", m.Info.ActionID, m.Info.Agent, m.Info.Tool, m.Info.Reason)
	}
	if p.Who != nil && len(p.Actions) == 0 {
		fmt.Println("  no action marker: the transaction did not come through the MCP server")
	}
	var names []string
	for n := range p.Counts {
		names = append(names, n)
	}
	sort.Strings(names)
	for _, n := range names {
		c := p.Counts[n]
		fmt.Printf("  %s: inserts %d, updates %d, deletes %d\n", n, c.I, c.U, c.D)
	}
	s := p.Summary()
	fmt.Printf("  undo steps %d: restore values %d, restore deleted rows %d, remove inserted rows %d; rows touched more than once %d; no net change %d\n",
		s.Steps, s.Restore, s.Reinsert, s.Remove, s.Twice, p.Noop)
	if len(p.Steps) == 0 {
		fmt.Println("  nothing to undo: the transaction changed no rows")
		return
	}
	if *dsn == "" {
		return
	}
	db := dial(*dsn)
	defer db.Close()
	statuses, err := p.Check(db)
	fail(err)
	ok, done, bad := pgundo.Tally(statuses)
	fmt.Printf("checked against the database: to apply %d, already as before %d, conflicts %d\n", ok, done, bad)
	for i, c := range p.Conflicts(statuses) {
		if i == *show {
			fmt.Printf("  … and %d more\n", bad-i)
			break
		}
		fmt.Printf("  CONFLICT, step %d: %s (%s): %s\n", c.Step, c.Table, c.Key, c.Why)
		for _, line := range c.Lines() {
			fmt.Printf("      %s\n", line)
		}
	}
	if bad > 0 {
		fmt.Println("  the undo leaves conflicting rows alone: a person decides about each")
	}
	if *out != "" {
		data, err := json.Marshal(p)
		fail(err)
		fail(os.WriteFile(*out, data, 0o600))
		fmt.Printf("checked plan written to %s\n", *out)
	}
}

func apply(args []string) {
	fs := flag.NewFlagSet("apply", flag.ExitOnError)
	path := fs.String("plan", "", "the checked plan written by esundo check -out")
	dsn := fs.String("dsn", "", "database to apply the undo to")
	by := fs.String("by", "", "who undoes (goes into the journal)")
	reason := fs.String("reason", "", "why (goes into the journal)")
	fs.Parse(args)
	if *path == "" || *dsn == "" || *by == "" {
		usage()
	}
	data, err := os.ReadFile(*path)
	fail(err)
	var p pgundo.Plan
	fail(json.Unmarshal(data, &p))
	if len(p.OK) == 0 {
		fmt.Println("nothing to apply: the check found no step to take")
		return
	}
	db := dial(*dsn)
	defer db.Close()
	xid, err := p.Apply(db, map[string]any{"undoes_xid": strconv.FormatUint(uint64(p.XID), 10), "by": *by, "reason": *reason,
		"steps_applied": len(p.OK), "steps_total": len(p.Steps)})
	fail(err)
	fmt.Printf("undo applied: %d steps in transaction %s\n", len(p.OK), xid)
}
