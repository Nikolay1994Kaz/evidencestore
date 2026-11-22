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
// С файлом настроек (-config undo.json) записи транзакции программа достаёт из
// хранилища сама — командами выдачи пакета и проверки из настроек, — и от
// тревоги до отката остаются две команды:
//
//	esundo check -config undo.json -xid N       сверить и записать план undo-N.json
//	esundo apply -config undo.json -plan undo-N.json -by WHO
//
// undo.json: {"dsn": "…", "index": "…/index.jsonl", "stamp": […], "proof": […],
// "verify": […], "wait": "15s"} — подключение к базе и раздел pgundo.Fetcher.
//
// Коды выхода: 0 — готово, 1 — ошибка вызова или базы, 2 — откат построить
// нельзя (TRUNCATE, таблица без REPLICA IDENTITY FULL, транзакция не вся),
// 3 — строка изменилась после сверки, ничего не применено.
package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
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
	fmt.Fprintln(os.Stderr, "usage:\n  esundo check -config undo.json -xid N [-out plan.json]\n  esundo check -bodies DIR -xid N [-dsn DSN] [-out plan.json]\n"+
		"  esundo apply [-config undo.json] -plan plan.json [-dsn DSN] -by WHO [-reason WHY]\n  esundo version")
	os.Exit(1)
}

// Config — undo.json: подключение к базе и то, как достать записи транзакции
// из хранилища.
type Config struct {
	// DSN — подключение ролью, которой можно менять таблицы (владелец):
	// "host=db user=owner dbname=shop sslmode=verify-full".
	DSN string `json:"dsn"`
	pgundo.Fetcher
}

func loadConfig(path string) *Config {
	data, err := os.ReadFile(path)
	fail(err)
	var c Config
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&c); err != nil {
		fail(fmt.Errorf("%s: %w", path, err))
	}
	if err := c.Validate(filepath.Dir(path)); err != nil {
		fail(fmt.Errorf("%s: %w", path, err))
	}
	return &c
}

func fail(err error) {
	if err == nil {
		return
	}
	// В ошибке базы бывают значения строк — от агента (P-251).
	fmt.Fprintln(os.Stderr, "error:", pgundo.Shown(err.Error()))
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
	cfgPath := fs.String("config", "", "undo.json: fetch the records from the store and take the database from there")
	dir := fs.String("bodies", "", "directory of record bodies written by esverify (instead of -config)")
	xid := fs.Uint("xid", 0, "the transaction to undo")
	dsn := fs.String("dsn", "", "database to check the plan against; without it the plan is only printed")
	out := fs.String("out", "", "write the checked plan here, for esundo apply (with -config: undo-<xid>.json)")
	show := fs.Int("show", 10, "how many conflicts to print")
	fs.Parse(args)
	if (*dir == "") == (*cfgPath == "") || *xid == 0 {
		usage()
	}
	var lines [][]byte
	var err error
	if *cfgPath != "" {
		// Записи — из хранилища: пакет на каждую, проверка — командой из настроек.
		cfg := loadConfig(*cfgPath)
		if *dsn == "" {
			*dsn = cfg.DSN
		}
		if *out == "" && *dsn != "" {
			*out = fmt.Sprintf("undo-%d.json", *xid)
		}
		lines, err = cfg.Fetch(uint32(*xid))
		fail(err)
		fmt.Printf("fetched from the store and verified: %d records\n", len(lines))
	} else {
		lines, err = bodies(*dir)
		fail(err)
	}
	p, err := pgundo.Build(uint32(*xid), lines)
	fail(err)

	describe(os.Stdout, p, len(lines))
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
		fmt.Printf("  CONFLICT, step %d: %s (%s): %s\n", c.Step, pgundo.Shown(c.Table), pgundo.Shown(c.Key), pgundo.Shown(c.Why))
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
		if *cfgPath != "" && ok > 0 {
			// Как звали эту программу, так и подсказывать: команда должна
			// сработать как есть.
			fmt.Printf("to apply it: %s apply -config %s -plan %s -by YOUR_NAME -reason \"…\"\n", os.Args[0], *cfgPath, *out)
		}
	}
}

func apply(args []string) {
	fs := flag.NewFlagSet("apply", flag.ExitOnError)
	cfgPath := fs.String("config", "", "undo.json: take the database from there")
	path := fs.String("plan", "", "the checked plan written by esundo check")
	dsn := fs.String("dsn", "", "database to apply the undo to")
	by := fs.String("by", "", "who undoes (goes into the journal)")
	reason := fs.String("reason", "", "why (goes into the journal)")
	fs.Parse(args)
	if *cfgPath != "" && *dsn == "" {
		*dsn = loadConfig(*cfgPath).DSN
	}
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
	done, err := p.Apply(db, map[string]any{"undoes_xid": strconv.FormatUint(uint64(p.XID), 10), "by": *by, "reason": *reason,
		"steps_applied": len(p.OK), "steps_total": len(p.Steps)})
	fail(err)
	fmt.Printf("undo applied: %d steps in transaction %s\n", done.Steps, done.XID)
	if done.Order == pgundo.OrderKeys {
		fmt.Println("  the steps went in the order of the foreign keys: in the order of the journal the database refused them (a cascade made a part of the changes)")
	}
	if len(done.Differ) == 0 {
		fmt.Println("  checked after the undo: every row is as it was before the transaction")
		return
	}
	fmt.Println("  checked after the undo: the rows are back, but not all values are as they were before the transaction.")
	fmt.Println("  Triggers of these tables rewrote what the undo put back (the undo does not switch triggers off):")
	for _, d := range done.Differ {
		fmt.Printf("    %s.%s: %d rows\n", pgundo.Shown(d.Table), pgundo.Shown(d.Column), d.Rows)
	}
}

// describe — что сделала транзакция и что сделает откат. Всё, что пришло из
// журнала (отметки агента, имена, значения), печатается через pgundo.Shown:
// агент не дописывает в этот вывод своих строк (P-251).
func describe(w io.Writer, p *pgundo.Plan, records int) {
	fmt.Fprintf(w, "transaction %d: %d store records, %d row changes\n", p.XID, records, p.Changes)
	var who struct{ Role, App string }
	if json.Unmarshal(p.Who, &who) == nil && who.Role != "" {
		fmt.Fprintf(w, "  who: role %s, session %q\n", pgundo.Shown(who.Role), who.App)
	}
	if p.Undo != nil {
		fmt.Fprintf(w, "  this is an undo transaction: %s\n", pgundo.Shown(string(p.Undo)))
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
		// Всё в отметке — от агента: причина, имена, номер действия (P-251).
		fmt.Fprintf(w, "  action %s: agent %s, tool %s, reason: %s\n", pgundo.Shown(m.Info.ActionID), pgundo.Shown(m.Info.Agent), pgundo.Shown(m.Info.Tool), pgundo.Shown(m.Info.Reason))
	}
	if p.Who != nil && len(p.Actions) == 0 {
		fmt.Fprintln(w, "  no action marker: the transaction did not come through the MCP server")
	}
	var names []string
	for n := range p.Counts {
		names = append(names, n)
	}
	sort.Strings(names)
	for _, n := range names {
		c := p.Counts[n]
		fmt.Fprintf(w, "  %s: inserts %d, updates %d, deletes %d\n", pgundo.Shown(n), c.I, c.U, c.D)
	}
	s := p.Summary()
	fmt.Fprintf(w, "  undo steps %d: restore values %d, restore deleted rows %d, remove inserted rows %d; rows touched more than once %d; no net change %d\n",
		s.Steps, s.Restore, s.Reinsert, s.Remove, s.Twice, p.Noop)
}
