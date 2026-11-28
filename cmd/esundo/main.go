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
// "verify": […], "wait": "15s", "search_path": ["public"], "receipts": "…",
// "key": "…", "gateway": "esundo", "pg_source": "postgres"} — подключение к
// базе, раздел pgundo.Settings и квитанции шлюза.
//
// Откат — тоже действие (DECISIONS, п. 42): до своих изменений esundo пишет в
// файл квитанций намерение отката с номером его транзакции, подписанное
// ключом key. По нему сборщик берёт откат целиком; без квитанции он лёг бы
// отпечатком. Поэтому apply без настроек с receipts и key отказывает.
//
// Коды выхода: 0 — готово, 1 — ошибка вызова или базы, 2 — откат построить
// нельзя (TRUNCATE, таблица без REPLICA IDENTITY FULL, транзакция не вся),
// 3 — строка изменилась после сверки, ничего не применено, 4 — связь
// оборвалась на COMMIT отката: он мог зафиксироваться, сначала посмотреть
// транзакцию.
package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"slices"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/Nikolay1994Kaz/evidencestore/internal/alert"
	"github.com/Nikolay1994Kaz/evidencestore/internal/gateway"
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
	pgundo.Settings
	// Receipts, Key — файл квитанций шлюза и ключ (PKCS#8 PEM): в него
	// esundo пишет намерение каждого отката до его изменений. Gateway — имя
	// цепочки (по умолчанию "esundo"); PGSource — источник базы в хранилище,
	// как у esmcp (по умолчанию "postgres"). Ключ — в gateway_keys сборщика.
	Receipts string `json:"receipts"`
	Key      string `json:"key"`
	Gateway  string `json:"gateway"`
	PGSource string `json:"pg_source"`
	// Head — где esundo держит голову своей цепочки квитанций (gateway.Head):
	// туда пишет только он. По умолчанию — рядом с ключом.
	Head string `json:"head"`
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
	for _, f := range []*string{&c.Receipts, &c.Key, &c.Head} {
		if *f != "" && !filepath.IsAbs(*f) {
			*f = filepath.Join(filepath.Dir(path), *f)
		}
	}
	if c.Gateway == "" {
		c.Gateway = "esundo"
	}
	if !gateway.ValidName(c.Gateway) {
		fail(fmt.Errorf("%s: gateway %q: 1 to %d letters, digits and . _ : -", path, c.Gateway, gateway.MaxGatewayName))
	}
	if c.PGSource == "" {
		c.PGSource = "postgres"
	}
	if c.Head == "" && c.Key != "" && c.Receipts != "" {
		c.Head = gateway.DefaultHead(c.Key, c.Receipts, c.Gateway)
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
	case errors.Is(err, pgundo.ErrCommitUnknown):
		os.Exit(4) // откат мог зафиксироваться: сначала посмотреть транзакцию
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
	searchPath := fs.String("search-path", "", "schemas after pg_catalog on the search_path of the check and the undo, comma-separated (with -config: search_path there)")
	fs.Parse(args)
	if (*dir == "") == (*cfgPath == "") || *xid == 0 {
		usage()
	}
	var lines [][]byte
	var err error
	var schemas []string
	if *searchPath != "" {
		for _, n := range strings.Split(*searchPath, ",") {
			schemas = append(schemas, strings.TrimSpace(n))
		}
	}
	if *cfgPath != "" {
		// Записи — из хранилища: пакет на каждую, проверка — командой из настроек.
		cfg := loadConfig(*cfgPath)
		if *dsn == "" {
			*dsn = cfg.DSN
		}
		if *out == "" && *dsn != "" {
			*out = fmt.Sprintf("undo-%d.json", *xid)
		}
		if *searchPath == "" {
			schemas = cfg.SearchPath
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
	fail(pgundo.ValidSearchPath(schemas))
	p.SearchPath = schemas

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
	fmt.Printf("  search_path of the check and the undo: %s\n", p.Path())
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
	var cfg *Config
	if *cfgPath != "" {
		cfg = loadConfig(*cfgPath)
		if *dsn == "" {
			*dsn = cfg.DSN
		}
	}
	if *path == "" || *dsn == "" || *by == "" {
		usage()
	}
	p, err := loadPlan(*path, cfg)
	fail(err)
	if len(p.OK) == 0 {
		fmt.Println("nothing to apply: the check found no step to take")
		return
	}
	if cfg == nil || cfg.Receipts == "" || cfg.Key == "" {
		fail(errors.New("apply writes the undo's receipt before its changes (the collector takes the undo by it): give -config with receipts and key"))
	}
	key, err := gateway.LoadKey(cfg.Key)
	fail(err)
	fail(gateway.CheckHead(cfg.Head, cfg.Receipts)) // до базы: голову не записать — откат отказал бы после сверки
	db := dial(*dsn)
	defer db.Close()
	action := "undo-" + strconv.FormatUint(uint64(p.XID), 10) + "-" + strconv.FormatInt(time.Now().UnixNano(), 36)
	done, err := p.Apply(db, undoIntent(cfg, key, p, action, *by, *reason))
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

// undoIntent — намерение отката: квитанция шагом undo со ссылкой на
// транзакцию отката, подписанная ключом esundo, — в его файл квитанций до
// изменений отката. По ней сборщик берёт откат целиком (п. 42). Если первая
// попытка отменена и откат идёт в порядке внешних ключей, у второй транзакции
// — своё намерение того же действия.
func undoIntent(cfg *Config, key ed25519.PrivateKey, p *pgundo.Plan, action, by, reason string) pgundo.IntentFunc {
	undoes := ""
	if p.Action != nil {
		undoes = p.Action.ID
	}
	return func(xid, xid8, started, timeline string) error {
		body, err := json.Marshal(map[string]any{"agent": by, "tool": "esundo", "reason": reason, "undoes": undoes,
			"undoes_xid": strconv.FormatUint(uint64(p.XID), 10), "xid8": xid8, "db_started": started, "db_timeline": timeline, "steps": len(p.OK)})
		if err != nil {
			return err
		}
		a, err := gateway.AppendHead(cfg.Receipts, cfg.Head, key, cfg.Gateway, gateway.Draft{Action: action, Step: alert.StepUndo,
			Refs: []gateway.Ref{{Source: cfg.PGSource, Subject: xid}}, Body: body})
		if a.KeyChanged {
			fmt.Fprintf(os.Stderr, "esundo: note: gateway %q signs with a new key (%s), and its chain goes on from seq %d: the store's source and the collector must list the new key (gateway_keys)\n", cfg.Gateway, a.Receipt.Kid, a.Receipt.Seq)
		}
		return err
	}
}

// loadPlan читает сверенный план.
func loadPlan(path string, cfg *Config) (*pgundo.Plan, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var p pgundo.Plan
	if err := json.Unmarshal(data, &p); err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	// Путь — тот, с которым план сверен. Настройки с другим путём — отказ:
	// молча подменить путь сверенного плана нельзя, а план со старым путём
	// после правки настроек тоже не годится (T-5; R1-8, R2-9, заход 2).
	if cfg != nil && !slices.Equal(p.SearchPath, cfg.SearchPath) {
		var checked, settings pgundo.Plan
		checked.SearchPath, settings.SearchPath = p.SearchPath, cfg.SearchPath
		return nil, fmt.Errorf("the plan was checked with search_path %s, and the undo settings now say %s: run esundo check again", checked.Path(), settings.Path())
	}
	return &p, nil
}

// describe — что сделала транзакция и что сделает откат. Всё, что пришло из
// журнала (действие шлюза с причиной агента, имена, значения), печатается через pgundo.Shown:
// агент не дописывает в этот вывод своих строк (P-251).
func describe(w io.Writer, p *pgundo.Plan, records int) {
	fmt.Fprintf(w, "transaction %d: %d store records, %d row changes\n", p.XID, records, p.Changes)
	if a := p.Action; a != nil {
		// Всё в квитанции — от шлюза, но причина и имена — от агента (P-251):
		// в кавычках и не длиннее 300 знаков, иначе пробелами агент переносил
		// свой текст на отдельные строки терминала (T заход 2).
		cut := func(s string, n int) string {
			if r := []rune(s); len(r) > n {
				return string(r[:n]) + "…"
			}
			return s
		}
		what := "action"
		if a.Step == alert.StepUndo {
			what = "undo"
		}
		fmt.Fprintf(w, "  %s %s: gateway %s (receipt %d), agent %s, tool %s, reason: %q\n", what, cut(pgundo.Shown(a.ID), 60), cut(pgundo.Shown(a.Gateway), 60), a.Seq,
			cut(pgundo.Shown(a.Agent), 60), cut(pgundo.Shown(a.Tool), 20), cut(a.Reason, 300))
		if a.Undoes != "" {
			fmt.Fprintf(w, "  it undoes action %s\n", cut(pgundo.Shown(a.Undoes), 60))
		}
	} else {
		fmt.Fprintln(w, "  no gateway intent: the collector kept the transaction whole without the gateway's receipts")
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
