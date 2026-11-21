// esmcp — MCP-сервер, через который ИИ-агент ходит в PostgreSQL
// (internal/mcpserver). Клиент MCP запускает его подпроцессом и говорит с ним
// по stdin/stdout; журнал сервера идёт в stderr.
//
//	esmcp -config mcp.json
//
// Подключается ролью агента: права этой роли и есть то, что агенту можно.
// Базу готовит скрипт escollect -setup-sql (роль, функция отметки действия).
package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/Nikolay1994Kaz/evidencestore/internal/config"
	"github.com/Nikolay1994Kaz/evidencestore/internal/mcpserver"
	"github.com/Nikolay1994Kaz/evidencestore/internal/pgtap"
	"github.com/Nikolay1994Kaz/evidencestore/internal/pgwire"
	"github.com/Nikolay1994Kaz/evidencestore/internal/version"
)

// Config — настройки сервера.
type Config struct {
	// DSN — подключение ролью агента: "host=db user=agent_bot dbname=shop
	// sslmode=verify-full". Пароль — здесь или в PGPASSWORD.
	DSN string `json:"dsn"`
	// Agent — имя агента в отметках действий и квитанциях.
	Agent string `json:"agent"`
	// Receipts — журнал квитанций; его читает escollect как свой источник.
	Receipts string `json:"receipts"`
	// MaxRows — сколько строк отдавать агенту на один запрос чтения; 0 — 200.
	MaxRows int `json:"max_rows"`
	// Undo — откуда брать до-образы для инструментов отката. Нет секции —
	// инструментов undo_preview и undo_apply у агента нет.
	Undo *Undo `json:"undo"`
}

// Undo — как достать из хранилища записи транзакции и проверить их. Команды —
// списком аргументов, без оболочки; пути в них — от каталога, где запущен сервер.
type Undo struct {
	// Index — справочник сборщика (index.jsonl источника "postgres"): под
	// какими номерами записей источника лежит транзакция.
	Index string `json:"index"`
	// Proof — команда выдачи пакета одной записи; сервер дописывает
	// "-seq N -out FILE": ["evidencestore", "proof", "-config", "…", "-source", "pg-agent", "-dek"].
	Proof []string `json:"proof"`
	// Verify — команда проверки; сервер дописывает "-proof FILE -body FILE":
	// ["esverify", "-store-key", "…", "-tsa-trust", "…"]. Тело берётся, только
	// если проверка прошла (код выхода 0): ключ хранилища и доверие к меткам
	// времени заданы здесь, а не тем, кто выдал пакет.
	Verify []string `json:"verify"`
	// Stamp — команда, которую звать перед выдачей пакетов, чтобы свежая запись
	// получила метку времени: ["evidencestore", "stamp", "-config", "…"]. Необязательна.
	Stamp []string `json:"stamp"`
	// Wait — сколько ждать, пока запись дойдёт до хранилища. По умолчанию 15s.
	Wait config.Duration `json:"wait"`
}

func loadConfig(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var c Config
	dec := json.NewDecoder(strings.NewReader(string(data)))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&c); err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	var errs []error
	if c.DSN == "" {
		errs = append(errs, errors.New("dsn is required"))
	}
	if c.Agent == "" {
		errs = append(errs, errors.New("agent: name the agent (it goes into every action marker)"))
	}
	if c.Receipts == "" {
		errs = append(errs, errors.New("receipts: name the receipts journal"))
	} else if !filepath.IsAbs(c.Receipts) {
		c.Receipts = filepath.Join(filepath.Dir(path), c.Receipts)
	}
	if c.MaxRows < 0 {
		errs = append(errs, errors.New("max_rows is negative"))
	}
	if u := c.Undo; u != nil {
		if u.Index == "" || len(u.Proof) == 0 || len(u.Verify) == 0 {
			errs = append(errs, errors.New("undo: index, proof and verify are all required"))
		} else if !filepath.IsAbs(u.Index) {
			u.Index = filepath.Join(filepath.Dir(path), u.Index)
		}
		if u.Wait == 0 {
			u.Wait = config.Duration(15 * time.Second)
		}
	}
	if err := errors.Join(errs...); err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	return &c, nil
}

// fetch достаёт из хранилища записи транзакции xid: по справочнику сборщика
// узнаёт их номера, на каждую берёт пакет и отдаёт его esverify. Транзакция,
// которую сборщик ещё не прочитал, и запись, которая до хранилища ещё не дошла,
// ждут до u.Wait.
func (u *Undo) fetch(xid uint32) ([][]byte, error) {
	deadline := time.Now().Add(u.Wait.D())
	var entry pgtap.IndexEntry
	for {
		// После пересылки транзакция лежит в справочнике дважды: Lookup отдаёт
		// последнюю строку.
		e, found, err := pgtap.Lookup(u.Index, xid)
		if err != nil {
			return nil, err
		}
		if found {
			entry = e
			break
		}
		if time.Now().After(deadline) {
			return nil, fmt.Errorf("transaction %d is not in the collector's index: it changed no watched table, or the collector has not read it yet", xid)
		}
		time.Sleep(100 * time.Millisecond)
	}
	dir, err := os.MkdirTemp("", "esmcp-undo-")
	if err != nil {
		return nil, err
	}
	defer os.RemoveAll(dir)
	run := func(argv []string, extra ...string) error {
		out, err := exec.Command(argv[0], append(slices.Clone(argv[1:]), extra...)...).CombinedOutput()
		if err != nil {
			return fmt.Errorf("%s: %w: %s", filepath.Base(argv[0]), err, strings.TrimSpace(string(out)))
		}
		return nil
	}
	var lines [][]byte
	for seq := entry.FirstSeq; seq <= entry.LastSeq; seq++ {
		bundle := filepath.Join(dir, fmt.Sprintf("%d.json", seq))
		body := filepath.Join(dir, fmt.Sprintf("%d.body", seq))
		for {
			if len(u.Stamp) > 0 {
				run(u.Stamp)
			}
			err := run(u.Proof, "-seq", strconv.FormatUint(seq, 10), "-out", bundle)
			if err == nil {
				// Пакет без метки времени после записи проверку не проходит: тогда — ещё попытка.
				err = run(u.Verify, "-proof", bundle, "-body", body)
			}
			if err == nil {
				break
			}
			if time.Now().After(deadline) {
				return nil, fmt.Errorf("record %d: %w", seq, err)
			}
			time.Sleep(300 * time.Millisecond)
		}
		line, err := os.ReadFile(body)
		if err != nil {
			return nil, err
		}
		lines = append(lines, line)
	}
	return lines, nil
}

func main() {
	path := flag.String("config", "mcp.json", "server config")
	showVersion := flag.Bool("version", false, "print the version and the commit it was built from")
	flag.Parse()
	if *showVersion {
		fmt.Println(version.String("esmcp"))
		return
	}
	cfg, err := loadConfig(*path)
	fail(err)
	dsn, err := pgwire.ParseDSN(cfg.DSN)
	fail(err)
	if dsn.AppName == "" {
		dsn.AppName = "esmcp/" + cfg.Agent
	}
	fail(os.MkdirAll(filepath.Dir(cfg.Receipts), 0o700))
	receipts, err := os.OpenFile(cfg.Receipts, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600)
	fail(err)
	defer receipts.Close()
	log := slog.New(slog.NewTextHandler(os.Stderr, nil))
	mc := mcpserver.Config{
		Agent: cfg.Agent, MaxRows: cfg.MaxRows, Receipts: receipts, ReceiptsPath: cfg.Receipts, Version: version.String("esmcp"),
		Dial: func() (mcpserver.DB, error) { return pgwire.Dial(context.Background(), dsn) },
	}
	if cfg.Undo != nil {
		mc.Fetch = cfg.Undo.fetch
	}
	srv := mcpserver.New(mc, log)
	fail(srv.Serve(os.Stdin, os.Stdout))
}

func fail(err error) {
	if err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
}
