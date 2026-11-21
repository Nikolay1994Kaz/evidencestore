// esmcp — MCP-сервер, через который ИИ-агент ходит в PostgreSQL
// (internal/mcpserver). Клиент MCP запускает его подпроцессом и говорит с ним
// по stdin/stdout; журнал сервера идёт в stderr.
//
//	esmcp -config mcp.json
//
// Подключается ролью агента: права этой роли и есть то, что агенту можно.
// Базу готовит скрипт espgtap -setup-sql (роль, функция отметки действия).
package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strings"

	"github.com/Nikolay1994Kaz/evidencestore/internal/mcpserver"
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
	if err := errors.Join(errs...); err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	return &c, nil
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
	srv := mcpserver.New(mcpserver.Config{
		Agent: cfg.Agent, MaxRows: cfg.MaxRows, Receipts: receipts, Version: version.String("esmcp"),
		Dial: func() (mcpserver.DB, error) { return pgwire.Dial(context.Background(), dsn) },
	}, log)
	fail(srv.Serve(os.Stdin, os.Stdout))
}

func fail(err error) {
	if err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
}
