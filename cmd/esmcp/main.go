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
	"path/filepath"
	"strings"
	"time"

	"github.com/Nikolay1994Kaz/evidencestore/internal/config"
	"github.com/Nikolay1994Kaz/evidencestore/internal/mcpserver"
	"github.com/Nikolay1994Kaz/evidencestore/internal/pgundo"
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
	// ActionRowLimit — предохранитель: сколько строк может изменить одно
	// действие execute. Больше — действие откатывается до фиксации, агент
	// получает отказ, сборщик поднимает тревогу refused. 0 — без предела.
	ActionRowLimit int `json:"action_row_limit"`
	// ActionsPerMinute — сколько действий execute агент может сделать за
	// минуту; WindowRows — сколько строк изменить за Window (по умолчанию
	// 10m). Счёт — по журналу квитанций, общий для всех сеансов агента. 0 —
	// без предела.
	ActionsPerMinute int             `json:"actions_per_minute"`
	WindowRows       int             `json:"window_rows"`
	Window           config.Duration `json:"window"`
	// StatementTimeout — сколько может идти SQL агента: дольше — запрос
	// отменяется на сервере базы, действие откатывается. По умолчанию 1m.
	// LockTimeout — сколько оператор агента ждёт чужую блокировку; по
	// умолчанию 10s. "0s" — без предела.
	StatementTimeout *config.Duration `json:"statement_timeout"`
	LockTimeout      *config.Duration `json:"lock_timeout"`
	// Undo — откуда брать до-образы для инструментов отката (тот же раздел,
	// что у esundo -config). Нет секции — инструментов undo_preview и
	// undo_apply у агента нет.
	Undo *pgundo.Fetcher `json:"undo"`
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
	if c.ActionRowLimit < 0 || c.ActionsPerMinute < 0 || c.WindowRows < 0 {
		errs = append(errs, errors.New("action_row_limit, actions_per_minute and window_rows must not be negative"))
	}
	if c.Window == 0 {
		c.Window = config.Duration(10 * time.Minute)
	}
	if c.Window.D() < time.Minute || c.Window.D() > 24*time.Hour {
		errs = append(errs, fmt.Errorf("window %v: from 1m to 24h", c.Window.D()))
	}
	for name, d := range map[string]**config.Duration{"statement_timeout": &c.StatementTimeout, "lock_timeout": &c.LockTimeout} {
		if *d == nil {
			def := config.Duration(time.Minute)
			if name == "lock_timeout" {
				def = config.Duration(10 * time.Second)
			}
			*d = &def
		}
		if (*d).D() < 0 {
			errs = append(errs, fmt.Errorf("%s is negative", name))
		}
	}
	if c.Undo != nil {
		if err := c.Undo.Validate(filepath.Dir(path)); err != nil {
			errs = append(errs, fmt.Errorf("undo: %w", err))
		}
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
	mc := mcpserver.Config{
		Agent: cfg.Agent, MaxRows: cfg.MaxRows, RowLimit: cfg.ActionRowLimit, ActionsPerMinute: cfg.ActionsPerMinute,
		WindowRows: cfg.WindowRows, Window: cfg.Window.D(), StatementTimeout: cfg.StatementTimeout.D(), LockTimeout: cfg.LockTimeout.D(),
		Receipts: receipts, ReceiptsPath: cfg.Receipts, Version: version.String("esmcp"),
		Dial: func(params map[string]string) (mcpserver.DB, error) {
			c := dsn
			c.Params = params
			return pgwire.Dial(context.Background(), c)
		},
	}
	if cfg.Undo != nil {
		mc.Fetch = cfg.Undo.Fetch
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
