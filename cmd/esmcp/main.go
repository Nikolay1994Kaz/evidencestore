// esmcp — MCP-сервер, через который ИИ-агент ходит в PostgreSQL
// (internal/mcpserver). Клиент MCP запускает его подпроцессом и говорит с ним
// по stdin/stdout; журнал сервера идёт в stderr.
//
//	esmcp -config mcp.json
//
// Подключается своей ролью сервера (mcp_roles в настройках сборщика): права
// этой роли и есть то, что можно SQL агента. Роль — только сервера: при
// запуске он отказывается работать суперпользователем или ролью, которой
// может стать другая роль со входом. Настройки с паролем агенту читать нельзя:
// esmcp — под другим пользователем ОС или в контейнере (DECISIONS, п. 39).
// Базу готовит скрипт escollect -setup-sql (роли, права, публикация).
//
// На каждое действие сервер пишет в свой файл квитанций (receipt/v2) намерение
// с номером транзакции до её COMMIT и исход после, подписанные ключом шлюза
// (key): по намерению сборщик берёт транзакцию целиком как действие агента
// (DECISIONS, п. 42). Ключ читает только esmcp: агенту — ни его, ни файла.
//
//	esmcp -config mcp.json -pubkey    # открытый ключ шлюза: в gateway_keys сборщика и gateway_key хранилища
package main

import (
	"context"
	"crypto/ed25519"
	"encoding/hex"
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
	"github.com/Nikolay1994Kaz/evidencestore/internal/gateway"
	"github.com/Nikolay1994Kaz/evidencestore/internal/mcpserver"
	"github.com/Nikolay1994Kaz/evidencestore/internal/pgundo"
	"github.com/Nikolay1994Kaz/evidencestore/internal/pgwire"
	"github.com/Nikolay1994Kaz/evidencestore/internal/version"
)

// Config — настройки сервера.
type Config struct {
	// DSN — подключение ролью сервера: "host=db user=esmcp_bot dbname=shop
	// sslmode=verify-full". Пароль — здесь или в PGPASSWORD.
	DSN string `json:"dsn"`
	// Agent — имя агента в квитанциях.
	Agent string `json:"agent"`
	// Receipts — файл квитанций шлюза (receipt/v2); его читает escollect:
	// источник postgres — ради намерений, второй источник — чтобы отдать
	// квитанции хранилищу.
	Receipts string `json:"receipts"`
	// Key — ключ шлюза (PKCS#8 PEM, Ed25519; esreceipt keygen): им подписана
	// каждая квитанция.
	Key string `json:"key"`
	// Gateway — имя цепочки квитанций (1–128 знаков из латиницы, цифр и
	// . _ : -). По умолчанию "esmcp". У каждого агента в общем файле — своё.
	Gateway string `json:"gateway"`
	// Head — где сервер держит голову своей цепочки квитанций (gateway.Head):
	// туда пишет только он, как и ключ. По умолчанию — рядом с ключом; если
	// каталог ключа только на чтение (Docker), — путь в каталоге, куда пишет
	// только сервер.
	Head string `json:"head"`
	// PGSource — имя источника базы в хранилище: на него ссылается намерение
	// ({"source": pg_source, "subject": xid}). По умолчанию "postgres"; то же
	// имя — в receipts.source у сборщика.
	PGSource string `json:"pg_source"`
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
	Undo *pgundo.Settings `json:"undo"`
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
		errs = append(errs, errors.New("agent: name the agent (it goes into every receipt)"))
	}
	if c.Receipts == "" {
		errs = append(errs, errors.New("receipts: name the receipts file"))
	} else if !filepath.IsAbs(c.Receipts) {
		c.Receipts = filepath.Join(filepath.Dir(path), c.Receipts)
	}
	if c.Key == "" {
		errs = append(errs, errors.New("key: name the gateway key (esreceipt keygen -key FILE writes one): every receipt is signed with it"))
	} else if !filepath.IsAbs(c.Key) {
		c.Key = filepath.Join(filepath.Dir(path), c.Key)
	}
	if c.Gateway == "" {
		c.Gateway = "esmcp"
	}
	if c.Head != "" && !filepath.IsAbs(c.Head) {
		c.Head = filepath.Join(filepath.Dir(path), c.Head)
	}
	if c.Head == "" && c.Key != "" && c.Receipts != "" {
		c.Head = gateway.DefaultHead(c.Key, c.Receipts, c.Gateway)
	}
	if !gateway.ValidName(c.Gateway) {
		errs = append(errs, fmt.Errorf("gateway %q: 1 to %d letters, digits and . _ : -", c.Gateway, gateway.MaxGatewayName))
	}
	if c.PGSource == "" {
		c.PGSource = "postgres"
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
	showPub := flag.Bool("pubkey", false, "print the gateway's public key (64 hex) and exit: it goes to gateway_keys of the collector and gateway_key of the store")
	flag.Parse()
	if *showVersion {
		fmt.Println(version.String("esmcp"))
		return
	}
	cfg, err := loadConfig(*path)
	fail(err)
	key, err := gateway.LoadKey(cfg.Key)
	fail(err)
	if *showPub {
		fmt.Println(hex.EncodeToString(key.Public().(ed25519.PublicKey)))
		return
	}
	dsn, err := pgwire.ParseDSN(cfg.DSN)
	fail(err)
	if dsn.AppName == "" {
		dsn.AppName = "esmcp/" + cfg.Agent
	}
	fail(os.MkdirAll(filepath.Dir(cfg.Receipts), 0o700))
	if cfg.Head != "" {
		fail(gateway.CheckHead(cfg.Head, cfg.Receipts))
	}
	log := slog.New(slog.NewTextHandler(os.Stderr, nil))
	mc := mcpserver.Config{
		Agent: cfg.Agent, MaxRows: cfg.MaxRows, RowLimit: cfg.ActionRowLimit, ActionsPerMinute: cfg.ActionsPerMinute,
		WindowRows: cfg.WindowRows, Window: cfg.Window.D(), StatementTimeout: cfg.StatementTimeout.D(), LockTimeout: cfg.LockTimeout.D(),
		ReceiptsPath: cfg.Receipts, HeadPath: cfg.Head, Key: key, Gateway: cfg.Gateway, PGSource: cfg.PGSource, Version: version.String("esmcp"),
		Dial: func(params map[string]string) (mcpserver.DB, error) {
			c := dsn
			c.Params = params
			return pgwire.Dial(context.Background(), c)
		},
	}
	if cfg.Undo != nil {
		mc.Fetch = cfg.Undo.Fetch
		mc.UndoSearchPath = cfg.Undo.SearchPath
	}
	srv := mcpserver.New(mc, log)
	// Роль сервера — только его (DECISIONS, п. 39): иначе не начинать. База
	// недоступна — проверка при следующем запуске, а соединяться сервер будет
	// по первому вызову, как всегда.
	// Роль проверяется и на каждом новом соединении: база, недоступная
	// сейчас, не пропускает проверку (R1-4, R2-5, T-2).
	if err := srv.CheckRole(); errors.Is(err, mcpserver.ErrSharedRole) {
		fail(err)
	} else if err != nil {
		log.Warn("the database is unreachable: the role of the server is checked when a connection is made", "err", err)
	}
	fail(srv.Serve(os.Stdin, os.Stdout))
}

func fail(err error) {
	if err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
}
