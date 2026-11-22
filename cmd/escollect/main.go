// Command escollect — сборщик: читает источник и доставляет записи в хранилище
// улик по HTTPS с клиентским сертификатом. Источник — файл журнала, файлы по
// маске или журнал PostgreSQL (раздел "postgres" настроек); в одном файле
// настроек источников может быть несколько ("sources"), и один процесс ведёт
// их все.
//
//	escollect -config collector.json
//	escollect -config collector.json -once      дочитать, отправить и выйти
//	escollect -config collector.json -promises  вывести номера с обещаниями хранилища
//	escollect -config collector.json -setup-sql SQL настройки базы для источника "postgres"
//	escollect -version                          версия и коммит сборки
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/Nikolay1994Kaz/evidencestore/internal/collector"
	"github.com/Nikolay1994Kaz/evidencestore/internal/pginput"
	"github.com/Nikolay1994Kaz/evidencestore/internal/version"
)

func main() {
	path := flag.String("config", "collector.json", "collector config")
	once := flag.Bool("once", false, "read and send what is there, then exit")
	promises := flag.Bool("promises", false, "list record numbers holding a signed store promise")
	setup := flag.Bool("setup-sql", false, "print the SQL that prepares the database for a \"postgres\" source (roles, grants, marker trigger, publication) and exit")
	showVersion := flag.Bool("version", false, "print the version and the commit it was built from")
	flag.Parse()
	if *showVersion {
		fmt.Println(version.String("escollect"))
		return
	}
	cfgs, err := collector.LoadConfigs(*path)
	fail(err)
	many := len(cfgs) > 1
	if *setup {
		found := false
		for _, cfg := range cfgs {
			if cfg.Postgres != nil {
				sql, err := pginput.SetupSQL(cfg.Postgres)
				fail(err)
				fmt.Print(sql)
				found = true
			}
		}
		if !found {
			fail(errors.New("-setup-sql: the config has no \"postgres\" source"))
		}
		return
	}
	if *promises {
		for _, cfg := range cfgs {
			m, bad, err := collector.Promises(cfg.SpoolDir)
			fail(err)
			if bad > 0 {
				fmt.Fprintf(os.Stderr, "warning: %d unreadable lines in promises.jsonl skipped\n", bad)
			}
			if many {
				fmt.Printf("%s: ", filepath.Base(cfg.SpoolDir))
			}
			fmt.Println(strings.Join(collector.SortedSeqs(m), " "))
		}
		return
	}
	log := slog.New(slog.NewTextHandler(os.Stderr, nil))
	var cs []*collector.Collector
	closeAll := func() {
		for _, c := range cs {
			c.Close()
		}
	}
	for _, cfg := range cfgs {
		c, err := collector.New(cfg, log)
		if err != nil {
			closeAll()
			fail(err)
		}
		cs = append(cs, c)
		if many {
			// Свой сертификат — своё имя источника: по нему строки журнала
			// сборщика различаются.
			c.SetLogger(log.With("source", c.Source()))
		}
	}
	// fail выходит мимо defer: Close — и на выходе по ошибке (хранилище
	// может вызвать её само, 409), иначе принятая, но ещё не записанная
	// голова цепи пропала бы.
	failClosing := func(err error) {
		if err != nil {
			closeAll()
			fail(err)
		}
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	if *once {
		for _, c := range cs {
			failClosing(c.Bootstrap(ctx))
			n, err := c.ReadAll(ctx)
			failClosing(err)
			failClosing(c.SendOnce(ctx))
			if many {
				fmt.Printf("%s: ", c.Source())
			}
			fmt.Printf("read %d new records, delivered up to seq %d, pending %d\n", n, c.Acked(), c.Pending())
		}
		closeAll()
		return
	}
	// Страница показателей — одна на процесс.
	listen := cfgs[0].MetricsListen
	for _, cfg := range cfgs {
		if cfg.MetricsListen != listen {
			failClosing(errors.New("metrics_listen differs between sources: one process serves one page, set it once at the top of the config"))
		}
	}
	if listen != "" {
		ln, err := net.Listen("tcp", listen)
		failClosing(err)
		srv := &http.Server{Handler: collector.MetricsHandler(cs...), ReadHeaderTimeout: 10 * time.Second}
		go srv.Serve(ln)
		defer srv.Close()
		log.Info("metrics", "listen", ln.Addr().String())
	}
	if !many {
		failClosing(cs[0].Run(ctx))
		closeAll()
		return
	}
	// Источники независимы: один остановился (хранилище отказало его
	// установке, его буфер сломался) — остальные работают, а о молчащем
	// скажет и хранилище (expect_contact). Код выхода — ошибка, если
	// остановился хоть один.
	var wg sync.WaitGroup
	errs := make([]error, len(cs))
	for i, c := range cs {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if errs[i] = c.Run(ctx); errs[i] != nil {
				log.Error("source stopped; the other sources keep running", "source", c.Source(), "err", errs[i])
			}
		}()
	}
	wg.Wait()
	closeAll()
	fail(errors.Join(errs...))
}

func fail(err error) {
	if err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
}
