// Command escollect — сборщик: читает файл журнала источника и доставляет
// строки в хранилище улик по HTTPS с клиентским сертификатом.
//
//	escollect -config collector.json
//	escollect -config collector.json -once     дочитать, отправить и выйти
//	escollect -config collector.json -promises вывести номера с обещаниями хранилища
//	escollect -version                         версия и коммит сборки
package main

import (
	"context"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"strings"
	"syscall"

	"github.com/Nikolay1994Kaz/evidencestore/internal/collector"
	"github.com/Nikolay1994Kaz/evidencestore/internal/version"
)

func main() {
	path := flag.String("config", "collector.json", "collector config")
	once := flag.Bool("once", false, "read and send what is there, then exit")
	promises := flag.Bool("promises", false, "list record numbers holding a signed store promise")
	showVersion := flag.Bool("version", false, "print the version and the commit it was built from")
	flag.Parse()
	if *showVersion {
		fmt.Println(version.String("escollect"))
		return
	}
	cfg, err := collector.LoadConfig(*path)
	fail(err)
	if *promises {
		m, bad, err := collector.Promises(cfg.SpoolDir)
		fail(err)
		if bad > 0 {
			fmt.Fprintf(os.Stderr, "warning: %d unreadable lines in promises.jsonl skipped\n", bad)
		}
		fmt.Println(strings.Join(collector.SortedSeqs(m), " "))
		return
	}
	log := slog.New(slog.NewTextHandler(os.Stderr, nil))
	c, err := collector.New(cfg, log)
	fail(err)
	defer c.Close()
	// fail выходит мимо defer: Close — и на выходе по ошибке (хранилище
	// может вызвать её само, 409), иначе принятая, но ещё не записанная
	// голова цепи пропала бы.
	failClosing := func(err error) {
		if err != nil {
			c.Close()
			fail(err)
		}
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	if *once {
		failClosing(c.Bootstrap(ctx))
		n, err := c.ReadOnce()
		failClosing(err)
		failClosing(c.SendOnce(ctx))
		fmt.Printf("read %d new records, delivered up to seq %d, pending %d\n", n, c.Acked(), c.Pending())
		return
	}
	failClosing(c.Run(ctx))
}

func fail(err error) {
	if err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
}
