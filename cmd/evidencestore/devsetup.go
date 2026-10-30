package main

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"path/filepath"

	"github.com/Nikolay1994Kaz/evidencestore/internal/config"
	"github.com/Nikolay1994Kaz/evidencestore/internal/store"
)

// cmdDevSetup готовит учебную установку в одном каталоге — то, что README
// («Run it yourself», шаги под «What dev-setup does») делает руками:
// учебный УЦ и сертификаты (dev-pki), store.json со встроенной демо-TSA,
// init, store.pub и collector.json с закреплённым ключом хранилища.
// Хранилище не запускает: serve, escollect, stamp, proof и esverify
// читатель набирает сам.
//
// Пишет только в новый или пустой каталог: указанный по ошибке каталог
// настоящего хранилища остаётся как был. collector.json пишется последним —
// по нему повторный запуск узнаёт готовый каталог.
func cmdDevSetup(args []string) error {
	fs := flag.NewFlagSet("dev-setup", flag.ExitOnError)
	dir := fs.String("dir", "", "directory for the demo setup: a new or empty one")
	source := fs.String("source", "app", "source name: the CommonName of the collector certificate")
	logFile := fs.String("log", "", "log file the collector reads (default: <source>.log in -dir)")
	port := fs.Int("port", 8443, "port on 127.0.0.1 the store listens on")
	fs.Parse(args)
	if *dir == "" {
		return errors.New("dev-setup: -dir is required")
	}
	if *port < 1 || *port > 65535 {
		return fmt.Errorf("dev-setup: -port %d: must be between 1 and 65535", *port)
	}
	// Относительный путь в collector.json сборщик считает от каталога
	// настроек, а читатель набрал -log от текущего.
	file := *source + ".log"
	if *logFile != "" {
		abs, err := filepath.Abs(*logFile)
		if err != nil {
			return err
		}
		file = abs
	}
	entries, err := os.ReadDir(*dir)
	switch {
	case errors.Is(err, os.ErrNotExist):
	case err != nil:
		return fmt.Errorf("dev-setup: %w", err)
	case len(entries) > 0:
		if _, err := os.Stat(filepath.Join(*dir, "collector.json")); err == nil {
			return fmt.Errorf("dev-setup: %s is already set up, nothing changed: start the store with `evidencestore serve -config %s`; to start over, stop it and remove %s",
				*dir, filepath.Join(*dir, "store.json"), *dir)
		}
		return fmt.Errorf("dev-setup: %s is not empty: dev-setup writes only into a new or empty directory", *dir)
	}
	if err := os.MkdirAll(*dir, 0o700); err != nil {
		return err
	}
	storePath := filepath.Join(*dir, "store.json")
	if err := writeJSON(storePath, map[string]any{
		"data_dir":  "data",
		"roots_dir": "roots",
		"listen":    fmt.Sprintf("127.0.0.1:%d", *port),
		"tls":       map[string]string{"cert": "pki/server.crt", "key": "pki/server.key", "client_ca": "pki/ca.crt"},
		"tsa":       map[string]string{"url": "local"},
		"sources":   []map[string]string{{"name": *source, "content_type": "text"}},
	}); err != nil {
		return err
	}
	// Имя источника и длину пути сокета проверяет загрузка конфига, пока в
	// каталоге нет ничего другого: не прошла — каталог снова пуст.
	cfg, err := config.Load(storePath)
	if err != nil {
		os.Remove(storePath)
		return fmt.Errorf("dev-setup: %w", err)
	}
	unfinished := func(err error) error {
		return fmt.Errorf("%w (%s holds an unfinished setup: remove it and run dev-setup again)", err, *dir)
	}
	if err := cmdDevPKI([]string{"-out", filepath.Join(*dir, "pki"), "-source", *source}); err != nil {
		return unfinished(err)
	}
	pub, err := store.Init(cfg)
	if err != nil {
		return unfinished(err)
	}
	if err := os.WriteFile(filepath.Join(*dir, "store.pub"), []byte(pub+"\n"), 0o644); err != nil {
		return unfinished(err)
	}
	if err := writeJSON(filepath.Join(*dir, "collector.json"), map[string]any{
		"server":     fmt.Sprintf("https://127.0.0.1:%d", *port),
		"ca":         "pki/ca.crt",
		"cert":       "pki/" + *source + ".crt",
		"key":        "pki/" + *source + ".key",
		"store_key":  pub,
		"spool_dir":  "spool",
		"file":       file,
		"from_start": true,
	}); err != nil {
		return unfinished(err)
	}
	fmt.Printf("demo setup in %s: pki/, store.json, data/, roots/, store.pub, collector.json\n", *dir)
	fmt.Printf("store public key (pinned in collector.json as store_key, saved to store.pub for esverify):\n%s\n", pub)
	fmt.Println("for a try only: the CA is a demo one, and time-stamps come from the demo TSA built into the store")
	fmt.Printf("next: cd %s && evidencestore serve -config store.json   (leave it running)\n", *dir)
	fmt.Printf("then, in another terminal there: escollect -config collector.json -once   (reads %s)\n", file)
	return nil
}

// writeJSON пишет конфиг учебной установки.
func writeJSON(path string, v any) error {
	data, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, append(data, '\n'), 0o644)
}
