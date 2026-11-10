// Command eswitness — свидетель голов цепи по C2SP (tlog-witness).
//
//	eswitness init  -config C   завести ключ свидетеля и напечатать его ключ проверки (vkey)
//	eswitness serve -config C   принимать головы хранилищ и подписывать их
//	eswitness vkey  -config C   напечатать ключ проверки
//	eswitness version
//
// Держит его не администратор хранилища: регулятор, банк-партнёр,
// аудиторская фирма. Хранилище шлёт ему головы (witness.cosigners), он
// подписывает только головы, которые продолжают последнюю подписанную, и
// держит одну последнюю голову на хранилище. Ключ проверки (vkey) отдают
// аудиторам: esverify -witness-key.
package main

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/Nikolay1994Kaz/evidencestore/internal/cosign"
	"github.com/Nikolay1994Kaz/evidencestore/internal/proof"
	"github.com/Nikolay1994Kaz/evidencestore/internal/version"
	"github.com/Nikolay1994Kaz/evidencestore/internal/witness"
)

func main() { os.Exit(run(os.Args[1:], os.Stdout, os.Stderr)) }

func usage(w io.Writer) {
	fmt.Fprintln(w, "usage: eswitness init -config FILE    create the witness key and print its verifier key")
	fmt.Fprintln(w, "       eswitness serve -config FILE   cosign the chain heads of the stores in the config")
	fmt.Fprintln(w, "       eswitness vkey -config FILE    print the verifier key (give it to auditors: esverify -witness-key)")
	fmt.Fprintln(w, "       eswitness version")
}

func run(args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		usage(stderr)
		return 2
	}
	cmd, args := args[0], args[1:]
	if cmd == "version" || cmd == "-version" {
		fmt.Fprintln(stdout, version.String("eswitness"))
		return 0
	}
	fs := flag.NewFlagSet("eswitness "+cmd, flag.ContinueOnError)
	fs.SetOutput(stderr)
	path := fs.String("config", "", "witness configuration (JSON)")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if *path == "" {
		usage(stderr)
		return 2
	}
	cfg, err := loadConfig(*path)
	if err != nil {
		fmt.Fprintln(stderr, "error:", err)
		return 2
	}
	switch cmd {
	case "init":
		err = cmdInit(cfg, stdout)
	case "vkey":
		err = cmdVkey(cfg, stdout)
	case "serve":
		err = cmdServe(cfg, stderr)
	default:
		usage(stderr)
		return 2
	}
	if err != nil {
		fmt.Fprintln(stderr, "error:", err)
		return 1
	}
	return 0
}

// Config — конфигурация свидетеля. Относительные пути — от каталога файла
// конфигурации.
type Config struct {
	// Name — имя свидетеля: оно в каждой его подписи и в ключе проверки.
	// Лучше URL без схемы под контролем владельца: witness.example/w1.
	Name string `json:"name"`
	// Listen — адрес приёма голов, например 127.0.0.1:8444.
	Listen string `json:"listen"`
	// DataDir — ключ свидетеля (witness.key), состояние журналов (state/),
	// журнал подписанного (cosigned.jsonl), журнал отказов (refused.jsonl),
	// замок (LOCK).
	DataDir string `json:"data_dir"`
	// TLS — сертификат и ключ HTTPS. Нет — обычный HTTP (за прокси с TLS):
	// подпись свидетеля от транспорта не зависит.
	TLS *struct {
		Cert string `json:"cert"`
		Key  string `json:"key"`
	} `json:"tls,omitempty"`
	// Logs — хранилища, чьи головы свидетель подписывает: открытый ключ, как
	// его печатает evidencestore init.
	Logs []struct {
		StoreKey string `json:"store_key"`
	} `json:"logs"`

	logs []witness.Log
}

const keyFile = "witness.key"

func loadConfig(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var c Config
	dec := json.NewDecoder(strings.NewReader(string(data)))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&c); err != nil {
		return nil, fmt.Errorf("config %s: %w", path, err)
	}
	base := filepath.Dir(path)
	abs := func(p string) string {
		if p == "" || filepath.IsAbs(p) {
			return p
		}
		return filepath.Join(base, p)
	}
	c.DataDir = abs(c.DataDir)
	if c.TLS != nil {
		c.TLS.Cert, c.TLS.Key = abs(c.TLS.Cert), abs(c.TLS.Key)
	}
	var errs []error
	if !cosign.ValidName(c.Name) {
		errs = append(errs, fmt.Errorf("name %q: non-empty, at most %d bytes, no spaces, '+' or control characters (a URL without the scheme, e.g. witness.example/w1)", c.Name, cosign.MaxNameLen))
	}
	if c.Listen == "" {
		errs = append(errs, errors.New("listen is required, e.g. 127.0.0.1:8444"))
	}
	if c.DataDir == "" {
		errs = append(errs, errors.New("data_dir is required"))
	}
	if c.TLS != nil && (c.TLS.Cert == "" || c.TLS.Key == "") {
		errs = append(errs, errors.New("tls needs both cert and key"))
	}
	if len(c.Logs) == 0 {
		errs = append(errs, errors.New("logs: name at least one store by its store_key"))
	}
	seen := map[string]bool{}
	for i, l := range c.Logs {
		key, err := parseStoreKey(l.StoreKey)
		if err != nil {
			errs = append(errs, fmt.Errorf("logs[%d]: %w", i, err))
			continue
		}
		origin := proof.OriginFor(key)
		if seen[origin] {
			errs = append(errs, fmt.Errorf("logs[%d]: the store %s is listed twice", i, origin))
			continue
		}
		seen[origin] = true
		c.logs = append(c.logs, witness.Log{Origin: origin, Key: key})
	}
	if err := errors.Join(errs...); err != nil {
		return nil, fmt.Errorf("config %s: %w", path, err)
	}
	return &c, nil
}

// parseStoreKey — открытый ключ хранилища в base64 (с дополнением или без:
// evidencestore init печатает без).
func parseStoreKey(v string) (ed25519.PublicKey, error) {
	raw, err := base64.RawStdEncoding.DecodeString(strings.TrimRight(strings.TrimSpace(v), "="))
	if err != nil || len(raw) != ed25519.PublicKeySize {
		return nil, errors.New("store_key must be the store's base64 Ed25519 public key, as evidencestore init prints it")
	}
	return ed25519.PublicKey(raw), nil
}

// cmdInit заводит ключ свидетеля. Ключ есть — отказ: новый ключ свидетеля
// сделал бы прежние подписи непроверяемыми тем, кто закрепил старый.
func cmdInit(cfg *Config, stdout io.Writer) error {
	if err := os.MkdirAll(cfg.DataDir, 0o700); err != nil {
		return err
	}
	path := filepath.Join(cfg.DataDir, keyFile)
	if _, err := os.Stat(path); err == nil {
		return fmt.Errorf("%s already exists: the witness has a key; eswitness vkey prints it", path)
	}
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return err
	}
	tmp := path + ".tmp"
	// Остаток init, прерванного падением: ключа ещё нет, временный файл — не ключ.
	if err := os.Remove(tmp); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	f, err := os.OpenFile(tmp, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	_, werr := f.Write(priv)
	if err := errors.Join(werr, f.Sync(), f.Close()); err != nil {
		os.Remove(tmp)
		return err
	}
	// Link, а не Rename: ключ, появившийся за это время, не затирается.
	if err := os.Link(tmp, path); err != nil {
		os.Remove(tmp)
		return err
	}
	os.Remove(tmp)
	if d, err := os.Open(cfg.DataDir); err == nil {
		d.Sync()
		d.Close()
	}
	return cmdVkey(cfg, stdout)
}

func loadSigner(cfg *Config) (cosign.Signer, error) {
	path := filepath.Join(cfg.DataDir, keyFile)
	data, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return cosign.Signer{}, fmt.Errorf("%s does not exist: run eswitness init first", path)
	}
	if err != nil {
		return cosign.Signer{}, err
	}
	if len(data) != ed25519.PrivateKeySize {
		return cosign.Signer{}, fmt.Errorf("%s is damaged: %d bytes instead of %d", path, len(data), ed25519.PrivateKeySize)
	}
	return cosign.NewSigner(cfg.Name, ed25519.PrivateKey(data))
}

func cmdVkey(cfg *Config, stdout io.Writer) error {
	s, err := loadSigner(cfg)
	if err != nil {
		return err
	}
	fmt.Fprintln(stdout, s.Verifier().String())
	return nil
}

func cmdServe(cfg *Config, stderr io.Writer) error {
	log := slog.New(slog.NewTextHandler(stderr, nil))
	signer, err := loadSigner(cfg)
	if err != nil {
		return err
	}
	lock, err := witness.Lock(cfg.DataDir)
	if err != nil {
		return err
	}
	defer lock.Close()
	w, err := witness.New(signer, cfg.logs, cfg.DataDir, log)
	if err != nil {
		return err
	}
	defer w.Close()
	srv := &http.Server{
		Handler:           w.Handler(),
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      30 * time.Second,
		IdleTimeout:       2 * time.Minute,
		ErrorLog:          slog.NewLogLogger(log.Handler(), slog.LevelWarn),
	}
	ln, err := net.Listen("tcp", cfg.Listen)
	if err != nil {
		return err
	}
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	errc := make(chan error, 1)
	go func() {
		if cfg.TLS != nil {
			srv.TLSConfig = &tls.Config{MinVersion: tls.VersionTLS12}
			errc <- srv.ServeTLS(ln, cfg.TLS.Cert, cfg.TLS.Key)
			return
		}
		errc <- srv.Serve(ln)
	}()
	log.Info("eswitness listening", "name", signer.Name, "addr", ln.Addr().String(), "logs", len(cfg.logs), "vkey", signer.Verifier().String())
	select {
	case <-ctx.Done():
	case err = <-errc:
	}
	shutdown, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	srv.Shutdown(shutdown)
	if errors.Is(err, http.ErrServerClosed) {
		err = nil
	}
	return err
}
