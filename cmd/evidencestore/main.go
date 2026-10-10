// Command evidencestore — хранилище улик: сервер и команды оператора.
//
//	evidencestore init     -config C           завести хранилище (кейринг, ключ подписи)
//	evidencestore serve    -config C           принимать улики
//	evidencestore dev-pki  -out DIR -source N…  учебный УЦ и сертификаты для стенда
//	evidencestore status   -config C           сводка
//	evidencestore stamp    -config C           заверить голову цепи у TSA сейчас
//	evidencestore proof    -config C -source S -seq N [-dek] [-out F]
//	evidencestore statement -config C          подписанная голова цепи
//	evidencestore tsa-root -config C -out F    корень встроенной демо-TSA
//	evidencestore keys list|due|deactivate|schedule|cancel|complete|destroy-orphan-roots -config C …
//	evidencestore restore  -config C -from URL -store-key KEY  журнал и цепь из копии
//
// Команды оператора ходят в работающий сервер через unix-сокет админки:
// у кейринга и цепи один писатель.
package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"evidencestore/internal/config"
	"evidencestore/internal/pki"
	"evidencestore/internal/server"
	"evidencestore/internal/ship"
	"evidencestore/internal/store"
)

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(2)
	}
	cmd, args := os.Args[1], os.Args[2:]
	var err error
	switch cmd {
	case "init":
		err = cmdInit(args)
	case "serve":
		err = cmdServe(args)
	case "dev-pki":
		err = cmdDevPKI(args)
	case "status":
		err = adminGet(args, "/admin/status", nil)
	case "statement":
		err = adminGet(args, "/admin/statement", nil)
	case "stamp":
		err = adminPost(args, "/admin/stamp", nil, nil)
	case "proof":
		err = cmdProof(args)
	case "tsa-root":
		err = cmdTSARoot(args)
	case "keys":
		err = cmdKeys(args)
	case "sources":
		err = cmdSources(args)
	case "restore":
		err = cmdRestore(args)
	case "help", "-h", "--help":
		usage()
	default:
		fmt.Fprintf(os.Stderr, "unknown command %q\n\n", cmd)
		usage()
		os.Exit(2)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
}

func usage() {
	fmt.Fprint(os.Stderr, `evidencestore — tamper-evident storage for audit records

Server:
  init      -config FILE                       create keyring, signing key (once)
  serve     -config FILE                       accept evidence over mTLS
  dev-pki   -out DIR -source NAME [-source …]  demo CA, server and collector certificates

Operator (talks to the running server via its admin socket):
  status    -config FILE
  statement -config FILE                       signed chain head
  stamp     -config FILE                       time-stamp the chain head now
  proof     -config FILE -source S -seq N [-dek] [-out FILE]
  tsa-root  -config FILE -out FILE             root certificate of the built-in demo TSA
  keys list|due      -config FILE
  keys deactivate    -config FILE -scope S [-force]
  keys schedule      -config FILE -scope S -approve A -approve B [-wait 168h]
  keys cancel        -config FILE -scope S -approve A
  keys complete      -config FILE
  keys destroy-orphan-roots -config FILE       destroy keyring roots unknown to keyring.dat
                                               (shown in status; they keep destruction non-final)
  sources bind -config FILE -source S -epoch E bind the source to this collector installation:
                                               accept a reinstalled collector (its error names E);
                                               the previous installation is refused from then on

Disaster recovery:
  restore   -config FILE -from URL -store-key KEY   rebuild evidence log and chain from the copy;
            keyring.dat and sign.key come from keys.backup_dir, roots from keys.roots_mirror_dir
`)
}

func loadConfig(fs *flag.FlagSet, args []string) (*config.Config, error) {
	path := fs.String("config", "evidencestore.json", "config file")
	if err := fs.Parse(args); err != nil {
		return nil, err
	}
	return config.Load(*path)
}

func cmdInit(args []string) error {
	cfg, err := loadConfig(flag.NewFlagSet("init", flag.ExitOnError), args)
	if err != nil {
		return err
	}
	pub, err := store.Init(cfg)
	if err != nil {
		return err
	}
	fmt.Printf("evidencestore initialised in %s\n", cfg.DataDir)
	fmt.Printf("store public key (pin it at auditors and collectors):\n%s\n", pub)
	return nil
}

func cmdServe(args []string) error {
	cfg, err := loadConfig(flag.NewFlagSet("serve", flag.ExitOnError), args)
	if err != nil {
		return err
	}
	log := slog.New(slog.NewTextHandler(os.Stderr, nil))
	st, err := store.Open(cfg, store.Options{Logger: log})
	if err != nil {
		return err
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	runErr := server.New(cfg, st, log).Run(ctx)
	return errors.Join(runErr, st.Close())
}

type multiFlag []string

func (m *multiFlag) String() string     { return strings.Join(*m, ",") }
func (m *multiFlag) Set(v string) error { *m = append(*m, v); return nil }

func cmdDevPKI(args []string) error {
	fs := flag.NewFlagSet("dev-pki", flag.ExitOnError)
	out := fs.String("out", "pki", "output directory")
	var sources, hosts multiFlag
	fs.Var(&sources, "source", "collector certificate for this source (repeatable)")
	fs.Var(&hosts, "host", "server name or IP (repeatable; default localhost, 127.0.0.1)")
	fs.Parse(args)
	if len(hosts) == 0 {
		hosts = multiFlag{"localhost", "127.0.0.1"}
	}
	// Учебный УЦ уже есть — сертификаты выпускаются под ним, ничего не
	// затирается: новый УЦ сделал бы негодными все выданные сертификаты.
	exists := func(name string) bool { _, err := os.Stat(filepath.Join(*out, name)); return err == nil }
	var ca *pki.CA
	var err error
	switch {
	case exists("ca.crt") && exists("ca.key"):
		if ca, err = pki.LoadCA(*out); err != nil {
			return err
		}
	case exists("ca.crt"):
		return fmt.Errorf("dev-pki: %s holds ca.crt without ca.key: certificates cannot be issued under it, and it is not overwritten", *out)
	default:
		if ca, err = pki.NewCA("evidencestore demo collectors CA"); err != nil {
			return err
		}
		if err := ca.Save(*out); err != nil {
			return err
		}
	}
	if !exists("server.crt") {
		srv, err := ca.Server(hosts...)
		if err != nil {
			return err
		}
		if err := srv.Write(*out, "server"); err != nil {
			return err
		}
	}
	for _, s := range sources {
		if exists(s + ".crt") {
			return fmt.Errorf("dev-pki: %s already exists and is not overwritten", filepath.Join(*out, s+".crt"))
		}
		c, err := ca.Client(s)
		if err != nil {
			return err
		}
		if err := c.Write(*out, s); err != nil {
			return err
		}
		fmt.Printf("%s: cert_sha256 %s\n", s, config.CertFingerprint(c.Cert.Raw))
	}
	fmt.Printf("demo PKI written to %s (ca.crt, server.crt/key, <source>.crt/key)\n", *out)
	return nil
}

func cmdProof(args []string) error {
	fs := flag.NewFlagSet("proof", flag.ExitOnError)
	source := fs.String("source", "", "source name")
	seq := fs.Uint64("seq", 0, "record number at the source")
	dek := fs.Bool("dek", false, "attach the key of this one record so the auditor can open the body")
	out := fs.String("out", "", "write the bundle here instead of stdout")
	cfg, err := loadConfig(fs, args)
	if err != nil {
		return err
	}
	q := url.Values{"source": {*source}, "seq": {fmt.Sprint(*seq)}}
	if *dek {
		q.Set("dek", "1")
	}
	body, err := adminDo(cfg, http.MethodGet, "/admin/proof?"+q.Encode(), nil)
	if err != nil {
		return err
	}
	return output(*out, body)
}

func cmdTSARoot(args []string) error {
	fs := flag.NewFlagSet("tsa-root", flag.ExitOnError)
	out := fs.String("out", "tsa-root.crt", "where to write the DER certificate")
	cfg, err := loadConfig(fs, args)
	if err != nil {
		return err
	}
	body, err := adminDo(cfg, http.MethodGet, "/admin/tsa-root", nil)
	if err != nil {
		return err
	}
	return output(*out, body)
}

func cmdRestore(args []string) error {
	fs := flag.NewFlagSet("restore", flag.ExitOnError)
	from := fs.String("from", "", "replica URL (default: replica.url from the config)")
	key := fs.String("store-key", "", "pinned store public key (base64): the copy's signed head is checked against it")
	cfg, err := loadConfig(fs, args)
	if err != nil {
		return err
	}
	if *from == "" {
		*from = cfg.Replica.URL
	}
	raw, err := base64.RawStdEncoding.DecodeString(strings.TrimRight(*key, "="))
	if err != nil || len(raw) != ed25519.PublicKeySize {
		return errors.New("restore: -store-key must be the store's base64 Ed25519 public key")
	}
	remote, err := ship.OpenRemote(*from)
	if err != nil {
		return err
	}
	rep, err := store.RestoreReplica(context.Background(), remote, cfg.DataDir, ed25519.PublicKey(raw))
	if err != nil {
		return err
	}
	fmt.Printf("restored %d files, %d bytes; chain verified up to signed head %d\n", rep.Files, rep.Bytes, rep.HeadSeq)
	fmt.Printf("now put keyring.dat into %s and sign.key into %s (from keys.backup_dir),\n", cfg.DataDir, filepath.Join(cfg.DataDir, "chain"))
	if cfg.Keys.RootsMirrorDir != "" {
		fmt.Printf("make sure roots_dir %s exists (the store reads missing roots from the mirror %s),\n", cfg.RootsDir, cfg.Keys.RootsMirrorDir)
	} else {
		fmt.Println("put the roots back into roots_dir (without keys.roots_mirror_dir there is no copy the store knows of),")
	}
	fmt.Println("then run `evidencestore serve` and check `evidencestore status` for orphan_roots")
	return nil
}

func cmdKeys(args []string) error {
	if len(args) == 0 {
		return errors.New("keys: list|due|deactivate|schedule|cancel|complete|destroy-orphan-roots")
	}
	sub, args := args[0], args[1:]
	fs := flag.NewFlagSet("keys "+sub, flag.ExitOnError)
	scope := fs.String("scope", "", "key scope, e.g. abs-core/2026-09")
	wait := fs.String("wait", "", "waiting period before destruction (default keys.min_wait)")
	force := fs.Bool("force", false, "deactivate: also the current month (intake from the source stops until the month ends)")
	var approve multiFlag
	fs.Var(&approve, "approve", "approver name (repeatable)")
	switch sub {
	case "list":
		return adminGet(args, "/admin/keys", fs)
	case "due":
		return adminGet(args, "/admin/keys/due", fs)
	case "complete":
		return adminPost(args, "/admin/keys/complete", nil, fs)
	case "destroy-orphan-roots":
		return adminPost(args, "/admin/keys/destroy-orphan-roots", nil, fs)
	case "deactivate":
		return adminPost(args, "/admin/keys/deactivate", func() any {
			return map[string]any{"scopes": []string{*scope}, "force": *force}
		}, fs)
	case "schedule":
		return adminPost(args, "/admin/keys/schedule", func() any {
			return server.ScheduleRequest{Scope: *scope, Wait: *wait, Approvals: approve}
		}, fs)
	case "cancel":
		return adminPost(args, "/admin/keys/cancel", func() any {
			return server.ScheduleRequest{Scope: *scope, Approvals: approve}
		}, fs)
	}
	return fmt.Errorf("keys: unknown subcommand %q", sub)
}

func cmdSources(args []string) error {
	if len(args) == 0 || args[0] != "bind" {
		return errors.New("sources: bind")
	}
	fs := flag.NewFlagSet("sources bind", flag.ExitOnError)
	source := fs.String("source", "", "source name")
	epoch := fs.String("epoch", "", "collector epoch (32 hex digits, from the collector's error message)")
	return adminPost(args[1:], "/admin/sources/bind", func() any {
		return server.BindRequest{Source: *source, Epoch: *epoch}
	}, fs)
}

func adminGet(args []string, path string, fs *flag.FlagSet) error {
	if fs == nil {
		fs = flag.NewFlagSet(path, flag.ExitOnError)
	}
	cfg, err := loadConfig(fs, args)
	if err != nil {
		return err
	}
	body, err := adminDo(cfg, http.MethodGet, path, nil)
	if err != nil {
		return err
	}
	return output("", body)
}

func adminPost(args []string, path string, payload func() any, fs *flag.FlagSet) error {
	if fs == nil {
		fs = flag.NewFlagSet(path, flag.ExitOnError)
	}
	cfg, err := loadConfig(fs, args)
	if err != nil {
		return err
	}
	var data []byte
	if payload != nil {
		data, _ = json.Marshal(payload())
	}
	body, err := adminDo(cfg, http.MethodPost, path, data)
	if err != nil {
		return err
	}
	return output("", body)
}

func adminDo(cfg *config.Config, method, path string, payload []byte) ([]byte, error) {
	client := &http.Client{
		Timeout: 2 * time.Minute,
		Transport: &http.Transport{DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			return (&net.Dialer{}).DialContext(ctx, "unix", cfg.AdminSocket)
		}},
	}
	req, err := http.NewRequest(method, "http://admin"+path, bytes.NewReader(payload))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("admin socket %s (is the server running?): %w", cfg.AdminSocket, err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != http.StatusOK {
		var e server.ErrorResponse
		if json.Unmarshal(body, &e) == nil && e.Error != "" {
			return nil, fmt.Errorf("%s: %s", resp.Status, e.Error)
		}
		return nil, fmt.Errorf("%s: %s", resp.Status, body)
	}
	return body, nil
}

func output(path string, body []byte) error {
	if path == "" {
		_, err := os.Stdout.Write(body)
		return err
	}
	// Пакет с ключом записи открывает тело: файл — только владельцу.
	if err := os.WriteFile(path, body, 0o600); err != nil {
		return err
	}
	fmt.Fprintf(os.Stderr, "written %s (%d bytes)\n", path, len(body))
	return nil
}
