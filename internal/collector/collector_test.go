package collector

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"evidencestore/internal/config"
	"evidencestore/internal/evidence"
	"evidencestore/internal/keyring"
	"evidencestore/internal/pki"
	"evidencestore/internal/proof"
	"evidencestore/internal/server"
	"evidencestore/internal/store"
)

var quiet = slog.New(slog.NewTextHandler(io.Discard, nil))

type rig struct {
	st     *store.Store
	srv    *httptest.Server
	cfg    *Config
	logDir string
}

func newRig(t *testing.T) *rig {
	t.Helper()
	dir := t.TempDir()
	ca, _ := pki.NewCA("ca")
	srvCert, _ := ca.Server("127.0.0.1")
	srvCert.Write(dir, "server")
	pki.WriteCert(filepath.Join(dir, "ca.crt"), ca.Cert)
	cl, _ := ca.Client("abs-core")
	cl.Write(dir, "abs-core")

	scfg := &config.Config{
		DataDir: filepath.Join(dir, "data"), RootsDir: filepath.Join(dir, "roots"),
		TLS:     config.TLS{Cert: filepath.Join(dir, "server.crt"), Key: filepath.Join(dir, "server.key"), ClientCA: filepath.Join(dir, "ca.crt")},
		TSA:     config.TSA{URL: "local"},
		Sources: []config.Source{{Name: "abs-core", ContentType: "syslog"}},
	}
	scfg.Defaults()
	if _, err := store.Init(scfg); err != nil {
		t.Fatal(err)
	}
	st, err := store.Open(scfg, store.Options{Logger: quiet, NoBackground: true})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	tlsCfg, err := server.TLSConfig(scfg)
	if err != nil {
		t.Fatal(err)
	}
	hs := httptest.NewUnstartedServer(server.New(scfg, st, quiet).IntakeHandler())
	hs.TLS = tlsCfg
	hs.StartTLS()
	t.Cleanup(hs.Close)

	logDir := t.TempDir()
	cfg := &Config{
		Server: hs.URL, CA: filepath.Join(dir, "ca.crt"),
		Cert: filepath.Join(dir, "abs-core.crt"), Key: filepath.Join(dir, "abs-core.key"),
		StoreKey: st.PublicKey(), SpoolDir: filepath.Join(t.TempDir(), "spool"),
		File: filepath.Join(logDir, "audit.log"), FromStart: true,
	}
	if err := cfg.validate(); err != nil {
		t.Fatal(err)
	}
	return &rig{st: st, srv: hs, cfg: cfg, logDir: logDir}
}

func (r *rig) collector(t *testing.T) *Collector {
	t.Helper()
	c, err := New(r.cfg, quiet)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { c.Close() })
	if err := c.Bootstrap(context.Background()); err != nil {
		t.Fatal(err)
	}
	return c
}

func appendLines(t *testing.T, path string, lines ...string) {
	t.Helper()
	f, err := os.OpenFile(path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	for _, l := range lines {
		f.WriteString(l)
	}
}

func cycle(t *testing.T, c *Collector) {
	t.Helper()
	if _, err := c.ReadOnce(); err != nil {
		t.Fatal(err)
	}
	if err := c.SendOnce(context.Background()); err != nil {
		t.Fatal(err)
	}
}

// bodies — что хранилище приняло от источника, по номерам.
func (r *rig) bodies(t *testing.T) []string {
	t.Helper()
	last, _ := r.st.LastSeq("abs-core")
	var out []string
	for q := uint64(1); q <= last; q++ {
		b, err := r.st.Proof("abs-core", q, true)
		if err != nil {
			out = append(out, fmt.Sprintf("<нет %d: %v>", q, err))
			continue
		}
		sealed, _ := evidence.Unmarshal(b.Evidence)
		body, _ := keyring.OpenWithDEK(sealed.Envelope, b.DEK)
		out = append(out, string(body))
	}
	return out
}

func TestDeliveryAndPromises(t *testing.T) {
	r := newRig(t)
	c := r.collector(t)
	appendLines(t, r.cfg.File, "login admin\n", "delete table payments\n", "half a li")
	cycle(t, c)
	if got := strings.Join(r.bodies(t), "|"); got != "login admin|delete table payments" {
		t.Fatalf("доставлено: %q", got)
	}
	appendLines(t, r.cfg.File, "ne\n")
	cycle(t, c)
	if got := r.bodies(t); len(got) != 3 || got[2] != "half a line" {
		t.Fatalf("дописанная строка: %q", got)
	}
	ps, err := Promises(r.cfg.SpoolDir)
	if err != nil || len(ps) != 3 {
		t.Fatalf("обещания: %d, %v", len(ps), err)
	}
	pub, _ := base64.RawStdEncoding.DecodeString(r.st.PublicKey())
	for _, p := range ps {
		if err := proof.VerifyPromise(p, ed25519.PublicKey(pub)); err != nil {
			t.Fatal(err)
		}
	}
}

// Падение после записи в буфер, до отправки: после рестарта те же строки
// уходят с теми же номерами, без повторов.
func TestRestartNoDuplicates(t *testing.T) {
	r := newRig(t)
	c := r.collector(t)
	appendLines(t, r.cfg.File, "a\n", "b\n")
	cycle(t, c)
	appendLines(t, r.cfg.File, "c\n", "d\n")
	if _, err := c.ReadOnce(); err != nil { // в буфере, не отправлено
		t.Fatal(err)
	}
	c.Close()
	c2 := r.collector(t)
	if c2.Pending() != 2 {
		t.Fatalf("после рестарта в буфере %d", c2.Pending())
	}
	cycle(t, c2)
	appendLines(t, r.cfg.File, "e\n")
	cycle(t, c2)
	if got := strings.Join(r.bodies(t), ""); got != "abcde" {
		t.Fatalf("принято: %q", got)
	}
}

// Ротация файла: новый файл читается с начала.
func TestRotation(t *testing.T) {
	r := newRig(t)
	c := r.collector(t)
	appendLines(t, r.cfg.File, "1\n", "2\n")
	cycle(t, c)
	os.Rename(r.cfg.File, r.cfg.File+".1")
	appendLines(t, r.cfg.File, "3\n")
	cycle(t, c)
	if got := strings.Join(r.bodies(t), ""); got != "123" {
		t.Fatalf("после ротации: %q", got)
	}
}

// Переустановка сборщика (буфер потерян): нумерация продолжается с
// последнего принятого номера, а не с единицы.
func TestReinstallContinuesNumbering(t *testing.T) {
	r := newRig(t)
	c := r.collector(t)
	appendLines(t, r.cfg.File, "x\n", "y\n")
	cycle(t, c)
	c.Close()
	os.RemoveAll(r.cfg.SpoolDir)
	r.cfg.FromStart = false
	c2 := r.collector(t)
	appendLines(t, r.cfg.File, "z\n")
	cycle(t, c2)
	if got := strings.Join(r.bodies(t), ""); got != "xyz" {
		t.Fatalf("после переустановки: %q", got)
	}
}

// Хранилище недоступно: записи ждут в буфере и уходят, когда оно вернётся.
func TestStoreDownKeepsSpool(t *testing.T) {
	r := newRig(t)
	c := r.collector(t)
	good := r.cfg.Server
	c.cfg.Server = "https://127.0.0.1:1"
	appendLines(t, r.cfg.File, "p\n", "q\n")
	c.ReadOnce()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := c.SendOnce(ctx); err == nil {
		t.Fatal("отправка в недоступное хранилище прошла")
	}
	if c.Pending() != 2 {
		t.Fatalf("в буфере %d", c.Pending())
	}
	c.cfg.Server = good
	cycle(t, c)
	if got := strings.Join(r.bodies(t), ""); got != "pq" {
		t.Fatalf("после возврата: %q", got)
	}
}

// Сборщик с закреплённым ключом не станет говорить с чужим хранилищем.
func TestPinnedStoreKey(t *testing.T) {
	r := newRig(t)
	other := newRig(t)
	r.cfg.StoreKey = other.st.PublicKey()
	c, err := New(r.cfg, quiet)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	if err := c.Bootstrap(context.Background()); err == nil {
		t.Fatal("сборщик принял хранилище с чужим ключом")
	}
}

// Ротация с недочитанным хвостом: старый файл дочитывается до конца, вместе
// с последней строкой без перевода строки.
func TestRotationDrainsOldFile(t *testing.T) {
	r := newRig(t)
	c := r.collector(t)
	appendLines(t, r.cfg.File, "1\n", "2\n")
	cycle(t, c)
	appendLines(t, r.cfg.File, "2b\n", "2c")
	os.Rename(r.cfg.File, r.cfg.File+".1")
	appendLines(t, r.cfg.File, "3\n")
	cycle(t, c)
	if got := strings.Join(r.bodies(t), ","); got != "1,2,2b,2c,3" {
		t.Fatalf("после ротации: %q", got)
	}
}

// Ротированный файл удалили раньше, чем его дочитали: потеря не тихая — в
// нумерации пропуск, который хранилище запишет в цепь.
func TestLostRotatedTailLeavesGap(t *testing.T) {
	r := newRig(t)
	c := r.collector(t)
	appendLines(t, r.cfg.File, "1\n")
	cycle(t, c)
	appendLines(t, r.cfg.File, "lost\n")
	os.Rename(r.cfg.File, r.cfg.File+".1")
	appendLines(t, r.cfg.File, "2\n") // новый файл создан, пока старый ещё есть: inode другой
	os.Remove(r.cfg.File + ".1")
	cycle(t, c)
	if last, _ := r.st.LastSeq("abs-core"); last != 3 {
		t.Fatalf("последний номер %d, ожидали 3 (номер 2 пропущен)", last)
	}
	if _, err := r.st.Proof("abs-core", 2, false); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("номер 2: %v", err)
	}
	if got := r.bodies(t); got[2] != "2" {
		t.Fatalf("принято: %q", got)
	}
}

// Пачка ограничена и числом записей, и байтами: длинные строки не упираются
// в предел запроса хранилища.
func TestBigLinesFitRequestLimit(t *testing.T) {
	r := newRig(t)
	c := r.collector(t)
	line := strings.Repeat("x", 900<<10)
	for i := 0; i < 20; i++ {
		appendLines(t, r.cfg.File, fmt.Sprintf("%02d%s\n", i, line))
	}
	cycle(t, c)
	if last, _ := r.st.LastSeq("abs-core"); last != 20 {
		t.Fatalf("доставлено %d из 20", last)
	}
}
