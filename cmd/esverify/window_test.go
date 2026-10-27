package main

import (
	"encoding/json"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/Nikolay1994Kaz/evidencestore/internal/config"
	"github.com/Nikolay1994Kaz/evidencestore/internal/proof"
	"github.com/Nikolay1994Kaz/evidencestore/internal/store"
)

// windowWorld — хранилище по часам теста и пакет за окно 10:04–10:06:
// улики 1–2 в 10:00 и метка, улики 3–4 в 10:05, метка в 10:10. С -source
// abs-core -dek — с телами улик 3–4. source — пакет по abs-core за то же
// окно, с телами.
type windowWorld struct {
	dir, bundle, bare, source, single, key, trust string
}

func newWindowWorld(t *testing.T) windowWorld {
	t.Helper()
	dir := t.TempDir()
	cfg := &config.Config{
		DataDir: filepath.Join(dir, "data"), RootsDir: filepath.Join(dir, "roots"),
		TSA:     config.TSA{URL: "local"},
		Sources: []config.Source{{Name: "abs-core", ContentType: "syslog"}},
		Demo:    true,
	}
	cfg.Defaults()
	if _, err := store.Init(cfg); err != nil {
		t.Fatal(err)
	}
	var mu sync.Mutex
	now := time.Date(2026, 10, 26, 10, 0, 0, 0, time.UTC)
	clock := func() time.Time { mu.Lock(); defer mu.Unlock(); return now }
	advance := func(d time.Duration) { mu.Lock(); now = now.Add(d); mu.Unlock() }
	s, err := store.Open(cfg, store.Options{Logger: slog.New(slog.NewTextHandler(io.Discard, nil)), Now: clock, NoBackground: true})
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	in := func(q uint64) []store.Incoming {
		return []store.Incoming{{Seq: q, Body: []byte("line \x1b[31m" + string(rune('0'+q)) + "\n")}}
	}
	for _, q := range []uint64{1, 2} {
		if _, err := s.Ingest("abs-core", in(q)); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := s.Stamp(t.Context()); err != nil {
		t.Fatal(err)
	}
	advance(5 * time.Minute)
	for _, q := range []uint64{3, 4} {
		if _, err := s.Ingest("abs-core", in(q)); err != nil {
			t.Fatal(err)
		}
	}
	advance(5 * time.Minute)
	if _, err := s.Stamp(t.Context()); err != nil {
		t.Fatal(err)
	}
	from, to := time.Date(2026, 10, 26, 10, 4, 0, 0, time.UTC), time.Date(2026, 10, 26, 10, 6, 0, 0, time.UTC)
	w := windowWorld{dir: dir}
	write := func(name string, v any) string {
		data, ok := v.([]byte)
		if !ok {
			data, _ = json.Marshal(v)
		}
		p := filepath.Join(dir, name)
		if err := os.WriteFile(p, data, 0o600); err != nil {
			t.Fatal(err)
		}
		return p
	}
	b, err := s.ProofWindow(from, to, "abs-core", true, 0)
	if err != nil {
		t.Fatal(err)
	}
	w.bundle = write("window.json", b)
	bare, err := s.ProofWindow(from, to, "", false, 0)
	if err != nil {
		t.Fatal(err)
	}
	w.bare = write("window-bare.json", bare)
	src, err := s.ProofSource("abs-core", from, to, true, 0)
	if err != nil {
		t.Fatal(err)
	}
	w.source = write("source.json", src)
	single, err := s.Proof("abs-core", 3, true)
	if err != nil {
		t.Fatal(err)
	}
	w.single = write("proof.json", single)
	w.key = write("store.key", []byte(s.PublicKey()))
	w.trust = write("tsa-root.crt", s.TSARoot())
	return w
}

func (w windowWorld) run(t *testing.T, bundle string, extra ...string) (int, string, string) {
	t.Helper()
	var out, errOut strings.Builder
	args := append([]string{"-proof", bundle, "-store-key", w.key, "-tsa-trust", w.trust}, extra...)
	code := run(args, &out, &errOut)
	return code, out.String(), errOut.String()
}

func TestWindowBundle(t *testing.T) {
	w := newWindowWorld(t)
	code, out, _ := w.run(t, w.bundle)
	if code != exitValid || !strings.HasPrefix(out, "VERIFIED") || !strings.Contains(out, "Every record the store put into its chain") ||
		!strings.Contains(out, "abs-core: records 3–4 (2 in the stretch, 2 received in the window)") {
		t.Fatalf("код %d:\n%s", code, out)
	}

	// Тела — байт в байт, каждое в свой файл, только владельцу; сообщение —
	// в stderr, отчёт JSON остаётся чистым.
	dir := filepath.Join(w.dir, "bodies")
	code, out, errOut := w.run(t, w.bundle, "-bodies", dir, "-json")
	var rep map[string]any
	if err := json.Unmarshal([]byte(out), &rep); err != nil || code != exitValid || rep["kind"] != "window" || rep["valid"] != true || rep["bodies_opened"] != float64(2) {
		t.Fatalf("код %d, %v:\n%s", code, err, out)
	}
	if !strings.Contains(errOut, "2 bodies written to") {
		t.Fatalf("stderr: %s", errOut)
	}
	for _, q := range []string{"3", "4"} {
		p := filepath.Join(dir, "abs-core-"+q)
		data, err := os.ReadFile(p)
		if err != nil || string(data) != "line \x1b[31m"+q+"\n" {
			t.Fatalf("тело %s: %q, %v", q, data, err)
		}
		if st, err := os.Stat(p); err != nil || st.Mode().Perm() != 0o600 {
			t.Fatalf("права на тело %s: %v %v", q, st.Mode(), err)
		}
	}

	// Окно аудитора: внутри меток — проходит, шире — нет.
	if code, out, _ := w.run(t, w.bundle, "-from", "2026-10-26T10:01:00Z", "-to", "2026-10-26T10:07:00Z"); code != exitValid || !strings.Contains(out, "asked by the auditor") {
		t.Fatalf("окно внутри меток: код %d\n%s", code, out)
	}
	if code, out, _ := w.run(t, w.bundle, "-from", "2026-10-26T09:30:00Z", "-to", "2026-10-26T10:06:00Z"); code != exitInvalid {
		t.Fatalf("окно шире меток: код %d\n%s", code, out)
	}
}

// Флаги одного вида пакета к другому не подходят: неверный вызов (2).
func TestWindowFlags(t *testing.T) {
	w := newWindowWorld(t)
	promise := filepath.Join(w.dir, "promise.json") // разбирается: отказ — из-за вида пакета, а не файла
	if err := os.WriteFile(promise, []byte("{}"), 0o600); err != nil {
		t.Fatal(err)
	}
	for _, extra := range [][]string{
		{"-promise", promise}, {"-body", "b.bin"}, {"-allow-no-tsa"}, {"-gateway-key", strings.Repeat("ab", 32)},
		{"-from", "вчера", "-to", "2026-10-26T10:06:00Z"}, {"-from", "2026-10-26T10:04:00Z", "-to", "сегодня"},
	} {
		if code, out, errOut := w.run(t, w.bundle, extra...); code != exitUsage {
			t.Fatalf("%v с пакетом за окно: код %d\n%s%s", extra, code, out, errOut)
		}
	}
	for _, extra := range [][]string{{"-bodies", "dir"}, {"-from", "2026-10-26T10:04:00Z", "-to", "2026-10-26T10:06:00Z"}} {
		if code, out, errOut := w.run(t, w.single, extra...); code != exitUsage {
			t.Fatalf("%v с пакетом одной улики: код %d\n%s%s", extra, code, out, errOut)
		}
	}
	// -bodies у пакета без тел — неверный вызов, файлов нет.
	dir := filepath.Join(w.dir, "none")
	if code, _, errOut := w.run(t, w.bare, "-bodies", dir); code != exitUsage || !strings.Contains(errOut, "no record keys") {
		t.Fatalf("пакет без тел: код %d, %s", code, errOut)
	}
	if _, err := os.Stat(dir); !os.IsNotExist(err) {
		t.Fatalf("каталог тел создан: %v", err)
	}
}

// Подделанный пакет — провал (1), тела не пишутся; пакет вида «окно»,
// который не разбирается, — тоже провал, а не неверный вызов.
func TestWindowForged(t *testing.T) {
	w := newWindowWorld(t)
	data, err := os.ReadFile(w.bundle)
	if err != nil {
		t.Fatal(err)
	}
	b, err := proof.ParseWindow(data)
	if err != nil {
		t.Fatal(err)
	}
	b.Leaves = append(b.Leaves[:1], b.Leaves[2:]...)
	forged, _ := json.Marshal(b)
	path := filepath.Join(w.dir, "forged.json")
	if err := os.WriteFile(path, forged, 0o600); err != nil {
		t.Fatal(err)
	}
	dir := filepath.Join(w.dir, "bodies")
	code, out, errOut := w.run(t, path, "-bodies", dir)
	if code != exitInvalid || !strings.HasPrefix(out, "NOT VERIFIED") || !strings.Contains(errOut, "bodies not written") {
		t.Fatalf("подделка: код %d\n%s%s", code, out, errOut)
	}
	if _, err := os.Stat(dir); !os.IsNotExist(err) {
		t.Fatalf("тела подделки записаны: %v", err)
	}
	broken := filepath.Join(w.dir, "broken.json")
	if err := os.WriteFile(broken, []byte(`{"kind": "window", "v": 3}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if code, out, _ := w.run(t, broken, "-json"); code != exitInvalid || !strings.Contains(out, "the window bundle parses") {
		t.Fatalf("неразборчивый пакет: код %d\n%s", code, out)
	}
}

// Пакет по источнику — тем же вызовом, что пакет за окно: отчёт, тела,
// подделка, флаги пакета одной улики.
func TestSourceBundle(t *testing.T) {
	w := newWindowWorld(t)
	code, out, _ := w.run(t, w.source)
	if code != exitValid || !strings.HasPrefix(out, "VERIFIED") ||
		!strings.Contains(out, "Every record abs-core put into the store's chain from the time-stamp of 2026-10-26 10:00:00 UTC to the time-stamp of 2026-10-26 10:10:00 UTC is in this bundle: records 3–4 (2, 2 received in the window)") {
		t.Fatalf("код %d:\n%s", code, out)
	}
	dir := filepath.Join(w.dir, "bodies")
	code, out, errOut := w.run(t, w.source, "-bodies", dir, "-json")
	var rep map[string]any
	if err := json.Unmarshal([]byte(out), &rep); err != nil || code != exitValid || rep["kind"] != "source" || rep["valid"] != true ||
		rep["source"] != "abs-core" || rep["records"] != float64(2) || rep["first_seq"] != float64(3) || rep["last_seq"] != float64(4) || rep["bodies_opened"] != float64(2) {
		t.Fatalf("код %d, %v:\n%s", code, err, out)
	}
	if !strings.Contains(errOut, "2 bodies written to") {
		t.Fatalf("stderr: %s", errOut)
	}
	for _, q := range []string{"3", "4"} {
		if data, err := os.ReadFile(filepath.Join(dir, "abs-core-"+q)); err != nil || string(data) != "line \x1b[31m"+q+"\n" {
			t.Fatalf("тело %s: %q, %v", q, data, err)
		}
	}
	for _, extra := range [][]string{{"-body", "b.bin"}, {"-allow-no-tsa"}, {"-from", "вчера", "-to", "2026-10-26T10:06:00Z"}} {
		if code, out, errOut := w.run(t, w.source, extra...); code != exitUsage {
			t.Fatalf("%v с пакетом по источнику: код %d\n%s%s", extra, code, out, errOut)
		}
	}

	// Выброшенная запись — провал, тела не пишутся.
	data, err := os.ReadFile(w.source)
	if err != nil {
		t.Fatal(err)
	}
	b, err := proof.ParseSource(data)
	if err != nil {
		t.Fatal(err)
	}
	b.Records = b.Records[1:]
	forged, _ := json.Marshal(b)
	path := filepath.Join(w.dir, "forged.json")
	if err := os.WriteFile(path, forged, 0o600); err != nil {
		t.Fatal(err)
	}
	dir = filepath.Join(w.dir, "forged-bodies")
	if code, out, errOut := w.run(t, path, "-bodies", dir); code != exitInvalid || !strings.HasPrefix(out, "NOT VERIFIED") || !strings.Contains(errOut, "bodies not written") {
		t.Fatalf("подделка: код %d\n%s%s", code, out, errOut)
	}
	if _, err := os.Stat(dir); !os.IsNotExist(err) {
		t.Fatalf("тела подделки записаны: %v", err)
	}
	broken := filepath.Join(w.dir, "broken.json")
	if err := os.WriteFile(broken, []byte(`{"kind": "source", "v": 3}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if code, out, _ := w.run(t, broken, "-json"); code != exitInvalid || !strings.Contains(out, "the source bundle parses") {
		t.Fatalf("неразборчивый пакет: код %d\n%s", code, out)
	}
}

// Имя источника из пакета не выводит файл тела из каталога.
func TestSafeName(t *testing.T) {
	for in, want := range map[string]string{"abs-core": "abs-core", "../etc/x": ".._etc_x", `a\b:c`: "a_b_c", "лог": "___"} {
		if got := safeName(in); got != want {
			t.Fatalf("safeName(%q) = %q, want %q", in, got, want)
		}
	}
}
