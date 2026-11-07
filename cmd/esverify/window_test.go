package main

import (
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/Nikolay1994Kaz/evidencestore/internal/config"
	"github.com/Nikolay1994Kaz/evidencestore/internal/keyring"
	"github.com/Nikolay1994Kaz/evidencestore/internal/proof"
	"github.com/Nikolay1994Kaz/evidencestore/internal/store"
)

// windowWorld — хранилище по часам теста и пакет за окно 10:04–10:06:
// улики 1–2 в 10:00 и метка, улики 3–4 в 10:05, метка в 10:10, запись
// web-1 и метка в 10:11 (её хвосты — верхний край пакета по источнику). С
// -source abs-core -dek — с телами улик 3–4. source — пакет по abs-core за
// то же окно, с телами.
type windowWorld struct {
	dir, bundle, bare, source, single, key, trust string
}

func newWindowWorld(t *testing.T) windowWorld {
	t.Helper()
	dir := t.TempDir()
	cfg := &config.Config{
		DataDir: filepath.Join(dir, "data"), RootsDir: filepath.Join(dir, "roots"),
		TSA:     config.TSA{URL: "local"},
		Sources: []config.Source{{Name: "abs-core", ContentType: "syslog"}, {Name: "web-1", ContentType: "syslog"}},
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
	advance(time.Minute)
	if _, err := s.Ingest("web-1", in(1)); err != nil {
		t.Fatal(err)
	}
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
	if err := os.WriteFile(broken, []byte(`{"kind": "window", "v": 99}`), 0o600); err != nil {
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
		!strings.Contains(out, "Every record \"abs-core\" put into the store's chain from the source tails laid right before the time-stamp of 2026-10-26 10:00:00 UTC to the first source tails laid after the time-stamp of 2026-10-26 10:10:00 UTC is in this bundle: records 3–4 (2, 2 received in the window)") {
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
	if err := os.WriteFile(broken, []byte(`{"kind": "source", "v": 99}`), 0o600); err != nil {
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

// Пакет по субъекту (DECISIONS, п. 32): отчёт называет его, -bodies пишет только
// его записи, подделка отказа даёт код 1 и файлов не оставляет.
func TestSubjectBundle(t *testing.T) {
	dir := t.TempDir()
	cfg := &config.Config{
		DataDir: filepath.Join(dir, "data"), RootsDir: filepath.Join(dir, "roots"),
		TSA:     config.TSA{URL: "local"},
		Sources: []config.Source{{Name: "agent", ContentType: "application/json", SubjectField: "client"}},
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
	line := func(q uint64, client string) {
		t.Helper()
		if _, err := s.Ingest("agent", []store.Incoming{{Seq: q, Body: []byte(`{"client":"` + client + `"}`)}}); err != nil {
			t.Fatal(err)
		}
	}
	line(1, "c-1")
	if _, err := s.Stamp(t.Context()); err != nil {
		t.Fatal(err)
	}
	advance(5 * time.Minute)
	line(2, "c-1")
	line(3, "c-2")
	advance(5 * time.Minute)
	for range 2 {
		if _, err := s.StampNow(t.Context()); err != nil {
			t.Fatal(err)
		}
	}
	from, to := time.Date(2026, 10, 26, 10, 4, 0, 0, time.UTC), time.Date(2026, 10, 26, 10, 6, 0, 0, time.UTC)
	b, err := s.ProofSubject("agent", "c-1", from, to, 0)
	if err != nil {
		t.Fatal(err)
	}
	write := func(name string, data []byte) string {
		p := filepath.Join(dir, name)
		if err := os.WriteFile(p, data, 0o600); err != nil {
			t.Fatal(err)
		}
		return p
	}
	data, _ := json.Marshal(b)
	w := windowWorld{dir: dir, key: write("store.key", []byte(s.PublicKey())), trust: write("tsa-root.crt", s.TSARoot())}
	bundle := write("subject.json", data)

	bodies := filepath.Join(dir, "bodies")
	code, out, _ := w.run(t, bundle, "-bodies", bodies)
	if code != exitValid || !strings.Contains(out, "(field \"client\", label "+fmt.Sprintf("%x", b.Subject.Tag)+"): 1 of the 2 records received in the window, 1 of them open, the other 1 stay closed") {
		t.Fatalf("код %d:\n%s", code, out)
	}
	files, _ := os.ReadDir(bodies)
	if len(files) != 1 || files[0].Name() != "agent-2" {
		t.Fatalf("файлы %v", files)
	}
	if got, _ := os.ReadFile(filepath.Join(bodies, "agent-2")); string(got) != `{"client":"c-1"}` {
		t.Fatalf("тело %q", got)
	}

	// Клиент без записей в окне: писать нечего, и это не ошибка.
	none, err := s.ProofSubject("agent", "c-3", from, to, 0)
	if err != nil {
		t.Fatal(err)
	}
	data, _ = json.Marshal(none)
	empty := filepath.Join(dir, "bodies-none")
	if code, _, errOut := w.run(t, write("none.json", data), "-bodies", empty); code != exitValid || !strings.Contains(errOut, "no record of the window is under this label") {
		t.Fatalf("субъект без записей: код %d, %s", code, errOut)
	}

	code, out, _ = w.run(t, bundle, "-json")
	var rep map[string]any
	if err := json.Unmarshal([]byte(out), &rep); code != exitValid || err != nil {
		t.Fatalf("код %d, %v:\n%s", code, err, out)
	}
	sub, _ := rep["subject"].(map[string]any)
	if sub["value"] != "c-1" || sub["field"] != "client" || sub["records"] != 1.0 || sub["others"] != 1.0 {
		t.Fatalf("отчёт JSON: %v", rep["subject"])
	}
	if rep["source_named"] != true {
		t.Fatalf("source_named: %v", rep["source_named"])
	}

	forged := filepath.Join(dir, "bodies-forged")
	b.Subject.Value = "c-2"
	data, _ = json.Marshal(b)
	if code, _, errOut := w.run(t, write("forged.json", data), "-bodies", forged); code != exitInvalid || !strings.Contains(errOut, "bodies not written") {
		t.Fatalf("подделка: код %d, %s", code, errOut)
	}
	if _, err := os.Stat(forged); err == nil {
		t.Fatal("подделка оставила файлы")
	}
}

// subjectWorld — источник agent с subject_field: запись 1 (c-1), метка, через пять
// минут записи 2 (c-1) и 3 (c-2), ещё через пять две метки. Окно from–to держит
// записи 2 и 3, окно emptyFrom–emptyTo пусто, а метки вокруг него есть.
type subjectWorld struct {
	windowWorld
	s                            *store.Store
	advance                      func(time.Duration)
	from, to, emptyFrom, emptyTo time.Time
}

// openWorld — хранилище с этими источниками, часы теста стоят на 10:00.
func openWorld(t *testing.T, sources []config.Source) subjectWorld {
	t.Helper()
	dir := t.TempDir()
	cfg := &config.Config{
		DataDir: filepath.Join(dir, "data"), RootsDir: filepath.Join(dir, "roots"),
		TSA:     config.TSA{URL: "local"},
		Sources: sources,
		Keys:    config.Keys{MinWait: config.Duration(time.Nanosecond)},
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
	t.Cleanup(func() { s.Close() })
	w := subjectWorld{s: s, advance: advance,
		from: time.Date(2026, 10, 26, 10, 4, 0, 0, time.UTC), to: time.Date(2026, 10, 26, 10, 6, 0, 0, time.UTC),
		emptyFrom: time.Date(2026, 10, 26, 10, 1, 0, 0, time.UTC), emptyTo: time.Date(2026, 10, 26, 10, 2, 0, 0, time.UTC),
	}
	w.dir = dir
	w.key = w.file(t, "store.key", []byte(s.PublicKey()))
	w.trust = w.file(t, "tsa-root.crt", s.TSARoot())
	return w
}

func (w subjectWorld) line(t *testing.T, source string, q uint64, body string) {
	t.Helper()
	if _, err := w.s.Ingest(source, []store.Incoming{{Seq: q, Body: []byte(body)}}); err != nil {
		t.Fatal(err)
	}
}

func (w subjectWorld) stamp(t *testing.T) {
	t.Helper()
	if _, err := w.s.Stamp(t.Context()); err != nil {
		t.Fatal(err)
	}
}

// closeUp — две метки сразу: закрывающая и та, чьи хвосты — верхний край.
func (w subjectWorld) closeUp(t *testing.T) {
	t.Helper()
	for range 2 {
		if _, err := w.s.StampNow(t.Context()); err != nil {
			t.Fatal(err)
		}
	}
}

func newSubjectWorld(t *testing.T) subjectWorld {
	t.Helper()
	w := openWorld(t, []config.Source{{Name: "agent", ContentType: "application/json", SubjectField: "client"}})
	w.line(t, "agent", 1, `{"client":"c-1"}`)
	w.stamp(t)
	w.advance(5 * time.Minute)
	w.line(t, "agent", 2, `{"client":"c-1"}`)
	w.line(t, "agent", 3, `{"client":"c-2"}`)
	w.advance(5 * time.Minute)
	w.closeUp(t)
	return w
}

// file пишет данные в файл мира; не []byte — как JSON.
func (w windowWorld) file(t *testing.T, name string, v any) string {
	t.Helper()
	data, ok := v.([]byte)
	if !ok {
		var err error
		if data, err = json.Marshal(v); err != nil {
			t.Fatal(err)
		}
	}
	p := filepath.Join(w.dir, name)
	if err := os.WriteFile(p, data, 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

// Закон -bodies: окно, в котором пакет не показывает записей, — код 0 и точная
// фраза (скрипт, идущий окно за окном, не встаёт); записи есть, а не открылось ни
// одно тело, — код 2 и причина. Открылась часть — код 0, остальное считает отчёт.
func TestBodiesEmptyWindow(t *testing.T) {
	w := newSubjectWorld(t)
	src, err := w.s.ProofSource("agent", w.emptyFrom, w.emptyTo, true, 0)
	if err != nil {
		t.Fatal(err)
	}
	win, err := w.s.ProofWindow(w.emptyFrom, w.emptyTo, "agent", true, 0)
	if err != nil {
		t.Fatal(err)
	}
	sub, err := w.s.ProofSubject("agent", "c-1", w.emptyFrom, w.emptyTo, 0)
	if err != nil {
		t.Fatal(err)
	}
	for name, b := range map[string]any{"source": src, "window": win, "subject": sub} {
		file := w.file(t, name+".json", b)
		code, out, errOut := w.run(t, file, "-bodies", filepath.Join(w.dir, "bodies-"+name))
		if code != exitValid || !strings.Contains(errOut, "no record received in the window it names") {
			t.Errorf("%s: код %d, %s\n%s", name, code, errOut, out)
		}
		code, out, errOut = w.run(t, file, "-bodies", filepath.Join(w.dir, "own-"+name),
			"-from", w.emptyFrom.Format(time.RFC3339), "-to", w.emptyTo.Format(time.RFC3339))
		if code != exitValid || !strings.Contains(errOut, "no record received in your window") {
			t.Errorf("%s, своё окно: код %d, %s\n%s", name, code, errOut, out)
		}
	}
}

// Пакет -window не называет источник своих ключей: пусто только окно без записей
// всех источников, а не первого из них.
func TestBodiesQuietFirstSource(t *testing.T) {
	w := openWorld(t, []config.Source{{Name: "aaa", ContentType: "syslog"}, {Name: "zzz", ContentType: "syslog"}})
	w.line(t, "aaa", 1, "a1")
	w.line(t, "zzz", 1, "z1")
	w.stamp(t)
	w.advance(5 * time.Minute)
	w.line(t, "aaa", 2, "a2")
	w.advance(30 * time.Second)
	w.line(t, "zzz", 2, "z2")
	w.advance(5 * time.Minute)
	w.closeUp(t)
	from := time.Date(2026, 10, 26, 10, 5, 10, 0, time.UTC)
	win, err := w.s.ProofWindow(from, w.to, "", false, 0)
	if err != nil {
		t.Fatal(err)
	}
	code, out, errOut := w.run(t, w.file(t, "w.json", win), "-bodies", filepath.Join(w.dir, "bodies"))
	if code != exitUsage || strings.Contains(errOut, "no record received") {
		t.Fatalf("код %d, %s\n%s", code, errOut, out)
	}
}

// Открылась часть записей под меткой: тела пишутся, код 0, остальное считает отчёт.
func TestBodiesPartlyOpen(t *testing.T) {
	w := openWorld(t, []config.Source{{Name: "agent", ContentType: "application/json", SubjectField: "client"}})
	w.line(t, "agent", 1, `{"client":"c-1"}`)
	w.stamp(t)
	w.advance(5 * time.Minute)
	w.line(t, "agent", 2, `{"client":"c-1","n":1}`)
	w.line(t, "agent", 3, `{"client":"c-1","n":2}`)
	w.advance(5 * time.Minute)
	w.closeUp(t)
	b, err := w.s.ProofSubject("agent", "c-1", w.from, w.to, 0)
	if err != nil {
		t.Fatal(err)
	}
	stripped := false
	for i := range b.Records {
		if len(b.Records[i].DEK) > 0 && !stripped {
			b.Records[i].DEK, stripped = nil, true
		}
	}
	bodies := filepath.Join(w.dir, "bodies")
	code, out, _ := w.run(t, w.file(t, "partly.json", b), "-bodies", bodies)
	files, _ := os.ReadDir(bodies)
	if code != exitValid || len(files) != 1 || !strings.Contains(out, "1 of the 2 records under this label come without a record key") {
		t.Fatalf("код %d, файлов %d:\n%s", code, len(files), out)
	}
}

// Все записи окна поломаны, ключи в пакете есть: причина — не ключи.
func TestBodiesBrokenGatewayRecords(t *testing.T) {
	dir := filepath.Join("..", "..", "internal", "gateway", "testdata", "pipelock-v3.6.0")
	raw, err := os.ReadFile(filepath.Join(dir, "pubkey.hex"))
	if err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(filepath.Join(dir, "tampered.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(strings.TrimRight(string(data), "\n"), "\n")
	w := openWorld(t, []config.Source{{Name: "gw", ContentType: config.GatewayContentType, GatewayKey: strings.TrimSpace(string(raw))}})
	w.line(t, "gw", 1, lines[0])
	w.line(t, "gw", 2, lines[1])
	w.stamp(t)
	w.advance(5 * time.Minute)
	w.line(t, "gw", 3, lines[2])
	w.advance(5 * time.Minute)
	w.closeUp(t)
	b, err := w.s.ProofSource("gw", w.from, w.to, true, 0)
	if err != nil {
		t.Fatal(err)
	}
	code, out, errOut := w.run(t, w.file(t, "gw.json", b), "-bodies", filepath.Join(w.dir, "bodies"))
	if code != exitUsage || !strings.Contains(out, "found broken") {
		t.Fatalf("код %d:\n%s", code, out)
	}
	if !strings.Contains(errOut, "found its records broken at intake") || strings.Contains(errOut, "carries no record keys") {
		t.Fatalf("сообщение: %s", errOut)
	}
}

func TestBodiesClosedRecords(t *testing.T) {
	w := newSubjectWorld(t)
	src, err := w.s.ProofSource("agent", w.from, w.to, false, 0)
	if err != nil {
		t.Fatal(err)
	}
	win, err := w.s.ProofWindow(w.from, w.to, "", false, 0)
	if err != nil {
		t.Fatal(err)
	}
	for name, b := range map[string]any{"source": src, "window": win} {
		code, _, errOut := w.run(t, w.file(t, name+".json", b), "-bodies", filepath.Join(w.dir, "bodies-"+name))
		if code != exitUsage || !strings.Contains(errOut, "evidencestore proof -source S -dek") {
			t.Errorf("%s: код %d, %s", name, code, errOut)
		}
	}
}

// Под меткой в окне ничего нет, а записи в окне есть: -bodies не утверждает, что
// записей субъекта нет: метка выдумана, или они лежат без метки.
func TestBodiesNoRecordUnderLabel(t *testing.T) {
	w := newSubjectWorld(t)
	b, err := w.s.ProofSubject("agent", "c-1", w.from, w.to, 0)
	if err != nil {
		t.Fatal(err)
	}
	for i := range b.Records {
		b.Records[i].DEK = nil
	}
	b.Subject.Tag = []byte("0123456789abcdef")
	code, out, errOut := w.run(t, w.file(t, "forged.json", b), "-bodies", filepath.Join(w.dir, "bodies"))
	if code != exitValid || !strings.Contains(out, "that the subject has no records") {
		t.Fatalf("код %d:\n%s", code, out)
	}
	if !strings.Contains(errOut, "does not show that the subject has none") || strings.Contains(errOut, "holds no records") {
		t.Fatalf("сообщение: %s", errOut)
	}
}

// Записи субъекта есть, ключ месяца ждёт уничтожения: код 2 с настоящей причиной,
// без совета взять -dek (открыл бы всех клиентов окна) и окно шире (шире не откроется).
func TestBodiesKeyAwaitsDestruction(t *testing.T) {
	w := newSubjectWorld(t)
	scope := "agent/2026-10"
	if err := w.s.Deactivate(true, scope); err != nil {
		t.Fatal(err)
	}
	if _, err := w.s.ScheduleDestroy(t.Context(), scope, time.Hour, []keyring.Approval{{Who: "operator"}, {Who: "security"}}); err != nil {
		t.Fatal(err)
	}
	b, err := w.s.ProofSubject("agent", "c-1", w.from, w.to, 0)
	if err != nil {
		t.Fatal(err)
	}
	code, out, errOut := w.run(t, w.file(t, "keyless.json", b), "-bodies", filepath.Join(w.dir, "bodies"))
	if code != exitUsage || !strings.Contains(out, "come without a record key") {
		t.Fatalf("код %d:\n%s", code, out)
	}
	if !strings.Contains(errOut, "the month key was destroyed") || !strings.Contains(errOut, "removed from this bundle") ||
		strings.Contains(errOut, "wider window") || strings.Contains(errOut, "-dek") {
		t.Fatalf("сообщение: %s", errOut)
	}
}

// Заметка велит сравнить метку с пакетом, где тело открыто: метка видна в отчёте
// обоих пакетов.
func TestSubjectLabelIsInTheReport(t *testing.T) {
	w := newSubjectWorld(t)
	open, err := w.s.ProofSubject("agent", "c-1", w.from, w.to, 0)
	if err != nil {
		t.Fatal(err)
	}
	closed, err := w.s.ProofSubject("agent", "c-1", w.from, w.to, 0)
	if err != nil {
		t.Fatal(err)
	}
	for i := range closed.Records {
		closed.Records[i].DEK = nil
	}
	label := fmt.Sprintf(`Subject: "c-1" (field "client", label %x)`, open.Subject.Tag)
	for name, b := range map[string]any{"open": open, "closed": closed} {
		code, out, _ := w.run(t, w.file(t, name+".json", b))
		if code != exitValid || !strings.Contains(out, label) {
			t.Fatalf("%s: код %d, нет %q:\n%s", name, code, label, out)
		}
	}
}

// subject_field включили на источнике с историей: запись клиента в окне есть, без
// метки, под меткой пусто. -bodies не говорит, что записей нет.
func TestBodiesUnlabeledHistory(t *testing.T) {
	dir := t.TempDir()
	cfg := &config.Config{
		DataDir: filepath.Join(dir, "data"), RootsDir: filepath.Join(dir, "roots"),
		TSA:     config.TSA{URL: "local"},
		Sources: []config.Source{{Name: "agent", ContentType: "application/json"}},
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
	opts := store.Options{Logger: slog.New(slog.NewTextHandler(io.Discard, nil)), Now: clock, NoBackground: true}
	s, err := store.Open(cfg, opts)
	if err != nil {
		t.Fatal(err)
	}
	line := func(q uint64) {
		t.Helper()
		if _, err := s.Ingest("agent", []store.Incoming{{Seq: q, Body: []byte(`{"client":"c-1"}`)}}); err != nil {
			t.Fatal(err)
		}
	}
	line(1)
	if _, err := s.Stamp(t.Context()); err != nil {
		t.Fatal(err)
	}
	advance(5 * time.Minute)
	line(2)
	s.Close()
	cfg.Sources[0].SubjectField = "client"
	if s, err = store.Open(cfg, opts); err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	advance(5 * time.Minute)
	for range 2 {
		if _, err := s.StampNow(t.Context()); err != nil {
			t.Fatal(err)
		}
	}
	b, err := s.ProofSubject("agent", "c-1", time.Date(2026, 10, 26, 10, 4, 0, 0, time.UTC), time.Date(2026, 10, 26, 10, 6, 0, 0, time.UTC), 0)
	if err != nil {
		t.Fatal(err)
	}
	w := windowWorld{dir: dir}
	w.key, w.trust = w.file(t, "store.key", []byte(s.PublicKey())), w.file(t, "tsa-root.crt", s.TSARoot())
	code, out, errOut := w.run(t, w.file(t, "s.json", b), "-bodies", filepath.Join(dir, "bodies"))
	if code != exitValid || !strings.Contains(out, "1 records received in the window carry no subject label") {
		t.Fatalf("код %d:\n%s", code, out)
	}
	if !strings.Contains(errOut, "does not show that the subject has none") {
		t.Fatalf("сообщение: %s", errOut)
	}
}
