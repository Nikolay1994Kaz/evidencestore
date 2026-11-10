package main

import (
	"bytes"
	"crypto/md5"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/Nikolay1994Kaz/evidencestore/internal/config"
	"github.com/Nikolay1994Kaz/evidencestore/internal/proof"
	"github.com/Nikolay1994Kaz/evidencestore/internal/store"
)

// Тестировщик T, третий раунд (08.11): честные каталоги проверяющего через
// esverify -heads DIR. Головы — от настоящего хранилища со свидетелем file://
// (в каталоге ровно те байты, что хранилище кладёт свидетелю одним PUT);
// проверяющий раскладывает их так, как раскладывают инструменты.
//
// Мир (одно честное хранилище):
//
//	10:00:00 метка T1; 10:00:05 обход свидетеля — головы 2, 3;
//	10:00:20 запись 1 (звено L = 4), 10:00:21–24 записи 2–5;
//	10:00:25 обход — голова 8; 10:01:00 запись 6 (газета в 10:02 — голова 9);
//	10:03:00 метка T2, 10:03:01 запись 7; 10:03:05 обход — 10, 11, 12
//	(PUT через секунду); пакет записи 1 кончается головой N = 10;
//	10:12:00 метка T3; 10:12:05 обход — 13, 14; газета в 10:15 — голова 14.

type lyClock struct {
	mu  sync.Mutex
	now time.Time
}

func (c *lyClock) Now() time.Time  { c.mu.Lock(); defer c.mu.Unlock(); return c.now }
func (c *lyClock) Set(t time.Time) { c.mu.Lock(); c.now = t; c.mu.Unlock() }

// lyHead — голова, ушедшая свидетелю: номер, байты PUT, время PUT.
type lyHead struct {
	seq  uint64
	data []byte
	at   time.Time
}

type lyWorld struct {
	t          *testing.T
	dir, wdir  string
	s          *store.Store
	clock      *lyClock
	key, trust string
	heads      []lyHead
	cps        map[uint64]proof.Checkpoint
	statements map[string][]byte // газета: evidencestore statement в момент
	honest     string
	L, N       uint64
}

func lyDay(h, m, s int) time.Time { return time.Date(2026, 11, 8, h, m, s, 0, time.UTC) }

func newLyWorld(t *testing.T) *lyWorld {
	t.Helper()
	dir := t.TempDir()
	w := &lyWorld{t: t, dir: dir, wdir: filepath.Join(dir, "witness"), clock: &lyClock{now: lyDay(10, 0, 0)},
		cps: map[uint64]proof.Checkpoint{}, statements: map[string][]byte{}}
	if err := os.MkdirAll(w.wdir, 0o700); err != nil {
		t.Fatal(err)
	}
	cfg := &config.Config{
		DataDir: filepath.Join(dir, "data"), RootsDir: filepath.Join(dir, "roots"),
		TSA:     config.TSA{URL: "local"},
		Sources: []config.Source{{Name: "abs-core", ContentType: "syslog"}},
		Demo:    true,
	}
	cfg.Witness.URL = "file://" + w.wdir
	cfg.Defaults()
	if _, err := store.Init(cfg); err != nil {
		t.Fatal(err)
	}
	s, err := store.Open(cfg, store.Options{Logger: slog.New(slog.NewTextHandler(io.Discard, nil)), Now: w.clock.Now, NoBackground: true})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Close() })
	w.s = s

	w.stamp(lyDay(10, 0, 0))
	w.pass(lyDay(10, 0, 5))
	w.line(lyDay(10, 0, 20), 1, "login admin")
	for i, body := range []string{"ls", "cat /etc/hosts", "id", "exit"} {
		w.line(lyDay(10, 0, 21+i), uint64(2+i), body)
	}
	w.pass(lyDay(10, 0, 25))
	w.line(lyDay(10, 1, 0), 6, "whoami")
	w.statement("1002", lyDay(10, 2, 0))
	w.stamp(lyDay(10, 3, 0))
	w.line(lyDay(10, 3, 1), 7, "uptime")
	w.pass(lyDay(10, 3, 5))
	b, err := s.Proof("abs-core", 1, true)
	if err != nil {
		t.Fatal(err)
	}
	w.N, w.L = b.Checkpoint.Size, b.Inclusion.LinkSeq
	w.honest = w.file("honest.json", b)
	w.stamp(lyDay(10, 12, 0))
	w.pass(lyDay(10, 12, 5))
	w.statement("1015", lyDay(10, 15, 0))
	w.key = w.file("store.key", []byte(s.PublicKey()))
	w.trust = w.file("tsa-root.crt", s.TSARoot())
	if got := w.seqs(); w.L != 4 || w.N != 10 || fmt.Sprint(got) != "[2 3 8 10 11 12 13 14]" {
		t.Fatalf("мир не тот: L=%d N=%d головы %v", w.L, w.N, got)
	}
	return w
}

func (w *lyWorld) stamp(at time.Time) {
	w.t.Helper()
	w.clock.Set(at)
	if _, err := w.s.Stamp(w.t.Context()); err != nil {
		w.t.Fatal(err)
	}
}

// line — запись и звено под неё (выдача пакета сворачивает листья в звено).
func (w *lyWorld) line(at time.Time, seq uint64, body string) {
	w.t.Helper()
	w.clock.Set(at)
	if _, err := w.s.Ingest("abs-core", []store.Incoming{{Seq: seq, Body: []byte(body)}}); err != nil {
		w.t.Fatal(err)
	}
	if _, err := w.s.Proof("abs-core", seq, false); err != nil {
		w.t.Fatal(err)
	}
}

// pass — обход свидетеля: новые головы по возрастанию номера, PUT через секунду.
func (w *lyWorld) pass(at time.Time) {
	w.t.Helper()
	w.clock.Set(at)
	before := map[string]bool{}
	paths, _ := filepath.Glob(filepath.Join(w.wdir, "heads", "*.json"))
	for _, p := range paths {
		before[p] = true
	}
	if err := w.s.WitnessOnce(w.t.Context()); err != nil {
		w.t.Fatal(err)
	}
	paths, _ = filepath.Glob(filepath.Join(w.wdir, "heads", "*.json"))
	sort.Strings(paths)
	i := 0
	for _, p := range paths {
		if before[p] {
			continue
		}
		data, err := os.ReadFile(p)
		if err != nil {
			w.t.Fatal(err)
		}
		c, err := proof.ParseCheckpoint(data)
		if err != nil {
			w.t.Fatal(err)
		}
		w.cps[c.Size] = c
		w.heads = append(w.heads, lyHead{seq: c.Size, data: data, at: at.Add(time.Duration(i) * time.Second)})
		i++
	}
}

// statement — evidencestore statement: голова, как её отдаёт админка
// (json.Encoder с отступом в пробел и переводом строки).
func (w *lyWorld) statement(name string, at time.Time) {
	w.t.Helper()
	w.clock.Set(at)
	c, err := w.s.Checkpoint()
	if err != nil {
		w.t.Fatal(err)
	}
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetIndent("", " ")
	if err := enc.Encode(c); err != nil {
		w.t.Fatal(err)
	}
	w.cps[c.Size] = c
	w.statements[name] = buf.Bytes()
}

func (w *lyWorld) seqs() []uint64 {
	var out []uint64
	for _, h := range w.heads {
		out = append(out, h.seq)
	}
	return out
}

func (w *lyWorld) file(name string, v any) string {
	w.t.Helper()
	return lyWrite(w.t, filepath.Join(w.dir, name), v)
}

// bundleTo — честный пакет записи 1 до головы n (evidencestore proof -to-head n).
func (w *lyWorld) bundleTo(n uint64) string {
	w.t.Helper()
	b, err := w.s.ProofTo("abs-core", 1, true, n)
	if err != nil {
		w.t.Fatal(err)
	}
	return w.file(fmt.Sprintf("honest-to-%d.json", n), b)
}

func (w *lyWorld) run(bundle string, extra ...string) (int, string) {
	w.t.Helper()
	return world{bundle: bundle, key: w.key, trust: w.trust}.run(w.t, extra...)
}

// verify — текст и -json одного каталога.
func (w *lyWorld) verify(bundle, dir string) (code int, text string, rep map[string]any) {
	w.t.Helper()
	code, text = w.run(bundle, "-heads", dir)
	jcode, out := w.run(bundle, "-heads", dir, "-json")
	if err := json.Unmarshal([]byte(out), &rep); err != nil || jcode != code {
		w.t.Fatalf("-json: код %d (текст — %d), %v\n%s", jcode, code, err, out)
	}
	return code, text, rep
}

func lyWrite(t *testing.T, path string, v any) string {
	t.Helper()
	data, ok := v.([]byte)
	if !ok {
		var err error
		if data, err = json.Marshal(v); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

// lyObj — версия объекта у свидетеля S3.
type lyObj struct {
	key, vid string
	seq      uint64
	data     []byte
	at       time.Time
}

var (
	lyAWS   = func(i int) string { return fmt.Sprintf("Rb_l2T8UHDkFEwCgJjhlgPOZC0qJ%04d", i) }
	lyMinIO = func(i int) string { return fmt.Sprintf("0e8b3b5a-6c1f-4d0e-9a5b-%012d", i) }
)

// objs — головы мира как версии под префиксом prefix; skip — номера, которых
// у этого бакета нет; shift — сдвиг времени PUT (другой бакет).
func (w *lyWorld) objs(prefix string, vid func(int) string, shift time.Duration, skip ...uint64) []lyObj {
	var out []lyObj
	for i, h := range w.heads {
		if contains64(skip, h.seq) {
			continue
		}
		out = append(out, lyObj{key: fmt.Sprintf("%s/heads/%020d.json", prefix, h.seq), vid: vid(i + 1), seq: h.seq, data: h.data, at: h.at.Add(shift)})
	}
	return out
}

func contains64(list []uint64, v uint64) bool {
	for _, x := range list {
		if x == v {
			return true
		}
	}
	return false
}

func lyETag(data []byte) string {
	sum := md5.Sum(data)
	return hex.EncodeToString(sum[:])
}

// versionsPage — страница вывода aws s3api list-object-versions: ключи по
// порядку, версии ключа — от новой к старой; v1 — время «…000Z».
func versionsPage(objs []lyObj, v1 bool, next string) map[string]any {
	sorted := append([]lyObj(nil), objs...)
	sort.SliceStable(sorted, func(i, j int) bool {
		if sorted[i].key != sorted[j].key {
			return sorted[i].key < sorted[j].key
		}
		return sorted[i].at.After(sorted[j].at)
	})
	latest := map[string]bool{}
	vs := []map[string]any{}
	for _, o := range sorted {
		at := o.at.UTC().Format("2006-01-02T15:04:05+00:00")
		if v1 {
			at = o.at.UTC().Format("2006-01-02T15:04:05.000Z")
		}
		vs = append(vs, map[string]any{"ETag": `"` + lyETag(o.data) + `"`, "Size": len(o.data), "StorageClass": "STANDARD",
			"Key": o.key, "VersionId": o.vid, "IsLatest": !latest[o.key], "LastModified": at,
			"Owner": map[string]any{"DisplayName": "witness", "ID": strings.Repeat("ab", 32)}})
		latest[o.key] = true
	}
	page := map[string]any{"Versions": vs, "RequestCharged": nil}
	if next != "" {
		page["NextToken"] = next
	}
	return page
}

func writeVersions(t *testing.T, path string, objs []lyObj, v1 bool) {
	t.Helper()
	data, err := json.MarshalIndent(versionsPage(objs, v1, ""), "", "    ")
	if err != nil {
		t.Fatal(err)
	}
	lyWrite(t, path, append(data, '\n'))
}

// writeVersionFiles — каждая версия в свой файл, путь — name(o) в dir.
func writeVersionFiles(t *testing.T, dir string, objs []lyObj, name func(lyObj) string) {
	t.Helper()
	for _, o := range objs {
		lyWrite(t, filepath.Join(dir, name(o)), o.data)
	}
}

func byVID(o lyObj) string { return o.vid + ".json" }

// Строки файлов сборщика — как их пишет internal/collector/head.go.
type lyRecord struct {
	ReceivedAt time.Time         `json:"received_at"`
	Checkpoint *proof.Checkpoint `json:"checkpoint"`
}

type lyConflict struct {
	ReceivedAt  time.Time         `json:"received_at"`
	Reason      string            `json:"reason"`
	Previous    *proof.Checkpoint `json:"previous"`
	Checkpoint  *proof.Checkpoint `json:"checkpoint"`
	Consistency [][]byte          `json:"consistency,omitempty"`
}

func (w *lyWorld) record(seq uint64, at time.Time) []byte {
	w.t.Helper()
	c, ok := w.cps[seq]
	if !ok {
		w.t.Fatalf("нет головы %d", seq)
	}
	data, err := json.Marshal(lyRecord{ReceivedAt: at, Checkpoint: &c})
	if err != nil {
		w.t.Fatal(err)
	}
	return data
}

// journal — checkpoints.jsonl: строка на голову.
func (w *lyWorld) journal(lines ...any) []byte {
	w.t.Helper()
	var out []byte
	for i := 0; i < len(lines); i += 2 {
		out = append(out, w.record(lines[i].(uint64), lines[i+1].(time.Time))...)
		out = append(out, '\n')
	}
	return out
}

// conflict — строка checkpoints-conflict.jsonl: сборщик держал prev, отверг cp.
func (w *lyWorld) conflict(prev, cp uint64, at time.Time, reason string) []byte {
	w.t.Helper()
	p, c := w.cps[prev], w.cps[cp]
	data, err := json.Marshal(lyConflict{ReceivedAt: at, Reason: reason, Previous: &p, Checkpoint: &c})
	if err != nil {
		w.t.Fatal(err)
	}
	return append(data, '\n')
}

// mustHave — каждая строка есть в выводе.
func mustHave(t *testing.T, what, out string, subs ...string) {
	t.Helper()
	for _, s := range subs {
		if !strings.Contains(out, s) {
			t.Fatalf("%s: нет %q\n%s", what, s, out)
		}
	}
}

func mustNot(t *testing.T, what, out string, subs ...string) {
	t.Helper()
	for _, s := range subs {
		if strings.Contains(out, s) {
			t.Fatalf("%s: лишнее %q\n%s", what, s, out)
		}
	}
}

// jsonWitness — поля свидетеля в -json одной строкой для сравнения.
func jsonWitness(rep map[string]any) string {
	return fmt.Sprintf("valid=%v head=%v received=%v refused=%v fork=%v", rep["valid"], rep["witness_head"], rep["witness_received"], rep["witness_refused"], rep["witness_fork"])
}
