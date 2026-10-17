package main

import (
	"bytes"
	"encoding/json"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Nikolay1994Kaz/evidencestore/internal/config"
	"github.com/Nikolay1994Kaz/evidencestore/internal/proof"
	"github.com/Nikolay1994Kaz/evidencestore/internal/store"
)

// world — настоящее хранилище с демо-TSA и файлы для esverify.
type world struct {
	dir, bundle, key, trust, promise string
}

func newWorld(t *testing.T) world { return newWorldWith(t, []byte("login admin")) }

// newWorldWith — то же с заданным телом единственной улики.
func newWorldWith(t *testing.T, body []byte) world {
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
	s, err := store.Open(cfg, store.Options{Logger: slog.New(slog.NewTextHandler(io.Discard, nil)), NoBackground: true})
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	res, err := s.Ingest("abs-core", []store.Incoming{{Seq: 1, Body: body}})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.Stamp(t.Context()); err != nil {
		t.Fatal(err)
	}
	b, err := s.Proof("abs-core", 1, true)
	if err != nil {
		t.Fatal(err)
	}
	w := world{dir: dir}
	write := func(name string, data []byte) string {
		p := filepath.Join(dir, name)
		if err := os.WriteFile(p, data, 0o600); err != nil {
			t.Fatal(err)
		}
		return p
	}
	data, _ := json.Marshal(b)
	w.bundle = write("proof.json", data)
	w.key = write("store.key", []byte(s.PublicKey()))
	w.trust = write("tsa-root.crt", s.TSARoot())
	pdata, _ := json.Marshal(res[0].Promise)
	w.promise = write("promise.json", pdata)
	return w
}

func (w world) run(t *testing.T, extra ...string) (int, string) {
	t.Helper()
	var out, errOut bytes.Buffer
	args := append([]string{"-proof", w.bundle, "-store-key", w.key, "-tsa-trust", w.trust}, extra...)
	code := run(args, &out, &errOut)
	return code, out.String() + errOut.String()
}

// V-06, B-07: коды выхода различают «пакет не проходит» (1) и «неверный
// вызов или не читается файл» (2); нарушенное обещание — часть вердикта, и
// шапка отчёта его не противоречит.
func TestExitCodesAndPromiseVerdict(t *testing.T) {
	w := newWorld(t)
	if code, out := w.run(t, "-promise", w.promise); code != exitValid {
		t.Fatalf("целый пакет: %d\n%s", code, out)
	}

	if code, out := w.run(t, "-promise", filepath.Join(w.dir, "nope.json")); code != exitUsage || strings.Contains(out, "the promise given at intake") {
		t.Fatalf("опечатка в пути обещания: %d\n%s", code, out)
	}

	var p proof.Promise
	data, _ := os.ReadFile(w.promise)
	json.Unmarshal(data, &p)
	p.Seq = 2 // обещание про другую запись (подпись тоже разойдётся)
	bad, _ := json.Marshal(p)
	os.WriteFile(w.promise, bad, 0o600)
	code, out := w.run(t, "-promise", w.promise)
	if code != exitInvalid || !strings.HasPrefix(out, "NOT VERIFIED") {
		t.Fatalf("нарушенное обещание: %d\n%s", code, out)
	}

	os.WriteFile(w.bundle, []byte("{not json"), 0o600)
	code, out = w.run(t, "-json")
	if code != exitInvalid || !strings.Contains(out, `"valid": false`) {
		t.Fatalf("битый пакет: %d\n%s", code, out)
	}
}

// V-05: пакет без метки TSA после улики не проходит без явного
// -allow-no-tsa.
func TestBundleWithoutTSAIsRefused(t *testing.T) {
	w := newWorld(t)
	data, _ := os.ReadFile(w.bundle)
	b, err := proof.Parse(data)
	if err != nil {
		t.Fatal(err)
	}
	b.Upper = nil
	stripped, _ := json.Marshal(b)
	os.WriteFile(w.bundle, stripped, 0o600)
	if code, out := w.run(t); code != exitInvalid {
		t.Fatalf("без метки TSA: %d\n%s", code, out)
	}
	if code, out := w.run(t, "-allow-no-tsa"); code != exitValid {
		t.Fatalf("без метки TSA с -allow-no-tsa: %d\n%s", code, out)
	}
}

// P-01: -body отдаёт тело байт в байт (отчёт экранирует управляющие символы,
// файл — нет) и только из пакета, прошедшего проверку; без ключа записи
// тела нет, и вызов говорит об этом кодом 2, а не пустым файлом.
func TestBodyFlag(t *testing.T) {
	body := []byte("login root from 203.0.113.7\x1b[2K\r\xff\x00 tail")
	w := newWorldWith(t, body)
	out := filepath.Join(w.dir, "body.bin")
	if code, rep := w.run(t, "-body", out); code != exitValid {
		t.Fatalf("целый пакет: %d\n%s", code, rep)
	}
	got, err := os.ReadFile(out)
	if err != nil || !bytes.Equal(got, body) {
		t.Fatalf("тело в файле %q (%v), а пришло %q", got, err, body)
	}
	if fi, _ := os.Stat(out); fi.Mode().Perm() != 0o600 {
		t.Fatalf("права файла с телом: %v", fi.Mode().Perm())
	}

	// JSON-отчёт остаётся чистым JSON: сообщение о файле — в stderr.
	var stdout, stderr bytes.Buffer
	args := []string{"-proof", w.bundle, "-store-key", w.key, "-tsa-trust", w.trust, "-json", "-body", filepath.Join(w.dir, "json-body.bin")}
	if code := run(args, &stdout, &stderr); code != exitValid {
		t.Fatalf("-json -body: %d\n%s%s", code, stdout.String(), stderr.String())
	}
	var rep map[string]any
	if err := json.Unmarshal(stdout.Bytes(), &rep); err != nil || rep["valid"] != true {
		t.Fatalf("stdout с -json -body — не отчёт: %v\n%s", err, stdout.String())
	}

	data, _ := os.ReadFile(w.bundle)
	b, err := proof.Parse(data)
	if err != nil {
		t.Fatal(err)
	}
	save := func() {
		bad, _ := json.Marshal(b)
		os.WriteFile(w.bundle, bad, 0o600)
	}
	rewrite := func(dek []byte) {
		b.DEK = dek
		save()
	}

	// Тело вскрывается, но пакет не проходит (нет метки TSA после улики):
	// файла нет.
	upper := b.Upper
	b.Upper = nil
	save()
	noTSA := filepath.Join(w.dir, "no-tsa.bin")
	if code, rep := w.run(t, "-body", noTSA); code != exitInvalid || !strings.Contains(rep, "body not written") {
		t.Fatalf("пакет без метки TSA: %d\n%s", code, rep)
	}
	if _, err := os.Stat(noTSA); !os.IsNotExist(err) {
		t.Fatalf("тело записано из пакета, который не прошёл: %v", err)
	}
	b.Upper = upper

	// Ключ записи не тот: проверка не проходит, файла нет.
	rewrite(bytes.Repeat([]byte{7}, 32))
	wrong := filepath.Join(w.dir, "wrong-dek.bin")
	if code, rep := w.run(t, "-body", wrong); code != exitInvalid || !strings.Contains(rep, "body not written") {
		t.Fatalf("чужой ключ записи: %d\n%s", code, rep)
	}
	if _, err := os.Stat(wrong); !os.IsNotExist(err) {
		t.Fatalf("тело записано из пакета, который не прошёл: %v", err)
	}

	// Ключа записи нет: пакет проходит, а тела нет — код 2, файла нет.
	rewrite(nil)
	none := filepath.Join(w.dir, "no-dek.bin")
	if code, rep := w.run(t, "-body", none); code != exitUsage || !strings.Contains(rep, "no record key") {
		t.Fatalf("пакет без ключа записи: %d\n%s", code, rep)
	}
	if _, err := os.Stat(none); !os.IsNotExist(err) {
		t.Fatalf("файл тела без ключа записи: %v", err)
	}
}

// -version отвечает без пакета и ключей: проверяющий узнаёт, что у него за
// сборка, до всякой проверки.
func TestVersionFlag(t *testing.T) {
	var out, errb bytes.Buffer
	if code := run([]string{"-version"}, &out, &errb); code != exitValid || !strings.HasPrefix(out.String(), "esverify ") {
		t.Fatalf("-version: код %d, вывод %q, ошибки %q", code, out.String(), errb.String())
	}
}
