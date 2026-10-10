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

	"evidencestore/internal/config"
	"evidencestore/internal/proof"
	"evidencestore/internal/store"
)

// world — настоящее хранилище с демо-TSA и файлы для esverify.
type world struct {
	dir, bundle, key, trust, promise string
}

func newWorld(t *testing.T) world {
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
	res, err := s.Ingest("abs-core", []store.Incoming{{Seq: 1, Body: []byte("login admin")}})
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
	data, _ := b.JSON()
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

	if code, out := w.run(t, "-promise", filepath.Join(w.dir, "nope.json")); code != exitUsage || strings.Contains(out, "обещание при приёме") {
		t.Fatalf("опечатка в пути обещания: %d\n%s", code, out)
	}

	var p proof.Promise
	data, _ := os.ReadFile(w.promise)
	json.Unmarshal(data, &p)
	p.Seq = 2 // обещание про другую запись (подпись тоже разойдётся)
	bad, _ := json.Marshal(p)
	os.WriteFile(w.promise, bad, 0o600)
	code, out := w.run(t, "-promise", w.promise)
	if code != exitInvalid || !strings.HasPrefix(out, "ПРОВЕРКА НЕ ПРОЙДЕНА") {
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
	stripped, _ := b.JSON()
	os.WriteFile(w.bundle, stripped, 0o600)
	if code, out := w.run(t); code != exitInvalid {
		t.Fatalf("без метки TSA: %d\n%s", code, out)
	}
	if code, out := w.run(t, "-allow-no-tsa"); code != exitValid {
		t.Fatalf("без метки TSA с -allow-no-tsa: %d\n%s", code, out)
	}
}
