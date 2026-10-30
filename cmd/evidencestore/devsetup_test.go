package main

import (
	"bytes"
	"io/fs"
	"maps"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Nikolay1994Kaz/evidencestore/internal/auditchain"
	"github.com/Nikolay1994Kaz/evidencestore/internal/collector"
	"github.com/Nikolay1994Kaz/evidencestore/internal/config"
)

// files — содержимое всех файлов под каталогом.
func files(t *testing.T, dir string) map[string][]byte {
	t.Helper()
	m := make(map[string][]byte)
	err := filepath.WalkDir(dir, func(path string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return err
		}
		data, err := os.ReadFile(path)
		m[path] = data
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
	return m
}

// dev-setup готовит каталог, с которым идут шаги README: оба конфига
// проходят загрузчики хранилища и сборщика (неизвестных полей они не
// принимают — поменяется формат, тест покраснеет), в collector.json и
// store.pub — ключ подписи этого хранилища, имя источника — в сертификате
// сборщика. Повтор не меняет ни байта.
func TestDevSetup(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "try")
	if err := cmdDevSetup([]string{"-dir", dir, "-source", "web-1", "-port", "9443"}); err != nil {
		t.Fatal(err)
	}
	cfg, err := config.Load(filepath.Join(dir, "store.json"))
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := cfg.Source("web-1"); !ok || cfg.TSA.URL != "local" || cfg.Listen != "127.0.0.1:9443" {
		t.Fatalf("store.json: источники %v, tsa %q, listen %q", cfg.Sources, cfg.TSA.URL, cfg.Listen)
	}
	cc, err := collector.LoadConfig(filepath.Join(dir, "collector.json"))
	if err != nil {
		t.Fatal(err)
	}
	if cc.Server != "https://127.0.0.1:9443" || cc.File != filepath.Join(dir, "web-1.log") || !cc.FromStart {
		t.Fatalf("collector.json: server %q, file %q, from_start %v", cc.Server, cc.File, cc.FromStart)
	}
	signer, err := auditchain.LoadOrCreateSigner(filepath.Join(cfg.DataDir, "chain"))
	if err != nil {
		t.Fatal(err)
	}
	pub, err := os.ReadFile(filepath.Join(dir, "store.pub"))
	if err != nil {
		t.Fatal(err)
	}
	if key := signer.PublicKeyString(); cc.StoreKey != key || strings.TrimSpace(string(pub)) != key {
		t.Fatalf("ключ хранилища %s, в collector.json %s, в store.pub %q", key, cc.StoreKey, pub)
	}
	if cn := readCert(t, cc.Cert).Subject.CommonName; cn != "web-1" {
		t.Fatalf("сертификат сборщика выписан на %q", cn)
	}
	before := files(t, dir)
	if err := cmdDevSetup([]string{"-dir", dir}); err == nil || !strings.Contains(err.Error(), "already set up") {
		t.Fatalf("повтор в готовом каталоге: %v", err)
	}
	if !maps.EqualFunc(before, files(t, dir), bytes.Equal) {
		t.Fatal("повтор изменил каталог")
	}
}

// В непустой каталог dev-setup не пишет: указанный по ошибке каталог
// настоящего хранилища остаётся как был. Имя источника, которое не
// принимает конфиг, оставляет новый каталог пустым — повтор с верным
// именем проходит.
func TestDevSetupRefuses(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "evidencestore.json"), []byte("{}"), 0o644); err != nil {
		t.Fatal(err)
	}
	before := files(t, dir)
	if err := cmdDevSetup([]string{"-dir", dir}); err == nil || !strings.Contains(err.Error(), "not empty") {
		t.Fatalf("непустой каталог: %v", err)
	}
	if !maps.EqualFunc(before, files(t, dir), bytes.Equal) {
		t.Fatal("dev-setup тронул непустой каталог")
	}

	fresh := filepath.Join(t.TempDir(), "try")
	if err := cmdDevSetup([]string{"-dir", fresh, "-source", "a/b"}); err == nil {
		t.Fatal("имя источника с '/' принято")
	}
	if entries, _ := os.ReadDir(fresh); len(entries) != 0 {
		t.Fatalf("после отказа в каталоге осталось %d записей", len(entries))
	}
	if err := cmdDevSetup([]string{"-dir", fresh}); err != nil {
		t.Fatalf("повтор с верным именем: %v", err)
	}
}

// -log считается от текущего каталога, как его набрал читатель, а не от
// каталога collector.json, от которого сборщик считает относительные пути.
func TestDevSetupLogFromWorkingDir(t *testing.T) {
	base := t.TempDir()
	t.Chdir(base)
	if err := cmdDevSetup([]string{"-dir", "try", "-log", "my.log"}); err != nil {
		t.Fatal(err)
	}
	cc, err := collector.LoadConfig(filepath.Join(base, "try", "collector.json"))
	if err != nil {
		t.Fatal(err)
	}
	if want := filepath.Join(base, "my.log"); cc.File != want {
		t.Fatalf("сборщик читает %s, а не %s", cc.File, want)
	}
}
