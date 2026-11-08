package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Nikolay1994Kaz/evidencestore/internal/auditchain"
	"github.com/Nikolay1994Kaz/evidencestore/internal/cosign"
)

func writeConfig(t *testing.T, body string) string {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "eswitness.json")
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func storeKey(t *testing.T) string {
	t.Helper()
	s, err := auditchain.LoadOrCreateSigner(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	return s.PublicKeyString()
}

// init заводит ключ и печатает ключ проверки; второй init ключ не затирает;
// vkey печатает тот же ключ; путь data_dir — от каталога конфигурации.
func TestInitAndVkey(t *testing.T) {
	path := writeConfig(t, `{"name": "witness.example/w1", "listen": "127.0.0.1:0", "data_dir": "data", "logs": [{"store_key": "`+storeKey(t)+`"}]}`)
	var out, errb bytes.Buffer
	if code := run([]string{"init", "-config", path}, &out, &errb); code != 0 {
		t.Fatalf("init: %d %s", code, errb.String())
	}
	vkey := strings.TrimSpace(out.String())
	v, err := cosign.ParseVerifier(vkey)
	if err != nil || v.Name != "witness.example/w1" {
		t.Fatalf("ключ проверки %q: %v", vkey, err)
	}
	key := filepath.Join(filepath.Dir(path), "data", keyFile)
	fi, err := os.Stat(key)
	if err != nil || fi.Mode().Perm() != 0o600 {
		t.Fatalf("ключ свидетеля %s: %v %v", key, fi, err)
	}
	before, _ := os.ReadFile(key)
	out.Reset()
	if code := run([]string{"init", "-config", path}, &out, &errb); code == 0 {
		t.Fatal("второй init прошёл")
	}
	after, _ := os.ReadFile(key)
	if !bytes.Equal(before, after) {
		t.Fatal("второй init затёр ключ свидетеля")
	}
	out.Reset()
	if code := run([]string{"vkey", "-config", path}, &out, &errb); code != 0 || strings.TrimSpace(out.String()) != vkey {
		t.Fatalf("vkey: %d %q", code, out.String())
	}
}

func TestConfigRefused(t *testing.T) {
	key := storeKey(t)
	cases := map[string]string{
		"имя с пробелом": `{"name": "witness example", "listen": "x", "data_dir": "d", "logs": [{"store_key": "` + key + `"}]}`,
		"без listen":     `{"name": "w.example/w", "data_dir": "d", "logs": [{"store_key": "` + key + `"}]}`,
		"без хранилищ":   `{"name": "w.example/w", "listen": "x", "data_dir": "d", "logs": []}`,
		"не ключ":        `{"name": "w.example/w", "listen": "x", "data_dir": "d", "logs": [{"store_key": "abc"}]}`,
		"дважды":         `{"name": "w.example/w", "listen": "x", "data_dir": "d", "logs": [{"store_key": "` + key + `"}, {"store_key": "` + key + `="}]}`,
		"лишнее поле":    `{"name": "w.example/w", "listen": "x", "data_dir": "d", "logs": [{"store_key": "` + key + `"}], "witness": true}`,
		"tls без ключа":  `{"name": "w.example/w", "listen": "x", "data_dir": "d", "tls": {"cert": "c"}, "logs": [{"store_key": "` + key + `"}]}`,
		"без каталога":   `{"name": "w.example/w", "listen": "x", "logs": [{"store_key": "` + key + `"}]}`,
	}
	for name, body := range cases {
		var out, errb bytes.Buffer
		if code := run([]string{"vkey", "-config", writeConfig(t, body)}, &out, &errb); code != 2 {
			t.Errorf("%s: код %d, %s", name, code, errb.String())
		}
	}
}

func TestServeWithoutKey(t *testing.T) {
	path := writeConfig(t, `{"name": "witness.example/w1", "listen": "127.0.0.1:0", "data_dir": "data", "logs": [{"store_key": "`+storeKey(t)+`"}]}`)
	var out, errb bytes.Buffer
	if code := run([]string{"serve", "-config", path}, &out, &errb); code != 1 || !strings.Contains(errb.String(), "run eswitness init first") {
		t.Fatalf("serve без ключа: %d %s", code, errb.String())
	}
}

// Пример конфигурации из configs/ разбирается: его копируют как есть.
func TestExampleConfig(t *testing.T) {
	cfg, err := loadConfig(filepath.Join("..", "..", "configs", "eswitness.example.json"))
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Name != "witness.example/w1" || len(cfg.logs) != 1 || cfg.TLS == nil {
		t.Fatalf("пример: %+v", cfg)
	}
}
