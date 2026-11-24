package main

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"crypto/ecdsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Nikolay1994Kaz/evidencestore/internal/config"
)

// dockerStand — хранилище, заведённое docker init во временном каталоге.
func dockerStand(t *testing.T, tsa string) dockerPaths {
	t.Helper()
	d := t.TempDir()
	p := dockerPaths{
		config: filepath.Join(d, "config"),
		tsa:    filepath.Join("..", "..", "configs", "tsa"),
		data:   filepath.Join(d, "data"),
		roots:  filepath.Join(d, "roots"),
		backup: filepath.Join(d, "backup", "keyring"),
		mirror: filepath.Join(d, "mirror", "evidencestore"),
	}
	// Точки монтирования есть всегда, каталоги в них заводит init.
	for _, m := range []string{filepath.Dir(p.backup), filepath.Dir(p.mirror)} {
		if err := os.Mkdir(m, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	var out bytes.Buffer
	if err := dockerInit(p, "10.0.0.5, logs.example.com", tsa, &out); err != nil {
		t.Fatal(err)
	}
	return p
}

type tarFile struct {
	mode  int64
	body  []byte
	mtime time.Time
}

func untar(t *testing.T, data []byte) map[string]tarFile {
	t.Helper()
	gz, err := gzip.NewReader(bytes.NewReader(data))
	if err != nil {
		t.Fatal(err)
	}
	tr := tar.NewReader(gz)
	files := map[string]tarFile{}
	for {
		h, err := tr.Next()
		if err == io.EOF {
			return files
		}
		if err != nil {
			t.Fatal(err)
		}
		b, _ := io.ReadAll(tr)
		files[h.Name] = tarFile{h.Mode, b, h.ModTime}
	}
}

func body(t *testing.T, files map[string]tarFile, name string) []byte {
	t.Helper()
	f, ok := files[name]
	if !ok {
		t.Fatalf("в архиве нет %s", name)
	}
	return f.body
}

// docker init заводит хранилище, с которым сервер стартует: конфиг
// загружается, источников нет, сертификат сервера — на все имена ES_HOST,
// метки — DigiCert с файлами доверия рядом с конфигом, резерв и зеркало —
// внутри точек монтирования.
func TestDockerInit(t *testing.T) {
	p := dockerStand(t, "digicert")
	cfg, err := config.Load(filepath.Join(p.config, "evidencestore.json"))
	if err != nil {
		t.Fatal(err)
	}
	if len(cfg.Sources) != 0 || cfg.TSA.URL != "http://timestamp.digicert.com" || len(cfg.TSA.Trust) != 2 {
		t.Fatalf("конфиг: источники %v, метки %q %v", cfg.Sources, cfg.TSA.URL, cfg.TSA.Trust)
	}
	if cfg.Keys.BackupDir != p.backup || cfg.Keys.RootsMirrorDir != p.mirror {
		t.Fatalf("резерв %q, зеркало %q", cfg.Keys.BackupDir, cfg.Keys.RootsMirrorDir)
	}
	raw, _ := os.ReadFile(cfg.TLS.Cert)
	b, _ := pem.Decode(raw)
	srv, err := x509.ParseCertificate(b.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	if len(srv.DNSNames) != 1 || srv.DNSNames[0] != "logs.example.com" || len(srv.IPAddresses) != 1 || srv.IPAddresses[0].String() != "10.0.0.5" {
		t.Fatalf("имена сертификата сервера: %v %v", srv.DNSNames, srv.IPAddresses)
	}
	for _, f := range []string{"store.pub", "ca/ca.key", "server.key"} {
		if _, err := os.Stat(filepath.Join(p.config, f)); err != nil {
			t.Fatal(err)
		}
	}
	if st, _ := os.Stat(filepath.Join(p.config, "ca", "ca.key")); st.Mode().Perm() != 0o600 {
		t.Fatalf("ca.key: %v", st.Mode().Perm())
	}
	// Второй раз init ничего не трогает.
	before, _ := os.ReadFile(filepath.Join(p.config, "evidencestore.json"))
	if err := dockerInit(p, "other.example.com", "digicert", io.Discard); err == nil {
		t.Fatal("второй init прошёл")
	}
	after, _ := os.ReadFile(filepath.Join(p.config, "evidencestore.json"))
	if !bytes.Equal(before, after) {
		t.Fatal("второй init изменил конфиг")
	}
}

// Без ES_HOST, с неизвестной службой меток и без точки монтирования резерва
// init отказывает, ничего не заводя в каталоге конфига.
func TestDockerInitRefuses(t *testing.T) {
	d := t.TempDir()
	p := dockerPaths{
		config: filepath.Join(d, "config"), tsa: filepath.Join("..", "..", "configs", "tsa"),
		data: filepath.Join(d, "data"), roots: filepath.Join(d, "roots"),
		backup: filepath.Join(d, "backup", "keyring"), mirror: filepath.Join(d, "mirror", "evidencestore"),
	}
	for _, c := range []struct{ hosts, tsa string }{{"", "digicert"}, {" , ", "local"}, {"h", "freetsa"}, {"h", "local"}} {
		if err := dockerInit(p, c.hosts, c.tsa, io.Discard); err == nil {
			t.Fatalf("init с %q %q прошёл", c.hosts, c.tsa)
		}
		if entries, _ := os.ReadDir(p.config); len(entries) > 0 {
			t.Fatalf("init с %q %q оставил файлы", c.hosts, c.tsa)
		}
	}
}

// add-source выпускает сертификат, закрепляет его в конфиге и отдаёт
// архив, с которым сборщик пойдёт к этому хранилищу: его адрес, ключ
// хранилища, сертификат под УЦ хранилища, ключ к нему и путь лога в
// контейнере. На хосте хранилища закрытого ключа сборщика нет.
func TestDockerAddSource(t *testing.T) {
	p := dockerStand(t, "local")
	cfgPath := filepath.Join(p.config, "evidencestore.json")
	var out, errOut bytes.Buffer
	if err := cmdDockerAddSource([]string{"-config", cfgPath, "-name", "web1", "-file", "/var/log/nginx/access.log", "-image", "evidencestore:test", "-retention-months", "36"}, &out, &errOut); err != nil {
		t.Fatal(err)
	}
	cfg, err := config.Load(cfgPath)
	if err != nil {
		t.Fatal(err)
	}
	src, ok := cfg.Source("web1")
	if !ok || src.ContentType != "text" || src.RetentionMonths != 36 || src.CertSHA256 == "" {
		t.Fatalf("источник: %+v", src)
	}
	files := untar(t, out.Bytes())
	for _, f := range []string{"web1/", "web1/ca.crt", "web1/web1.crt", "web1/web1.key", "web1/collector.json", "web1/compose.yaml", "web1/README.txt"} {
		if _, ok := files[f]; !ok {
			t.Fatalf("в архиве нет %s", f)
		}
	}
	// Время файлов — в прошлом с запасом и целыми секундами: tar на хосте
	// сборщика с отстающими часами не предупреждает о файлах «из будущего».
	for name, f := range files {
		if !f.mtime.Before(time.Now().Add(-30*time.Minute)) || f.mtime.Nanosecond() != 0 {
			t.Errorf("%s: время %v", name, f.mtime)
		}
	}
	if files["web1/web1.key"].mode != 0o600 {
		t.Fatalf("ключ сборщика: %o", files["web1/web1.key"].mode)
	}
	var cc map[string]any
	if err := json.Unmarshal(body(t, files, "web1/collector.json"), &cc); err != nil {
		t.Fatal(err)
	}
	pub, _ := os.ReadFile(filepath.Join(p.config, "store.pub"))
	if cc["server"] != "https://10.0.0.5:8443" || cc["store_key"] != strings.TrimSpace(string(pub)) || cc["file"] != "/host/var/log/nginx/access.log" || cc["spool_dir"] != "/spool" {
		t.Fatalf("collector.json: %v", cc)
	}
	compose := string(body(t, files, "web1/compose.yaml"))
	for _, want := range []string{"image: evidencestore:test", "- /var/log/nginx:/host/var/log/nginx:ro", "name: escollect-web1"} {
		if !strings.Contains(compose, want) {
			t.Fatalf("в compose.yaml нет %q:\n%s", want, compose)
		}
	}

	// Сертификат — под УЦ хранилища, закреплён его отпечаток, ключ — к нему.
	cb, _ := pem.Decode(body(t, files, "web1/web1.crt"))
	cert, err := x509.ParseCertificate(cb.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	if config.CertFingerprint(cert.Raw) != src.CertSHA256 || cert.Subject.CommonName != "web1" {
		t.Fatalf("сертификат: %q, отпечаток %s, закреплён %s", cert.Subject.CommonName, config.CertFingerprint(cert.Raw), src.CertSHA256)
	}
	pool := x509.NewCertPool()
	caPEM, _ := os.ReadFile(filepath.Join(p.config, "ca", "ca.crt"))
	pool.AppendCertsFromPEM(caPEM)
	if !bytes.Equal(body(t, files, "web1/ca.crt"), caPEM) {
		t.Fatal("ca.crt архива — не УЦ хранилища")
	}
	if _, err := cert.Verify(x509.VerifyOptions{Roots: pool, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}}); err != nil {
		t.Fatal(err)
	}
	kb, _ := pem.Decode(body(t, files, "web1/web1.key"))
	key, err := x509.ParsePKCS8PrivateKey(kb.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	if !key.(*ecdsa.PrivateKey).PublicKey.Equal(cert.PublicKey) {
		t.Fatal("ключ архива — не к сертификату")
	}
	filepath.Walk(filepath.Dir(p.config), func(path string, info os.FileInfo, err error) error {
		if err == nil && strings.HasPrefix(info.Name(), "web1") {
			t.Errorf("на хосте хранилища остался %s", path)
		}
		return nil
	})

	// Второй источник дописывается к первому, прочие ключи конфига — на месте.
	if err := cmdDockerAddSource([]string{"-config", cfgPath, "-name", "db-2", "-image", "evidencestore:test"}, io.Discard, io.Discard); err != nil {
		t.Fatal(err)
	}
	cfg2, err := config.Load(cfgPath)
	if err != nil {
		t.Fatal(err)
	}
	if len(cfg2.Sources) != 2 || cfg2.Sources[0].Name != "web1" || cfg2.Sources[1].Name != "db-2" || cfg2.TSA.URL != "local" || cfg2.Keys.BackupDir != p.backup {
		t.Fatalf("после второго источника: %+v", cfg2)
	}
}

// Отказ add-source не меняет конфиг и не оставляет файлов: тот же
// источник второй раз, имя и путь, которым не место в YAML, адрес не https,
// сборка не выпуска без -image.
func TestDockerAddSourceRefuses(t *testing.T) {
	p := dockerStand(t, "local")
	cfgPath := filepath.Join(p.config, "evidencestore.json")
	if err := cmdDockerAddSource([]string{"-config", cfgPath, "-name", "web1", "-image", "evidencestore:test"}, io.Discard, io.Discard); err != nil {
		t.Fatal(err)
	}
	before, _ := os.ReadFile(cfgPath)
	t.Setenv("ES_IMAGE", "")
	for _, args := range [][]string{
		{"-name", "web1", "-image", "evidencestore:test"},
		{"-name", "Web1", "-image", "evidencestore:test"},
		{"-name", "-web", "-image", "evidencestore:test"},
		{"-name", "web 1", "-image", "evidencestore:test"},
		{"-name", "", "-image", "evidencestore:test"},
		{"-name", "web2", "-file", "/var/log/a b.log", "-image", "evidencestore:test"},
		{"-name", "web2", "-file", "var/log/auth.log", "-image", "evidencestore:test"},
		{"-name", "web2", "-file", "/auth.log", "-image", "evidencestore:test"},
		{"-name", "web2", "-file", "/var/log/../etc/shadow", "-image", "evidencestore:test"},
		{"-name", "web2", "-image", "evil\n    privileged: true"},
		{"-name", "web2", "-image", "evidencestore:test", "-server", "http://logs.example.com:8443"},
		{"-name", "web2", "-image", "evidencestore:test", "-server", "https://logs.example.com:8443\n#"},
		{"-name", "web2"}, // go test — не выпуск: образа этой сборки нет
	} {
		var out bytes.Buffer
		if err := cmdDockerAddSource(append([]string{"-config", cfgPath}, args...), &out, io.Discard); err == nil {
			t.Errorf("add-source %q прошёл", args)
		}
		if out.Len() != 0 {
			t.Errorf("add-source %q выдал архив", args)
		}
		if after, _ := os.ReadFile(cfgPath); !bytes.Equal(before, after) {
			t.Fatalf("add-source %q изменил конфиг", args)
		}
		if _, err := os.Stat(cfgPath + ".new"); err == nil {
			t.Fatalf("add-source %q оставил конфиг.new", args)
		}
	}
}

// appendSource сохраняет ключи верхнего уровня и их порядок, в том числе
// дописанные оператором руками, и заводит sources, если его нет.
func TestAppendSource(t *testing.T) {
	d := t.TempDir()
	p := filepath.Join(d, "evidencestore.json")
	os.WriteFile(p, []byte(`{"data_dir":"d","witness":{"url":"file:///w"},"sources":[{"name":"a","content_type":"text"}],"roots_dir":"r"}`), 0o640)
	tmp, err := appendSource(p, map[string]any{"name": "b", "content_type": "text"})
	if err != nil {
		t.Fatal(err)
	}
	got, _ := os.ReadFile(tmp)
	want := `{
  "data_dir": "d",
  "witness": {
    "url": "file:///w"
  },
  "sources": [
    {"name":"a","content_type":"text"},
    {"content_type":"text","name":"b"}
  ],
  "roots_dir": "r"
}
`
	if string(got) != want {
		t.Fatalf("получилось:\n%s", got)
	}
	if st, _ := os.Stat(tmp); st.Mode().Perm() != 0o640 {
		t.Fatalf("права: %v", st.Mode().Perm())
	}
	os.WriteFile(p, []byte(`{"data_dir":"d"}`), 0o644)
	tmp, err = appendSource(p, map[string]any{"name": "b"})
	if err != nil {
		t.Fatal(err)
	}
	got, _ = os.ReadFile(tmp)
	if !strings.Contains(string(got), "\"sources\": [\n    {\"name\":\"b\"}\n  ]") {
		t.Fatalf("без sources:\n%s", got)
	}
	for _, bad := range []string{`[]`, `{"a":1} {}`, `{"sources":{}}`, `{`} {
		os.WriteFile(p, []byte(bad), 0o644)
		if _, err := appendSource(p, map[string]any{"name": "b"}); err == nil {
			t.Errorf("appendSource принял %q", bad)
		}
	}
}
