package config

import (
	"crypto/ed25519"
	"crypto/rand"
	"fmt"
	"net"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Nikolay1994Kaz/evidencestore/internal/cosign"
)

// Путь сокета длиннее предела ловится при проверке конфига, а не
// невнятным «bind: invalid argument» при запуске сервера.
func TestAdminSocketPathLimit(t *testing.T) {
	base := t.TempDir()
	cfg := func(sock string) *Config {
		c := &Config{DataDir: filepath.Join(base, "data"), RootsDir: filepath.Join(base, "roots"), AdminSocket: sock}
		c.Defaults()
		return c
	}
	pad := func(n int) string {
		p := filepath.Join(base, "s")
		return p + strings.Repeat("x", n-len(p))
	}
	if len(filepath.Join(base, "s")) >= MaxSocketPath {
		t.Skipf("временный каталог %s сам длиннее предела", base)
	}

	ok := pad(MaxSocketPath)
	if err := cfg(ok).Validate(); err != nil {
		t.Fatalf("путь ровно %d байт отвергнут: %v", MaxSocketPath, err)
	}
	// Предел настоящий: сокет на таком пути открывается.
	if l, err := net.Listen("unix", ok); err != nil {
		t.Fatalf("ядро не приняло путь %d байт: %v", len(ok), err)
	} else {
		l.Close()
	}

	long := pad(MaxSocketPath + 1)
	err := cfg(long).Validate()
	if err == nil || !strings.Contains(err.Error(), "admin_socket") {
		t.Fatalf("путь %d байт принят: %v", len(long), err)
	}
	if l, err := net.Listen("unix", long); err == nil {
		l.Close()
		t.Fatalf("ядро приняло путь %d байт — предел в конфиге занижен", len(long))
	}
}

// Копия, где лежат и keyring.dat (данные или его резерв), и корень,
// открывает все ключи: такие каталоги не вкладываются друг в друга.
func TestKeyDirsDoNotNest(t *testing.T) {
	base := t.TempDir()
	cfg := func(edit func(*Config)) error {
		c := &Config{
			DataDir:  filepath.Join(base, "data"),
			RootsDir: filepath.Join(base, "roots"),
			Keys:     Keys{BackupDir: filepath.Join(base, "backup"), RootsMirrorDir: filepath.Join(base, "mirror")},
		}
		edit(c)
		c.Defaults()
		return c.Validate()
	}
	if err := cfg(func(*Config) {}); err != nil {
		t.Fatalf("раздельные каталоги отвергнуты: %v", err)
	}
	for name, edit := range map[string]func(*Config){
		"зеркало в данных":      func(c *Config) { c.Keys.RootsMirrorDir = filepath.Join(c.DataDir, "mirror") },
		"зеркало = корни":       func(c *Config) { c.Keys.RootsMirrorDir = c.RootsDir },
		"зеркало в резерве":     func(c *Config) { c.Keys.RootsMirrorDir = filepath.Join(c.Keys.BackupDir, "roots") },
		"резерв внутри зеркала": func(c *Config) { c.Keys.BackupDir = filepath.Join(c.Keys.RootsMirrorDir, "kr") },
		"резерв в корнях":       func(c *Config) { c.Keys.BackupDir = filepath.Join(c.RootsDir, "backup") },
		"корни в резерве":       func(c *Config) { c.RootsDir = filepath.Join(c.Keys.BackupDir, "roots") },
	} {
		if err := cfg(edit); err == nil || !strings.Contains(err.Error(), "opens every key") {
			t.Errorf("%s: принято (%v)", name, err)
		}
	}
	// Соседи с общим префиксом имени — не вложение.
	if err := cfg(func(c *Config) { c.Keys.BackupDir = c.RootsDir + "-backup" }); err != nil {
		t.Fatalf("соседний каталог с общим префиксом принят за вложенный: %v", err)
	}
}

// S-10, K-07, S-09, S-11: опасные значения — ошибка проверки, а не беда
// посреди работы: корни внутри данных (или данные внутри корней, или «..roots»
// внутри data_dir), отрицательные и нулевые сроки, слишком короткое окно
// отмены уничтожения вне стенда, тип содержимого длиннее предела улики,
// срок обещания длиннее proof.MaxPromiseMMD (Q-33) или короче 55 с и двух
// тиков (Q-46).
func TestValidateRejectsDangerousValues(t *testing.T) {
	base := t.TempDir()
	good := func() *Config {
		c := &Config{DataDir: filepath.Join(base, "data"), RootsDir: filepath.Join(base, "roots"),
			Sources: []Source{{Name: "abs-core", ContentType: "syslog", CertSHA256: strings.Repeat("AB", 32)}}}
		c.Defaults()
		return c
	}
	c := good()
	if err := c.Validate(); err != nil {
		t.Fatal(err)
	}
	if c.Sources[0].CertSHA256 != strings.Repeat("ab", 32) {
		t.Fatalf("отпечаток не приведён к нижнему регистру: %s", c.Sources[0].CertSHA256)
	}
	if c.Sources[0].ExpectContact.D() != DefaultExpectContact {
		t.Fatalf("expect_contact по умолчанию: %v", c.Sources[0].ExpectContact.D())
	}
	for name, spoil := range map[string]func(*Config){
		"корни внутри данных": func(c *Config) { c.RootsDir = filepath.Join(c.DataDir, "roots") },
		"subject_field у журнала гейтвея": func(c *Config) {
			c.Sources[0].ContentType, c.Sources[0].SubjectField = GatewayContentType, "session_id"
		},
		"длинное subject_field":  func(c *Config) { c.Sources[0].SubjectField = strings.Repeat("x", MaxSubjectField+1) },
		"subject_field не UTF-8": func(c *Config) { c.Sources[0].SubjectField = "\xff" },
		"данные внутри корней":   func(c *Config) { c.DataDir = filepath.Join(c.RootsDir, "data") },
		"..roots внутри данных":  func(c *Config) { c.RootsDir = filepath.Join(c.DataDir, "..roots") },
		"min_wait -24h":          func(c *Config) { c.Keys.MinWait = Duration(-24 * time.Hour) },
		"min_wait 1s":            func(c *Config) { c.Keys.MinWait = Duration(time.Second) },
		"tsa.every -1m":          func(c *Config) { c.TSA.Every = Duration(-time.Minute) },
		"replica.every -1m":      func(c *Config) { c.Replica.Every = Duration(-time.Minute) },
		"witness.every -1m":      func(c *Config) { c.Witness.Every = Duration(-time.Minute) },
		"свидетель — сама копия": func(c *Config) {
			c.Replica.URL, c.Witness.URL = "file:///srv/copy", "file:///srv/copy"
			c.Keys.BackupDir = "/srv/keys"
		},
		"копия без резерва ключей": func(c *Config) { c.Replica.URL = "file:///srv/copy" },
		"expect_every -1s":      func(c *Config) { c.Sources[0].ExpectEvery = Duration(-time.Second) },
		"expect_contact 30s":    func(c *Config) { c.Sources[0].ExpectContact = Duration(30 * time.Second) },
		"expect_contact -1m":    func(c *Config) { c.Sources[0].ExpectContact = Duration(-time.Minute) },
		"content_type 256 байт": func(c *Config) { c.Sources[0].ContentType = strings.Repeat("x", 256) },
		"promise_mmd 61s":       func(c *Config) { c.Chain.PromiseMMD = Duration(61 * time.Second) },
		"promise_mmd 56s":       func(c *Config) { c.Chain.PromiseMMD = Duration(56 * time.Second) },
		"tick 3s":               func(c *Config) { c.Chain.Tick = Duration(3 * time.Second) },
	} {
		c := good()
		spoil(c)
		if err := c.Validate(); err == nil {
			t.Errorf("%s: принято", name)
		}
	}
	c = good()
	c.Keys.MinWait, c.Demo = Duration(time.Second), true
	if err := c.Validate(); err != nil {
		t.Fatalf("min_wait 1s на стенде: %v", err)
	}
	// Тик, при котором срока обещания нет вовсе, назван тиком, а не сроком.
	c = good()
	c.Chain.Tick = Duration(3 * time.Second)
	if err := c.Validate(); err == nil || !strings.Contains(err.Error(), "chain.tick must be at most 2.5s") {
		t.Fatalf("tick 3s: %v", err)
	}
}

func TestValidateCosigners(t *testing.T) {
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	signer, err := cosign.NewSigner("witness.example/w1", priv)
	if err != nil {
		t.Fatal(err)
	}
	key := signer.Verifier().String()
	bad := map[string][]Cosigner{
		"ftp":        {{URL: "ftp://w.example/", Key: key}},
		"без хоста":  {{URL: "https:///x", Key: key}},
		"с запросом": {{URL: "https://w.example/?a=1", Key: key}},
		"не ключ":    {{URL: "https://w.example/", Key: "witness.example/w1"}},
		"дважды":     {{URL: "https://a.example/", Key: key}, {URL: "https://b.example/", Key: key}},
	}
	// Девять разных свидетелей — больше предела, даже без повторов.
	var nine []Cosigner
	for i := range MaxCosigners + 1 {
		_, priv, _ := ed25519.GenerateKey(rand.Reader)
		w, err := cosign.NewSigner(fmt.Sprintf("witness.example/n%d", i), priv)
		if err != nil {
			t.Fatal(err)
		}
		nine = append(nine, Cosigner{URL: "https://w.example/", Key: w.Verifier().String()})
	}
	bad["девять"] = nine
	for name, cs := range bad {
		c := Config{Witness: Witness{Cosigners: cs}}
		if errs := c.validateCosigners(); len(errs) == 0 {
			t.Errorf("%s: принято", name)
		}
	}
	good := Config{Witness: Witness{Cosigners: []Cosigner{{URL: "https://w.example/sub/", Key: key}, {URL: "http://127.0.0.1:8444", Key: other(t)}}}}
	if errs := good.validateCosigners(); len(errs) != 0 {
		t.Fatal(errs)
	}
}

func other(t *testing.T) string {
	_, priv, _ := ed25519.GenerateKey(rand.Reader)
	s, err := cosign.NewSigner("witness.example/w2", priv)
	if err != nil {
		t.Fatal(err)
	}
	return s.Verifier().String()
}

// ca свидетеля C2SP — путь от каталога конфигурации, как у прочих файлов.
func TestCosignerCAResolved(t *testing.T) {
	c := Config{Witness: Witness{Cosigners: []Cosigner{{CA: "witness-ca.pem"}, {CA: "/etc/ca.pem"}, {}}}}
	c.resolve("/etc/evidencestore")
	if got := c.Witness.Cosigners; got[0].CA != "/etc/evidencestore/witness-ca.pem" || got[1].CA != "/etc/ca.pem" || got[2].CA != "" {
		t.Fatalf("пути ca: %+v", got)
	}
}
