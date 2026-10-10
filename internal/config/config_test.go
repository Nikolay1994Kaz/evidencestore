package config

import (
	"net"
	"path/filepath"
	"strings"
	"testing"
	"time"
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
// отмены уничтожения вне стенда, тип содержимого длиннее предела улики.
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
	for name, spoil := range map[string]func(*Config){
		"корни внутри данных":   func(c *Config) { c.RootsDir = filepath.Join(c.DataDir, "roots") },
		"данные внутри корней":  func(c *Config) { c.DataDir = filepath.Join(c.RootsDir, "data") },
		"..roots внутри данных": func(c *Config) { c.RootsDir = filepath.Join(c.DataDir, "..roots") },
		"min_wait -24h":         func(c *Config) { c.Keys.MinWait = Duration(-24 * time.Hour) },
		"min_wait 1s":           func(c *Config) { c.Keys.MinWait = Duration(time.Second) },
		"tsa.every -1m":         func(c *Config) { c.TSA.Every = Duration(-time.Minute) },
		"replica.every -1m":     func(c *Config) { c.Replica.Every = Duration(-time.Minute) },
		"expect_every -1s":      func(c *Config) { c.Sources[0].ExpectEvery = Duration(-time.Second) },
		"content_type 256 байт": func(c *Config) { c.Sources[0].ContentType = strings.Repeat("x", 256) },
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
}
