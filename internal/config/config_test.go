package config

import (
	"net"
	"path/filepath"
	"strings"
	"testing"
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
