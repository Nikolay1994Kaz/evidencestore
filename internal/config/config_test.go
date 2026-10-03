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
