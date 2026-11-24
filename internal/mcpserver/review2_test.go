package mcpserver

// Регрессия второго захода проверки шагов 2–3 (24.11): тесты R1, R2 и T,
// которые падали на 7643a65 и проходят после исправлений (FINDINGS, P-357…).

// Проверка исправлений шагов 2–3 (R2, второй заход).
// go test ./internal/mcpserver -run R2Rev -count=1 -v

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// R2-4. Отказ за частоту — до базы, в счёт не идёт, а его квитанция исхода
// несёт текст SQL агента целиком (outcomeBody режет только то, что не влезает
// в квитанцию): каждый отказ — до 1 МиБ в файл квитанций с fsync, без
// предела. Агент в цикле пишет файл улик со скоростью диска — он же источник
// хранилища и вход сборщика (читается с начала при каждом запуске), а
// history() (actions, undo) читает его в память целиком.
func TestR2RevRefusedCallsGrowTheReceiptsWithoutBound(t *testing.T) {
	path := filepath.Join(t.TempDir(), "receipts.jsonl")
	s := serverOn(t, &fakeDB{}, path, func(c *Config) { c.ActionsPerMinute = 1 })
	if _, err := s.execute([]string{"UPDATE accounts SET note = 'x' WHERE id = 1"}, "one real action"); err != nil {
		t.Fatal(err)
	}
	fi, _ := os.Stat(path)
	before := fi.Size()
	big := "SELECT '" + strings.Repeat("x", 1000<<10) + "'"
	const n = 40
	start := time.Now()
	refused := 0
	for i := 0; i < n; i++ {
		if _, err := s.execute([]string{big}, ""); err != nil && strings.Contains(err.Error(), "actions in the last minute") {
			refused++
		}
	}
	fi, _ = os.Stat(path)
	grown := fi.Size() - before
	actions, _, _, _ := s.usage(time.Now(), "")
	t.Logf("%d of %d calls refused for the rate in %v; the receipts file grew by %d MiB; actions counted in the last minute: %d",
		refused, n, time.Since(start).Round(time.Millisecond), grown>>20, actions)
	if refused == n && grown > n*(64<<10) {
		t.Errorf("refused calls, which count for nothing, wrote %d MiB of the agent's text into the receipts (%d KiB each)", grown>>20, grown/n>>10)
	}
}

// R2-9. Ротация файла квитанций (logrotate create, mv): счёт пределов
// сеанса (ledger) видит файл меньше прочитанного и забывает всё, что было до
// ротации, — окно и минута начинаются заново. Ротацию по размеру агент
// вызывает сам: отказы за частоту пишут его текст (R2-4).
func TestR2RevRotationResetsTheLimits(t *testing.T) {
	path := filepath.Join(t.TempDir(), "receipts.jsonl")
	s := serverOn(t, &fakeDB{}, path, func(c *Config) { c.ActionsPerMinute = 2 })
	for i := 0; i < 2; i++ {
		if _, err := s.execute([]string{"UPDATE accounts SET note = 'x' WHERE id = 1"}, ""); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := s.execute([]string{"UPDATE accounts SET note = 'x' WHERE id = 1"}, ""); err == nil {
		t.Fatal("the third action in a minute passed before the rotation")
	}
	os.Rename(path, path+".1") // logrotate
	passed := 0
	for i := 0; i < 5; i++ {
		if _, err := s.execute([]string{"UPDATE accounts SET note = 'x' WHERE id = 1"}, ""); err == nil {
			passed++
		}
	}
	t.Logf("after the rotation, within the same minute: %d of 5 actions passed (limit 2 a minute, 2 already made)", passed)
	if passed > 0 {
		t.Errorf("the rotation reset the limit: %d more actions passed in the same minute", passed)
	}
}
