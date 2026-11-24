package mcpserver

// Третий заход проверки (R1, 24.11): следствие R1-4 (ссылка на месте файла
// квитанций) для пределов MCP-сервера. Тест ПАДАЕТ на 1f9a0f2.
// go test ./internal/mcpserver -run R1Rev8 -count=1 -v

import (
	"os"
	"path/filepath"
	"testing"
)

// R1-4в. Противник 3 кладёт на место receipts.jsonl ссылку на голову шлюза
// (её путь в Docker постоянный). Квитанции действий уходят в inode головы и
// пропадают при её замене, а счёт пределов (ledger) читает тот же путь и не
// видит ни одного действия: предел частоты (здесь 2 в минуту) и окно строк
// перестают действовать — каждое действие проходит.
func TestR1Rev8ReceiptsLinkTurnsOffTheLimits(t *testing.T) {
	path := filepath.Join(t.TempDir(), "receipts.jsonl")
	head := filepath.Join(t.TempDir(), "esmcp.head") // каталог головы — не каталог квитанций
	// Ссылка лежит с начала сеанса (сеанс esmcp в Docker — свой процесс,
	// `docker compose run --rm` на каждый сеанс агента).
	if err := os.Symlink(head, path); err != nil {
		t.Fatal(err)
	}
	s := serverOn(t, &fakeDB{}, path, func(c *Config) { c.ActionsPerMinute = 2; c.HeadPath = head })
	passed := 0
	for i := 0; i < 10; i++ {
		if _, err := s.execute([]string{"UPDATE accounts SET note = 'x' WHERE id = 1"}, ""); err == nil {
			passed++
		}
	}
	t.Logf("with a link to the head at the receipts path: %d of 10 actions passed in the same minute (limit 2 a minute)", passed)
	if passed > 2 {
		t.Errorf("%d actions passed with a limit of 2 a minute: their receipts went into the head's inode, and the ledger reads none", passed)
	}
}
