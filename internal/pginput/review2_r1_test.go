package pginput

// Регрессия второго захода проверки шагов 2–3 (24.11): тесты R1, R2 и T,
// которые падали на 7643a65 и проходят после исправлений (FINDINGS, P-357…).

// Второй заход проверки (R1, rev7): последствие R1-1 у сборщика. Шлюз после
// обрезки файла раздваивает цепочку (gateway.Append, journal.go:98), а
// сборщик считает тревоги по исходам по seq (P-353: rc.Seq <= c.Alerted —
// уже поднята): исходы новой ветви с теми же seq тревог не поднимают.

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/Nikolay1994Kaz/evidencestore/internal/alert"
	"github.com/Nikolay1994Kaz/evidencestore/internal/gateway"
)

func TestR1ForkAfterTruncationSilencesOutcomeAlerts(t *testing.T) {
	g := newRig(t, "esmcp.jsonl")
	path := g.cfg.Files[0]
	now := time.Now()
	var ends []int64
	for i := range 6 {
		g.sign("esmcp.jsonl", outcome(fmt.Sprintf("a-%d", i), `{"outcome":"refused","cause":"row-limit","rows":9,"limit":1}`))
		ends = append(ends, fileSize(t, path))
	}
	g.r.poll()
	if g.count(alert.KindRefused) != 6 {
		t.Fatalf("alerts %s", g.kinds())
	}
	// Писатель без ключа обрезает файл до конца второй строки (seq 2).
	if err := os.Truncate(path, ends[1]); err != nil {
		t.Fatal(err)
	}
	// Агент действует дальше: намерение и исходы — escaped, unknown, отказ.
	g.sign("esmcp.jsonl", intent("a-x", now, "777"))
	g.sign("esmcp.jsonl", outcome("a-x", `{"outcome":"escaped","cause":"escaped","xid":"777","tool":"execute"}`))
	g.sign("esmcp.jsonl", outcome("a-y", `{"outcome":"unknown","cause":"unknown","xid":"778","rows":3}`))
	g.sign("esmcp.jsonl", outcome("a-z", `{"outcome":"refused","cause":"row-limit","rows":3000,"limit":500}`))
	g.r.poll()
	if g.count(alert.KindEscaped) != 1 || g.count(alert.KindUnknown) != 1 || g.count(alert.KindRefused) != 7 {
		t.Fatalf("после обрезки файла: escaped %d, commit-unknown %d, refused %d (ждали 1, 1, 7) — тревоги новых исходов не подняты: %s",
			g.count(alert.KindEscaped), g.count(alert.KindUnknown), g.count(alert.KindRefused), g.kinds())
	}
}

// R1-4 у сборщика. Новая цепочка шлюза (метки нет, файл новый) сбрасывает
// счёт тревог (c.Genesis), а одна дописанная копия исхода прежней цепочки с
// большим seq поднимает c.Alerted до него: исходы новой цепочки с seq не выше
// тревог не поднимают.
func TestR1OldChainCopySilencesOutcomeAlerts(t *testing.T) {
	g := newRig(t, "esmcp.jsonl")
	path := g.cfg.Files[0]
	refused := `{"outcome":"refused","cause":"row-limit","rows":9,"limit":1}`
	for i := range 20 {
		g.sign("esmcp.jsonl", outcome(fmt.Sprintf("old-%d", i), refused))
	}
	g.r.poll()
	data, _ := os.ReadFile(path)
	lines := bytes.Split(bytes.TrimRight(data, "\n"), []byte("\n"))
	last := append(bytes.Clone(lines[len(lines)-1]), '\n')
	// Файл ушёл, метки нет: шлюз начинает новую цепочку.
	os.Rename(path, path+".1")
	os.Remove(filepath.Join(g.dir, ".esmcp_jsonl.heads"))
	for i := range 3 {
		g.sign("esmcp.jsonl", outcome(fmt.Sprintf("new-%d", i), refused))
	}
	g.r.poll()
	g.raw("esmcp.jsonl", last) // копия исхода прежней seq 20
	g.r.poll()
	before := g.count(alert.KindRefused)
	g.sign("esmcp.jsonl", outcome("a-x", `{"outcome":"escaped","cause":"escaped","xid":"777","tool":"execute"}`))
	g.sign("esmcp.jsonl", outcome("a-y", refused))
	g.r.poll()
	if g.count(alert.KindEscaped) != 1 || g.count(alert.KindRefused) != before+1 {
		t.Fatalf("после одной копии строки прежней цепочки: escaped %d (ждали 1), новых refused %d (ждали 1)", g.count(alert.KindEscaped), g.count(alert.KindRefused)-before)
	}
}

// Стык с R2. Два агента, у каждого свой файл и свой ключ, имя шлюза — по
// умолчанию у обоих "esmcp" (README esmcp: «у каждого агента в общем файле —
// своё», про разные файлы — ничего). Счёт тревог сборщика — по имени шлюза
// (chains), а не по файлу и ключу: исходы второго с seq не выше первого
// тревог не поднимают, а его начало цепочки обнуляет счёт первого.
func TestR1TwoFilesOneGatewayNameShareTheAlertCount(t *testing.T) {
	g := newRig(t, "a.jsonl", "b.jsonl")
	refused := `{"outcome":"refused","cause":"row-limit","rows":9,"limit":1}`
	put := func(file, action string) {
		path := filepath.Join(g.dir, file)
		if _, err := gateway.Append(path, g.keys[path], "esmcp", outcome(action, refused)); err != nil {
			t.Fatal(err)
		}
	}
	for i := range 5 {
		put("a.jsonl", fmt.Sprintf("a-%d", i))
	}
	g.r.poll()
	for i := range 3 {
		put("b.jsonl", fmt.Sprintf("b-%d", i))
	}
	g.r.poll()
	put("a.jsonl", "a-5") // seq 6 у первого
	g.r.poll()
	put("b.jsonl", "b-3") // seq 4 у второго
	put("b.jsonl", "b-4") // seq 5
	g.r.poll()
	if n := g.count(alert.KindRefused); n != 11 {
		t.Fatalf("два агента в разных файлах под одним именем шлюза: тревог refused %d из 11 (%s)", n, g.kinds())
	}
}
