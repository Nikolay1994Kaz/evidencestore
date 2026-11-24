package pginput

// Регрессия второго захода проверки шагов 2–3 (24.11): тесты R1, R2 и T,
// которые падали на 7643a65 и проходят после исправлений (FINDINGS, P-357…).

// Проверка исправлений шагов 2–3 (R2, второй заход): читатель квитанций без базы.
// go test ./internal/pginput -run R2Rev -count=1 -v

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"syscall"
	"testing"
	"time"

	"github.com/Nikolay1994Kaz/evidencestore/internal/alert"
	"github.com/Nikolay1994Kaz/evidencestore/internal/gateway"
)

// twoAgents — два esmcp со своими файлами и ключами и именем шлюза по
// умолчанию ("esmcp"): так их и настраивают — у каждого агента свой
// mcp.json, gateway не задан.
type twoAgents struct {
	t      *testing.T
	dir    string
	cfg    ReceiptsConfig
	keys   []ed25519.PrivateKey
	r      *receipts
	alerts []alert.Event
}

func newTwoAgents(t *testing.T) *twoAgents {
	a := &twoAgents{t: t, dir: t.TempDir()}
	for _, sub := range []string{"support", "billing"} {
		os.MkdirAll(filepath.Join(a.dir, sub), 0o700)
		pub, key, _ := ed25519.GenerateKey(rand.Reader)
		a.keys = append(a.keys, key)
		a.cfg.Files = append(a.cfg.Files, filepath.Join(a.dir, sub, "receipts.jsonl"))
		a.cfg.GatewayKeys = append(a.cfg.GatewayKeys, hex.EncodeToString(pub))
	}
	if err := a.cfg.validate(); err != nil {
		t.Fatal(err)
	}
	a.open()
	return a
}

func (a *twoAgents) open() {
	a.t.Helper()
	if a.r != nil {
		a.r.close()
	}
	var err error
	if a.r, err = openReceipts(a.cfg, filepath.Join(a.dir, "state"), func(ev alert.Event) error { a.alerts = append(a.alerts, ev); return nil }); err != nil {
		a.t.Fatal(err)
	}
	os.MkdirAll(filepath.Join(a.dir, "state"), 0o700)
	a.t.Cleanup(a.r.close)
	if err := a.r.poll(); err != nil {
		a.t.Fatal(err)
	}
}

func (a *twoAgents) sign(i int, d gateway.Draft) {
	a.t.Helper()
	if _, err := gateway.Append(a.cfg.Files[i], a.keys[i], "esmcp", d); err != nil {
		a.t.Fatal(err)
	}
}

func (a *twoAgents) count(kind string) int {
	n := 0
	for _, e := range a.alerts {
		for _, k := range e.Kinds() {
			if k == kind {
				n++
			}
		}
	}
	return n
}

// R2-2а. Два агента, у каждого свой esmcp, свой файл и ключ, имя шлюза по
// умолчанию. Цепочки сборщик ведёт по имени шлюза: тревоги исхода второго
// агента (отказ, выход из транзакции, обрыв на COMMIT) молча не поднимаются,
// пока его seq не обгонит seq первого.
func TestR2RevSameGatewayNameHidesOutcomeAlerts(t *testing.T) {
	a := newTwoAgents(t)
	now := time.Now()
	// Оба начали работать.
	a.sign(0, intent("s-1", now, "100"))
	a.sign(0, outcome("s-1", `{"outcome":"committed","xid":"100","rows":1}`))
	a.sign(1, intent("b-1", now, "101"))
	a.sign(1, outcome("b-1", `{"outcome":"committed","xid":"101","rows":1}`))
	a.r.poll()
	// Первый агент много работает (обычные действия).
	for i := 2; i <= 30; i++ {
		x := fmt.Sprint(100 + 2*i)
		a.sign(0, intent(fmt.Sprintf("s-%d", i), now, x))
		a.sign(0, outcome(fmt.Sprintf("s-%d", i), `{"outcome":"committed","xid":"`+x+`","rows":1}`))
	}
	a.r.poll()
	// Второй агент: отказ пределом, выход из транзакции, обрыв на COMMIT.
	a.sign(1, intent("b-2", now, "201"))
	a.sign(1, outcome("b-2", `{"outcome":"refused","cause":"row-limit","rows":5000,"limit":100}`))
	a.sign(1, intent("b-3", now, "202"))
	a.sign(1, outcome("b-3", `{"outcome":"escaped","cause":"escaped","xid":"202","tool":"execute"}`))
	a.sign(1, intent("b-4", now, "203"))
	a.sign(1, outcome("b-4", `{"outcome":"unknown","cause":"unknown","xid":"203","rows":7}`))
	a.r.poll()
	t.Logf("alerts: refused %d, escaped %d, commit-unknown %d", a.count(alert.KindRefused), a.count(alert.KindEscaped), a.count(alert.KindUnknown))
	if a.count(alert.KindRefused) != 1 || a.count(alert.KindEscaped) != 1 || a.count(alert.KindUnknown) != 1 {
		t.Errorf("the second agent's refused/escaped/commit-unknown outcomes raised no alerts (chain state shared by gateway name %q)", "esmcp")
	}
}

// R2-2б. То же имя у двух цепочек: после db-rewound намерения второго агента,
// записанные ПОСЛЕ подъёма, не в счёт (его seq ниже Void, взятого по первому),
// — его действия идут отпечатком, без отката. А после перезапуска сборщика
// снятые намерения возвращаются: начало каждой цепочки обнуляет Void.
func TestR2RevSameGatewayNameVoid(t *testing.T) {
	a := newTwoAgents(t)
	now := time.Now()
	a.sign(0, intent("s-1", now, "500")) // первый агент: одно действие до подъёма
	for i := 1; i <= 20; i++ {           // второй (его файл читается вторым): двадцать
		a.sign(1, intent(fmt.Sprintf("b-%d", i), now, fmt.Sprint(600+i)))
	}
	a.r.poll()
	if err := a.r.void(voidSpec{}); err != nil { // база поднята из копии
		t.Fatal(err)
	}
	// После подъёма: новое действие первого агента — его намерение должно быть в счёте.
	a.sign(0, intent("s-2", now.Add(time.Second), "700"))
	if _, ok, _ := a.r.Intent(700, now, 0x700); !ok {
		t.Errorf("an intent written after the rewind (agent 1, seq 2) is void: its action goes as a fingerprint, Void=%q", a.r.chains["esmcp"].VoidTime)
	}
	// Перезапуск сборщика: снятые намерения (до подъёма) — не в счёт и теперь.
	a.open()
	for xid, who := range map[uint32]string{500: "agent 1", 605: "agent 2"} {
		if in, ok, _ := a.r.Intent(xid, now, 0x5000); ok {
			t.Errorf("after a restart the voided intent %s of %s decides transaction %d again", in.ID, who, xid)
		}
	}
}

// R2-2в. Один шлюз, новый ключ (ротация ключа: в gateway_keys оба). Append
// с новым ключом начинает новую цепочку в том же файле. Начало новой цепочки
// обнуляет Void, и после перезапуска сборщика снятые намерения старой
// цепочки возвращаются.
func TestR2RevKeyRotationRevivesVoidedIntents(t *testing.T) {
	g := newRig(t, "esmcp.jsonl")
	now := time.Now()
	path := g.cfg.Files[0]
	g.sign("esmcp.jsonl", intent("a-1", now, "751"))
	g.r.poll()
	if err := g.r.void(voidSpec{}); err != nil {
		t.Fatal(err)
	}
	// Новый ключ шлюза; сборщик знает оба.
	pub2, key2, _ := ed25519.GenerateKey(rand.Reader)
	g.cfg.GatewayKeys = append(g.cfg.GatewayKeys, hex.EncodeToString(pub2))
	if _, err := gateway.Append(path, key2, "esmcp", intent("a-2", now, "752")); err != nil {
		t.Fatal(err)
	}
	for restart := 1; restart <= 2; restart++ {
		g.open()
		if in, ok, _ := g.r.Intent(751, now, 0x9000); ok {
			t.Errorf("after a key rotation and restart %d the voided intent %s decides transaction 751 again", restart, in.ID)
		}
	}
}

// R2-5. Память читателя: r.spent (хэш намерения → место фиксации) растёт с
// каждым решённым намерением и не убывает никогда — сжатие переписывает
// только файл. Предел maxIntents держит byXID, а не spent.
func TestR2RevSpentGrowsWithoutBound(t *testing.T) {
	old := maxIntents
	maxIntents = 10
	t.Cleanup(func() { maxIntents = old })
	g := newRig(t, "esmcp.jsonl")
	now := time.Now()
	for i := 1; i <= 500; i++ {
		g.sign("esmcp.jsonl", intent(fmt.Sprint("a-", i), now, fmt.Sprint(1000+i)))
		if _, ok, err := g.r.Intent(uint32(1000+i), now, uint64(0x10000+i)); !ok || err != nil {
			t.Fatalf("intent %d: %v %v", i, ok, err)
		}
	}
	data, _ := os.ReadFile(filepath.Join(g.dir, ReceiptsSpent))
	lines := 0
	for _, b := range data {
		if b == '\n' {
			lines++
		}
	}
	t.Logf("in memory: %d intents, %d spent entries; the spent file: %d lines", len(g.r.byXID), len(g.r.spent), lines)
	if len(g.r.spent) > 4*maxIntents {
		t.Errorf("r.spent holds %d entries with maxIntents %d: it grows with every action for as long as the collector runs", len(g.r.spent), maxIntents)
	}
}

// R2-6. Писатель каталога квитанций без ключа (модель 3) заменяет файл по
// пути каталогом (или ссылкой на файл, который сборщику не прочесть, или
// FIFO). Читатель теперь идёт за путём (P-342): на ходу каждый Begin
// транзакции — ошибка, поток рвётся и подключается снова, вход стоит; при
// запуске Source.Open возвращает ошибку, и escollect не запускается вовсе —
// со всеми источниками процесса. С FIFO os.Open висит.
func TestR2RevReceiptsPathReplacedStopsTheInput(t *testing.T) {
	g := newRig(t, "esmcp.jsonl")
	now := time.Now()
	path := g.cfg.Files[0]
	g.sign("esmcp.jsonl", intent("a-1", now, "751"))
	if _, ok, err := g.r.Intent(751, now, 0); !ok || err != nil {
		t.Fatal(ok, err)
	}
	// Замена на ходу: каталог по пути.
	os.Rename(path, path+".1")
	if err := os.Mkdir(path, 0o755); err != nil {
		t.Fatal(err)
	}
	_, _, err := g.r.Intent(999, now, 0) // транзакция человека: намерения нет
	t.Logf("a transaction without an intent after the path became a directory: %v", err)
	if err != nil {
		t.Errorf("every transaction now fails in Begin: %v", err)
	}
	// Запуск сборщика с таким путём.
	cfg := Config{DSN: "host=/nonexistent user=tap dbname=x", Dir: t.TempDir(), MCPRoles: []string{"m"}, Tables: []string{"public.t"}, Receipts: &g.cfg}
	if err := cfg.Validate(); err != nil {
		t.Fatal(err)
	}
	src, _ := New(cfg, nil)
	err = src.Open(0, &memSink{})
	t.Logf("Source.Open at the collector's start: %v", err)
	if err != nil {
		t.Errorf("the collector does not start (collector.New fails, escollect exits with all its sources): %v", err)
	} else {
		src.Close()
	}
	// FIFO по пути: open для чтения ждёт писателя.
	os.Remove(path)
	if err := syscall.Mkfifo(path, 0o644); err != nil {
		t.Skip("mkfifo:", err)
	}
	done := make(chan error, 1)
	r2, _ := openReceipts(g.cfg, t.TempDir(), func(alert.Event) error { return nil })
	go func() { done <- r2.poll() }()
	select {
	case err := <-done:
		t.Logf("poll with a FIFO: %v", err)
	case <-time.After(2 * time.Second):
		t.Errorf("poll hangs in os.Open of a FIFO at the receipts path (the input, and the collector's start, stop for good)")
		f, _ := os.OpenFile(path, os.O_WRONLY|syscall.O_NONBLOCK, 0) // отпустить
		if f != nil {
			f.Close()
		}
	}
}
