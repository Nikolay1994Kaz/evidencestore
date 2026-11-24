package pginput

// Третий заход проверки (R1, 24.11): находки по читателю квитанций в
// сборщике. Каждый тест здесь ПАДАЕТ на 1f9a0f2 — значит, уязвимость есть.
// go test ./internal/pginput -run R1Rev8 -count=1 -v

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Nikolay1994Kaz/evidencestore/internal/alert"
	"github.com/Nikolay1994Kaz/evidencestore/internal/pgtap"
)

// R1-1. Пока сборщик стоит, писатель файла квитанций без ключа (противник 3)
// обрезает файл (прежние строки сборщик уже прочёл, они в хранилище), ждёт,
// пока шлюз допишет квитанции (голова шлюза — у ключа, цепочка идёт дальше
// без раздвоения), вынимает одно намерение и добивает файл пустыми строками
// до прежнего размера. При запуске сборщик читает тот же inode с начала, но
// «свежесть» строк — по месту в файле (end > alerted из receipts.json): всё,
// что шлюз написал, пока сборщик стоял, лежит теперь раньше этого места.
// Итог: исход escaped (агент вышел из транзакции шлюза — изменения без
// проверки пределов) — без тревоги; намерение вынуто — транзакция пойдёт
// отпечатком, а receipts-gap и intent-missing молчат (пропуск seq 2 → 4 и
// исход без намерения стоят до места тревог). Пустые строки тревог не
// поднимают.
func TestR1Rev8RestartRewriteSilencesEverything(t *testing.T) {
	g := newRig(t, "esmcp.jsonl")
	now := time.Now()
	path := g.cfg.Files[0]
	// История: обычные действия, сборщик их прочёл.
	for i := 1; i <= 20; i++ {
		x := fmt.Sprint(700 + i)
		g.sign("esmcp.jsonl", intent(fmt.Sprint("h-", i), now, x))
		g.sign("esmcp.jsonl", outcome(fmt.Sprint("h-", i), `{"outcome":"committed","xid":"`+x+`","rows":1}`))
	}
	g.r.poll()
	if len(g.alerts) != 0 {
		t.Fatalf("history: %s", g.kinds())
	}
	alertedAt := fileSize(t, path)
	g.r.close() // сборщик остановлен (обновление, перезагрузка)

	// Противник 3: обрезка — та же inode, шлюз пишет дальше по голове.
	if err := os.Truncate(path, 0); err != nil {
		t.Fatal(err)
	}
	g.sign("esmcp.jsonl", intent("a-esc", now, "900"))
	g.sign("esmcp.jsonl", outcome("a-esc", `{"outcome":"escaped","cause":"escaped","xid":"900","tool":"execute"}`))
	keep, _ := os.ReadFile(path)
	g.sign("esmcp.jsonl", intent("a-gone", now, "901")) // это намерение он вынет
	g.sign("esmcp.jsonl", outcome("a-gone", `{"outcome":"committed","xid":"901","rows":3}`))
	all, _ := os.ReadFile(path)
	outcomeLine := all[bytes.LastIndexByte(all[:len(all)-1], '\n')+1:]
	data := append(append([]byte{}, keep...), outcomeLine...)
	if pad := alertedAt - int64(len(data)); pad > 0 {
		data = append(data, bytes.Repeat([]byte("\n"), int(pad)+1)...)
	}
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_TRUNC, 0) // на месте: inode тот же
	if err != nil {
		t.Fatal(err)
	}
	f.Write(data)
	f.Close()

	g.open() // сборщик запущен
	g.r.poll()
	if _, ok, _ := g.r.Intent(901, now, 0x901); ok {
		t.Fatal("setup: the removed intent was read")
	}
	t.Logf("alerts after the restart: %q", g.kinds())
	if g.count(alert.KindEscaped) != 1 {
		t.Errorf("the escaped outcome written while the collector was stopped raised no alert (it lies before %d, the alerted place of receipts.json)", alertedAt)
	}
	if g.count(alert.KindReceiptsGap) != 1 || g.count(alert.KindIntentMissing) != 1 {
		t.Errorf("the intent removed while the collector was stopped: receipts-gap %d, intent-missing %d — transaction 901 goes as a fingerprint without a word",
			g.count(alert.KindReceiptsGap), g.count(alert.KindIntentMissing))
	}
}

// R1-2. Копии одной квитанции исхода, дописанные без ключа, — тревога
// intent-missing на каждую копию и полный проход справочника (pgtap.Lookup
// читает справочник с начала) на каждую. Нужен исход, чьего намерения нет в
// памяти: намерения сборщик в памяти держит только с запуска, а файл с ним
// повернули и сжали (или это намерение вынули). Исход failed (SQL с ошибкой,
// откат) тревоги исхода не поднимает, его хэш не помечается, и
// «Дважды о том же исходе — нет … по копии прежней строки» не выполняется.
func TestR1Rev8CopiedOutcomeFloodsIntentMissing(t *testing.T) {
	g := newRig(t, "esmcp.jsonl")
	now := time.Now()
	path := g.cfg.Files[0]
	g.sign("esmcp.jsonl", intent("a-1", now, "751"))
	failed := g.append("esmcp.jsonl", outcome("a-1", `{"outcome":"failed","xid":"751","error":"division by zero"}`)).Line
	g.r.poll()
	g.r.close()
	// Ротация, пока сборщик стоит: прежний файл сжат (другой inode).
	os.Rename(path, path+".1.gz")
	os.WriteFile(path+".1.gz", []byte("compressed"), 0o600)
	g.sign("esmcp.jsonl", intent("a-2", now, "752")) // цепочка идёт дальше: seq 3
	g.open()
	g.r.poll()
	if len(g.alerts) != 0 {
		t.Fatalf("setup: %s", g.kinds())
	}
	// Противник 3 (читает .1.gz в том же каталоге) дописывает 50 копий исхода.
	f, _ := os.OpenFile(path, os.O_APPEND|os.O_WRONLY, 0)
	for range 50 {
		f.Write(append(bytes.TrimRight(failed, "\n"), '\n'))
	}
	f.Close()
	g.r.poll()
	t.Logf("intent-missing alerts for 50 copies of one outcome: %d", g.count(alert.KindIntentMissing))
	if g.count(alert.KindIntentMissing) > 1 {
		t.Errorf("%d intent-missing alerts for copies of one outcome line", g.count(alert.KindIntentMissing))
	}
}

// R1-2б. То же для исхода committed, чья транзакция в справочнике: тревоги
// нет, но каждая копия — полный проход справочника под потоком (poll зовётся
// из Intent на начале транзакции и в простое). Справочник растёт на строку
// на транзакцию и не ротируется; здесь 400 000 строк (≈40 МБ) и 200 копий
// одной строки исхода (≈40 КБ, ничего не стоят противнику).
func TestR1Rev8CopiedOutcomeScansTheIndexEachTime(t *testing.T) {
	g := newRig(t, "esmcp.jsonl")
	now := time.Now()
	path := g.cfg.Files[0]
	var idx bytes.Buffer
	for x := 1000; x < 401000; x++ {
		fmt.Fprintf(&idx, `{"xid":%d,"first_seq":%d,"last_seq":%d,"changes":1,"action":{"id":"x-%d","gateway":"esmcp","seq":%d}}`+"\n", x, x, x, x, x)
	}
	fmt.Fprintf(&idx, `{"xid":751,"first_seq":1,"last_seq":1,"changes":1,"action":{"id":"a-1","gateway":"esmcp","seq":1}}`+"\n")
	if err := os.WriteFile(filepath.Join(g.dir, pgtap.IndexFile), idx.Bytes(), 0o600); err != nil {
		t.Fatal(err)
	}
	g.sign("esmcp.jsonl", intent("a-1", now, "751"))
	done := g.append("esmcp.jsonl", outcome("a-1", `{"outcome":"committed","xid":"751","rows":1}`)).Line
	g.r.poll()
	g.r.close()
	os.Rename(path, path+".1.gz")
	os.WriteFile(path+".1.gz", []byte("compressed"), 0o600)
	g.sign("esmcp.jsonl", intent("a-2", now, "752"))
	g.open()
	g.r.poll()
	f, _ := os.OpenFile(path, os.O_APPEND|os.O_WRONLY, 0)
	n := 200
	f.Write(bytes.Repeat(append(bytes.TrimRight(done, "\n"), '\n'), n))
	f.Close()
	start := time.Now()
	g.r.poll()
	took := time.Since(start)
	t.Logf("%d copies (%d bytes) of one outcome line: poll took %v (index %d MB), alerts %q", n, n*len(done), took, idx.Len()>>20, g.kinds())
	if took > time.Second {
		t.Errorf("reading %d copied lines took %v: a full scan of the index per copy, in the stream path", n, took)
	}
}

// R1-3. logrotate (create, без сжатия) повернул файл, пока сборщик стоял:
// прежний лежит рядом (.1), сборщик дочитывает его по inode (drainRotated) —
// но сцепку ведёт по имени повёрнутого файла (rf.path в ключе links), а не
// по пути из настроек. Первая квитанция нового файла сверяется с местом
// цепочки до остановки — ложная тревога receipts-gap «1 receipts between
// them are not in the file», хотя ни одна строка не пропала. Ключ links по
// имени .1 (с dateext — по новому имени на каждую ротацию) остаётся в
// receipts.json навсегда.
func TestR1Rev8RotationWhileDownFalseGap(t *testing.T) {
	g := newRig(t, "esmcp.jsonl")
	now := time.Now()
	path := g.cfg.Files[0]
	g.sign("esmcp.jsonl", intent("a-1", now, "751"))
	g.r.poll()
	g.r.close()
	g.sign("esmcp.jsonl", intent("a-2", now, "752")) // сборщик стоит
	os.Rename(path, path+".1")
	g.sign("esmcp.jsonl", intent("a-3", now, "753"))
	g.open()
	g.r.poll()
	for xid, id := range map[uint32]string{751: "a-1", 752: "a-2", 753: "a-3"} {
		if in, ok, _ := g.r.Intent(xid, now, 0); !ok || in.ID != id {
			t.Fatalf("setup: xid %d: %+v %v", xid, in, ok)
		}
	}
	state, _ := os.ReadFile(filepath.Join(g.dir, ReceiptsState))
	t.Logf("alerts: %q; links in receipts.json name the rotated file: %v", g.kinds(), strings.Contains(string(state), "esmcp.jsonl.1"))
	if g.count(alert.KindReceiptsGap) != 0 {
		t.Errorf("a plain rotation while the collector was stopped raised receipts-gap: %s", g.alerts[0].Signals[0].Detail)
	}
}
