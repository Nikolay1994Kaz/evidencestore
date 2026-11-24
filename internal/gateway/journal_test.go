//go:build unix

package gateway

import (
	"bytes"
	"crypto/ed25519"
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"
)

// Файл квитанций шлюза против того, кто пишет в него без ключа (R1-2, R1-3,
// R2-7): ни копия прежней строки, ни строка от имени шлюза с чужой
// подписью, ни строка длиннее любой квитанции не раздваивают цепочку и не
// останавливают шлюз.

func receiptLines(t *testing.T, path string) [][]byte {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var out [][]byte
	for _, l := range bytes.Split(data, []byte("\n")) {
		if len(l) > 0 {
			out = append(out, l)
		}
	}
	return out
}

func appendRaw(t *testing.T, path string, data []byte) {
	t.Helper()
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_APPEND, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	if _, err := f.Write(data); err != nil {
		t.Fatal(err)
	}
}

func mustAppend(t *testing.T, path string, key ed25519.PrivateKey, action string) Appended {
	t.Helper()
	return mustAppendHead(t, path, "", key, action)
}

// headOf — голова цепочки рядом с ключом (как у шлюзов продукта); ключ в
// тестах — в своём каталоге, а не рядом с файлом квитанций.
func headOf(t *testing.T, path string) string {
	t.Helper()
	return DefaultHead(filepath.Join(t.TempDir(), "gw.key"), path, "esmcp")
}

func mustAppendHead(t *testing.T, path, head string, key ed25519.PrivateKey, action string) Appended {
	t.Helper()
	a, err := AppendHead(path, head, key, "esmcp", Draft{Time: at, Action: action, Step: "intent", Refs: []Ref{{Source: "pg", Subject: "754"}}})
	if err != nil {
		t.Fatal(err)
	}
	return a
}

// chainOf — цепочка файла глазами хранилища: сколько чистых квитанций у
// каждого seq.
func chainOf(t *testing.T, path string, pub ed25519.PublicKey) map[uint64]int {
	t.Helper()
	tr := NewReceiptTracker(pub)
	clean := map[uint64]int{}
	for _, l := range receiptLines(t, path) {
		if v := tr.Check(l); v.Clean() {
			clean[v.Seq]++
		}
	}
	return clean
}

// Копия прежней строки шлюза, дописанная без ключа: Append раньше брал её за
// последнюю свою квитанцию и сам раздваивал цепочку — новая квитанция
// получала занятый seq, и у хранилища выходило две чистые seq 3 (R1-2). С
// головой цепочка идёт от неё; без головы — от своей квитанции с большим seq.
func TestAppendIgnoresReplays(t *testing.T) {
	for _, withHead := range []bool{true, false} {
		key := receiptKey(t, 42)
		pub := key.Public().(ed25519.PublicKey)
		path := filepath.Join(t.TempDir(), "receipts.jsonl")
		head := ""
		if withHead {
			head = headOf(t, path)
		}
		for _, a := range []string{"a-1", "a-2", "a-3"} {
			mustAppendHead(t, path, head, key, a)
		}
		lines := receiptLines(t, path)
		appendRaw(t, path, append(bytes.Clone(lines[1]), '\n'))
		if a := mustAppendHead(t, path, head, key, "a-4"); a.Receipt.Seq != 4 || a.Stale != 1 {
			t.Fatalf("head %v, after a copy of seq 2: seq %d, stale %d", withHead, a.Receipt.Seq, a.Stale)
		}
		// Копии начала цепочки в конце файла: настоящая последняя — раньше.
		appendRaw(t, path, append(append(bytes.Clone(lines[0]), '\n'), append(bytes.Clone(lines[1]), '\n')...))
		if a := mustAppendHead(t, path, head, key, "a-5"); a.Receipt.Seq != 5 {
			t.Fatalf("head %v, after copies of seq 1 and 2: seq %d", withHead, a.Receipt.Seq)
		}
		if c := chainOf(t, path, pub); len(c) != 5 || c[3] != 1 {
			t.Fatalf("head %v, clean receipts: %v", withHead, c)
		}
	}
}

// Голова — состояние шлюза, а не подсказка рядом с файлом квитанций (R1-1,
// R1-2, R1-3 второго захода). Обрезка, оставившая ранние свои строки, —
// цепочка идёт от головы, а не от ранней квитанции (раньше — второй seq k+1
// без единого предупреждения); что лежит в каталоге файла квитанций, шлюз не
// читает: ни метка у предела seq, ни FIFO, ни ссылка его не останавливают.
// Голова другого файла, другого шлюза или ключа — не его.
func TestAppendHeadIsTheGatewaysState(t *testing.T) {
	key := receiptKey(t, 49)
	pub := key.Public().(ed25519.PublicKey)
	dir := t.TempDir()
	path := filepath.Join(dir, "receipts.jsonl")
	head := headOf(t, path)
	for _, a := range []string{"a-1", "a-2", "a-3", "a-4", "a-5"} {
		mustAppendHead(t, path, head, key, a)
	}
	lines := receiptLines(t, path)
	last, _ := ParseReceipt(lines[4])
	keep := append(append(bytes.Clone(lines[0]), '\n'), append(bytes.Clone(lines[1]), '\n')...)
	if err := os.WriteFile(path, keep, 0o640); err != nil { // обрезка до конца второй
		t.Fatal(err)
	}
	// Подложенное в каталог файла квитанций: метка прежней версии с seq у
	// предела, FIFO и ссылка на чужой файл.
	os.WriteFile(filepath.Join(dir, ".receipts_jsonl.heads"), []byte(`{"esmcp":{"key":"`+hex.EncodeToString(pub)+`","seq":9007199254740989,"hash":"`+strings.Repeat("a", 64)+`","end":1}}`), 0o640)
	syscall.Mkfifo(filepath.Join(dir, ".receipts_jsonl.heads.tmp"), 0o640)
	a := mustAppendHead(t, path, head, key, "a-6")
	if a.Receipt.Seq != 6 || a.Receipt.Prev != last.Hash {
		t.Fatalf("after a truncation that kept seq 1 and 2: seq %d, prev %s", a.Receipt.Seq, a.Receipt.Prev)
	}
	// Голова чужого файла (тот же ключ) — не его: цепочка по файлу.
	other := filepath.Join(dir, "other.jsonl")
	if a := mustAppendHead(t, other, head, key, "b-1"); a.Receipt.Seq != 1 || a.Receipt.Prev != Genesis {
		t.Fatalf("another file with this head: seq %d", a.Receipt.Seq)
	}
	// Голова — не обычный файл: отказ, а не ожидание и не запись по ссылке.
	fifo := filepath.Join(t.TempDir(), "fifo.head")
	syscall.Mkfifo(fifo, 0o640)
	if _, err := AppendHead(path, fifo, key, "esmcp", Draft{Time: at, Action: "a-7", Step: "intent"}); err == nil || !strings.Contains(err.Error(), "is not a file of the gateway") {
		t.Fatalf("a FIFO for a head: %v", err)
	}
}

// Строка длиннее любой квитанции после последней квитанции шлюза: Append
// отказывал на каждом вызове, пока файл не почистят руками (R1-3а, R2-7).
func TestAppendPastALongLine(t *testing.T) {
	key := receiptKey(t, 43)
	path := filepath.Join(t.TempDir(), "receipts.jsonl")
	head := headOf(t, path)
	mustAppendHead(t, path, head, key, "a-1")
	appendRaw(t, path, append(bytes.Repeat([]byte("x"), 2*MaxReceiptLen+1), '\n'))
	if a := mustAppendHead(t, path, head, key, "a-2"); a.Receipt.Seq != 2 || a.Skipped != 1 {
		t.Fatalf("past a long line: seq %d, skipped %d", a.Receipt.Seq, a.Skipped)
	}
	appendRaw(t, path, append(bytes.Repeat([]byte("y"), 3*MaxReceiptLen), '\n'))
	if a := mustAppend(t, path, key, "a-3"); a.Receipt.Seq != 3 {
		t.Fatalf("past a long line without the head: seq %d", a.Receipt.Seq)
	}
}

// Обрезать файл и дописать одну строку от имени шлюза с чужой подписью:
// Append отказывал («none is signed with this key») до тех пор, пока строку
// не уберут руками (R1-3б). Теперь цепочка идёт дальше от головы, а строка
// названа в Claimed. Без головы — новая цепочка.
func TestAppendAfterTruncateAndClaim(t *testing.T) {
	key := receiptKey(t, 44)
	path := filepath.Join(t.TempDir(), "receipts.jsonl")
	head := headOf(t, path)
	first := mustAppendHead(t, path, head, key, "a-1")
	forger, _ := NewSigner(receiptKey(t, 45), "esmcp", nil)
	claim := append(mustSign(t, forger, Draft{Time: at, Action: "x", Step: "intent"}), '\n')
	if err := os.WriteFile(path, claim, 0o640); err != nil {
		t.Fatal(err)
	}
	if a := mustAppendHead(t, path, head, key, "a-2"); a.Receipt.Seq != 2 || a.Receipt.Prev != first.Receipt.Hash {
		t.Fatalf("after a truncation and a forged claim: seq %d, prev %s", a.Receipt.Seq, a.Receipt.Prev)
	}
	if err := os.WriteFile(path, claim, 0o640); err != nil {
		t.Fatal(err)
	}
	if a := mustAppend(t, path, key, "a-3"); a.Receipt.Seq != 1 || a.Receipt.Prev != Genesis || a.Claimed != 1 {
		t.Fatalf("without the head: seq %d, prev %s, claimed %d", a.Receipt.Seq, a.Receipt.Prev, a.Claimed)
	}
}

// logrotate (create): файл ушёл под другое имя, шлюз пишет в новый — цепочка
// идёт дальше, а не начинается заново: у хранилища новая цепочка — поломка
// «receipts after seq N may be lost» на каждой ротации.
func TestAppendAfterRotation(t *testing.T) {
	key := receiptKey(t, 51)
	pub := key.Public().(ed25519.PublicKey)
	path := filepath.Join(t.TempDir(), "receipts.jsonl")
	head := headOf(t, path)
	mustAppendHead(t, path, head, key, "a-1")
	last := mustAppendHead(t, path, head, key, "a-2")
	if err := os.Rename(path, path+".1"); err != nil {
		t.Fatal(err)
	}
	a := mustAppendHead(t, path, head, key, "a-3")
	if a.Receipt.Seq != 3 || a.Receipt.Prev != last.Receipt.Hash {
		t.Fatalf("after a rotation: seq %d, prev %s", a.Receipt.Seq, a.Receipt.Prev)
	}
	tr := NewReceiptTracker(pub)
	for _, f := range []string{path + ".1", path} {
		for _, l := range receiptLines(t, f) {
			if v := tr.Check(l); !v.Clean() {
				t.Fatalf("%s: %+v", f, v)
			}
		}
	}
}

// Шлюз упал между записью квитанции и головы: следующая квитанция идёт от
// той, что уже в файле, а не от головы, — цепочка не раздваивается.
func TestAppendCatchesUpAfterACrash(t *testing.T) {
	key := receiptKey(t, 52)
	pub := key.Public().(ed25519.PublicKey)
	path := filepath.Join(t.TempDir(), "receipts.jsonl")
	head := headOf(t, path)
	mustAppendHead(t, path, head, key, "a-1")
	saved, _ := os.ReadFile(head)
	mustAppendHead(t, path, head, key, "a-2")
	os.WriteFile(head, saved, 0o600) // голова — до a-2
	if a := mustAppendHead(t, path, head, key, "a-3"); a.Receipt.Seq != 3 {
		t.Fatalf("after a crash between the receipt and the head: seq %d", a.Receipt.Seq)
	}
	if c := chainOf(t, path, pub); len(c) != 3 {
		t.Fatalf("clean receipts: %v", c)
	}
}

// Строки от имени шлюза с чужой подписью в конце файла: Append проверял
// подпись каждой при каждом вызове — под flock, так что ждали и остальные
// писатели (R1-3в). Теперь их читает один Append, следующий идёт от метки
// за ними.
func TestAppendReadsAForgedTailOnce(t *testing.T) {
	key := receiptKey(t, 47)
	path := filepath.Join(t.TempDir(), "receipts.jsonl")
	head := headOf(t, path)
	mustAppendHead(t, path, head, key, "a-1")
	forger, _ := NewSigner(receiptKey(t, 48), "esmcp", nil)
	var junk bytes.Buffer
	for range 2000 {
		junk.Write(mustSign(t, forger, Draft{Time: at, Action: "x", Step: "s"}))
		junk.WriteByte('\n')
	}
	appendRaw(t, path, junk.Bytes())
	if a := mustAppendHead(t, path, head, key, "a-2"); a.Receipt.Seq != 2 || a.Skipped != 2000 || a.Claimed != 2000 {
		t.Fatalf("past the forged tail: seq %d, skipped %d, claimed %d", a.Receipt.Seq, a.Skipped, a.Claimed)
	}
	start := time.Now()
	if a := mustAppendHead(t, path, head, key, "a-3"); a.Receipt.Seq != 3 || a.Skipped != 0 {
		t.Fatalf("the next one: seq %d, skipped %d", a.Receipt.Seq, a.Skipped)
	}
	t.Logf("the Append after the forged tail: %v", time.Since(start))
}

// Писатель без flock видит, что замок у шлюза, и дописывает байт без
// перевода строки между проверкой хвоста и записью: квитанция склеивалась с
// ним («x{…}»), намерение не читалось, и действие агента шло отпечатком
// (T-5: 11 из 20). Теперь склейка видна сразу после записи, и та же строка
// ложится ещё раз, с переводом строки впереди.
func TestAppendRewritesAGluedReceipt(t *testing.T) {
	key := receiptKey(t, 50)
	pub := key.Public().(ed25519.PublicKey)
	path := filepath.Join(t.TempDir(), "receipts.jsonl")
	mustAppend(t, path, key, "a-1")
	beforeWrite = func(p string) { appendRaw(t, p, []byte("x")) }
	defer func() { beforeWrite = nil }()
	a := mustAppend(t, path, key, "a-2")
	beforeWrite = nil
	if !a.Glued {
		t.Fatal("the glued receipt is not seen")
	}
	lines := receiptLines(t, path)
	if len(lines) != 3 || !bytes.Equal(lines[1], append([]byte("x"), a.Line...)) || !bytes.Equal(lines[2], a.Line) {
		t.Fatalf("the file: %q", lines)
	}
	// Хранилище: склейка — поломанная строка без цепочки, копия — сцеплена.
	if c := chainOf(t, path, pub); c[1] != 1 || c[2] != 1 {
		t.Fatalf("clean receipts: %v", c)
	}
	if next := mustAppend(t, path, key, "a-3"); next.Receipt.Seq != 3 || next.Glued {
		t.Fatalf("the next one: seq %d, glued %v", next.Receipt.Seq, next.Glued)
	}
}

// Голову в каталоге только для чтения шлюз видит при запуске (CheckHead), а
// не отказом на каждом действии.
func TestCheckHead(t *testing.T) {
	dir := t.TempDir()
	receipts := filepath.Join(t.TempDir(), "receipts.jsonl")
	if err := CheckHead(filepath.Join(dir, "esmcp.head"), receipts); err != nil {
		t.Fatal(err)
	}
	if err := CheckHead(filepath.Join(dir, "missing", "esmcp.head"), receipts); err == nil || !strings.Contains(err.Error(), `unless "head" says where`) {
		t.Fatalf("a head in a directory that is not there: %v", err)
	}
	if err := syscall.Mkfifo(filepath.Join(dir, "fifo.head"), 0o600); err == nil {
		if err := CheckHead(filepath.Join(dir, "fifo.head"), receipts); err == nil {
			t.Fatal("a FIFO for a head passed")
		}
	}
	// T-5 третьего захода: голова в каталоге квитанций — отказ при запуске.
	if err := CheckHead(filepath.Join(filepath.Dir(receipts), "esmcp.key.head-0011223344556677"), receipts); err == nil || !strings.Contains(err.Error(), "lies in the directory of the receipts file") {
		t.Fatalf("a head in the receipts directory: %v", err)
	}
	left, _ := os.ReadDir(dir)
	for _, e := range left {
		if strings.Contains(e.Name(), ".check-") {
			t.Fatalf("the check left %s", e.Name())
		}
	}
}

// Дыра разреженного файла посреди файла (за ней дописали) перешагивается, а
// не читается: 32 ГиБ нулей, свободных для писателя файла, не стоят секунд
// под flock на каждом Append и в каждом чтении счёта пределов (P-378).
// Строки по обе стороны дыры — те же, что при чтении нулей.
func TestReadLinesStepsOverAHole(t *testing.T) {
	path := filepath.Join(t.TempDir(), "receipts.jsonl")
	if err := os.WriteFile(path, []byte("first\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Truncate(path, 6+32<<30); err != nil {
		t.Fatal(err)
	}
	f, err := os.OpenFile(path, os.O_RDWR|os.O_APPEND, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	if _, err := f.Write([]byte("\nsecond\n")); err != nil {
		t.Fatal(err)
	}
	fi, _ := f.Stat()
	var got []string
	start := time.Now()
	done, err := ReadLines(f, 0, fi.Size(), func(line []byte, _ int64, long bool) {
		if long {
			line = []byte("(long)")
		}
		got = append(got, string(line))
	})
	took := time.Since(start)
	if err != nil || done != fi.Size() || strings.Join(got, ",") != "first,(long),second" {
		t.Fatalf("%q, done %d of %d: %v", got, done, fi.Size(), err)
	}
	if took > time.Second {
		t.Fatalf("the hole was read: %v", took)
	}
}
