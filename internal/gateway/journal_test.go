package gateway

import (
	"bytes"
	"crypto/ed25519"
	"os"
	"path/filepath"
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
	a, err := Append(path, key, "esmcp", Draft{Time: at, Action: action, Step: "intent", Refs: []Ref{{Source: "pg", Subject: "754"}}})
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
// получала занятый seq, и у хранилища выходило две чистые seq 3. Теперь
// цепочка идёт от настоящей последней — и по метке рядом с файлом, и без неё
// (метку тоже может стереть тот, кто пишет в каталог).
func TestAppendIgnoresReplays(t *testing.T) {
	key := receiptKey(t, 42)
	pub := key.Public().(ed25519.PublicKey)
	path := filepath.Join(t.TempDir(), "receipts.jsonl")
	for _, a := range []string{"a-1", "a-2", "a-3"} {
		mustAppend(t, path, key, a)
	}
	lines := receiptLines(t, path)
	appendRaw(t, path, append(bytes.Clone(lines[1]), '\n'))
	a := mustAppend(t, path, key, "a-4")
	if a.Receipt.Seq != 4 || a.Stale != 1 {
		t.Fatalf("after a copy of seq 2: seq %d, stale %d", a.Receipt.Seq, a.Stale)
	}
	// Без метки: копии начала цепочки в конце файла — настоящая последняя
	// раньше них.
	os.Remove(headsPath(path))
	appendRaw(t, path, append(append(bytes.Clone(lines[0]), '\n'), append(bytes.Clone(lines[1]), '\n')...))
	if a := mustAppend(t, path, key, "a-5"); a.Receipt.Seq != 5 {
		t.Fatalf("without the mark, after copies of seq 1 and 2: seq %d", a.Receipt.Seq)
	}
	for seq, n := range chainOf(t, path, pub) {
		if n != 1 {
			t.Errorf("seq %d: %d clean receipts", seq, n)
		}
	}
	if c := chainOf(t, path, pub); len(c) != 5 {
		t.Fatalf("clean receipts: %v", c)
	}
}

// Метка рядом с файлом — подсказка: устаревшая (на более раннюю квитанцию)
// или указывающая за конец файла цепочку не раздваивает.
func TestAppendDoesNotTrustTheMark(t *testing.T) {
	key := receiptKey(t, 49)
	path := filepath.Join(t.TempDir(), "receipts.jsonl")
	first := mustAppend(t, path, key, "a-1")
	mustAppend(t, path, key, "a-2")
	mustAppend(t, path, key, "a-3")
	old := readHeads(path)["esmcp"]
	old.Seq, old.Hash, old.End = first.Receipt.Seq, first.Receipt.Hash, int64(len(first.Line)+1)
	writeHeads(path, map[string]headMark{"esmcp": old})
	if a := mustAppend(t, path, key, "a-4"); a.Receipt.Seq != 4 {
		t.Fatalf("from an old mark: seq %d", a.Receipt.Seq)
	}
	old.End = 1 << 30
	writeHeads(path, map[string]headMark{"esmcp": old})
	if a := mustAppend(t, path, key, "a-5"); a.Receipt.Seq != 5 {
		t.Fatalf("from a mark past the end: seq %d", a.Receipt.Seq)
	}
}

// Строка длиннее любой квитанции после последней квитанции шлюза: Append
// отказывал на каждом вызове, пока файл не почистят руками (R1-3а, R2-7).
func TestAppendPastALongLine(t *testing.T) {
	key := receiptKey(t, 43)
	path := filepath.Join(t.TempDir(), "receipts.jsonl")
	mustAppend(t, path, key, "a-1")
	appendRaw(t, path, append(bytes.Repeat([]byte("x"), 2*MaxReceiptLen+1), '\n'))
	if a := mustAppend(t, path, key, "a-2"); a.Receipt.Seq != 2 || a.Skipped != 1 {
		t.Fatalf("past a long line: seq %d, skipped %d", a.Receipt.Seq, a.Skipped)
	}
	appendRaw(t, path, append(bytes.Repeat([]byte("y"), 3*MaxReceiptLen), '\n'))
	os.Remove(headsPath(path))
	if a := mustAppend(t, path, key, "a-3"); a.Receipt.Seq != 3 {
		t.Fatalf("past a long line without the mark: seq %d", a.Receipt.Seq)
	}
}

// Обрезать файл и дописать одну строку от имени шлюза с чужой подписью:
// Append отказывал («none is signed with this key») до тех пор, пока строку
// не уберут руками (R1-3б). Теперь цепочка идёт дальше от метки, а строка
// названа в Claimed. Без метки (её тоже можно стереть) — новая цепочка.
func TestAppendAfterTruncateAndClaim(t *testing.T) {
	key := receiptKey(t, 44)
	path := filepath.Join(t.TempDir(), "receipts.jsonl")
	first := mustAppend(t, path, key, "a-1")
	forger, _ := NewSigner(receiptKey(t, 45), "esmcp", nil)
	claim := append(mustSign(t, forger, Draft{Time: at, Action: "x", Step: "intent"}), '\n')
	if err := os.WriteFile(path, claim, 0o640); err != nil {
		t.Fatal(err)
	}
	a := mustAppend(t, path, key, "a-2")
	if a.Receipt.Seq != 2 || a.Receipt.Prev != first.Receipt.Hash || a.Claimed != 1 {
		t.Fatalf("after a truncation and a forged claim: seq %d, prev %s, claimed %d", a.Receipt.Seq, a.Receipt.Prev, a.Claimed)
	}
	os.Remove(headsPath(path))
	if err := os.WriteFile(path, claim, 0o640); err != nil {
		t.Fatal(err)
	}
	if a := mustAppend(t, path, key, "a-3"); a.Receipt.Seq != 1 || a.Receipt.Prev != Genesis || a.Claimed != 1 {
		t.Fatalf("without the mark: seq %d, prev %s, claimed %d", a.Receipt.Seq, a.Receipt.Prev, a.Claimed)
	}
}

// logrotate (create): файл ушёл под другое имя, шлюз пишет в новый — цепочка
// идёт дальше, а не начинается заново: у хранилища новая цепочка — поломка
// «receipts after seq N may be lost» на каждой ротации.
func TestAppendAfterRotation(t *testing.T) {
	key := receiptKey(t, 51)
	pub := key.Public().(ed25519.PublicKey)
	path := filepath.Join(t.TempDir(), "receipts.jsonl")
	mustAppend(t, path, key, "a-1")
	last := mustAppend(t, path, key, "a-2")
	if err := os.Rename(path, path+".1"); err != nil {
		t.Fatal(err)
	}
	a := mustAppend(t, path, key, "a-3")
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

// Строки от имени шлюза с чужой подписью в конце файла: Append проверял
// подпись каждой при каждом вызове — под flock, так что ждали и остальные
// писатели (R1-3в). Теперь их читает один Append, следующий идёт от метки
// за ними.
func TestAppendReadsAForgedTailOnce(t *testing.T) {
	key := receiptKey(t, 47)
	path := filepath.Join(t.TempDir(), "receipts.jsonl")
	mustAppend(t, path, key, "a-1")
	forger, _ := NewSigner(receiptKey(t, 48), "esmcp", nil)
	var junk bytes.Buffer
	for range 2000 {
		junk.Write(mustSign(t, forger, Draft{Time: at, Action: "x", Step: "s"}))
		junk.WriteByte('\n')
	}
	appendRaw(t, path, junk.Bytes())
	if a := mustAppend(t, path, key, "a-2"); a.Receipt.Seq != 2 || a.Skipped != 2000 || a.Claimed != 2000 {
		t.Fatalf("past the forged tail: seq %d, skipped %d, claimed %d", a.Receipt.Seq, a.Skipped, a.Claimed)
	}
	start := time.Now()
	if a := mustAppend(t, path, key, "a-3"); a.Receipt.Seq != 3 || a.Skipped != 0 {
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
