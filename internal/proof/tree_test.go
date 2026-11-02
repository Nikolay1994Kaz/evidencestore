package proof

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"strings"
	"testing"

	"golang.org/x/mod/sumdb/note"
	"golang.org/x/mod/sumdb/tlog"

	"github.com/Nikolay1994Kaz/evidencestore/internal/auditchain"
)

// memHashes — хранимые хеши дерева в памяти: эталон из tlog.
type memHashes []tlog.Hash

func (m memHashes) ReadHashes(indexes []int64) ([]tlog.Hash, error) {
	out := make([]tlog.Hash, len(indexes))
	for i, idx := range indexes {
		out[i] = m[idx]
	}
	return out, nil
}

func linkHashN(i int) [32]byte {
	var b [8]byte
	binary.BigEndian.PutUint64(b[:], uint64(i))
	return sha256.Sum256(b[:])
}

// Граница дерева сходится с tlog на каждом размере: корень по границе,
// хеши, которые дописывает запись, граница из хранимых хешей и корни после
// продолжения с любого места.
func TestFrontierMatchesTlog(t *testing.T) {
	const n = 300
	var stored memHashes
	var f Frontier
	for i := range n {
		leaf := LinkLeaf(linkHashN(i))
		hs, err := tlog.StoredHashesForRecordHash(int64(i), leaf, stored)
		if err != nil {
			t.Fatal(err)
		}
		pushed := f.Push(leaf)
		if len(pushed) != len(hs) {
			t.Fatalf("запись %d: дописано %d хешей, у tlog %d", i, len(pushed), len(hs))
		}
		for j := range hs {
			if pushed[j] != [32]byte(hs[j]) {
				t.Fatalf("запись %d: хеш %d не совпал с tlog", i, j)
			}
		}
		stored = append(stored, hs...)
		want, err := tlog.TreeHash(int64(i+1), stored)
		if err != nil {
			t.Fatal(err)
		}
		if f.Root() != [32]byte(want) {
			t.Fatalf("размер %d: корень по границе не совпал с tlog", i+1)
		}
	}
	for m := range n {
		hs, _ := stored.ReadHashes(FrontierIndexes(uint64(m)))
		nodes := make([][32]byte, len(hs))
		for i, h := range hs {
			nodes[i] = h
		}
		front, err := NewFrontier(uint64(m), nodes)
		if err != nil {
			t.Fatal(err)
		}
		hashes := make([][32]byte, 0, n-m)
		for i := m; i < n; i++ {
			hashes = append(hashes, linkHashN(i))
		}
		rootAt, err := linkRoots(front.Bytes(), uint64(m+1), hashes)
		if err != nil {
			t.Fatal(err)
		}
		for size := m + 1; size <= n; size++ {
			want, _ := tlog.TreeHash(int64(size), stored)
			if got, ok := rootAt(uint64(size)); !ok || got != [32]byte(want) {
				t.Fatalf("граница %d, размер %d: корень не совпал с tlog", m, size)
			}
		}
		if _, ok := rootAt(uint64(n + 1)); ok {
			t.Fatal("корень после последнего звена пакета")
		}
		if _, ok := rootAt(uint64(m)); ok {
			t.Fatal("корень до первого звена пакета")
		}
	}
	if _, err := NewFrontier(5, make([][32]byte, 1)); err == nil {
		t.Fatal("граница размера 5 из одного хеша")
	}
}

// Звенья, пронумерованные с нуля или с переполнением номера, не дают
// корней (иначе граница размера 2⁶⁴−1 крутила бы проверку без конца).
func TestLinkRootsRejectWrap(t *testing.T) {
	if _, err := linkRoots(nil, 0, make([][32]byte, 1)); err == nil {
		t.Fatal("звенья с нулевого номера")
	}
	// Граница размера 2⁶⁴−2 — 63 хеша; два звена после неё переполняют номер.
	full := make([][]byte, 63)
	for i := range full {
		full[i] = make([]byte, 32)
	}
	if _, err := linkRoots(full, 1<<64-1, make([][32]byte, 2)); err == nil {
		t.Fatal("номера звеньев переполняются")
	}
}

// Контрольная точка подписана ключом хранилища и проверяется закреплённым
// ключом, а её подпись открывается как заметка C2SP проверкой из
// golang.org/x/mod/sumdb/note — такую голову поймёт свидетель C2SP. Заметка:
// тело, пустая строка, строка «— <имя ключа> base64(хеш ключа ‖ подпись)»,
// хеш ключа — первые 4 байта SHA-256(имя ‖ "\n" ‖ 0x01 ‖ ключ).
func TestCheckpointIsC2SPNote(t *testing.T) {
	signer, err := auditchain.LoadOrCreateSigner(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	pub := signer.PublicKey()
	root := [32]byte{1, 2, 3}
	c := SignCheckpoint(signer, 42, root)
	if err := VerifyCheckpoint(c, pub); err != nil {
		t.Fatal(err)
	}
	data, _ := c.JSON()
	back, err := ParseCheckpoint(data)
	if err != nil || VerifyCheckpoint(back, pub) != nil || string(back.body()) != string(c.body()) {
		t.Fatalf("точка после JSON: %v", err)
	}
	if again := SignCheckpoint(signer, 42, root); string(again.Signature) != string(c.Signature) {
		t.Fatal("две точки одного размера одной цепи различаются")
	}

	kh := sha256.Sum256(append([]byte(c.Origin+"\n\x01"), pub...))
	msg := append(c.body(), "\n— "+c.Origin+" "+base64.StdEncoding.EncodeToString(append(kh[:4:4], c.Signature...))+"\n"...)
	vkey, err := note.NewEd25519VerifierKey(c.Origin, pub)
	if err != nil {
		t.Fatal(err)
	}
	v, err := note.NewVerifier(vkey)
	if err != nil {
		t.Fatal(err)
	}
	n, err := note.Open(msg, note.VerifierList(v))
	if err != nil {
		t.Fatalf("заметка C2SP не открылась: %v\n%s", err, msg)
	}
	if want := c.Origin + "\n42\n" + base64.StdEncoding.EncodeToString(root[:]) + "\n"; n.Text != want {
		t.Fatalf("текст заметки %q, ждали %q", n.Text, want)
	}

	// Подмена любого поля и чужой ключ — отказ.
	other, err := auditchain.LoadOrCreateSigner(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	for name, spoil := range map[string]func(*Checkpoint){
		"размер":        func(c *Checkpoint) { c.Size++ },
		"корень":        func(c *Checkpoint) { c.Root = append([]byte(nil), c.Root...); c.Root[0] ^= 1 },
		"происхождение": func(c *Checkpoint) { c.Origin = OriginFor(other.PublicKey()) },
		"пустая цепь":   func(c *Checkpoint) { c.Size = 0 },
		"корень короче": func(c *Checkpoint) { c.Root = c.Root[:31] },
	} {
		bad := c
		spoil(&bad)
		if VerifyCheckpoint(bad, pub) == nil {
			t.Fatalf("подменено %s — точка прошла", name)
		}
	}
	if VerifyCheckpoint(c, other.PublicKey()) == nil || VerifyCheckpoint(c, nil) == nil {
		t.Fatal("точка прошла чужим ключом или без ключа")
	}
	if VerifyCheckpoint(SignCheckpoint(other, 42, root), pub) == nil {
		t.Fatal("точка другого хранилища прошла")
	}
	// Тело начинается с буквы, прочие подписи хранилища — с длины домена.
	if !strings.HasPrefix(string(c.body()), "evidencestore/") {
		t.Fatalf("тело %q", c.body())
	}
	if HeadImprint(42, root) == HeadImprint(43, root) || HeadImprint(42, root) == HeadImprint(42, [32]byte{}) {
		t.Fatal("отпечаток головы не различает размер или корень")
	}
}
