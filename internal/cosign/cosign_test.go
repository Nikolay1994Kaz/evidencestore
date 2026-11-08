package cosign

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/binary"
	"strings"
	"testing"
)

// Пример из c2sp.org/signed-note: ключ проверки и заметка, которую он
// проверяет. Сходятся номер ключа (SHA-256 от имени, перевода строки, типа и
// ключа) и подпись над текстом — значит, формат строки подписи тот же, что у
// всех реализаций C2SP.
func TestSignedNoteVector(t *testing.T) {
	const vkey = "example.com/foo+530d903a+AekyeRrm56hApGFkyQR4ZCbV54Id2LKaANYcrnKv3U2k"
	const note = "This is an example message.\n\n— example.com/foo Uw2QOkn8srV1yJGh2VYRlL1Tnagv1YEq6TfXppzi2ONncAlTgK7Ztg1ERYNZXsYjOBH3mFXmRKuwHjG1Yu72IneyaQM=\n"
	parts := strings.SplitN(vkey, "+", 3)
	raw, err := base64.StdEncoding.DecodeString(parts[2])
	if err != nil || raw[0] != TypeEd25519 {
		t.Fatalf("ключ примера: %v", err)
	}
	pub := ed25519.PublicKey(raw[1:])
	if got := KeyID(parts[0], TypeEd25519, pub); got != 0x530d903a {
		t.Fatalf("номер ключа %08x, в примере 530d903a", got)
	}
	text, sigs, err := SplitNote([]byte(note))
	if err != nil || string(text) != "This is an example message.\n" || len(sigs) != 1 {
		t.Fatalf("заметка разобрана как %q, %q, %v", text, sigs, err)
	}
	if err := VerifyLogSignature(text, sigs, parts[0], pub); err != nil {
		t.Fatalf("подпись примера: %v", err)
	}
	tampered := []byte(strings.Replace(note, "example message", "example massage", 1))
	text, sigs, _ = SplitNote(tampered)
	if VerifyLogSignature(text, sigs, parts[0], pub) == nil {
		t.Fatal("подпись сошлась с изменённым текстом")
	}
}

// Вход подписи cosignature/v1 — ровно пример из c2sp.org/tlog-cosignature.
func TestMessageMatchesSpec(t *testing.T) {
	root, _ := base64.StdEncoding.DecodeString("CsUYapGGPo4dkMgIAUqom/Xajj7h2fB2MPA3j2jxq2I=")
	text := CheckpointText("example.com/behind-the-sofa", 20852163, [32]byte(root))
	want := "cosignature/v1\ntime 1679315147\nexample.com/behind-the-sofa\n20852163\nCsUYapGGPo4dkMgIAUqom/Xajj7h2fB2MPA3j2jxq2I=\n"
	if got := string(Message(1679315147, text)); got != want {
		t.Fatalf("вход подписи:\n%q\nждали\n%q", got, want)
	}
	origin, size, r, err := ParseCheckpointText(text)
	if err != nil || origin != "example.com/behind-the-sofa" || size != 20852163 || r != [32]byte(root) {
		t.Fatalf("точка разобрана как %q %d %x: %v", origin, size, r, err)
	}
}

func newSigner(t *testing.T, name string) Signer {
	t.Helper()
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	s, err := NewSigner(name, priv)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func TestCosignRoundTrip(t *testing.T) {
	s := newSigner(t, "witness.example/w1")
	v, err := ParseVerifier(s.Verifier().String())
	if err != nil {
		t.Fatalf("ключ проверки не разобрался: %v", err)
	}
	text := CheckpointText("evidencestore/0011223344556677", 42, [32]byte{7})
	blob := s.Cosign(text, 1700000000)
	if len(blob) != BlobSize || binary.BigEndian.Uint32(blob) != s.ID {
		t.Fatalf("подпись %d байт, номер %08x", len(blob), binary.BigEndian.Uint32(blob))
	}
	ts, err := v.Verify(text, blob)
	if err != nil || ts != 1700000000 {
		t.Fatalf("подпись не сошлась: %d %v", ts, err)
	}
	line := SigLine(s.Name, blob)
	name, back, err := ParseSigLine(strings.TrimSuffix(line, "\n"))
	if err != nil || name != s.Name || !bytes.Equal(back, blob) {
		t.Fatalf("строка подписи: %q %v", name, err)
	}

	// Любой бит подписи, времени, номера и текста — отказ; чужой номер —
	// ErrOtherKey: подпись другого ключа пропускают, а не проверяют.
	for i := 4; i < len(blob); i++ {
		bad := bytes.Clone(blob)
		bad[i] ^= 1
		if _, err := v.Verify(text, bad); err == nil {
			t.Fatalf("байт %d подписи изменён, а она сошлась", i)
		}
	}
	other := bytes.Clone(blob)
	other[0] ^= 1
	if _, err := v.Verify(text, other); err != ErrOtherKey {
		t.Fatalf("чужой номер ключа: %v", err)
	}
	if _, err := v.Verify(CheckpointText("evidencestore/0011223344556677", 43, [32]byte{7}), blob); err == nil {
		t.Fatal("подпись над размером 42 сошлась с размером 43")
	}
	if _, err := v.Verify(text, blob[:len(blob)-1]); err == nil {
		t.Fatal("короткая подпись сошлась")
	}
	zero := s.Cosign(text, 0)
	if _, err := v.Verify(text, zero); err == nil {
		t.Fatal("подпись без времени принята")
	}
	// Ключ того же имени с другим ключом — другой номер, подпись не его.
	twin := newSigner(t, s.Name)
	if _, err := twin.Verifier().Verify(text, blob); err != ErrOtherKey {
		t.Fatalf("ключ-тёзка: %v", err)
	}
}

func TestParseVerifierStrict(t *testing.T) {
	s := newSigner(t, "witness.example/w1")
	good := s.Verifier().String()
	parts := strings.SplitN(good, "+", 3)
	raw, _ := base64.StdEncoding.DecodeString(parts[2])
	ed := append([]byte{TypeEd25519}, raw[1:]...)
	edID := KeyID(parts[0], TypeEd25519, raw[1:])
	cases := map[string]string{
		"две части":            parts[0] + "+" + parts[1],
		"имя с пробелом":       "witness example+" + parts[1] + "+" + parts[2],
		"номер не hex":         parts[0] + "+zz0d903a+" + parts[2],
		"номер прописными":     parts[0] + "+" + strings.ToUpper(parts[1]) + "+" + parts[2],
		"номер не сходится":    parts[0] + "+00000000+" + parts[2],
		"тип 0x01":             parts[0] + "+" + hex8(edID) + "+" + base64.StdEncoding.EncodeToString(ed),
		"короткий ключ":        parts[0] + "+" + parts[1] + "+" + base64.StdEncoding.EncodeToString(raw[:20]),
		"base64 с лишним =":    parts[0] + "+" + parts[1] + "+" + parts[2] + "==",
		"base64 URL-алфавитом": parts[0] + "+" + parts[1] + "+" + strings.NewReplacer("+", "-", "/", "_").Replace(parts[2]) + "-",
	}
	if strings.ToUpper(parts[1]) == parts[1] {
		delete(cases, "номер прописными")
	}
	for name, vkey := range cases {
		if _, err := ParseVerifier(vkey); err == nil {
			t.Errorf("%s: ключ %q принят", name, vkey)
		}
	}
	if _, err := ParseVerifier(good); err != nil {
		t.Fatalf("верный ключ: %v", err)
	}
}

func hex8(id uint32) string {
	const digits = "0123456789abcdef"
	var b [8]byte
	for i := 7; i >= 0; i-- {
		b[i] = digits[id&0xf]
		id >>= 4
	}
	return string(b[:])
}

func TestParseCheckpointTextStrict(t *testing.T) {
	root := base64.StdEncoding.EncodeToString(make([]byte, 32))
	bad := map[string]string{
		"без перевода строки": "o\n1\n" + root,
		"расширение":          "o\n1\n" + root + "\next\n",
		"ведущий ноль":        "o\n01\n" + root + "\n",
		"знак":                "o\n+1\n" + root + "\n",
		"больше 2^63-1":       "o\n9223372036854775808\n" + root + "\n",
		"корень 31 байт":      "o\n1\n" + base64.StdEncoding.EncodeToString(make([]byte, 31)) + "\n",
		"корень без =":        "o\n1\n" + strings.TrimRight(root, "=") + "\n",
		"имя с пробелом":      "o o\n1\n" + root + "\n",
		"пустое имя":          "\n1\n" + root + "\n",
	}
	for name, text := range bad {
		if _, _, _, err := ParseCheckpointText([]byte(text)); err == nil {
			t.Errorf("%s: %q принят", name, text)
		}
	}
	if _, size, _, err := ParseCheckpointText([]byte("o\n0\n" + root + "\n")); err != nil || size != 0 {
		t.Fatalf("размер 0: %d %v", size, err)
	}
}

// Неканонический base64 (ненулевые лишние биты) у одной подписи давал бы
// много написаний; C2SP велит их отвергать.
func TestNonCanonicalBase64(t *testing.T) {
	enc := base64.StdEncoding.EncodeToString(make([]byte, 32)) // ...A=
	noncanon := enc[:len(enc)-2] + "B="
	if _, err := decode64(noncanon); err == nil {
		t.Fatalf("неканонический %q принят", noncanon)
	}
	if _, err := decode64(enc); err != nil {
		t.Fatal(err)
	}
}

func TestSplitNote(t *testing.T) {
	bad := map[string]string{
		"без подписей":        "a\nb\n",
		"пустой хвост":        "a\nb\n\n",
		"без перевода строки": "a\n\n— k AAAA",
		"управляющий символ":  "a\tb\n\n— k AAAA\n",
		"пустая строка":       "a\n\n— k AAAA\n\n\n",
		"не UTF-8":            "a\xff\n\n— k AAAA\n",
	}
	for name, note := range bad {
		if _, _, err := SplitNote([]byte(note)); err == nil {
			t.Errorf("%s: %q принята", name, note)
		}
	}
	text, sigs, err := SplitNote([]byte("a\n\nb\n\n— k AAAA\n— j BBBB\n"))
	if err != nil || string(text) != "a\n\nb\n" || len(sigs) != 2 {
		t.Fatalf("заметка с пустой строкой в тексте: %q %q %v", text, sigs, err)
	}
	var many strings.Builder
	many.WriteString("a\n\n")
	for range MaxSigLines + 1 {
		many.WriteString("— k AAAA\n")
	}
	if _, _, err := SplitNote([]byte(many.String())); err == nil {
		t.Fatal("заметка с лишними подписями принята")
	}
}

func TestAddCheckpointBody(t *testing.T) {
	proof := [][32]byte{{1}, {2}, {3}}
	note := []byte("o\n5\n" + base64.StdEncoding.EncodeToString(make([]byte, 32)) + "\n\n— o AAAA\n")
	body := AddCheckpoint(4, proof, note)
	old, p, n, err := ParseAddCheckpoint(body)
	if err != nil || old != 4 || len(p) != 3 || p[2] != proof[2] || !bytes.Equal(n, note) {
		t.Fatalf("тело запроса: %d %v %q %v", old, p, n, err)
	}
	if _, p, _, err := ParseAddCheckpoint(AddCheckpoint(0, nil, note)); err != nil || len(p) != 0 {
		t.Fatalf("без доказательства: %v", err)
	}
	bad := map[string][]byte{
		"без строки old":     []byte("5\n\n" + string(note)),
		"old с нулём":        []byte("old 04\n\n" + string(note)),
		"без пустой":         []byte("old 4\n"),
		"хеш 31 байт":        []byte("old 4\n" + base64.StdEncoding.EncodeToString(make([]byte, 31)) + "\n\n" + string(note)),
		"хеш без дополнения": []byte("old 4\n" + strings.TrimRight(base64.StdEncoding.EncodeToString(make([]byte, 32)), "=") + "\n\n" + string(note)),
	}
	var long [][32]byte
	for range MaxProofLines + 1 {
		long = append(long, [32]byte{9})
	}
	bad["64 строки"] = AddCheckpoint(4, long, note)
	for name, b := range bad {
		if _, _, _, err := ParseAddCheckpoint(b); err == nil {
			t.Errorf("%s: принято", name)
		}
	}
	if _, p, _, err := ParseAddCheckpoint(AddCheckpoint(4, long[:MaxProofLines], note)); err != nil || len(p) != MaxProofLines {
		t.Fatalf("63 строки: %v", err)
	}
}

func TestValidName(t *testing.T) {
	for _, n := range []string{"witness.example/w1", "evidencestore/0011223344556677", "oid/1.2.3", strings.Repeat("a", MaxNameLen)} {
		if !ValidName(n) {
			t.Errorf("%q отвергнуто", n)
		}
	}
	for _, n := range []string{"", "a b", "a+b", "a\x01", "a b", "\xff", strings.Repeat("a", MaxNameLen+1)} {
		if ValidName(n) {
			t.Errorf("%q принято", n)
		}
	}
}
