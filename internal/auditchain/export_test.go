package auditchain

import (
	"crypto/ed25519"
	"crypto/rand"
	"os"
	"path/filepath"
	"testing"
)

func newSigner(t *testing.T) (*Signer, string) {
	t.Helper()
	dir := t.TempDir()
	s, err := LoadOrCreateSigner(dir)
	if err != nil {
		t.Fatalf("LoadOrCreateSigner: %v", err)
	}
	return s, dir
}

func TestSigner_KeyIsStableAcrossRestarts(t *testing.T) {
	s, dir := newSigner(t)
	again, err := LoadOrCreateSigner(dir)
	if err != nil {
		t.Fatal(err)
	}
	if s.PublicKeyString() != again.PublicKeyString() {
		t.Fatal("после перезапуска ключ другой — все прежде выданные заявления перестали бы сходиться")
	}

	// Приватный ключ не должен быть читаем никому, кроме владельца процесса.
	st, err := os.Stat(filepath.Join(dir, SignKeyFileName))
	if err != nil {
		t.Fatal(err)
	}
	if perm := st.Mode().Perm(); perm != 0o600 {
		t.Errorf("права на ключ подписи %o, ожидалось 600", perm)
	}
}

func TestStatement_VerifiesAndDetectsEdits(t *testing.T) {
	s, _ := newSigner(t)
	head := Head{Seq: 42, Hash: [32]byte{1, 2, 3}}
	st := s.Sign(head, 42, 1_753_700_000)

	if err := VerifyStatement(st, s.PublicKey()); err != nil {
		t.Fatalf("своё заявление отвергнуто: %v", err)
	}

	// Каждое подписанное поле обязано быть подписанным на самом деле.
	for _, mut := range []struct {
		name  string
		apply func(*Statement)
	}{
		{"head_seq", func(x *Statement) { x.HeadSeq++ }},
		{"head_hash", func(x *Statement) { x.HeadHash = "AAAA" }},
		{"links", func(x *Statement) { x.Links = 1 }},
		{"signed_at", func(x *Statement) { x.SignedAt++ }},
		{"version", func(x *Statement) { x.Version = 99 }},
	} {
		edited := st
		mut.apply(&edited)
		if err := VerifyStatement(edited, s.PublicKey()); err == nil {
			t.Errorf("правка поля %s не обнаружена — поле подписью не покрыто", mut.name)
		}
	}
}

// ⭐TestStatement_ForeignInstanceIsRejected — то, ради чего подпись
// асимметричная. Аудитор, однажды закрепивший публичный ключ, обязан заметить
// подмену сервера или «нового чистого» журнала.
func TestStatement_ForeignInstanceIsRejected(t *testing.T) {
	mine, _ := newSigner(t)
	theirs, _ := newSigner(t)

	head := Head{Seq: 7, Hash: [32]byte{9}}
	forged := theirs.Sign(head, 7, 1_753_700_000)

	// ПАРНЫЙ КОНТРОЛЬ: чужое заявление внутренне безупречно и без
	// закреплённого ключа проходит проверку. Именно поэтому nil — не
	// доказательство происхождения, и это записано в доке функции.
	if err := VerifyStatement(forged, nil); err != nil {
		t.Fatalf("внутренне корректное заявление отвергнуто без закреплённого ключа: %v", err)
	}
	if err := VerifyStatement(forged, mine.PublicKey()); err == nil {
		t.Fatal("заявление чужого инстанса принято при закреплённом ключе")
	}
}

func TestStatement_RoundTripsThroughJSON(t *testing.T) {
	s, _ := newSigner(t)
	st := s.Sign(Head{Seq: 5, Hash: [32]byte{7}}, 5, 1_753_700_000)
	b, err := st.JSON()
	if err != nil {
		t.Fatal(err)
	}
	got, err := ParseStatement(b)
	if err != nil {
		t.Fatal(err)
	}
	if err := VerifyStatement(got, s.PublicKey()); err != nil {
		t.Fatalf("заявление не пережило JSON: %v", err)
	}
}

func TestSigner_RejectsCorruptKeyFile(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, SignKeyFileName), []byte("не ключ"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadOrCreateSigner(dir); err == nil {
		t.Fatal("битый файл ключа принят — инстанс молча сменил бы личность")
	}
}

func TestVerifyStatement_RejectsRandomKeyOfRightSize(t *testing.T) {
	s, _ := newSigner(t)
	st := s.Sign(Head{Seq: 1}, 1, 1)
	other := make([]byte, ed25519.PublicKeySize)
	rand.Read(other)
	if err := VerifyStatement(st, ed25519.PublicKey(other)); err == nil {
		t.Fatal("заявление прошло проверку случайным ключом")
	}
}
