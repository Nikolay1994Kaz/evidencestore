package keyring

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"fmt"
)

// envelopeOverhead — служебные байты конверта: 3+16+32+12+48+12+16.
const envelopeOverhead = len(envelopeTag) + kekIDSize + commitSize + 12 + dekSize + 16 + 12 + 16

// commitDomain — домен обязательства на ключ записи.
const commitDomain = "evidencestore/dek-commit/v1"

// Seal запечатывает открытый текст под ключом скоупа. Конверт:
//
//	"EV2" | kekID(16) | commit(32) | wrapNonce(12) | wrappedDEK(48) | dataNonce(12) | ct+tag
//
// У каждой записи свой DEK; он обёрнут ключом скоупа и едет в конверте.
// kekID лежит открытым: по нему Unseal находит ключ, а после уничтожения
// отличает «стёрто» от «повреждено». Он же входит в AAD обоих слоёв.
//
// commit = SHA-256(домен ‖ kekID ‖ DEK) — обязательство на ключ записи. Оно
// внутри конверта, то есть под отпечатком улики. AES-GCM не связывает
// шифротекст с ключом: без обязательства тот, кто готовит шифротекст,
// подобрал бы два ключа записи с разными телами под одним отпечатком и
// показал бы разным проверяющим разное. Ключ записи открывает тело, только
// если сходится с обязательством (OpenWithDEK).
//
// Ключ, ещё не дошедший до резерва, Seal не выдаёт (ErrNotBackedUp): звать
// после EnsureScope этого скоупа, он дожидается копии.
func (k *Keyring) Seal(scope string, plaintext []byte) ([]byte, error) {
	// Замок держится всю операцию: иначе Destroy или Close обнулят ключ
	// посреди шифрования.
	k.mu.RLock()
	defer k.mu.RUnlock()
	if k.closed {
		return nil, ErrClosed
	}
	e, ok := k.byName[scope]
	switch {
	case !ok:
		return nil, fmt.Errorf("%w: %q", ErrUnknownScope, scope)
	case e.state == Destroyed:
		return nil, fmt.Errorf("%w: %q", ErrScopeDestroyed, scope)
	case e.state != Active:
		return nil, fmt.Errorf("%w: %q is %v", ErrScopeClosed, scope, e.state)
	case e.gen > k.safe:
		return nil, fmt.Errorf("%w: %q", ErrNotBackedUp, scope)
	}
	dek := make([]byte, dekSize)
	defer zeroize(dek)
	rand.Read(dek)
	dataAEAD, err := newAEAD(dek)
	if err != nil {
		return nil, err
	}
	out := make([]byte, 0, envelopeOverhead+len(plaintext))
	out = append(out, envelopeTag...)
	out = append(out, e.id[:]...)
	commit := dekCommit(e.id, dek)
	out = append(out, commit[:]...)
	out = appendSealed(out, e.aead, dek, e.id[:])
	return appendSealed(out, dataAEAD, plaintext, e.id[:]), nil
}

func dekCommit(id [kekIDSize]byte, dek []byte) [commitSize]byte {
	h := sha256.New()
	h.Write([]byte(commitDomain))
	h.Write(id[:])
	h.Write(dek)
	var out [commitSize]byte
	h.Sum(out[:0])
	return out
}

// LegacyEnvelope — конверт прежнего формата (EV1): ключ записи в нём не
// связан с отпечатком улики.
func LegacyEnvelope(envelope []byte) bool {
	return len(envelope) >= len(legacyTag) && string(envelope[:len(legacyTag)]) == legacyTag
}

// wrappedAt — где в конверте начинается обёрнутый DEK.
func wrappedAt(envelope []byte) int {
	if LegacyEnvelope(envelope) {
		return len(legacyTag) + kekIDSize
	}
	return len(envelopeTag) + kekIDSize + commitSize
}

// Unseal вскрывает конверт. Исходы:
//
//	ErrKeyDestroyed — ключ уничтожен штатно: запись пропустить;
//	ErrKeyPending   — ключ ждёт уничтожения: не читать, но и не считать стёртым;
//	ErrUnknownKey   — такого ключа здесь не было: чужой конверт или не тот файл;
//	ErrMalformed    — конверт повреждён;
//	ErrClosed       — кейринг закрыт.
func (k *Keyring) Unseal(envelope []byte) ([]byte, error) {
	dek, err := k.UnwrapDEK(envelope)
	if err != nil {
		return nil, err
	}
	defer zeroize(dek)
	return OpenWithDEK(envelope, dek)
}

// UnwrapDEK достаёт из конверта ключ одной записи. Его можно выдать
// проверяющему: он вскроет ровно эту запись (OpenWithDEK) и не получит
// ключа месяца. Исходы — как у Unseal. Ключ записи вызывающий обнуляет сам.
func (k *Keyring) UnwrapDEK(envelope []byte) ([]byte, error) {
	id, ok := KEKIDOf(envelope)
	if !ok {
		return nil, ErrMalformed
	}
	k.mu.RLock()
	defer k.mu.RUnlock()
	if k.closed {
		return nil, ErrClosed
	}
	e, ok := k.byID[id]
	switch {
	case !ok:
		return nil, ErrUnknownKey
	case e.state == Destroyed:
		return nil, ErrKeyDestroyed
	case e.state == Pending:
		return nil, ErrKeyPending
	}
	at := wrappedAt(envelope)
	if len(envelope) < at {
		return nil, ErrMalformed
	}
	dek, _, err := openNext(e.aead, envelope[at:], dekSize+e.aead.Overhead(), id[:])
	if err != nil {
		return nil, ErrMalformed
	}
	return dek, nil
}

// OpenWithDEK вскрывает тело конверта ключом записи, без кейринга: так
// проверяющий читает выданную ему улику офлайн. Ключ записи сверяется с
// обязательством в конверте (EV2), тег GCM проверяет, что тело не менялось.
func OpenWithDEK(envelope, dek []byte) ([]byte, error) {
	id, ok := KEKIDOf(envelope)
	if !ok || len(dek) != dekSize {
		return nil, ErrMalformed
	}
	if !LegacyEnvelope(envelope) {
		want := envelope[len(envelopeTag)+kekIDSize:]
		got := dekCommit(id, dek)
		if len(want) < commitSize || subtle.ConstantTimeCompare(want[:commitSize], got[:]) != 1 {
			return nil, fmt.Errorf("%w: record key does not match the commitment in the envelope", ErrMalformed)
		}
	}
	dataAEAD, err := newAEAD(dek)
	if err != nil {
		return nil, ErrMalformed
	}
	// Обёрнутый DEK пропускаем: nonce(12) | wrappedDEK(48).
	p := envelope[wrappedAt(envelope):]
	wrapped := dataAEAD.NonceSize() + dekSize + dataAEAD.Overhead()
	if len(p) < wrapped {
		return nil, ErrMalformed
	}
	p = p[wrapped:]
	out, _, err := openNext(dataAEAD, p, len(p)-dataAEAD.NonceSize(), id[:])
	if err != nil {
		return nil, ErrMalformed
	}
	return out, nil
}

// KEKIDOf достаёт ID ключа из конверта, не вскрывая его: для квитанций,
// в том числе после уничтожения ключа.
func KEKIDOf(envelope []byte) ([kekIDSize]byte, bool) {
	var id [kekIDSize]byte
	if len(envelope) < len(envelopeTag)+kekIDSize {
		return id, false
	}
	if tag := string(envelope[:len(envelopeTag)]); tag != envelopeTag && tag != legacyTag {
		return id, false
	}
	copy(id[:], envelope[len(envelopeTag):])
	return id, true
}

func newAEAD(key []byte) (cipher.AEAD, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(block)
}

// appendSealed дописывает к dst: nonce | шифротекст с тегом.
func appendSealed(dst []byte, aead cipher.AEAD, plaintext, aad []byte) []byte {
	nonce := make([]byte, aead.NonceSize())
	rand.Read(nonce)
	dst = append(dst, nonce...)
	return aead.Seal(dst, nonce, plaintext, aad)
}

// openNext снимает с начала p кусок nonce | шифротекст длиной ctLen,
// вскрывает его и отдаёт остаток.
func openNext(aead cipher.AEAD, p []byte, ctLen int, aad []byte) (plain, rest []byte, err error) {
	ns := aead.NonceSize()
	if ctLen < aead.Overhead() || len(p) < ns+ctLen {
		return nil, nil, ErrMalformed
	}
	plain, err = aead.Open(nil, p[:ns], p[ns:ns+ctLen], aad)
	return plain, p[ns+ctLen:], err
}

func zeroize(b []byte) {
	for i := range b {
		b[i] = 0
	}
}
