package keyring

import (
	"crypto/hkdf"
	"crypto/sha256"
	"fmt"
)

// DeriveKey — ключ для другой задачи, выведенный из ключа скоупа:
// HKDF-Expand (RFC 5869, SHA-256), ключ скоупа — псевдослучайный ключ, домен —
// info. Ключ скоупа служит и AES-GCM для ключей записей; HKDF отделяет
// выведенный ключ от этой роли по построению. Живёт ровно столько, сколько ключ
// скоупа: после уничтожения его не выведет никто — ни хранилище, ни тот, у кого
// остались копии keyring.dat под старыми корнями (уничтожение — поворот корня,
// DECISIONS, п. 10). Так стирание месяца стирает и всё, что из его ключа
// выведено (метки субъектов, п. 32).
//
// Исходы — как у UnwrapDEK: уничтожен — ErrKeyDestroyed, ждёт уничтожения —
// ErrKeyPending (на время ожидания ключ не выдаёт ничего), ещё не в резерве —
// ErrNotBackedUp: выведенное из ключа, которого нет в резерве, после потери
// диска не повторить. Ключ вызывающий обнуляет сам.
func (k *Keyring) DeriveKey(scope, domain string) ([32]byte, error) {
	var out [32]byte
	k.mu.RLock()
	defer k.mu.RUnlock()
	if k.closed {
		return out, ErrClosed
	}
	e, ok := k.byName[scope]
	switch {
	case !ok:
		return out, fmt.Errorf("%w: %q", ErrUnknownScope, scope)
	case e.state == Destroyed:
		return out, ErrKeyDestroyed
	case e.state == Pending:
		return out, ErrKeyPending
	case e.gen > k.safe:
		return out, fmt.Errorf("%w: %q", ErrNotBackedUp, scope)
	}
	k32, err := hkdf.Expand(sha256.New, e.key, domain, len(out))
	if err != nil {
		return out, err
	}
	copy(out[:], k32)
	clear(k32)
	return out, nil
}
