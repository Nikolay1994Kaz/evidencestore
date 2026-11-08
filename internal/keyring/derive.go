package keyring

import (
	"crypto/hkdf"
	"crypto/sha256"
	"fmt"
)

// DeriveKey — ключ для другой задачи, выведенный из ключа скоупа:
// HKDF-Expand (RFC 5869, SHA-256), ключ скоупа — псевдослучайный ключ, домен —
// info. Ключ скоупа служит и AES-GCM для ключей записей; HKDF отделяет
// выведенный ключ от этой роли по построению. Вывод односторонний: по
// выведенному ключу ключа скоупа не восстановить, тел он не открывает.
//
// Срок у него тот же, что у ключа скоупа, и хранить его не нужно: уничтожен
// ключ скоупа — ErrKeyDestroyed, и выведенный не повторит никто, ни хранилище,
// ни тот, у кого остались копии keyring.dat под старыми корнями (уничтожение —
// поворот корня, DECISIONS, п. 10). Ждёт уничтожения — ErrKeyPending: на время
// ожидания ключ не выдаёт ничего, как UnwrapDEK; но ключ лежит в файле и в
// резерве, и отмена уничтожения вернёт тот же выведенный ключ.
//
// Резерв здесь не проверяется: ключ, который не дошёл до резерва, не выдаёт
// Seal, а выведенное пишется только рядом с запечатанной им записью (метка
// ставится после Seal). Чтение — пакеты за прошлые месяцы — от резерва не
// зависит, как UnwrapDEK. Ключ вызывающий обнуляет сам.
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
	}
	k32, err := hkdf.Expand(sha256.New, e.key, domain, len(out))
	if err != nil {
		return out, err
	}
	copy(out[:], k32)
	clear(k32)
	return out, nil
}
