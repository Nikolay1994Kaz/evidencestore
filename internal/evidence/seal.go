package evidence

import (
	"fmt"
	"time"
)

// MaxBodyLen — предел тела до шифрования. Меньше MaxEnvelopeLen на запас
// под служебные поля конверта (у keyring их 107 байт).
const MaxBodyLen = MaxEnvelopeLen - 1024

// Sealer — то, чем запечатывается тело. Сейчас это keyring.Keyring.
// Интерфейс здесь намеренно: на его место встанет сертифицированное СКЗИ,
// и остальной код этого не заметит.
type Sealer interface {
	EnsureScope(scope string) ([16]byte, error)
	Seal(scope string, plaintext []byte) ([]byte, error)
}

// Unsealer — то, чем тело открывается обратно.
type Unsealer interface {
	Unseal(envelope []byte) ([]byte, error)
}

// Record — улика как пришла от источника, с открытым телом.
// В таком виде она не попадает на диск никогда.
type Record struct {
	Header
	Body []byte
}

// Scope — имя ключа, под которым шифруется тело: источник и месяц приёма
// по UTC, например "abs-core/2026-09". Это единица стирания: уничтожить ключ
// скоупа — значит стереть тела всех записей источника за месяц, не трогая
// ни байты на диске, ни цепь.
//
// Месяц берётся из ReceivedAt, то есть по нашим часам, а не по часам
// источника. Поэтому новые записи всегда попадают в текущий месяц, и
// стёртый прошлый месяц новых записей не получит.
func (h Header) Scope() string {
	t := time.Unix(0, h.ReceivedAt).UTC()
	return fmt.Sprintf("%s/%04d-%02d", h.Source, t.Year(), int(t.Month()))
}

// Seal шифрует тело под ключом скоупа и возвращает улику для хранения.
// Ключ скоупа создаётся при первой записи месяца.
func (r Record) Seal(k Sealer) (Sealed, error) {
	// Проверки до EnsureScope: негодная запись не должна заводить ключей.
	if err := r.Header.Validate(); err != nil {
		return Sealed{}, err
	}
	if len(r.Body) > MaxBodyLen {
		return Sealed{}, fmt.Errorf("evidence: body longer than %d bytes", MaxBodyLen)
	}
	scope := r.Scope()
	if _, err := k.EnsureScope(scope); err != nil {
		return Sealed{}, fmt.Errorf("evidence: key for %q: %w", scope, err)
	}
	env, err := k.Seal(scope, r.Body)
	if err != nil {
		return Sealed{}, fmt.Errorf("evidence: seal %q: %w", scope, err)
	}
	s := Sealed{Header: r.Header, Envelope: env}
	if err := s.Validate(); err != nil {
		return Sealed{}, err
	}
	return s, nil
}

// Open расшифровывает тело. Если ключ скоупа уничтожен, вернёт
// keyring.ErrKeyDestroyed: это штатный исход стирания, а не поломка.
//
// Open не проверяет, что улику не подменили. Это делает цепь по отпечатку.
func (s Sealed) Open(k Unsealer) ([]byte, error) {
	return k.Unseal(s.Envelope)
}
