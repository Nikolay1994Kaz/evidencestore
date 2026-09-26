// Package evidence — формат улики: какие поля хранятся и как они кодируются
// в байты.
//
// ЗАЧЕМ СВОЙ ФОРМАТ. От записи считается хэш, и он уходит в цепь. Значит, одна
// и та же запись обязана всегда давать одни и те же байты. JSON этого не
// гарантирует (порядок полей, пробелы, экранирование), protobuf тоже
// (детерминированность не входит в спецификацию). Здесь поля идут в
// фиксированном порядке, числа — big-endian, строки и байты — с префиксом
// длины, как в auditchain. Такой формат однозначен по построению.
//
// ЧТО ОТКРЫТО, ЧТО ЗАКРЫТО. Заголовок (кто прислал, какой номер, когда, что
// внутри) лежит открытым: по нему отсекают повторы, ищут и пишут отчёт. Тело
// лежит только конвертом keyring. Отпечаток считается от байт на диске, то
// есть от шифротекста: после уничтожения ключа тело не прочитать, а отпечаток
// по-прежнему сходится.
package evidence

import (
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"unicode/utf8"
)

// Version — версия формата. Меняется при любом изменении состава полей.
const Version byte = 1

// Пределы полей. Проверяются и при кодировании, и при разборе.
const (
	MaxSourceLen      = 255
	MaxContentTypeLen = 255
	MaxEnvelopeLen    = 1 << 20 // 1 МиБ: запись журнала, а не файл
)

// domainSealed отделяет отпечаток улики от других хэшей проекта:
// одни и те же байты в разных ролях дают разные хэши.
const domainSealed = "evidencestore/sealed/v1"

// ErrMalformed — байты не являются корректной уликой.
var ErrMalformed = errors.New("evidence: malformed record")

// Header — открытая часть улики.
type Header struct {
	Source      string // кто прислал: имя из клиентского сертификата
	Seq         uint64 // номер записи у источника; пара (Source, Seq) уникальна
	ReceivedAt  int64  // когда принята, UnixNano по часам хранилища
	ContentType string // что в теле: "syslog", "pipelock/receipt" и т. п.
}

// Validate проверяет, что заголовок можно хранить.
func (h Header) Validate() error {
	switch {
	case h.Source == "":
		return errors.New("evidence: empty source")
	case len(h.Source) > MaxSourceLen:
		return fmt.Errorf("evidence: source longer than %d bytes", MaxSourceLen)
	case !utf8.ValidString(h.Source):
		return errors.New("evidence: source is not valid UTF-8")
	case h.Seq == 0:
		return errors.New("evidence: seq must be > 0")
	case h.ReceivedAt <= 0:
		return errors.New("evidence: received_at must be > 0")
	case len(h.ContentType) > MaxContentTypeLen:
		return fmt.Errorf("evidence: content type longer than %d bytes", MaxContentTypeLen)
	}
	return nil
}

// Sealed — улика в том виде, в каком она лежит на диске.
type Sealed struct {
	Header
	Envelope []byte // тело, запечатанное keyring.Seal
}

// Validate проверяет заголовок и размер конверта.
func (s Sealed) Validate() error {
	if err := s.Header.Validate(); err != nil {
		return err
	}
	if len(s.Envelope) == 0 || len(s.Envelope) > MaxEnvelopeLen {
		return fmt.Errorf("evidence: envelope size %d out of range", len(s.Envelope))
	}
	return nil
}

// Marshal кодирует улику:
//
//	version(1) | seq(8) | received_at(8) | len(4)+source | len(4)+content_type | len(4)+envelope
func (s Sealed) Marshal() ([]byte, error) {
	if err := s.Validate(); err != nil {
		return nil, err
	}
	buf := make([]byte, 0, 1+8+8+3*4+len(s.Source)+len(s.ContentType)+len(s.Envelope))
	buf = append(buf, Version)
	buf = binary.BigEndian.AppendUint64(buf, s.Seq)
	buf = binary.BigEndian.AppendUint64(buf, uint64(s.ReceivedAt))
	buf = appendField(buf, []byte(s.Source))
	buf = appendField(buf, []byte(s.ContentType))
	buf = appendField(buf, s.Envelope)
	return buf, nil
}

// Unmarshal разбирает байты, записанные Marshal. Лишние байты в конце — ошибка:
// у записи должно быть ровно одно представление.
func Unmarshal(b []byte) (Sealed, error) {
	var s Sealed
	if len(b) < 1+8+8 {
		return Sealed{}, fmt.Errorf("%w: too short", ErrMalformed)
	}
	if b[0] != Version {
		return Sealed{}, fmt.Errorf("%w: unknown version %d", ErrMalformed, b[0])
	}
	s.Seq = binary.BigEndian.Uint64(b[1:9])
	s.ReceivedAt = int64(binary.BigEndian.Uint64(b[9:17]))

	rest := b[17:]
	var src, ctype, env []byte
	var err error
	if src, rest, err = readField(rest, MaxSourceLen); err != nil {
		return Sealed{}, err
	}
	if ctype, rest, err = readField(rest, MaxContentTypeLen); err != nil {
		return Sealed{}, err
	}
	if env, rest, err = readField(rest, MaxEnvelopeLen); err != nil {
		return Sealed{}, err
	}
	if len(rest) != 0 {
		return Sealed{}, fmt.Errorf("%w: %d trailing bytes", ErrMalformed, len(rest))
	}

	s.Source = string(src)
	s.ContentType = string(ctype)
	// Копия, а не подсрез: иначе чужая правка буфера b поменяла бы улику.
	s.Envelope = append([]byte(nil), env...)
	if err := s.Validate(); err != nil {
		return Sealed{}, fmt.Errorf("%w: %v", ErrMalformed, err)
	}
	return s, nil
}

// Digest — отпечаток закодированной улики. Он уходит в цепь листом.
// Считается от байт, а не от структуры: проверяющему не нужно разбирать
// запись, чтобы убедиться, что её не меняли.
func Digest(marshaled []byte) [32]byte {
	h := sha256.New()
	h.Write([]byte(domainSealed))
	h.Write(marshaled)
	var d [32]byte
	h.Sum(d[:0])
	return d
}

func appendField(dst, field []byte) []byte {
	dst = binary.BigEndian.AppendUint32(dst, uint32(len(field)))
	return append(dst, field...)
}

// readField читает поле с префиксом длины и возвращает остаток.
func readField(b []byte, limit int) (field, rest []byte, err error) {
	if len(b) < 4 {
		return nil, nil, fmt.Errorf("%w: truncated length", ErrMalformed)
	}
	n := binary.BigEndian.Uint32(b)
	if uint64(n) > uint64(limit) {
		return nil, nil, fmt.Errorf("%w: field length %d exceeds %d", ErrMalformed, n, limit)
	}
	b = b[4:]
	if uint64(len(b)) < uint64(n) {
		return nil, nil, fmt.Errorf("%w: truncated field", ErrMalformed)
	}
	return b[:n], b[n:], nil
}
