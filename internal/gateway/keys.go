package gateway

// Ключи шлюза (DECISIONS, п. 47). Квитанция называет ключ, которым подписана,
// в заголовке подписи (kid), а у источника ключей может быть несколько: шлюз
// меняет ключ, и прежние квитанции проверяются прежним. У ключа есть срок, в
// который он говорит за шлюз, и сверяется срок со временем приёма квитанции
// хранилищем, а не с часами шлюза: время в квитанции пишет тот, кто её
// подписал, и держатель украденного ключа поставит любое. Так же делается и
// отзыв: not_after — миг, с которого ключу не верят.

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"
)

// KeyID — имя ключа в заголовке подписи квитанции (kid): отпечаток JWK по
// RFC 7638 — SHA-256 от {"crv":"Ed25519","kty":"OKP","x":"…"} в base64url.
// Имя считается из самого ключа: реестра имён нет, и двух ключей под одним
// именем быть не может.
func KeyID(pub ed25519.PublicKey) string {
	sum := sha256.Sum256([]byte(`{"crv":"Ed25519","kty":"OKP","x":"` + base64.RawURLEncoding.EncodeToString(pub) + `"}`))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}

// JWK — открытый ключ шлюза как JSON Web Key (RFC 8037) с его kid: в таком
// виде его берут библиотеки JOSE.
func JWK(pub ed25519.PublicKey) []byte {
	return []byte(`{"kty":"OKP","crv":"Ed25519","x":"` + base64.RawURLEncoding.EncodeToString(pub) + `","kid":"` + KeyID(pub) + `"}`)
}

// Key — открытый ключ шлюза и срок, в который он говорит за шлюз: от
// NotBefore включительно до NotAfter, не включая его. Ноль — без границы.
type Key struct {
	Pub       ed25519.PublicKey
	NotBefore time.Time
	NotAfter  time.Time
}

// ID — kid ключа.
func (k Key) ID() string { return KeyID(k.Pub) }

// covers — ключ говорит за шлюз в миг at.
func (k Key) covers(at time.Time) error {
	switch {
	case !k.NotBefore.IsZero() && at.Before(k.NotBefore):
		return fmt.Errorf("the receipt was received at %s, before gateway key %s speaks for the gateway (not_before %s)",
			at.UTC().Format(time.RFC3339), k.ID(), k.NotBefore.UTC().Format(time.RFC3339))
	case !k.NotAfter.IsZero() && !at.Before(k.NotAfter):
		return fmt.Errorf("the receipt was received at %s, when gateway key %s no longer speaks for the gateway (not_after %s)",
			at.UTC().Format(time.RFC3339), k.ID(), k.NotAfter.UTC().Format(time.RFC3339))
	}
	return nil
}

// KeySet — ключи шлюзов одного источника. nil — ключей нет.
type KeySet struct {
	byID  map[string]Key
	order []string
}

// NewKeySet — набор из ключей keys. Один ключ дважды — ошибка: у двух
// записей об одном ключе были бы два срока, и какой из них верен, не решить.
func NewKeySet(keys ...Key) (*KeySet, error) {
	s := &KeySet{byID: map[string]Key{}}
	for _, k := range keys {
		if len(k.Pub) != ed25519.PublicKeySize {
			return nil, errors.New("gateway: not an Ed25519 public key")
		}
		if !k.NotBefore.IsZero() && !k.NotAfter.IsZero() && !k.NotBefore.Before(k.NotAfter) {
			return nil, fmt.Errorf("gateway: key %s: not_after must be later than not_before", k.ID())
		}
		id := k.ID()
		if _, dup := s.byID[id]; dup {
			return nil, fmt.Errorf("gateway: key %s is listed twice", id)
		}
		s.byID[id] = k
		s.order = append(s.order, id)
	}
	return s, nil
}

// OneKey — набор из одного ключа без срока; nil — ключа нет.
func OneKey(pub ed25519.PublicKey) *KeySet {
	if len(pub) != ed25519.PublicKeySize {
		return nil
	}
	s, _ := NewKeySet(Key{Pub: pub}) // один ключ: ни повтора, ни срока
	return s
}

// Len — сколько ключей в наборе.
func (s *KeySet) Len() int {
	if s == nil {
		return 0
	}
	return len(s.order)
}

// Keys — ключи набора в порядке настройки.
func (s *KeySet) Keys() []Key {
	if s == nil {
		return nil
	}
	out := make([]Key, 0, len(s.order))
	for _, id := range s.order {
		out = append(out, s.byID[id])
	}
	return out
}

// Lookup — ключ с именем kid.
func (s *KeySet) Lookup(kid string) (Key, bool) {
	if s == nil {
		return Key{}, false
	}
	k, ok := s.byID[kid]
	return k, ok
}

// Verify проверяет подпись квитанции r ключом набора, который она называет,
// и срок этого ключа в миг at — время приёма квитанции хранилищем. Нулевое
// at — срок не сверяется: у того, кто проверяет файл квитанций сам, времени
// приёма нет.
func (s *KeySet) Verify(r Receipt, at time.Time) error {
	if r.Sig == nil {
		return errNoSignature
	}
	k, ok := s.Lookup(r.Kid)
	if !ok {
		return fmt.Errorf("the receipt names key %s, which is not among the gateway keys", r.Kid)
	}
	if err := r.Verify(k.Pub); err != nil {
		return err
	}
	if at.IsZero() {
		return nil
	}
	return k.covers(at)
}

// KeyEntry — ключ шлюза в настройках: строка из 64 hex или объект
// {"key": "<64 hex>", "not_before": "<RFC 3339>", "not_after": "<RFC 3339>"},
// где сроки — по желанию.
type KeyEntry struct {
	Key       string `json:"key"`
	NotBefore string `json:"not_before,omitempty"`
	NotAfter  string `json:"not_after,omitempty"`
}

// UnmarshalJSON принимает и строку с ключом, и объект со сроками. Лишнее поле
// объекта — ошибка: опечатка в not_after оставила бы отозванный ключ в силе.
func (e *KeyEntry) UnmarshalJSON(b []byte) error {
	b = bytes.TrimSpace(b)
	if len(b) > 0 && b[0] == '"' {
		*e = KeyEntry{}
		return json.Unmarshal(b, &e.Key)
	}
	type plain KeyEntry
	var p plain
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&p); err != nil {
		return fmt.Errorf("a gateway key is 64 hex characters or {\"key\": …, \"not_before\": …, \"not_after\": …}: %w", err)
	}
	*e = KeyEntry(p)
	return nil
}

// Parse — ключ со сроком из записи настроек.
func (e KeyEntry) Parse() (Key, error) {
	pub, err := ParseKey(e.Key)
	if err != nil {
		return Key{}, err
	}
	k := Key{Pub: pub}
	if e.NotBefore != "" {
		if k.NotBefore, err = time.Parse(time.RFC3339, e.NotBefore); err != nil {
			return Key{}, fmt.Errorf("gateway: key %s: not_before must be RFC 3339 (2026-11-28T00:00:00Z)", e.Key)
		}
	}
	if e.NotAfter != "" {
		if k.NotAfter, err = time.Parse(time.RFC3339, e.NotAfter); err != nil {
			return Key{}, fmt.Errorf("gateway: key %s: not_after must be RFC 3339 (2026-11-28T00:00:00Z)", e.Key)
		}
	}
	return k, nil
}

// ParseKeySet — набор ключей из записей настроек.
func ParseKeySet(entries []KeyEntry) (*KeySet, error) {
	keys := make([]Key, 0, len(entries))
	for _, e := range entries {
		k, err := e.Parse()
		if err != nil {
			return nil, err
		}
		keys = append(keys, k)
	}
	return NewKeySet(keys...)
}

// ParseKeyList разбирает ключи шлюза, как их даёт проверяющий: один ключ в 64
// hex или массив JSON записей настроек (gateway_keys источника).
func ParseKeyList(data []byte) ([]KeyEntry, error) {
	data = bytes.TrimSpace(data)
	if len(data) > 0 && data[0] == '[' {
		var entries []KeyEntry
		dec := json.NewDecoder(bytes.NewReader(data))
		if err := dec.Decode(&entries); err != nil {
			return nil, fmt.Errorf("gateway: keys: %w", err)
		}
		if dec.More() {
			return nil, errors.New("gateway: keys: data after the array")
		}
		if len(entries) == 0 {
			return nil, errors.New("gateway: keys: the array is empty")
		}
		return entries, nil
	}
	if _, err := ParseKey(string(data)); err != nil {
		return nil, err
	}
	return []KeyEntry{{Key: strings.ToLower(string(data))}}, nil
}

// ParseKey разбирает открытый ключ гейтвея: 64 hex-символа.
func ParseKey(s string) (ed25519.PublicKey, error) {
	b, err := hex.DecodeString(strings.TrimSpace(s))
	if err != nil || len(b) != ed25519.PublicKeySize {
		return nil, errors.New("gateway: key must be 64 hex characters (Ed25519 public key)")
	}
	return ed25519.PublicKey(b), nil
}
