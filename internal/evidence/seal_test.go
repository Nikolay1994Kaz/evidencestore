package evidence

import (
	"bytes"
	"errors"
	"testing"
	"time"

	"evidencestore/internal/keyring"
)

// Проверка при компиляции: keyring подходит под оба интерфейса.
var (
	_ Sealer   = (*keyring.Keyring)(nil)
	_ Unsealer = (*keyring.Keyring)(nil)
)

var sept = time.Date(2026, 9, 25, 10, 0, 0, 0, time.UTC)

func openRing(t *testing.T) *keyring.Keyring {
	t.Helper()
	k, err := keyring.Create(t.TempDir(), keyring.FileRoots{Dir: t.TempDir()}, keyring.Options{})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { k.Close() })
	return k
}

func record(source string, at time.Time, body string) Record {
	return Record{
		Header: Header{Source: source, Seq: 1, ReceivedAt: at.UnixNano(), ContentType: "syslog"},
		Body:   []byte(body),
	}
}

func TestSealOpenRoundTrip(t *testing.T) {
	k := openRing(t)
	r := record("abs-core", sept, "user=admin action=delete table=payments")
	s, err := r.Seal(k)
	if err != nil {
		t.Fatal(err)
	}
	if s.Header != r.Header {
		t.Fatalf("header changed: %+v", s.Header)
	}
	if bytes.Contains(s.Envelope, r.Body) {
		t.Fatal("envelope contains the plaintext body")
	}
	body, err := s.Open(k)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(body, r.Body) {
		t.Fatalf("opened %q, want %q", body, r.Body)
	}
}

// Имя скоупа не зависит от часового пояса сервера: иначе два сервера
// в разных поясах завели бы для одной записи разные ключи.
func TestScopeIsSourceAndUTCMonth(t *testing.T) {
	almaty := time.FixedZone("UTC+5", 5*60*60)
	old := time.Local
	time.Local = almaty
	t.Cleanup(func() { time.Local = old })

	cases := []struct {
		at   time.Time
		want string
	}{
		{time.Date(2026, 9, 30, 23, 59, 59, 0, time.UTC), "abs-core/2026-09"},
		{time.Date(2026, 10, 1, 0, 0, 0, 0, time.UTC), "abs-core/2026-10"},
		// 1 октября 03:00 в Алматы — это ещё 30 сентября по UTC.
		{time.Date(2026, 10, 1, 3, 0, 0, 0, almaty), "abs-core/2026-09"},
	}
	for _, c := range cases {
		h := Header{Source: "abs-core", Seq: 1, ReceivedAt: c.at.UnixNano()}
		if got := h.Scope(); got != c.want {
			t.Errorf("%v: scope %q, want %q", c.at, got, c.want)
		}
	}
}

// Главное свойство продукта: после уничтожения ключа тело не прочитать,
// а байты на диске и их отпечаток остаются прежними, поэтому цепь цела.
func TestDestroyedKeyErasesBodyKeepsDigest(t *testing.T) {
	k := openRing(t)
	s, err := record("abs-core", sept, "secret payload").Seal(k)
	if err != nil {
		t.Fatal(err)
	}
	stored, err := s.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	before := Digest(stored)

	destroy(t, k, s.Scope())

	again, err := Unmarshal(stored)
	if err != nil {
		t.Fatalf("stored bytes no longer parse: %v", err)
	}
	if Digest(stored) != before {
		t.Fatal("digest changed after key destruction")
	}
	if _, err := again.Open(k); !errors.Is(err, keyring.ErrKeyDestroyed) {
		t.Fatalf("open after destroy: err = %v, want ErrKeyDestroyed", err)
	}
}

// Стирание сентября одного источника не задевает ни октябрь, ни другой источник.
func TestDestroyIsScopedToSourceAndMonth(t *testing.T) {
	k := openRing(t)
	seal := func(r Record) Sealed {
		t.Helper()
		s, err := r.Seal(k)
		if err != nil {
			t.Fatal(err)
		}
		return s
	}
	target := seal(record("abs-core", sept, "a"))
	nextMonth := seal(record("abs-core", sept.AddDate(0, 1, 0), "b"))
	otherSource := seal(record("crm", sept, "c"))

	destroy(t, k, target.Scope())
	if _, err := target.Open(k); !errors.Is(err, keyring.ErrKeyDestroyed) {
		t.Fatalf("target: err = %v, want ErrKeyDestroyed", err)
	}
	for want, s := range map[string]Sealed{"b": nextMonth, "c": otherSource} {
		body, err := s.Open(k)
		if err != nil || string(body) != want {
			t.Fatalf("%s: body %q, err %v", s.Scope(), body, err)
		}
	}
}

func TestSealBodyLimits(t *testing.T) {
	k := openRing(t)

	bad := record("abs-core", sept, "x")
	bad.Seq = 0
	if _, err := bad.Seal(k); err == nil {
		t.Error("sealed a record with zero seq")
	}
	big := record("abs-core", sept, "")
	big.Body = make([]byte, MaxBodyLen+1)
	if _, err := big.Seal(k); err == nil {
		t.Error("sealed an oversized body")
	}
	if scopes := k.Scopes(); len(scopes) != 0 {
		t.Fatalf("invalid records created keys: %v", scopes)
	}

	// Тело ровно на пределе проходит: запаса хватает на служебные поля конверта.
	edge := record("abs-core", sept, "")
	edge.Body = make([]byte, MaxBodyLen)
	s, err := edge.Seal(k)
	if err != nil {
		t.Fatalf("body at the limit: %v", err)
	}
	if _, err := s.Marshal(); err != nil {
		t.Fatalf("sealed body at the limit does not marshal: %v", err)
	}
}

// destroy проводит скоуп через все шаги уничтожения: закрыть, заявка двух
// людей, срок ожидания (в тестах нулевой), уничтожение.
func destroy(t *testing.T, k *keyring.Keyring, scope string) {
	t.Helper()
	if err := k.Deactivate(scope); err != nil {
		t.Fatal(err)
	}
	approvals := []keyring.Approval{{Who: "operator"}, {Who: "security"}}
	if _, err := k.ScheduleDestroy(scope, 0, approvals); err != nil {
		t.Fatal(err)
	}
	if _, err := k.CompleteDue(); err != nil {
		t.Fatal(err)
	}
}
