package tsa

// Пересмотр 10.11 (DECISIONS, п. 35): демо-службы перестали быть тёзками —
// у каждой своё имя корня и свои номера.

import (
	"testing"
)

// Две демо-службы — разные центры: имя корня и номера у каждой свои.
func TestDemoAuthoritiesDiffer(t *testing.T) {
	a, err := NewAuthority(false)
	if err != nil {
		t.Fatal(err)
	}
	b, err := NewAuthority(false)
	if err != nil {
		t.Fatal(err)
	}
	switch {
	case string(a.Root().RawSubject) == string(b.Root().RawSubject), a.Cert().Issuer.String() == b.Cert().Issuer.String():
		t.Fatalf("имя корня одно: %s", a.Root().Subject)
	case a.Cert().SerialNumber.Cmp(b.Cert().SerialNumber) == 0, a.Root().SerialNumber.Cmp(b.Root().SerialNumber) == 0:
		t.Fatalf("номера совпали: %v %v", a.Cert().SerialNumber, a.Root().SerialNumber)
	case a.Cert().SerialNumber.Sign() <= 0 || a.Root().SerialNumber.Sign() <= 0:
		t.Fatalf("номер не положителен: %v %v", a.Cert().SerialNumber, a.Root().SerialNumber)
	}
}
