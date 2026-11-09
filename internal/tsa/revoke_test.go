package tsa

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/pem"
	"errors"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// revWorld — служба, её токен и каталог для CRL.
type revWorld struct {
	t    *testing.T
	a    *Authority
	info Info
	gen  time.Time
	dir  string
}

func newRevWorld(t *testing.T) *revWorld {
	t.Helper()
	a, err := NewAuthority(false)
	if err != nil {
		t.Fatal(err)
	}
	gen := time.Date(2026, 10, 1, 12, 0, 0, 0, time.UTC)
	a.Now = func() time.Time { return gen }
	imprint := sha256.Sum256([]byte("head"))
	token, err := a.Sign(imprint[:], nil)
	if err != nil {
		t.Fatal(err)
	}
	info, err := Verify(token, imprint, a.Trust())
	if err != nil {
		t.Fatal(err)
	}
	if len(info.Chains) != 1 || len(info.Chains[0]) != 2 {
		t.Fatalf("цепочки токена: %d", len(info.Chains))
	}
	return &revWorld{t: t, a: a, info: info, gen: gen, dir: t.TempDir()}
}

// crl пишет CRL корня службы с записями и отдаёт путь.
func (w *revWorld) crl(name string, next time.Time, entries ...x509.RevocationListEntry) string {
	w.t.Helper()
	der, err := w.a.RevocationList(w.gen.Add(24*time.Hour), next, entries...)
	if err != nil {
		w.t.Fatal(err)
	}
	p := filepath.Join(w.dir, name)
	if err := os.WriteFile(p, der, 0o600); err != nil {
		w.t.Fatal(err)
	}
	return p
}

func (w *revWorld) check(r *Revocations) (Verdict, error) {
	return r.Check(w.info.Chains, w.info.GenTime)
}

func ext(t *testing.T, id asn1.ObjectIdentifier, v any, params string) pkix.Extension {
	b, err := asn1.MarshalWithParams(v, params)
	if err != nil {
		t.Fatal(err)
	}
	return pkix.Extension{Id: id, Value: b}
}

// Без сведений об отзыве — проверять нечем: сертификат службы назван
// непроверенным. CRL центра, где его нет, — проверен и не отозван.
func TestRevocationsNotRevoked(t *testing.T) {
	w := newRevWorld(t)
	now := w.gen.Add(48 * time.Hour)
	v, err := w.check(NewRevocations(now))
	if err != nil || v.NeedPOE || len(v.Unchecked) != 1 || v.Unchecked[0] != w.info.Signer {
		t.Fatalf("без CRL: %+v %v", v, err)
	}
	r := NewRevocations(now)
	other := x509.RevocationListEntry{SerialNumber: big.NewInt(777), RevocationTime: w.gen}
	if err := r.AddCRL(w.crl("root.crl", now.Add(time.Hour), other)); err != nil {
		t.Fatal(err)
	}
	v, err = w.check(r)
	if err != nil || v.NeedPOE || v.Revoked != nil || len(v.Unchecked) != 0 || len(v.CRLs) != 1 || len(v.Stale) != 0 {
		t.Fatalf("CRL без записи о службе: %+v %v", v, err)
	}
}

// Отзыв без компрометации (RFC 3161, 4, п. 1): метки до даты отзыва в силе,
// с неё — нет. Явная причина unspecified — то же.
func TestRevocationsWithoutCompromise(t *testing.T) {
	w := newRevWorld(t)
	now := w.gen.Add(48 * time.Hour)
	serial := w.a.Cert().SerialNumber
	for name, reason := range map[string]int{"superseded": ReasonSuperseded, "cessation": ReasonCessationOfOperation, "unspecified": ReasonUnspecified} {
		for _, at := range []struct {
			when  time.Time
			valid bool
		}{{w.gen.Add(time.Hour), true}, {w.gen, false}} { // после метки — в силе; ровно во время — уже нет
			r := NewRevocations(now)
			if err := r.AddCRL(w.reasonCRL(name+".crl", now.Add(time.Hour), serial, at.when, reason)); err != nil {
				t.Fatal(err)
			}
			v, err := w.check(r)
			if at.valid && (err != nil || v.NeedPOE) || !at.valid && (!errors.Is(err, ErrRevoked) || !strings.Contains(err.Error(), "not earlier")) {
				t.Fatalf("%s, отзыв %s: %+v %v", name, at.when, v, err)
			}
		}
	}
}

// reasonCRL — CRL корня с одной записью и явной причиной, unspecified (0)
// тоже: x509 не пишет её через RevocationListEntry, только через прежнее
// поле RevokedCertificates.
func (w *revWorld) reasonCRL(name string, next time.Time, serial *big.Int, at time.Time, reason int) string {
	w.t.Helper()
	der, err := x509.CreateRevocationList(rand.Reader, &x509.RevocationList{
		Number: big.NewInt(1), ThisUpdate: w.gen.Add(24 * time.Hour), NextUpdate: next,
		RevokedCertificates: []pkix.RevokedCertificate{{SerialNumber: serial, RevocationTime: at,
			Extensions: []pkix.Extension{ext(w.t, oidReasonCode, asn1.Enumerated(reason), "")}}},
	}, w.a.root, w.a.rootKey)
	if err != nil {
		w.t.Fatal(err)
	}
	p := filepath.Join(w.dir, name)
	if err := os.WriteFile(p, der, 0o600); err != nil {
		w.t.Fatal(err)
	}
	return p
}

// Компрометация или нет причины (п. 2): времени метки верить нельзя — нужна
// POE раньше отсечки; отсечка — invalidityDate, если она раньше даты отзыва.
func TestRevocationsCompromiseNeedsPOE(t *testing.T) {
	w := newRevWorld(t)
	now := w.gen.Add(48 * time.Hour)
	serial := w.a.Cert().SerialNumber
	revoked := w.gen.Add(10 * time.Hour)
	suspected := w.gen.Add(-5 * time.Hour)
	cases := []struct {
		name   string
		e      x509.RevocationListEntry
		cutoff time.Time
		reason int
	}{
		{"keyCompromise", x509.RevocationListEntry{SerialNumber: serial, RevocationTime: revoked, ReasonCode: ReasonKeyCompromise}, revoked, ReasonKeyCompromise},
		{"keyCompromise с invalidityDate", x509.RevocationListEntry{SerialNumber: serial, RevocationTime: revoked, ReasonCode: ReasonKeyCompromise,
			ExtraExtensions: []pkix.Extension{ext(t, oidInvalidityDate, suspected, "generalized")}}, suspected, ReasonKeyCompromise},
		{"без причины", x509.RevocationListEntry{SerialNumber: serial, RevocationTime: revoked}, revoked, ReasonAbsent},
		{"certificateHold", x509.RevocationListEntry{SerialNumber: serial, RevocationTime: revoked, ReasonCode: ReasonCertificateHold}, revoked, ReasonCertificateHold},
	}
	for i, c := range cases {
		r := NewRevocations(now)
		if err := r.AddCRL(w.crl("c"+string(rune('a'+i))+".crl", now.Add(time.Hour), c.e)); err != nil {
			t.Fatal(err)
		}
		v, err := w.check(r)
		if err != nil || !v.NeedPOE || !v.Cutoff.Equal(c.cutoff) || v.Revoked != w.info.Signer || v.Entry.Reason != c.reason {
			t.Fatalf("%s: %+v %v", c.name, v, err)
		}
	}
	// Снятие с удержания (removeFromCRL) — не отзыв.
	r := NewRevocations(now)
	if err := r.AddCRL(w.crl("removed.crl", now.Add(time.Hour), x509.RevocationListEntry{SerialNumber: serial, RevocationTime: revoked, ReasonCode: ReasonRemoveFromCRL})); err != nil {
		t.Fatal(err)
	}
	if v, err := w.check(r); err != nil || v.NeedPOE {
		t.Fatalf("removeFromCRL: %+v %v", v, err)
	}
}

// CRL центра с тем же именем, но не его подписью, — не его CRL: отзыв не
// проверен, и это названо. Старый CRL (nextUpdate прошёл) — проверен, но
// назван несвежим. PEM — тоже CRL.
func TestRevocationsCRLItself(t *testing.T) {
	w := newRevWorld(t)
	now := w.gen.Add(48 * time.Hour)
	other, err := NewAuthority(false) // корень с тем же именем, другой ключ
	if err != nil {
		t.Fatal(err)
	}
	der, err := other.RevocationList(w.gen, now.Add(time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	p := filepath.Join(w.dir, "foreign.crl")
	os.WriteFile(p, der, 0o600)
	r := NewRevocations(now)
	if err := r.AddCRL(p); err != nil {
		t.Fatal(err)
	}
	if v, err := w.check(r); err != nil || len(v.Unchecked) != 1 || len(v.Foreign) != 1 || !strings.Contains(v.Foreign[0], "does not verify") {
		t.Fatalf("чужой CRL: %+v %v", v, err)
	}
	// Есть и свой — берётся он.
	if err := r.AddCRL(w.crl("own.crl", now.Add(time.Hour))); err != nil {
		t.Fatal(err)
	}
	if v, err := w.check(r); err != nil || len(v.Unchecked) != 0 || len(v.CRLs) != 1 {
		t.Fatalf("свой CRL рядом с чужим: %+v %v", v, err)
	}

	r = NewRevocations(now)
	stale := w.crl("stale.crl", now.Add(-time.Minute))
	data, _ := os.ReadFile(stale)
	pemPath := filepath.Join(w.dir, "stale.pem")
	os.WriteFile(pemPath, pem.EncodeToMemory(&pem.Block{Type: "X509 CRL", Bytes: data}), 0o600)
	if err := r.AddCRL(pemPath); err != nil {
		t.Fatal(err)
	}
	if v, err := w.check(r); err != nil || len(v.Stale) != 1 || len(v.CRLs) != 1 {
		t.Fatalf("несвежий CRL в PEM: %+v %v", v, err)
	}
	notCRL := filepath.Join(w.dir, "cert.pem")
	os.WriteFile(notCRL, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: w.a.Root().Raw}), 0o600)
	if err := NewRevocations(now).AddCRL(notCRL); err == nil {
		t.Fatal("сертификат принят за CRL")
	}
}

// Перечень проверяющего: отзыв по отпечатку, в том числе корня; разбор
// строгий.
func TestRevocationsList(t *testing.T) {
	w := newRevWorld(t)
	now := w.gen.Add(48 * time.Hour)
	write := func(body string) string {
		p := filepath.Join(w.dir, "list.json")
		os.WriteFile(p, []byte(body), 0o600)
		return p
	}
	r := NewRevocations(now)
	if err := r.AddList(write(`[{"cert_sha256": "` + Fingerprint(w.a.Cert()) + `", "revoked": "2026-10-03T00:00:00Z", "reason": "keyCompromise", "invalidity": "2026-09-30T00:00:00Z"}]`)); err != nil {
		t.Fatal(err)
	}
	v, err := w.check(r)
	if err != nil || !v.NeedPOE || !v.Cutoff.Equal(time.Date(2026, 9, 30, 0, 0, 0, 0, time.UTC)) {
		t.Fatalf("компрометация по перечню: %+v %v", v, err)
	}
	// Корень выведен из работы до метки — метка не в силе.
	r = NewRevocations(now)
	if err := r.AddList(write(`[{"cert_sha256": "` + Fingerprint(w.a.Root()) + `", "revoked": "2026-09-01T00:00:00Z", "reason": "cessationOfOperation"}]`)); err != nil {
		t.Fatal(err)
	}
	if _, err := w.check(r); !errors.Is(err, ErrRevoked) {
		t.Fatalf("корень выведен до метки: %v", err)
	}
	for name, body := range map[string]string{
		"не hex":        `[{"cert_sha256": "xyz", "revoked": "2026-09-01T00:00:00Z"}]`,
		"без времени":   `[{"cert_sha256": "` + Fingerprint(w.a.Root()) + `"}]`,
		"чужая причина": `[{"cert_sha256": "` + Fingerprint(w.a.Root()) + `", "revoked": "2026-09-01T00:00:00Z", "reason": "stolen"}]`,
		"removeFromCRL": `[{"cert_sha256": "` + Fingerprint(w.a.Root()) + `", "revoked": "2026-09-01T00:00:00Z", "reason": "removeFromCRL"}]`,
		"лишнее поле":   `[{"cert_sha256": "` + Fingerprint(w.a.Root()) + `", "revoked": "2026-09-01T00:00:00Z", "why": "x"}]`,
		"не список":     `{"cert_sha256": "x"}`,
	} {
		if err := NewRevocations(now).AddList(write(body)); err == nil {
			t.Errorf("%s: принято", name)
		}
	}
}
