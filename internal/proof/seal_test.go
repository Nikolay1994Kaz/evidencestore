package proof

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Nikolay1994Kaz/evidencestore/internal/tsa"
)

// sealPKI — центр печатей и сертификат печати организации под ним.
type sealPKI struct {
	root, org       *x509.Certificate
	rootKey, orgKey crypto.Signer
}

func newSealPKI(t testing.TB) sealPKI {
	t.Helper()
	key := func() crypto.Signer {
		k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		return k
	}
	p := sealPKI{rootKey: key(), orgKey: key()}
	rootTmpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "seal CA"},
		NotBefore: time.Date(2020, 1, 1, 0, 0, 0, 0, time.UTC), NotAfter: time.Date(2040, 1, 1, 0, 0, 0, 0, time.UTC),
		KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageCRLSign, BasicConstraintsValid: true, IsCA: true}
	der, err := x509.CreateCertificate(rand.Reader, rootTmpl, rootTmpl, p.rootKey.Public(), p.rootKey)
	if err != nil {
		t.Fatal(err)
	}
	p.root, _ = x509.ParseCertificate(der)
	orgTmpl := &x509.Certificate{SerialNumber: big.NewInt(42), Subject: pkix.Name{Organization: []string{"Example Bank"}, CommonName: "Example Bank seal"},
		NotBefore: time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC), NotAfter: time.Date(2030, 1, 1, 0, 0, 0, 0, time.UTC),
		KeyUsage: x509.KeyUsageDigitalSignature | x509.KeyUsageContentCommitment}
	der, err = x509.CreateCertificate(rand.Reader, orgTmpl, p.root, p.orgKey.Public(), p.rootKey)
	if err != nil {
		t.Fatal(err)
	}
	p.org, _ = x509.ParseCertificate(der)
	return p
}

// trust — проверяющий верит центру печатей.
func (p sealPKI) trust() *tsa.Trust {
	pool := x509.NewCertPool()
	pool.AddCert(p.root)
	return &tsa.Trust{Roots: pool}
}

// seal — печать организации на ключ pub в момент at и метка службы мира над
// ней в момент stamped (ноль — без метки).
func (p sealPKI) seal(t testing.TB, w *world, pub ed25519.PublicKey, at, stamped time.Time) *StoreSeal {
	return p.sealBy(t, w.tsa, pub, at, stamped)
}

// sealBy — то же, метка службы a.
func (p sealPKI) sealBy(t testing.TB, a *tsa.Authority, pub ed25519.PublicKey, at, stamped time.Time) *StoreSeal {
	t.Helper()
	cms, err := tsa.Seal(p.orgKey, p.org, nil, SealStatement(pub), at)
	if err != nil {
		t.Fatal(err)
	}
	s := &StoreSeal{CMS: cms}
	if !stamped.IsZero() {
		was := a.Now
		a.Now = func() time.Time { return stamped }
		imprint := SealImprint(cms)
		if s.Token, err = a.Sign(imprint[:], nil); err != nil {
			t.Fatal(err)
		}
		a.Now = was
	}
	return s
}

// crlDER — CRL центра печатей с записями, на момент now.
func (p sealPKI) crlDER(t testing.TB, now time.Time, entries ...x509.RevocationListEntry) []byte {
	t.Helper()
	der, err := x509.CreateRevocationList(rand.Reader, &x509.RevocationList{Number: big.NewInt(1), ThisUpdate: now.Add(-time.Hour), NextUpdate: now.Add(time.Hour), RevokedCertificateEntries: entries}, p.root, p.rootKey)
	if err != nil {
		t.Fatal(err)
	}
	return der
}

// revsOf — сведения об отзыве из нескольких CRL.
func revsOf(t testing.TB, now time.Time, crls ...[]byte) *tsa.Revocations {
	t.Helper()
	r := tsa.NewRevocations(now)
	for i, der := range crls {
		path := filepath.Join(t.TempDir(), fmt.Sprintf("%d.crl", i))
		if err := os.WriteFile(path, der, 0o600); err != nil {
			t.Fatal(err)
		}
		if err := r.AddCRL(path); err != nil {
			t.Fatal(err)
		}
	}
	return r
}

func pins(t testing.TB, texts ...string) []tsa.SubjectPin {
	t.Helper()
	var out []tsa.SubjectPin
	for _, s := range texts {
		p, err := tsa.ParseSubjectPin(s)
		if err != nil {
			t.Fatal(err)
		}
		out = append(out, p)
	}
	return out
}

func sealCheckOf(r Report) (Check, bool) {
	for _, c := range r.Checks {
		if c.Name == sealCheckName {
			return c, true
		}
	}
	return Check{}, false
}

// Печать организации на ключ хранилища: с корнем центра печатей и именем
// владельца ключ можно не закреплять; без имени — нельзя; печать на другой
// ключ, чужим центром, другого владельца, без печати при -seal-trust —
// провал; без -seal-trust печать только названа.
func TestSealOfStoreKey(t *testing.T) {
	w, b := standard(t, nil)
	p := newSealPKI(t)
	b.Seal = p.seal(t, w, w.signer.PublicKey(), w.now, w.now.Add(time.Minute))
	tr := w.trust()
	tr.SealTrust = p.trust()
	r := Verify(b, tr)
	if c, ok := sealCheckOf(r); !r.Valid() || !ok || !c.OK || !strings.Contains(c.Detail, "Example Bank seal") || !strings.Contains(c.Detail, "time-stamped at") {
		t.Fatalf("печать при закреплённом ключе:\n%s", r.Text())
	}
	tr.StoreKey = nil
	if r := Verify(b, tr); r.Valid() || !strings.Contains(r.Text(), "nothing names whose seal") {
		t.Fatalf("ключ из печати без имени владельца:\n%s", r.Text())
	}
	tr.SealSubject = pins(t, "O=Example Bank", "CN=Example Bank seal")
	if r := Verify(b, tr); !r.Valid() {
		t.Fatalf("ключ из печати:\n%s", r.Text())
	}
	tr.SealSubject = pins(t, "O=Example Bank", "CN=Example Bank")
	if r := Verify(b, tr); r.Valid() || !strings.Contains(r.Text(), "its name has no CN=Example Bank") {
		t.Fatalf("ключ из печати другого владельца:\n%s", r.Text())
	}
	tr.StoreKey = w.signer.PublicKey()
	if r := Verify(b, tr); r.Valid() || !strings.Contains(r.Text(), "its name has no CN=Example Bank") {
		t.Fatalf("печать другого владельца при закреплённом ключе:\n%s", r.Text())
	}
	// Печать на другой ключ: при закреплённом — провал пункта; без него —
	// подпись головы не сходится.
	other, _, _ := ed25519.GenerateKey(nil)
	b2 := b
	b2.Seal = p.seal(t, w, other, w.now, w.now.Add(time.Minute))
	tr2 := w.trust()
	tr2.SealTrust = p.trust()
	if r := Verify(b2, tr2); r.Valid() || !strings.Contains(r.Text(), "another key") {
		t.Fatalf("печать на другой ключ:\n%s", r.Text())
	}
	tr2.StoreKey = nil
	tr2.SealSubject = pins(t, "O=Example Bank")
	if r := Verify(b2, tr2); r.Valid() {
		t.Fatalf("печать на другой ключ, ключ не закреплён:\n%s", r.Text())
	}
	// Чужой центр.
	tr3 := w.trust()
	tr3.SealTrust = newSealPKI(t).trust()
	if r := Verify(b, tr3); r.Valid() {
		t.Fatalf("печать чужого центра:\n%s", r.Text())
	}
	// Пакет без печати, а её просили.
	b4 := b
	b4.Seal = nil
	if r := Verify(b4, tr3); r.Valid() || !strings.Contains(r.Text(), "carries no seal") {
		t.Fatalf("пакет без печати при -seal-trust:\n%s", r.Text())
	}
	// Без -seal-trust печать названа, пункта нет.
	if r := Verify(b, w.trust()); !r.Valid() || !strings.Contains(r.Text(), SealNotChecked) {
		t.Fatalf("печать без -seal-trust:\n%s", r.Text())
	}
}

// Отзыв сертификата печати: без компрометации — в силе печать до даты
// отзыва; по компрометации — печать в силе, только если метка над ней
// раньше отсечки. Без метки над печатью компрометация её валит.
func TestSealRevoked(t *testing.T) {
	w, b := standard(t, nil)
	p := newSealPKI(t)
	made, stamped := w.now, w.now.Add(time.Minute)
	b.Seal = p.seal(t, w, w.signer.PublicKey(), made, stamped)
	now := w.now.Add(48 * time.Hour)
	tsaCRL, err := w.tsa.RevocationList(now.Add(-time.Hour), now.Add(time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	runWith := func(s *StoreSeal, at time.Time, reason int, crls ...[]byte) Report {
		tr := w.trust()
		tr.SealTrust = p.trust()
		tr.TSARevocations = revsOf(t, now, append([][]byte{p.crlDER(t, now, x509.RevocationListEntry{SerialNumber: p.org.SerialNumber, RevocationTime: at, ReasonCode: reason})}, crls...)...)
		bb := b
		bb.Seal = s
		return Verify(bb, tr)
	}
	run := func(s *StoreSeal, at time.Time, reason int) Report { return runWith(s, at, reason, tsaCRL) }
	if r := run(b.Seal, stamped.Add(time.Hour), tsa.ReasonKeyCompromise); !r.Valid() || !strings.Contains(r.Text(), "made earlier") {
		t.Fatalf("компрометация после метки над печатью:\n%s", r.Text())
	}
	// Отзыв службы метки над печатью не проверен — метка времени печати не
	// показывает.
	if r := runWith(b.Seal, stamped.Add(time.Hour), tsa.ReasonKeyCompromise); r.Valid() || !strings.Contains(r.Text(), "the revocation of the time-stamp's own certificate was not checked") {
		t.Fatalf("компрометация после метки над печатью, отзыв службы метки не проверен:\n%s", r.Text())
	}
	if r := run(b.Seal, stamped.Add(-time.Second), tsa.ReasonKeyCompromise); r.Valid() || !strings.Contains(r.Text(), "nothing shows it was made before") {
		t.Fatalf("компрометация до метки над печатью:\n%s", r.Text())
	}
	if r := run(b.Seal, stamped.Add(-time.Second), tsa.ReasonSuperseded); r.Valid() || !strings.Contains(r.Text(), "not in force") {
		t.Fatalf("выведен из работы до метки над печатью:\n%s", r.Text())
	}
	if r := run(b.Seal, stamped.Add(time.Hour), tsa.ReasonSuperseded); !r.Valid() {
		t.Fatalf("выведен из работы после метки над печатью:\n%s", r.Text())
	}
	unstamped := p.seal(t, w, w.signer.PublicKey(), made, time.Time{})
	if r := run(unstamped, stamped.Add(time.Hour), tsa.ReasonKeyCompromise); r.Valid() || !strings.Contains(r.Text(), "no time-stamp over the seal") {
		t.Fatalf("компрометация, печать без метки:\n%s", r.Text())
	}
	// Метка над чужими байтами — не метка над печатью.
	forged := *b.Seal
	other := p.seal(t, w, w.signer.PublicKey(), made, stamped)
	forged.Token = other.Token
	if r := run(&forged, stamped.Add(time.Hour), tsa.ReasonKeyCompromise); r.Valid() || !strings.Contains(r.Text(), "does not verify") {
		t.Fatalf("метка над другой печатью:\n%s", r.Text())
	}
}

// Метка над печатью, которая не в силе или под подозрением (ключ её службы
// скомпрометирован), времени печати не показывает: печать судится на момент
// проверки, как без метки. Действует сейчас — в силе; истекла или отозвана
// к моменту проверки — нет, как бы ни была датирована метка.
func TestSealTokenNotTrusted(t *testing.T) {
	w, b := standard(t, nil)
	p := newSealPKI(t)
	other, tr := otherTSA(t, w)
	made, stamped := w.now, w.now.Add(time.Minute)
	b.Seal = p.sealBy(t, other, w.signer.PublicKey(), made, stamped)
	tr.SealTrust = p.trust()
	otherCRL := func(now time.Time, reason int, at time.Time) []byte {
		der, err := other.RevocationList(now.Add(-time.Hour), now.Add(time.Hour), x509.RevocationListEntry{SerialNumber: other.Cert().SerialNumber, RevocationTime: at, ReasonCode: reason})
		if err != nil {
			t.Fatal(err)
		}
		return der
	}
	check := func(now time.Time, crls ...[]byte) Check {
		t.Helper()
		tr := tr
		tr.TSARevocations = revsOf(t, now, crls...)
		c, ok := sealCheckOf(Verify(b, tr))
		if !ok {
			t.Fatal("нет пункта о печати")
		}
		return c
	}
	soon, late := w.now.Add(48*time.Hour), time.Date(2031, 1, 1, 0, 0, 0, 0, time.UTC)
	for name, crl := range map[string]func(time.Time) []byte{
		"компрометация службы метки": func(now time.Time) []byte { return otherCRL(now, tsa.ReasonKeyCompromise, stamped.Add(time.Hour)) },
		"служба выведена до метки":   func(now time.Time) []byte { return otherCRL(now, tsa.ReasonSuperseded, stamped.Add(-time.Second)) },
	} {
		if c := check(soon, crl(soon)); !c.OK || !strings.Contains(c.Detail, "when the seal was made is not shown") {
			t.Fatalf("%s, печать действует сейчас: %+v", name, c)
		}
		if c := check(late, crl(late)); c.OK || !strings.Contains(c.Detail, "expired") {
			t.Fatalf("%s, сертификат печати истёк к проверке: %+v", name, c)
		}
		sealCRL := p.crlDER(t, soon, x509.RevocationListEntry{SerialNumber: p.org.SerialNumber, RevocationTime: stamped.Add(2 * time.Hour), ReasonCode: tsa.ReasonSuperseded})
		if c := check(soon, crl(soon), sealCRL); c.OK || !strings.Contains(c.Detail, "not in force") {
			t.Fatalf("%s, сертификат печати выведен после метки, до проверки: %+v", name, c)
		}
	}
	// Метка в силе: тот же отзыв печати после метки её не валит.
	sealCRL := p.crlDER(t, soon, x509.RevocationListEntry{SerialNumber: p.org.SerialNumber, RevocationTime: stamped.Add(2 * time.Hour), ReasonCode: tsa.ReasonSuperseded})
	if c := check(soon, sealCRL); !c.OK || !strings.Contains(c.Detail, "time-stamped at") {
		t.Fatalf("метка в силе, печать выведена после неё: %+v", c)
	}
}
