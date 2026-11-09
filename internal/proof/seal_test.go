package proof

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
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
	t.Helper()
	cms, err := tsa.Seal(p.orgKey, p.org, nil, SealStatement(pub), at)
	if err != nil {
		t.Fatal(err)
	}
	s := &StoreSeal{CMS: cms}
	if !stamped.IsZero() {
		was := w.tsa.Now
		w.tsa.Now = func() time.Time { return stamped }
		imprint := SealImprint(cms)
		if s.Token, err = w.tsa.Sign(imprint[:], nil); err != nil {
			t.Fatal(err)
		}
		w.tsa.Now = was
	}
	return s
}

// crl — CRL центра печатей с записями, на момент now.
func (p sealPKI) crl(t testing.TB, now time.Time, entries ...x509.RevocationListEntry) *tsa.Revocations {
	t.Helper()
	der, err := x509.CreateRevocationList(rand.Reader, &x509.RevocationList{Number: big.NewInt(1), ThisUpdate: now.Add(-time.Hour), NextUpdate: now.Add(time.Hour), RevokedCertificateEntries: entries}, p.root, p.rootKey)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "seal-ca.crl")
	if err := os.WriteFile(path, der, 0o600); err != nil {
		t.Fatal(err)
	}
	r := tsa.NewRevocations(now)
	if err := r.AddCRL(path); err != nil {
		t.Fatal(err)
	}
	return r
}

func sealCheckOf(r Report) (Check, bool) {
	for _, c := range r.Checks {
		if c.Name == sealCheckName {
			return c, true
		}
	}
	return Check{}, false
}

// Печать организации на ключ хранилища: с корнем центра печатей ключ можно не
// закреплять; печать на другой ключ, чужим центром, без печати при
// -seal-trust — провал; без -seal-trust печать только названа.
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
	if r := Verify(b, tr); !r.Valid() {
		t.Fatalf("ключ из печати:\n%s", r.Text())
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
	run := func(s *StoreSeal, at time.Time, reason int) Report {
		tr := w.trust()
		tr.SealTrust = p.trust()
		tr.TSARevocations = p.crl(t, now, x509.RevocationListEntry{SerialNumber: p.org.SerialNumber, RevocationTime: at, ReasonCode: reason})
		bb := b
		bb.Seal = s
		return Verify(bb, tr)
	}
	if r := run(b.Seal, stamped.Add(time.Hour), tsa.ReasonKeyCompromise); !r.Valid() || !strings.Contains(r.Text(), "made earlier") {
		t.Fatalf("компрометация после метки над печатью:\n%s", r.Text())
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
