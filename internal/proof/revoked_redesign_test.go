package proof

// Пересмотр 10.11 (FINDINGS, цикл 2, заход 3): пакет несёт сертификат второй
// службы, которая не кладёт его в токен.

import (
	"crypto/ecdsa"
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

// Вторая служба не кладёт свой сертификат в токен: пакет несёт его (Cert),
// и проверяющему довольно её корня. Без него — подсказка про сертификат, а не
// про корень; испорченный — отказ этой метке.
func TestRevocationArchiveCarriesCert(t *testing.T) {
	w, b := standard(t, nil)
	b.Upper.Inclusion = ptr(w.inclusion(5, 0))
	other, tr := otherTSA(t, w)
	other.WithoutCert()
	cut := w.now.Add(2 * time.Hour)
	now := w.now.Add(48 * time.Hour)
	st := archiveOver(t, w, other, 5, cut.Add(-time.Hour))
	tr.TSARevocations = checkedToo(t, compromised(t, w.tsa, cut, now), other)
	b.Archive = []ArchiveStamp{st}
	if r := Verify(b, tr); r.Valid() || !strings.Contains(r.Text(), "does not put its certificate in its time-stamps, and the bundle does not carry it") {
		t.Fatalf("без сертификата второй службы:\n%s", r.Text())
	}
	st.Certs = [][]byte{other.Cert().Raw}
	b.Archive = []ArchiveStamp{st}
	if r := Verify(b, tr); !r.Valid() {
		t.Fatalf("пакет несёт сертификат второй службы, её корень дан:\n%s", r.Text())
	}
	st.Certs = [][]byte{other.Cert().Raw, {0x30, 0x03, 0x02, 0x01, 0x01}}
	b.Archive = []ArchiveStamp{st}
	if r := Verify(b, tr); r.Valid() || !strings.Contains(r.Text(), "carries a certificate that does not parse") {
		t.Fatalf("испорченный сертификат второй службы:\n%s", r.Text())
	}
}

// Вторая служба под промежуточным центром, её токены не несут сертификатов
// вовсе: пакет несёт сертификат службы и её центра (журнал хранит их), и
// проверяющему довольно корня. Без центра в пакете — подсказка о центрах ниже
// корня.
func TestRevocationArchiveCarriesChain(t *testing.T) {
	w, b := standard(t, nil)
	b.Upper.Inclusion = ptr(w.inclusion(5, 0))
	key := func() *ecdsa.PrivateKey {
		k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		return k
	}
	issue := func(serial int64, cn string, ca bool, k *ecdsa.PrivateKey, parent *x509.Certificate, pk *ecdsa.PrivateKey) *x509.Certificate {
		tmpl := &x509.Certificate{SerialNumber: big.NewInt(serial), Subject: pkix.Name{CommonName: cn}, NotBefore: w.now.Add(-24 * time.Hour), NotAfter: w.now.Add(365 * 24 * time.Hour)}
		if ca {
			tmpl.IsCA, tmpl.BasicConstraintsValid, tmpl.KeyUsage = true, true, x509.KeyUsageCertSign|x509.KeyUsageCRLSign
		} else {
			tmpl.KeyUsage, tmpl.ExtKeyUsage = x509.KeyUsageDigitalSignature, []x509.ExtKeyUsage{x509.ExtKeyUsageTimeStamping}
		}
		if parent == nil {
			parent, pk = tmpl, k
		}
		der, err := x509.CreateCertificate(rand.Reader, tmpl, parent, k.Public(), pk)
		if err != nil {
			t.Fatal(err)
		}
		c, _ := x509.ParseCertificate(der)
		return c
	}
	kRoot, kInter, kTSA := key(), key(), key()
	root := issue(1, "chain root", true, kRoot, nil, nil)
	inter := issue(2, "chain issuing CA", true, kInter, root, kRoot)
	leaf := issue(3, "chain second TSA", false, kTSA, inter, kInter)
	other := tsa.AuthorityWith(kTSA, leaf, root)
	other.WithoutCert()
	cut := w.now.Add(2 * time.Hour)
	now := w.now.Add(48 * time.Hour)
	st := archiveOver(t, w, other, 5, cut.Add(-time.Hour))
	tr := w.trust()
	tr.TSA.Roots.AddCert(root)
	tr.TSARevocations = compromised(t, w.tsa, cut, now)
	for i, c := range []struct {
		ca  *x509.Certificate
		key *ecdsa.PrivateKey
	}{{root, kRoot}, {inter, kInter}} {
		der, err := x509.CreateRevocationList(rand.Reader, &x509.RevocationList{Number: big.NewInt(int64(i + 1)), ThisUpdate: now.Add(-time.Hour), NextUpdate: now.Add(time.Hour)}, c.ca, c.key)
		if err != nil {
			t.Fatal(err)
		}
		p := filepath.Join(t.TempDir(), "chain.crl")
		if err := os.WriteFile(p, der, 0o600); err != nil {
			t.Fatal(err)
		}
		if err := tr.TSARevocations.AddCRL(p); err != nil {
			t.Fatal(err)
		}
	}
	st.Certs = [][]byte{leaf.Raw}
	b.Archive = []ArchiveStamp{st}
	if r := Verify(b, tr); r.Valid() || !strings.Contains(r.Text(), "and its CAs below the root") {
		t.Fatalf("пакет несёт только сертификат службы, не её центр:\n%s", r.Text())
	}
	st.Certs = [][]byte{leaf.Raw, inter.Raw}
	b.Archive = []ArchiveStamp{st}
	if r := Verify(b, tr); !r.Valid() {
		t.Fatalf("пакет несёт сертификаты службы и её центра, корень дан:\n%s", r.Text())
	}
}
