package proof

// Находки захода 1 второго цикла (FINDINGS, P-157…) сквозь пакет.

import (
	"crypto"
	"crypto/ecdsa"
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

	"github.com/Nikolay1994Kaz/evidencestore/internal/auditchain"
	"github.com/Nikolay1994Kaz/evidencestore/internal/tsa"
)

// c2ca — сертификат и ключ: центр или служба.
type c2ca struct {
	cert *x509.Certificate
	key  crypto.Signer
}

func c2date(y int, m time.Month, d int) time.Time { return time.Date(y, m, d, 0, 0, 0, 0, time.UTC) }

// c2issue — сертификат центра (isCA) или службы меток от parent (nil —
// самоподписанный).
func c2issue(t *testing.T, serial int64, cn string, isCA bool, from, to time.Time, k crypto.Signer, parent *c2ca) *c2ca {
	t.Helper()
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(serial), Subject: pkix.Name{CommonName: cn}, NotBefore: from, NotAfter: to}
	if isCA {
		tmpl.KeyUsage, tmpl.BasicConstraintsValid, tmpl.IsCA = x509.KeyUsageCertSign|x509.KeyUsageCRLSign, true, true
	} else {
		tmpl.KeyUsage, tmpl.ExtKeyUsage = x509.KeyUsageDigitalSignature, []x509.ExtKeyUsage{x509.ExtKeyUsageTimeStamping}
	}
	pc, pk := tmpl, k
	if parent != nil {
		pc, pk = parent.cert, parent.key
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, pc, k.Public(), pk)
	if err != nil {
		t.Fatal(err)
	}
	c, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return &c2ca{c, k}
}

func c2key(t *testing.T) crypto.Signer {
	t.Helper()
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return k
}

// c2crl — CRL центра ca от this в сведения revs.
func c2crl(t *testing.T, revs *tsa.Revocations, ca *c2ca, this time.Time, entries ...x509.RevocationListEntry) {
	t.Helper()
	der, err := x509.CreateRevocationList(rand.Reader, &x509.RevocationList{Number: big.NewInt(this.Unix()), ThisUpdate: this, NextUpdate: this.Add(30 * 24 * time.Hour),
		RevokedCertificateEntries: entries}, ca.cert, ca.key)
	if err != nil {
		t.Fatal(err)
	}
	p := filepath.Join(t.TempDir(), "c2.crl")
	if err := os.WriteFile(p, der, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := revs.AddCRL(p); err != nil {
		t.Fatal(err)
	}
}

// c2bundle — пакет одной улики, T1 ставит служба t1a, T2 — t2a.
func c2bundle(t *testing.T, w *world, t1a, t2a *tsa.Authority) Bundle {
	t.Helper()
	w.wlink(auditchain.Leaf{Type: auditchain.EventStart})
	w.tsa = t1a
	h1, t1 := w.stamp()
	w.now = w.now.Add(time.Second)
	w.wlink(tokenLeaf(h1, t1))
	e1 := sealedBytes(t, 1, w.now.Add(time.Second), "first")
	e2 := sealedBytes(t, 2, w.now.Add(2*time.Second), "second")
	w.now = w.now.Add(3 * time.Second)
	w.wlink(evLeaf(t, e1, 1), evLeaf(t, e2, 2))
	w.wlink(auditchain.Leaf{Type: auditchain.EventGap, Scope: "abs-core"})
	w.now = w.now.Add(time.Second)
	w.tsa = t2a
	h4, t2 := w.stamp()
	w.wlink(tokenLeaf(h4, t2))
	b := w.bundle(e2, 3, 1, h4, t2, 2)
	b.Upper.Inclusion = ptr(w.inclusion(5, 0))
	return b
}

// P-157 сквозь пакет. Удержание в H, затем keyCompromise с датой R > H
// (удержание сделано постоянным); свидетель подписал голову T2 в P, H < P <
// R. С обоими CRL отсечка — H, и подпись свидетеля T2 не спасает.
func TestRevocationHoldMadePermanentBundle(t *testing.T) {
	w, b := standard(t, nil)
	b.Upper.Inclusion = ptr(w.inclusion(5, 0))
	t2 := Verify(b, w.trust()).Upper
	H, P, R := t2.Add(10*time.Minute), t2.Add(30*time.Minute), t2.Add(2*time.Hour)
	now := R.Add(2 * time.Hour)
	s := cosigner(t, "witness.example/w1")
	b.Cosignatures = []Cosignature{w.cosigned(s, 5, w.root(5), P)}
	serial := w.tsa.Cert().SerialNumber
	tr := cosignTrust(w, s)
	tr.TSARevocations = tsa.NewRevocations(now)
	for _, c := range []struct {
		this   time.Time
		entry  x509.RevocationListEntry
		reason string
	}{
		{H.Add(5 * time.Minute), x509.RevocationListEntry{SerialNumber: serial, RevocationTime: H, ReasonCode: tsa.ReasonCertificateHold}, "hold"},
		{R.Add(time.Hour), x509.RevocationListEntry{SerialNumber: serial, RevocationTime: R, ReasonCode: tsa.ReasonKeyCompromise}, "permanent"},
	} {
		der, err := w.tsa.RevocationList(c.this, now.Add(time.Hour), c.entry)
		if err != nil {
			t.Fatal(err)
		}
		p := filepath.Join(t.TempDir(), c.reason+".crl")
		os.WriteFile(p, der, 0o600)
		if err := tr.TSARevocations.AddCRL(p); err != nil {
			t.Fatal(err)
		}
	}
	if r := Verify(b, tr); r.Valid() || !strings.Contains(revocationCheck(t, r.Checks).Detail, "certificateHold") {
		t.Fatalf("удержание, сделанное постоянным, — POE после H спасла:\n%s", r.Text())
	}
}

// P-160 сквозь пакет. Метка второй службы, чей отзыв не проверен (CRL её
// центра не дан), — не POE: время другой метки показывает только метка,
// прошедшая проверку (ETSI EN 319 102-1). Отчёт говорит, чего не хватило.
func TestRevocationPOEOnlyFromCheckedStamp(t *testing.T) {
	w, b := standard(t, nil)
	b.Upper.Inclusion = ptr(w.inclusion(5, 0))
	other, tr := otherTSA(t, w)
	cut := w.now.Add(2 * time.Hour)
	tr.TSARevocations = compromised(t, w.tsa, cut, w.now.Add(48*time.Hour))
	b.Archive = []ArchiveStamp{archiveOver(t, w, other, 5, cut.Add(-time.Hour))}
	if r := Verify(b, tr); r.Valid() || !strings.Contains(revocationCheck(t, r.Checks).Detail, "the revocation of its own certificate was not checked") {
		t.Fatalf("POE от метки с непроверенным отзывом:\n%s", r.Text())
	}
	tr.TSARevocations = checkedToo(t, compromised(t, w.tsa, cut, w.now.Add(48*time.Hour)), other)
	if r := Verify(b, tr); !r.Valid() {
		t.Fatalf("POE от метки с проверенным отзывом:\n%s", r.Text())
	}
}

// Центр сменил ключ; CRL нового ключа называет службу прежнего отозванной.
// Подпись такого CRL с цепочкой меток не сверить (срез 10.11: путь нового
// ключа к корню не строится, с его сертификатом в -tsa-trust или без него):
// записи не в счёт, отзыв службы «не проверен», пакет проходит, и заметка
// говорит, что делать. Проверяющий, который этому CRL верит, называет
// сертификат службы в перечне — и пакет без POE не проходит.
func TestRevocationOtherKeyCRLNotChecked(t *testing.T) {
	root := c2issue(t, 1, "rekey root", true, c2date(2020, 1, 1), c2date(2040, 1, 1), c2key(t), nil)
	caA := c2issue(t, 10, "TSA CA", true, c2date(2020, 1, 1), c2date(2040, 1, 1), c2key(t), root)
	caB := c2issue(t, 11, "TSA CA", true, c2date(2026, 1, 1), c2date(2040, 1, 1), c2key(t), root)
	leaf := c2issue(t, 77, "main TSA", false, c2date(2024, 1, 1), c2date(2030, 1, 1), c2key(t), caA)
	run := func(reason int, at func(time.Time) time.Time, listed bool, inter ...*x509.Certificate) Report {
		w := newWorld(t)
		a := tsa.AuthorityWith(leaf.key, leaf.cert, root.cert)
		a.Now = func() time.Time { return w.now }
		b := c2bundle(t, w, a, a)
		pool := x509.NewCertPool()
		pool.AddCert(root.cert)
		tr := Trust{StoreKey: w.signer.PublicKey(), TSA: tsa.Trust{Roots: pool, Intermediates: inter}}
		t2 := Verify(b, tr).Upper
		tr.TSARevocations = tsa.NewRevocations(w.now.Add(30 * 24 * time.Hour))
		c2crl(t, tr.TSARevocations, caA, w.now.Add(-time.Hour))
		c2crl(t, tr.TSARevocations, caB, w.now.Add(29*24*time.Hour), x509.RevocationListEntry{SerialNumber: leaf.cert.SerialNumber, RevocationTime: at(t2), ReasonCode: reason})
		c2crl(t, tr.TSARevocations, root, w.now.Add(29*24*time.Hour))
		if listed {
			list := filepath.Join(t.TempDir(), "mine.json")
			os.WriteFile(list, []byte(fmt.Sprintf(`[{"cert_sha256": %q, "revoked": %q, "reason": "keyCompromise"}]`, tsa.Fingerprint(leaf.cert), at(t2).Format(time.RFC3339))), 0o600)
			if err := tr.TSARevocations.AddList(list); err != nil {
				t.Fatal(err)
			}
		}
		return Verify(b, tr)
	}
	soon := func(now time.Time) time.Time { return now.Add(time.Hour) }
	before := func(now time.Time) time.Time { return now.Add(-time.Second) }
	for name, r := range map[string]Report{
		"сертификата нового ключа нет":               run(tsa.ReasonKeyCompromise, soon, false, caA.cert),
		"сертификат нового ключа в -tsa-trust":       run(tsa.ReasonKeyCompromise, soon, false, caA.cert, caB.cert),
		"выведен из работы до T2 в CRL нового ключа": run(tsa.ReasonSuperseded, before, false, caA.cert, caB.cert),
	} {
		if !r.Valid() || !strings.Contains(r.Text(), "did the CA change its key?") || !strings.Contains(r.Text(), "list the certificate with -tsa-revoked") ||
			!strings.Contains(revocationCheck(t, r.Checks).Detail, "the revocation of 1 certificates was not checked") {
			t.Errorf("%s:\n%s", name, r.Text())
		}
	}
	if r := run(tsa.ReasonKeyCompromise, soon, true, caA.cert); r.Valid() || !strings.Contains(revocationCheck(t, r.Checks).Detail, "mine.json") {
		t.Fatalf("служба названа в перечне проверяющего:\n%s", r.Text())
	}
}
