package proof

// Находки захода 1 второго цикла (FINDINGS, P-157…) сквозь пакет.

import (
	"crypto"
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

// P-161 сквозь пакет. Центр продлён на тот же ключ, корень отозвал текущий
// сертификат центра по компрометации, прежний истёк. Метки — под службой,
// выпущенной ключом центра временем до продления. С текущим сертификатом
// центра в -tsa-trust пакет не проходит; без него — проходит (из CRL ключа не
// узнать: limitations.md).
func TestRevocationRenewedCAKeyInTrust(t *testing.T) {
	root := c2issue(t, 1, "renewal root", true, c2date(2020, 1, 1), c2date(2040, 1, 1), c2key(t), nil)
	kCA := c2key(t)
	caOld := c2issue(t, 10, "TSA CA", true, c2date(2020, 1, 1), c2date(2026, 6, 30), kCA, root)
	caCur := c2issue(t, 11, "TSA CA", true, c2date(2026, 6, 1), c2date(2035, 1, 1), kCA, root)
	forged := c2issue(t, 99, "TSA", false, c2date(2025, 1, 1), c2date(2026, 6, 29), c2key(t), caOld)
	run := func(inter ...*x509.Certificate) Report {
		w := newWorld(t)
		w.now = time.Date(2026, 3, 1, 10, 0, 0, 0, time.UTC)
		a := tsa.AuthorityWith(forged.key, forged.cert, root.cert)
		a.Now = func() time.Time { return w.now }
		b := c2bundle(t, w, a, a)
		pool := x509.NewCertPool()
		pool.AddCert(root.cert)
		tr := Trust{StoreKey: w.signer.PublicKey(), TSA: tsa.Trust{Roots: pool, Intermediates: inter}}
		tr.TSARevocations = tsa.NewRevocations(c2date(2027, 3, 10))
		c2crl(t, tr.TSARevocations, root, c2date(2027, 3, 1), x509.RevocationListEntry{SerialNumber: caCur.cert.SerialNumber, RevocationTime: c2date(2027, 2, 20), ReasonCode: tsa.ReasonKeyCompromise})
		c2crl(t, tr.TSARevocations, root, c2date(2026, 6, 15))
		c2crl(t, tr.TSARevocations, caCur, c2date(2026, 6, 1))
		return Verify(b, tr)
	}
	if r := run(caOld.cert); !r.Valid() {
		t.Fatalf("без текущего сертификата центра:\n%s", r.Text())
	}
	if r := run(caOld.cert, caCur.cert); r.Valid() || !strings.Contains(revocationCheck(t, r.Checks).Detail, "with the same key") {
		t.Fatalf("текущий сертификат центра в -tsa-trust:\n%s", r.Text())
	}
}

// P-162 сквозь пакет. Центр сменил ключ; CRL нового ключа отзывает службу
// прежнего по компрометации. С сертификатом нового ключа в -tsa-trust пакет
// не проходит; без него проходит, и заметка говорит, что CRL называет
// службу и что дать. Вывод из работы до T2 в CRL нового ключа — T2 не в силе.
func TestRevocationRekeyedCAInTrust(t *testing.T) {
	root := c2issue(t, 1, "rekey root", true, c2date(2020, 1, 1), c2date(2040, 1, 1), c2key(t), nil)
	caA := c2issue(t, 10, "TSA CA", true, c2date(2020, 1, 1), c2date(2040, 1, 1), c2key(t), root)
	caB := c2issue(t, 11, "TSA CA", true, c2date(2026, 1, 1), c2date(2040, 1, 1), c2key(t), root)
	leaf := c2issue(t, 77, "main TSA", false, c2date(2024, 1, 1), c2date(2030, 1, 1), c2key(t), caA)
	run := func(reason int, at func(time.Time) time.Time, inter ...*x509.Certificate) Report {
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
		return Verify(b, tr)
	}
	soon := func(now time.Time) time.Time { return now.Add(time.Hour) }
	if r := run(tsa.ReasonKeyCompromise, soon, caA.cert); !r.Valid() || !strings.Contains(r.Text(), "pass that certificate in -tsa-trust") {
		t.Fatalf("сертификата нового ключа нет:\n%s", r.Text())
	}
	if r := run(tsa.ReasonKeyCompromise, soon, caA.cert, caB.cert); r.Valid() || !strings.Contains(r.Text(), "under a root of -tsa-trust") {
		t.Fatalf("сертификат нового ключа в -tsa-trust:\n%s", r.Text())
	}
	before := func(now time.Time) time.Time { return now.Add(-time.Second) }
	if r := run(tsa.ReasonSuperseded, before, caA.cert, caB.cert); r.Valid() || !strings.Contains(revocationCheck(t, r.Checks).Detail, "superseded") {
		t.Fatalf("выведен из работы до T2 в CRL нового ключа:\n%s", r.Text())
	}
}

// P-161, сертификаты токенов. Служба перевыпущена на тот же ключ (X1 истёк,
// X1r отозван по компрометации) и кладёт в токены оба сертификата: метки под
// X1 под подозрением. Так же — когда X1r несёт метка второй службы, а не
// свои.
func TestRevocationTokenCarriesRenewedCert(t *testing.T) {
	root := c2issue(t, 1, "renewal root", true, c2date(2020, 1, 1), c2date(2040, 1, 1), c2key(t), nil)
	ca := c2issue(t, 10, "TSA CA", true, c2date(2020, 1, 1), c2date(2040, 1, 1), c2key(t), root)
	kTSA := c2key(t)
	x1 := c2issue(t, 1, "main TSA", false, c2date(2024, 1, 1), c2date(2026, 12, 31), kTSA, ca)
	x1r := c2issue(t, 2, "main TSA", false, c2date(2026, 6, 1), c2date(2028, 12, 31), kTSA, ca)
	run := func(own bool) Report {
		w := newWorld(t)
		w.now = time.Date(2026, 3, 1, 10, 0, 0, 0, time.UTC)
		a := tsa.AuthorityWith(kTSA, x1.cert, root.cert)
		a.Now = func() time.Time { return w.now }
		if own {
			a.Carry(x1r.cert)
		}
		b := c2bundle(t, w, a, a)
		pool := x509.NewCertPool()
		pool.AddCert(root.cert)
		tr := Trust{StoreKey: w.signer.PublicKey(), TSA: tsa.Trust{Roots: pool, Intermediates: []*x509.Certificate{ca.cert}}}
		if !own {
			other, _ := otherTSA(t, w)
			tr.TSA.Roots.AddCert(other.Root())
			other.Carry(x1r.cert)
			b.Archive = []ArchiveStamp{archiveOver(t, w, other, 5, w.now)}
		}
		tr.TSARevocations = tsa.NewRevocations(c2date(2027, 3, 10))
		c2crl(t, tr.TSARevocations, ca, c2date(2027, 3, 1), x509.RevocationListEntry{SerialNumber: x1r.cert.SerialNumber, RevocationTime: c2date(2027, 2, 20), ReasonCode: tsa.ReasonKeyCompromise})
		c2crl(t, tr.TSARevocations, ca, c2date(2026, 12, 1))
		c2crl(t, tr.TSARevocations, root, c2date(2027, 3, 1))
		return Verify(b, tr)
	}
	for _, own := range []bool{true, false} {
		if r := run(own); r.Valid() || !strings.Contains(revocationCheck(t, r.Checks).Detail, "with the same key") {
			t.Fatalf("X1r в токенах (свои %v):\n%s", own, r.Text())
		}
	}
}

// twinRoot — корень с тем же именем, что у корня службы of, со своим ключом
// (центр-тёзка), и CRL от его имени.
func twinRoot(t *testing.T, of *tsa.Authority) (*x509.Certificate, func(this, next time.Time, es ...x509.RevocationListEntry) []byte) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{SerialNumber: of.Root().SerialNumber, RawSubject: of.Root().RawSubject, NotBefore: of.Root().NotBefore, NotAfter: of.Root().NotAfter,
		KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageCRLSign, BasicConstraintsValid: true, IsCA: true}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, key.Public(), key)
	if err != nil {
		t.Fatal(err)
	}
	root, _ := x509.ParseCertificate(der)
	return root, func(this, next time.Time, es ...x509.RevocationListEntry) []byte {
		der, err := x509.CreateRevocationList(rand.Reader, &x509.RevocationList{Number: big.NewInt(this.Unix()), ThisUpdate: this, NextUpdate: next, RevokedCertificateEntries: es}, root, key)
		if err != nil {
			t.Fatal(err)
		}
		return der
	}
}

// P-178, пересмотр 10.11 (и цикл 3, заход 1). Центр-тёзка второй службы
// (то же имя корня) и его более новый CRL с тем же номером: «другим центром»
// проверка его не признаёт — имя издателя и номер называют один сертификат.
// Корень тёзки дал проверяющий — это CRL того же центра под другим ключом:
// запись о компрометации в счёт, метка второй службы под подозрением, POE не
// даёт. Корня тёзки нет — CRL не связать с корнем: метка второй службы «не
// проверена», POE не даёт; отчёт называет CRL и что дать.
func TestRevocationNamesakeIsNotChecked(t *testing.T) {
	for _, trusted := range []bool{false, true} {
		w, b := standard(t, nil)
		b.Upper.Inclusion = ptr(w.inclusion(5, 0))
		other, tr := otherTSA(t, w)
		cut := w.now.Add(2 * time.Hour)
		now := w.now.Add(48 * time.Hour)
		b.Archive = []ArchiveStamp{archiveOver(t, w, other, 5, cut.Add(-time.Hour))}
		tr.TSARevocations = checkedToo(t, compromised(t, w.tsa, cut, now), other)
		if r := Verify(b, tr); !r.Valid() {
			t.Fatalf("контроль, без CRL тёзки:\n%s", r.Text())
		}
		root, crl := twinRoot(t, other)
		if trusted {
			tr.TSA.Roots.AddCert(root)
			tr.TSA.RootCerts = append(tr.TSA.RootCerts, root)
		}
		p := filepath.Join(t.TempDir(), "twin.crl")
		if err := os.WriteFile(p, crl(now.Add(-30*time.Minute), now.Add(time.Hour), x509.RevocationListEntry{SerialNumber: other.Cert().SerialNumber, RevocationTime: w.now, ReasonCode: tsa.ReasonKeyCompromise}), 0o600); err != nil {
			t.Fatal(err)
		}
		if err := tr.TSARevocations.AddCRL(p); err != nil {
			t.Fatal(err)
		}
		r := Verify(b, tr)
		want := "did the CA change its key?"
		if trusted {
			want = "itself: not used" // метка второй службы под подозрением
		}
		if r.Valid() || !strings.Contains(r.Text(), "twin.crl") || !strings.Contains(r.Text(), want) {
			t.Fatalf("CRL тёзки второй службы новее её CRL и называет её номер (корень тёзки дан: %v):\n%s", trusted, r.Text())
		}
	}
}
