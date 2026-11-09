package proof

// Ревью цикла 2, заход 2 (r1): гипотезы сквозь пакет.

import (
	"crypto/x509"
	"crypto/x509/pkix"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Nikolay1994Kaz/evidencestore/internal/tsa"
)

// c2crlAt — CRL центра ca с thisUpdate this и nextUpdate next.
func r1crl(t *testing.T, revs *tsa.Revocations, ca *c2ca, this, next time.Time, entries ...x509.RevocationListEntry) {
	t.Helper()
	before := len(revs.CRLs())
	c2crl(t, revs, ca, this, entries...)
	_ = before
	_ = next
}

// H1 сквозь пакет. Служба перевыпущена на тот же ключ: метки идут через X1
// (истёк), текущий X2 дан в -tsa-trust. Центр сменил ключ и отозвал X2
// (выпущенный прежним ключом) по компрометации уже новым ключом;
// сертификат нового ключа центра тоже в -tsa-trust. Ни второй службы, ни
// свидетеля: пакет обязан не пройти. Проходит.
func TestRevocationC2bRenewedTSARevokedByRekeyedCABundle(t *testing.T) {
	root := c2issue(t, 1, "r1 root", true, c2date(2020, 1, 1), c2date(2040, 1, 1), c2key(t), nil)
	caOld := c2issue(t, 10, "TSA CA", true, c2date(2020, 1, 1), c2date(2040, 1, 1), c2key(t), root)
	caNew := c2issue(t, 11, "TSA CA", true, c2date(2026, 9, 1), c2date(2040, 1, 1), c2key(t), root)
	kTSA := c2key(t)
	x1 := c2issue(t, 1, "main TSA", false, c2date(2024, 1, 1), c2date(2026, 6, 30), kTSA, caOld)
	x2 := c2issue(t, 2, "main TSA", false, c2date(2026, 6, 1), c2date(2029, 1, 1), kTSA, caOld)
	run := func(inter ...*x509.Certificate) Report {
		w := newWorld(t)
		w.now = time.Date(2026, 3, 1, 10, 0, 0, 0, time.UTC)
		a := tsa.AuthorityWith(kTSA, x1.cert, root.cert)
		a.Now = func() time.Time { return w.now }
		b := c2bundle(t, w, a, a)
		pool := x509.NewCertPool()
		pool.AddCert(root.cert)
		tr := Trust{StoreKey: w.signer.PublicKey(), TSA: tsa.Trust{Roots: pool, Intermediates: inter}}
		tr.TSARevocations = tsa.NewRevocations(c2date(2027, 3, 10))
		c2crl(t, tr.TSARevocations, caOld, c2date(2026, 3, 2))
		c2crl(t, tr.TSARevocations, caNew, c2date(2027, 3, 1), x509.RevocationListEntry{SerialNumber: x2.cert.SerialNumber, RevocationTime: c2date(2027, 2, 20), ReasonCode: tsa.ReasonKeyCompromise})
		c2crl(t, tr.TSARevocations, root, c2date(2027, 3, 1))
		return Verify(b, tr)
	}
	r := run(caOld.cert, caNew.cert, x2.cert)
	t.Logf("verdict valid=%v\n%s", r.Valid(), r.Text())
	if r.Valid() {
		t.Errorf("ключ службы отозван по компрометации (X2 в -tsa-trust, CRL нового ключа центра, сертификат нового ключа в -tsa-trust), POE нет — пакет прошёл")
	}
}

// H2 сквозь пакет. X2 (тот же ключ, текущий) был на удержании и снят;
// проверяющий дал X2 в -tsa-trust, как велит документ, и все CRL центра.
// Честный пакет без второй службы не проходит.
func TestRevocationC2bRenewedTSAReleasedHoldBundle(t *testing.T) {
	root := c2issue(t, 1, "r1 root", true, c2date(2020, 1, 1), c2date(2040, 1, 1), c2key(t), nil)
	ca := c2issue(t, 10, "TSA CA", true, c2date(2020, 1, 1), c2date(2040, 1, 1), c2key(t), root)
	kTSA := c2key(t)
	x1 := c2issue(t, 1, "main TSA", false, c2date(2024, 1, 1), c2date(2026, 6, 30), kTSA, ca)
	x2 := c2issue(t, 2, "main TSA", false, c2date(2026, 6, 1), c2date(2029, 1, 1), kTSA, ca)
	run := func(inter ...*x509.Certificate) Report {
		w := newWorld(t)
		w.now = time.Date(2026, 3, 1, 10, 0, 0, 0, time.UTC)
		a := tsa.AuthorityWith(kTSA, x1.cert, root.cert)
		a.Now = func() time.Time { return w.now }
		b := c2bundle(t, w, a, a)
		pool := x509.NewCertPool()
		pool.AddCert(root.cert)
		tr := Trust{StoreKey: w.signer.PublicKey(), TSA: tsa.Trust{Roots: pool, Intermediates: inter}}
		tr.TSARevocations = tsa.NewRevocations(c2date(2027, 3, 10))
		c2crl(t, tr.TSARevocations, ca, c2date(2026, 3, 2))
		c2crl(t, tr.TSARevocations, ca, c2date(2026, 11, 2), x509.RevocationListEntry{SerialNumber: x2.cert.SerialNumber, RevocationTime: c2date(2026, 11, 1), ReasonCode: tsa.ReasonCertificateHold})
		c2crl(t, tr.TSARevocations, ca, c2date(2027, 3, 1))
		c2crl(t, tr.TSARevocations, root, c2date(2027, 3, 1))
		return Verify(b, tr)
	}
	if r := run(ca.cert); !r.Valid() {
		t.Fatalf("контроль: без X2 в -tsa-trust:\n%s", r.Text())
	}
	r := run(ca.cert, x2.cert)
	t.Logf("with X2 in -tsa-trust valid=%v\n%s", r.Valid(), r.Text())
	if !r.Valid() {
		t.Errorf("X2 в -tsa-trust, удержание X2 снято — честный пакет не прошёл")
	}
}

// H5 сквозь пакет. Две демо-службы (имена и номера одни, ключи разные):
// основная отозвана по компрометации после меток, метка второй — над
// головой T2 раньше отсечки. Проверяющий дал CRL обеих; CRL основной на
// минуту новее CRL второй. Честный пакет не проходит: «revocation of its
// own certificate was not checked … pass the CRL of its CA».
func TestRevocationC2bNamesakeDemoTSAsBundle(t *testing.T) {
	w, b := standard(t, nil)
	b.Upper.Inclusion = ptr(w.inclusion(5, 0))
	other, tr := otherTSA(t, w)
	cut := w.now.Add(2 * time.Hour)
	now := w.now.Add(48 * time.Hour)
	b.Archive = []ArchiveStamp{archiveOver(t, w, other, 5, cut.Add(-time.Hour))}
	run := func(mainLater time.Duration) Report {
		revs := tsa.NewRevocations(now)
		write := func(a *tsa.Authority, this time.Time, name string, entries ...x509.RevocationListEntry) {
			der, err := a.RevocationList(this, now.Add(time.Hour), entries...)
			if err != nil {
				t.Fatal(err)
			}
			p := filepath.Join(t.TempDir(), name)
			os.WriteFile(p, der, 0o600)
			if err := revs.AddCRL(p); err != nil {
				t.Fatal(err)
			}
		}
		write(other, now.Add(-time.Hour), "second.crl")
		write(w.tsa, now.Add(-time.Hour+mainLater), "main.crl", x509.RevocationListEntry{SerialNumber: w.tsa.Cert().SerialNumber, RevocationTime: cut, ReasonCode: tsa.ReasonKeyCompromise})
		tr.TSARevocations = revs
		return Verify(b, tr)
	}
	if r := run(0); !r.Valid() {
		t.Fatalf("контроль: CRL выпущены в одну секунду:\n%s", r.Text())
	}
	r := run(time.Minute)
	t.Logf("main CRL a minute newer: valid=%v\n%s", r.Valid(), r.Text())
	if !r.Valid() {
		t.Errorf("CRL основной службы на минуту новее CRL второй (тёзки) — честный пакет не прошёл")
	}
}

// H4 сквозь пакет. Центр второй службы сменил ключ и в CRL нового ключа
// назвал её сертификат выведенным из работы (superseded) после её метки;
// сертификат нового ключа центра — в -tsa-trust (как велит документ).
// Основная служба отозвана по компрометации. Метка второй службы в силе и
// показала бы существование, но её сертификат «не проверен» — пакет не
// проходит.
func TestRevocationC2bSecondTSARekeyedCASupersededBundle(t *testing.T) {
	w, b := standard(t, nil)
	b.Upper.Inclusion = ptr(w.inclusion(5, 0))
	cut := w.now.Add(2 * time.Hour)
	now := w.now.Add(48 * time.Hour)
	root2 := c2issue(t, 1, "second root", true, c2date(2020, 1, 1), c2date(2040, 1, 1), c2key(t), nil)
	caOld := c2issue(t, 10, "second CA", true, c2date(2020, 1, 1), c2date(2040, 1, 1), c2key(t), root2)
	caNew := c2issue(t, 11, "second CA", true, c2date(2026, 9, 1), c2date(2040, 1, 1), c2key(t), root2)
	leaf := c2issue(t, 7, "second TSA", false, c2date(2024, 1, 1), c2date(2030, 1, 1), c2key(t), caOld)
	other := tsa.AuthorityWith(leaf.key, leaf.cert, root2.cert)
	b.Archive = []ArchiveStamp{archiveOver(t, w, other, 5, cut.Add(-time.Hour))}
	tr := w.trust()
	tr.TSA.Roots.AddCert(root2.cert)
	tr.TSA.Intermediates = append(tr.TSA.Intermediates, caOld.cert, caNew.cert)
	revs := tsa.NewRevocations(now)
	der, _ := w.tsa.RevocationList(now.Add(-time.Hour), now.Add(time.Hour), x509.RevocationListEntry{SerialNumber: w.tsa.Cert().SerialNumber, RevocationTime: cut, ReasonCode: tsa.ReasonKeyCompromise})
	p := filepath.Join(t.TempDir(), "main.crl")
	os.WriteFile(p, der, 0o600)
	if err := revs.AddCRL(p); err != nil {
		t.Fatal(err)
	}
	c2crl(t, revs, caOld, now.Add(-10*24*time.Hour))
	c2crl(t, revs, caNew, now.Add(-time.Hour), x509.RevocationListEntry{SerialNumber: leaf.cert.SerialNumber, RevocationTime: cut.Add(time.Hour), ReasonCode: tsa.ReasonSuperseded})
	c2crl(t, revs, root2, now.Add(-time.Hour))
	tr.TSARevocations = revs
	r := Verify(b, tr)
	t.Logf("valid=%v\n%s", r.Valid(), r.Text())
	if !r.Valid() && strings.Contains(r.Text(), "the revocation of its own certificate was not checked") {
		t.Errorf("метка второй службы в силе (superseded после неё, CRL нового ключа признан), но не POE: честный пакет не прошёл")
	}
}

// H7 сквозь пакет. Сертификат второй службы истёк (служба сменила
// сертификат), её метка над головой T2 — до истечения и до отсечки основной.
// Основная отозвана по компрометации позже. Проверяющий даёт свежий CRL
// центра второй службы — истёкшего сертификата в нём нет (RFC 5280, 3.3), он
// «не проверен», и метка не POE. CRL второй службы хранилище не хранит, и в
// пакете его нет: честный пакет не проходит, хотя до P-160 проходил.
func TestRevocationC2bSecondTSAExpiredCertBundle(t *testing.T) {
	w, b := standard(t, nil)
	b.Upper.Inclusion = ptr(w.inclusion(5, 0))
	cut := w.now.Add(2 * time.Hour)
	now := w.now.Add(60 * 24 * time.Hour)
	root2 := c2issue(t, 1, "second root", true, c2date(2020, 1, 1), c2date(2040, 1, 1), c2key(t), nil)
	leaf := c2issue(t, 7, "second TSA", false, c2date(2024, 1, 1), w.now.Add(30*24*time.Hour), c2key(t), root2)
	other := tsa.AuthorityWith(leaf.key, leaf.cert, root2.cert)
	b.Archive = []ArchiveStamp{archiveOver(t, w, other, 5, cut.Add(-time.Hour))}
	tr := w.trust()
	tr.TSA.Roots.AddCert(root2.cert)
	revs := tsa.NewRevocations(now)
	der, _ := w.tsa.RevocationList(now.Add(-time.Hour), now.Add(time.Hour), x509.RevocationListEntry{SerialNumber: w.tsa.Cert().SerialNumber, RevocationTime: cut, ReasonCode: tsa.ReasonKeyCompromise})
	p := filepath.Join(t.TempDir(), "main.crl")
	os.WriteFile(p, der, 0o600)
	if err := revs.AddCRL(p); err != nil {
		t.Fatal(err)
	}
	c2crl(t, revs, root2, now.Add(-time.Hour))
	tr.TSARevocations = revs
	// Записано в limitations.md: без CRL её центра того времени, когда её
	// сертификат действовал, статус метки второй службы не известен, и она не
	// POE (ETSI EN 319 102-1); отчёт говорит, какой CRL дать.
	r := Verify(b, tr)
	if r.Valid() || !strings.Contains(r.Text(), "from before then too") || !strings.Contains(r.Text(), "the revocation of its own certificate was not checked") {
		t.Fatalf("сертификат второй службы истёк до свежего CRL:\n%s", r.Text())
	}
	// С CRL её центра того времени — POE.
	c2crl(t, revs, root2, leaf.cert.NotAfter.Add(-24*time.Hour))
	if r := Verify(b, tr); !r.Valid() {
		t.Fatalf("сертификат второй службы истёк, CRL того времени дан:\n%s", r.Text())
	}
}

// H6 сквозь пакет. Поле certificates токена не подписано: к метке второй
// службы можно дописать сертификаты, и подпись токена сойдётся. Все они идут
// в оценку (Known), и Verdicts сверяет подпись на каждой паре Known × pool
// с совпавшими именами.
func TestRevocationC2bJunkCertsInArchiveTokens(t *testing.T) {
	w, b := standard(t, nil)
	root2 := c2issue(t, 1, "second root", true, c2date(2020, 1, 1), c2date(2040, 1, 1), c2key(t), nil)
	leaf := c2issue(t, 7, "second TSA", false, c2date(2024, 1, 1), c2date(2030, 1, 1), c2key(t), root2)
	k := c2key(t)
	var junk []*x509.Certificate
	for i := range 520 {
		subj, iss := "A", "B"
		if i%2 == 1 {
			subj, iss = "B", "A"
		}
		parent := &c2ca{&x509.Certificate{Subject: pkix.Name{CommonName: iss}}, k}
		c := c2issue(t, int64(1000+i), subj, false, c2date(2025, 1, 1), c2date(2030, 1, 1), k, parent)
		junk = append(junk, c.cert)
	}
	tr := w.trust()
	tr.TSA.Roots.AddCert(root2.cert)
	for i := 0; i < len(junk); i += 130 {
		a := tsa.AuthorityWith(leaf.key, leaf.cert, root2.cert)
		a.Carry(junk[i:min(i+130, len(junk))]...)
		st := archiveOver(t, w, a, 5, w.now.Add(time.Hour))
		if len(st.Token) > tsa.MaxTokenSize {
			t.Fatalf("token %d bytes", len(st.Token))
		}
		b.Archive = append(b.Archive, st)
	}
	tr.TSARevocations = checkedToo(t, tsa.NewRevocations(w.now.Add(48*time.Hour)), w.tsa)
	start := time.Now()
	r := Verify(b, tr)
	if took := time.Since(start); took > 5*time.Second || !r.Valid() {
		t.Fatalf("%d junk certs in %d archive tokens: Verify took %v, valid=%v\n%s", len(junk), len(b.Archive), took, r.Valid(), r.Text())
	}
}
