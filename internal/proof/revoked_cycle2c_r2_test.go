package proof

// Ревью цикла 2, заход 3 (r2): гипотезы сквозь пакет.

import (
	"crypto/x509"
	"strings"
	"testing"
	"time"

	"github.com/Nikolay1994Kaz/evidencestore/internal/tsa"
)

// N1 сквозь пакет. Трёхуровневый центр: корень продлён на тот же ключ (R1
// истёк 2026-12-31, R2 с 2026-06-01), Policy CA под ним, TSA CA под Policy CA
// сменил ключ (C2 с 2027-02-01). Метки 2026-03-01 — под C1 (прежний ключ).
// CRL нового ключа TSA CA (2027-03-01) отзывает службу по компрометации
// (2027-02-20). Проверяющий дал всё: R1, R2, Policy CA, C1, C2 и все CRL. Ни
// второй службы, ни свидетеля: пакет обязан не пройти (limitations.md).
func TestC2cR2RootRenewed3LevelRekeyedCABundle(t *testing.T) {
	kR := c2key(t)
	r1 := c2issue(t, 1, "r2c root", true, c2date(2016, 1, 1), c2date(2026, 12, 31), kR, nil)
	r2 := c2issue(t, 2, "r2c root", true, c2date(2026, 6, 1), c2date(2036, 12, 31), kR, nil)
	p := c2issue(t, 5, "Policy CA", true, c2date(2020, 1, 1), c2date(2040, 1, 1), c2key(t), r1)
	c1 := c2issue(t, 10, "TSA CA", true, c2date(2020, 1, 1), c2date(2040, 1, 1), c2key(t), p)
	c2 := c2issue(t, 11, "TSA CA", true, c2date(2027, 2, 1), c2date(2040, 1, 1), c2key(t), p)
	kTSA := c2key(t)
	x1 := c2issue(t, 1, "main TSA", false, c2date(2024, 1, 1), c2date(2029, 1, 1), kTSA, c1)
	w := newWorld(t)
	w.now = time.Date(2026, 3, 1, 10, 0, 0, 0, time.UTC)
	a := tsa.AuthorityWith(kTSA, x1.cert, r1.cert)
	a.Now = func() time.Time { return w.now }
	b := c2bundle(t, w, a, a)
	pool := x509.NewCertPool()
	pool.AddCert(r1.cert)
	pool.AddCert(r2.cert)
	tr := Trust{StoreKey: w.signer.PublicKey(), TSA: tsa.Trust{Roots: pool, Intermediates: []*x509.Certificate{p.cert, c1.cert, c2.cert}, RootCerts: []*x509.Certificate{r1.cert, r2.cert}}}
	tr.TSARevocations = tsa.NewRevocations(c2date(2027, 3, 10))
	c2crl(t, tr.TSARevocations, c1, c2date(2026, 12, 1))
	c2crl(t, tr.TSARevocations, c2, c2date(2027, 3, 1), x509.RevocationListEntry{SerialNumber: x1.cert.SerialNumber, RevocationTime: c2date(2027, 2, 20), ReasonCode: tsa.ReasonKeyCompromise})
	c2crl(t, tr.TSARevocations, p, c2date(2027, 3, 1))
	c2crl(t, tr.TSARevocations, r2, c2date(2027, 3, 1))
	r := Verify(b, tr)
	t.Logf("valid=%v\n%s", r.Valid(), r.Text())
	if r.Valid() {
		t.Errorf("ключ службы отозван по компрометации в CRL нового ключа её центра (тот же корень: имя и ключ), проверяющий дал всё, POE нет — пакет прошёл")
	}
}

// N2 сквозь пакет. Двухуровневый центр сменил ключ, C2 выпущен новым
// промежуточным центром корня; проверяющий дал C2 в -tsa-trust (как велит
// документ), промежуточного — нет. До диффа: «не проверено» и подсказка; после
// — «тёзка», «none found revoked», VERIFIED.
func TestC2cR2RekeyedCAMissingIntermediateBundle(t *testing.T) {
	root := c2issue(t, 1, "r2c root", true, c2date(2020, 1, 1), c2date(2040, 1, 1), c2key(t), nil)
	c1 := c2issue(t, 10, "TSA CA", true, c2date(2020, 1, 1), c2date(2040, 1, 1), c2key(t), root)
	pNew := c2issue(t, 6, "Issuing CA 2027", true, c2date(2027, 1, 1), c2date(2040, 1, 1), c2key(t), root)
	c2 := c2issue(t, 11, "TSA CA", true, c2date(2027, 2, 1), c2date(2040, 1, 1), c2key(t), pNew)
	kTSA := c2key(t)
	x1 := c2issue(t, 1, "main TSA", false, c2date(2024, 1, 1), c2date(2029, 1, 1), kTSA, c1)
	run := func(inter ...*x509.Certificate) Report {
		w := newWorld(t)
		w.now = time.Date(2026, 3, 1, 10, 0, 0, 0, time.UTC)
		a := tsa.AuthorityWith(kTSA, x1.cert, root.cert)
		a.Now = func() time.Time { return w.now }
		b := c2bundle(t, w, a, a)
		pool := x509.NewCertPool()
		pool.AddCert(root.cert)
		tr := Trust{StoreKey: w.signer.PublicKey(), TSA: tsa.Trust{Roots: pool, Intermediates: inter, RootCerts: []*x509.Certificate{root.cert}}}
		tr.TSARevocations = tsa.NewRevocations(c2date(2027, 3, 10))
		c2crl(t, tr.TSARevocations, c1, c2date(2026, 12, 1))
		c2crl(t, tr.TSARevocations, c2, c2date(2027, 3, 1), x509.RevocationListEntry{SerialNumber: x1.cert.SerialNumber, RevocationTime: c2date(2027, 2, 20), ReasonCode: tsa.ReasonKeyCompromise})
		c2crl(t, tr.TSARevocations, root, c2date(2027, 3, 1))
		return Verify(b, tr)
	}
	if r := run(c1.cert, c2.cert, pNew.cert); r.Valid() {
		t.Fatalf("контроль: с промежуточным пакет прошёл:\n%s", r.Text())
	}
	// Без промежуточного ключ C2 к корню не связать: компрометацию не
	// засчитать, но и «проверен» не сказать — «не проверено» и что дать
	// (пересмотр 10.11: тёзкой такой CRL не считается).
	r := run(c1.cert, c2.cert)
	rc := revocationCheck(t, r.Checks)
	if !strings.Contains(rc.Detail, "not checked") || !strings.Contains(r.Text(), "with the CA certificates between it and the root") {
		t.Errorf("C2 в -tsa-trust, без его промежуточного: отчёт не говорит, что отзыв не проверен и что дать:\n%s", r.Text())
	}
}

// N3 сквозь пакет. Как N1, но C2 проверяющий не давал (о смене ключа центра не
// знал; доверяет R1 и продлённому R2). Без лишней метки отчёт говорит «не
// проверено» (как обещает limitations.md). Сборщик пакета кладёт метку
// «второй службы» — токен той же службы под новым сертификатом (от C2) над
// головой пакета, с C2 и Policy CA в поле certificates (оно не подписано):
// C2 — в цепочке, «тёзка», и «не проверено» пропадает.
func TestC2cR2NamesakeForcedByArchiveStampBundle(t *testing.T) {
	kR := c2key(t)
	r1 := c2issue(t, 1, "r2c root", true, c2date(2016, 1, 1), c2date(2026, 12, 31), kR, nil)
	r2 := c2issue(t, 2, "r2c root", true, c2date(2026, 6, 1), c2date(2036, 12, 31), kR, nil)
	p := c2issue(t, 5, "Policy CA", true, c2date(2020, 1, 1), c2date(2040, 1, 1), c2key(t), r1)
	c1 := c2issue(t, 10, "TSA CA", true, c2date(2020, 1, 1), c2date(2040, 1, 1), c2key(t), p)
	c2 := c2issue(t, 11, "TSA CA", true, c2date(2027, 2, 1), c2date(2040, 1, 1), c2key(t), p)
	kTSA := c2key(t)
	x1 := c2issue(t, 1, "main TSA", false, c2date(2024, 1, 1), c2date(2029, 1, 1), kTSA, c1)
	xn := c2issue(t, 2, "main TSA", false, c2date(2027, 2, 25), c2date(2030, 1, 1), c2key(t), c2)
	w := newWorld(t)
	w.now = time.Date(2026, 3, 1, 10, 0, 0, 0, time.UTC)
	a := tsa.AuthorityWith(kTSA, x1.cert, r1.cert)
	a.Now = func() time.Time { return w.now }
	b := c2bundle(t, w, a, a)
	pool := x509.NewCertPool()
	pool.AddCert(r1.cert)
	pool.AddCert(r2.cert)
	tr := Trust{StoreKey: w.signer.PublicKey(), TSA: tsa.Trust{Roots: pool, Intermediates: []*x509.Certificate{p.cert, c1.cert}, RootCerts: []*x509.Certificate{r1.cert, r2.cert}}}
	tr.TSARevocations = tsa.NewRevocations(c2date(2027, 3, 10))
	c2crl(t, tr.TSARevocations, c1, c2date(2026, 12, 1))
	c2crl(t, tr.TSARevocations, c2, c2date(2027, 3, 1), x509.RevocationListEntry{SerialNumber: x1.cert.SerialNumber, RevocationTime: c2date(2027, 2, 20), ReasonCode: tsa.ReasonKeyCompromise})
	c2crl(t, tr.TSARevocations, p, c2date(2027, 3, 1))
	c2crl(t, tr.TSARevocations, r2, c2date(2027, 3, 1))
	r := Verify(b, tr)
	rc := revocationCheck(t, r.Checks)
	t.Logf("without the extra stamp: valid=%v detail=%q", r.Valid(), rc.Detail)
	if !strings.Contains(rc.Detail, "not checked") {
		t.Fatalf("контроль: без лишней метки ждали «не проверено»:\n%s", r.Text())
	}
	an := tsa.AuthorityWith(xn.key, xn.cert, r2.cert)
	an.Carry(c2.cert, p.cert)
	b.Archive = []ArchiveStamp{archiveOver(t, w, an, 5, c2date(2027, 3, 5))}
	r = Verify(b, tr)
	rc = revocationCheck(t, r.Checks)
	t.Logf("with the extra stamp: valid=%v\n%s", r.Valid(), r.Text())
	if !strings.Contains(rc.Detail, "not checked") && r.Valid() {
		t.Errorf("метка, положенная сборщиком пакета, сняла «не проверено»: ключ отозван по компрометации, отчёт — %q", rc.Detail)
	}
}

// A1. Вторая служба, чьи токены не несут её сертификат (P-182: журнал теперь
// хранит его в строке, cert). В пакет идёт только токен; проверяющий дал
// корень второй службы, как велит bundles.md («Give esverify the root of the
// second TSA in -tsa-trust too»). Основная отозвана по компрометации после
// меток; метка второй над головой T2 — раньше отсечки.
func TestC2cR2CertlessSecondTSAHint(t *testing.T) {
	w, b := standard(t, nil)
	b.Upper.Inclusion = ptr(w.inclusion(5, 0))
	other, tr := otherTSA(t, w)
	other.WithoutCert()
	cut := w.now.Add(2 * time.Hour)
	now := w.now.Add(48 * time.Hour)
	b.Archive = []ArchiveStamp{archiveOver(t, w, other, 5, cut.Add(-time.Hour))}
	tr.TSARevocations = checkedToo(t, compromised(t, w.tsa, cut, now), other)
	r := Verify(b, tr)
	t.Logf("valid=%v\n%s", r.Valid(), r.Text())
	if !r.Valid() && strings.Contains(r.Text(), "is the root of that TSA in -tsa-trust?") {
		t.Errorf("корень второй службы дан; не хватает её сертификата (его нет ни в токене, ни в пакете), а подсказка — про корень")
	}
}
