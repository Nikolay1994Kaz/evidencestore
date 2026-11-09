package proof

// Ревью цикла 2, заход 2 (r2): находки по диффу ecad1a9..4d4f528 сквозь пакет.

import (
	"crypto/rand"
	"crypto/x509"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Nikolay1994Kaz/evidencestore/internal/tsa"
)

// r2crl — CRL демо-службы a (её корня) с thisUpdate this.
func r2crl(t *testing.T, r *tsa.Revocations, a *tsa.Authority, name string, this time.Time, entries ...x509.RevocationListEntry) {
	t.Helper()
	der, err := a.RevocationList(this, this.Add(72*time.Hour), entries...)
	if err != nil {
		t.Fatal(err)
	}
	p := filepath.Join(t.TempDir(), name)
	if err := os.WriteFile(p, der, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := r.AddCRL(p); err != nil {
		t.Fatal(err)
	}
}

// R2-B сквозь пакет. Основная и вторая службы — демо (имя корня и номер
// службы у всех одни). Ключ основной украден: её CRL отзывает номер 2 и
// выпущен на два часа позже чистого CRL второй. Метка второй службы раньше
// отсечки — настоящая POE, её CRL дан; но CRL основной для сертификата второй
// — «CRL тёзки новее статусного, называет номер»: отзыв второй «не проверен»,
// по P-160 она не POE, и честный пакет не проходит. С CRL второй того же
// часа — проходит.
func TestC2bR2TwinDemoArchiveCannotRescue(t *testing.T) {
	for _, c := range []struct {
		name string
		lag  time.Duration
		want bool
	}{{"CRL второй того же часа", 0, true}, {"CRL второй на 2 ч старше", 2 * time.Hour, true}} {
		w, b := standard(t, nil)
		b.Upper.Inclusion = ptr(w.inclusion(5, 0))
		other, tr := otherTSA(t, w)
		cut := w.now.Add(2 * time.Hour)
		now := w.now.Add(48 * time.Hour)
		r := tsa.NewRevocations(now)
		r2crl(t, r, other, "other.crl", now.Add(-time.Hour-c.lag))
		r2crl(t, r, w.tsa, "main.crl", now.Add(-time.Hour),
			x509.RevocationListEntry{SerialNumber: w.tsa.Cert().SerialNumber, RevocationTime: cut, ReasonCode: tsa.ReasonKeyCompromise})
		tr.TSARevocations = r
		b.Archive = []ArchiveStamp{archiveOver(t, w, other, 5, cut.Add(-time.Hour))}
		rep := Verify(b, tr)
		if rep.Valid() != c.want {
			t.Errorf("%s: valid=%v, ждали %v:\n%s", c.name, rep.Valid(), c.want, rep.Text())
		}
	}
}

// R2-A сквозь пакет. Ни один сертификат не скомпрометирован. Служба
// перевыпущена на тот же ключ (X0 → X1); X0 когда-то был на удержании и
// снят. Проверяющий, как велит -tsa-trust («any other certificates of the
// TSAs … one issued again on the same key too») и bundles.md («pass every CRL
// of a CA you have, old ones too»), даёт X0 и все CRL центра. Метки через X1
// — под подозрением с даты снятого удержания X0, и честный пакет без POE не
// проходит. Без X0 в -tsa-trust — проходит.
func TestC2bR2KnownHoldFailsHonestBundle(t *testing.T) {
	root := c2issue(t, 1, "hold root", true, c2date(2020, 1, 1), c2date(2040, 1, 1), c2key(t), nil)
	ca := c2issue(t, 10, "TSA CA", true, c2date(2020, 1, 1), c2date(2040, 1, 1), c2key(t), root)
	kTSA := c2key(t)
	x0 := c2issue(t, 1, "main TSA", false, c2date(2024, 1, 1), c2date(2027, 12, 31), kTSA, ca)
	x1 := c2issue(t, 2, "main TSA", false, c2date(2026, 6, 1), c2date(2030, 12, 31), kTSA, ca)
	carry := false
	run := func(inter ...*x509.Certificate) Report {
		w := newWorld(t)
		a := tsa.AuthorityWith(kTSA, x1.cert, root.cert)
		a.Now = func() time.Time { return w.now }
		if carry {
			a.Carry(x0.cert) // служба кладёт в токен и прежний сертификат ключа
		}
		b := c2bundle(t, w, a, a)
		pool := x509.NewCertPool()
		pool.AddCert(root.cert)
		tr := Trust{StoreKey: w.signer.PublicKey(), TSA: tsa.Trust{Roots: pool, Intermediates: inter}}
		tr.TSARevocations = tsa.NewRevocations(c2date(2026, 11, 2))
		c2crl(t, tr.TSARevocations, ca, c2date(2026, 5, 1), x509.RevocationListEntry{SerialNumber: x0.cert.SerialNumber, RevocationTime: c2date(2026, 4, 30), ReasonCode: tsa.ReasonCertificateHold})
		c2crl(t, tr.TSARevocations, ca, c2date(2026, 11, 1))
		c2crl(t, tr.TSARevocations, root, c2date(2026, 11, 1))
		return Verify(b, tr)
	}
	if r := run(ca.cert); !r.Valid() {
		t.Fatalf("без X0 в -tsa-trust:\n%s", r.Text())
	}
	if r := run(ca.cert, x0.cert); !r.Valid() {
		t.Errorf("X0 (снятое удержание) в -tsa-trust — честный пакет не проходит:\n%s", r.Text())
	}
	carry = true
	if r := run(ca.cert); !r.Valid() {
		t.Errorf("X0 (снятое удержание) несёт сам токен — честный пакет не проходит, хотя проверяющий X0 не давал:\n%s", revocationCheck(t, r.Checks).Detail)
	}
}

// R2-C сквозь пакет. Ключ основной службы украден, вторая служба спасает.
// Центр второй сменил ключ (как в P-162: CRL нового ключа ведёт ту же базу),
// а сертификат второй службы позже меток выведен из работы (superseded,
// смена сертификата) — запись в CRL нового ключа. Проверяющий дал сертификат
// нового ключа центра в -tsa-trust, как просит заметка. Запись в счёт, но
// статус второй — «не проверен», по P-160 её метка не POE, и честный пакет
// не проходит.
func TestC2bR2RekeyedSecondTSACannotRescue(t *testing.T) {
	w, b := standard(t, nil)
	b.Upper.Inclusion = ptr(w.inclusion(5, 0))
	cut := w.now.Add(2 * time.Hour)
	now := w.now.Add(48 * time.Hour)
	root2 := c2issue(t, 1, "second root", true, c2date(2020, 1, 1), c2date(2040, 1, 1), c2key(t), nil)
	caA := c2issue(t, 10, "second TSA CA", true, c2date(2020, 1, 1), c2date(2040, 1, 1), c2key(t), root2)
	caB := c2issue(t, 11, "second TSA CA", true, c2date(2026, 1, 1), c2date(2040, 1, 1), c2key(t), root2)
	leaf2 := c2issue(t, 7, "second TSA", false, c2date(2024, 1, 1), c2date(2030, 1, 1), c2key(t), caA)
	other := tsa.AuthorityWith(leaf2.key, leaf2.cert, root2.cert)
	tr := w.trust()
	tr.TSA.Roots.AddCert(root2.cert)
	tr.TSA.Intermediates = []*x509.Certificate{caA.cert, caB.cert}
	r := tsa.NewRevocations(now)
	r2crl(t, r, w.tsa, "main.crl", now.Add(-time.Hour),
		x509.RevocationListEntry{SerialNumber: w.tsa.Cert().SerialNumber, RevocationTime: cut, ReasonCode: tsa.ReasonKeyCompromise})
	c2crl(t, r, caA, w.now.Add(-24*time.Hour))
	c2crl(t, r, caB, now.Add(-time.Hour), x509.RevocationListEntry{SerialNumber: leaf2.cert.SerialNumber, RevocationTime: cut.Add(24 * time.Hour), ReasonCode: tsa.ReasonSuperseded})
	c2crl(t, r, root2, now.Add(-time.Hour))
	tr.TSARevocations = r
	b.Archive = []ArchiveStamp{archiveOver(t, w, other, 5, cut.Add(-time.Hour))}
	rep := Verify(b, tr)
	if !rep.Valid() {
		t.Errorf("метка второй службы (отзыв известен: superseded после метки) не спасает:\n%s", rep.Text())
	}
	if !strings.Contains(rep.Text(), "its entries about certificate") {
		t.Logf("нет заметки о CRL нового ключа")
	}
	_ = rand.Reader
	_ = big.NewInt
}

// R2-E. Add и Verdicts: T2 не в силе по CRL нового ключа центра (superseded
// до T2) — Retired приходит из Verdicts. Пункт T2 и время приёма — «✔», не
// проходит только пункт об отзыве; при той же записи в CRL своего ключа
// (Add) — «✘» сам пункт T2. Отчёт разный для одного и того же «T2 не в силе».
func TestC2bR2RetiredLateReport(t *testing.T) {
	root := c2issue(t, 1, "rekey root", true, c2date(2020, 1, 1), c2date(2040, 1, 1), c2key(t), nil)
	caA := c2issue(t, 10, "TSA CA", true, c2date(2020, 1, 1), c2date(2040, 1, 1), c2key(t), root)
	caB := c2issue(t, 11, "TSA CA", true, c2date(2026, 1, 1), c2date(2040, 1, 1), c2key(t), root)
	leaf := c2issue(t, 77, "main TSA", false, c2date(2024, 1, 1), c2date(2030, 1, 1), c2key(t), caA)
	for _, signer := range []*c2ca{caA, caB} {
		w := newWorld(t)
		a := tsa.AuthorityWith(leaf.key, leaf.cert, root.cert)
		a.Now = func() time.Time { return w.now }
		b := c2bundle(t, w, a, a)
		pool := x509.NewCertPool()
		pool.AddCert(root.cert)
		tr := Trust{StoreKey: w.signer.PublicKey(), TSA: tsa.Trust{Roots: pool, Intermediates: []*x509.Certificate{caA.cert, caB.cert}}}
		t2 := Verify(b, tr).Upper
		tr.TSARevocations = tsa.NewRevocations(w.now.Add(30 * 24 * time.Hour))
		c2crl(t, tr.TSARevocations, caA, w.now.Add(-time.Hour))
		c2crl(t, tr.TSARevocations, signer, w.now.Add(29*24*time.Hour), x509.RevocationListEntry{SerialNumber: leaf.cert.SerialNumber, RevocationTime: t2.Add(-time.Second), ReasonCode: tsa.ReasonSuperseded})
		c2crl(t, tr.TSARevocations, root, w.now.Add(29*24*time.Hour))
		r := Verify(b, tr)
		for _, c := range r.Checks {
			if strings.HasPrefix(c.Name, "a TSA time-stamp over the chain after") || strings.HasPrefix(c.Name, "the receive time") || c.Name == revocationCheckName {
				t.Logf("CRL от %s: ok=%v %s — %.120s", signer.cert.SerialNumber, c.OK, c.Name[:30], c.Detail)
			}
		}
	}
}

// R2-H. Ключ службы сертифицирован двумя центрами одного корня: X1 (CA1) — в
// цепочках, X2 (CA2) — в -tsa-trust. CRL центра CA2 отзывает X2 по
// компрометации: ключ под подозрением (верно), а заметки говорят, что этот
// CRL «of no CA in the chains … : not used» — Named считает только центры
// цепочек.
func TestC2bR2KnownCRLReportedNotUsed(t *testing.T) {
	root := c2issue(t, 1, "root", true, c2date(2020, 1, 1), c2date(2040, 1, 1), c2key(t), nil)
	ca1 := c2issue(t, 10, "CA1", true, c2date(2020, 1, 1), c2date(2040, 1, 1), c2key(t), root)
	ca2 := c2issue(t, 11, "CA2", true, c2date(2020, 1, 1), c2date(2040, 1, 1), c2key(t), root)
	k := c2key(t)
	x1 := c2issue(t, 5, "main TSA", false, c2date(2024, 1, 1), c2date(2030, 1, 1), k, ca1)
	x2 := c2issue(t, 6, "main TSA", false, c2date(2024, 1, 1), c2date(2030, 1, 1), k, ca2)
	w := newWorld(t)
	a := tsa.AuthorityWith(k, x1.cert, root.cert)
	a.Now = func() time.Time { return w.now }
	b := c2bundle(t, w, a, a)
	pool := x509.NewCertPool()
	pool.AddCert(root.cert)
	tr := Trust{StoreKey: w.signer.PublicKey(), TSA: tsa.Trust{Roots: pool, Intermediates: []*x509.Certificate{ca1.cert, ca2.cert, x2.cert}}}
	tr.TSARevocations = tsa.NewRevocations(w.now.Add(48 * time.Hour))
	c2crl(t, tr.TSARevocations, ca1, w.now.Add(47*time.Hour))
	c2crl(t, tr.TSARevocations, ca2, w.now.Add(47*time.Hour), x509.RevocationListEntry{SerialNumber: x2.cert.SerialNumber, RevocationTime: w.now.Add(time.Hour), ReasonCode: tsa.ReasonKeyCompromise})
	c2crl(t, tr.TSARevocations, root, w.now.Add(47*time.Hour))
	r := Verify(b, tr)
	used := strings.Contains(revocationCheck(t, r.Checks).Detail, "with the same key")
	notUsed := false
	for _, n := range r.TSANotes {
		if strings.Contains(n, "is of no CA in the chains") {
			notUsed = true
			t.Logf("заметка: %s", n)
		}
	}
	if used && notUsed {
		t.Errorf("CRL центра CA2 сработал (ключ под подозрением), а отчёт называет его неиспользованным")
	}
}
