package proof

// Ревью цикла 2, заход 3 (r1): гипотезы сквозь пакет.

import (
	"crypto/x509"
	"strings"
	"testing"
	"time"

	"github.com/Nikolay1994Kaz/evidencestore/internal/tsa"
)

// H1 сквозь пакет. Трёхуровневый УЦ: корень (продлён на тот же ключ: R1
// истёк, R2 действует) → промежуточный → центр службы. Центр сменил ключ
// (сертификат нового ключа — от того же промежуточного) и отозвал службу по
// компрометации CRL нового ключа; ключ украден до меток пакета
// (invalidityDate). Проверяющий дал всё: оба корня, промежуточный, оба
// сертификата центра — в -tsa-trust, CRL обоих ключей центра, промежуточного
// и корня. Ни второй службы, ни свидетеля: пакет обязан не пройти.
func TestR1C3RekeyedUnderIntermediateBundle(t *testing.T) {
	kRoot := c2key(t)
	r1 := c2issue(t, 1, "three-tier root", true, c2date(2016, 1, 1), c2date(2026, 12, 31), kRoot, nil)
	r2 := c2issue(t, 2, "three-tier root", true, c2date(2026, 6, 1), c2date(2036, 12, 31), kRoot, nil)
	inter := c2issue(t, 5, "policy CA", true, c2date(2016, 1, 1), c2date(2034, 1, 1), c2key(t), r1)
	caOld := c2issue(t, 10, "TSA CA", true, c2date(2016, 1, 1), c2date(2034, 1, 1), c2key(t), inter)
	caNew := c2issue(t, 11, "TSA CA", true, c2date(2027, 2, 16), c2date(2037, 1, 1), c2key(t), inter)
	leaf := c2issue(t, 77, "main TSA", false, c2date(2024, 1, 1), c2date(2030, 1, 1), c2key(t), caOld)

	w := newWorld(t)
	w.now = time.Date(2025, 10, 1, 10, 0, 0, 0, time.UTC)
	a := tsa.AuthorityWith(leaf.key, leaf.cert, r1.cert)
	a.Now = func() time.Time { return w.now }
	b := c2bundle(t, w, a, a)

	pool := x509.NewCertPool()
	pool.AddCert(r1.cert)
	pool.AddCert(r2.cert)
	tr := Trust{StoreKey: w.signer.PublicKey(), TSA: tsa.Trust{Roots: pool,
		Intermediates: []*x509.Certificate{inter.cert, caOld.cert, caNew.cert},
		RootCerts:     []*x509.Certificate{r1.cert, r2.cert}}}
	revs := tsa.NewRevocations(c2date(2027, 3, 10))
	c2crl(t, revs, caOld, c2date(2027, 2, 15))
	c2crl(t, revs, caNew, c2date(2027, 3, 1), x509.RevocationListEntry{SerialNumber: leaf.cert.SerialNumber,
		RevocationTime: c2date(2027, 2, 20), ReasonCode: tsa.ReasonKeyCompromise})
	c2crl(t, revs, inter, c2date(2027, 3, 1))
	c2crl(t, revs, r2, c2date(2027, 3, 1))
	tr.TSARevocations = revs
	r := Verify(b, tr)
	t.Logf("valid=%v\n%s", r.Valid(), r.Text())
	if r.Valid() {
		t.Errorf("служба отозвана по компрометации (CRL нового ключа центра, сертификат нового ключа в -tsa-trust), POE нет — пакет прошёл VERIFIED")
	}
	if strings.Contains(r.Text(), "another CA") {
		t.Errorf("отчёт называет CRL самого центра службы CRL центра-тёзки")
	}
}

// H1c сквозь пакет. Двухуровневый УЦ: центр сменил ключ (2026-09), сертификат
// нового ключа продлён на тот же ключ (2027-12). Служба отозвана по
// компрометации CRL нового ключа (2027-03); после истечения службы (2027-06)
// центр её из CRL убрал. Проверяющий дал корень, сертификат прежнего ключа
// центра и текущий сертификат нового ключа (-tsa-trust), все CRL. Ни второй
// службы, ни свидетеля: пакет обязан не пройти.
func TestR1C3RekeyedCACertRenewedLaterBundle(t *testing.T) {
	root := c2issue(t, 1, "two-tier root", true, c2date(2016, 1, 1), c2date(2040, 1, 1), c2key(t), nil)
	caOld := c2issue(t, 10, "TSA CA", true, c2date(2016, 1, 1), c2date(2034, 1, 1), c2key(t), root)
	kNew := c2key(t)
	caNew1 := c2issue(t, 11, "TSA CA", true, c2date(2026, 9, 1), c2date(2027, 12, 31), kNew, root)
	caNew2 := c2issue(t, 12, "TSA CA", true, c2date(2027, 12, 1), c2date(2032, 12, 31), kNew, root)
	leaf := c2issue(t, 77, "main TSA", false, c2date(2024, 1, 1), c2date(2027, 6, 1), c2key(t), caOld)

	w := newWorld(t)
	w.now = time.Date(2025, 10, 1, 10, 0, 0, 0, time.UTC)
	a := tsa.AuthorityWith(leaf.key, leaf.cert, root.cert)
	a.Now = func() time.Time { return w.now }
	b := c2bundle(t, w, a, a)

	pool := x509.NewCertPool()
	pool.AddCert(root.cert)
	tr := Trust{StoreKey: w.signer.PublicKey(), TSA: tsa.Trust{Roots: pool,
		Intermediates: []*x509.Certificate{caOld.cert, caNew2.cert},
		RootCerts:     []*x509.Certificate{root.cert}}}
	revs := tsa.NewRevocations(c2date(2028, 3, 10))
	c2crl(t, revs, caOld, c2date(2026, 8, 25))
	c2crl(t, revs, caNew1, c2date(2027, 3, 1), x509.RevocationListEntry{SerialNumber: leaf.cert.SerialNumber,
		RevocationTime: c2date(2027, 2, 20), ReasonCode: tsa.ReasonKeyCompromise})
	c2crl(t, revs, caNew2, c2date(2028, 3, 1))
	c2crl(t, revs, root, c2date(2028, 3, 1))
	tr.TSARevocations = revs
	r := Verify(b, tr)
	t.Logf("valid=%v\n%s", r.Valid(), r.Text())
	if r.Valid() {
		t.Errorf("служба отозвана по компрометации CRL нового ключа центра, сертификат нового ключа (продлённый) в -tsa-trust, POE нет — пакет прошёл VERIFIED")
	}
}

// H1c, активный вариант. Проверяющий НЕ дал сертификат нового ключа центра:
// без него отчёт честно говорит «not checked». Подделывающий прикладывает к
// пакету «метку второй службы» — настоящий токен любой службы под тем же
// центром (его новым ключом, текущий сертификат) над выдуманной головой. Её
// голова с пакетом не сходится, POE она не даёт (и заметки о ней нет: POE не
// понадобилась), но её цепочка «ручается» за сертификат нового ключа — и CRL,
// где служба отозвана по компрометации, становится CRL «тёзки».
func TestR1C3NamesakeByAttachedArchiveToken(t *testing.T) {
	root := c2issue(t, 1, "two-tier root", true, c2date(2016, 1, 1), c2date(2040, 1, 1), c2key(t), nil)
	caOld := c2issue(t, 10, "TSA CA", true, c2date(2016, 1, 1), c2date(2034, 1, 1), c2key(t), root)
	kNew := c2key(t)
	caNew1 := c2issue(t, 11, "TSA CA", true, c2date(2026, 9, 1), c2date(2027, 12, 31), kNew, root)
	caNew2 := c2issue(t, 12, "TSA CA", true, c2date(2027, 12, 1), c2date(2032, 12, 31), kNew, root)
	leaf := c2issue(t, 77, "main TSA", false, c2date(2024, 1, 1), c2date(2027, 6, 1), c2key(t), caOld)
	// Служба под текущим сертификатом нового ключа центра (её токен получит кто угодно).
	other := c2issue(t, 501, "another TSA of the CA", false, c2date(2028, 1, 1), c2date(2031, 1, 1), c2key(t), caNew2)

	w := newWorld(t)
	w.now = time.Date(2025, 10, 1, 10, 0, 0, 0, time.UTC)
	a := tsa.AuthorityWith(leaf.key, leaf.cert, root.cert)
	a.Now = func() time.Time { return w.now }
	b := c2bundle(t, w, a, a)

	pool := x509.NewCertPool()
	pool.AddCert(root.cert)
	tr := Trust{StoreKey: w.signer.PublicKey(), TSA: tsa.Trust{Roots: pool,
		Intermediates: []*x509.Certificate{caOld.cert},
		RootCerts:     []*x509.Certificate{root.cert}}}
	revs := tsa.NewRevocations(c2date(2028, 3, 10))
	c2crl(t, revs, caOld, c2date(2026, 8, 25))
	c2crl(t, revs, caNew1, c2date(2027, 3, 1), x509.RevocationListEntry{SerialNumber: leaf.cert.SerialNumber,
		RevocationTime: c2date(2027, 2, 20), ReasonCode: tsa.ReasonKeyCompromise})
	c2crl(t, revs, caNew2, c2date(2028, 3, 1))
	c2crl(t, revs, root, c2date(2028, 3, 1))
	tr.TSARevocations = revs

	r0 := Verify(b, tr)
	t.Logf("без приложенного токена: valid=%v, «not checked»=%v", r0.Valid(), strings.Contains(r0.Text(), "was not checked"))

	ot := tsa.AuthorityWith(other.key, other.cert, root.cert)
	ot.Carry(caNew2.cert)
	ot.Now = func() time.Time { return c2date(2028, 3, 1) }
	fake := [32]byte{7}
	imprint := HeadImprint(999, fake)
	token, err := ot.Sign(imprint[:], nil)
	if err != nil {
		t.Fatal(err)
	}
	b.Archive = append(b.Archive, ArchiveStamp{HeadSeq: 999, Root: fake[:], Token: token})
	r := Verify(b, tr)
	t.Logf("с приложенным токеном: valid=%v\n%s", r.Valid(), r.Text())
	if !strings.Contains(r0.Text(), "was not checked") {
		t.Fatalf("контроль: без приложенного токена отчёт должен говорить «not checked»")
	}
	if r.Valid() && !strings.Contains(r.Text(), "was not checked") {
		t.Errorf("приложенный к пакету чужой токен снял «not checked»: компрометация не в счёт, VERIFIED, «none found revoked»")
	}
}
