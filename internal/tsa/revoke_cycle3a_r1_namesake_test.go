package tsa

import (
	"crypto/x509"
	"math/big"
	"testing"
)

// N1. Два разных центра одного имени «TSA CA» (разные организации, номера по
// порядку): под первым — основная служба (номер 2), под вторым — вторая служба;
// корни обоих проверяющий доверяет (иначе вторая служба не проверится). CRL
// второго центра отзывает по компрометации свой сертификат с номером 2.
// limitations.md: «the newer CRL of one makes a certificate of the other with
// the same number not checked». 14762ae: «не проверено» (как записано).
// ea88e88: запись засчитана — ключ основной службы под подозрением.
func TestC3R1NamesakeUnderTrustedRootCounts(t *testing.T) {
	dir := t.TempDir()
	rootA := issue(t, caTmpl(1, "c3r1q root A"), newKey(t), nil)
	caA := issue(t, caTmpl(1, "c3r1q TSA CA"), newKey(t), rootA)
	rootB := issue(t, caTmpl(1, "c3r1q root B"), newKey(t), nil)
	caB := issue(t, caTmpl(1, "c3r1q TSA CA"), newKey(t), rootB)
	x := issue(t, r1leafTmpl(2, "TSA A", day(2025, 1, 1), day(2029, 1, 1)), newKey(t), caA)
	pool := x509.NewCertPool()
	pool.AddCert(rootA.cert)
	pool.AddCert(rootB.cert)
	infoA := renewedStamp(t, x, rootA, day(2026, 10, 15), Trust{Roots: pool, Intermediates: []*x509.Certificate{caA.cert}})
	_, infoB := tsaUnder(t, caB, day(2030, 1, 1), day(2026, 10, 15), []*x509.Certificate{rootA.cert, rootB.cert}, caB.cert)
	r := NewRevocations(day(2026, 11, 10))
	r.AddCRL(caA.crlOf(t, dir, "a.crl", day(2026, 11, 1), day(2026, 12, 1), nil))
	r.AddCRL(caB.crlOf(t, dir, "b.crl", day(2026, 11, 2), day(2026, 12, 2), nil,
		x509.RevocationListEntry{SerialNumber: big.NewInt(2), RevocationTime: day(2026, 9, 1), ReasonCode: ReasonKeyCompromise}))
	r.AddCRL(rootA.crlOf(t, dir, "rootA.crl", day(2026, 11, 1), day(2026, 12, 1), nil))
	r.AddCRL(rootB.crlOf(t, dir, "rootB.crl", day(2026, 11, 1), day(2026, 12, 1), nil))
	a := r.NewAssessment()
	a.KnownTrusted(rootA.cert, rootB.cert)
	i, err := a.Add(infoA.Chains, infoA.GenTime)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := a.Add(infoB.Chains, infoB.GenTime); err != nil {
		t.Fatal(err)
	}
	v := a.Verdicts()[i]
	t.Logf("NeedPOE=%v Unchecked=%d Entry.From=%q", v.NeedPOE, len(v.Unchecked), v.Entry.From)
	// Цикл 3, заход 1: цена правила корней проверяющего (limitations.md) —
	// центр того же имени под корнем -tsa-trust считается тем же центром.
	if !v.NeedPOE {
		t.Errorf("CRL центра-тёзки под доверенным корнем: по limitations.md его записи в счёт, а ключ не под подозрением")
	}
}
