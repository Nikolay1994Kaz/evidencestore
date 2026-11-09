package tsa

// Ревью цикла 2, заход 2 (r2): находки по диффу ecad1a9..4d4f528.

import (
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"strings"
	"testing"
)

// R2-A. Сертификат вне цепочек (Known: -tsa-trust или сертификат токена) был
// на удержании и снят с него: более новый CRL, годный для статуса, его не
// называет вовсе. У сертификата цепочки judge такое удержание снимает; у
// Known — signed() берёт записи всех CRL без снятия, и ключ под подозрением с
// даты удержания навсегда.
func TestC2bR2KnownHoldNeverReleased(t *testing.T) {
	dir := t.TempDir()
	root := issue(t, caTmpl(1, "hold root"), newKey(t), nil)
	ca := issue(t, caTmpl(10, "TSA CA"), newKey(t), root)
	kTSA := newKey(t)
	x0T := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "TSA"}, NotBefore: day(2024, 1, 1), NotAfter: day(2027, 12, 31),
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageTimeStamping}}
	x0 := issue(t, x0T, kTSA, ca)
	x1T := *x0T
	x1T.SerialNumber, x1T.NotBefore, x1T.NotAfter = big.NewInt(2), day(2026, 6, 1), day(2030, 12, 31)
	x1 := issue(t, &x1T, kTSA, ca)
	pool := x509.NewCertPool()
	pool.AddCert(root.cert)
	trust := Trust{Roots: pool, Intermediates: []*x509.Certificate{ca.cert}}
	info1 := renewedStamp(t, x1, root, day(2026, 10, 1), trust) // цепочка через X1
	info0 := renewedStamp(t, x0, root, day(2026, 3, 1), trust)  // цепочка через X0

	r := NewRevocations(day(2026, 11, 2))
	// X0 на удержании с 30.04, снят: CRL от 01.06 его не называет.
	r.AddCRL(ca.crlOf(t, dir, "held.crl", day(2026, 5, 1), day(2026, 6, 1), nil,
		x509.RevocationListEntry{SerialNumber: x0.cert.SerialNumber, RevocationTime: day(2026, 4, 30), ReasonCode: ReasonCertificateHold}))
	r.AddCRL(ca.crlOf(t, dir, "released.crl", day(2026, 11, 1), day(2026, 12, 1), nil))
	r.AddCRL(root.crlOf(t, dir, "root.crl", day(2026, 11, 1), day(2026, 12, 1), nil))

	// X0 в цепочке другой метки той же оценки: удержание снято.
	a := r.NewAssessment()
	i1, _ := a.Add(info1.Chains, info1.GenTime)
	a.Add(info0.Chains, info0.GenTime)
	if v := a.Verdicts()[i1]; v.NeedPOE {
		t.Errorf("X0 в цепочке: удержание не снято: %+v", v)
	}
	// X0 только известен (-tsa-trust): то же удержание держит ключ.
	a = r.NewAssessment()
	a.Known(x0.cert)
	i1, _ = a.Add(info1.Chains, info1.GenTime)
	if v := a.Verdicts()[i1]; v.NeedPOE {
		t.Errorf("X0 в Known: снятое удержание ставит ключ под подозрение (ложная тревога): NeedPOE=%v cutoff=%v from=%q", v.NeedPOE, v.Cutoff, v.Entry.From)
	}
}

// R2-C. Центр сменил ключ (P-162), сертификат нового ключа дан (Known). CRL
// нового ключа называет службу: superseded после метки (служба сменила
// сертификат). Записи в счёт (заметка «its entries count»), но статус —
// «не проверен»: judge не знает, что путь CRL сверен. Отзыв службы известен
// целиком, а метка по P-160 не POE.
func TestC2bR2RekeyedListingStillUnchecked(t *testing.T) {
	dir := t.TempDir()
	root := issue(t, caTmpl(1, "rekey root"), newKey(t), nil)
	caA := issue(t, caTmpl(10, "TSA CA"), newKey(t), root)
	caB := issue(t, caTmpl(11, "TSA CA"), newKey(t), root)
	gen := day(2026, 10, 1)
	leaf, info := tsaUnder(t, caA, day(2030, 1, 1), gen, []*x509.Certificate{root.cert}, caA.cert)
	r := NewRevocations(day(2026, 11, 2))
	r.AddCRL(caA.crlOf(t, dir, "old-key.crl", day(2026, 9, 15), day(2026, 12, 15), nil))
	r.AddCRL(caB.crlOf(t, dir, "new-key.crl", day(2026, 11, 1), day(2026, 12, 1), nil,
		x509.RevocationListEntry{SerialNumber: leaf.cert.SerialNumber, RevocationTime: day(2026, 10, 20), ReasonCode: ReasonSuperseded}))
	r.AddCRL(root.crlOf(t, dir, "root.crl", day(2026, 11, 1), day(2026, 12, 1), nil))
	a := r.NewAssessment()
	a.Known(caB.cert)
	i, err := a.Add(info.Chains, info.GenTime)
	if err != nil {
		t.Fatal(err)
	}
	v := a.Verdicts()[i]
	if v.NeedPOE || v.Retired != nil {
		t.Fatalf("superseded после метки: %+v", v)
	}
	counts := hasNote(v, "its entries")
	notChecked := hasNote(v, "was not checked")
	if len(v.Unchecked) != 0 {
		t.Errorf("CRL нового ключа сверен и в счёт (%v), а статус службы «не проверен» (%v): unchecked=%d, notes=%q", counts, notChecked, len(v.Unchecked), strings.Join(v.Notes, " | "))
	}
}
