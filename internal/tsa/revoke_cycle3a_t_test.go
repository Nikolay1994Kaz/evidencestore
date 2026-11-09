package tsa

// Тестировщик, цикл 3, заход 1 (чёрный ящик): воспроизведение находок.

import (
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"testing"
	"time"
)

// Центр (ключ K1) выпущен корнем A и перекрёстно корнем B; центр сменил ключ
// на K2 (выпущен корнем A) и отозвал сертификат службы по компрометации CRL
// нового ключа. Проверяющий дал оба корня и сертификат нового ключа. Метки
// подписаны одним ключом службы; честные токены несут сертификат центра от
// корня A, токены подделывающего — только перекрёстный (корень B). Ключ
// службы и запись о нём одни и те же — вердикт должен быть один: компрометация
// в счёт. Факт: через перекрёстную цепочку «корень сертификата» — B, CRL
// нового ключа «не известен», и метка проходит с «не проверено».
func TestC3aTCrossChainUntiesNewKeyCRL(t *testing.T) {
	dir := t.TempDir()
	rootA := issue(t, caTmpl(1, "c3t root A"), newKey(t), nil)
	rootB := issue(t, caTmpl(2, "c3t root B"), newKey(t), nil)
	k1 := newKey(t)
	ca := issue(t, caTmpl(10, "c3t TSA CA"), k1, rootA)           // ключ K1 под корнем A
	caX := issue(t, caTmpl(11, "c3t TSA CA"), k1, rootB)          // тот же ключ K1, перекрёстно под B
	caNew := issue(t, caTmpl(12, "c3t TSA CA"), newKey(t), rootA) // новый ключ K2 под корнем A
	gen := day(2026, 10, 1)
	leaf := issue(t, &x509.Certificate{SerialNumber: big.NewInt(77), Subject: pkix.Name{CommonName: "c3t TSA"},
		NotBefore: day(2021, 1, 1), NotAfter: day(2030, 1, 1),
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageTimeStamping}}, newKey(t), ca)
	a := &Authority{key: leaf.key, cert: leaf.cert, root: ca.cert, policy: demoPolicy, Now: func() time.Time { return gen }}
	imprint := sha256.Sum256([]byte("head"))
	token, err := a.Sign(imprint[:], nil)
	if err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	roots.AddCert(rootA.cert)
	roots.AddCert(rootB.cert)
	honest, err := Verify(token, imprint, Trust{Roots: roots, Intermediates: []*x509.Certificate{ca.cert}})
	if err != nil {
		t.Fatal(err)
	}
	forged, err := Verify(token, imprint, Trust{Roots: roots, Intermediates: []*x509.Certificate{caX.cert}})
	if err != nil {
		t.Fatal(err)
	}
	r := NewRevocations(day(2026, 11, 10))
	if err := r.AddCRL(ca.crlOf(t, dir, "k1.crl", day(2026, 11, 1), day(2026, 12, 1), nil)); err != nil {
		t.Fatal(err)
	}
	if err := r.AddCRL(caNew.crlOf(t, dir, "k2.crl", day(2026, 11, 9), day(2026, 12, 9), nil,
		x509.RevocationListEntry{SerialNumber: leaf.cert.SerialNumber, RevocationTime: day(2026, 9, 1), ReasonCode: ReasonKeyCompromise})); err != nil {
		t.Fatal(err)
	}
	run := func(info Info) Verdict {
		as := r.NewAssessment()
		as.KnownTrusted(rootA.cert, rootB.cert, caNew.cert) // -tsa-trust проверяющего
		i, err := as.Add(info.Chains, info.GenTime)
		if err != nil {
			t.Fatal(err)
		}
		return as.Verdicts()[i]
	}
	if v := run(honest); !v.NeedPOE {
		t.Fatalf("честная цепочка (через корень A): компрометация не в счёт: %+v", v)
	}
	if v := run(forged); !v.NeedPOE {
		t.Errorf("цепочка через перекрёстный сертификат центра (корень B): CRL нового ключа центра не в счёт, метка проходит; Unchecked=%d, notes=%q", len(v.Unchecked), v.Notes)
	}
}
