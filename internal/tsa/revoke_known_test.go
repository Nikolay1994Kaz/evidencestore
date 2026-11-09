package tsa

// Тестировщик T, цикл 2 заход 2: сертификаты вне цепочек (Known) — удержание.

import (
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"testing"
	"time"
)

// Служба перевыпущена на тот же ключ: X1 — в цепочке метки, X1r — только в
// оценке (-tsa-trust или токен его несёт). X1r был на удержании, затем центр
// удержание снял (CRL новее, годный для статуса, X1r не называет). Если X1r в
// цепочке какой-либо метки — удержание снято, ключ не под подозрением. Если
// X1r только Known — запись об удержании остаётся навсегда, и честная метка
// после даты удержания требует POE.
func TestRevocationsC2bTKnownHoldReleased(t *testing.T) {
	dir := t.TempDir()
	root := issue(t, caTmpl(1, "known hold root"), newKey(t), nil)
	ca := issue(t, caTmpl(20, "known hold CA"), newKey(t), root)
	kTSA := newKey(t)
	x1T := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "TSA"}, NotBefore: day(2024, 1, 1), NotAfter: day(2028, 12, 31),
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageTimeStamping}}
	x1 := issue(t, x1T, kTSA, ca)
	x1rT := *x1T
	x1rT.SerialNumber, x1rT.NotBefore = big.NewInt(2), day(2026, 6, 1)
	x1r := issue(t, &x1rT, kTSA, ca)
	pool := x509.NewCertPool()
	pool.AddCert(root.cert)
	trust := Trust{Roots: pool, Intermediates: []*x509.Certificate{ca.cert}}
	stampX1 := renewedStamp(t, x1, root, day(2026, 10, 10), trust)
	stampX1r := renewedStamp(t, x1r, root, day(2026, 10, 10), trust)

	r := NewRevocations(day(2026, 10, 21))
	// CRL1: X1r на удержании с 4.10; CRL2 (позже): X1r не назван — удержание снято.
	r.AddCRL(ca.crlOf(t, dir, "held.crl", day(2026, 10, 5), day(2026, 11, 5), nil,
		x509.RevocationListEntry{SerialNumber: x1r.cert.SerialNumber, RevocationTime: day(2026, 10, 4), ReasonCode: ReasonCertificateHold}))
	r.AddCRL(ca.crlOf(t, dir, "released.crl", day(2026, 10, 20), day(2026, 11, 20), nil))

	// 1) X1r в цепочке другой метки той же оценки: удержание снято.
	a := r.NewAssessment()
	i, err := a.Add(stampX1.Chains, stampX1.GenTime)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := a.Add(stampX1r.Chains, stampX1r.GenTime); err != nil {
		t.Fatal(err)
	}
	vChain := a.Verdicts()[i]
	t.Logf("X1r в цепочке: NeedPOE=%v cutoff=%v", vChain.NeedPOE, vChain.Cutoff)

	// 2) X1r только в оценке (Known), как советует bundles.md: «Give every
	// certificate of a key you know of in -tsa-trust».
	b := r.NewAssessment()
	b.Known(x1r.cert)
	j, err := b.Add(stampX1.Chains, stampX1.GenTime)
	if err != nil {
		t.Fatal(err)
	}
	vKnown := b.Verdicts()[j]
	t.Logf("X1r Known: NeedPOE=%v cutoff=%v from=%s", vKnown.NeedPOE, vKnown.Cutoff, vKnown.Entry.From)

	if vChain.NeedPOE {
		t.Errorf("X1r в цепочке: удержание снято, а ключ под подозрением: %+v", vChain)
	}
	if vKnown.NeedPOE != vChain.NeedPOE {
		t.Errorf("один и тот же сертификат, те же CRL: в цепочке — NeedPOE=%v, вне цепочки (Known) — NeedPOE=%v (удержание вне цепочки не снимается)", vChain.NeedPOE, vKnown.NeedPOE)
	}
}

// Служба продлена на тот же ключ (X1 — в цепочке метки, X1r — текущий, дан в
// -tsa-trust), центр сменил ключ (caNew: то же имя, новый ключ, тот же корень,
// дан в -tsa-trust) и отозвал X1r по компрометации в CRL нового ключа (openssl
// ca с прежней базой). Каждое условие по отдельности ловится (X1r в CRL
// прежнего ключа — P-161; X1 в CRL нового ключа — P-162), вместе — нет: ключ
// не под подозрением, метка после отсечки проходит без POE.
func TestRevocationsC2bTKnownRevokedInRekeyedCRL(t *testing.T) {
	dir := t.TempDir()
	root := issue(t, caTmpl(1, "rekey+renew root"), newKey(t), nil)
	caOld := issue(t, caTmpl(10, "TSA CA"), newKey(t), root)
	caNew := issue(t, caTmpl(11, "TSA CA"), newKey(t), root) // смена ключа центра
	kTSA := newKey(t)
	x1T := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "TSA"}, NotBefore: day(2024, 1, 1), NotAfter: day(2028, 12, 31),
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageTimeStamping}}
	x1 := issue(t, x1T, kTSA, caOld)
	x1rT := *x1T
	x1rT.SerialNumber, x1rT.NotBefore = big.NewInt(2), day(2026, 6, 1)
	x1r := issue(t, &x1rT, kTSA, caOld) // продление на тот же ключ, до смены ключа центра
	pool := x509.NewCertPool()
	pool.AddCert(root.cert)
	stamp := renewedStamp(t, x1, root, day(2026, 10, 10), Trust{Roots: pool, Intermediates: []*x509.Certificate{caOld.cert}})
	cutoff := day(2026, 10, 1) // компрометация раньше метки: метку не спасёт ничто

	verdict := func(crl string) Verdict {
		r := NewRevocations(day(2026, 10, 21))
		r.AddCRL(caOld.crlOf(t, dir, "old-key.crl", day(2026, 9, 15), day(2026, 12, 15), nil))
		r.AddCRL(crl)
		a := r.NewAssessment()
		a.Known(caNew.cert, x1r.cert) // всё, что советует bundles.md, — в -tsa-trust
		i, err := a.Add(stamp.Chains, stamp.GenTime)
		if err != nil {
			t.Fatal(err)
		}
		return a.Verdicts()[i]
	}
	kc := func(serial *big.Int) x509.RevocationListEntry {
		return x509.RevocationListEntry{SerialNumber: serial, RevocationTime: cutoff, ReasonCode: ReasonKeyCompromise}
	}
	if v := verdict(caOld.crlOf(t, dir, "old-key-x1r.crl", day(2026, 10, 20), day(2026, 11, 20), nil, kc(x1r.cert.SerialNumber))); !v.NeedPOE {
		t.Errorf("контроль: X1r в CRL прежнего ключа — ключ не под подозрением: %+v", v)
	}
	if v := verdict(caNew.crlOf(t, dir, "new-key-x1.crl", day(2026, 10, 20), day(2026, 11, 20), nil, kc(x1.cert.SerialNumber))); !v.NeedPOE {
		t.Errorf("контроль: X1 в CRL нового ключа — ключ не под подозрением: %+v", v)
	}
	if v := verdict(caNew.crlOf(t, dir, "new-key-x1r.crl", day(2026, 10, 20), day(2026, 11, 20), nil, kc(x1r.cert.SerialNumber))); !v.NeedPOE {
		t.Errorf("X1r (дан в -tsa-trust) отозван по компрометации в CRL нового ключа центра (его сертификат дан в -tsa-trust, тот же корень): ключ не под подозрением, метка %v после отсечки %v проходит: %+v",
			stamp.GenTime.Format(time.DateOnly), cutoff.Format(time.DateOnly), v)
	}
}
