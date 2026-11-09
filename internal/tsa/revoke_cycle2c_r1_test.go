package tsa

// Ревью цикла 2, заход 3 (r1): гипотезы по диффу 2c7da6d..dcef3db.

import (
	"crypto/x509"
	"math/big"
	"strings"
	"testing"
	"time"
)

// r1c3Known — сертификаты, которые проверяющий дал в -tsa-trust (в оценку —
// как esverify: KnownTrusted).
func r1c3Known(a *Assessment, certs ...*x509.Certificate) { a.KnownTrusted(certs...) }

// H1. Трёхуровневый УЦ (корень → промежуточный → центр службы). Корень продлён
// на тот же ключ (R1 истёк, R2 действует, оба в -tsa-trust), центр службы
// сменил ключ: сертификат нового ключа выпущен тем же промежуточным центром
// и дан в -tsa-trust, как велит документ. CRL нового ключа отзывает службу по
// компрометации. Путь к корню R1 на дату CRL не строится (R1 истёк), прямой
// выпуск ключом корня (P-181) — только для центра под корнем. Сертификат
// нового ключа «ручается» (дан проверяющим), и rekeyedBy называет CRL
// тёзкой: «another CA … leads to another root», запись не в счёт, статус —
// по старому CRL («проверен»).
func TestR1C3RekeyedUnderIntermediateRootRenewed(t *testing.T) {
	dir := t.TempDir()
	kRoot := newKey(t)
	r1T := caTmpl(1, "three-tier root")
	r1T.NotBefore, r1T.NotAfter = day(2016, 1, 1), day(2026, 12, 31)
	r1 := issue(t, r1T, kRoot, nil)
	r2T := caTmpl(2, "three-tier root")
	r2T.NotBefore, r2T.NotAfter = day(2026, 6, 1), day(2036, 12, 31)
	r2 := issue(t, r2T, kRoot, nil)
	interT := caTmpl(5, "policy CA")
	interT.NotBefore, interT.NotAfter = day(2016, 1, 1), day(2034, 1, 1)
	inter := issue(t, interT, newKey(t), r1)
	caOld := issue(t, caTmpl(10, "TSA CA"), newKey(t), inter)
	caNewT := caTmpl(11, "TSA CA")
	caNewT.NotBefore = day(2027, 2, 1)
	caNew := issue(t, caNewT, newKey(t), inter)
	gen := day(2025, 10, 1)
	leaf, info := tsaUnder(t, caOld, day(2030, 1, 1), gen, []*x509.Certificate{r1.cert, r2.cert}, inter.cert, caOld.cert)
	for _, ch := range info.Chains {
		t.Logf("chain root serial %s", ch[len(ch)-1].SerialNumber)
	}
	r := NewRevocations(day(2027, 3, 10))
	// Последний CRL прежнего ключа — до смены ключа; после неё центр
	// подписывает CRL новым ключом (openssl ca: одна база, новый ключ).
	r.AddCRL(caOld.crlOf(t, dir, "old-key.crl", day(2027, 1, 25), day(2027, 4, 25), nil))
	r.AddCRL(caNew.crlOf(t, dir, "new-key.crl", day(2027, 3, 1), day(2027, 4, 1), nil,
		x509.RevocationListEntry{SerialNumber: leaf.cert.SerialNumber, RevocationTime: day(2027, 2, 20), ReasonCode: ReasonKeyCompromise}))
	r.AddCRL(r2.crlOf(t, dir, "root.crl", day(2027, 3, 1), day(2027, 4, 1), nil))
	r.AddCRL(inter.crlOf(t, dir, "inter.crl", day(2027, 3, 1), day(2027, 4, 1), nil))
	a := r.NewAssessment()
	r1c3Known(a, inter.cert, caOld.cert, caNew.cert, r1.cert, r2.cert)
	i, err := a.Add(info.Chains, info.GenTime)
	if err != nil {
		t.Fatal(err)
	}
	v := a.Verdicts()[i]
	t.Logf("NeedPOE=%v Unchecked=%d CRLs=%q", v.NeedPOE, len(v.Unchecked), v.CRLs)
	for _, n := range v.Notes {
		t.Logf("note: %s", n)
	}
	if !v.NeedPOE {
		misleading := ""
		for _, n := range v.Notes {
			if strings.Contains(n, "another CA") {
				misleading = " — и отчёт называет CRL центром-тёзкой: " + n
			}
		}
		t.Errorf("компрометация службы в CRL нового ключа центра не в счёт при всём, что дано (корни R1 и R2, промежуточный, оба ключа центра); Unchecked=%d%s", len(v.Unchecked), misleading)
	}
}

// H1b. То же без продления корня: промежуточный центр продлён на тот же ключ
// (прежний сертификат истёк к дате CRL), сертификат нового ключа центра
// службы выпущен им же. Дано всё, кроме продлённого промежуточного.
func TestR1C3RekeyedUnderRenewedIntermediate(t *testing.T) {
	dir := t.TempDir()
	root := issue(t, caTmpl(1, "three-tier root b"), newKey(t), nil)
	kInter := newKey(t)
	i1T := caTmpl(5, "policy CA b")
	i1T.NotBefore, i1T.NotAfter = day(2016, 1, 1), day(2026, 12, 31)
	i1 := issue(t, i1T, kInter, root)
	i2T := caTmpl(6, "policy CA b")
	i2T.NotBefore, i2T.NotAfter = day(2026, 6, 1), day(2036, 12, 31)
	i2 := issue(t, i2T, kInter, root)
	caOld := issue(t, caTmpl(10, "TSA CA b"), newKey(t), i1)
	caNewT := caTmpl(11, "TSA CA b")
	caNewT.NotBefore = day(2027, 2, 1)
	caNew := issue(t, caNewT, newKey(t), i2)
	gen := day(2025, 10, 1)
	leaf, info := tsaUnder(t, caOld, day(2030, 1, 1), gen, []*x509.Certificate{root.cert}, i1.cert, caOld.cert)
	r := NewRevocations(day(2027, 3, 10))
	r.AddCRL(caOld.crlOf(t, dir, "old-key.crl", day(2027, 1, 25), day(2027, 4, 25), nil))
	r.AddCRL(caNew.crlOf(t, dir, "new-key.crl", day(2027, 3, 1), day(2027, 4, 1), nil,
		x509.RevocationListEntry{SerialNumber: leaf.cert.SerialNumber, RevocationTime: day(2027, 2, 20), ReasonCode: ReasonKeyCompromise}))
	r.AddCRL(root.crlOf(t, dir, "root.crl", day(2027, 3, 1), day(2027, 4, 1), nil))
	r.AddCRL(i2.crlOf(t, dir, "inter.crl", day(2027, 3, 1), day(2027, 4, 1), nil))
	for _, withI2 := range []bool{false, true} {
		a := r.NewAssessment()
		r1c3Known(a, i1.cert, caOld.cert, caNew.cert, root.cert)
		if withI2 {
			r1c3Known(a, i2.cert)
		}
		i, err := a.Add(info.Chains, info.GenTime)
		if err != nil {
			t.Fatal(err)
		}
		v := a.Verdicts()[i]
		t.Logf("withI2=%v NeedPOE=%v Unchecked=%d CRLs=%q", withI2, v.NeedPOE, len(v.Unchecked), v.CRLs)
		for _, n := range v.Notes {
			t.Logf("  note: %s", n)
		}
		if !v.NeedPOE && len(v.Unchecked) == 0 {
			t.Errorf("withI2=%v: компрометация в CRL нового ключа центра не в счёт, а сертификат службы — «проверен» (статус по старому CRL)", withI2)
		}
	}
}

var _ = big.NewInt
var _ = time.Hour

// H1, контроль: то же, но сертификат нового ключа центра НЕ дан. Тогда
// rekeyedBy его не находит, и сертификат службы честно «не проверен».
// Следовать документу (дать сертификат нового ключа) — хуже: «проверен».
func TestR1C3RekeyedUnderIntermediateWithoutNewCACert(t *testing.T) {
	dir := t.TempDir()
	kRoot := newKey(t)
	r1T := caTmpl(1, "three-tier root c")
	r1T.NotBefore, r1T.NotAfter = day(2016, 1, 1), day(2026, 12, 31)
	r1 := issue(t, r1T, kRoot, nil)
	r2T := caTmpl(2, "three-tier root c")
	r2T.NotBefore, r2T.NotAfter = day(2026, 6, 1), day(2036, 12, 31)
	r2 := issue(t, r2T, kRoot, nil)
	interT := caTmpl(5, "policy CA c")
	interT.NotBefore, interT.NotAfter = day(2016, 1, 1), day(2034, 1, 1)
	inter := issue(t, interT, newKey(t), r1)
	caOld := issue(t, caTmpl(10, "TSA CA c"), newKey(t), inter)
	caNewT := caTmpl(11, "TSA CA c")
	caNewT.NotBefore = day(2027, 2, 1)
	caNew := issue(t, caNewT, newKey(t), inter)
	gen := day(2025, 10, 1)
	leaf, info := tsaUnder(t, caOld, day(2030, 1, 1), gen, []*x509.Certificate{r1.cert, r2.cert}, inter.cert, caOld.cert)
	r := NewRevocations(day(2027, 3, 10))
	r.AddCRL(caOld.crlOf(t, dir, "old-key.crl", day(2027, 1, 25), day(2027, 4, 25), nil))
	r.AddCRL(caNew.crlOf(t, dir, "new-key.crl", day(2027, 3, 1), day(2027, 4, 1), nil,
		x509.RevocationListEntry{SerialNumber: leaf.cert.SerialNumber, RevocationTime: day(2027, 2, 20), ReasonCode: ReasonKeyCompromise}))
	r.AddCRL(r2.crlOf(t, dir, "root.crl", day(2027, 3, 1), day(2027, 4, 1), nil))
	r.AddCRL(inter.crlOf(t, dir, "inter.crl", day(2027, 3, 1), day(2027, 4, 1), nil))
	for _, give := range []bool{false, true} {
		a := r.NewAssessment()
		r1c3Known(a, inter.cert, caOld.cert, r1.cert, r2.cert)
		if give {
			r1c3Known(a, caNew.cert)
		}
		i, _ := a.Add(info.Chains, info.GenTime)
		v := a.Verdicts()[i]
		t.Logf("CA new-key cert given=%v: NeedPOE=%v Unchecked=%d", give, v.NeedPOE, len(v.Unchecked))
		for _, n := range v.Notes {
			t.Logf("  note: %.200s", n)
		}
		if !v.NeedPOE && len(v.Unchecked) == 0 {
			t.Errorf("CA new-key cert given=%v: компрометация не в счёт, и сертификат службы «проверен»", give)
		}
	}
}

// H1c. Двухуровневый УЦ (без промежуточного). Центр сменил ключ; сертификат
// нового ключа потом продлён на тот же ключ. Служба истекла, и CRL нового
// ключа, где она названа по компрометации, — только времени первого
// сертификата нового ключа. Проверяющий дал текущий (продлённый) сертификат
// нового ключа: путь на дату CRL не строится (он ещё не действовал) — тёзка.
func TestR1C3RekeyedCACertRenewedLater(t *testing.T) {
	dir := t.TempDir()
	root := issue(t, caTmpl(1, "two-tier root"), newKey(t), nil)
	caOld := issue(t, caTmpl(10, "TSA CA d"), newKey(t), root)
	kNew := newKey(t)
	n1T := caTmpl(11, "TSA CA d")
	n1T.NotBefore, n1T.NotAfter = day(2026, 9, 1), day(2027, 12, 31)
	caNew1 := issue(t, n1T, kNew, root)
	n2T := caTmpl(12, "TSA CA d")
	n2T.NotBefore, n2T.NotAfter = day(2027, 12, 1), day(2032, 12, 31)
	caNew2 := issue(t, n2T, kNew, root)
	gen := day(2025, 10, 1)
	leaf, info := tsaUnder(t, caOld, day(2027, 6, 1), gen, []*x509.Certificate{root.cert}, caOld.cert)
	r := NewRevocations(day(2028, 3, 10))
	// Последний CRL прежнего ключа — до смены ключа; служба тогда ещё
	// действовала. CRL нового ключа (центр сменил ключ в 2026-09) называет её по
	// компрометации; после истечения службы (2027-06) центр её убрал.
	r.AddCRL(caOld.crlOf(t, dir, "old-key.crl", day(2026, 8, 25), day(2026, 9, 25), nil))
	r.AddCRL(caNew1.crlOf(t, dir, "new-key-2027.crl", day(2027, 3, 1), day(2027, 4, 1), nil,
		x509.RevocationListEntry{SerialNumber: leaf.cert.SerialNumber, RevocationTime: day(2027, 2, 20), ReasonCode: ReasonKeyCompromise}))
	r.AddCRL(caNew2.crlOf(t, dir, "new-key-2028.crl", day(2028, 3, 1), day(2028, 4, 1), nil))
	r.AddCRL(root.crlOf(t, dir, "root.crl", day(2028, 3, 1), day(2028, 4, 1), nil))
	a := r.NewAssessment()
	r1c3Known(a, caOld.cert, caNew2.cert, root.cert)
	i, _ := a.Add(info.Chains, info.GenTime)
	v := a.Verdicts()[i]
	t.Logf("NeedPOE=%v Unchecked=%d CRLs=%q", v.NeedPOE, len(v.Unchecked), v.CRLs)
	for _, n := range v.Notes {
		t.Logf("note: %s", n)
	}
	if !v.NeedPOE && len(v.Unchecked) == 0 {
		t.Errorf("компрометация в CRL нового ключа центра не в счёт, сертификат службы «проверен»")
	}
}
