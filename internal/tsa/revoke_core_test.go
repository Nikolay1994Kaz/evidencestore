package tsa

// Срез 10.11.2026 (DECISIONS, п. 35): судится сертификат цепочки метки, а не
// ключ; CRL под другим ключом центра — «не проверен» (TestRevocationsCRLItself);
// остальное называет проверяющий в перечне. Здесь — честный исход случаев,
// которые раньше выводились, и правило о цепочках одной метки.

import (
	"bytes"
	"crypto/x509"
	"errors"
	"fmt"
	"testing"
	"time"
)

func listOf(c *x509.Certificate, at time.Time, reason string) []byte {
	return []byte(fmt.Sprintf(`[{"cert_sha256": %q, "revoked": %q, "reason": %q}]`, Fingerprint(c), at.Format(time.RFC3339), reason))
}

// Сертификат службы перевыпущен на тот же ключ, и по компрометации отозван
// новый, а метку подписал прежний. CRL прежний не называет: по цепочке метки
// отзыва нет, статус — «проверен». Запись о новом сертификате на метку не
// переходит: её переносит проверяющий, назвав в перечне прежний.
func TestRevocationsSameKeyOutsideChain(t *testing.T) {
	dir := t.TempDir()
	root := issue(t, caTmpl(1, "core root"), newKey(t), nil)
	ca := issue(t, caTmpl(10, "core TSA CA"), newKey(t), root)
	gen := day(2026, 10, 1)
	leaf, info := tsaUnder(t, ca, day(2030, 1, 1), gen, []*x509.Certificate{root.cert}, ca.cert)
	renewed := issue(t, r1leafTmpl(78, "test TSA", day(2026, 10, 2), day(2031, 1, 1)), leaf.key, ca)
	r := NewRevocations(day(2026, 11, 2))
	r.AddCRL(root.crlOf(t, dir, "root.crl", day(2026, 11, 1), day(2026, 12, 1), nil))
	r.AddCRL(ca.crlOf(t, dir, "ca.crl", day(2026, 11, 1), day(2026, 12, 1), nil,
		x509.RevocationListEntry{SerialNumber: renewed.cert.SerialNumber, RevocationTime: day(2026, 10, 20), ReasonCode: ReasonKeyCompromise}))
	if v, err := r.Check(info.Chains, info.GenTime); err != nil || v.NeedPOE || len(v.Unchecked) != 0 || len(v.CRLs) != 2 {
		t.Fatalf("отозван другой сертификат того же ключа: %+v %v", v, err)
	}
	if err := r.addList("mine.json", listOf(leaf.cert, day(2026, 10, 20), "keyCompromise")); err != nil {
		t.Fatal(err)
	}
	v, err := r.Check(info.Chains, info.GenTime)
	if err != nil || !v.NeedPOE || !v.Cutoff.Equal(day(2026, 10, 20)) || !bytes.Equal(v.Revoked.Raw, leaf.cert.Raw) {
		t.Fatalf("прежний сертификат назван в перечне: %+v %v", v, err)
	}
}

// Сертификат центра в цепочке метки, отозванный корнем: без причины или по
// компрометации — время метки ничего не доказывает, отсечка — дата отзыва;
// без компрометации — метка до даты в силе, с неё — нет.
func TestRevocationsCAInChain(t *testing.T) {
	dir := t.TempDir()
	root := issue(t, caTmpl(1, "core root 2"), newKey(t), nil)
	ca := issue(t, caTmpl(10, "core TSA CA 2"), newKey(t), root)
	gen := day(2026, 10, 10)
	_, info := tsaUnder(t, ca, day(2030, 1, 1), gen, []*x509.Certificate{root.cert}, ca.cert)
	for name, c := range map[string]struct {
		code    int
		at      time.Time
		poe     bool
		revoked bool
	}{
		"без причины, позже метки":       {0, day(2026, 10, 20), true, false},
		"без причины, раньше метки":      {0, day(2026, 10, 1), true, false},
		"компрометация центра":           {ReasonCACompromise, day(2026, 10, 20), true, false},
		"смена сертификата, позже метки": {ReasonSuperseded, day(2026, 10, 20), false, false},
		"смена сертификата, в миг метки": {ReasonSuperseded, gen, false, true},
		"вывод из работы, раньше метки":  {ReasonCessationOfOperation, day(2026, 10, 1), false, true},
	} {
		r := NewRevocations(day(2026, 11, 2))
		r.AddCRL(ca.crlOf(t, dir, "ca.crl", day(2026, 11, 1), day(2026, 12, 1), nil))
		r.AddCRL(root.crlOf(t, dir, "root.crl", day(2026, 11, 1), day(2026, 12, 1), nil,
			x509.RevocationListEntry{SerialNumber: ca.cert.SerialNumber, RevocationTime: c.at, ReasonCode: c.code}))
		v, err := r.Check(info.Chains, info.GenTime)
		switch {
		case c.revoked:
			if !errors.Is(err, ErrRevoked) {
				t.Errorf("%s: ждали отказ, вышло %+v %v", name, v, err)
			}
		case err != nil || v.NeedPOE != c.poe || len(v.Unchecked) != 0:
			t.Errorf("%s: %+v %v", name, v, err)
		case c.poe && (!v.Cutoff.Equal(c.at) || !bytes.Equal(v.Revoked.Raw, ca.cert.Raw)):
			t.Errorf("%s: отсечка %s, сертификат %q", name, v.Cutoff, v.Revoked.Subject)
		}
	}
}

// У метки две цепочки (центр выпущен двумя корнями на один ключ). Цепочка, где
// сертификат отозван без компрометации к времени метки, не судится вовсе:
// вердикт — по оставшейся, даже когда он хуже; обе такие — метка не в силе.
// Метка, которая не в силе, вердикта не получает и другим не мешает.
func TestAssessmentLiveChains(t *testing.T) {
	dir := t.TempDir()
	rootA := issue(t, caTmpl(1, "live root A"), newKey(t), nil)
	rootB := issue(t, caTmpl(1, "live root B"), newKey(t), nil)
	k := newKey(t)
	interA := issue(t, caTmpl(10, "live TSA CA"), k, rootA)
	interB := issue(t, caTmpl(11, "live TSA CA"), k, rootB)
	gen := day(2026, 10, 10)
	roots := []*x509.Certificate{rootA.cert, rootB.cert}
	_, info := tsaUnder(t, interA, day(2030, 1, 1), gen, roots, interA.cert, interB.cert)
	if len(info.Chains) != 2 {
		t.Fatalf("цепочек %d, ждали двух", len(info.Chains))
	}
	now := day(2026, 11, 2)
	inter := interA.crlOf(t, dir, "inter.crl", day(2026, 11, 1), day(2026, 12, 1), nil)
	retiredA := rootA.crlOf(t, dir, "rootA.crl", day(2026, 11, 1), day(2026, 12, 1), nil,
		x509.RevocationListEntry{SerialNumber: interA.cert.SerialNumber, RevocationTime: day(2026, 10, 1), ReasonCode: ReasonSuperseded})
	crlB := func(name string, code int, at time.Time) string {
		return rootB.crlOf(t, dir, name, day(2026, 11, 1), day(2026, 12, 1), nil,
			x509.RevocationListEntry{SerialNumber: interB.cert.SerialNumber, RevocationTime: at, ReasonCode: code})
	}
	// Цепочка через выпуск корня A не в силе, через выпуск корня B — под
	// подозрением: вердикт — по ней, хотя цепочка A подозрения не несёт.
	r := NewRevocations(now)
	r.AddCRL(inter)
	r.AddCRL(retiredA)
	r.AddCRL(crlB("rootB-compromise.crl", ReasonCACompromise, day(2026, 10, 20)))
	v, err := r.Check(info.Chains, info.GenTime)
	if err != nil || !v.NeedPOE || !bytes.Equal(v.Revoked.Raw, interB.cert.Raw) || len(v.Unchecked) != 0 {
		t.Fatalf("одна цепочка не в силе, другая под подозрением: %+v %v", v, err)
	}
	// Обе не в силе.
	r = NewRevocations(now)
	r.AddCRL(inter)
	r.AddCRL(retiredA)
	r.AddCRL(crlB("rootB-superseded.crl", ReasonSuperseded, day(2026, 10, 2)))
	if v, err := r.Check(info.Chains, info.GenTime); !errors.Is(err, ErrRevoked) || v.NeedPOE || len(v.Named) != 3 {
		t.Fatalf("обе цепочки не в силе: %+v %v", v, err)
	}
	// В одной оценке с меткой другой службы: у метки не в силе вердикт пуст,
	// у второй — свой.
	other := issue(t, caTmpl(1, "live other root"), newKey(t), nil)
	_, info2 := tsaUnder(t, other, day(2030, 1, 1), gen, []*x509.Certificate{other.cert})
	r.AddCRL(other.crlOf(t, dir, "other.crl", day(2026, 11, 1), day(2026, 12, 1), nil))
	a := r.NewAssessment()
	if i, err := a.Add(info.Chains, info.GenTime); i != 0 || !errors.Is(err, ErrRevoked) {
		t.Fatalf("метка не в силе: %d %v", i, err)
	}
	if i, err := a.Add(info2.Chains, info2.GenTime); i != 1 || err != nil {
		t.Fatalf("вторая метка: %d %v", i, err)
	}
	vs := a.Verdicts()
	if len(vs) != 2 || vs[0].NeedPOE || vs[0].Revoked != nil || len(vs[0].CRLs) != 0 || len(vs[0].Unchecked) != 0 {
		t.Fatalf("вердикт метки не в силе не пуст: %+v", vs)
	}
	if vs[1].NeedPOE || len(vs[1].Unchecked) != 0 || len(vs[1].CRLs) != 1 || len(vs[1].Named) != 4 {
		t.Fatalf("вердикт второй метки: %+v", vs[1])
	}
}
