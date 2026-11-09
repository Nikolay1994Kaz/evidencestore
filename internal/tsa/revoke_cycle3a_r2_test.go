package tsa

// Ревью цикла 3, заход 1 (r2): гипотезы по диффу пересмотра 0aa4e7c..14762ae.

import (
	"crypto/x509"
	"fmt"
	"math/big"
	"strings"
	"testing"
	"time"
)

// G1. Служба перевыпущена на тот же ключ, центр сменил ключ (AD CS: у каждого
// ключа свой CRL, CRL прежнего ключа публикуется и дальше). Прежний сертификат
// службы X0 (выпущен прежним ключом центра K0) отозван «superseded» при
// перевыпуске — так делают при продлении. Проверяющий, как велит документ,
// дал «every certificate of a key you know of» — и X0, — и все CRL центра, но
// не сертификат прежнего ключа центра. Запись superseded у сертификата вне
// цепочек ничего не меняет, даже будь CRL проверен (P-191: вывод из работы
// без компрометации у сертификата вне цепочек метки ключа не выводит), а
// статус X1 (в цепочке) пропадает: «не проверено».
func TestC3aR2SupersededKnownMakesChainUnchecked(t *testing.T) {
	dir := t.TempDir()
	root := issue(t, caTmpl(1, "g1 root"), newKey(t), nil)
	caK0 := issue(t, caTmpl(10, "g1 TSA CA"), newKey(t), root) // прежний ключ центра; проверяющему не дан
	caK1 := issue(t, caTmpl(11, "g1 TSA CA"), newKey(t), root) // нынешний
	kTSA := newKey(t)
	x0 := issue(t, r1leafTmpl(500, "TSA", day(2023, 1, 1), day(2027, 1, 1)), kTSA, caK0)
	x1 := issue(t, r1leafTmpl(600, "TSA", day(2025, 1, 1), day(2029, 1, 1)), kTSA, caK1)
	pool := x509.NewCertPool()
	pool.AddCert(root.cert)
	info := renewedStamp(t, x1, root, day(2026, 10, 15), Trust{Roots: pool, Intermediates: []*x509.Certificate{caK1.cert}})
	now := day(2026, 11, 10)
	r := NewRevocations(now)
	r.AddCRL(root.crlOf(t, dir, "root.crl", day(2026, 11, 1), day(2026, 12, 1), nil))
	r.AddCRL(caK1.crlOf(t, dir, "k1.crl", day(2026, 11, 9), day(2026, 12, 9), nil))
	r.AddCRL(caK0.crlOf(t, dir, "k0.crl", day(2026, 11, 9), day(2026, 12, 9), nil,
		x509.RevocationListEntry{SerialNumber: x0.cert.SerialNumber, RevocationTime: day(2025, 1, 2), ReasonCode: ReasonSuperseded}))
	run := func(known ...*x509.Certificate) Verdict {
		a := r.NewAssessment()
		a.KnownTrusted(known...)
		i, err := a.Add(info.Chains, info.GenTime)
		if err != nil {
			t.Fatal(err)
		}
		return a.Verdicts()[i]
	}
	// Контроль: без X0 — проверен.
	if v := run(); v.NeedPOE || len(v.Unchecked) != 0 {
		t.Fatalf("контроль без X0: %+v", v)
	}
	// Контроль: с X0 и сертификатом прежнего ключа центра — проверен (superseded вне цепочек ни на что не влияет).
	if v := run(x0.cert, caK0.cert); v.NeedPOE || len(v.Unchecked) != 0 {
		t.Fatalf("контроль с X0 и K0: %+v", v)
	}
	v := run(x0.cert)
	t.Logf("X0 дан без центра: NeedPOE=%v Unchecked=%d Notes=%q", v.NeedPOE, len(v.Unchecked), v.Notes)
	if len(v.Unchecked) != 0 {
		t.Errorf("запись superseded о сертификате вне цепочек (в CRL ключа, которого нет) сняла статус X1: «не проверено», хотя такая запись ни на что не влияет и будь CRL проверен")
	}
}

// G1b. То же для перекрёстного сертификата центра: проверяющий дал в
// -tsa-trust перекрёстный выпуск центра службы другим корнем (которому он не
// доверяет и чьего сертификата не давал), и у него есть CRL того корня, где
// перекрёстный сертификат выведен (cessationOfOperation или без причины —
// прекращена перекрёстная сертификация). Сертификат центра в цепочке
// становится «не проверенным», а с ним — все метки через него.
func TestC3aR2CrossCertEndedMakesCAUnchecked(t *testing.T) {
	dir := t.TempDir()
	root := issue(t, caTmpl(1, "g1b root"), newKey(t), nil)
	bridge := issue(t, caTmpl(2, "g1b bridge"), newKey(t), nil) // проверяющему не дан
	kCA := newKey(t)
	ca := issue(t, caTmpl(10, "g1b TSA CA"), kCA, root)
	cross := issue(t, caTmpl(20, "g1b TSA CA"), kCA, bridge)
	_, info := tsaUnder(t, ca, day(2030, 1, 1), day(2026, 10, 15), []*x509.Certificate{root.cert}, ca.cert)
	now := day(2026, 11, 10)
	for _, reason := range []int{ReasonCessationOfOperation, -1} {
		r := NewRevocations(now)
		r.AddCRL(root.crlOf(t, dir, "root.crl", day(2026, 11, 1), day(2026, 12, 1), nil))
		r.AddCRL(ca.crlOf(t, dir, "ca.crl", day(2026, 11, 9), day(2026, 12, 9), nil))
		e := x509.RevocationListEntry{SerialNumber: cross.cert.SerialNumber, RevocationTime: day(2026, 6, 1), ReasonCode: reason}
		if reason < 0 {
			e.ReasonCode = 0
			e.ExtraExtensions = nil
		}
		r.AddCRL(bridge.crlOf(t, dir, "bridge.crl", day(2026, 11, 9), day(2026, 12, 9), nil, e))
		a := r.NewAssessment()
		a.KnownTrusted(cross.cert)
		i, err := a.Add(info.Chains, info.GenTime)
		if err != nil {
			t.Fatal(err)
		}
		v := a.Verdicts()[i]
		t.Logf("reason %s: NeedPOE=%v Unchecked=%d Notes=%q", ReasonName(reason), v.NeedPOE, len(v.Unchecked), v.Notes)
		if len(v.Unchecked) != 0 {
			t.Errorf("перекрёстный сертификат центра выведен %s в CRL корня, которому не доверяют: центр в цепочке «не проверен»", ReasonName(reason))
		}
	}
}

// G2. Удержание в CRL нового ключа центра снимается более новым CRL того же
// ключа, только если право на CRL — у первого найденного сертификата этого
// ключа (by), а не у любого из них, как у своего CRL (judge: «право на CRL —
// хоть у одного сертификата центра», P-149, P-141).
func TestC3aR2HoldReleaseNeedsCRLSignOnFirstCert(t *testing.T) {
	dir := t.TempDir()
	root := issue(t, caTmpl(1, "g2 root"), newKey(t), nil)
	caOld := issue(t, caTmpl(10, "g2 TSA CA"), newKey(t), root)
	kNew := newKey(t)
	noCRL := caTmpl(11, "g2 TSA CA")
	noCRL.KeyUsage = x509.KeyUsageCertSign // первый выпуск нового ключа — без cRLSign
	caNewA := issue(t, noCRL, kNew, root)
	caNewB := issue(t, caTmpl(12, "g2 TSA CA"), kNew, root) // перевыпуск с cRLSign
	gen := day(2026, 10, 15)
	_, info := tsaUnder(t, caOld, day(2030, 1, 1), gen, []*x509.Certificate{root.cert}, caOld.cert)
	leaf := info.Chains[0][0]
	r := NewRevocations(day(2026, 11, 10))
	r.AddCRL(caOld.crlOf(t, dir, "old.crl", day(2026, 9, 2), day(2026, 12, 1), nil))
	r.AddCRL(caNewB.crlOf(t, dir, "hold.crl", day(2026, 10, 6), day(2026, 11, 6), nil,
		x509.RevocationListEntry{SerialNumber: leaf.SerialNumber, RevocationTime: day(2026, 10, 5), ReasonCode: ReasonCertificateHold}))
	r.AddCRL(caNewB.crlOf(t, dir, "released.crl", day(2026, 11, 9), day(2026, 12, 9), nil))
	for name, order := range map[string][]*x509.Certificate{"с cRLSign первым": {caNewB.cert, caNewA.cert}, "без cRLSign первым": {caNewA.cert, caNewB.cert}} {
		a := r.NewAssessment()
		a.KnownTrusted(order...)
		i, err := a.Add(info.Chains, info.GenTime)
		if err != nil {
			t.Fatal(err)
		}
		v := a.Verdicts()[i]
		t.Logf("%s: NeedPOE=%v Entry=%+v", name, v.NeedPOE, v.Entry)
		if v.NeedPOE {
			t.Errorf("%s: удержание в CRL нового ключа снято более новым CRL того же ключа, сертификат с cRLSign дан, — а удержание в силе", name)
		}
	}
}

// G1c. Как G1, но CRL прежнего ключа центра старше статусного CRL X1: для
// сертификата цепочки такой CRL «not used» (правило: «не проверено» — только
// от CRL новее статусного), а через сертификат вне цепочек без центра —
// «не проверено» при любом возрасте, и заметка утверждает «a CRL newer than
// <статусный>», что неправда. Контроль: та же запись с keyCompromise —
// тревога уместна (ключ мог быть украден, а CRL не сверить).
func TestC3aR2UnknownKeyIgnoresAgeAndNoteLies(t *testing.T) {
	dir := t.TempDir()
	root := issue(t, caTmpl(1, "g1c root"), newKey(t), nil)
	caK0 := issue(t, caTmpl(10, "g1c TSA CA"), newKey(t), root)
	caK1 := issue(t, caTmpl(11, "g1c TSA CA"), newKey(t), root)
	kTSA := newKey(t)
	x0 := issue(t, r1leafTmpl(500, "TSA", day(2023, 1, 1), day(2027, 1, 1)), kTSA, caK0)
	x1 := issue(t, r1leafTmpl(600, "TSA", day(2025, 1, 1), day(2029, 1, 1)), kTSA, caK1)
	pool := x509.NewCertPool()
	pool.AddCert(root.cert)
	info := renewedStamp(t, x1, root, day(2026, 10, 15), Trust{Roots: pool, Intermediates: []*x509.Certificate{caK1.cert}})
	for _, reason := range []int{ReasonSuperseded, ReasonKeyCompromise} {
		r := NewRevocations(day(2026, 11, 10))
		r.AddCRL(root.crlOf(t, dir, "root.crl", day(2026, 11, 1), day(2026, 12, 1), nil))
		r.AddCRL(caK1.crlOf(t, dir, "k1.crl", day(2026, 11, 9), day(2026, 12, 9), nil))
		r.AddCRL(caK0.crlOf(t, dir, "k0.crl", day(2025, 2, 1), day(2025, 3, 1), nil, // старше k1.crl на полтора года
			x509.RevocationListEntry{SerialNumber: x0.cert.SerialNumber, RevocationTime: day(2025, 1, 2), ReasonCode: reason}))
		a := r.NewAssessment()
		a.KnownTrusted(x0.cert)
		i, err := a.Add(info.Chains, info.GenTime)
		if err != nil {
			t.Fatal(err)
		}
		v := a.Verdicts()[i]
		t.Logf("%s: Unchecked=%d", ReasonName(reason), len(v.Unchecked))
		if reason == ReasonSuperseded && len(v.Unchecked) != 0 {
			t.Errorf("superseded в CRL старше статусного: X1 «не проверен»")
			if hasNote(v, "a CRL newer than") {
				t.Errorf("заметка говорит «a CRL newer than …k1.crl», а k0.crl старше его: %q", v.Notes)
			}
		}
		if reason == ReasonKeyCompromise && len(v.Unchecked) == 0 {
			t.Errorf("контроль: keyCompromise в CRL, которого не сверить, — X1 проверен")
		}
	}
}

// G3. under: общий seen с пределом глубины. Узел настоящего пути, впервые
// достигнутый глубоко (через цикл перекрёстных выпусков) и там не дошедший до
// корня из-за предела, помечен seen, и короткий путь через него потом закрыт.
// C2 (новый ключ центра) ← P_short ← M ← корень — три ребра; но первым по
// порядку идёт P_long (тот же ключ P), за ним цикл Q1…Q5, выпущенный ключом P:
// P_short достигнут на глубине 7, M — на 8.
func TestC3aR2PathSeenPoisonedByDeepCycle(t *testing.T) {
	dir := t.TempDir()
	root := issue(t, caTmpl(1, "g3 root"), newKey(t), nil)
	c1 := issue(t, caTmpl(10, "g3 TSA CA"), newKey(t), root)
	m := issue(t, caTmpl(20, "g3 M"), newKey(t), root)
	kP := newKey(t)
	pShort := issue(t, caTmpl(30, "g3 P"), kP, m)
	pSelf := &pki{cert: pShort.cert, key: kP} // выпускающий ключом P от имени P
	// Цикл: P выпускает Q5, Q5 — Q4, …, Q1 — P_long (тот же ключ P).
	qs := make([]*pki, 6)
	keys := []any{nil}
	_ = keys
	prev := pSelf
	for i := 5; i >= 1; i-- {
		qs[i] = issue(t, caTmpl(int64(40+i), fmt.Sprintf("g3 Q%d", i)), newKey(t), prev)
		prev = qs[i]
	}
	pLong := issue(t, caTmpl(31, "g3 P"), kP, qs[1])
	c2 := issue(t, caTmpl(11, "g3 TSA CA"), newKey(t), pSelf) // новый ключ центра, выпущен ключом P
	_, info := tsaUnder(t, c1, day(2030, 1, 1), day(2026, 10, 15), []*x509.Certificate{root.cert}, c1.cert)
	leaf := info.Chains[0][0]
	r := NewRevocations(day(2026, 11, 10))
	r.AddCRL(c1.crlOf(t, dir, "old.crl", day(2026, 10, 20), day(2026, 12, 1), nil))
	r.AddCRL(c2.crlOf(t, dir, "new.crl", day(2026, 11, 9), day(2026, 12, 9), nil,
		x509.RevocationListEntry{SerialNumber: leaf.SerialNumber, RevocationTime: day(2026, 11, 1), ReasonCode: ReasonKeyCompromise}))
	run := func(trusted ...*x509.Certificate) Verdict {
		a := r.NewAssessment()
		a.KnownTrusted(trusted...)
		i, err := a.Add(info.Chains, info.GenTime)
		if err != nil {
			t.Fatal(err)
		}
		return a.Verdicts()[i]
	}
	if v := run(pShort.cert, m.cert, c2.cert); !v.NeedPOE {
		t.Fatalf("контроль: короткий путь без цикла — компрометация не в счёт: %+v", v)
	}
	v := run(pLong.cert, pShort.cert, qs[1].cert, qs[2].cert, qs[3].cert, qs[4].cert, qs[5].cert, m.cert, c2.cert)
	t.Logf("с циклом: NeedPOE=%v Unchecked=%d", v.NeedPOE, len(v.Unchecked))
	if !v.NeedPOE {
		t.Errorf("путь C2 → P → M → корень (3 ребра) есть, но DFS сначала дошёл до P через цикл на глубине 7 и пометил его seen: CRL нового ключа «не известен»")
	}
}

var _ = big.NewInt
var _ = strings.Contains
var _ = time.Second

// G4. Смена ключа корня: R1 (KR1), R2 (KR2, самоподписанный), связующий
// old-with-new (имя R, ключ KR2, выпущен KR1). Центр сменил ключ под новым
// ключом корня. Со связующим — путь до R1 есть, запись в счёт. Без него, но с
// R2 у проверяющего — тоже в счёт (цикл 3, заход 1: ключ CRL засчитывается
// под любым корнем проверяющего, корень цепочки выбирает тот, кто собирал
// пакет). Без R2 и без связующего — «не проверено».
func TestC3aR2RootRolloverLinkCerts(t *testing.T) {
	dir := t.TempDir()
	kR1, kR2 := newKey(t), newKey(t)
	r1 := issue(t, caTmpl(1, "g4 root"), kR1, nil)
	r2 := issue(t, caTmpl(2, "g4 root"), kR2, nil)
	own := issue(t, caTmpl(3, "g4 root"), kR2, r1) // old-with-new: ключ KR2 под KR1
	nwo := issue(t, caTmpl(4, "g4 root"), kR1, r2) // new-with-old: ключ KR1 под KR2
	c1 := issue(t, caTmpl(10, "g4 TSA CA"), newKey(t), r1)
	c2 := issue(t, caTmpl(11, "g4 TSA CA"), newKey(t), r2)
	_, info := tsaUnder(t, c1, day(2030, 1, 1), day(2026, 10, 15), []*x509.Certificate{r1.cert}, c1.cert)
	leaf := info.Chains[0][0]
	r := NewRevocations(day(2026, 11, 10))
	r.AddCRL(c1.crlOf(t, dir, "old.crl", day(2026, 10, 20), day(2026, 12, 1), nil))
	r.AddCRL(c2.crlOf(t, dir, "new.crl", day(2026, 11, 9), day(2026, 12, 9), nil,
		x509.RevocationListEntry{SerialNumber: leaf.SerialNumber, RevocationTime: day(2026, 11, 1), ReasonCode: ReasonKeyCompromise}))
	run := func(trusted ...*x509.Certificate) Verdict {
		a := r.NewAssessment()
		a.KnownTrusted(trusted...)
		i, err := a.Add(info.Chains, info.GenTime)
		if err != nil {
			t.Fatal(err)
		}
		return a.Verdicts()[i]
	}
	if v := run(c2.cert, own.cert); !v.NeedPOE {
		t.Errorf("со связующим old-with-new запись не в счёт: %+v", v)
	}
	if v := run(c2.cert, r2.cert); !v.NeedPOE {
		t.Errorf("без связующего, R2 у проверяющего: запись не в счёт: %+v", v)
	}
	if v := run(c2.cert, r2.cert, nwo.cert); !v.NeedPOE {
		t.Errorf("new-with-old и R2 у проверяющего: запись не в счёт: %+v", v)
	}
	if v := run(c2.cert, nwo.cert); v.NeedPOE || len(v.Unchecked) == 0 {
		t.Errorf("ни R2, ни old-with-new: ждали «не проверено»: %+v", v)
	}
}
