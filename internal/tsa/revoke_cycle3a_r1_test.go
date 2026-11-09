package tsa

// Ревью цикла 3, заход 1 (r1): гипотезы по диффу пересмотра 0aa4e7c..14762ae.

import (
	"crypto/x509"
	"math/big"
	"strings"
	"testing"
	"time"
)

// A1. Служба перевыпущена на тот же ключ под новым ключом центра (AD CS:
// продление центра с новым ключом, у каждого ключа свой CRL); прежний
// сертификат службы X0 выведен из работы (superseded) в CRL прежнего ключа
// центра. Проверяющий, как велит документ («Give every certificate of a key
// you know of in -tsa-trust», «Pass every CRL of a CA you have, old ones
// too»), дал X0 и оба CRL, но не сертификат прежнего ключа центра. Запись о
// X0 — без компрометации, и вне цепочек такие записи ключа не касаются
// (P-191): засчитай её — вердикт тот же. А действующий X1 в цепочке
// становится «не проверенным» (unknownKey), и метка не годится в POE.
func TestC3R1UnknownKeyFiresOnSuperseded(t *testing.T) {
	dir := t.TempDir()
	root := issue(t, caTmpl(1, "c3r1 root"), newKey(t), nil)
	c1 := issue(t, caTmpl(10, "c3r1 TSA CA"), newKey(t), root) // прежний ключ центра: проверяющему не дан
	c2 := issue(t, caTmpl(11, "c3r1 TSA CA"), newKey(t), root) // нынешний: в цепочке
	kTSA := newKey(t)
	x0 := issue(t, r1leafTmpl(0x5a01, "TSA", day(2024, 1, 1), day(2027, 1, 1)), kTSA, c1)
	x1 := issue(t, r1leafTmpl(0x7b02, "TSA", day(2026, 6, 1), day(2029, 1, 1)), kTSA, c2)
	pool := x509.NewCertPool()
	pool.AddCert(root.cert)
	info := renewedStamp(t, x1, root, day(2026, 10, 15), Trust{Roots: pool, Intermediates: []*x509.Certificate{c2.cert}})
	r := NewRevocations(day(2026, 11, 10))
	r.AddCRL(root.crlOf(t, dir, "root.crl", day(2026, 11, 1), day(2026, 12, 1), nil))
	r.AddCRL(c1.crlOf(t, dir, "ca-key0.crl", day(2026, 11, 1), day(2026, 12, 1), nil,
		x509.RevocationListEntry{SerialNumber: x0.cert.SerialNumber, RevocationTime: day(2026, 6, 1), ReasonCode: ReasonSuperseded}))
	r.AddCRL(c2.crlOf(t, dir, "ca-key1.crl", day(2026, 11, 1), day(2026, 12, 1), nil))
	run := func(known ...*x509.Certificate) Verdict {
		a := r.NewAssessment()
		a.KnownTrusted(known...)
		i, err := a.Add(info.Chains, info.GenTime)
		if err != nil {
			t.Fatal(err)
		}
		return a.Verdicts()[i]
	}
	if v := run(); v.NeedPOE || len(v.Unchecked) != 0 {
		t.Fatalf("контроль: без X0 статус X1 проверен: %+v", v)
	}
	if v := run(x0.cert, c1.cert); v.NeedPOE || len(v.Unchecked) != 0 {
		t.Fatalf("контроль: X0 с его центром — запись superseded ничего не меняет: %+v", v)
	}
	v := run(x0.cert)
	t.Logf("X0 без его центра: NeedPOE=%v Unchecked=%d Notes=%q", v.NeedPOE, len(v.Unchecked), v.Notes)
	if len(v.Unchecked) != 0 {
		t.Errorf("запись superseded о сертификате вне цепочек (засчитанная, она ничего бы не изменила) сделала X1 «не проверенным»")
	}
}

// A2. То же для сертификата центра: перекрёстный сертификат центра службы
// (тот же ключ, выпущен другим корнем) дан проверяющим, корня, который его
// выпустил, нет, а CRL того корня называет его отозванным без причины
// (центр прекратил перекрёстную сертификацию). Засчитанная, такая запись — не
// о ключе (chainOnly): цепочки через перекрёстный сертификат здесь нет. А
// сертификат центра в цепочке — «не проверен».
func TestC3R1UnknownKeyFiresOnChainOnly(t *testing.T) {
	dir := t.TempDir()
	root := issue(t, caTmpl(1, "c3r1b root"), newKey(t), nil)
	other := issue(t, caTmpl(2, "c3r1b bridge"), newKey(t), nil) // проверяющему не дан
	kCA := newKey(t)
	ca := issue(t, caTmpl(10, "c3r1b TSA CA"), kCA, root)
	cross := issue(t, caTmpl(0x3c55, "c3r1b TSA CA"), kCA, other)
	_, info := tsaUnder(t, ca, day(2030, 1, 1), day(2026, 10, 15), []*x509.Certificate{root.cert}, ca.cert)
	r := NewRevocations(day(2026, 11, 10))
	r.AddCRL(root.crlOf(t, dir, "root.crl", day(2026, 11, 1), day(2026, 12, 1), nil))
	r.AddCRL(ca.crlOf(t, dir, "ca.crl", day(2026, 11, 1), day(2026, 12, 1), nil))
	r.AddCRL(other.crlOf(t, dir, "bridge.crl", day(2026, 11, 1), day(2026, 12, 1), nil,
		x509.RevocationListEntry{SerialNumber: cross.cert.SerialNumber, RevocationTime: day(2026, 9, 1)}))
	run := func(known ...*x509.Certificate) Verdict {
		a := r.NewAssessment()
		a.KnownTrusted(known...)
		i, err := a.Add(info.Chains, info.GenTime)
		if err != nil {
			t.Fatal(err)
		}
		return a.Verdicts()[i]
	}
	if v := run(cross.cert, other.cert); v.NeedPOE || len(v.Unchecked) != 0 {
		t.Fatalf("контроль: с корнем перекрёстного — его отзыв без причины не о ключе: %+v", v)
	}
	v := run(cross.cert)
	t.Logf("перекрёстный без его корня: NeedPOE=%v Unchecked=%d Notes=%q", v.NeedPOE, len(v.Unchecked), v.Notes)
	if len(v.Unchecked) != 0 {
		t.Errorf("отзыв без причины перекрёстного сертификата центра (засчитанный, он не о ключе) сделал сертификат центра в цепочке «не проверенным»")
	}
}

// A3. Заметка unknownKey говорит «a CRL newer than <статусный CRL сертификата
// цепочки>», а сравнивался CRL со статусом сертификата вне цепочек (у
// сертификата без известного центра статуса нет вовсе). CRL, что старше
// статусного CRL X1 на год, делает X1 «не проверенным»; тот же CRL, назови он
// X1, был бы «not used».
func TestC3R1UnknownKeyAgeNotCompared(t *testing.T) {
	dir := t.TempDir()
	root := issue(t, caTmpl(1, "c3r1c root"), newKey(t), nil)
	c1 := issue(t, caTmpl(10, "c3r1c TSA CA"), newKey(t), root)
	c2 := issue(t, caTmpl(11, "c3r1c TSA CA"), newKey(t), root)
	kTSA := newKey(t)
	x0 := issue(t, r1leafTmpl(0x6601, "TSA", day(2024, 1, 1), day(2027, 1, 1)), kTSA, c1)
	x1 := issue(t, r1leafTmpl(0x6602, "TSA", day(2025, 6, 1), day(2029, 1, 1)), kTSA, c2)
	pool := x509.NewCertPool()
	pool.AddCert(root.cert)
	info := renewedStamp(t, x1, root, day(2026, 10, 15), Trust{Roots: pool, Intermediates: []*x509.Certificate{c2.cert}})
	r := NewRevocations(day(2026, 11, 10))
	r.AddCRL(root.crlOf(t, dir, "root.crl", day(2026, 11, 1), day(2026, 12, 1), nil))
	r.AddCRL(c1.crlOf(t, dir, "ca-key0-2025.crl", day(2025, 7, 1), day(2025, 8, 1), nil,
		x509.RevocationListEntry{SerialNumber: x0.cert.SerialNumber, RevocationTime: day(2025, 6, 1), ReasonCode: ReasonCertificateHold}))
	r.AddCRL(c2.crlOf(t, dir, "ca-key1.crl", day(2026, 11, 1), day(2026, 12, 1), nil))
	a := r.NewAssessment()
	a.KnownTrusted(x0.cert)
	i, err := a.Add(info.Chains, info.GenTime)
	if err != nil {
		t.Fatal(err)
	}
	v := a.Verdicts()[i]
	t.Logf("NeedPOE=%v Unchecked=%d Notes=%q", v.NeedPOE, len(v.Unchecked), v.Notes)
	for _, n := range v.Notes {
		if strings.Contains(n, "a CRL newer than") && strings.Contains(n, "ca-key1.crl") {
			t.Errorf("заметка называет CRL 2025 года «newer than» статусный CRL 2026 года: %q", n)
		}
	}
}

var _ = big.NewInt
var _ = time.Hour

// M2. Удержание в CRL нового ключа центра снимает более новый CRL того же
// ключа — но право на CRL сверяется только у первого найденного сертификата
// этого ключа (crlSigner → by). Сертификат нового ключа выпущен дважды:
// первый (в цепочке второй метки) — без cRLSign, второй (дан проверяющим) — с
// ним. Центр снял удержание, а метка ждёт POE.
func TestC3R1HoldReleaseUsesFirstSignerOnly(t *testing.T) {
	dir := t.TempDir()
	root := issue(t, caTmpl(1, "c3r1m root"), newKey(t), nil)
	caOld := issue(t, caTmpl(10, "c3r1m TSA CA"), newKey(t), root)
	kNew := newKey(t)
	noCRL := caTmpl(11, "c3r1m TSA CA")
	noCRL.KeyUsage = x509.KeyUsageCertSign // без cRLSign
	caNewA := issue(t, noCRL, kNew, root)
	caNewB := issue(t, caTmpl(12, "c3r1m TSA CA"), kNew, root) // тот же ключ, с cRLSign
	gen := day(2026, 10, 15)
	_, info := tsaUnder(t, caOld, day(2030, 1, 1), gen, []*x509.Certificate{root.cert}, caOld.cert)
	leaf := info.Chains[0][0]
	// Вторая метка — служба под новым ключом центра (сертификат без cRLSign).
	_, info2 := tsaUnder(t, caNewA, day(2030, 1, 1), gen, []*x509.Certificate{root.cert}, caNewA.cert)
	r := NewRevocations(day(2026, 11, 10))
	r.AddCRL(root.crlOf(t, dir, "root.crl", day(2026, 11, 1), day(2026, 12, 1), nil))
	r.AddCRL(caOld.crlOf(t, dir, "old.crl", day(2026, 9, 2), day(2026, 12, 1), nil))
	der := func(ca *pki, name string, this time.Time, es ...x509.RevocationListEntry) string {
		return (&pki{cert: caNewB.cert, key: kNew}).crlOf(t, dir, name, this, this.AddDate(0, 1, 0), nil, es...)
	}
	r.AddCRL(der(caNewB, "hold.crl", day(2026, 10, 6), x509.RevocationListEntry{SerialNumber: leaf.SerialNumber, RevocationTime: day(2026, 10, 5), ReasonCode: ReasonCertificateHold}))
	r.AddCRL(der(caNewB, "released.crl", day(2026, 11, 9)))
	run := func(second bool) Verdict {
		a := r.NewAssessment()
		a.KnownTrusted(caNewB.cert)
		i, err := a.Add(info.Chains, info.GenTime)
		if err != nil {
			t.Fatal(err)
		}
		if second {
			if _, err := a.Add(info2.Chains, info2.GenTime); err != nil {
				t.Fatal(err)
			}
		}
		return a.Verdicts()[i]
	}
	if v := run(false); v.NeedPOE {
		t.Fatalf("контроль: сертификат нового ключа с cRLSign — удержание снято: %+v", v)
	}
	v := run(true)
	t.Logf("со второй меткой (сертификат того же ключа без cRLSign первым): NeedPOE=%v Entry=%+v", v.NeedPOE, v.Entry)
	if v.NeedPOE {
		t.Errorf("удержание, снятое центром, не снято: право на CRL сверено только у первого сертификата нового ключа")
	}
}

// M3. Путь к корню: seen — общий на весь обход, а глубина ограничена. Узел,
// впервые встреченный на длинной ветке (где до корня не хватило глубины),
// помечен и на короткой ветке не пробуется: путь «не построен».
func TestC3R1PathSeenAcrossDepth(t *testing.T) {
	dir := t.TempDir()
	root := issue(t, caTmpl(1, "c3r1p root"), newKey(t), nil)
	caOld := issue(t, caTmpl(10, "c3r1p TSA CA"), newKey(t), root)
	_, info := tsaUnder(t, caOld, day(2030, 1, 1), day(2026, 10, 15), []*x509.Certificate{root.cert}, caOld.cert)
	leaf := info.Chains[0][0]
	// Короткий путь нового ключа центра: C2 ← Yb ← Z ← root (глубина 3).
	z := issue(t, caTmpl(2, "c3r1p Z"), newKey(t), root)
	kY := newKey(t)
	yb := issue(t, caTmpl(3, "c3r1p Y"), kY, z)
	// Длинная ветка: тот же центр Y (тот же ключ) перекрёстно выпущен кольцом
	// D1…D5, которое само выпущено Yb: Ya ← D1 ← … ← D5 ← Yb.
	d5 := issue(t, caTmpl(105, "c3r1p D5"), newKey(t), yb)
	d4 := issue(t, caTmpl(104, "c3r1p D4"), newKey(t), d5)
	d3 := issue(t, caTmpl(103, "c3r1p D3"), newKey(t), d4)
	d2 := issue(t, caTmpl(102, "c3r1p D2"), newKey(t), d3)
	d1 := issue(t, caTmpl(101, "c3r1p D1"), newKey(t), d2)
	ya := issue(t, caTmpl(4, "c3r1p Y"), kY, d1)
	c2 := issue(t, caTmpl(11, "c3r1p TSA CA"), newKey(t), yb)
	r := NewRevocations(day(2026, 11, 10))
	r.AddCRL(caOld.crlOf(t, dir, "old.crl", day(2026, 11, 1), day(2026, 12, 1), nil))
	r.AddCRL(c2.crlOf(t, dir, "new.crl", day(2026, 11, 9), day(2026, 12, 9), nil,
		x509.RevocationListEntry{SerialNumber: leaf.SerialNumber, RevocationTime: day(2026, 10, 20), ReasonCode: ReasonKeyCompromise}))
	run := func(certs ...*x509.Certificate) Verdict {
		a := r.NewAssessment()
		a.KnownTrusted(certs...)
		i, err := a.Add(info.Chains, info.GenTime)
		if err != nil {
			t.Fatal(err)
		}
		return a.Verdicts()[i]
	}
	if v := run(yb.cert, z.cert, c2.cert); !v.NeedPOE {
		t.Fatalf("контроль: короткий путь C2 ← Yb ← Z ← корень — компрометация в счёт: %+v", v)
	}
	// Те же сертификаты и кольцо, Ya — первым: путь глубины 3 есть, но Yb
	// впервые встречен на глубине 7 (кольцо), помечен seen и коротким путём
	// не пробуется.
	v := run(ya.cert, d1.cert, d2.cert, d3.cert, d4.cert, d5.cert, yb.cert, z.cert, c2.cert)
	t.Logf("с кольцом: NeedPOE=%v Unchecked=%d", v.NeedPOE, len(v.Unchecked))
	if !v.NeedPOE {
		t.Errorf("путь глубины 3 к корню есть, а CRL нового ключа «не известен»: seen общий для ветвей при пределе глубины")
	}
}

// OK1. Смена ключа корня со связующими сертификатами: служба выпущена прямо
// корнем R1 (ключ K1), корень сменил ключ на K2 (R2), выпущены old-with-new
// (имя R, ключ K1, подписан K2) и new-with-old (имя R, ключ K2, подписан K1).
// CRL корня под K2 называет службу по компрометации. Проверяющий доверяет R1 и
// дал R2 и связующие: путь R2 ← new-with-old ← R1 — запись в счёт. Только
// old-with-new (K2 ручается за K1, не наоборот) — «не проверено».
func TestC3R1RootRekeyLinks(t *testing.T) {
	dir := t.TempDir()
	k1, k2 := newKey(t), newKey(t)
	r1 := issue(t, caTmpl(1, "c3r1l root"), k1, nil)
	r2 := issue(t, caTmpl(2, "c3r1l root"), k2, nil)
	newWithOld := issue(t, caTmpl(3, "c3r1l root"), k2, r1)
	oldWithNew := issue(t, caTmpl(4, "c3r1l root"), k1, r2)
	_, info := tsaUnder(t, r1, day(2030, 1, 1), day(2026, 10, 15), []*x509.Certificate{r1.cert})
	leaf := info.Chains[0][0]
	r := NewRevocations(day(2026, 11, 10))
	r.AddCRL(r1.crlOf(t, dir, "k1.crl", day(2026, 11, 1), day(2026, 12, 1), nil))
	r.AddCRL(r2.crlOf(t, dir, "k2.crl", day(2026, 11, 9), day(2026, 12, 9), nil,
		x509.RevocationListEntry{SerialNumber: leaf.SerialNumber, RevocationTime: day(2026, 10, 20), ReasonCode: ReasonKeyCompromise}))
	run := func(certs ...*x509.Certificate) Verdict {
		a := r.NewAssessment()
		a.KnownTrusted(certs...)
		i, err := a.Add(info.Chains, info.GenTime)
		if err != nil {
			t.Fatal(err)
		}
		return a.Verdicts()[i]
	}
	if v := run(r1.cert, r2.cert, newWithOld.cert, oldWithNew.cert); !v.NeedPOE {
		t.Errorf("связующие даны: компрометация в CRL нового ключа корня не в счёт: %+v", v)
	}
	if v := run(r1.cert, r2.cert, oldWithNew.cert); !v.NeedPOE { // R2 у проверяющего — корень, под ним и K2
		t.Errorf("только old-with-new, R2 у проверяющего: запись не в счёт: NeedPOE=%v Unchecked=%d", v.NeedPOE, len(v.Unchecked))
	}
}

// OK2. Кольцо перекрёстных выпусков (A выпущен B, B выпущен A, оба — с
// именами центров пути) и путь предельной глубины: обход кончается, путь из
// 8 центров строится, из 9 — нет (maxPath).
func TestC3R1PathCycleAndDepth(t *testing.T) {
	dir := t.TempDir()
	root := issue(t, caTmpl(1, "c3r1d root"), newKey(t), nil)
	caOld := issue(t, caTmpl(10, "c3r1d TSA CA"), newKey(t), root)
	_, info := tsaUnder(t, caOld, day(2030, 1, 1), day(2026, 10, 15), []*x509.Certificate{root.cert}, caOld.cert)
	leaf := info.Chains[0][0]
	build := func(n int) (*pki, []*x509.Certificate) {
		var certs []*x509.Certificate
		prev := root
		for i := 0; i < n; i++ {
			prev = issue(t, caTmpl(int64(200+i), "c3r1d P"+string(rune('a'+i))), newKey(t), prev)
			certs = append(certs, prev.cert)
		}
		// кольцо: перекрёстный A↔B под последним
		kA, kB := newKey(t), newKey(t)
		aT, bT := caTmpl(300, "c3r1d A"), caTmpl(301, "c3r1d B")
		a1 := issue(t, aT, kA, prev)
		b1 := issue(t, bT, kB, a1)
		a2 := issue(t, caTmpl(302, "c3r1d A"), kA, b1)
		certs = append(certs, a2.cert, b1.cert, a1.cert)
		_ = a1
		return prev, certs
	}
	for _, c := range []struct {
		n    int
		want bool
	}{{7, true}, {8, false}} {
		last, certs := build(c.n)
		c2 := issue(t, caTmpl(11, "c3r1d TSA CA"), newKey(t), last) // глубина пути c2: n+1
		r := NewRevocations(day(2026, 11, 10))
		r.AddCRL(caOld.crlOf(t, dir, "old.crl", day(2026, 11, 1), day(2026, 12, 1), nil))
		r.AddCRL(c2.crlOf(t, dir, "new.crl", day(2026, 11, 9), day(2026, 12, 9), nil,
			x509.RevocationListEntry{SerialNumber: leaf.SerialNumber, RevocationTime: day(2026, 10, 20), ReasonCode: ReasonKeyCompromise}))
		a := r.NewAssessment()
		a.KnownTrusted(append(certs, c2.cert)...)
		i, err := a.Add(info.Chains, info.GenTime)
		if err != nil {
			t.Fatal(err)
		}
		start := time.Now()
		v := a.Verdicts()[i]
		if v.NeedPOE != c.want {
			t.Errorf("путь из %d центров до корня: NeedPOE=%v, ждали %v", c.n+1, v.NeedPOE, c.want)
		}
		if d := time.Since(start); d > time.Second {
			t.Errorf("обход пути с кольцом: %v", d)
		}
	}
}

// M4. Сертификат вне цепочек, данный проверяющим, без известного центра:
// якоря для CRL — корни всех цепочек оценки (allRoots), второй службы тоже.
// Центр второй службы — тёзка центра основной (другая организация, то же имя,
// номера по порядку), и его CRL отзывает по компрометации свой сертификат с
// тем же номером, что у прежнего сертификата основной службы X0. Запись
// засчитана как запись о X0 — ключ основной службы под подозрением; limitations
// обещает тёзкам с одинаковыми номерами только «не проверено».
func TestC3R1UnknownIssuerAnchorsAllRoots(t *testing.T) {
	dir := t.TempDir()
	rootA := issue(t, caTmpl(1, "c3r1n root A"), newKey(t), nil)
	caA := issue(t, caTmpl(2, "c3r1n TSA CA"), newKey(t), rootA)
	caAold := issue(t, caTmpl(3, "c3r1n TSA CA"), newKey(t), rootA) // прежний ключ центра A: не дан
	kT := newKey(t)
	x1 := issue(t, r1leafTmpl(2, "TSA A", day(2025, 1, 1), day(2029, 1, 1)), kT, caA)
	x0 := issue(t, r1leafTmpl(3, "TSA A", day(2023, 1, 1), day(2027, 1, 1)), kT, caAold)
	rootB := issue(t, caTmpl(1, "c3r1n root B"), newKey(t), nil)
	caB := issue(t, caTmpl(2, "c3r1n TSA CA"), newKey(t), rootB) // тёзка центра A
	poolA := x509.NewCertPool()
	poolA.AddCert(rootA.cert)
	infoA := renewedStamp(t, x1, rootA, day(2026, 10, 15), Trust{Roots: poolA, Intermediates: []*x509.Certificate{caA.cert}})
	_, infoB := tsaUnder(t, caB, day(2030, 1, 1), day(2026, 10, 15), []*x509.Certificate{rootB.cert}, caB.cert)
	r := NewRevocations(day(2026, 11, 10))
	r.AddCRL(caA.crlOf(t, dir, "a.crl", day(2026, 11, 1), day(2026, 12, 1), nil))
	r.AddCRL(rootA.crlOf(t, dir, "rootA.crl", day(2026, 11, 1), day(2026, 12, 1), nil))
	r.AddCRL(rootB.crlOf(t, dir, "rootB.crl", day(2026, 11, 1), day(2026, 12, 1), nil))
	r.AddCRL(caB.crlOf(t, dir, "b.crl", day(2026, 11, 1), day(2026, 12, 1), nil,
		x509.RevocationListEntry{SerialNumber: big.NewInt(3), RevocationTime: day(2026, 9, 1), ReasonCode: ReasonKeyCompromise}))
	a := r.NewAssessment()
	a.KnownTrusted(x0.cert)
	i, err := a.Add(infoA.Chains, infoA.GenTime)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := a.Add(infoB.Chains, infoB.GenTime); err != nil {
		t.Fatal(err)
	}
	v := a.Verdicts()[i]
	t.Logf("NeedPOE=%v Entry=%+v Unchecked=%d", v.NeedPOE, v.Entry, len(v.Unchecked))
	if !v.NeedPOE { // цена правила корней проверяющего (limitations.md)
		t.Errorf("CRL тёзки под доверенным корнем второй службы: по limitations.md его записи в счёт, а ключ не под подозрением")
	}
}

// X1 (подсмотрено в незакоммиченной правке рабочего дерева, проверено на
// 14762ae). Корни цепочки выбирает сборщик пакета сертификатами в токене.
// Центр службы C (ключ K) выпущен корнем R1 и перекрёстно корнем R2 (оба
// доверены проверяющим); центр сменил ключ, сертификат нового ключа C2 выпущен
// R1 и дан проверяющим; CRL нового ключа отзывает службу по компрометации.
// Токен с C от R1 — запись в счёт. Тот же токен с перекрёстным C от R2 (поле
// certificates не подписано) — цепочка к R2, C2 «не под корнем сертификата»,
// компрометация не в счёт, «не проверено», метка в силе.
func TestC3R1ChainChoiceAvoidsRekeyRoot(t *testing.T) {
	dir := t.TempDir()
	r1 := issue(t, caTmpl(1, "c3r1x root 1"), newKey(t), nil)
	r2 := issue(t, caTmpl(2, "c3r1x root 2"), newKey(t), nil)
	kC := newKey(t)
	cR1 := issue(t, caTmpl(10, "c3r1x TSA CA"), kC, r1)
	cR2 := issue(t, caTmpl(0x7a11, "c3r1x TSA CA"), kC, r2)
	c2 := issue(t, caTmpl(11, "c3r1x TSA CA"), newKey(t), r1)
	gen := day(2026, 10, 15)
	pool := x509.NewCertPool()
	pool.AddCert(r1.cert)
	pool.AddCert(r2.cert)
	leaf := issue(t, r1leafTmpl(77, "TSA", day(2025, 1, 1), day(2029, 1, 1)), newKey(t), cR1)
	via := func(ca *pki) Info {
		return renewedStamp(t, leaf, r1, gen, Trust{Roots: pool, Intermediates: []*x509.Certificate{ca.cert}})
	}
	r := NewRevocations(day(2026, 11, 10))
	r.AddCRL(cR1.crlOf(t, dir, "old-key.crl", day(2026, 11, 1), day(2026, 12, 1), nil))
	r.AddCRL(c2.crlOf(t, dir, "new-key.crl", day(2026, 11, 9), day(2026, 12, 9), nil,
		x509.RevocationListEntry{SerialNumber: leaf.cert.SerialNumber, RevocationTime: day(2026, 10, 1), ReasonCode: ReasonKeyCompromise}))
	r.AddCRL(r1.crlOf(t, dir, "r1.crl", day(2026, 11, 1), day(2026, 12, 1), nil))
	r.AddCRL(r2.crlOf(t, dir, "r2.crl", day(2026, 11, 1), day(2026, 12, 1), nil))
	run := func(info Info) Verdict {
		a := r.NewAssessment()
		a.KnownTrusted(c2.cert, r1.cert, r2.cert) // проверяющий дал C2 и оба корня
		i, err := a.Add(info.Chains, info.GenTime)
		if err != nil {
			t.Fatal(err)
		}
		return a.Verdicts()[i]
	}
	if v := run(via(cR1)); !v.NeedPOE {
		t.Fatalf("контроль: цепочка к R1 — компрометация в счёт: %+v", v)
	}
	v := run(via(cR2))
	t.Logf("цепочка через перекрёстный C от R2: NeedPOE=%v Unchecked=%d", v.NeedPOE, len(v.Unchecked))
	if !v.NeedPOE {
		t.Errorf("сборщик пакета увёл цепочку к R2 перекрёстным сертификатом центра: компрометация, засчитанная бы при цепочке к R1, не в счёт")
	}
}
