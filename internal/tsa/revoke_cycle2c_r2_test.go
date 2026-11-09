package tsa

// Ревью цикла 2, заход 3 (r2): гипотезы по диффу 2c7da6d..dcef3db.

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/pem"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// N1. «Тёзка» в rekeyedBy — не «подписант ведёт к другому корню», а «путь к
// корню цепочки на дату CRL не построился». Трёхуровневый центр: корень
// продлён на тот же ключ (R1 истёк, R2 действует), под ним Policy CA, под ним
// TSA CA, сменивший ключ (C2 выпущен Policy CA). Цепочки старой метки — к R1.
// Проверяющий дал всё: R1, R2, Policy CA, C1, C2 и все CRL. CRL нового ключа
// TSA CA отзывает службу по компрометации. Путь C2 → Policy CA → R1 на дату
// CRL не строится (R1 истёк; R2 в пуле — промежуточный, якорь — только R1),
// прямой выпуск ключом корня (P-181) не тот случай (C2 выпущен Policy CA).
// Итог: CRL назван центром-тёзкой, статус «проверен», компрометация не в счёт.
func TestC2cR2NamesakeWhenPathFailsRootRenewed3Level(t *testing.T) {
	dir := t.TempDir()
	kR := newKey(t)
	r1T := caTmpl(1, "r2c renewed root")
	r1T.NotBefore, r1T.NotAfter = day(2016, 1, 1), day(2026, 12, 31)
	r1 := issue(t, r1T, kR, nil)
	r2T := caTmpl(2, "r2c renewed root")
	r2T.NotBefore, r2T.NotAfter = day(2026, 6, 1), day(2036, 12, 31)
	r2 := issue(t, r2T, kR, nil)
	p := issue(t, caTmpl(5, "Policy CA"), newKey(t), r1)
	c1 := issue(t, caTmpl(10, "TSA CA"), newKey(t), p)
	c2T := caTmpl(11, "TSA CA")
	c2T.NotBefore = day(2027, 2, 1)
	c2 := issue(t, c2T, newKey(t), p)
	gen := day(2025, 10, 1)
	leaf, info := tsaUnder(t, c1, day(2030, 1, 1), gen, []*x509.Certificate{r1.cert, r2.cert}, p.cert, c1.cert)
	for _, ch := range info.Chains {
		t.Logf("chain root: serial %v, valid to %v", ch[len(ch)-1].SerialNumber, ch[len(ch)-1].NotAfter)
	}
	r := NewRevocations(day(2027, 3, 10))
	for _, f := range []string{
		c1.crlOf(t, dir, "old-key.crl", day(2026, 12, 1), day(2027, 1, 1), nil),
		c2.crlOf(t, dir, "new-key.crl", day(2027, 3, 1), day(2027, 4, 1), nil,
			x509.RevocationListEntry{SerialNumber: leaf.cert.SerialNumber, RevocationTime: day(2027, 2, 20), ReasonCode: ReasonKeyCompromise}),
		p.crlOf(t, dir, "policy.crl", day(2027, 3, 1), day(2027, 4, 1), nil),
		r2.crlOf(t, dir, "root.crl", day(2027, 3, 1), day(2027, 4, 1), nil),
	} {
		if err := r.AddCRL(f); err != nil {
			t.Fatal(err)
		}
	}
	a := r.NewAssessment()
	// Как esverify: -tsa-trust — промежуточные (Intermediates) и корни (RootCerts).
	a.KnownTrusted(p.cert, c1.cert, c2.cert)
	a.KnownTrusted(r1.cert, r2.cert)
	i, err := a.Add(info.Chains, info.GenTime)
	if err != nil {
		t.Fatal(err)
	}
	v := a.Verdicts()[i]
	t.Logf("NeedPOE=%v Unchecked=%d CRLs=%q", v.NeedPOE, len(v.Unchecked), v.CRLs)
	for _, n := range v.Notes {
		t.Logf("note: %s", n)
	}
	if !v.NeedPOE && len(v.Unchecked) == 0 {
		t.Errorf("служба отозвана по компрометации в CRL нового ключа центра (C2 ведёт к тому же корню — имя и ключ), проверяющий дал все сертификаты: метка без POE, статус «проверен», CRL назван тёзкой")
	}
	if hasNote(v, "of another CA") {
		t.Errorf("отчёт называет CRL нового ключа того же центра CRL другого центра-тёзки (ключ ведёт к тому же корню)")
	}
}

// N2. То же в двухуровневом центре: C2 выпущен новым промежуточным центром,
// которого проверяющий не дал (дал C2, как велит документ). Путь не строится
// — и вместо «не проверено» (до диффа) — «тёзка», статус «проверен».
func TestC2cR2NamesakeWhenIntermediateMissing(t *testing.T) {
	dir := t.TempDir()
	root := issue(t, caTmpl(1, "r2c root"), newKey(t), nil)
	c1 := issue(t, caTmpl(10, "TSA CA"), newKey(t), root)
	pNew := issue(t, caTmpl(6, "Issuing CA 2027"), newKey(t), root)
	c2T := caTmpl(11, "TSA CA")
	c2T.NotBefore = day(2027, 2, 1)
	c2 := issue(t, c2T, newKey(t), pNew)
	gen := day(2026, 10, 1)
	leaf, info := tsaUnder(t, c1, day(2030, 1, 1), gen, []*x509.Certificate{root.cert}, c1.cert)
	r := NewRevocations(day(2027, 3, 10))
	for _, f := range []string{
		c1.crlOf(t, dir, "old-key.crl", day(2026, 12, 1), day(2027, 1, 1), nil),
		c2.crlOf(t, dir, "new-key.crl", day(2027, 3, 1), day(2027, 4, 1), nil,
			x509.RevocationListEntry{SerialNumber: leaf.cert.SerialNumber, RevocationTime: day(2027, 2, 20), ReasonCode: ReasonKeyCompromise}),
		root.crlOf(t, dir, "root.crl", day(2027, 3, 1), day(2027, 4, 1), nil),
	} {
		if err := r.AddCRL(f); err != nil {
			t.Fatal(err)
		}
	}
	a := r.NewAssessment()
	a.KnownTrusted(c1.cert, c2.cert)
	a.KnownTrusted(root.cert)
	i, err := a.Add(info.Chains, info.GenTime)
	if err != nil {
		t.Fatal(err)
	}
	v := a.Verdicts()[i]
	t.Logf("NeedPOE=%v Unchecked=%d", v.NeedPOE, len(v.Unchecked))
	for _, n := range v.Notes {
		t.Logf("note: %s", n)
	}
	if !v.NeedPOE && len(v.Unchecked) == 0 {
		t.Errorf("путь C2 к корню не построился (нет промежуточного): вместо «не проверено» — статус «проверен», компрометация не видна")
	}
	if hasNote(v, "of another CA") {
		t.Errorf("отчёт называет CRL тёзкой, хотя C2 ведёт к тому же корню (нет лишь промежуточного)")
	}
	// Контроль: с промежуточным — в счёт.
	a = r.NewAssessment()
	a.KnownTrusted(c1.cert, c2.cert, pNew.cert)
	a.KnownTrusted(root.cert)
	i, _ = a.Add(info.Chains, info.GenTime)
	if v := a.Verdicts()[i]; !v.NeedPOE {
		t.Fatalf("контроль: с промежуточным CRL нового ключа не в счёт: %+v", v)
	}
}

// K1. Сертификат вне цепочек (Known) и CRL под неизвестным ключом центра.
// Служба перевыпущена на тот же ключ: X1 — в цепочке (действует, его статус
// по CRL прежнего ключа «проверен»), X2 — в -tsa-trust, как велит документ.
// Центр сменил ключ и отозвал X2 по компрометации новым ключом; сертификата
// нового ключа проверяющий не знает. Для сертификата цепочки это «not used …
// pass that certificate in -tsa-trust» и «не проверено»; для Known заметки
// judge и Verdicts выбрасываются (Known — без статуса), а CRL попадает в
// Named (extra) — и о нём отчёт молчит совсем.
func TestC2cR2KnownListedByUnknownKeySilent(t *testing.T) {
	dir := t.TempDir()
	root := issue(t, caTmpl(1, "r2c k root"), newKey(t), nil)
	caOld := issue(t, caTmpl(10, "TSA CA"), newKey(t), root)
	caNewT := caTmpl(11, "TSA CA")
	caNewT.NotBefore = day(2026, 9, 1)
	caNew := issue(t, caNewT, newKey(t), root)
	kTSA := newKey(t)
	x1 := issue(t, r1leafTmpl(1, "TSA", day(2024, 1, 1), day(2028, 6, 30)), kTSA, caOld)
	x2 := issue(t, r1leafTmpl(2, "TSA", day(2026, 6, 1), day(2029, 1, 1)), kTSA, caOld)
	pool := x509.NewCertPool()
	pool.AddCert(root.cert)
	info := renewedStamp(t, x1, root, day(2026, 3, 1), Trust{Roots: pool, Intermediates: []*x509.Certificate{caOld.cert}})
	r := NewRevocations(day(2027, 3, 10))
	for _, f := range []string{
		caOld.crlOf(t, dir, "old-key.crl", day(2027, 3, 1), day(2027, 4, 1), nil),
		caNew.crlOf(t, dir, "new-key.crl", day(2027, 3, 2), day(2027, 4, 1), nil,
			x509.RevocationListEntry{SerialNumber: x2.cert.SerialNumber, RevocationTime: day(2027, 2, 20), ReasonCode: ReasonKeyCompromise}),
		root.crlOf(t, dir, "root.crl", day(2027, 3, 1), day(2027, 4, 1), nil),
	} {
		if err := r.AddCRL(f); err != nil {
			t.Fatal(err)
		}
	}
	a := r.NewAssessment()
	a.KnownTrusted(caOld.cert, x2.cert)
	a.KnownTrusted(root.cert)
	i, err := a.Add(info.Chains, info.GenTime)
	if err != nil {
		t.Fatal(err)
	}
	v := a.Verdicts()[i]
	t.Logf("NeedPOE=%v Unchecked=%d Named=%d", v.NeedPOE, len(v.Unchecked), len(v.Named))
	for _, n := range v.Notes {
		t.Logf("note: %s", n)
	}
	// Заметка о CRL от X1 («names the issuer, but is not signed with its key:
	// not used») бывает у любого честного CRL другого ключа (AD CS: CRL на
	// каждый ключ) и о том, что CRL называет сертификат ключа, не говорит.
	mentioned := false
	for _, n := range v.Notes {
		if strings.Contains(n, "new-key.crl") && (strings.Contains(n, "lists") || strings.Contains(n, "not checked")) {
			mentioned = true
		}
	}
	if !v.NeedPOE && len(v.Unchecked) == 0 && !mentioned {
		t.Errorf("CRL под новым ключом центра отзывает X2 (ключ службы) по компрометации; сертификата нового ключа нет: ни «не проверено», ни заметки, что CRL называет сертификат ключа (CRL в Named)")
	}
	// Контроль: X2 в цепочке — заметка и «не проверено».
	info2 := renewedStamp(t, x2, root, day(2026, 10, 1), Trust{Roots: pool, Intermediates: []*x509.Certificate{caOld.cert}})
	a2 := r.NewAssessment()
	a2.KnownTrusted(caOld.cert)
	j, _ := a2.Add(info2.Chains, info2.GenTime)
	v2 := a2.Verdicts()[j]
	if len(v2.Unchecked) == 0 || !hasNote(v2, "pass that certificate in -tsa-trust") {
		t.Fatalf("контроль: X2 в цепочке: %+v", v2)
	}
}

// B1. brokenBoundary: строка, что начинается или кончается двумя тире и
// называет CRL, — отказ. До диффа отказ был только у «-----»: «-- CRL … --»
// проходило. Законный комментарий теперь — отказ.
func TestC2cR2BrokenBoundaryTwoDashes(t *testing.T) {
	w := newRevWorld(t)
	now := w.gen.Add(48 * time.Hour)
	fresh, _ := os.ReadFile(w.crlAt("fresh.crl", w.gen.Add(24*time.Hour), now.Add(time.Hour), nil))
	good := string(pem.EncodeToMemory(&pem.Block{Type: "X509 CRL", Bytes: fresh}))
	for _, pre := range []string{
		"-- CRL of NCA RK, fetched 2026-11-10\n",
		"CRL list --\n",
		"=== x509 --\n",
	} {
		p := filepath.Join(w.dir, "text.pem")
		os.WriteFile(p, []byte(pre+good), 0o600)
		if err := NewRevocations(now).AddCRL(p); err != nil {
			t.Errorf("%q: %v", pre, err)
		}
	}
}

// S1. findSigners: по SID подходят все сертификаты пула, и для каждого
// сверяется подпись (дорого) раньше атрибута signingCertificate (дёшево).
// Поле certificates не подписано: токен с сотней подложенных сертификатов
// того же issuer и номера, стоящих раньше настоящего, проверяется в сотню
// раз дольше. До диффа брался первый — и токен не проходил.
func TestC2cR2FindSignersCost(t *testing.T) {
	if testing.Short() {
		t.Skip("замер")
	}
	w := newRevWorld(t)
	imprint := sha256.Sum256([]byte("head"))
	clean, err := w.a.Sign(imprint[:], nil)
	if err != nil {
		t.Fatal(err)
	}
	var fakes []*x509.Certificate
	for i := range 130 {
		k, _ := ecdsa.GenerateKey(elliptic.P521(), rand.Reader)
		tmpl := *w.a.Cert()
		tmpl.PublicKey = nil
		der, err := x509.CreateCertificate(rand.Reader, &tmpl, w.a.Root(), k.Public(), w.a.rootKey)
		if err != nil {
			t.Fatal(err)
		}
		c, _ := x509.ParseCertificate(der)
		fakes = append(fakes, c)
		_ = i
	}
	// Токен с подложенными сертификатами впереди своего.
	stuffedTok, err := w.a.signWithLeading(imprint[:], fakes)
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("token sizes: clean %d, stuffed %d", len(clean), len(stuffedTok))
	if len(stuffedTok) > MaxTokenSize {
		t.Skipf("stuffed token too large: %d", len(stuffedTok))
	}
	measure := func(token []byte) time.Duration {
		start := time.Now()
		for range 10 {
			if _, err := Verify(token, imprint, w.a.Trust()); err != nil {
				t.Fatal(err)
			}
		}
		return time.Since(start) / 10
	}
	c, s := measure(clean), measure(stuffedTok)
	t.Logf("Verify: clean %v, stuffed %v (x%.0f)", c, s, float64(s)/float64(c))
	// Подпись сверяется только у названного атрибутом: остаётся разбор
	// сертификатов (около x13); подпись у каждого — около x970.
	if s > 100*c {
		t.Errorf("130 подложенных сертификатов с тем же SID: Verify в %.0f раз дольше — подпись сверяется у каждого", float64(s)/float64(c))
	}
}

// N3. То же, что N1, но проверяющий C2 не давал (о смене ключа центра не
// знал), а доверяет обоим сертификатам корня (R1 и продлённому R2). Без
// второй метки — «не проверено» (документ: сертификата нового ключа нет —
// не проверено). Сборщик пакета добавляет метку второй службы — токен самой
// службы под новым сертификатом (выпущен C2) над головой пакета, C2 и Policy
// CA дописаны в поле certificates: её цепочка C2 → Policy CA → R2 строится
// на её время, C2 становится «сертификатом цепочки» (vouched), путь C2 к R1
// на дату CRL не строится — «тёзка», и предупреждение пропадает.
func TestC2cR2NamesakeForcedByExtraStamp(t *testing.T) {
	dir := t.TempDir()
	kR := newKey(t)
	r1T := caTmpl(1, "r2c renewed root")
	r1T.NotBefore, r1T.NotAfter = day(2016, 1, 1), day(2026, 12, 31)
	r1 := issue(t, r1T, kR, nil)
	r2T := caTmpl(2, "r2c renewed root")
	r2T.NotBefore, r2T.NotAfter = day(2026, 6, 1), day(2036, 12, 31)
	r2 := issue(t, r2T, kR, nil)
	p := issue(t, caTmpl(5, "Policy CA"), newKey(t), r1)
	c1 := issue(t, caTmpl(10, "TSA CA"), newKey(t), p)
	c2T := caTmpl(11, "TSA CA")
	c2T.NotBefore = day(2027, 2, 1)
	c2 := issue(t, c2T, newKey(t), p)
	leaf, info := tsaUnder(t, c1, day(2030, 1, 1), day(2025, 10, 1), []*x509.Certificate{r1.cert, r2.cert}, p.cert, c1.cert)
	// Новый сертификат службы под C2; токен несёт C2 и Policy CA.
	_, info2 := tsaUnder(t, c2, day(2030, 1, 1), day(2027, 3, 5), []*x509.Certificate{r1.cert, r2.cert}, p.cert, c2.cert)
	r := NewRevocations(day(2027, 3, 10))
	for _, f := range []string{
		c1.crlOf(t, dir, "old-key.crl", day(2026, 12, 1), day(2027, 1, 1), nil),
		c2.crlOf(t, dir, "new-key.crl", day(2027, 3, 1), day(2027, 4, 1), nil,
			x509.RevocationListEntry{SerialNumber: leaf.cert.SerialNumber, RevocationTime: day(2027, 2, 20), ReasonCode: ReasonKeyCompromise}),
		p.crlOf(t, dir, "policy.crl", day(2027, 3, 1), day(2027, 4, 1), nil),
		r2.crlOf(t, dir, "root.crl", day(2027, 3, 1), day(2027, 4, 1), nil),
	} {
		if err := r.AddCRL(f); err != nil {
			t.Fatal(err)
		}
	}
	run := func(extra bool) Verdict {
		a := r.NewAssessment()
		a.KnownTrusted(p.cert, c1.cert) // -tsa-trust: без C2
		a.KnownTrusted(r1.cert, r2.cert)
		i, err := a.Add(info.Chains, info.GenTime)
		if err != nil {
			t.Fatal(err)
		}
		if extra {
			a.Known(c2.cert, p.cert) // сертификаты токена
			if _, err := a.Add(info2.Chains, info2.GenTime); err != nil {
				t.Fatal(err)
			}
		}
		return a.Verdicts()[i]
	}
	if v := run(false); len(v.Unchecked) == 0 && !v.NeedPOE {
		t.Fatalf("контроль: без C2 — «не проверено»: %+v", v)
	}
	v := run(true)
	t.Logf("with extra stamp: NeedPOE=%v Unchecked=%d", v.NeedPOE, len(v.Unchecked))
	for _, n := range v.Notes {
		t.Logf("note: %s", n)
	}
	if !v.NeedPOE && len(v.Unchecked) == 0 {
		t.Errorf("лишняя метка в пакете (цепочка через C2) сняла «не проверено»: компрометация не видна, отчёт — «проверен»")
	}
}
