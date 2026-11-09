package tsa

// Ревью цикла 2, заход 2 (r1): гипотезы по диффу ecad1a9..4d4f528.

import (
	"bytes"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func r1leafTmpl(serial int64, cn string, from, to time.Time) *x509.Certificate {
	return &x509.Certificate{SerialNumber: big.NewInt(serial), Subject: pkix.Name{CommonName: cn}, NotBefore: from, NotAfter: to,
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageTimeStamping}}
}

// H1. Служба перевыпущена на тот же ключ (P-161): цепочка метки идёт через
// прежний X1 (истёк), текущий X2 известен оценке (Known). Центр сменил ключ
// (P-162): X2, выпущенный прежним ключом центра, отозван по компрометации в
// CRL нового ключа, и сертификат нового ключа центра тоже известен оценке.
// Для сертификата цепочки такой CRL в счёт (rekeyedBy); для Known — нет:
// signed(c, x) берёт только CRL ключа, которым выпущен сам c.
func TestRevocationsC2bKnownRenewedCertRevokedByRekeyedCA(t *testing.T) {
	dir := t.TempDir()
	root := issue(t, caTmpl(1, "r1 root"), newKey(t), nil)
	caOld := issue(t, caTmpl(10, "TSA CA"), newKey(t), root)
	caNewT := caTmpl(11, "TSA CA")
	caNewT.NotBefore = day(2026, 9, 1)
	caNew := issue(t, caNewT, newKey(t), root)
	kTSA := newKey(t)
	x1 := issue(t, r1leafTmpl(1, "TSA", day(2024, 1, 1), day(2026, 6, 30)), kTSA, caOld)
	x2 := issue(t, r1leafTmpl(2, "TSA", day(2026, 6, 1), day(2029, 1, 1)), kTSA, caOld)
	pool := x509.NewCertPool()
	pool.AddCert(root.cert)
	info := renewedStamp(t, x1, root, day(2026, 3, 1), Trust{Roots: pool, Intermediates: []*x509.Certificate{caOld.cert}})
	now := day(2027, 3, 10)
	r := NewRevocations(now)
	// CRL прежнего ключа — до смены ключа (статус X1 на то время), CRL нового
	// — после: X2 отозван по компрометации.
	if err := r.AddCRL(caOld.crlOf(t, dir, "old-key.crl", day(2026, 3, 2), day(2026, 4, 2), nil)); err != nil {
		t.Fatal(err)
	}
	if err := r.AddCRL(caNew.crlOf(t, dir, "new-key.crl", day(2027, 3, 1), day(2027, 4, 1), nil,
		x509.RevocationListEntry{SerialNumber: x2.cert.SerialNumber, RevocationTime: day(2027, 2, 20), ReasonCode: ReasonKeyCompromise})); err != nil {
		t.Fatal(err)
	}
	a := r.NewAssessment()
	a.Known(caOld.cert, caNew.cert, x2.cert)
	i, err := a.Add(info.Chains, info.GenTime)
	if err != nil {
		t.Fatal(err)
	}
	v := a.Verdicts()[i]
	t.Logf("known X2 (old CA key), CRL of new CA key: NeedPOE=%v Cutoff=%v Unchecked=%d Notes=%q", v.NeedPOE, v.Cutoff, len(v.Unchecked), v.Notes)
	// Для сравнения: X2 в цепочке (метка под X2) — тот же CRL в счёт.
	info2 := renewedStamp(t, x2, root, day(2026, 10, 1), Trust{Roots: pool, Intermediates: []*x509.Certificate{caOld.cert}})
	a2 := r.NewAssessment()
	a2.Known(caOld.cert, caNew.cert)
	j, err := a2.Add(info2.Chains, info2.GenTime)
	if err != nil {
		t.Fatal(err)
	}
	v2 := a2.Verdicts()[j]
	t.Logf("X2 in chain: NeedPOE=%v Cutoff=%v", v2.NeedPOE, v2.Cutoff)
	if !v2.NeedPOE {
		t.Fatalf("контроль: X2 в цепочке, CRL нового ключа центра — не в счёт: %+v", v2)
	}
	if !v.NeedPOE {
		t.Errorf("X2 известен (Known), отозван по компрометации в CRL нового ключа центра, сертификат нового ключа дан — ключ службы не под подозрением: метка X1 проходит без POE")
	}
}

// H2. Known и удержание: текущий сертификат X2 (тот же ключ) был на
// удержании и снят (более новый CRL его не называет). В цепочке удержание
// снимается (judge); для Known — нет: signed() отдаёт запись удержания как
// есть, и ключ под подозрением с даты удержания.
func TestRevocationsC2bKnownReleasedHold(t *testing.T) {
	dir := t.TempDir()
	root := issue(t, caTmpl(1, "r1 hold root"), newKey(t), nil)
	ca := issue(t, caTmpl(10, "TSA CA"), newKey(t), root)
	kTSA := newKey(t)
	x1 := issue(t, r1leafTmpl(1, "TSA", day(2024, 1, 1), day(2026, 6, 30)), kTSA, ca)
	x2 := issue(t, r1leafTmpl(2, "TSA", day(2026, 6, 1), day(2029, 1, 1)), kTSA, ca)
	pool := x509.NewCertPool()
	pool.AddCert(root.cert)
	info := renewedStamp(t, x1, root, day(2026, 3, 1), Trust{Roots: pool, Intermediates: []*x509.Certificate{ca.cert}})
	now := day(2027, 3, 10)
	r := NewRevocations(now)
	r.AddCRL(ca.crlOf(t, dir, "held.crl", day(2026, 11, 2), day(2026, 12, 2), nil,
		x509.RevocationListEntry{SerialNumber: x2.cert.SerialNumber, RevocationTime: day(2026, 11, 1), ReasonCode: ReasonCertificateHold}))
	r.AddCRL(ca.crlOf(t, dir, "released.crl", day(2027, 3, 1), day(2027, 4, 1), nil))
	r.AddCRL(root.crlOf(t, dir, "root.crl", day(2027, 3, 1), day(2027, 4, 1), nil))
	// Контроль: X2 в цепочке — удержание снято.
	info2 := renewedStamp(t, x2, root, day(2026, 10, 1), Trust{Roots: pool, Intermediates: []*x509.Certificate{ca.cert}})
	if v, err := r.Check(info2.Chains, info2.GenTime); err != nil || v.NeedPOE {
		t.Fatalf("контроль: X2 в цепочке, удержание снято: %+v %v", v, err)
	}
	a := r.NewAssessment()
	a.Known(x2.cert)
	i, err := a.Add(info.Chains, info.GenTime)
	if err != nil {
		t.Fatal(err)
	}
	v := a.Verdicts()[i]
	t.Logf("known X2 released hold: NeedPOE=%v Cutoff=%v From=%q", v.NeedPOE, v.Cutoff, v.Entry.From)
	if v.NeedPOE {
		t.Errorf("X2 известен (Known), удержание снято более новым CRL — ключ всё равно под подозрением с даты удержания (ложная тревога)")
	}
}

// H3. Перечень проверяющего без причины у сертификата центра (корень или
// промежуточный): было — ключ под подозрением (нужна POE), стало — как без
// компрометации: метки до даты в силе без POE.
func TestRevocationsC2bListNoReasonCA(t *testing.T) {
	dir := t.TempDir()
	root := issue(t, caTmpl(1, "r1 list root"), newKey(t), nil)
	ca := issue(t, caTmpl(10, "TSA CA"), newKey(t), root)
	gen := day(2026, 10, 1)
	_, info := tsaUnder(t, ca, day(2030, 1, 1), gen, []*x509.Certificate{root.cert}, ca.cert)
	for name, c := range map[string]*x509.Certificate{"root": root.cert, "intermediate": ca.cert} {
		list := filepath.Join(dir, name+".json")
		data, _ := json.Marshal([]map[string]string{{"cert_sha256": Fingerprint(c), "revoked": day(2026, 10, 20).Format(time.RFC3339)}})
		os.WriteFile(list, data, 0o600)
		r := NewRevocations(day(2026, 11, 2))
		if err := r.AddList(list); err != nil {
			t.Fatal(err)
		}
		r.AddCRL(ca.crlOf(t, dir, "ca.crl", day(2026, 11, 1), day(2026, 12, 1), nil))
		r.AddCRL(root.crlOf(t, dir, "root.crl", day(2026, 11, 1), day(2026, 12, 1), nil))
		v, err := r.Check(info.Chains, info.GenTime)
		t.Logf("%s listed without reason after the stamp: NeedPOE=%v err=%v", name, v.NeedPOE, err)
		if err == nil && !v.NeedPOE {
			t.Errorf("%s в перечне проверяющего без причины: метка до даты — в силе без POE (было: ключ под подозрением)", name)
		}
	}
}

// H4. CRL нового ключа центра признан (rekeyedBy, сертификат нового ключа
// дан) и называет службу выведенной из работы ПОСЛЕ метки: метка в силе, и
// всё о сертификате известно, но он — Unchecked (статус не дан), и метка не
// годится в POE.
func TestRevocationsC2bRekeyedListingSupersededLeavesUnchecked(t *testing.T) {
	dir := t.TempDir()
	root := issue(t, caTmpl(1, "r1 rekey root"), newKey(t), nil)
	caA := issue(t, caTmpl(10, "TSA CA"), newKey(t), root)
	caB := issue(t, caTmpl(11, "TSA CA"), newKey(t), root)
	gen := day(2026, 10, 1)
	leaf, info := tsaUnder(t, caA, day(2030, 1, 1), gen, []*x509.Certificate{root.cert}, caA.cert)
	r := NewRevocations(day(2026, 11, 2))
	r.AddCRL(caA.crlOf(t, dir, "old-key.crl", day(2026, 9, 15), day(2026, 12, 15), nil))
	r.AddCRL(caB.crlOf(t, dir, "new-key.crl", day(2026, 11, 1), day(2026, 12, 1), nil,
		x509.RevocationListEntry{SerialNumber: leaf.cert.SerialNumber, RevocationTime: gen.Add(24 * time.Hour), ReasonCode: ReasonSuperseded}))
	r.AddCRL(root.crlOf(t, dir, "root.crl", day(2026, 11, 1), day(2026, 12, 1), nil))
	a := r.NewAssessment()
	a.Known(caB.cert)
	i, err := a.Add(info.Chains, info.GenTime)
	if err != nil {
		t.Fatal(err)
	}
	v := a.Verdicts()[i]
	t.Logf("rekeyed CRL accepted, superseded after stamp: NeedPOE=%v Retired=%v Unchecked=%d notes=%q", v.NeedPOE, v.Retired, len(v.Unchecked), v.Notes)
	if len(v.Unchecked) > 0 {
		t.Errorf("CRL нового ключа признан и называет сертификат (superseded после метки), а сертификат — непроверенный: метка не годится в POE")
	}
}

// H5. Центры-тёзки с одинаковыми номерами (так у демо-служб: имя корня и
// номера одни): CRL чужого тёзки новее своего и называет тот же номер — свой
// сертификат «не проверен». До P-160 это была заметка; теперь метка такой
// службы — не POE.
func TestRevocationsC2bNamesakeCRLMakesUnchecked(t *testing.T) {
	a, err := NewAuthority(false)
	if err != nil {
		t.Fatal(err)
	}
	b, err := NewAuthority(false)
	if err != nil {
		t.Fatal(err)
	}
	gen := time.Date(2026, 10, 1, 12, 0, 0, 0, time.UTC)
	b.Now = func() time.Time { return gen }
	imprint := [32]byte{1}
	token, err := b.Sign(imprint[:], nil)
	if err != nil {
		t.Fatal(err)
	}
	pool := x509.NewCertPool()
	pool.AddCert(a.Root())
	pool.AddCert(b.Root())
	info, err := Verify(token, imprint, Trust{Roots: pool})
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	now := gen.Add(48 * time.Hour)
	r := NewRevocations(now)
	// Своя служба (b) — CRL своего корня, пустой; основная (a) отозвана по
	// компрометации в CRL своего корня, выпущенном позже.
	bder, _ := b.RevocationList(gen.Add(time.Hour), now.Add(time.Hour))
	ader, _ := a.RevocationList(gen.Add(2*time.Hour), now.Add(time.Hour), x509.RevocationListEntry{SerialNumber: a.Cert().SerialNumber, RevocationTime: gen.Add(30 * time.Minute), ReasonCode: ReasonKeyCompromise})
	os.WriteFile(filepath.Join(dir, "b.crl"), bder, 0o600)
	os.WriteFile(filepath.Join(dir, "a.crl"), ader, 0o600)
	r.AddCRL(filepath.Join(dir, "b.crl"))
	r.AddCRL(filepath.Join(dir, "a.crl"))
	// Корень тёзки, которого принёс токен (подложить его может кто угодно —
	// открытый ключ не секрет), тёзкой не делает: статус не известен.
	as := r.NewAssessment()
	as.Known(a.Root())
	i, _ := as.Add(info.Chains, info.GenTime)
	if v := as.Verdicts()[i]; len(v.Unchecked) == 0 {
		t.Fatalf("тёзка из токена снял «не проверено»: %+v", v)
	}
	as = r.NewAssessment()
	as.KnownTrusted(a.Root(), b.Root()) // корни из -tsa-trust
	i, err = as.Add(info.Chains, info.GenTime)
	v := as.Verdicts()[i]
	t.Logf("namesake: err=%v NeedPOE=%v Unchecked=%d notes=%q", err, v.NeedPOE, len(v.Unchecked), v.Notes)
	if err == nil && len(v.Unchecked) > 0 {
		for _, n := range v.Notes {
			if strings.Contains(n, "newer than") {
				t.Errorf("служба b проверена своим CRL, но CRL тёзки (другой корень, тот же номер) делает её непроверенной: %s", n)
			}
		}
	}
}

// H6. Known без предела: сертификаты, что несут токены (поле certificates в
// CMS не подписано — их может дописать к любому токену кто угодно), идут в
// оценку. Дедупликация в Known — квадрат по числу, цикл Known в Verdicts —
// произведение Known × pool с проверкой подписи на каждой паре, где имя
// издателя совпало с именем субъекта.
func TestRevocationsC2bKnownQuadraticCost(t *testing.T) {
	w := newRevWorld(t)
	k := newKey(t)
	mk := func(n int) []*x509.Certificate {
		out := make([]*x509.Certificate, 0, n)
		for i := range n {
			subj, iss := "A", "B"
			if i%2 == 1 {
				subj, iss = "B", "A"
			}
			tmpl := &x509.Certificate{SerialNumber: big.NewInt(int64(1000 + i)), Subject: pkix.Name{CommonName: subj},
				NotBefore: day(2025, 1, 1), NotAfter: day(2030, 1, 1)}
			parent := &x509.Certificate{Subject: pkix.Name{CommonName: iss}}
			c := issue(t, tmpl, k, &pki{cert: parent, key: k})
			out = append(out, c.cert)
		}
		return out
	}
	r := NewRevocations(w.gen.Add(48 * time.Hour))
	for _, n := range []int{200, 400, 800} {
		junk := mk(n)
		start := time.Now()
		a := r.NewAssessment()
		a.Known(junk...)
		known := time.Since(start)
		a.Add(w.info.Chains, w.info.GenTime)
		start = time.Now()
		a.Verdicts()
		if took := time.Since(start); took > 5*time.Second {
			t.Errorf("junk certs %d: Known %v, Verdicts %v", n, known, took)
		}
	}
}

// H8. rekeyedBy: путь нового ключа центра сверяется к сертификату корня из
// цепочек метки на момент CRL. Корень продлён на тот же ключ (R1 истёк, R1'
// действует): цепочки старых меток — к R1, и путь сертификата нового ключа
// центра на дату CRL к R1 не строится (R1 истёк), хотя якорь тот же (имя и
// ключ). Запись о компрометации не в счёт, сертификат «не проверен».
func TestRevocationsC2bRekeyedCAAfterRootRenewedSameKey(t *testing.T) {
	dir := t.TempDir()
	kRoot := newKey(t)
	r1T := caTmpl(1, "renewed root")
	r1T.NotBefore, r1T.NotAfter = day(2016, 1, 1), day(2026, 12, 31)
	r1 := issue(t, r1T, kRoot, nil)
	r2T := caTmpl(2, "renewed root")
	r2T.NotBefore, r2T.NotAfter = day(2026, 6, 1), day(2036, 12, 31)
	r2 := issue(t, r2T, kRoot, nil)
	caOld := issue(t, caTmpl(10, "TSA CA"), newKey(t), r1)
	caNewT := caTmpl(11, "TSA CA")
	caNewT.NotBefore = day(2027, 2, 1)
	caNew := issue(t, caNewT, newKey(t), r2)
	gen := day(2025, 10, 1)
	leaf, info := tsaUnder(t, caOld, day(2030, 1, 1), gen, []*x509.Certificate{r1.cert, r2.cert}, caOld.cert)
	t.Logf("chains: %d, roots: %v", len(info.Chains), func() []string {
		var s []string
		for _, ch := range info.Chains {
			s = append(s, ch[len(ch)-1].SerialNumber.String())
		}
		return s
	}())
	r := NewRevocations(day(2027, 3, 10))
	r.AddCRL(caOld.crlOf(t, dir, "old-key.crl", day(2026, 12, 1), day(2027, 1, 1), nil))
	r.AddCRL(caNew.crlOf(t, dir, "new-key.crl", day(2027, 3, 1), day(2027, 4, 1), nil,
		x509.RevocationListEntry{SerialNumber: leaf.cert.SerialNumber, RevocationTime: day(2027, 2, 20), ReasonCode: ReasonKeyCompromise}))
	a := r.NewAssessment()
	a.Known(caOld.cert, caNew.cert)
	i, err := a.Add(info.Chains, info.GenTime)
	if err != nil {
		t.Fatal(err)
	}
	v := a.Verdicts()[i]
	t.Logf("NeedPOE=%v Unchecked=%d notes=%q", v.NeedPOE, len(v.Unchecked), v.Notes)
	if !v.NeedPOE {
		t.Errorf("центр сменил ключ под продлённым на тот же ключ корнем, сертификат нового ключа дан: компрометация не в счёт")
	}
}

// P-177, худший случай: сертификаты-мусор с открытым ключом самой службы
// (ключ не секрет) и именами, ссылающимися друг на друга, — фильтр по ключам
// цепочек их не отсеет. Центром сертификату вне цепочек может быть только
// сертификат цепочки или данный проверяющим, так что подписи мусора друг о
// друге не сверяются: время линейно.
func TestRevocationsC2bKnownJunkWithChainKey(t *testing.T) {
	w := newRevWorld(t)
	signer := newKey(t)
	var junk []*x509.Certificate
	for i := range 1024 {
		subj, iss := "J", "Q"
		if i%2 == 1 {
			subj, iss = "Q", "J"
		}
		tmpl := &x509.Certificate{SerialNumber: big.NewInt(int64(5000 + i)), Subject: pkix.Name{CommonName: subj},
			NotBefore: day(2025, 1, 1), NotAfter: day(2030, 1, 1)}
		parent := &x509.Certificate{Subject: pkix.Name{CommonName: iss}}
		der, err := x509.CreateCertificate(rand.Reader, tmpl, parent, w.a.Cert().PublicKey, signer)
		if err != nil {
			t.Fatal(err)
		}
		c, err := x509.ParseCertificate(der)
		if err != nil {
			t.Fatal(err)
		}
		junk = append(junk, c)
	}
	r := NewRevocations(w.gen.Add(48 * time.Hour))
	start := time.Now()
	a := r.NewAssessment()
	a.Known(junk...)
	i, err := a.Add(w.info.Chains, w.info.GenTime)
	if err != nil {
		t.Fatal(err)
	}
	v := a.Verdicts()[i]
	if took := time.Since(start); took > 2*time.Second || v.NeedPOE {
		t.Fatalf("1024 сертификата с ключом службы: %v, %+v", took, v)
	}
}

// P-187. Подписант по номеру ключа: у перевыпущенного на тот же ключ
// сертификата номер ключа тот же. Токен без своего сертификата, оба — в
// доверии, прежний первым: годен тот, кого называет signingCertificate.
func TestSignerByKeyIDAmongRenewedCerts(t *testing.T) {
	root := issue(t, caTmpl(1, "skid root"), newKey(t), nil)
	ca := issue(t, caTmpl(10, "TSA CA"), newKey(t), root)
	k := newKey(t)
	skid := []byte{1, 2, 3, 4, 5, 6, 7, 8}
	tmpl := func(serial int64) *x509.Certificate {
		return &x509.Certificate{SerialNumber: big.NewInt(serial), Subject: pkix.Name{CommonName: "TSA"}, NotBefore: day(2025, 1, 1), NotAfter: day(2030, 1, 1),
			SubjectKeyId: skid, KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageTimeStamping}}
	}
	x1, x2 := issue(t, tmpl(1), k, ca), issue(t, tmpl(2), k, ca)
	a := &Authority{key: x2.key, cert: x2.cert, root: root.cert, policy: demoPolicy, Now: func() time.Time { return day(2026, 10, 1) }}
	a.SignByKeyID()
	a.WithoutCert()
	imprint := [32]byte{9}
	token, err := a.Sign(imprint[:], nil)
	if err != nil {
		t.Fatal(err)
	}
	pool := x509.NewCertPool()
	pool.AddCert(root.cert)
	info, err := Verify(token, imprint, Trust{Roots: pool, Intermediates: []*x509.Certificate{x1.cert, x2.cert, ca.cert}})
	if err != nil || !bytes.Equal(info.Signer.Raw, x2.cert.Raw) {
		t.Fatalf("подписант по номеру ключа, прежний сертификат в доверии первым: %v", err)
	}
}
