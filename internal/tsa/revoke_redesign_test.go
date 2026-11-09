package tsa

// Пересмотр 10.11 (DECISIONS, п. 35; FINDINGS, цикл 2, заход 3): CRL под
// другим ключом центра в счёт, только когда этот ключ выпущен под корнем
// сертификата (корень — имя и ключ, сроки не сверяются) сертификатами цепочек
// или проверяющего; иначе — «не проверено», тёзок проверка не признаёт.

import (
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/pem"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// Ключ нового центра выпущен под корнем, но сертификат пути истёк к дате CRL:
// сроки не сверяются — запись в счёт. Тот же сертификат нового ключа, если
// его несёт только токен, ключа не связывает: «не проверено».
func TestRevocationsRedesignPathIgnoresDatesAndTokenCerts(t *testing.T) {
	dir := t.TempDir()
	root := issue(t, caTmpl(1, "rd root"), newKey(t), nil)
	pT := caTmpl(5, "rd policy")
	pT.NotBefore, pT.NotAfter = day(2020, 1, 1), day(2026, 12, 31) // истёк к CRL
	policy := issue(t, pT, newKey(t), root)
	caOld := issue(t, caTmpl(10, "rd TSA CA"), newKey(t), policy)
	caNew := issue(t, caTmpl(11, "rd TSA CA"), newKey(t), policy)
	gen := day(2026, 10, 1)
	_, info := tsaUnder(t, caOld, day(2030, 1, 1), gen, []*x509.Certificate{root.cert}, policy.cert, caOld.cert)
	leaf := info.Chains[0][0]
	r := NewRevocations(day(2027, 3, 10))
	r.AddCRL(caOld.crlOf(t, dir, "old.crl", day(2026, 12, 1), day(2027, 1, 1), nil))
	r.AddCRL(caNew.crlOf(t, dir, "new.crl", day(2027, 3, 1), day(2027, 4, 1), nil,
		x509.RevocationListEntry{SerialNumber: leaf.SerialNumber, RevocationTime: day(2027, 2, 20), ReasonCode: ReasonKeyCompromise}))
	run := func(add func(a *Assessment)) Verdict {
		a := r.NewAssessment()
		add(a)
		i, err := a.Add(info.Chains, info.GenTime)
		if err != nil {
			t.Fatal(err)
		}
		return a.Verdicts()[i]
	}
	if v := run(func(a *Assessment) { a.KnownTrusted(caNew.cert) }); !v.NeedPOE || !strings.Contains(v.Entry.From, "new.crl") || !hasNote(v, "under a root of -tsa-trust") {
		t.Fatalf("сертификат нового ключа дан, промежуточный истёк к дате CRL: компрометация не в счёт: %+v", v)
	}
	v := run(func(a *Assessment) { a.Known(caNew.cert) })
	if v.NeedPOE || len(v.Unchecked) == 0 || !hasNote(v, "lists it as revoked, and its signature cannot be checked") {
		t.Fatalf("сертификат нового ключа только в токене: %+v", v)
	}
}

// Корень продлён на тот же ключ, а центр выпущен прямо ключом корня под новым
// ключом: корень — имя и ключ, оба сертификата корня — один корень.
func TestRevocationsRedesignAnchorIsNameAndKey(t *testing.T) {
	dir := t.TempDir()
	kRoot := newKey(t)
	r1T := caTmpl(1, "rd2 root")
	r1T.NotBefore, r1T.NotAfter = day(2016, 1, 1), day(2026, 12, 31)
	r1 := issue(t, r1T, kRoot, nil)
	r2T := caTmpl(2, "rd2 root")
	r2T.NotBefore, r2T.NotAfter = day(2026, 6, 1), day(2036, 12, 31)
	r2 := issue(t, r2T, kRoot, nil)
	caOld := issue(t, caTmpl(10, "rd2 TSA CA"), newKey(t), r1)
	caNew := issue(t, caTmpl(11, "rd2 TSA CA"), newKey(t), r2) // выпущен продлённым корнем
	gen := day(2026, 3, 1)
	_, info := tsaUnder(t, caOld, day(2030, 1, 1), gen, []*x509.Certificate{r1.cert}, caOld.cert)
	leaf := info.Chains[0][0]
	r := NewRevocations(day(2027, 3, 10))
	r.AddCRL(caOld.crlOf(t, dir, "old.crl", day(2026, 12, 1), day(2027, 1, 1), nil))
	r.AddCRL(caNew.crlOf(t, dir, "new.crl", day(2027, 3, 1), day(2027, 4, 1), nil,
		x509.RevocationListEntry{SerialNumber: leaf.SerialNumber, RevocationTime: day(2027, 2, 20), ReasonCode: ReasonKeyCompromise}))
	a := r.NewAssessment()
	a.KnownTrusted(caNew.cert) // r2 не дан: выпуск ключом корня сверяется по r1
	i, err := a.Add(info.Chains, info.GenTime)
	if err != nil {
		t.Fatal(err)
	}
	if v := a.Verdicts()[i]; !v.NeedPOE {
		t.Fatalf("центр выпущен продлённым корнем (тот же ключ): компрометация не в счёт: %+v", v)
	}
}

// Удержание в CRL прежнего ключа снимает только CRL прежнего ключа: CRL
// нового ключа, который сертификат не называет, его не снимает (AD CS: у
// каждого ключа свой CRL, сертификатов прежнего ключа в CRL нового нет).
// limitations.md.
func TestRevocationsRedesignHoldNotReleasedAcrossKeys(t *testing.T) {
	dir := t.TempDir()
	root := issue(t, caTmpl(1, "rd3 root"), newKey(t), nil)
	caOld := issue(t, caTmpl(10, "rd3 TSA CA"), newKey(t), root)
	caNew := issue(t, caTmpl(11, "rd3 TSA CA"), newKey(t), root)
	gen := day(2026, 10, 15)
	_, info := tsaUnder(t, caOld, day(2030, 1, 1), gen, []*x509.Certificate{root.cert}, caOld.cert)
	leaf := info.Chains[0][0]
	r := NewRevocations(day(2026, 11, 10))
	r.AddCRL(caOld.crlOf(t, dir, "hold.crl", day(2026, 10, 6), day(2026, 12, 6), nil,
		x509.RevocationListEntry{SerialNumber: leaf.SerialNumber, RevocationTime: day(2026, 10, 5), ReasonCode: ReasonCertificateHold}))
	r.AddCRL(caNew.crlOf(t, dir, "new.crl", day(2026, 11, 9), day(2026, 12, 9), nil))
	a := r.NewAssessment()
	a.KnownTrusted(caNew.cert)
	i, err := a.Add(info.Chains, info.GenTime)
	if err != nil {
		t.Fatal(err)
	}
	if v := a.Verdicts()[i]; !v.NeedPOE || v.Entry.Reason != ReasonCertificateHold {
		t.Fatalf("удержание в CRL прежнего ключа снято CRL нового: %+v", v)
	}
}

// Две демо-службы — разные центры: имя корня и номера у каждой свои.
func TestDemoAuthoritiesDiffer(t *testing.T) {
	a, err := NewAuthority(false)
	if err != nil {
		t.Fatal(err)
	}
	b, err := NewAuthority(false)
	if err != nil {
		t.Fatal(err)
	}
	switch {
	case string(a.Root().RawSubject) == string(b.Root().RawSubject), a.Cert().Issuer.String() == b.Cert().Issuer.String():
		t.Fatalf("имя корня одно: %s", a.Root().Subject)
	case a.Cert().SerialNumber.Cmp(b.Cert().SerialNumber) == 0, a.Root().SerialNumber.Cmp(b.Root().SerialNumber) == 0:
		t.Fatalf("номера совпали: %v %v", a.Cert().SerialNumber, a.Root().SerialNumber)
	case a.Cert().SerialNumber.Sign() <= 0 || a.Root().SerialNumber.Sign() <= 0:
		t.Fatalf("номер не положителен: %v %v", a.Cert().SerialNumber, a.Root().SerialNumber)
	}
}

// Отброшенный сверх предела сертификат считается раз, сколько бы токенов его
// ни несли.
func TestRevocationsDroppedCountedOnce(t *testing.T) {
	w := newRevWorld(t)
	r := NewRevocations(w.gen.Add(time.Hour))
	a := r.NewAssessment()
	junk := make([]*x509.Certificate, maxKnown)
	for i := range junk {
		junk[i] = issue(t, caTmpl(int64(1000+i), "junk"), w.a.key, nil).cert
	}
	a.Known(junk...)
	extra := issue(t, caTmpl(5000, "junk"), w.a.key, nil).cert
	for range 3 {
		a.Known(extra)
	}
	i, err := a.Add(w.info.Chains, w.info.GenTime)
	if err != nil {
		t.Fatal(err)
	}
	if v := a.Verdicts()[i]; !hasNote(v, "1 of them were not looked at") {
		t.Fatalf("один отброшенный, принесённый трижды: %q", v.Notes)
	}
}

// Сертификат, данный проверяющим, вне цепочек, его центр не известен (новый
// ключ центра не дан), и CRL с именем центра называет его: ключ — ключ
// сертификата цепочки, и его статус «не проверен». Тот же сертификат из
// токена не судится: подложить его может кто угодно.
func TestRevocationsRedesignTrustedKnownWithoutIssuer(t *testing.T) {
	dir := t.TempDir()
	root := issue(t, caTmpl(1, "rd4 root"), newKey(t), nil)
	caOld := issue(t, caTmpl(10, "rd4 TSA CA"), newKey(t), root)
	caNew := issue(t, caTmpl(11, "rd4 TSA CA"), newKey(t), root) // проверяющему не дан
	kTSA := newKey(t)
	x1 := issue(t, r1leafTmpl(1, "TSA", day(2024, 1, 1), day(2029, 1, 1)), kTSA, caOld)
	x2 := issue(t, r1leafTmpl(2, "TSA", day(2026, 6, 1), day(2029, 1, 1)), kTSA, caNew)
	pool := x509.NewCertPool()
	pool.AddCert(root.cert)
	info := renewedStamp(t, x1, root, day(2026, 10, 15), Trust{Roots: pool, Intermediates: []*x509.Certificate{caOld.cert}})
	r := NewRevocations(day(2026, 11, 10))
	r.AddCRL(root.crlOf(t, dir, "root.crl", day(2026, 11, 1), day(2026, 12, 1), nil))
	r.AddCRL(caOld.crlOf(t, dir, "old.crl", day(2026, 11, 1), day(2026, 12, 1), nil))
	r.AddCRL(caNew.crlOf(t, dir, "new.crl", day(2026, 11, 9), day(2026, 12, 9), nil,
		x509.RevocationListEntry{SerialNumber: x2.cert.SerialNumber, RevocationTime: day(2026, 10, 2), ReasonCode: ReasonKeyCompromise}))
	run := func(trusted bool) Verdict {
		a := r.NewAssessment()
		if trusted {
			a.KnownTrusted(x2.cert)
		} else {
			a.Known(x2.cert)
		}
		i, err := a.Add(info.Chains, info.GenTime)
		if err != nil {
			t.Fatal(err)
		}
		return a.Verdicts()[i]
	}
	if v := run(true); len(v.Unchecked) != 1 || v.Unchecked[0] != x1.cert && !v.Unchecked[0].Equal(x1.cert) || !hasNote(v, "that certificate has the same key") {
		t.Fatalf("X2 дан проверяющим, его центр не известен, CRL с именем центра называет X2: %+v", v)
	}
	if v := run(false); len(v.Unchecked) != 0 {
		t.Fatalf("X2 из токена без известного центра: %+v", v)
	}
	// С сертификатом нового ключа — запись в счёт: ключ под подозрением.
	a := r.NewAssessment()
	a.KnownTrusted(caNew.cert, x2.cert)
	i, _ := a.Add(info.Chains, info.GenTime)
	if v := a.Verdicts()[i]; !v.NeedPOE {
		t.Fatalf("X2 и сертификат нового ключа даны: компрометация не в счёт: %+v", v)
	}
}

// Текст вне блоков, который пишут люди и openssl, принимается; строка с меткой
// блока или с пятью тире и BEGIN/END — обломок границы.
func TestRevocationsPEMTextAround(t *testing.T) {
	w := newRevWorld(t)
	now := w.gen.Add(48 * time.Hour)
	fresh, _ := os.ReadFile(w.crl("fresh.crl", now.Add(time.Hour)))
	good := string(pem.EncodeToMemory(&pem.Block{Type: "X509 CRL", Bytes: fresh}))
	for name, c := range map[string]struct{ pre, want string }{
		"разделитель с CRL":   {"---------- CRL 1 of 2 ----------\n", ""},
		"два тире":            {"-- CRL of NCA RK, fetched 10.11 --\nCRL list --\n", ""},
		"имя центра с тире":   {"        Issuer: CN = -- Test CRL CA --\n", ""},
		"приглашение":         {"-------- Calendar invite --------\n", ""},
		"три тире":            {"--- CRL of Issuing CA A, fetched today ---\n", ""},
		"два тире и END":      {"-- END of notes --\n", ""},
		"граница без тире":    {"BEGIN X509 CRL\n", "broken PEM boundary"},
		"метка в тексте":      {"see the X509  CRL below\n", "broken PEM boundary"},
		"конец пересланного":  {"---------- End of forwarded message ----------\n", "broken PEM boundary"},
		"граница с пробелами": {"----- BEGIN -----\n", "broken PEM boundary"},
	} {
		p := filepath.Join(w.dir, "text.pem")
		os.WriteFile(p, []byte(c.pre+good), 0o600)
		err := NewRevocations(now).AddCRL(p)
		if c.want == "" && err != nil || c.want != "" && (err == nil || !strings.Contains(err.Error(), c.want)) {
			t.Errorf("%s: %v", name, err)
		}
	}
}

// Удержание в CRL нового ключа центра снимает только более новый CRL того же
// ключа: ни более старый CRL нового ключа, ни CRL прежнего ключа его не
// снимают.
func TestRevocationsRedesignHoldInNewKeyCRL(t *testing.T) {
	dir := t.TempDir()
	root := issue(t, caTmpl(1, "rd6 root"), newKey(t), nil)
	caOld := issue(t, caTmpl(10, "rd6 TSA CA"), newKey(t), root)
	caNew := issue(t, caTmpl(11, "rd6 TSA CA"), newKey(t), root)
	gen := day(2026, 10, 15)
	_, info := tsaUnder(t, caOld, day(2030, 1, 1), gen, []*x509.Certificate{root.cert}, caOld.cert)
	leaf := info.Chains[0][0]
	hold := x509.RevocationListEntry{SerialNumber: leaf.SerialNumber, RevocationTime: day(2026, 10, 5), ReasonCode: ReasonCertificateHold}
	run := func(more func(r *Revocations)) Verdict {
		r := NewRevocations(day(2026, 11, 10))
		r.AddCRL(caOld.crlOf(t, dir, "old.crl", day(2026, 9, 2), day(2026, 12, 1), nil))
		r.AddCRL(caNew.crlOf(t, dir, "hold.crl", day(2026, 10, 6), day(2026, 11, 6), nil, hold))
		more(r)
		a := r.NewAssessment()
		a.KnownTrusted(caNew.cert)
		i, err := a.Add(info.Chains, info.GenTime)
		if err != nil {
			t.Fatal(err)
		}
		return a.Verdicts()[i]
	}
	if v := run(func(r *Revocations) {}); !v.NeedPOE {
		t.Fatalf("удержание в CRL нового ключа, снятия нет: %+v", v)
	}
	if v := run(func(r *Revocations) {
		r.AddCRL(caNew.crlOf(t, dir, "earlier.crl", day(2026, 10, 1), day(2026, 11, 1), nil))
	}); !v.NeedPOE {
		t.Fatalf("удержание снято более старым CRL нового ключа: %+v", v)
	}
	if v := run(func(r *Revocations) {
		r.AddCRL(caOld.crlOf(t, dir, "old-later.crl", day(2026, 11, 9), day(2026, 12, 9), nil))
	}); !v.NeedPOE {
		t.Fatalf("удержание из CRL нового ключа снято CRL прежнего: %+v", v)
	}
	if v := run(func(r *Revocations) {
		r.AddCRL(caNew.crlOf(t, dir, "released.crl", day(2026, 11, 9), day(2026, 12, 9), nil))
	}); v.NeedPOE {
		t.Fatalf("удержание не снято более новым CRL нового ключа: %+v", v)
	}
}

// rawName — имя из одного CN в кодировке PrintableString или UTF8String.
func rawName(t *testing.T, cn string, utf8 bool) []byte {
	t.Helper()
	tag := asn1.TagPrintableString
	if utf8 {
		tag = asn1.TagUTF8String
	}
	der, err := asn1.Marshal(pkix.RDNSequence{{{Type: asn1.ObjectIdentifier{2, 5, 4, 3}, Value: asn1.RawValue{Tag: tag, Bytes: []byte(cn)}}}})
	if err != nil {
		t.Fatal(err)
	}
	return der
}

// Имя центра в сертификате нового ключа закодировано иначе, чем в
// сертификате центра выше по пути (UTF8String против PrintableString): имена
// сравниваются и по строке, путь строится.
func TestRevocationsRedesignNameEncodings(t *testing.T) {
	dir := t.TempDir()
	root := issue(t, caTmpl(1, "rd5 root"), newKey(t), nil)
	kP := newKey(t)
	pPrint := caTmpl(5, "")
	pPrint.RawSubject = rawName(t, "rd5 policy", false)
	policy := issue(t, pPrint, kP, root)
	pUTF8 := caTmpl(6, "")
	pUTF8.RawSubject = rawName(t, "rd5 policy", true)
	policyUTF8 := issue(t, pUTF8, kP, root) // им выпущен сертификат нового ключа; проверяющему не дан
	caOld := issue(t, caTmpl(10, "rd5 TSA CA"), newKey(t), policy)
	caNew := issue(t, caTmpl(11, "rd5 TSA CA"), newKey(t), policyUTF8)
	if string(caNew.cert.RawIssuer) == string(policy.cert.RawSubject) || caNew.cert.Issuer.String() != policy.cert.Subject.String() {
		t.Fatal("кодировки имён совпали")
	}
	gen := day(2026, 10, 1)
	_, info := tsaUnder(t, caOld, day(2030, 1, 1), gen, []*x509.Certificate{root.cert}, policy.cert, caOld.cert)
	leaf := info.Chains[0][0]
	r := NewRevocations(day(2026, 11, 10))
	r.AddCRL(caOld.crlOf(t, dir, "old.crl", day(2026, 11, 1), day(2026, 12, 1), nil))
	r.AddCRL(caNew.crlOf(t, dir, "new.crl", day(2026, 11, 9), day(2026, 12, 9), nil,
		x509.RevocationListEntry{SerialNumber: leaf.SerialNumber, RevocationTime: day(2026, 10, 20), ReasonCode: ReasonKeyCompromise}))
	a := r.NewAssessment()
	a.KnownTrusted(caNew.cert)
	i, err := a.Add(info.Chains, info.GenTime)
	if err != nil {
		t.Fatal(err)
	}
	if v := a.Verdicts()[i]; !v.NeedPOE {
		t.Fatalf("имя центра выше по пути в другой кодировке: компрометация в CRL нового ключа не в счёт: %+v", v)
	}
}
