package tsa

// Ревью цикла 2, заход 3 (тестировщик t): находки по диффу 2c7da6d..dcef3db.
// Каждый тест на dcef3db падает и описывает дефект; на исправленном коде —
// зелёный.

import (
	"crypto/x509"
	"strings"
	"testing"
)

// T1. Сертификат службы вне цепочек с флагом центра (CA:TRUE, EKU
// timeStamping) — перевыпуск ключа службы, данный проверяющим, — отозван без
// причины. Правило «без причины — ключ под подозрением» — для сертификата
// службы (RFC 3161, 4); у сертификата цепочки на месте службы оно действует
// и с флагом центра (TestRevocationsNoReasonSignerMarkedCA), а вне цепочек
// флаг центра делает его «центром» (chainOnly): ключ не под подозрением.
func TestC2cTKnownTSAWithCAFlagNoReason(t *testing.T) {
	dir := t.TempDir()
	root := issue(t, caTmpl(1, "t root"), newKey(t), nil)
	ca := issue(t, caTmpl(10, "TSA CA"), newKey(t), root)
	kTSA := newKey(t)
	x1 := issue(t, r1leafTmpl(1, "TSA", day(2024, 1, 1), day(2029, 1, 1)), kTSA, ca)
	x2t := r1leafTmpl(2, "TSA", day(2026, 6, 1), day(2029, 1, 1))
	x2t.BasicConstraintsValid, x2t.IsCA = true, true
	x2 := issue(t, x2t, kTSA, ca)
	x3 := issue(t, r1leafTmpl(3, "TSA", day(2026, 6, 1), day(2029, 1, 1)), kTSA, ca) // контроль: без флага
	pool := x509.NewCertPool()
	pool.AddCert(root.cert)
	info := renewedStamp(t, x1, root, day(2026, 10, 1), Trust{Roots: pool, Intermediates: []*x509.Certificate{ca.cert}})
	for _, c := range []struct {
		name string
		x    *pki
	}{{"CA:TRUE", x2}, {"контроль CA:FALSE", x3}} {
		r := NewRevocations(day(2026, 11, 10))
		// ReasonCode 0 — записи без причины.
		if err := r.AddCRL(ca.crlOf(t, dir, "ca-"+c.x.cert.SerialNumber.String()+".crl", day(2026, 11, 9), day(2026, 12, 9), nil,
			x509.RevocationListEntry{SerialNumber: c.x.cert.SerialNumber, RevocationTime: day(2026, 9, 1)})); err != nil {
			t.Fatal(err)
		}
		r.AddCRL(root.crlOf(t, dir, "root.crl", day(2026, 11, 9), day(2026, 12, 9), nil))
		a := r.NewAssessment()
		a.KnownTrusted(c.x.cert)
		i, err := a.Add(info.Chains, info.GenTime)
		if err != nil {
			t.Fatal(err)
		}
		if v := a.Verdicts()[i]; !v.NeedPOE {
			t.Errorf("%s: перевыпуск ключа службы (EKU timeStamping) в -tsa-trust отозван без причины до метки — ключ не под подозрением: %+v", c.name, v)
		}
	}
}

// T2. Тёзка без тёзки: CRL нового ключа центра называет сертификат службы
// (компрометация); сертификат нового ключа (то же имя, тот же корень) дан
// проверяющим, но истёк до thisUpdate CRL — центр продлён на тот же ключ, а
// продлённого у проверяющего нет. rekeyedBy не находит пути на дату CRL и
// объявляет CRL «другого центра того же имени» (namesake — любой vouched без
// пути), статус по прежнему CRL не сбрасывается: «none found revoked». До
// диффа — «не проверено». Подписавший ведёт к ТОМУ ЖЕ корню: это не тёзка.
func TestC2cTNamesakeIsNotOneWithExpiredCertOfSameRoot(t *testing.T) {
	dir := t.TempDir()
	root := issue(t, caTmpl(1, "t root"), newKey(t), nil)
	caOld := issue(t, caTmpl(10, "TSA CA"), newKey(t), root)
	expT := caTmpl(11, "TSA CA")
	expT.NotBefore, expT.NotAfter = day(2026, 9, 1), day(2026, 10, 1)
	caNewExp := issue(t, expT, newKey(t), root) // сертификат нового ключа центра, истёк 2026-10-01
	x1 := issue(t, r1leafTmpl(1, "TSA", day(2024, 1, 1), day(2029, 1, 1)), newKey(t), caOld)
	pool := x509.NewCertPool()
	pool.AddCert(root.cert)
	info := renewedStamp(t, x1, root, day(2026, 10, 15), Trust{Roots: pool, Intermediates: []*x509.Certificate{caOld.cert}})
	r := NewRevocations(day(2026, 11, 10))
	r.AddCRL(caOld.crlOf(t, dir, "old.crl", day(2026, 9, 2), day(2026, 12, 1), nil))
	r.AddCRL(caNewExp.crlOf(t, dir, "new.crl", day(2026, 11, 9), day(2026, 12, 9), nil,
		x509.RevocationListEntry{SerialNumber: x1.cert.SerialNumber, RevocationTime: day(2026, 10, 2), ReasonCode: ReasonKeyCompromise}))
	r.AddCRL(root.crlOf(t, dir, "root.crl", day(2026, 11, 9), day(2026, 12, 9), nil))
	a := r.NewAssessment()
	a.KnownTrusted(caNewExp.cert)
	i, err := a.Add(info.Chains, info.GenTime)
	if err != nil {
		t.Fatal(err)
	}
	v := a.Verdicts()[i]
	for _, n := range v.Notes {
		if strings.Contains(n, "another CA") {
			t.Errorf("CRL, подписанный ключом сертификата центра с тем же именем под ТЕМ ЖЕ корнем, назван CRL другого центра: %q", n)
		}
	}
	if !v.NeedPOE && len(v.Unchecked) == 0 {
		t.Errorf("CRL нового ключа центра называет сертификат службы (keyCompromise), подпись к корню не сверить на его дату — а отзыв считается проверенным и не найденным: %+v", v)
	}
}

// T3. Удержание в CRL нового ключа центра (openssl ca с той же базой и новым
// ключом; сертификат нового ключа дан, путь к тому же корню): запись идёт «как
// своя» (Verdicts, by != nil), но правила снятия удержания у неё нет — более
// новый CRL того же ключа, который сертификат не называет, удержание не
// снимает, и честная метка после даты удержания ждёт POE навсегда. В ecad1a9
// (до P-162) такой CRL не считался вовсе.
func TestC2cTRekeyedHoldReleased(t *testing.T) {
	dir := t.TempDir()
	root := issue(t, caTmpl(1, "t root"), newKey(t), nil)
	caOld := issue(t, caTmpl(10, "TSA CA"), newKey(t), root)
	newT := caTmpl(11, "TSA CA")
	newT.NotBefore = day(2026, 9, 1)
	caNew := issue(t, newT, newKey(t), root)
	x1 := issue(t, r1leafTmpl(1, "TSA", day(2024, 1, 1), day(2029, 1, 1)), newKey(t), caOld)
	pool := x509.NewCertPool()
	pool.AddCert(root.cert)
	info := renewedStamp(t, x1, root, day(2026, 10, 15), Trust{Roots: pool, Intermediates: []*x509.Certificate{caOld.cert}})
	r := NewRevocations(day(2026, 11, 10))
	r.AddCRL(caOld.crlOf(t, dir, "old.crl", day(2026, 9, 2), day(2026, 12, 1), nil))
	r.AddCRL(caNew.crlOf(t, dir, "hold.crl", day(2026, 10, 6), day(2026, 11, 6), nil,
		x509.RevocationListEntry{SerialNumber: x1.cert.SerialNumber, RevocationTime: day(2026, 10, 5), ReasonCode: ReasonCertificateHold}))
	r.AddCRL(caNew.crlOf(t, dir, "released.crl", day(2026, 11, 9), day(2026, 12, 9), nil))
	r.AddCRL(root.crlOf(t, dir, "root.crl", day(2026, 11, 9), day(2026, 12, 9), nil))
	a := r.NewAssessment()
	a.KnownTrusted(caNew.cert)
	i, err := a.Add(info.Chains, info.GenTime)
	if err != nil {
		t.Fatal(err)
	}
	if v := a.Verdicts()[i]; v.NeedPOE {
		t.Errorf("удержание из CRL нового ключа центра снято более новым CRL того же ключа — метка всё равно ждёт POE с даты удержания: From=%q", v.Entry.From)
	}
}

// T4. Сертификат вне цепочек (перевыпуск ключа службы, дан проверяющим)
// назван отозванным в CRL с именем центра под ключом, сертификата которого
// нет. Документ (bundles.md): «When esverify finds no such certificate, the
// report says that the CRL lists the certificate and is not used». Для
// сертификата цепочки так и есть; для сертификата вне цепочек заметки нет —
// отчёт: «none found revoked».
func TestC2cTKnownListedByUnknownKeyIsNoted(t *testing.T) {
	dir := t.TempDir()
	root := issue(t, caTmpl(1, "t root"), newKey(t), nil)
	caOld := issue(t, caTmpl(10, "TSA CA"), newKey(t), root)
	newT := caTmpl(11, "TSA CA")
	newT.NotBefore = day(2026, 9, 1)
	caNewHidden := issue(t, newT, newKey(t), root) // проверяющему не дан
	kTSA := newKey(t)
	x1 := issue(t, r1leafTmpl(1, "TSA", day(2024, 1, 1), day(2029, 1, 1)), kTSA, caOld)
	x2 := issue(t, r1leafTmpl(2, "TSA", day(2026, 6, 1), day(2029, 1, 1)), kTSA, caOld)
	pool := x509.NewCertPool()
	pool.AddCert(root.cert)
	info := renewedStamp(t, x1, root, day(2026, 10, 15), Trust{Roots: pool, Intermediates: []*x509.Certificate{caOld.cert}})
	r := NewRevocations(day(2026, 11, 10))
	r.AddCRL(caOld.crlOf(t, dir, "old.crl", day(2026, 9, 2), day(2026, 12, 1), nil))
	r.AddCRL(caNewHidden.crlOf(t, dir, "new.crl", day(2026, 11, 9), day(2026, 12, 9), nil,
		x509.RevocationListEntry{SerialNumber: x2.cert.SerialNumber, RevocationTime: day(2026, 10, 2), ReasonCode: ReasonKeyCompromise}))
	r.AddCRL(root.crlOf(t, dir, "root.crl", day(2026, 11, 9), day(2026, 12, 9), nil))
	a := r.NewAssessment()
	a.KnownTrusted(x2.cert)
	i, err := a.Add(info.Chains, info.GenTime)
	if err != nil {
		t.Fatal(err)
	}
	v := a.Verdicts()[i]
	noted := len(v.Unchecked) > 0
	for _, n := range v.Notes {
		noted = noted || strings.Contains(n, "lists certificate")
	}
	if !noted {
		t.Errorf("CRL под неизвестным ключом центра называет перевыпуск ключа службы (keyCompromise) — отчёт об этом молчит: %q", v.Notes)
	}
}
