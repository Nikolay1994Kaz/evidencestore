package tsa

// Находки захода 1 второго цикла (FINDINGS, P-157…): каждая — тест, красный
// на коде до исправления.

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func day(y int, m time.Month, d int) time.Time { return time.Date(y, m, d, 0, 0, 0, 0, time.UTC) }

// P-157. Удержание, сделанное постоянным (AD CS переписывает причину и
// дату): более новый CRL называет сертификат с другой причиной — это не
// снятие удержания, и его дата в силе. Снимает удержание только CRL, который
// сертификат не называет вовсе.
func TestRevocationsHoldMadePermanent(t *testing.T) {
	w := newRevWorld(t)
	now := w.gen.Add(48 * time.Hour)
	serial := w.a.Cert().SerialNumber
	holdAt, later := w.gen.Add(-2*time.Hour), w.gen.Add(10*time.Hour)
	held := w.crlAt("held.crl", w.gen.Add(-time.Hour), now.Add(time.Hour), nil,
		x509.RevocationListEntry{SerialNumber: serial, RevocationTime: holdAt, ReasonCode: ReasonCertificateHold})
	for _, reason := range []int{ReasonKeyCompromise, ReasonCessationOfOperation, ReasonSuperseded} {
		perm := w.crlAt("perm.crl", w.gen.Add(24*time.Hour), now.Add(time.Hour), nil,
			x509.RevocationListEntry{SerialNumber: serial, RevocationTime: later, ReasonCode: reason})
		r := NewRevocations(now)
		r.AddCRL(held)
		r.AddCRL(perm)
		if v, err := w.check(r); err != nil || !v.NeedPOE || !v.Cutoff.Equal(holdAt) {
			t.Errorf("удержание, затем %s: %+v %v", ReasonName(reason), v, err)
		}
	}
	// Снятие: новый CRL сертификата не называет.
	released := w.crlAt("released.crl", w.gen.Add(24*time.Hour), now.Add(time.Hour), nil)
	r := NewRevocations(now)
	r.AddCRL(held)
	r.AddCRL(released)
	if v, err := w.check(r); err != nil || v.NeedPOE {
		t.Errorf("снят с удержания: %+v %v", v, err)
	}
}

// P-165. Расширение дважды — в записи (два reasonCode: компрометация и вывод
// из работы) и в самом CRL: отказ при чтении, а не последнее из двух.
func TestRevocationsDuplicateExtension(t *testing.T) {
	w := newRevWorld(t)
	now := w.gen.Add(48 * time.Hour)
	for name, rl := range map[string]*x509.RevocationList{
		"запись": {Number: big.NewInt(1), ThisUpdate: w.gen.Add(24 * time.Hour), NextUpdate: now.Add(time.Hour),
			RevokedCertificates: []pkix.RevokedCertificate{{SerialNumber: w.a.Cert().SerialNumber, RevocationTime: w.gen.Add(10 * time.Hour),
				Extensions: []pkix.Extension{ext(t, oidReasonCode, asn1.Enumerated(ReasonKeyCompromise), ""), ext(t, oidReasonCode, asn1.Enumerated(ReasonSuperseded), "")}}}},
		"CRL": {Number: big.NewInt(1), ThisUpdate: w.gen.Add(24 * time.Hour), NextUpdate: now.Add(time.Hour),
			ExtraExtensions: []pkix.Extension{ext(t, oidExpiredCerts, w.gen, "generalized"), ext(t, oidExpiredCerts, w.gen, "generalized")}},
	} {
		der, err := x509.CreateRevocationList(rand.Reader, rl, w.a.root, w.a.rootKey)
		if err != nil {
			t.Fatal(err)
		}
		p := filepath.Join(w.dir, "dup.crl")
		os.WriteFile(p, der, 0o600)
		if err := NewRevocations(now).AddCRL(p); err == nil || !strings.Contains(err.Error(), "given twice") {
			t.Errorf("%s: расширение дважды: %v", name, err)
		}
	}
}

// P-158, P-167. Обломки границы блока вне блоков: блок с испорченной строкой начала
// для разбора — текст, и CRL в нём пропал бы молча. Отказ; пояснение UTF-8 —
// годно, в другой кодировке или с управляющими символами — отказ со словами,
// что не так.
func TestRevocationsDamagedPEMBoundary(t *testing.T) {
	w := newRevWorld(t)
	now := w.gen.Add(48 * time.Hour)
	comp, _ := os.ReadFile(w.crlAt("comp.crl", w.gen.Add(time.Hour), now.Add(time.Hour), nil,
		x509.RevocationListEntry{SerialNumber: w.a.Cert().SerialNumber, RevocationTime: w.gen.Add(10 * time.Hour), ReasonCode: ReasonKeyCompromise}))
	fresh, _ := os.ReadFile(w.crlAt("fresh.crl", w.gen.Add(24*time.Hour), now.Add(time.Hour), nil))
	bad := string(pem.EncodeToMemory(&pem.Block{Type: "X509 CRL", Bytes: comp}))
	good := string(pem.EncodeToMemory(&pem.Block{Type: "X509 CRL", Bytes: fresh}))
	lines := strings.SplitAfter(bad, "\n")
	for name, data := range map[string]string{
		"тире потеряно":         bad[1:] + good,
		"буква испорчена":       strings.Replace(bad, "BEGIN", "BEGlN", 1) + good,
		"нет строки начала":     strings.Join(lines[1:], "") + good,
		"после целого блока":    good + bad[1:],
		"строка конца в тексте": good + "-----END X509 CRL-----\n",
	} {
		p := filepath.Join(w.dir, "damaged.pem")
		os.WriteFile(p, []byte(data), 0o600)
		if err := NewRevocations(now).AddCRL(p); err == nil || !strings.Contains(err.Error(), "broken PEM boundary") {
			t.Errorf("%s: %v", name, err)
		}
	}
	for name, c := range map[string]struct{ pre, want string }{
		"UTF-8":      {"Список отозванных сертификатов\n", ""},
		"cp1251":     {"\xd1\xef\xe8\xf1\xee\xea\n", "not UTF-8"},
		"управление": {"\x1b[1mCRL\x1b[0m\n", "control characters"},
	} {
		p := filepath.Join(w.dir, "text.pem")
		os.WriteFile(p, []byte(c.pre+good), 0o600)
		err := NewRevocations(now).AddCRL(p)
		if c.want == "" && err != nil || c.want != "" && (err == nil || !strings.Contains(err.Error(), c.want)) {
			t.Errorf("%s: %v", name, err)
		}
	}
}

// P-166. CRL только атрибутных сертификатов о сертификатах служб ничего не
// говорит, а номера в нём — других сертификатов: отказ при чтении.
func TestRevocationsAttributeOnlyCRL(t *testing.T) {
	w := newRevWorld(t)
	now := w.gen.Add(48 * time.Hour)
	idp, _ := asn1.Marshal(struct {
		OnlyAttr bool `asn1:"optional,tag:5"`
	}{true})
	p := w.crlAt("ac.crl", w.gen.Add(time.Hour), now.Add(time.Hour), []pkix.Extension{{Id: oidIssuingDP, Critical: true, Value: idp}},
		x509.RevocationListEntry{SerialNumber: w.a.Cert().SerialNumber, RevocationTime: w.gen.Add(-time.Hour), ReasonCode: ReasonKeyCompromise})
	if err := NewRevocations(now).AddCRL(p); err == nil || !strings.Contains(err.Error(), "attribute certificates") {
		t.Fatalf("CRL атрибутных сертификатов принят: %v", err)
	}
}

// renewedStamp — метка службы leaf, проверенная доверием trust.
func renewedStamp(t *testing.T, leaf, root *pki, gen time.Time, trust Trust) Info {
	t.Helper()
	a := &Authority{key: leaf.key, cert: leaf.cert, root: root.cert, policy: demoPolicy, Now: func() time.Time { return gen }}
	imprint := sha256.Sum256([]byte("head"))
	token, err := a.Sign(imprint[:], nil)
	if err != nil {
		t.Fatal(err)
	}
	info, err := Verify(token, imprint, trust)
	if err != nil {
		t.Fatal(err)
	}
	return info
}

// P-161. Ключ перевыпущен на тот же ключ: по компрометации отозван текущий
// сертификат, а цепочка метки идёт через прежний, истёкший и потому из CRL
// убранный (RFC 5280, 3.3). Ключ под подозрением, когда текущий сертификат
// известен оценке (Known: -tsa-trust или сертификаты токенов); без него —
// нет: из CRL ключа не узнать, и это записано в limitations.md.
func TestRevocationsRenewedKey(t *testing.T) {
	dir := t.TempDir()
	root := issue(t, caTmpl(1, "renewal root"), newKey(t), nil)
	// Центр продлён на тот же ключ: caOld истёк, caCur — с 2026-06-01.
	kCA := newKey(t)
	oldT := caTmpl(10, "TSA CA")
	oldT.NotBefore, oldT.NotAfter = day(2020, 1, 1), day(2026, 6, 30)
	caOld := issue(t, oldT, kCA, root)
	curT := caTmpl(11, "TSA CA")
	curT.NotBefore, curT.NotAfter = day(2026, 6, 1), day(2035, 1, 1)
	caCur := issue(t, curT, kCA, root)
	leaf := issue(t, &x509.Certificate{SerialNumber: big.NewInt(99), Subject: pkix.Name{CommonName: "TSA under the old CA certificate"},
		NotBefore: day(2025, 1, 1), NotAfter: day(2026, 6, 29), KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageTimeStamping}}, newKey(t), caOld)
	pool := x509.NewCertPool()
	pool.AddCert(root.cert)
	info := renewedStamp(t, leaf, root, day(2026, 3, 1), Trust{Roots: pool, Intermediates: []*x509.Certificate{caOld.cert}})
	r := NewRevocations(day(2027, 3, 10))
	r.AddCRL(root.crlOf(t, dir, "root.crl", day(2027, 3, 1), day(2027, 4, 1), nil,
		x509.RevocationListEntry{SerialNumber: caCur.cert.SerialNumber, RevocationTime: day(2027, 2, 20), ReasonCode: ReasonKeyCompromise}))
	check := func(known ...*x509.Certificate) Verdict {
		a := r.NewAssessment()
		a.Known(known...)
		i, err := a.Add(info.Chains, info.GenTime)
		if err != nil {
			t.Fatal(err)
		}
		return a.Verdicts()[i]
	}
	if v := check(); v.NeedPOE {
		t.Fatalf("без текущего сертификата центра: %+v", v)
	}
	if v := check(caCur.cert); !v.NeedPOE || !v.Cutoff.Equal(day(2027, 2, 20)) || !strings.Contains(v.Entry.From, "with the same key") {
		t.Fatalf("текущий сертификат центра известен: %+v", v)
	}

	// Служба перевыпущена на тот же ключ: X1 истёк, X1r отозван.
	ca := issue(t, caTmpl(20, "TSA CA 2"), newKey(t), root)
	kTSA := newKey(t)
	x1T := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "TSA"}, NotBefore: day(2024, 1, 1), NotAfter: day(2026, 12, 31),
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageTimeStamping}}
	x1 := issue(t, x1T, kTSA, ca)
	x1rT := *x1T
	x1rT.SerialNumber, x1rT.NotBefore, x1rT.NotAfter = big.NewInt(2), day(2026, 6, 1), day(2028, 12, 31)
	x1r := issue(t, &x1rT, kTSA, ca)
	info = renewedStamp(t, x1, root, day(2026, 3, 1), Trust{Roots: pool, Intermediates: []*x509.Certificate{ca.cert}})
	r = NewRevocations(day(2027, 3, 10))
	r.AddCRL(ca.crlOf(t, dir, "ca.crl", day(2027, 3, 1), day(2027, 4, 1), nil,
		x509.RevocationListEntry{SerialNumber: x1r.cert.SerialNumber, RevocationTime: day(2027, 2, 20), ReasonCode: ReasonKeyCompromise}))
	if v := check(); v.NeedPOE {
		t.Fatalf("без X1r: %+v", v)
	}
	if v := check(x1r.cert); !v.NeedPOE {
		t.Fatalf("X1r известен: %+v", v)
	}
	// Подделанный «сертификат» того же номера, не выпущенный центром, о ключе
	// ничего не говорит.
	forged := issue(t, &x1rT, kTSA, issue(t, caTmpl(20, "TSA CA 2"), newKey(t), root))
	if v := check(forged.cert); v.NeedPOE {
		t.Fatalf("сертификат с именем центра, но не его подписью: %+v", v)
	}
}

// P-162. Центр сменил ключ (то же имя) и отозвал сертификат службы, выданный
// прежним ключом, в CRL нового: запись в счёт, когда сертификат нового ключа
// ведёт к тому же корню (RFC 5280, 6.3.3 f). Без него — заметка, что CRL
// называет сертификат, и чем помочь. CRL того же имени под корнем-тёзкой — не
// в счёт. Вывод из работы в CRL нового ключа до метки — метка не в силе
// (Verdict.Retired: Add о таких CRL не знает).
func TestRevocationsRekeyedCA(t *testing.T) {
	dir := t.TempDir()
	root := issue(t, caTmpl(1, "rekey root"), newKey(t), nil)
	caA := issue(t, caTmpl(10, "TSA CA"), newKey(t), root)
	caB := issue(t, caTmpl(11, "TSA CA"), newKey(t), root)
	gen := day(2026, 10, 1)
	leaf, info := tsaUnder(t, caA, day(2030, 1, 1), gen, []*x509.Certificate{root.cert}, caA.cert)
	now := day(2026, 11, 2)
	run := func(reason int, at time.Time, known ...*x509.Certificate) Verdict {
		r := NewRevocations(now)
		r.AddCRL(caA.crlOf(t, dir, "old-key.crl", day(2026, 9, 15), day(2026, 12, 15), nil))
		r.AddCRL(caB.crlOf(t, dir, "new-key.crl", day(2026, 11, 1), day(2026, 12, 1), nil,
			x509.RevocationListEntry{SerialNumber: leaf.cert.SerialNumber, RevocationTime: at, ReasonCode: reason}))
		a := r.NewAssessment()
		a.Known(known...)
		i, err := a.Add(info.Chains, info.GenTime)
		if err != nil {
			t.Fatal(err)
		}
		return a.Verdicts()[i]
	}
	if v := run(ReasonKeyCompromise, gen.Add(time.Hour)); v.NeedPOE || !hasNote(v, "pass that certificate in -tsa-trust") {
		t.Fatalf("сертификата нового ключа нет: %+v", v)
	}
	if v := run(ReasonKeyCompromise, gen.Add(time.Hour), caB.cert); !v.NeedPOE || !strings.Contains(v.Entry.From, "new-key.crl") || !hasNote(v, "under the same root") {
		t.Fatalf("сертификат нового ключа известен: %+v", v)
	}
	if v := run(ReasonSuperseded, gen.Add(-time.Hour), caB.cert); v.Retired == nil || !strings.Contains(v.Retired.Error(), "superseded") {
		t.Fatalf("выведен из работы в CRL нового ключа до метки: %+v", v)
	}
	if v := run(ReasonSuperseded, gen.Add(time.Hour), caB.cert); v.Retired != nil || v.NeedPOE {
		t.Fatalf("выведен из работы после метки: %+v", v)
	}
	// Тёзка: центр «TSA CA» под другим корнем.
	other := issue(t, caTmpl(1, "other root"), newKey(t), nil)
	twin := issue(t, caTmpl(11, "TSA CA"), caB.key, other)
	if v := run(ReasonKeyCompromise, gen.Add(time.Hour), twin.cert); v.NeedPOE {
		t.Fatalf("тот же ключ под чужим корнем: %+v", v)
	}
}

// P-163. Перекрёстный сертификат закреплённого корня отозван другим корнем без
// причины (так прекращают перекрёстную сертификацию): ключ корня не под
// подозрением, цепочка через сам корень в силе.
func TestRevocationsCrossCertNoReason(t *testing.T) {
	dir := t.TempDir()
	kMain := newKey(t)
	rootMain := issue(t, caTmpl(1, "Main root"), kMain, nil)
	rootX := issue(t, caTmpl(1, "Root X"), newKey(t), nil)
	cross := issue(t, caTmpl(5, "Main root"), kMain, rootX)
	gen := day(2026, 10, 1)
	_, info := tsaUnder(t, rootMain, day(2030, 1, 1), gen, []*x509.Certificate{rootMain.cert, rootX.cert}, cross.cert)
	if len(info.Chains) != 2 {
		t.Fatalf("цепочек %d", len(info.Chains))
	}
	for reason, poe := range map[int]bool{ReasonAbsent: false, ReasonKeyCompromise: true} {
		code := reason
		if reason == ReasonAbsent {
			code = 0
		}
		r := NewRevocations(day(2026, 11, 2))
		r.AddCRL(rootX.crlOf(t, dir, "rootX.crl", day(2026, 11, 1), day(2026, 12, 1), nil,
			x509.RevocationListEntry{SerialNumber: cross.cert.SerialNumber, RevocationTime: day(2026, 9, 1), ReasonCode: code}))
		r.AddCRL(rootMain.crlOf(t, dir, "rootMain.crl", day(2026, 11, 1), day(2026, 12, 1), nil))
		if v, err := r.Check(info.Chains, info.GenTime); err != nil || v.NeedPOE != poe {
			t.Errorf("%s: %+v %v", ReasonName(reason), v, err)
		}
	}
}

// P-164. Оценка при многих CRL: Named — по разным сертификатам, раз; CRL —
// по имени центра. Месяц меток при годе ежедневных CRL двух центров —
// доли секунды (было: десятки секунд).
func TestRevocationsManyCRLs(t *testing.T) {
	dir := t.TempDir()
	root := issue(t, caTmpl(1, "cost root"), newKey(t), nil)
	ca := issue(t, caTmpl(10, "TSA CA"), newKey(t), root)
	gen := day(2026, 10, 1)
	_, info := tsaUnder(t, ca, day(2030, 1, 1), gen, []*x509.Certificate{root.cert}, ca.cert)
	r := NewRevocations(day(2026, 11, 2))
	for i := range 365 {
		this := day(2025, 11, 1).Add(time.Duration(i) * 24 * time.Hour)
		r.AddCRL(ca.crlOf(t, dir, "ca"+this.Format("060102")+".crl", this, this.Add(48*time.Hour), nil))
		r.AddCRL(root.crlOf(t, dir, "root"+this.Format("060102")+".crl", this, this.Add(48*time.Hour), nil))
	}
	start := time.Now()
	a := r.NewAssessment()
	for i := range 4000 {
		a.Add(info.Chains, info.GenTime.Add(time.Duration(i)*time.Minute))
	}
	vs := a.Verdicts()
	named := a.Named()
	if took := time.Since(start); took > 10*time.Second || len(vs) != 4000 || len(named) != 730 {
		t.Fatalf("4000 меток, 730 CRL: %v, вердиктов %d, названо %d", took, len(vs), len(named))
	}
}

// P-163. Правило «без причины — о ключе» — для сертификата службы, даже если
// он помечен как центр (IsCA): решает его место в цепочке, а не флаг.
func TestRevocationsNoReasonSignerMarkedCA(t *testing.T) {
	dir := t.TempDir()
	root := issue(t, caTmpl(1, "flag root"), newKey(t), nil)
	ca := issue(t, caTmpl(10, "TSA CA"), newKey(t), root)
	leafT := &x509.Certificate{SerialNumber: big.NewInt(5), Subject: pkix.Name{CommonName: "TSA marked CA"},
		NotBefore: day(2025, 1, 1), NotAfter: day(2030, 1, 1), BasicConstraintsValid: true, IsCA: true,
		KeyUsage: x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageTimeStamping}}
	leaf := issue(t, leafT, newKey(t), ca)
	pool := x509.NewCertPool()
	pool.AddCert(root.cert)
	info := renewedStamp(t, leaf, root, day(2026, 10, 1), Trust{Roots: pool, Intermediates: []*x509.Certificate{ca.cert}})
	r := NewRevocations(day(2026, 11, 2))
	r.AddCRL(ca.crlOf(t, dir, "ca.crl", day(2026, 11, 1), day(2026, 12, 1), nil,
		x509.RevocationListEntry{SerialNumber: leaf.cert.SerialNumber, RevocationTime: day(2026, 10, 20)}))
	if v, err := r.Check(info.Chains, info.GenTime); err != nil || !v.NeedPOE {
		t.Fatalf("служба с флагом центра, отозвана без причины: %+v %v", v, err)
	}
}
