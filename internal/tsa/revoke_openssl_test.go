package tsa

// Сверка проверки отзыва с OpenSSL: те же сертификаты и CRL уходят в
// openssl verify -crl_check_all, и исходы сравниваются: «не отозван»,
// «отозван», «не проверить».
//
// Сравнивается слой статуса (RFC 5280, 6.3): подпись CRL, его область и срок,
// право центра на CRL, есть ли сертификат в списке. Правило RFC 3161 о причине
// отзыва (метки до даты в силе, POE) — над этим слоем, и OpenSSL его не знает:
// у него «в списке» значит «отозван», когда бы и почему. Поэтому метка здесь —
// позже всех записей: любая запись в счёт даёт отказ или POE.
//
// Где мы расходимся с OpenSSL намеренно, случай называет оба исхода и причину.
// В CI (переменная CI) отсутствие openssl — отказ, а не пропуск.

import (
	"bytes"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"
)

const (
	stGood    = "не отозван"
	stRevoked = "отозван"
	stUnknown = "не проверить"
)

func opensslBin(t *testing.T) string {
	t.Helper()
	bin, err := exec.LookPath("openssl")
	if err != nil {
		if os.Getenv("CI") != "" {
			t.Fatal("openssl не найден, а в CI сверка с эталоном обязательна")
		}
		t.Skip("openssl не найден: сверка с эталоном пропущена")
	}
	return bin
}

func writePEM(t *testing.T, path, typ string, ders ...[]byte) {
	t.Helper()
	var buf bytes.Buffer
	for _, der := range ders {
		pem.Encode(&buf, &pem.Block{Type: typ, Bytes: der})
	}
	if err := os.WriteFile(path, buf.Bytes(), 0o600); err != nil {
		t.Fatal(err)
	}
}

// opensslStatus — исход openssl verify -crl_check_all на момент at: цепочка
// leaf ← inter ← root, CRL — из файлов crls (DER).
func opensslStatus(t *testing.T, bin string, at time.Time, root *x509.Certificate, inter []*x509.Certificate, leaf *x509.Certificate, crls []string) (string, string) {
	t.Helper()
	dir := t.TempDir()
	rootPath, leafPath := filepath.Join(dir, "root.pem"), filepath.Join(dir, "leaf.pem")
	writePEM(t, rootPath, "CERTIFICATE", root.Raw)
	writePEM(t, leafPath, "CERTIFICATE", leaf.Raw)
	args := []string{"verify", "-crl_check_all", "-attime", strconv.FormatInt(at.Unix(), 10), "-CAfile", rootPath}
	if len(inter) > 0 {
		var ders [][]byte
		for _, c := range inter {
			ders = append(ders, c.Raw)
		}
		p := filepath.Join(dir, "inter.pem")
		writePEM(t, p, "CERTIFICATE", ders...)
		args = append(args, "-untrusted", p)
	}
	if len(crls) > 0 {
		var ders [][]byte
		for _, c := range crls {
			der, err := os.ReadFile(c)
			if err != nil {
				t.Fatal(err)
			}
			ders = append(ders, der)
		}
		p := filepath.Join(dir, "crls.pem")
		writePEM(t, p, "X509 CRL", ders...)
		args = append(args, "-CRLfile", p)
	}
	out, err := exec.Command(bin, append(args, leafPath)...).CombinedOutput()
	switch {
	case err == nil:
		return stGood, string(out)
	case bytes.Contains(out, []byte("certificate revoked")):
		return stRevoked, string(out)
	}
	return stUnknown, string(out)
}

// ourStatus — тот же исход по нашей проверке; gen позже всех записей CRL.
func ourStatus(t *testing.T, r *Revocations, chains [][]*x509.Certificate, gen time.Time) (string, Verdict) {
	t.Helper()
	v, err := r.Check(chains, gen)
	switch {
	case errors.Is(err, ErrRevoked), err == nil && v.NeedPOE:
		return stRevoked, v
	case err != nil:
		t.Fatal(err)
	case len(v.Unchecked) > 0:
		return stUnknown, v
	}
	return stGood, v
}

func TestRevocationsAgainstOpenSSL(t *testing.T) {
	bin := opensslBin(t)
	gen, now := day(2026, 10, 20), day(2026, 11, 2)
	this, next, at := day(2026, 11, 1), day(2026, 12, 1), day(2026, 10, 10)
	idp := func(content []byte) []pkix.Extension {
		return []pkix.Extension{{Id: oidIssuingDP, Critical: true, Value: tlv(0x30, content)}}
	}
	type world struct {
		dir            string
		root, ca, twin *pki // twin — имя центра, другой ключ
		crlCA          *pki // чем подписаны CRL центра: ca, а без cRLSign — тот же ключ под сертификатом с cRLSign (иначе Go CRL не выпустит)
		leaf           *x509.Certificate
	}
	entry := func(c *x509.Certificate, code int) x509.RevocationListEntry {
		return x509.RevocationListEntry{SerialNumber: c.SerialNumber, RevocationTime: at, ReasonCode: code}
	}
	both := func(w world, es ...x509.RevocationListEntry) []string {
		return []string{w.crlCA.crlOf(t, w.dir, "ca.crl", this, next, nil, es...), w.root.crlOf(t, w.dir, "root.crl", this, next, nil)}
	}
	for _, c := range []struct {
		name    string
		noSign  bool // сертификат центра без cRLSign
		crls    func(w world) []string
		ours    string
		openssl string // пусто — как ours
		why     string // почему исходы разные
	}{
		{name: "оба CRL свежие, сертификатов в них нет", ours: stGood,
			crls: func(w world) []string { return both(w) }},
		{name: "служба в CRL: компрометация ключа", ours: stRevoked,
			crls: func(w world) []string { return both(w, entry(w.leaf, ReasonKeyCompromise)) }},
		{name: "служба в CRL: смена сертификата", ours: stRevoked,
			crls: func(w world) []string { return both(w, entry(w.leaf, ReasonSuperseded)) }},
		{name: "служба в CRL без причины", ours: stRevoked,
			crls: func(w world) []string { return both(w, entry(w.leaf, 0)) }},
		{name: "служба на удержании", ours: stRevoked,
			crls: func(w world) []string { return both(w, entry(w.leaf, ReasonCertificateHold)) }},
		{name: "центр в CRL корня: компрометация", ours: stRevoked,
			crls: func(w world) []string {
				return []string{w.ca.crlOf(t, w.dir, "ca.crl", this, next, nil), w.root.crlOf(t, w.dir, "root.crl", this, next, nil, entry(w.ca.cert, ReasonCACompromise))}
			}},
		{name: "CRL центра не дан", ours: stUnknown,
			crls: func(w world) []string { return both(w)[1:] }},
		{name: "CRL корня не дан", ours: stUnknown,
			crls: func(w world) []string { return both(w)[:1] }},
		{name: "ни одного CRL", ours: stUnknown,
			crls: func(w world) []string { return nil }},
		{name: "CRL с именем центра под другим ключом, с записью", ours: stUnknown,
			crls: func(w world) []string {
				return []string{w.twin.crlOf(t, w.dir, "twin.crl", this, next, nil, entry(w.leaf, ReasonKeyCompromise)), w.root.crlOf(t, w.dir, "root.crl", this, next, nil)}
			}},
		{name: "такой CRL новее своего, с записью", ours: stUnknown, openssl: stGood,
			why: "мы строже: это может быть CRL самого центра под новым ключом, и статус снимается; OpenSSL берёт CRL, чей ключ совпал",
			crls: func(w world) []string {
				return append(both(w), w.twin.crlOf(t, w.dir, "twin.crl", this.Add(time.Hour), next, nil, entry(w.leaf, ReasonKeyCompromise)))
			}},
		{name: "такой CRL новее своего, без записи", ours: stGood,
			crls: func(w world) []string {
				return append(both(w), w.twin.crlOf(t, w.dir, "twin.crl", this.Add(time.Hour), next, nil))
			}},
		{name: "CRL только для сертификатов центров", ours: stUnknown,
			crls: func(w world) []string {
				return []string{w.ca.crlOf(t, w.dir, "ca.crl", this, next, idp(tlv(0x82, []byte{0xff}))), w.root.crlOf(t, w.dir, "root.crl", this, next, nil)}
			}},
		{name: "CRL только для конечных сертификатов", ours: stGood,
			crls: func(w world) []string {
				return []string{w.ca.crlOf(t, w.dir, "ca.crl", this, next, idp(tlv(0x81, []byte{0xff}))), w.root.crlOf(t, w.dir, "root.crl", this, next, nil)}
			}},
		{name: "CRL другой точки распространения", ours: stUnknown,
			crls: func(w world) []string {
				dp := idp(tlv(0xA0, tlv(0xA0, tlv(0x86, []byte("http://crl.example/other.crl")))))
				return []string{w.ca.crlOf(t, w.dir, "ca.crl", this, next, dp), w.root.crlOf(t, w.dir, "root.crl", this, next, nil)}
			}},
		{name: "у центра нет права на CRL, список пуст", noSign: true, ours: stUnknown,
			crls: func(w world) []string { return both(w) }},
		{name: "у центра нет права на CRL, служба в списке", noSign: true, ours: stRevoked, openssl: stUnknown,
			why:  "мы строже: запись — свидетельство и в счёт при любом keyUsage центра; OpenSSL такой CRL не берёт вовсе",
			crls: func(w world) []string { return both(w, entry(w.leaf, ReasonKeyCompromise)) }},
		{name: "удержание снято более новым CRL", ours: stGood,
			crls: func(w world) []string {
				return append(both(w), w.ca.crlOf(t, w.dir, "hold.crl", this.Add(-24*time.Hour), next, nil, entry(w.leaf, ReasonCertificateHold)))
			}},
		{name: "CRL центра просрочен", ours: stGood, openssl: stUnknown,
			why: "мы мягче, и отчёт это говорит: просроченный CRL берётся с заметкой, что отзыв после него не виден; OpenSSL его отвергает",
			crls: func(w world) []string {
				return []string{w.ca.crlOf(t, w.dir, "ca.crl", this.Add(-48*time.Hour), now.Add(-time.Hour), nil), w.root.crlOf(t, w.dir, "root.crl", this, next, nil)}
			}},
		{name: "CRL центра из будущего", ours: stUnknown,
			crls: func(w world) []string {
				return []string{w.ca.crlOf(t, w.dir, "ca.crl", now.Add(48*time.Hour), next, nil), w.root.crlOf(t, w.dir, "root.crl", this, next, nil)}
			}},
	} {
		t.Run(c.name, func(t *testing.T) {
			w := world{dir: t.TempDir()}
			w.root = issue(t, caTmpl(1, "ossl root"), newKey(t), nil)
			tmpl := caTmpl(10, "ossl TSA CA")
			if c.noSign {
				tmpl.KeyUsage = x509.KeyUsageCertSign
			}
			w.ca = issue(t, tmpl, newKey(t), w.root)
			w.crlCA = w.ca
			if c.noSign {
				w.crlCA = issue(t, caTmpl(12, "ossl TSA CA"), w.ca.key, w.root)
			}
			w.twin = issue(t, caTmpl(10, "ossl TSA CA"), newKey(t), w.root)
			leaf, info := tsaUnder(t, w.ca, day(2030, 1, 1), gen, []*x509.Certificate{w.root.cert}, w.ca.cert)
			w.leaf = leaf.cert
			crls := c.crls(w)
			r := NewRevocations(now)
			for _, p := range crls {
				if err := r.AddCRL(p); err != nil {
					t.Fatal(err)
				}
			}
			ours, v := ourStatus(t, r, info.Chains, gen)
			theirs, out := opensslStatus(t, bin, now, w.root.cert, []*x509.Certificate{w.ca.cert}, w.leaf, crls)
			want := c.openssl
			if want == "" {
				want = c.ours
			}
			if ours != c.ours || theirs != want {
				t.Fatalf("у нас «%s» (ждали «%s»), у openssl «%s» (ждали «%s»)\nнаш вердикт: %+v\nopenssl: %s", ours, c.ours, theirs, want, v, out)
			}
			if c.name == "CRL центра просрочен" && !hasNote(v, "past its next update") {
				t.Fatalf("просроченный CRL взят без заметки: %+v", v)
			}
			if (ours != theirs) != (c.why != "") {
				t.Fatalf("расхождение с openssl без причины в таблице (или причина без расхождения): «%s» и «%s»", ours, theirs)
			}
		})
	}
}

// Настоящий CRL центра НУЦ РК и CRL его корня (testdata/README): формат
// настоящего центра разбирается, подпись сходится с его сертификатом, и отзыв
// сертификата службы из настоящего токена проверен — как у openssl на тот же
// момент.
func TestRealNCACRL(t *testing.T) {
	token, err := os.ReadFile("testdata/nca_kz_token.der")
	if err != nil {
		t.Fatal(err)
	}
	trust, err := LoadTrust("testdata/root_rsa_2020.cer,testdata/nca_rsa_2022.cer")
	if err != nil {
		t.Fatal(err)
	}
	info, err := Verify(token, Imprint("evidencestore/testdata/v1", []byte("nca-kz golden token")), trust)
	if err != nil {
		t.Fatal(err)
	}
	if len(info.Chains) != 1 || len(info.Chains[0]) != 3 {
		t.Fatalf("цепочек %d", len(info.Chains))
	}
	leaf, ca, root := info.Chains[0][0], info.Chains[0][1], info.Chains[0][2]
	now := time.Date(2026, 11, 10, 12, 0, 0, 0, time.UTC) // между выпуском и следующим выпуском обоих CRL
	crls := []string{"testdata/nca_rsa_2022.crl", "testdata/root_rsa_2020.crl"}
	r := NewRevocations(now)
	for _, p := range crls {
		if err := r.AddCRL(p); err != nil {
			t.Fatal(err)
		}
	}
	if n := len(r.crls[0].bySN); n != 1843 || r.crls[0].scope != nil || r.crls[0].deltas || r.crls[0].rl.CheckSignatureFrom(ca) != nil {
		t.Fatalf("CRL центра: записей %d, область %v, дельты %v, подпись %v", n, r.crls[0].scope, r.crls[0].deltas, r.crls[0].rl.CheckSignatureFrom(ca))
	}
	reasons := map[int]int{}
	for _, es := range r.crls[0].bySN {
		for _, e := range es {
			reasons[e.Reason]++
		}
	}
	t.Logf("причины в CRL центра: %v", reasons)
	if reasons[ReasonAbsent] != 0 {
		// Запись без причины для RFC 3161 — как компрометация: если центр
		// так пишет, это надо знать до первой отозванной службы.
		t.Logf("в CRL центра %d записей без причины", reasons[ReasonAbsent])
	}
	v, err := r.Check(info.Chains, info.GenTime)
	if err != nil || v.NeedPOE || len(v.Unchecked) != 0 || len(v.CRLs) != 2 || len(v.Notes) != 0 {
		t.Fatalf("служба НУЦ по настоящим CRL: %+v %v", v, err)
	}
	// Без CRL корня сертификат центра не проверен, а служба — проверена.
	r1 := NewRevocations(now)
	r1.AddCRL(crls[0])
	if v, err := r1.Check(info.Chains, info.GenTime); err != nil || len(v.Unchecked) != 1 || !bytes.Equal(v.Unchecked[0].Raw, ca.Raw) {
		t.Fatalf("без CRL корня: %+v %v", v, err)
	}
	// На другой день этот CRL просрочен: берётся, и отчёт это говорит.
	late := NewRevocations(now.Add(48 * time.Hour))
	late.AddCRL(crls[0])
	late.AddCRL(crls[1])
	if v, err := late.Check(info.Chains, info.GenTime); err != nil || len(v.Unchecked) != 0 || !hasNote(v, "past its next update") {
		t.Fatalf("через двое суток: %+v %v", v, err)
	}
	bin := opensslBin(t)
	if st, out := opensslStatus(t, bin, now, root, []*x509.Certificate{ca}, leaf, crls); st != stGood {
		t.Fatalf("openssl на настоящих CRL: «%s»\n%s", st, out)
	}
	if st, out := opensslStatus(t, bin, now, root, []*x509.Certificate{ca}, leaf, crls[:1]); st != stUnknown || !strings.Contains(out, "unable to get certificate CRL") {
		t.Fatalf("openssl без CRL корня: «%s»\n%s", st, out)
	}
}
