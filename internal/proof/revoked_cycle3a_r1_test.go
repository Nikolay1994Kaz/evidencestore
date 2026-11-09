package proof

// Ревью цикла 3, заход 1 (r1): гипотезы сквозь пакет.

import (
	"crypto/x509"
	"strings"
	"testing"
	"time"

	"github.com/Nikolay1994Kaz/evidencestore/internal/tsa"
)

// A1 сквозь пакет. Основная служба отозвана по компрометации после меток
// пакета; метка второй службы над головой T2 — раньше отсечки, это POE.
// Вторая служба перевыпущена на тот же ключ под новым ключом своего центра
// (AD CS: свой CRL на каждый ключ центра); прежний её сертификат Y0 выведен
// из работы (superseded) в CRL прежнего ключа центра. Проверяющий следует
// bundles.md: даёт Y0 («Give every certificate of a key you know of in
// -tsa-trust») и все CRL центра, старые тоже, — но не сертификат прежнего
// ключа центра. Запись superseded о сертификате вне цепочек ключа не
// касается (P-191), а пакет из-за неё NOT VERIFIED: статус Y1 «не проверен»,
// и метка второй службы не POE.
func TestC3R1SupersededOldCertKillsPOE(t *testing.T) {
	w, b := standard(t, nil)
	b.Upper.Inclusion = ptr(w.inclusion(5, 0))
	cut := w.now.Add(2 * time.Hour)
	now := w.now.Add(48 * time.Hour)
	root2 := c2issue(t, 1, "c3r1 second root", true, c2date(2020, 1, 1), c2date(2040, 1, 1), c2key(t), nil)
	ca1 := c2issue(t, 10, "c3r1 second CA", true, c2date(2020, 1, 1), c2date(2040, 1, 1), c2key(t), root2)
	ca2 := c2issue(t, 11, "c3r1 second CA", true, c2date(2025, 1, 1), c2date(2040, 1, 1), c2key(t), root2)
	k2 := c2key(t)
	y0 := c2issue(t, 0x4e01, "second TSA", false, c2date(2023, 1, 1), c2date(2027, 1, 1), k2, ca1)
	y1 := c2issue(t, 0x4e02, "second TSA", false, c2date(2026, 1, 1), c2date(2029, 1, 1), k2, ca2)
	second := tsa.AuthorityWith(k2, y1.cert, root2.cert)
	second.Carry(ca2.cert)
	b.Archive = []ArchiveStamp{archiveOver(t, w, second, 5, cut.Add(-time.Hour))}
	run := func(inter ...*x509.Certificate) Report {
		tr := w.trust()
		tr.TSA.Roots.AddCert(root2.cert)
		tr.TSA.RootCerts = []*x509.Certificate{w.tsa.Root(), root2.cert}
		tr.TSA.Intermediates = inter
		tr.TSARevocations = compromised(t, w.tsa, cut, now)
		c2crl(t, tr.TSARevocations, root2, now.Add(-time.Hour))
		c2crl(t, tr.TSARevocations, ca1, now.Add(-time.Hour), x509.RevocationListEntry{SerialNumber: y0.cert.SerialNumber, RevocationTime: c2date(2026, 1, 1), ReasonCode: tsa.ReasonSuperseded})
		c2crl(t, tr.TSARevocations, ca2, now.Add(-time.Hour))
		return Verify(b, tr)
	}
	if r := run(); !r.Valid() {
		t.Fatalf("контроль: без Y0 метка второй службы — POE:\n%s", r.Text())
	}
	if r := run(y0.cert, ca1.cert); !r.Valid() {
		t.Fatalf("контроль: Y0 с сертификатом прежнего ключа центра:\n%s", r.Text())
	}
	r := run(y0.cert)
	t.Logf("Y0 без сертификата прежнего ключа центра: valid=%v\n%s", r.Valid(), r.Text())
	if !r.Valid() {
		t.Errorf("честный пакет NOT VERIFIED: запись superseded о прежнем сертификате второй службы сняла её POE")
	}
	if !strings.Contains(r.Text(), "superseded") && !r.Valid() {
		t.Logf("отчёт не называет причину записи (superseded), из-за которой POE снята")
	}
}

// D1. configuration.md: «when a token does not carry the TSA's certificate,
// … the bundles carry it beside the token, so that the auditor needs only the
// root». Вторая служба под промежуточным центром не кладёт свой сертификат в
// токен (журнал хранит только его — info.Signer, без центра). Аудитор, как
// сказано, даёт её корень: метка второй службы не годится («is the root of
// that TSA in -tsa-trust?» — корень там есть), POE нет, честный пакет NOT
// VERIFIED.
func TestC3R1CertlessSecondTSAUnderIntermediate(t *testing.T) {
	w, b := standard(t, nil)
	b.Upper.Inclusion = ptr(w.inclusion(5, 0))
	cut := w.now.Add(2 * time.Hour)
	now := w.now.Add(48 * time.Hour)
	root2 := c2issue(t, 1, "c3r1d second root", true, c2date(2020, 1, 1), c2date(2040, 1, 1), c2key(t), nil)
	ca := c2issue(t, 10, "c3r1d second CA", true, c2date(2020, 1, 1), c2date(2040, 1, 1), c2key(t), root2)
	k2 := c2key(t)
	y := c2issue(t, 0x5c01, "second TSA", false, c2date(2023, 1, 1), c2date(2029, 1, 1), k2, ca)
	second := tsa.AuthorityWith(k2, y.cert, root2.cert)
	second.WithoutCert()
	st := archiveOver(t, w, second, 5, cut.Add(-time.Hour))
	st.Certs = [][]byte{y.cert.Raw, ca.cert.Raw} // как кладёт хранилище теперь: служба и её центр
	b.Archive = []ArchiveStamp{st}
	run := func(inter ...*x509.Certificate) Report {
		tr := w.trust()
		tr.TSA.Roots.AddCert(root2.cert)
		tr.TSA.RootCerts = []*x509.Certificate{w.tsa.Root(), root2.cert}
		tr.TSA.Intermediates = inter
		tr.TSARevocations = compromised(t, w.tsa, cut, now)
		c2crl(t, tr.TSARevocations, root2, now.Add(-time.Hour))
		c2crl(t, tr.TSARevocations, ca, now.Add(-time.Hour))
		return Verify(b, tr)
	}
	if r := run(ca.cert); !r.Valid() {
		t.Fatalf("контроль: с промежуточным центром второй службы:\n%s", r.Text())
	}
	r := run()
	t.Logf("только корень второй службы: valid=%v\n%s", r.Valid(), r.Text())
	if !r.Valid() {
		t.Errorf("аудитор дал корень второй службы, как велит configuration.md («needs only the root»), а её метка не годится")
	}
}
