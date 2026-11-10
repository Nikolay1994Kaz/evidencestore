package proof

// Ревью цикла 3, заход 1 (r1): гипотезы сквозь пакет.

import (
	"crypto/x509"
	"testing"
	"time"

	"github.com/Nikolay1994Kaz/evidencestore/internal/tsa"
)

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
