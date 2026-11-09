package proof

// Ревью цикла 3, заход 1 (r2): гипотезы сквозь пакет.

import (
	"crypto/x509"
	"strings"
	"testing"
	"time"

	"github.com/Nikolay1994Kaz/evidencestore/internal/tsa"
)

// G1 сквозь пакет. Основная служба скомпрометирована после T2; метка второй
// службы над головой T2 — раньше отсечки: честный пакет проходит по POE.
// Вторая служба перевыпущена на тот же ключ при смене ключа её центра (AD CS:
// CRL на каждый ключ). Прежний сертификат X0 (от прежнего ключа центра)
// выведен superseded. Проверяющий, как велит bundles.md («Give every
// certificate of a key you know of in -tsa-trust»), дал и X0, и все CRL
// центра, но не сертификат прежнего ключа центра. Запись superseded о
// сертификате вне цепочек ни на что не влияет — а вторая служба «не
// проверена», POE пропадает, честный пакет NOT VERIFIED.
func TestC3aR2SupersededKnownCostsPOEBundle(t *testing.T) {
	w, b := standard(t, nil)
	b.Upper.Inclusion = ptr(w.inclusion(5, 0))
	cut := w.now.Add(2 * time.Hour)
	now := w.now.Add(48 * time.Hour)
	root2 := c2issue(t, 1, "second root", true, c2date(2020, 1, 1), c2date(2040, 1, 1), c2key(t), nil)
	caK0 := c2issue(t, 10, "second TSA CA", true, c2date(2020, 1, 1), c2date(2040, 1, 1), c2key(t), root2)
	caK1 := c2issue(t, 11, "second TSA CA", true, c2date(2024, 1, 1), c2date(2040, 1, 1), c2key(t), root2)
	kA := c2key(t)
	x0 := c2issue(t, 500, "second TSA", false, c2date(2022, 1, 1), c2date(2027, 1, 1), kA, caK0)
	x1 := c2issue(t, 600, "second TSA", false, c2date(2024, 6, 1), c2date(2030, 1, 1), kA, caK1)
	other := tsa.AuthorityWith(kA, x1.cert, root2.cert)
	b.Archive = []ArchiveStamp{archiveOver(t, w, other, 5, cut.Add(-time.Hour))}
	run := func(inter ...*x509.Certificate) Report {
		tr := w.trust()
		tr.TSA.Roots.AddCert(root2.cert)
		tr.TSA.RootCerts = append(tr.TSA.RootCerts, root2.cert)
		tr.TSA.Intermediates = append(tr.TSA.Intermediates, inter...)
		tr.TSARevocations = compromised(t, w.tsa, cut, now)
		c2crl(t, tr.TSARevocations, root2, now.Add(-time.Hour))
		c2crl(t, tr.TSARevocations, caK1, now.Add(-time.Hour))
		c2crl(t, tr.TSARevocations, caK0, now.Add(-time.Hour),
			x509.RevocationListEntry{SerialNumber: x0.cert.SerialNumber, RevocationTime: c2date(2024, 6, 2), ReasonCode: tsa.ReasonSuperseded})
		return Verify(b, tr)
	}
	if r := run(caK1.cert); !r.Valid() {
		t.Fatalf("контроль: без X0 честный пакет не прошёл:\n%s", r.Text())
	}
	if r := run(caK1.cert, x0.cert, caK0.cert); !r.Valid() {
		t.Fatalf("контроль: X0 с сертификатом прежнего ключа центра — не прошёл:\n%s", r.Text())
	}
	r := run(caK1.cert, x0.cert)
	t.Logf("valid=%v\n%s", r.Valid(), r.Text())
	if !r.Valid() {
		t.Errorf("честный пакет: прежний сертификат ключа второй службы, выведенный superseded в CRL прежнего ключа её центра, снял POE — NOT VERIFIED")
	}
	if !strings.Contains(r.Text(), "superseded") && !r.Valid() {
		t.Logf("отчёт не называет причину записи, из-за которой статус снят")
	}
}
