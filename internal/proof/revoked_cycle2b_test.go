package proof

// Ревью цикла 2, заход 2 (r1): гипотезы сквозь пакет.

import (
	"crypto/x509"
	"crypto/x509/pkix"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Nikolay1994Kaz/evidencestore/internal/tsa"
)

// H5 сквозь пакет. Две демо-службы (имена и номера одни, ключи разные):
// основная отозвана по компрометации после меток, метка второй — над
// головой T2 раньше отсечки. Проверяющий дал CRL обеих; CRL основной на
// минуту новее CRL второй. Честный пакет не проходит: «revocation of its
// own certificate was not checked … pass the CRL of its CA».
func TestRevocationC2bNamesakeDemoTSAsBundle(t *testing.T) {
	w, b := standard(t, nil)
	b.Upper.Inclusion = ptr(w.inclusion(5, 0))
	other, tr := otherTSA(t, w)
	cut := w.now.Add(2 * time.Hour)
	now := w.now.Add(48 * time.Hour)
	b.Archive = []ArchiveStamp{archiveOver(t, w, other, 5, cut.Add(-time.Hour))}
	run := func(mainLater time.Duration) Report {
		revs := tsa.NewRevocations(now)
		write := func(a *tsa.Authority, this time.Time, name string, entries ...x509.RevocationListEntry) {
			der, err := a.RevocationList(this, now.Add(time.Hour), entries...)
			if err != nil {
				t.Fatal(err)
			}
			p := filepath.Join(t.TempDir(), name)
			os.WriteFile(p, der, 0o600)
			if err := revs.AddCRL(p); err != nil {
				t.Fatal(err)
			}
		}
		write(other, now.Add(-time.Hour), "second.crl")
		write(w.tsa, now.Add(-time.Hour+mainLater), "main.crl", x509.RevocationListEntry{SerialNumber: w.tsa.Cert().SerialNumber, RevocationTime: cut, ReasonCode: tsa.ReasonKeyCompromise})
		tr.TSARevocations = revs
		return Verify(b, tr)
	}
	if r := run(0); !r.Valid() {
		t.Fatalf("контроль: CRL выпущены в одну секунду:\n%s", r.Text())
	}
	r := run(time.Minute)
	t.Logf("main CRL a minute newer: valid=%v\n%s", r.Valid(), r.Text())
	if !r.Valid() {
		t.Errorf("CRL основной службы на минуту новее CRL второй (тёзки) — честный пакет не прошёл")
	}
}

// H7 сквозь пакет. Сертификат второй службы истёк (служба сменила
// сертификат), её метка над головой T2 — до истечения и до отсечки основной.
// Основная отозвана по компрометации позже. Проверяющий даёт свежий CRL
// центра второй службы — истёкшего сертификата в нём нет (RFC 5280, 3.3), он
// «не проверен», и метка не POE. CRL второй службы хранилище не хранит, и в
// пакете его нет: честный пакет не проходит, хотя до P-160 проходил.
func TestRevocationC2bSecondTSAExpiredCertBundle(t *testing.T) {
	w, b := standard(t, nil)
	b.Upper.Inclusion = ptr(w.inclusion(5, 0))
	cut := w.now.Add(2 * time.Hour)
	now := w.now.Add(60 * 24 * time.Hour)
	root2 := c2issue(t, 1, "second root", true, c2date(2020, 1, 1), c2date(2040, 1, 1), c2key(t), nil)
	leaf := c2issue(t, 7, "second TSA", false, c2date(2024, 1, 1), w.now.Add(30*24*time.Hour), c2key(t), root2)
	other := tsa.AuthorityWith(leaf.key, leaf.cert, root2.cert)
	b.Archive = []ArchiveStamp{archiveOver(t, w, other, 5, cut.Add(-time.Hour))}
	tr := w.trust()
	tr.TSA.Roots.AddCert(root2.cert)
	revs := tsa.NewRevocations(now)
	der, _ := w.tsa.RevocationList(now.Add(-time.Hour), now.Add(time.Hour), x509.RevocationListEntry{SerialNumber: w.tsa.Cert().SerialNumber, RevocationTime: cut, ReasonCode: tsa.ReasonKeyCompromise})
	p := filepath.Join(t.TempDir(), "main.crl")
	os.WriteFile(p, der, 0o600)
	if err := revs.AddCRL(p); err != nil {
		t.Fatal(err)
	}
	c2crl(t, revs, root2, now.Add(-time.Hour))
	tr.TSARevocations = revs
	// Записано в limitations.md: без CRL её центра того времени, когда её
	// сертификат действовал, статус метки второй службы не известен, и она не
	// POE (ETSI EN 319 102-1); отчёт говорит, какой CRL дать.
	r := Verify(b, tr)
	if r.Valid() || !strings.Contains(r.Text(), "from before then too") || !strings.Contains(r.Text(), "the revocation of its own certificate was not checked") {
		t.Fatalf("сертификат второй службы истёк до свежего CRL:\n%s", r.Text())
	}
	// С CRL её центра того времени — POE.
	c2crl(t, revs, root2, leaf.cert.NotAfter.Add(-24*time.Hour))
	if r := Verify(b, tr); !r.Valid() {
		t.Fatalf("сертификат второй службы истёк, CRL того времени дан:\n%s", r.Text())
	}
}

// H6 сквозь пакет. Поле certificates токена не подписано: к метке второй
// службы можно дописать сертификаты, и подпись токена сойдётся. До среза
// 10.11 все они шли в оценку отзыва, и проверка пакета росла квадратично;
// теперь оценка их не видит, и время проверки от их числа не зависит.
func TestRevocationC2bJunkCertsInArchiveTokens(t *testing.T) {
	w, b := standard(t, nil)
	root2 := c2issue(t, 1, "second root", true, c2date(2020, 1, 1), c2date(2040, 1, 1), c2key(t), nil)
	leaf := c2issue(t, 7, "second TSA", false, c2date(2024, 1, 1), c2date(2030, 1, 1), c2key(t), root2)
	k := c2key(t)
	var junk []*x509.Certificate
	for i := range 520 {
		subj, iss := "A", "B"
		if i%2 == 1 {
			subj, iss = "B", "A"
		}
		parent := &c2ca{&x509.Certificate{Subject: pkix.Name{CommonName: iss}}, k}
		c := c2issue(t, int64(1000+i), subj, false, c2date(2025, 1, 1), c2date(2030, 1, 1), k, parent)
		junk = append(junk, c.cert)
	}
	tr := w.trust()
	tr.TSA.Roots.AddCert(root2.cert)
	for i := 0; i < len(junk); i += 130 {
		a := tsa.AuthorityWith(leaf.key, leaf.cert, root2.cert)
		a.Carry(junk[i:min(i+130, len(junk))]...)
		st := archiveOver(t, w, a, 5, w.now.Add(time.Hour))
		if len(st.Token) > tsa.MaxTokenSize {
			t.Fatalf("token %d bytes", len(st.Token))
		}
		b.Archive = append(b.Archive, st)
	}
	tr.TSARevocations = checkedToo(t, tsa.NewRevocations(w.now.Add(48*time.Hour)), w.tsa)
	start := time.Now()
	r := Verify(b, tr)
	if took := time.Since(start); took > 5*time.Second || !r.Valid() {
		t.Fatalf("%d junk certs in %d archive tokens: Verify took %v, valid=%v\n%s", len(junk), len(b.Archive), took, r.Valid(), r.Text())
	}
}
