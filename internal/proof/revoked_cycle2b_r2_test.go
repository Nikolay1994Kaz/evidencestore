package proof

// Ревью цикла 2, заход 2 (r2): находки по диффу ecad1a9..4d4f528 сквозь пакет.

import (
	"crypto/x509"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/Nikolay1994Kaz/evidencestore/internal/tsa"
)

// r2crl — CRL демо-службы a (её корня) с thisUpdate this.
func r2crl(t *testing.T, r *tsa.Revocations, a *tsa.Authority, name string, this time.Time, entries ...x509.RevocationListEntry) {
	t.Helper()
	der, err := a.RevocationList(this, this.Add(72*time.Hour), entries...)
	if err != nil {
		t.Fatal(err)
	}
	p := filepath.Join(t.TempDir(), name)
	if err := os.WriteFile(p, der, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := r.AddCRL(p); err != nil {
		t.Fatal(err)
	}
}

// R2-B сквозь пакет. Основная и вторая службы — демо (имя корня и номер
// службы у всех одни). Ключ основной украден: её CRL отзывает номер 2 и
// выпущен на два часа позже чистого CRL второй. Метка второй службы раньше
// отсечки — настоящая POE, её CRL дан; но CRL основной для сертификата второй
// — «CRL тёзки новее статусного, называет номер»: отзыв второй «не проверен»,
// по P-160 она не POE, и честный пакет не проходит. С CRL второй того же
// часа — проходит.
func TestC2bR2TwinDemoArchiveCannotRescue(t *testing.T) {
	for _, c := range []struct {
		name string
		lag  time.Duration
		want bool
	}{{"CRL второй того же часа", 0, true}, {"CRL второй на 2 ч старше", 2 * time.Hour, true}} {
		w, b := standard(t, nil)
		b.Upper.Inclusion = ptr(w.inclusion(5, 0))
		other, tr := otherTSA(t, w)
		cut := w.now.Add(2 * time.Hour)
		now := w.now.Add(48 * time.Hour)
		r := tsa.NewRevocations(now)
		r2crl(t, r, other, "other.crl", now.Add(-time.Hour-c.lag))
		r2crl(t, r, w.tsa, "main.crl", now.Add(-time.Hour),
			x509.RevocationListEntry{SerialNumber: w.tsa.Cert().SerialNumber, RevocationTime: cut, ReasonCode: tsa.ReasonKeyCompromise})
		tr.TSARevocations = r
		b.Archive = []ArchiveStamp{archiveOver(t, w, other, 5, cut.Add(-time.Hour))}
		rep := Verify(b, tr)
		if rep.Valid() != c.want {
			t.Errorf("%s: valid=%v, ждали %v:\n%s", c.name, rep.Valid(), c.want, rep.Text())
		}
	}
}
