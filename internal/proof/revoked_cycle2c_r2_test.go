package proof

// Ревью цикла 2, заход 3 (r2): гипотезы сквозь пакет.

import (
	"strings"
	"testing"
	"time"
)

// A1. Вторая служба, чьи токены не несут её сертификат (P-182: журнал теперь
// хранит его в строке, cert). В пакет идёт только токен; проверяющий дал
// корень второй службы, как велит bundles.md («Give esverify the root of the
// second TSA in -tsa-trust too»). Основная отозвана по компрометации после
// меток; метка второй над головой T2 — раньше отсечки.
func TestC2cR2CertlessSecondTSAHint(t *testing.T) {
	w, b := standard(t, nil)
	b.Upper.Inclusion = ptr(w.inclusion(5, 0))
	other, tr := otherTSA(t, w)
	other.WithoutCert()
	cut := w.now.Add(2 * time.Hour)
	now := w.now.Add(48 * time.Hour)
	b.Archive = []ArchiveStamp{archiveOver(t, w, other, 5, cut.Add(-time.Hour))}
	tr.TSARevocations = checkedToo(t, compromised(t, w.tsa, cut, now), other)
	r := Verify(b, tr)
	t.Logf("valid=%v\n%s", r.Valid(), r.Text())
	if !r.Valid() && strings.Contains(r.Text(), "is the root of that TSA in -tsa-trust?") {
		t.Errorf("корень второй службы дан; не хватает её сертификата (его нет ни в токене, ни в пакете), а подсказка — про корень")
	}
}
