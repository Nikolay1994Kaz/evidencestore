package proof

// Пересмотр 10.11 (FINDINGS, цикл 2, заход 3): пакет несёт сертификат второй
// службы, которая не кладёт его в токен.

import (
	"strings"
	"testing"
	"time"
)

// Вторая служба не кладёт свой сертификат в токен: пакет несёт его (Cert),
// и проверяющему довольно её корня. Без него — подсказка про сертификат, а не
// про корень; испорченный — отказ этой метке.
func TestRevocationArchiveCarriesCert(t *testing.T) {
	w, b := standard(t, nil)
	b.Upper.Inclusion = ptr(w.inclusion(5, 0))
	other, tr := otherTSA(t, w)
	other.WithoutCert()
	cut := w.now.Add(2 * time.Hour)
	now := w.now.Add(48 * time.Hour)
	st := archiveOver(t, w, other, 5, cut.Add(-time.Hour))
	tr.TSARevocations = checkedToo(t, compromised(t, w.tsa, cut, now), other)
	b.Archive = []ArchiveStamp{st}
	if r := Verify(b, tr); r.Valid() || !strings.Contains(r.Text(), "does not put its certificate in its time-stamps, and the bundle does not carry it") {
		t.Fatalf("без сертификата второй службы:\n%s", r.Text())
	}
	st.Cert = other.Cert().Raw
	b.Archive = []ArchiveStamp{st}
	if r := Verify(b, tr); !r.Valid() {
		t.Fatalf("пакет несёт сертификат второй службы, её корень дан:\n%s", r.Text())
	}
	st.Cert = []byte{0x30, 0x03, 0x02, 0x01, 0x01}
	b.Archive = []ArchiveStamp{st}
	if r := Verify(b, tr); r.Valid() || !strings.Contains(r.Text(), "carries a certificate that does not parse") {
		t.Fatalf("испорченный сертификат второй службы:\n%s", r.Text())
	}
}
