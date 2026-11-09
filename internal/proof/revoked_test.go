package proof

import (
	"crypto/x509"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"golang.org/x/mod/sumdb/tlog"

	"github.com/Nikolay1994Kaz/evidencestore/internal/auditchain"
	"github.com/Nikolay1994Kaz/evidencestore/internal/tsa"
)

// revocations — сведения об отзыве на момент now: CRL корня службы a с
// записями (сертификат службы — серийный номер её сертификата).
func revocations(t *testing.T, a *tsa.Authority, now time.Time, entries ...x509.RevocationListEntry) *tsa.Revocations {
	t.Helper()
	der, err := a.RevocationList(now.Add(-time.Hour), now.Add(time.Hour), entries...)
	if err != nil {
		t.Fatal(err)
	}
	p := filepath.Join(t.TempDir(), "tsa.crl")
	if err := os.WriteFile(p, der, 0o600); err != nil {
		t.Fatal(err)
	}
	r := tsa.NewRevocations(now)
	if err := r.AddCRL(p); err != nil {
		t.Fatal(err)
	}
	return r
}

// compromised — сертификат службы a отозван по компрометации ключа в at.
func compromised(t *testing.T, a *tsa.Authority, at, now time.Time) *tsa.Revocations {
	return revocations(t, a, now, x509.RevocationListEntry{SerialNumber: a.Cert().SerialNumber, RevocationTime: at, ReasonCode: tsa.ReasonKeyCompromise})
}

// otherTSA — вторая служба со своим корнем; trust мира верит обеим.
func otherTSA(t *testing.T, w *world) (*tsa.Authority, Trust) {
	t.Helper()
	b, err := tsa.NewAuthority(false)
	if err != nil {
		t.Fatal(err)
	}
	tr := w.trust()
	tr.TSA.Roots.AddCert(b.Root())
	return b, tr
}

// archiveOver — метка службы b над головой head мира в момент when.
func archiveOver(t *testing.T, w *world, b *tsa.Authority, head uint64, when time.Time) ArchiveStamp {
	t.Helper()
	b.Now = func() time.Time { return when }
	root := w.root(head)
	imprint := HeadImprint(head, root)
	token, err := b.Sign(imprint[:], nil)
	if err != nil {
		t.Fatal(err)
	}
	return ArchiveStamp{HeadSeq: head, Root: root[:], Token: token}
}

// linkTree — хранимые хеши дерева звеньев мира (tlog): доказательства
// продолжения для меток дальше конца пакета.
type linkTree []tlog.Hash

func (h linkTree) ReadHashes(idx []int64) ([]tlog.Hash, error) {
	out := make([]tlog.Hash, len(idx))
	for i, x := range idx {
		out[i] = h[x]
	}
	return out, nil
}

func (w *world) tree() linkTree {
	var h linkTree
	for i, l := range w.links {
		lh := auditchain.Hash(l)
		hs, err := tlog.StoredHashes(int64(i), lh[:], h)
		if err != nil {
			w.t.Fatal(err)
		}
		h = append(h, hs...)
	}
	return h
}

func revocationCheck(t *testing.T, checks []Check) Check {
	t.Helper()
	for _, c := range checks {
		if c.Name == revocationCheckName {
			return c
		}
	}
	t.Fatalf("пункта об отзыве нет: %+v", checks)
	return Check{}
}

// Без сведений об отзыве пункта нет, а заметка говорит, что отзыв не
// проверен. CRL, где служба не отозвана, — пункт проходит.
func TestRevocationNotRevoked(t *testing.T) {
	w, b := standard(t, nil)
	r := Verify(b, w.trust())
	if !r.Valid() || !strings.Contains(r.Text(), RevocationNotChecked) {
		t.Fatalf("без сведений об отзыве:\n%s", r.Text())
	}
	tr := w.trust()
	tr.TSARevocations = revocations(t, w.tsa, w.now.Add(48*time.Hour), x509.RevocationListEntry{SerialNumber: big.NewInt(777), RevocationTime: w.now})
	r = Verify(b, tr)
	if c := revocationCheck(t, r.Checks); !r.Valid() || !c.OK || !strings.Contains(c.Detail, "2 time-stamps, none rests on a revoked certificate") || strings.Contains(r.Text(), RevocationNotChecked) {
		t.Fatalf("CRL без службы:\n%s", r.Text())
	}
}

// Отзыв без компрометации: метки до даты отзыва в силе; T2 позже даты — нет.
func TestRevocationSuperseded(t *testing.T) {
	w, b := standard(t, nil)
	t2 := Verify(b, w.trust()).Upper
	tr := w.trust()
	tr.TSARevocations = revocations(t, w.tsa, t2.Add(48*time.Hour), x509.RevocationListEntry{SerialNumber: w.tsa.Cert().SerialNumber, RevocationTime: t2.Add(time.Hour), ReasonCode: tsa.ReasonSuperseded})
	if r := Verify(b, tr); !r.Valid() {
		t.Fatalf("выведена из работы после меток:\n%s", r.Text())
	}
	tr.TSARevocations = revocations(t, w.tsa, t2.Add(48*time.Hour), x509.RevocationListEntry{SerialNumber: w.tsa.Cert().SerialNumber, RevocationTime: t2, ReasonCode: tsa.ReasonSuperseded})
	if r := Verify(b, tr); r.Valid() || !strings.Contains(r.Text(), "not earlier") {
		t.Fatalf("выведена из работы во время T2:\n%s", r.Text())
	}
}

// Компрометация после меток: время меток ничего не доказывает. Пакет без
// второй службы и свидетеля не проходит, и отчёт говорит, чего не хватает.
func TestRevocationCompromiseWithoutPOE(t *testing.T) {
	w, b := standard(t, nil)
	tr := w.trust()
	tr.TSARevocations = compromised(t, w.tsa, w.now.Add(2*time.Hour), w.now.Add(48*time.Hour))
	r := Verify(b, tr)
	c := revocationCheck(t, r.Checks)
	if r.Valid() || c.OK || !strings.Contains(c.Detail, "time-stamp T1 in link 2") || !strings.Contains(c.Detail, "does not show where its token lies") {
		t.Fatalf("компрометация без POE:\n%s", r.Text())
	}
	b.Upper.Inclusion = ptr(w.inclusion(5, 0)) // где лежит T2 — всё равно нечем показать
	if c := revocationCheck(t, Verify(b, tr).Checks); c.OK || !strings.Contains(c.Detail, "over a head at or after link 5") {
		t.Fatalf("T2 с листом, без POE: %+v", c)
	}
}

// POE от метки второй службы над концом пакета: раньше отсечки — пакет
// проходит; позже — нет; та же (скомпрометированная) служба — не в счёт;
// служба, которой проверяющий не верит, — заметка.
func TestRevocationPOEFromArchive(t *testing.T) {
	w, b := standard(t, nil)
	b.Upper.Inclusion = ptr(w.inclusion(5, 0))
	other, tr := otherTSA(t, w)
	cut := w.now.Add(2 * time.Hour)
	tr.TSARevocations = compromised(t, w.tsa, cut, w.now.Add(48*time.Hour))

	b.Archive = []ArchiveStamp{archiveOver(t, w, other, 5, cut.Add(-time.Hour))}
	r := Verify(b, tr)
	if c := revocationCheck(t, r.Checks); !r.Valid() || !strings.Contains(c.Detail, "the archive time-stamp") {
		t.Fatalf("POE от второй службы:\n%s", r.Text())
	}
	b.Archive = []ArchiveStamp{archiveOver(t, w, other, 5, cut.Add(time.Minute))}
	if r := Verify(b, tr); r.Valid() {
		t.Fatalf("метка второй службы позже отсечки спасла:\n%s", r.Text())
	}
	b.Archive = []ArchiveStamp{archiveOver(t, w, w.tsa, 5, cut.Add(-time.Hour))}
	if r := Verify(b, tr); r.Valid() || !strings.Contains(r.Text(), "rests on a revoked certificate itself") {
		t.Fatalf("метка той же службы:\n%s", r.Text())
	}
	b.Archive = []ArchiveStamp{archiveOver(t, w, other, 5, cut.Add(-time.Hour))}
	notTrusted := w.trust()
	notTrusted.TSARevocations = tr.TSARevocations
	if r := Verify(b, notTrusted); r.Valid() || !strings.Contains(r.Text(), "is the root of that TSA in -tsa-trust?") {
		t.Fatalf("вторая служба без доверия:\n%s", r.Text())
	}
}

// Метка второй службы над головой дальше конца пакета — корень по
// доказательству продолжения; подложное доказательство — не в счёт.
func TestRevocationArchiveBeyondBundle(t *testing.T) {
	w, b := standard(t, nil)
	b.Upper.Inclusion = ptr(w.inclusion(5, 0))
	w.wlink(auditchain.Leaf{Type: auditchain.EventGap, Scope: "abs-core"})
	w.wlink(auditchain.Leaf{Type: auditchain.EventGap, Scope: "abs-core"})
	other, tr := otherTSA(t, w)
	cut := w.now.Add(2 * time.Hour)
	tr.TSARevocations = compromised(t, w.tsa, cut, w.now.Add(48*time.Hour))
	a := archiveOver(t, w, other, 7, cut.Add(-time.Hour))
	p, err := tlog.ProveTree(7, 5, w.tree())
	if err != nil {
		t.Fatal(err)
	}
	for _, h := range p {
		a.Proof = append(a.Proof, h[:])
	}
	b.Archive = []ArchiveStamp{a}
	if r := Verify(b, tr); !r.Valid() {
		t.Fatalf("метка дальше конца пакета:\n%s", r.Text())
	}
	a.Proof[0][0] ^= 1
	b.Archive = []ArchiveStamp{a}
	if r := Verify(b, tr); r.Valid() || !strings.Contains(r.Text(), "does not extend the chain in the bundle") {
		t.Fatalf("подложное доказательство продолжения:\n%s", r.Text())
	}
}

// POE от своей метки пакета другой службы: T1 скомпрометированной службы,
// T2 — другой и раньше отсечки.
func TestRevocationPOEFromOtherTSAInBundle(t *testing.T) {
	w := newWorld(t)
	other, tr := otherTSA(t, w)
	other.Now = func() time.Time { return w.now }
	w.wlink(auditchain.Leaf{Type: auditchain.EventStart})
	h1, t1 := w.stamp()
	w.now = w.now.Add(time.Second)
	w.wlink(tokenLeaf(h1, t1))
	e2 := sealedBytes(t, 2, w.now.Add(time.Second), "second")
	w.now = w.now.Add(3 * time.Second)
	w.wlink(evLeaf(t, e2, 1))
	w.now = w.now.Add(time.Second)
	main := w.tsa
	w.tsa = other
	h3, t2 := w.stamp()
	w.tsa = main
	w.wlink(tokenLeaf(h3, t2))
	b := w.bundle(e2, 3, 0, h3, t2, 2)
	tr.TSARevocations = compromised(t, main, w.now.Add(time.Hour), w.now.Add(48*time.Hour))
	r := Verify(b, tr)
	if c := revocationCheck(t, r.Checks); !r.Valid() || !strings.Contains(c.Detail, "time-stamp T1 in link 2") || !strings.Contains(c.Detail, "over head 3") {
		t.Fatalf("T1 спасает T2 другой службы:\n%s", r.Text())
	}
}

// POE от подписи закреплённого свидетеля над концом пакета.
func TestRevocationPOEFromWitness(t *testing.T) {
	w, b := standard(t, nil)
	b.Upper.Inclusion = ptr(w.inclusion(5, 0))
	s := cosigner(t, "witness.example/w1")
	tr := cosignTrust(w, s)
	cut := w.now.Add(2 * time.Hour)
	tr.TSARevocations = compromised(t, w.tsa, cut, w.now.Add(48*time.Hour))
	b.Cosignatures = []Cosignature{w.cosigned(s, 5, w.root(5), cut.Add(-time.Hour))}
	r := Verify(b, tr)
	if c := revocationCheck(t, r.Checks); !r.Valid() || !strings.Contains(c.Detail, "witness witness.example/w1") {
		t.Fatalf("POE от свидетеля:\n%s", r.Text())
	}
	b.Cosignatures = []Cosignature{w.cosigned(s, 5, w.root(5), cut.Add(time.Minute))}
	if r := Verify(b, tr); r.Valid() {
		t.Fatalf("подпись свидетеля позже отсечки спасла:\n%s", r.Text())
	}
}

// Лист T2 в пакете обязан быть листом этого токена.
func TestRevocationUpperInclusionChecked(t *testing.T) {
	w, b := standard(t, nil)
	b.Upper.Inclusion = ptr(w.inclusion(3, 0)) // лист улики, а не токена
	if r := Verify(b, w.trust()); r.Valid() {
		t.Fatalf("чужой лист вместо токена T2:\n%s", r.Text())
	}
	b.Upper.Inclusion = ptr(w.inclusion(2, 0)) // токен T1
	if r := Verify(b, w.trust()); r.Valid() {
		t.Fatalf("токен T1 вместо T2:\n%s", r.Text())
	}
}

// Пакет за окно и по источнику: та же POE от метки второй службы.
func TestRevocationWindowAndSource(t *testing.T) {
	ww := windowWorld(t, []auditchain.Leaf{rec(t, 1, at(10, 5, 0))}, nil)
	wb := ww.window(1, 3, at(10, 4, 0), at(10, 6, 0))
	other, tr := otherTSA(t, ww)
	tr.TSARevocations = compromised(t, ww.tsa, at(12, 0, 0), at(23, 0, 0))
	if r := VerifyWindow(wb, tr, time.Time{}, time.Time{}); r.Valid() || !strings.Contains(r.Text(), "nothing in the bundle shows it existed before") {
		t.Fatalf("окно без POE:\n%s", r.Text())
	}
	wb.Archive = []ArchiveStamp{archiveOver(t, ww, other, 3, at(11, 0, 0))}
	if r := VerifyWindow(wb, tr, time.Time{}, time.Time{}); !r.Valid() {
		t.Fatalf("окно с POE:\n%s", r.Text())
	}

	sw := newSrcWorld(t, srcOpts{})
	sb := sw.bundle(at(10, 4, 0), at(10, 6, 0))
	end := sb.Checkpoint.Size
	other, tr = otherTSA(t, sw.world)
	cut := sw.now.Add(2 * time.Hour)
	tr.TSARevocations = compromised(t, sw.tsa, cut, cut.Add(24*time.Hour))
	if r := VerifySource(sb, tr, time.Time{}, time.Time{}); r.Valid() {
		t.Fatalf("источник без POE:\n%s", r.Text())
	}
	sb.Archive = []ArchiveStamp{archiveOver(t, sw.world, other, end, cut.Add(-time.Hour))}
	if r := VerifySource(sb, tr, time.Time{}, time.Time{}); !r.Valid() {
		t.Fatalf("источник с POE:\n%s", r.Text())
	}
}

func ptr[T any](v T) *T { return &v }
