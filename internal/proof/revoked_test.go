package proof

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"fmt"
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

// checkedToo — пустые CRL служб as в сведениях r: их отзыв проверен, и их
// метки могут быть POE (время другой метки показывает только метка, чей
// отзыв проверен, ETSI EN 319 102-1).
func checkedToo(t testing.TB, r *tsa.Revocations, as ...*tsa.Authority) *tsa.Revocations {
	t.Helper()
	for i, a := range as {
		der, err := a.RevocationList(r.Now.Add(-time.Hour), r.Now.Add(time.Hour))
		if err != nil {
			t.Fatal(err)
		}
		p := filepath.Join(t.TempDir(), fmt.Sprintf("also-%d.crl", i))
		if err := os.WriteFile(p, der, 0o600); err != nil {
			t.Fatal(err)
		}
		if err := r.AddCRL(p); err != nil {
			t.Fatal(err)
		}
	}
	return r
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
	if c := revocationCheck(t, r.Checks); !r.Valid() || !c.OK || !strings.Contains(c.Detail, "2 time-stamps, none found revoked") || strings.Contains(r.Text(), RevocationNotChecked) {
		t.Fatalf("CRL без службы:\n%s", r.Text())
	}
	// CRL центра, которого нет в цепочках меток пакета, назван: не тот файл.
	k, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "unrelated CA"}, NotBefore: w.now.Add(-time.Hour), NotAfter: w.now.Add(time.Hour),
		KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageCRLSign, BasicConstraintsValid: true, IsCA: true}
	der, _ := x509.CreateCertificate(rand.Reader, tmpl, tmpl, k.Public(), k)
	ca, _ := x509.ParseCertificate(der)
	crl, _ := x509.CreateRevocationList(rand.Reader, &x509.RevocationList{Number: big.NewInt(1), ThisUpdate: w.now, NextUpdate: w.now.Add(time.Hour)}, ca, k)
	p := filepath.Join(t.TempDir(), "unrelated.crl")
	os.WriteFile(p, crl, 0o600)
	if err := tr.TSARevocations.AddCRL(p); err != nil {
		t.Fatal(err)
	}
	if r := Verify(b, tr); !r.Valid() || !strings.Contains(r.Text(), "unrelated.crl") || !strings.Contains(r.Text(), "is of no CA in the chains") {
		t.Fatalf("посторонний CRL не назван:\n%s", r.Text())
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
	r := Verify(b, tr)
	// Пункт об отзыве не говорит «ни одна метка не на отозванном».
	if c := revocationCheck(t, r.Checks); r.Valid() || c.OK || !strings.Contains(c.Detail, "time-stamp T2 over head 4") || !strings.Contains(c.Detail, "not earlier") || strings.Contains(r.Text(), "is of no CA") {
		t.Fatalf("выведена из работы во время T2:\n%s", r.Text())
	}
}

// POE не раньше времени самой метки: голову с её токеном не заверить
// раньше, чем токен выдан. Метка второй службы с отстающими часами (на
// полминуты, на час) считается со времени метки: T1 раньше отсечки —
// спасена, T2 позже — нет. Отвергать её за отставание незачем: время метки
// под подозрением выбирает тот, у кого ключ.
func TestRevocationPOENotBeforeToken(t *testing.T) {
	w, b := standard(t, nil)
	b.Upper.Inclusion = ptr(w.inclusion(5, 0))
	r0 := Verify(b, w.trust())
	other, tr := otherTSA(t, w)
	cut := r0.Upper.Add(-time.Second) // T1 раньше отсечки, T2 — нет
	tr.TSARevocations = checkedToo(t, compromised(t, w.tsa, cut, w.now.Add(48*time.Hour)), other)
	b.Archive = []ArchiveStamp{archiveOver(t, w, other, 5, r0.Lower.Add(-30*time.Second))}
	r := Verify(b, tr)
	if c := revocationCheck(t, r.Checks); r.Valid() || !strings.Contains(c.Detail, "time-stamp T2 over head 4 rests") || strings.Contains(c.Detail, "time-stamp T1 in link 2 rests") {
		t.Fatalf("POE с часами, отстающими на полминуты:\n%s", r.Text())
	}
	b.Archive = []ArchiveStamp{archiveOver(t, w, other, 5, r0.Lower.Add(-time.Hour))}
	r = Verify(b, tr)
	if c := revocationCheck(t, r.Checks); r.Valid() || !strings.Contains(c.Detail, "time-stamp T2 over head 4 rests") || strings.Contains(c.Detail, "time-stamp T1 in link 2 rests") {
		t.Fatalf("POE на час раньше метки:\n%s", r.Text())
	}
	// Отсечка после обеих: POE на полминуты раньше T1 спасает обе, и отчёт
	// говорит, что её часы отстают.
	tr.TSARevocations = checkedToo(t, compromised(t, w.tsa, r0.Upper.Add(time.Hour), w.now.Add(48*time.Hour)), other)
	b.Archive = []ArchiveStamp{archiveOver(t, w, other, 5, r0.Lower.Add(-30*time.Second))}
	if r := Verify(b, tr); !r.Valid() || !strings.Contains(revocationCheck(t, r.Checks).Detail, "its clock is behind") {
		t.Fatalf("POE с отстающими часами, обе метки до отсечки:\n%s", r.Text())
	}
}

// Тот же ключ под двумя сертификатами в одном пакете: T1 — под отозванным по
// компрометации, T2 — под перевыпущенным, которого нет ни в одном CRL. T2
// подписана ключом под подозрением: сама ждёт POE и T1 не спасает.
func TestRevocationSameKeyTaintsOwnStamps(t *testing.T) {
	w := newWorld(t)
	main := w.tsa
	reissued, err := main.Reissue(77, w.now.Add(240*time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	reissued.Now = func() time.Time { return w.now }
	w.wlink(auditchain.Leaf{Type: auditchain.EventStart})
	h1, t1 := w.stamp()
	w.now = w.now.Add(time.Second)
	w.wlink(tokenLeaf(h1, t1))
	e2 := sealedBytes(t, 2, w.now.Add(time.Second), "second")
	w.now = w.now.Add(3 * time.Second)
	w.wlink(evLeaf(t, e2, 1))
	w.now = w.now.Add(time.Second)
	w.tsa = reissued
	h3, t2 := w.stamp()
	w.tsa = main
	w.wlink(tokenLeaf(h3, t2))
	b := w.bundle(e2, 3, 0, h3, t2, 2)
	b.Upper.Inclusion = ptr(w.inclusion(4, 0))
	tr := w.trust()
	if r := Verify(b, tr); !r.Valid() {
		t.Fatalf("контроль, без отзыва:\n%s", r.Text())
	}
	tr.TSARevocations = compromised(t, main, w.now.Add(time.Hour), w.now.Add(48*time.Hour))
	r := Verify(b, tr)
	if c := revocationCheck(t, r.Checks); r.Valid() || !strings.Contains(c.Detail, fmt.Sprintf("time-stamp T2 over head %d rests on certificate", h3)) || !strings.Contains(c.Detail, `(serial 2) issued by "CN=evidencestore demo TSA root" with the same key`) {
		t.Fatalf("T2 того же ключа под перевыпущенным сертификатом:\n%s", r.Text())
	}
}

// Сертификат службы перевыпущен на тот же ключ: CRL отзывает новый по
// компрометации, прежний не назван нигде. Метка «второй службы», подписанная
// тем же ключом под прежним сертификатом, — не POE: ключ под подозрением в
// этом же пакете.
func TestRevocationPOESameKeyOtherCert(t *testing.T) {
	w, b := standard(t, nil)
	b.Upper.Inclusion = ptr(w.inclusion(5, 0))
	cut := w.now.Add(2 * time.Hour)
	tr := w.trust()
	tr.TSARevocations = compromised(t, w.tsa, cut, w.now.Add(48*time.Hour))
	old, err := w.tsa.Reissue(77, w.now.Add(time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	b.Archive = []ArchiveStamp{archiveOver(t, w, old, 5, w.now)}
	r := Verify(b, tr)
	if r.Valid() || !strings.Contains(r.Text(), "with the same key) itself: not used") {
		t.Fatalf("POE тем же ключом под другим сертификатом:\n%s", r.Text())
	}
}

// Подпись свидетеля над головой дальше конца пакета корнем не сверить, но
// отчёт называет её: до какой головы просить пакет.
func TestRevocationWitnessBeyondBundle(t *testing.T) {
	w, b := standard(t, nil)
	b.Upper.Inclusion = ptr(w.inclusion(5, 0))
	w.wlink(auditchain.Leaf{Type: auditchain.EventGap, Scope: "abs-core"})
	s := cosigner(t, "witness.example/w1")
	tr := cosignTrust(w, s)
	cut := w.now.Add(2 * time.Hour)
	tr.TSARevocations = compromised(t, w.tsa, cut, w.now.Add(48*time.Hour))
	b.Cosignatures = []Cosignature{w.cosigned(s, 6, w.root(6), cut.Add(-time.Hour))}
	if c := revocationCheck(t, Verify(b, tr).Checks); c.OK || !strings.Contains(c.Detail, "-to-head 6") {
		t.Fatalf("подпись дальше конца пакета не названа: %+v", c)
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
	// Причина — свой отозванный сертификат метки, а не «ключ под подозрением».
	if r.Valid() || c.OK || !strings.Contains(c.Detail, "time-stamp T1 in link 2 rests on certificate") || !strings.Contains(c.Detail, "does not show where its token lies") || strings.Contains(c.Detail, "under suspicion in this bundle") {
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
	tr.TSARevocations = checkedToo(t, compromised(t, w.tsa, cut, w.now.Add(48*time.Hour)), other)

	b.Archive = []ArchiveStamp{archiveOver(t, w, other, 5, cut.Add(-time.Hour))}
	r := Verify(b, tr)
	if c := revocationCheck(t, r.Checks); !r.Valid() || !strings.Contains(c.Detail, "the archive time-stamp") {
		t.Fatalf("POE от второй службы:\n%s", r.Text())
	}
	b.Archive = []ArchiveStamp{archiveOver(t, w, other, 5, cut.Add(time.Minute))}
	if r := Verify(b, tr); r.Valid() {
		t.Fatalf("метка второй службы позже отсечки спасла:\n%s", r.Text())
	}
	// Над головой раньше звена токена T1 (звено 2) — токена в ней нет.
	b.Archive = []ArchiveStamp{archiveOver(t, w, other, 1, cut.Add(-time.Hour)), archiveOver(t, w, other, 5, cut.Add(time.Minute))}
	if r := Verify(b, tr); r.Valid() {
		t.Fatalf("метка над головой раньше токена спасла:\n%s", r.Text())
	}
	// Метка над чужим корнем головы пакета — не POE этой цепи.
	fake := [32]byte{7}
	other.Now = func() time.Time { return cut.Add(-time.Hour) }
	imprint := HeadImprint(5, fake)
	token, _ := other.Sign(imprint[:], nil)
	b.Archive = []ArchiveStamp{{HeadSeq: 5, Root: fake[:], Token: token}}
	if r := Verify(b, tr); r.Valid() || !strings.Contains(r.Text(), "does not agree with the chain in the bundle") {
		t.Fatalf("метка над чужим корнем:\n%s", r.Text())
	}
	b.Archive = []ArchiveStamp{archiveOver(t, w, w.tsa, 5, cut.Add(-time.Hour))}
	if r := Verify(b, tr); r.Valid() || !strings.Contains(r.Text(), "itself: not used") {
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
	tr.TSARevocations = checkedToo(t, compromised(t, w.tsa, cut, w.now.Add(48*time.Hour)), other)
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
	tr.TSARevocations = checkedToo(t, compromised(t, main, w.now.Add(time.Hour), w.now.Add(48*time.Hour)), other)
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
	// Подпись над чужим корнем головы пакета — не POE этой цепи.
	b.Cosignatures = []Cosignature{w.cosigned(s, 5, [32]byte{7}, cut.Add(-time.Hour))}
	if c := revocationCheck(t, Verify(b, tr).Checks); c.OK {
		t.Fatalf("подпись свидетеля над чужим корнем спасла: %+v", c)
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
	// Лист после головы T2, но не её токен.
	w.wlink(auditchain.Leaf{Type: auditchain.EventGap, Scope: "abs-core"})
	e2 := b.Evidence
	b = w.bundle(e2, 3, 1, b.Upper.HeadSeq, b.Upper.Token, 2)
	b.Upper.Inclusion = ptr(w.inclusion(6, 0))
	if r := Verify(b, w.trust()); r.Valid() {
		t.Fatalf("чужой лист после головы T2:\n%s", r.Text())
	}
	b.Upper.Inclusion = ptr(w.inclusion(5, 0))
	if r := Verify(b, w.trust()); !r.Valid() {
		t.Fatalf("лист T2 в пакете длиннее:\n%s", r.Text())
	}
}

// Пакет за окно и по источнику: та же POE от метки второй службы.
func TestRevocationWindowAndSource(t *testing.T) {
	ww := windowWorld(t, []auditchain.Leaf{rec(t, 1, at(10, 5, 0))}, nil)
	wb := ww.window(1, 3, at(10, 4, 0), at(10, 6, 0))
	other, tr := otherTSA(t, ww)
	tr.TSARevocations = checkedToo(t, compromised(t, ww.tsa, at(12, 0, 0), at(23, 0, 0)), other)
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
	tr.TSARevocations = checkedToo(t, compromised(t, sw.tsa, cut, cut.Add(24*time.Hour)), other)
	if r := VerifySource(sb, tr, time.Time{}, time.Time{}); r.Valid() {
		t.Fatalf("источник без POE:\n%s", r.Text())
	}
	sb.Archive = []ArchiveStamp{archiveOver(t, sw.world, other, end, cut.Add(-time.Hour))}
	if r := VerifySource(sb, tr, time.Time{}, time.Time{}); !r.Valid() {
		t.Fatalf("источник с POE:\n%s", r.Text())
	}
}

func ptr[T any](v T) *T { return &v }

// Подозрение из метки второй службы — и когда свои метки ничего не ждут:
// T1 и T2 подписаны ключом, другой сертификат которого (в метке второй службы
// того же пакета) отозван по компрометации. Ключ один — POE нужна всем, и
// метка тем же ключом её не даёт; даёт метка другой службы раньше отсечки.
func TestRevocationArchiveRevealsKey(t *testing.T) {
	w, b := standard(t, nil)
	b.Upper.Inclusion = ptr(w.inclusion(5, 0))
	re, err := w.tsa.Reissue(77, w.now.Add(240*time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	other, tr := otherTSA(t, w)
	cut := w.now.Add(2 * time.Hour)
	same := archiveOver(t, w, re, 5, w.now)
	b.Archive = []ArchiveStamp{same}
	if r := Verify(b, tr); !r.Valid() {
		t.Fatalf("контроль без отзыва:\n%s", r.Text())
	}
	tr.TSARevocations = checkedToo(t, revocations(t, w.tsa, w.now.Add(48*time.Hour),
		x509.RevocationListEntry{SerialNumber: big.NewInt(77), RevocationTime: cut, ReasonCode: tsa.ReasonKeyCompromise}), other)
	r := Verify(b, tr)
	if c := revocationCheck(t, r.Checks); r.Valid() || !strings.Contains(c.Detail, "time-stamp T1 in link 2 rests on certificate") || !strings.Contains(c.Detail, "(serial 77)") || !strings.Contains(r.Text(), "itself: not used") {
		t.Fatalf("ключ под подозрением по метке второй службы:\n%s", r.Text())
	}
	b.Archive = []ArchiveStamp{same, archiveOver(t, w, other, 5, cut.Add(-time.Hour))}
	if r := Verify(b, tr); !r.Valid() {
		t.Fatalf("POE от другой службы:\n%s", r.Text())
	}
}

// Отсечка ключа — по всему пакету. У ключа два сертификата: X1 отозван по
// компрометации в 10:30 (или в 11:30 с invalidityDate 10:30), X2 — в 12:00.
// T1 подписана под X1, T2 — под X2: T2 ждёт POE раньше 10:30, не раньше
// 12:00, и метка второй службы в 11:00 её не спасает — ключ к тому времени
// уже украден. POE раньше 10:30 — спасает.
func TestRevocationKeyCutoffBundleWide(t *testing.T) {
	day := time.Date(2026, 10, 3, 0, 0, 0, 0, time.UTC)
	c0 := day.Add(10*time.Hour + 30*time.Minute)
	run := func(withInvalidity bool, poe2 time.Time) Report {
		w := newWorld(t)
		x1 := w.tsa
		x2, err := x1.Reissue(77, w.now.Add(240*time.Hour))
		if err != nil {
			t.Fatal(err)
		}
		x2.Now = func() time.Time { return w.now }
		other, tr := otherTSA(t, w)
		w.wlink(auditchain.Leaf{Type: auditchain.EventStart})
		h1, t1 := w.stamp()
		w.now = w.now.Add(time.Second)
		w.wlink(tokenLeaf(h1, t1))
		e1 := sealedBytes(t, 1, w.now.Add(time.Second), "first")
		e2 := sealedBytes(t, 2, w.now.Add(2*time.Second), "second")
		w.now = w.now.Add(3 * time.Second)
		w.wlink(evLeaf(t, e1, 1), evLeaf(t, e2, 2))
		w.wlink(auditchain.Leaf{Type: auditchain.EventGap, Scope: "abs-core"})
		w.now = w.now.Add(time.Second)
		w.tsa = x2
		h4, t2 := w.stamp()
		w.wlink(tokenLeaf(h4, t2))
		w.tsa = x1
		b := w.bundle(e2, 3, 1, h4, t2, 2)
		b.Upper.Inclusion = ptr(w.inclusion(5, 0))
		rev1 := x509.RevocationListEntry{SerialNumber: x1.Cert().SerialNumber, RevocationTime: c0, ReasonCode: tsa.ReasonKeyCompromise}
		if withInvalidity {
			inv, _ := asn1.MarshalWithParams(c0, "generalized")
			rev1.RevocationTime = c0.Add(time.Hour)
			rev1.ExtraExtensions = []pkix.Extension{{Id: asn1.ObjectIdentifier{2, 5, 29, 24}, Value: inv}}
		}
		tr.TSARevocations = checkedToo(t, revocations(t, x1, w.now.Add(48*time.Hour), rev1,
			x509.RevocationListEntry{SerialNumber: x2.Cert().SerialNumber, RevocationTime: day.Add(12 * time.Hour), ReasonCode: tsa.ReasonKeyCompromise}), other)
		b.Archive = []ArchiveStamp{archiveOver(t, w, other, 2, day.Add(10*time.Hour+10*time.Minute)), archiveOver(t, w, other, 5, poe2)}
		return Verify(b, tr)
	}
	for _, inv := range []bool{false, true} {
		r := run(inv, day.Add(11*time.Hour))
		if c := revocationCheck(t, r.Checks); r.Valid() || !strings.Contains(c.Detail, "time-stamp T2 over head 4 rests on certificate") || !strings.Contains(c.Detail, "before 2026-10-03 10:30:00 UTC") {
			t.Fatalf("invalidityDate %v: T2 спасла POE после отсечки ключа:\n%s", inv, r.Text())
		}
		if r := run(inv, day.Add(10*time.Hour+20*time.Minute)); !r.Valid() {
			t.Fatalf("invalidityDate %v: POE раньше отсечки ключа:\n%s", inv, r.Text())
		}
	}
}

// Подозрение на ключ — из любой цепочки любой метки, не только выбранной:
// ключ kQ верхнего центра под двумя сертификатами, «Upper B» (отозван по
// компрометации) и «Upper C». У T1 и T2 две цепочки, лучшая — мимо kQ; метка
// второй службы — только через «Upper C», то есть через kQ: она не POE.
func TestRevocationSuspectKeyInAnyChain(t *testing.T) {
	type ca struct {
		cert *x509.Certificate
		key  crypto.Signer
	}
	key := func() crypto.Signer {
		k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		return k
	}
	issue := func(serial int64, cn string, isCA bool, k crypto.Signer, parent *ca) *ca {
		tmpl := &x509.Certificate{SerialNumber: big.NewInt(serial), Subject: pkix.Name{CommonName: cn},
			NotBefore: time.Date(2020, 1, 1, 0, 0, 0, 0, time.UTC), NotAfter: time.Date(2040, 1, 1, 0, 0, 0, 0, time.UTC)}
		if isCA {
			tmpl.KeyUsage, tmpl.BasicConstraintsValid, tmpl.IsCA = x509.KeyUsageCertSign|x509.KeyUsageCRLSign, true, true
		} else {
			tmpl.KeyUsage, tmpl.ExtKeyUsage = x509.KeyUsageDigitalSignature, []x509.ExtKeyUsage{x509.ExtKeyUsageTimeStamping}
		}
		pc, pk := tmpl, k
		if parent != nil {
			pc, pk = parent.cert, parent.key
		}
		der, err := x509.CreateCertificate(rand.Reader, tmpl, pc, k.Public(), pk)
		if err != nil {
			t.Fatal(err)
		}
		c, _ := x509.ParseCertificate(der)
		return &ca{c, k}
	}
	rootA, rootB, rootC := issue(1, "root A", true, key(), nil), issue(1, "root B", true, key(), nil), issue(1, "root C", true, key(), nil)
	kQ, kK := key(), key()
	upB, upC := issue(20, "Upper B", true, kQ, rootB), issue(21, "Upper C", true, kQ, rootC)
	caA, caB := issue(30, "TSA CA", true, kK, rootA), issue(31, "TSA CA", true, kK, upB)
	mainLeaf := issue(77, "main TSA", false, key(), caA)
	caS := issue(40, "Second CA", true, key(), upC)
	secLeaf := issue(88, "second TSA", false, key(), caS)

	w := newWorld(t)
	w.tsa = tsa.AuthorityWith(mainLeaf.key, mainLeaf.cert, rootA.cert)
	w.tsa.Now = func() time.Time { return w.now }
	second := tsa.AuthorityWith(secLeaf.key, secLeaf.cert, rootC.cert)
	w.wlink(auditchain.Leaf{Type: auditchain.EventStart})
	h1, t1 := w.stamp()
	w.now = w.now.Add(time.Second)
	w.wlink(tokenLeaf(h1, t1))
	e2 := sealedBytes(t, 2, w.now.Add(time.Second), "second")
	w.now = w.now.Add(3 * time.Second)
	w.wlink(evLeaf(t, e2, 1))
	w.now = w.now.Add(time.Second)
	h3, t2 := w.stamp()
	w.wlink(tokenLeaf(h3, t2))
	b := w.bundle(e2, 3, 0, h3, t2, 2)
	b.Upper.Inclusion = ptr(w.inclusion(4, 0))

	pool := x509.NewCertPool()
	for _, c := range []*ca{rootA, rootB, rootC} {
		pool.AddCert(c.cert)
	}
	tr := Trust{StoreKey: w.signer.PublicKey(), TSA: tsa.Trust{Roots: pool, Intermediates: []*x509.Certificate{caA.cert, caB.cert, upB.cert, upC.cert, caS.cert}}}
	day := time.Date(2026, 10, 3, 0, 0, 0, 0, time.UTC)
	revs := tsa.NewRevocations(day.Add(48 * time.Hour))
	addCRL := func(c *ca, entries ...x509.RevocationListEntry) {
		der, err := x509.CreateRevocationList(rand.Reader, &x509.RevocationList{Number: big.NewInt(1), ThisUpdate: day.Add(47 * time.Hour), NextUpdate: day.Add(72 * time.Hour), RevokedCertificateEntries: entries}, c.cert, c.key)
		if err != nil {
			t.Fatal(err)
		}
		p := filepath.Join(t.TempDir(), "ca.crl")
		os.WriteFile(p, der, 0o600)
		if err := revs.AddCRL(p); err != nil {
			t.Fatal(err)
		}
	}
	addCRL(rootB, x509.RevocationListEntry{SerialNumber: upB.cert.SerialNumber, RevocationTime: day.Add(9 * time.Hour), ReasonCode: tsa.ReasonKeyCompromise})
	addCRL(caA, x509.RevocationListEntry{SerialNumber: mainLeaf.cert.SerialNumber, RevocationTime: day.Add(12 * time.Hour), ReasonCode: tsa.ReasonKeyCompromise})
	tr.TSARevocations = revs
	b.Archive = []ArchiveStamp{archiveOver(t, w, second, 4, day.Add(11*time.Hour))}
	if r := Verify(b, tr); r.Valid() || !strings.Contains(r.Text(), "itself: not used") {
		t.Fatalf("POE через ключ, отозванный в невыбранной цепочке:\n%s", r.Text())
	}
}

// Часы свидетеля позади основной службы больше чем на минуту: подпись над
// головой звена T2 датирована раньше T2 и считается со времени T2 — POE в
// силе, отчёт говорит об отставании.
func TestRevocationWitnessClockBehind(t *testing.T) {
	w, b := standard(t, nil)
	b.Upper.Inclusion = ptr(w.inclusion(5, 0))
	t2 := Verify(b, w.trust()).Upper
	s := cosigner(t, "witness.example/w1")
	tr := cosignTrust(w, s)
	tr.TSARevocations = compromised(t, w.tsa, t2.Add(2*time.Hour), w.now.Add(48*time.Hour))
	b.Cosignatures = []Cosignature{w.cosigned(s, 5, w.root(5), t2.Add(-90*time.Second))}
	if r := Verify(b, tr); !r.Valid() || !strings.Contains(revocationCheck(t, r.Checks).Detail, "dated 1m30s before the time-stamp: its clock is behind") {
		t.Fatalf("свидетель отстаёт на полторы минуты:\n%s", r.Text())
	}
}
