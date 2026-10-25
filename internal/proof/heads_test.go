package proof

import (
	"strings"
	"testing"

	"github.com/Nikolay1994Kaz/evidencestore/internal/auditchain"
)

// Головы свидетеля над синтетической цепью из proof_test.go: звенья 1–5,
// улика в звене 3, T2 над головой 4.

func (w *world) published(name string, seq uint64, hash [32]byte) PublishedHead {
	return PublishedHead{Name: name, Statement: w.signer.Sign(auditchain.Head{Seq: seq, Hash: hash}, int(seq), w.now.Unix())}
}

func (w *world) linkHash(seq uint64) [32]byte { return auditchain.Hash(w.links[seq-1]) }

func failed(r Report, name string) bool {
	for _, c := range r.Checks {
		if c.Name == name && !c.OK {
			return true
		}
	}
	return false
}

const (
	checkOneVersion = "the witness holds one version of the chain (no two different heads with one number)"
	checkAgrees     = "the chain in the bundle agrees with the heads the witness saw"
)

// ⭐ Свидетель видел голову 4 той же цепи: она закрепляет улику из звена 3.
// Голова 2 раньше улики сверяется со звеном пакета, но улику не закрепляет.
func TestWitnessHeadFixesRecord(t *testing.T) {
	w, b := standard(t, nil)
	tr := w.trust()
	tr.Witness = &Witness{Heads: []PublishedHead{
		w.published("heads/2.json", 2, w.linkHash(2)),
		w.published("heads/4.json", 4, w.linkHash(4)),
	}}
	r := Verify(b, tr)
	if !r.Valid() || r.WitnessHead != 4 || !strings.Contains(strings.Join(r.Notes(), "\n"), "the witness saw head 4") {
		t.Fatalf("пакет со свидетелем:\n%s", r.Text())
	}
}

// Голова свидетеля с номером звена из пакета, но с другим хэшем: пакет —
// из другой версии цепи.
func TestWitnessHeadOfAnotherChain(t *testing.T) {
	w, b := standard(t, nil)
	tr := w.trust()
	tr.Witness = &Witness{Heads: []PublishedHead{w.published("heads/4.json", 4, w.linkHash(3))}}
	if r := Verify(b, tr); r.Valid() || !failed(r, checkAgrees) {
		t.Fatalf("голова свидетеля из другой цепи:\n%s", r.Text())
	}
}

// Две разные головы с одним номером у свидетеля — развилка, даже когда
// голова, закрепляющая улику, с пакетом сходится.
func TestWitnessSeesFork(t *testing.T) {
	w, b := standard(t, nil)
	tr := w.trust()
	tr.Witness = &Witness{Heads: []PublishedHead{
		w.published("heads/4.json", 4, w.linkHash(4)),
		w.published("heads/7.json", 7, w.linkHash(1)),
		w.published("heads/7.json.v2", 7, w.linkHash(2)),
	}}
	if r := Verify(b, tr); r.Valid() || !failed(r, checkOneVersion) {
		t.Fatalf("развилка у свидетеля:\n%s", r.Text())
	}
}

// Свидетель видел только голову дальше конца пакета: пакет не проходит, и
// отчёт говорит, какой пакет просить.
func TestWitnessHeadBeyondBundle(t *testing.T) {
	w, b := standard(t, nil)
	tr := w.trust()
	tr.Witness = &Witness{Heads: []PublishedHead{w.published("heads/9.json", 9, w.linkHash(1))}}
	if r := Verify(b, tr); r.Valid() || !failed(r, checkAgrees) || !strings.Contains(r.Text(), "proof -to-head 9") {
		t.Fatalf("голова свидетеля дальше пакета:\n%s", r.Text())
	}
}

// У свидетеля ещё нет головы не раньше звена улики, а голова под чужим
// ключом и посторонний файл не в счёт: пакет проходит, а отчёт говорит, что
// свидетель запись ещё не закрепил.
func TestWitnessHasNothingYet(t *testing.T) {
	w, b := standard(t, nil)
	other := newWorld(t)
	tr := w.trust()
	tr.Witness = &Witness{Heads: []PublishedHead{
		w.published("heads/2.json", 2, w.linkHash(2)),
		other.published("heads/4.json", 4, w.linkHash(3)),
		{Name: "README"},
	}}
	r := Verify(b, tr)
	if !r.Valid() || r.WitnessHead != 0 || !strings.Contains(strings.Join(r.Notes(), "\n"), "the witness has no head at or after this record yet") {
		t.Fatalf("свидетель без головы после улики:\n%s", r.Text())
	}
}
