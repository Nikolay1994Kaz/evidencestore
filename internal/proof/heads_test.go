package proof

import (
	"encoding/json"
	"fmt"
	"strings"
	"testing"

	"golang.org/x/mod/sumdb/tlog"

	"github.com/Nikolay1994Kaz/evidencestore/internal/auditchain"
)

// Головы свидетеля над синтетической цепью из proof_test.go: звенья 1–5,
// улика в звене 3, T2 над головой 4.

func (w *world) published(name string, seq uint64, root [32]byte) PublishedHead {
	return PublishedHead{Name: name, Checkpoint: SignCheckpoint(w.signer, seq, root)}
}

func failed(r Report, name string) bool {
	for _, c := range r.Checks {
		if c.Name == name && !c.OK {
			return true
		}
	}
	return false
}

const checkAgrees = "the chain in the bundle agrees with the heads the witness saw"

// ⭐ Свидетель видел голову 4 той же цепи: она закрепляет улику из звена 3.
// Голова 2 раньше улики сверяется со звеном пакета, но улику не закрепляет.
func TestWitnessHeadFixesRecord(t *testing.T) {
	w, b := standard(t, nil)
	tr := w.trust()
	tr.Witness = &Witness{Heads: []PublishedHead{
		w.published("heads/2.json", 2, w.root(2)),
		w.published("heads/4.json", 4, w.root(4)),
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
	tr.Witness = &Witness{Heads: []PublishedHead{w.published("heads/4.json", 4, w.root(3))}}
	if r := Verify(b, tr); r.Valid() || !failed(r, checkAgrees) {
		t.Fatalf("голова свидетеля из другой цепи:\n%s", r.Text())
	}
}

// Две разные головы с одним номером вне участка цепи этой записи: хранилище
// подписало вторую историю, но запись она не задевает — пакет проходит, а
// отчёт называет развилку (P-11).
func TestWitnessForkOutsideRecordIsNote(t *testing.T) {
	w, b := standard(t, nil)
	tr := w.trust()
	tr.Witness = &Witness{Heads: []PublishedHead{
		w.published("heads/4.json", 4, w.root(4)),
		w.published("heads/7.json", 7, w.root(1)),
		w.published("heads/7.json.v2", 7, w.root(2)),
	}}
	r := Verify(b, tr)
	if !r.Valid() || r.WitnessHead != 4 || r.WitnessFork != 7 || !strings.Contains(strings.Join(r.Notes(), "\n"), "two versions of the chain") {
		t.Fatalf("развилка вне участка записи:\n%s", r.Text())
	}
}

// Две разные головы с одним номером на участке цепи этой записи — провал,
// даже когда одна из них с пакетом сходится.
func TestWitnessForkInRecordPartFails(t *testing.T) {
	w, b := standard(t, nil)
	tr := w.trust()
	tr.Witness = &Witness{Heads: []PublishedHead{
		w.published("heads/4.json", 4, w.root(4)),
		w.published("heads/4.json.v2", 4, w.root(3)),
	}}
	if r := Verify(b, tr); r.Valid() || !failed(r, checkAgrees) || !strings.Contains(r.Text(), "two different heads number 4") {
		t.Fatalf("развилка на участке записи:\n%s", r.Text())
	}
}

// Свидетель видел только голову дальше конца пакета: пакет не проходит, и
// отчёт говорит, какой пакет просить.
func TestWitnessHeadBeyondBundle(t *testing.T) {
	w, b := standard(t, nil)
	tr := w.trust()
	tr.Witness = &Witness{Heads: []PublishedHead{w.published("heads/9.json", 9, w.root(1))}}
	r := Verify(b, tr)
	if r.Valid() || !failed(r, checkAgrees) || !strings.Contains(r.Text(), "proof -to-head 9") {
		t.Fatalf("голова свидетеля дальше пакета:\n%s", r.Text())
	}
	// Голова у свидетеля есть, просто пакет до неё не доходит: отчёт не
	// говорит, что её нет.
	if strings.Contains(strings.Join(r.Notes(), "\n"), "has no head") {
		t.Fatalf("замечание «головы ещё нет» при голове дальше пакета:\n%s", r.Text())
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
		w.published("heads/2.json", 2, w.root(2)),
		other.published("heads/4.json", 4, w.root(3)),
		{Name: "README"},
	}}
	r := Verify(b, tr)
	if !r.Valid() || r.WitnessHead != 0 || !strings.Contains(strings.Join(r.Notes(), "\n"), "the witness has no head at or after this record yet") {
		t.Fatalf("свидетель без головы после улики:\n%s", r.Text())
	}
}

// Головы из файлов свидетелей: одна точка (свидетель, копия, statement),
// последняя голова сборщика, его журнал голов и расхождения — по две
// головы в строке. Посторонний и пустой файлы — по одной пустой голове.
func TestParseHeads(t *testing.T) {
	w, _ := standard(t, nil)
	a, b := SignCheckpoint(w.signer, 2, w.root(2)), SignCheckpoint(w.signer, 4, w.root(4))
	js := func(v any) string {
		data, err := json.Marshal(v)
		if err != nil {
			t.Fatal(err)
		}
		return string(data)
	}
	aj, _ := a.JSON()
	for _, tc := range []struct {
		name, data string
		sizes      []uint64 // 0 — пустая голова
	}{
		{"heads/2.json", string(aj), []uint64{2}},
		{"checkpoint.json", js(map[string]any{"received_at": w.now, "checkpoint": b}), []uint64{4}},
		{"checkpoints.jsonl", js(map[string]any{"checkpoint": a}) + "\n" + js(map[string]any{"checkpoint": b}) + "\n", []uint64{2, 4}},
		{"checkpoints-conflict.jsonl", js(map[string]any{"reason": "x", "previous": b, "checkpoint": a}) + "\n", []uint64{4, 2}},
		{"README", "not a head", []uint64{0}},
		{"empty", "", []uint64{0}},
		{"мусор после головы", string(aj) + "\nnot json", []uint64{2, 0}},
		{"чужой JSON", `{"some": "thing"}`, []uint64{0}},
	} {
		heads := ParseHeads(tc.name, []byte(tc.data))
		var got []uint64
		for _, h := range heads {
			got = append(got, h.Checkpoint.Size)
			if h.Checkpoint.Size != 0 && VerifyCheckpoint(h.Checkpoint, w.signer.PublicKey()) != nil {
				t.Fatalf("%s: голова %s не проверяется", tc.name, h.Name)
			}
		}
		if fmt.Sprint(got) != fmt.Sprint(tc.sizes) {
			t.Fatalf("%s: головы %v, ждали %v", tc.name, got, tc.sizes)
		}
	}
	if heads := ParseHeads("checkpoints.jsonl", []byte(js(map[string]any{"checkpoint": a})+"\n"+js(map[string]any{"checkpoint": b}))); heads[1].Name != "checkpoints.jsonl:2" {
		t.Fatalf("имя головы из второй строки: %q", heads[1].Name)
	}
}

// Доказательство продолжения: верное сходится, с подменённым хешем, чужой
// старой головой или хешем не той длины — нет.
func TestCheckExtends(t *testing.T) {
	w, _ := standard(t, nil)
	var stored memHashes
	for i, l := range w.links {
		hs, err := tlog.StoredHashesForRecordHash(int64(i), LinkLeaf(auditchain.Hash(l)), stored)
		if err != nil {
			t.Fatal(err)
		}
		stored = append(stored, hs...)
	}
	n := uint64(len(w.links))
	for m := uint64(1); m < n; m++ {
		p, err := tlog.ProveTree(int64(n), int64(m), stored)
		if err != nil {
			t.Fatal(err)
		}
		var consistency [][]byte
		for _, h := range p {
			consistency = append(consistency, append([]byte(nil), h[:]...))
		}
		newer, older := w.checkpoint(n), w.checkpoint(m)
		if err := CheckExtends(newer, older, consistency); err != nil {
			t.Fatalf("%d → %d: %v", m, n, err)
		}
		if CheckExtends(newer, SignCheckpoint(w.signer, m, w.root(m-1)), consistency) == nil && m > 1 {
			t.Fatalf("%d → %d: чужая старая голова", m, n)
		}
		if len(consistency) > 0 {
			consistency[0][0] ^= 1
			if CheckExtends(newer, older, consistency) == nil {
				t.Fatalf("%d → %d: подменённый хеш", m, n)
			}
			consistency[0] = consistency[0][:31]
			if CheckExtends(newer, older, consistency) == nil {
				t.Fatalf("%d → %d: хеш не той длины", m, n)
			}
		}
	}
}
