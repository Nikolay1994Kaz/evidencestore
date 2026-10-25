package store

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/Nikolay1994Kaz/evidencestore/internal/auditchain"
	"github.com/Nikolay1994Kaz/evidencestore/internal/config"
	"github.com/Nikolay1994Kaz/evidencestore/internal/proof"
	"github.com/Nikolay1994Kaz/evidencestore/internal/ship"
)

func withWitness(dir string) func(*config.Config) {
	return func(c *config.Config) { c.Witness.URL = "file://" + dir }
}

// witnessHeads — все головы, лёгшие к свидетелю в каталог dir.
func witnessHeads(t *testing.T, dir string) *proof.Witness {
	t.Helper()
	paths, err := filepath.Glob(filepath.Join(dir, "heads", "*.json"))
	if err != nil {
		t.Fatal(err)
	}
	w := &proof.Witness{}
	for _, p := range paths {
		data, err := os.ReadFile(p)
		if err != nil {
			t.Fatal(err)
		}
		st, err := auditchain.ParseStatement(data)
		if err != nil {
			t.Fatal(err)
		}
		w.Heads = append(w.Heads, proof.PublishedHead{Name: filepath.Base(p), Statement: st})
	}
	return w
}

// deadRemote — свидетель, который не отвечает.
type deadRemote struct{ ship.Remote }

func (deadRemote) Put(context.Context, string, []byte) error { return errors.New("witness is down") }

// ⭐ Свидетель получает головы под метками TSA и текущую. Пакет, сверенный с
// его головами, проходит, и улику закрепляет голова под T2 — ею пакет и
// кончается.
func TestWitnessGetsStampedHeads(t *testing.T) {
	c := newClock()
	wdir := t.TempDir()
	s := openStore(t, testConfig(t, withWitness(wdir)), c)
	ingest(t, s, "abs-core", 1, 3)
	mustStamp(t, s) // T1
	c.add(time.Minute)
	ingest(t, s, "abs-core", 4, 6)
	c.add(time.Minute)
	mustStamp(t, s) // T2
	if err := s.WitnessOnce(context.Background()); err != nil {
		t.Fatal(err)
	}
	b, err := s.Proof("abs-core", 5, false)
	if err != nil {
		t.Fatal(err)
	}
	tr := trustOf(t, s)
	tr.Witness = witnessHeads(t, wdir)
	if n := len(tr.Witness.Heads); n != 3 {
		t.Fatalf("у свидетеля %d голов, ожидали 3: под T1, под T2 и текущая", n)
	}
	if r := proof.Verify(b, tr); !r.Valid() || b.Upper == nil || r.WitnessHead != b.Upper.HeadSeq {
		t.Fatalf("пакет со свидетелем:\n%s", r.Text())
	}
}

// Свидетель недоступен: головы под метками ждут в очереди все, текущая —
// одна, последней. Свидетель вернулся — уходят все.
func TestWitnessQueueWhileUnreachable(t *testing.T) {
	c := newClock()
	wdir := t.TempDir()
	s := openStore(t, testConfig(t, withWitness(wdir)), c)
	alive := s.witnessRemote
	s.witnessRemote = deadRemote{}
	for q := uint64(1); q <= 3; q++ {
		ingest(t, s, "abs-core", q, q)
		mustStamp(t, s)
		if err := s.WitnessOnce(context.Background()); err == nil {
			t.Fatal("голова ушла недоступному свидетелю")
		}
	}
	q := s.witnessQueue
	if len(q) != 4 || q[3].stamped || !q[0].stamped || !q[1].stamped || !q[2].stamped {
		t.Fatalf("очередь к свидетелю: %+v", q)
	}
	s.witnessRemote = alive
	if err := s.WitnessOnce(context.Background()); err != nil {
		t.Fatal(err)
	}
	if n := len(witnessHeads(t, wdir).Heads); n != 4 || len(s.witnessQueue) != 0 {
		t.Fatalf("у свидетеля %d голов, в очереди %d", n, len(s.witnessQueue))
	}
}

// Пакет до головы свидетеля доходит до неё, а до головы, которой ещё нет в
// цепи, пакет не выдаётся.
func TestProofToWitnessHead(t *testing.T) {
	c := newClock()
	s := openStore(t, testConfig(t), c)
	ingest(t, s, "abs-core", 1, 3)
	mustStamp(t, s)
	c.add(time.Minute)
	ingest(t, s, "abs-core", 4, 6)
	c.add(time.Minute)
	mustStamp(t, s)
	for q := uint64(7); q <= 9; q++ {
		ingest(t, s, "abs-core", q, q)
		if err := s.flush(); err != nil {
			t.Fatal(err)
		}
	}
	head := s.chain.Head().Seq
	b, err := s.ProofTo("abs-core", 5, false, head)
	if err != nil {
		t.Fatal(err)
	}
	if last := b.Links[len(b.Links)-1].Seq; last != head || b.Statement.HeadSeq != head {
		t.Fatalf("пакет до головы %d кончается звеном %d, заявление о голове %d", head, last, b.Statement.HeadSeq)
	}
	if r := proof.Verify(b, trustOf(t, s)); !r.Valid() {
		t.Fatalf("пакет до головы свидетеля:\n%s", r.Text())
	}
	if _, err := s.ProofTo("abs-core", 5, false, head+1); err == nil {
		t.Fatal("выдан пакет до головы, которой нет в цепи")
	}
}
