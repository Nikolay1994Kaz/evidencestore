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

// ⭐ Свидетель получает головы под метками TSA и за их токенами, и текущую.
// Пакет, сверенный с его головами, проходит, и улику закрепляет голова под
// T2 — ею пакет и кончается.
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
	if n := len(tr.Witness.Heads); n != 4 {
		t.Fatalf("у свидетеля %d голов, ожидали 4: под T1 и за её токеном, под T2 и за её токеном (она же текущая)", n)
	}
	if r := proof.Verify(b, tr); !r.Valid() || b.Upper == nil || r.WitnessHead != b.Upper.HeadSeq {
		t.Fatalf("пакет со свидетелем:\n%s", r.Text())
	}
}

// Свидетель недоступен: головы под метками (и за их токенами) ждут в
// очереди все, текущая — одна, последней. Свидетель вернулся — уходят все.
func TestWitnessQueueWhileUnreachable(t *testing.T) {
	c := newClock()
	wdir := t.TempDir()
	s := openStore(t, testConfig(t, withWitness(wdir)), c)
	alive := s.witnessRemote
	s.witnessRemote = deadRemote{}
	for q := uint64(1); q <= 3; q++ {
		ingest(t, s, "abs-core", 2*q-1, 2*q-1)
		mustStamp(t, s)
		ingest(t, s, "abs-core", 2*q, 2*q) // новая текущая голова
		if err := s.flush(); err != nil {
			t.Fatal(err)
		}
		if err := s.WitnessOnce(context.Background()); err == nil {
			t.Fatal("голова ушла недоступному свидетелю")
		}
	}
	q := s.witnessQueue
	stamped := 0
	for _, h := range q {
		if h.stamped {
			stamped++
		}
	}
	if len(q) != 7 || stamped != 6 || q[6].stamped {
		t.Fatalf("очередь к свидетелю: %+v", q)
	}
	s.witnessRemote = alive
	if err := s.WitnessOnce(context.Background()); err != nil {
		t.Fatal(err)
	}
	if n := len(witnessHeads(t, wdir).Heads); n != 7 || len(s.witnessQueue) != 0 {
		t.Fatalf("у свидетеля %d голов, в очереди %d", n, len(s.witnessQueue))
	}
}

// Голова встала в очередь текущей, пока свидетель недоступен, а потом над
// ней поставили метку: она остаётся в очереди головой под меткой, не
// уступает места следующей текущей и доходит до свидетеля — ею кончается
// пакет.
func TestWitnessKeepsStampedHeadQueuedAsCurrent(t *testing.T) {
	c := newClock()
	wdir := t.TempDir()
	s := openStore(t, testConfig(t, withWitness(wdir)), c)
	alive := s.witnessRemote
	s.witnessRemote = deadRemote{}
	ingest(t, s, "abs-core", 1, 1)
	if err := s.flush(); err != nil {
		t.Fatal(err)
	}
	if err := s.WitnessOnce(context.Background()); err == nil { // голова — в очереди текущей
		t.Fatal("голова ушла недоступному свидетелю")
	}
	mustStamp(t, s)                                             // метка над той же головой
	if err := s.WitnessOnce(context.Background()); err == nil { // следующая текущая
		t.Fatal("голова ушла недоступному свидетелю")
	}
	s.witnessRemote = alive
	if err := s.WitnessOnce(context.Background()); err != nil {
		t.Fatal(err)
	}
	b, err := s.Proof("abs-core", 1, false)
	if err != nil {
		t.Fatal(err)
	}
	tr := trustOf(t, s)
	tr.Witness = witnessHeads(t, wdir)
	if r := proof.Verify(b, tr); !r.Valid() || b.Upper == nil || r.WitnessHead != b.Upper.HeadSeq {
		t.Fatalf("пакет со свидетелем после его простоя:\n%s", r.Text())
	}
}

// ⭐ P-11: свидетель не обгоняет копию наружу. Пока копия отстаёт, головы
// после неё ждут; диск умер, хранилище поднято из копии — и цепь после
// подъёма со свидетелем не расходится: улики до подъёма и после проходят
// сверку, развилки нет. Раньше свидетель видел головы потерянного хвоста, и
// под теми же номерами поднятое хранилище писало другое.
func TestWitnessNeverAheadOfCopy(t *testing.T) {
	c := newClock()
	ctx := context.Background()
	remoteDir, wdir := t.TempDir(), t.TempDir()
	cfg := testConfig(t, withWitness(wdir), func(c *config.Config) {
		c.Replica.URL = "file://" + remoteDir
		c.Keys.BackupDir = t.TempDir()
	})
	s := openStore(t, cfg, c)
	remote, err := ship.OpenRemote(cfg.Replica.URL)
	if err != nil {
		t.Fatal(err)
	}
	ingest(t, s, "abs-core", 1, 3)
	mustStamp(t, s)
	if err := s.WitnessOnce(ctx); err != nil {
		t.Fatal(err)
	}
	if n := len(witnessHeads(t, wdir).Heads); n != 0 {
		t.Fatalf("свидетель получил %d голов раньше копии", n)
	}
	if _, err := s.ShipOnce(ctx, remote); err != nil {
		t.Fatal(err)
	}
	if err := s.WitnessOnce(ctx); err != nil {
		t.Fatal(err)
	}
	copied := len(witnessHeads(t, wdir).Heads)
	if copied == 0 {
		t.Fatal("копия прошла, а свидетелю ничего не ушло")
	}

	// Копия отстаёт: новые улики и метка свидетелю не уходят.
	c.add(time.Minute)
	ingest(t, s, "abs-core", 4, 6)
	mustStamp(t, s)
	if err := s.WitnessOnce(ctx); err != nil {
		t.Fatal(err)
	}
	if n := len(witnessHeads(t, wdir).Heads); n != copied {
		t.Fatalf("свидетель обогнал копию: голов %d, после копии было %d", n, copied)
	}
	pub := s.PublicKey()
	s.Close()

	// Диск умер: подъём из копии, улики 4–6 потеряны вместе с хвостом цепи.
	s2 := openStore(t, restoreFromCopy(t, cfg, remote, pub), c)
	c.add(time.Minute)
	ingest(t, s2, "abs-core", 4, 5)
	mustStamp(t, s2)
	if err := s2.WitnessOnce(ctx); err != nil {
		t.Fatal(err)
	}
	tr := trustOf(t, s2)
	tr.Witness = witnessHeads(t, wdir)
	for _, seq := range []uint64{2, 5} {
		b, err := s2.Proof("abs-core", seq, false)
		if err != nil {
			t.Fatal(err)
		}
		if r := proof.Verify(b, tr); !r.Valid() || r.WitnessHead == 0 || r.WitnessFork != 0 {
			t.Fatalf("улика %d после подъёма из копии:\n%s", seq, r.Text())
		}
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

// Q-06: голова под меткой TSA не доходит до свидетеля, если проход
// свидетеля (раз в witness.every) пришёлся на время запроса к TSA, а за это
// время цепь выросла (тик свернул пришедшие записи в звено). Текущая голова
// h' > h встаёт в очередь раньше, и queueWitnessLocked(h, true) выходит по
// h.Seq <= witnessQueued — голова h, которой кончаются пакеты, не уходит
// никогда (остаток P-09).
func TestStampedHeadReachesWitnessDuringTSA(t *testing.T) {
	c := newClock()
	wdir := t.TempDir()
	s := openStore(t, testConfig(t, withWitness(wdir)), c)
	ingest(t, s, "abs-core", 1, 3)
	mustStamp(t, s) // T1
	if err := s.WitnessOnce(context.Background()); err != nil {
		t.Fatal(err)
	}
	c.add(time.Minute)
	ingest(t, s, "abs-core", 4, 6)
	c.add(time.Minute)

	// Пока TSA отвечает: пришла запись, тик свернул её в звено, и сработал
	// проход свидетеля (фоновые циклы так и работают, chainMu свободен).
	orig := s.tsaLocal.Now
	done := false
	s.tsaLocal.Now = func() time.Time {
		if !done {
			done = true
			ingest(t, s, "abs-core", 7, 7)
			if err := s.flush(); err != nil {
				t.Fatal(err)
			}
			if err := s.WitnessOnce(context.Background()); err != nil {
				t.Fatal(err)
			}
		}
		if orig != nil {
			return orig()
		}
		return c.now()
	}
	h, err := s.Stamp(context.Background()) // T2 над головой h
	if err != nil {
		t.Fatal(err)
	}
	s.tsaLocal.Now = orig
	for i := 0; i < 3; i++ { // следующие проходы свидетеля
		if err := s.WitnessOnce(context.Background()); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := os.Stat(filepath.Join(wdir, "heads", fmtHead(h))); err != nil {
		t.Errorf("голова %d под меткой T2 у свидетеля отсутствует: %v", h, err)
	}

	b, err := s.Proof("abs-core", 5, false)
	if err != nil {
		t.Fatal(err)
	}
	tr := trustOf(t, s)
	tr.Witness = witnessHeads(t, wdir)
	r := proof.Verify(b, tr)
	t.Logf("пакет кончается головой %d (T2 над %d); у свидетеля голов %d", b.Statement.HeadSeq, b.Upper.HeadSeq, len(tr.Witness.Heads))
	if !r.Valid() {
		t.Errorf("пакет одной улики не проходит -heads, хотя хранилище честное:\n%s", r.Text())
	}
}

func fmtHead(h uint64) string {
	return filepathName(h)
}

func filepathName(h uint64) string {
	return fmtSeq(h) + ".json"
}

func fmtSeq(h uint64) string {
	s := "00000000000000000000"
	d := []byte(s)
	for i := len(d) - 1; h > 0 && i >= 0; i-- {
		d[i] = byte('0' + h%10)
		h /= 10
	}
	return string(d)
}
