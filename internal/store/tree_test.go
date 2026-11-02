package store

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/mod/sumdb/tlog"

	"github.com/Nikolay1994Kaz/evidencestore/internal/auditchain"
	"github.com/Nikolay1994Kaz/evidencestore/internal/proof"
)

// rootOf — корень дерева над первыми size звеньями цепи хранилища.
func rootOf(t *testing.T, s *Store, size uint64) [32]byte {
	t.Helper()
	links, err := auditchain.ReadLinks(s.chainDir, 1, size)
	if err != nil {
		t.Fatal(err)
	}
	return proof.FrontierOfLinks(links).Root()
}

// rootAfter — корень дерева после границы frontier (перед звеном links[0])
// и звеньев links.
func rootAfter(t *testing.T, frontier [][]byte, links []auditchain.Record) [32]byte {
	t.Helper()
	nodes := make([][32]byte, len(frontier))
	for i, n := range frontier {
		nodes[i] = [32]byte(n)
	}
	f, err := proof.NewFrontier(links[0].Seq-1, nodes)
	if err != nil {
		t.Fatal(err)
	}
	for _, l := range links {
		f.Push(proof.LinkLeaf(auditchain.Hash(l)))
	}
	return f.Root()
}

// headOver — голова из size звеньев над звеньями пакета links после границы
// frontier, подписанная ключом хранилища: так владелец ключа подписал бы
// переписанные звенья.
func headOver(t *testing.T, s *Store, frontier [][]byte, links []proof.Link, size uint64) proof.Checkpoint {
	t.Helper()
	var recs []auditchain.Record
	for _, l := range links[:size-links[0].Seq+1] {
		r := auditchain.Record{Seq: l.Seq, UnixNano: l.UnixNano, Type: auditchain.EventType(l.Type), Scope: l.Scope, Subject: l.Subject, Payload: l.Payload}
		copy(r.PrevHash[:], l.PrevHash)
		recs = append(recs, r)
	}
	return proof.SignCheckpoint(s.signer, size, rootAfter(t, frontier, recs))
}

// treeFile — файл хранимых хешей, каким его ждут для цепи хранилища: хеши
// по tlog.
func treeFile(t *testing.T, s *Store) []byte {
	t.Helper()
	links, err := auditchain.ReadChain(s.chainDir)
	if err != nil {
		t.Fatal(err)
	}
	var stored []tlog.Hash
	reader := tlog.HashReaderFunc(func(idx []int64) ([]tlog.Hash, error) {
		out := make([]tlog.Hash, len(idx))
		for i, x := range idx {
			out[i] = stored[x]
		}
		return out, nil
	})
	var out []byte
	for n, l := range links {
		hs, err := tlog.StoredHashesForRecordHash(int64(n), proof.LinkLeaf(auditchain.Hash(l)), reader)
		if err != nil {
			t.Fatal(err)
		}
		stored = append(stored, hs...)
		for _, h := range hs {
			out = append(out, h[:]...)
		}
	}
	return out
}

// Подписанная голова — число звеньев и корень дерева над ними, ключ
// хранилища; файл хранимых хешей — ровно хеши tlog над звеньями цепи.
func TestCheckpointOfChain(t *testing.T) {
	c := newClock()
	cfg := testConfig(t)
	s := openStore(t, cfg, c)
	for i := uint64(1); i <= 20; i++ {
		ingest(t, s, "abs-core", i, i)
		if err := s.flush(); err != nil {
			t.Fatal(err)
		}
	}
	head, err := s.Checkpoint()
	if err != nil {
		t.Fatal(err)
	}
	if err := proof.VerifyCheckpoint(head, trustOf(t, s).StoreKey); err != nil {
		t.Fatal(err)
	}
	if n := s.chain.Head().Seq; head.Size != n || head.RootHash() != rootOf(t, s, n) {
		t.Fatalf("голова %d, цепь %d: корень не над звеньями цепи", head.Size, n)
	}
	got, err := os.ReadFile(filepath.Join(cfg.DataDir, treeFileName))
	if err != nil {
		t.Fatal(err)
	}
	if want := treeFile(t, s); string(got) != string(want) {
		t.Fatalf("%s: %d байт, по tlog %d", treeFileName, len(got), len(want))
	}
}

// Файл хранимых хешей производный: испорченный в середине, обрезанный,
// длиннее цепи или пропавший, при запуске он собирается заново, и пакеты
// снова проходят. Пока хранилище работает, испорченный файл даёт отказ
// выдать пакет — не подпись под чужим корнем.
func TestTreeFileRebuilt(t *testing.T) {
	c := newClock()
	cfg := testConfig(t)
	s := openStore(t, cfg, c)
	for i := uint64(1); i <= 30; i++ {
		ingest(t, s, "abs-core", i, i)
		if err := s.flush(); err != nil {
			t.Fatal(err)
		}
		if i%10 == 0 {
			mustStamp(t, s)
		}
	}
	path := filepath.Join(cfg.DataDir, treeFileName)
	check := func(s *Store, what string) {
		t.Helper()
		got, err := os.ReadFile(path)
		if want := treeFile(t, s); err != nil || string(got) != string(want) {
			t.Fatalf("%s: файл не собран заново (%d байт, ждали %d): %v", what, len(got), len(want), err)
		}
		b, err := s.Proof("abs-core", 12, false)
		if err != nil {
			t.Fatalf("%s: %v", what, err)
		}
		if r := proof.Verify(b, trustOf(t, s)); !r.Valid() {
			t.Fatalf("%s:\n%s", what, r.Text())
		}
	}
	check(s, "как есть")

	// Испорчен хеш, по которому строится граница пакета записи 12: пока
	// хранилище работает, пакет не выдаётся.
	b, err := s.Proof("abs-core", 12, false)
	if err != nil {
		t.Fatal(err)
	}
	idx := proof.FrontierIndexes(b.Links[0].Seq - 1)
	if len(idx) == 0 {
		t.Fatal("раскладка теста поменялась: пакет с первого звена")
	}
	spoil := func(at int64) {
		f, err := os.OpenFile(path, os.O_RDWR, 0)
		if err != nil {
			t.Fatal(err)
		}
		defer f.Close()
		var h [1]byte
		if _, err := f.ReadAt(h[:], at); err != nil {
			t.Fatal(err)
		}
		h[0] ^= 1
		if _, err := f.WriteAt(h[:], at); err != nil {
			t.Fatal(err)
		}
	}
	spoil(idx[0] * 32)
	if _, err := s.Proof("abs-core", 12, false); !errors.Is(err, errTreeFile) {
		t.Fatalf("пакет по испорченному файлу: %v", err)
	}
	s.Close()
	s = openStore(t, cfg, c)
	check(s, "испорчен в середине")

	for what, change := range map[string]func(have []byte){
		"обрезан":          func(have []byte) { os.Truncate(path, int64(len(have)/2+5)) },
		"длиннее цепи":     func(have []byte) { os.WriteFile(path, append(have, make([]byte, 100)...), 0o600) },
		"пропал":           func([]byte) { os.Remove(path) },
		"испорчен в конце": func(have []byte) { spoil(int64(len(have) - 1)) },
	} {
		s.Close()
		have, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		change(have)
		s = openStore(t, cfg, c)
		check(s, what)
	}
}

// Пакет до прежней головы (-to-head) подписан корнем, взятым из файла и
// сверенным с границей в памяти, и проходит.
func TestCheckpointOfPastHead(t *testing.T) {
	c := newClock()
	cfg := testConfig(t)
	s := openStore(t, cfg, c)
	for i := uint64(1); i <= 12; i++ {
		ingest(t, s, "abs-core", i, i)
		if err := s.flush(); err != nil {
			t.Fatal(err)
		}
		if i == 4 {
			mustStamp(t, s)
		}
	}
	s.chainMu.Lock()
	n := s.tree.size()
	for m := uint64(1); m <= n; m++ {
		if err := s.tree.agreesLocked(m, rootOf(t, s, m)); err != nil {
			t.Fatalf("корень на размере %d: %v", m, err)
		}
		if m > 1 && s.tree.agreesLocked(m, rootOf(t, s, m-1)) == nil {
			t.Fatalf("на размере %d принят чужой корень", m)
		}
	}
	if s.tree.agreesLocked(n+1, rootOf(t, s, n)) == nil || s.tree.agreesLocked(0, [32]byte{}) == nil {
		t.Fatal("голова за пределами цепи")
	}
	s.chainMu.Unlock()

	b, err := s.ProofTo("abs-core", 2, false, 0)
	if err != nil {
		t.Fatal(err)
	}
	if b.Checkpoint.Size >= n {
		t.Fatalf("раскладка теста поменялась: пакет кончается головой %d из %d", b.Checkpoint.Size, n)
	}
	if r := proof.Verify(b, trustOf(t, s)); !r.Valid() {
		t.Fatal(r.Text())
	}
}

// Подъём из копии сверяет цепь с контрольной точкой: голова, положенная
// под чужим номером (настоящая, но меньшая), — отказ, а не тихий подъём до
// неё; с головой на своём месте копия поднимается, и поднятое хранилище
// собирает дерево по поднятой цепи.
func TestRestoreChecksCheckpoint(t *testing.T) {
	ctx := context.Background()
	c := newClock()
	cfg, remote := replicaConfig(t)
	s := openStore(t, cfg, c)
	for i := uint64(1); i <= 6; i++ {
		ingest(t, s, "abs-core", i, i)
		if err := s.flush(); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := s.ShipOnce(ctx, remote); err != nil {
		t.Fatal(err)
	}
	_, heads, err := listReplica(ctx, remote, "")
	if err != nil || len(heads) == 0 {
		t.Fatalf("головы в копии: %v, %v", heads, err)
	}
	n, _ := headSeqOf(heads[len(heads)-1])
	honest, err := remote.Get(ctx, heads[len(heads)-1])
	if err != nil {
		t.Fatal(err)
	}
	s.chainMu.Lock()
	smaller := proof.SignCheckpoint(s.signer, n-1, rootOf(t, s, n-1))
	s.chainMu.Unlock()
	s.Close()
	pub := trustOf(t, s).StoreKey
	key := copyKeyOf(t, cfg)

	data, _ := smaller.JSON()
	if err := remote.Put(ctx, heads[len(heads)-1], data); err != nil {
		t.Fatal(err)
	}
	if _, err := RestoreReplica(ctx, remote, filepath.Join(t.TempDir(), "data"), pub, key); err == nil || !strings.Contains(err.Error(), "holds a head of") {
		t.Fatalf("голова под чужим номером: %v", err)
	}
	if err := remote.Put(ctx, heads[len(heads)-1], honest); err != nil {
		t.Fatal(err)
	}
	s2, err := restoreCopy(t, cfg, s, remote, c)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s2.Close() })
	head, err := s2.Checkpoint()
	if err != nil || head.Size < n || head.RootHash() != rootOf(t, s2, head.Size) {
		t.Fatalf("поднятое хранилище: голова %d, %v", head.Size, err)
	}
	b, err := s2.Proof("abs-core", 3, false)
	if err != nil {
		t.Fatal(err)
	}
	if r := proof.Verify(b, trustOf(t, s2)); !r.Valid() && !strings.Contains(r.Text(), "no TSA time-stamp") {
		t.Fatal(r.Text())
	}
}

// Запись в tree.hashes отказала на ходу: пакеты не выдаются, а подпись
// текущей головы идёт по границе в памяти; перезапуск собирает файл заново.
func TestTreeFileWriteFails(t *testing.T) {
	c := newClock()
	cfg := testConfig(t)
	s := openStore(t, cfg, c)
	ingest(t, s, "abs-core", 1, 3)
	mustStamp(t, s)
	s.chainMu.Lock()
	s.tree.f.Close() // дальше запись в файл отказывает
	s.chainMu.Unlock()
	for i := uint64(4); i <= 6; i++ {
		ingest(t, s, "abs-core", i, i)
		if err := s.flush(); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := s.Proof("abs-core", 2, false); err == nil || !strings.Contains(err.Error(), "restart the store") {
		t.Fatalf("пакет при отказавшем файле: %v", err)
	}
	head, err := s.Checkpoint()
	if err != nil || head.RootHash() != rootOf(t, s, head.Size) || head.Size != s.chain.Head().Seq {
		t.Fatalf("голова при отказавшем файле: %d, %v", head.Size, err)
	}
	s.Close()
	s = openStore(t, cfg, c)
	mustStamp(t, s)
	b, err := s.Proof("abs-core", 5, false)
	if err != nil {
		t.Fatal(err)
	}
	if r := proof.Verify(b, trustOf(t, s)); !r.Valid() {
		t.Fatal(r.Text())
	}
}

// Голова для сборщика: без копии наружу — текущая, с копией — не дальше
// головы, которую держит копия (P-11), и до первого прохода копии — никакой.
// Доказательство продолжения сходится с любой прежней головой; сборщику,
// который назвал голову новее отдаваемой, — без доказательства; испорченный
// tree.hashes — голова без доказательства и ошибка хранилищу, не ложное
// доказательство.
func TestCollectorCheckpoint(t *testing.T) {
	c := newClock()
	cfg, remote := replicaConfig(t)
	s := openStore(t, cfg, c)
	for i := uint64(1); i <= 10; i++ {
		ingest(t, s, "abs-core", i, i)
		if err := s.flush(); err != nil {
			t.Fatal(err)
		}
	}
	if _, _, ok, err := s.CollectorCheckpoint(0); ok || err != nil {
		t.Fatalf("голова до первого прохода копии: %v, %v", ok, err)
	}
	if _, err := s.ShipOnce(context.Background(), remote); err != nil {
		t.Fatal(err)
	}
	shipped := s.replicaShipped.Load()
	for i := uint64(11); i <= 15; i++ {
		ingest(t, s, "abs-core", i, i)
		if err := s.flush(); err != nil {
			t.Fatal(err)
		}
	}
	key := trustOf(t, s).StoreKey
	head, _, ok, err := s.CollectorCheckpoint(0)
	if !ok || err != nil || head.Size != shipped || head.Size >= s.chain.Head().Seq || proof.VerifyCheckpoint(head, key) != nil {
		t.Fatalf("голова %d, копия держит %d, цепь %d: %v", head.Size, shipped, s.chain.Head().Seq, err)
	}
	if head.RootHash() != rootOf(t, s, head.Size) {
		t.Fatal("корень головы не над звеньями цепи")
	}
	for from := uint64(1); from < head.Size; from++ {
		_, consistency, _, err := s.CollectorCheckpoint(from)
		older := proof.SignCheckpoint(s.signer, from, rootOf(t, s, from))
		if err != nil || proof.CheckExtends(head, older, consistency) != nil {
			t.Fatalf("продолжение от %d: %v", from, err)
		}
		other := proof.SignCheckpoint(s.signer, from, [32]byte{1})
		if proof.CheckExtends(head, other, consistency) == nil {
			t.Fatalf("продолжение от чужой головы %d", from)
		}
	}
	if _, consistency, ok, err := s.CollectorCheckpoint(head.Size + 3); !ok || err != nil || consistency != nil {
		t.Fatalf("сборщик впереди: %v, %v, %d хешей", ok, err, len(consistency))
	}

	// tree.hashes испорчен: доказательство не отдаётся.
	path := filepath.Join(cfg.DataDir, treeFileName)
	fi, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, make([]byte, fi.Size()), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, consistency, ok, err := s.CollectorCheckpoint(3); !ok || !errors.Is(err, errTreeFile) || consistency != nil {
		t.Fatalf("испорченный файл: %v, %v, %d хешей", ok, err, len(consistency))
	}
}

// Без копии наружу сборщик получает текущую голову.
func TestCollectorCheckpointNoCopy(t *testing.T) {
	c := newClock()
	s := openStore(t, testConfig(t), c)
	ingest(t, s, "abs-core", 1, 3)
	if err := s.flush(); err != nil {
		t.Fatal(err)
	}
	head, _, ok, err := s.CollectorCheckpoint(0)
	if !ok || err != nil || head.Size != s.chain.Head().Seq || head.RootHash() != rootOf(t, s, head.Size) {
		t.Fatalf("голова %d, цепь %d: %v", head.Size, s.chain.Head().Seq, err)
	}
}
