package store

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sync/atomic"

	"golang.org/x/mod/sumdb/tlog"

	"github.com/Nikolay1994Kaz/evidencestore/internal/auditchain"
	"github.com/Nikolay1994Kaz/evidencestore/internal/proof"
)

// Дерево звеньев на стороне хранилища (DECISIONS п. 30).
//
// Граница в памяти — корень текущей головы: её строит проход по chain.log
// при запуске, дальше каждое звено ложится в неё в flushLocked. Корень
// текущей головы хранилище подписывает прямо по ней.
//
// Хранимые хеши — data_dir/tree.hashes, по 32 байта в порядке
// tlog.StoredHashIndex (около двух на звено): по ним строятся граница перед
// звеном пакета, корень на прежнем размере и доказательства продолжения.
// Файл производный, без fsync: при запуске каждый его хеш сверяется с
// посчитанным по цепи, и с первого расхождения или с конца файл
// переписывается, лишнее после цепи (хвост цепи отрезан) обрезается. Корень
// прежнего размера, взятый из файла, хранилище подписывает, только сверив его
// с границей в памяти доказательством продолжения (agreesLocked): испорченный
// файл даёт отказ выдать пакет, а не подпись под чужим корнем.

const treeFileName = "tree.hashes"

// errTreeFile — хранимые хеши разошлись с цепью.
var errTreeFile = errors.New("store: " + treeFileName + " disagrees with the chain: restart the store, it rebuilds the file from chain.log")

type linkTree struct {
	f     *os.File
	front proof.Frontier // граница текущей головы; меняется под chainMu
	// failed — запись в файл не прошла (пишется под chainMu, читается без
	// него): до перезапуска по файлу ничего не строится, подпись текущей
	// головы идёт дальше.
	failed atomic.Pointer[error]
}

// openLinkTree строит границу по звеньям цепи и приводит к ним файл
// хранимых хешей в dataDir.
func openLinkTree(dataDir string, links []auditchain.Record) (*linkTree, error) {
	f, err := os.OpenFile(filepath.Join(dataDir, treeFileName), os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return nil, fmt.Errorf("tree of links: %w", err)
	}
	t := &linkTree{f: f}
	if err := t.reconcile(links); err != nil {
		f.Close()
		return nil, fmt.Errorf("tree of links: %w", err)
	}
	return t, nil
}

// reconcile сверяет файл с хешами, посчитанными по звеньям: пока сходится —
// читает дальше, с первого расхождения или конца файла — пишет заново.
func (t *linkTree) reconcile(links []auditchain.Record) error {
	if _, err := t.f.Seek(0, io.SeekStart); err != nil {
		return err
	}
	in := bufio.NewReaderSize(t.f, 64<<10)
	var out *bufio.Writer
	have := make([]byte, 65*32)
	for n, l := range links {
		stored := t.front.Push(proof.LinkLeaf(auditchain.Hash(l)))
		if out == nil {
			got := have[:32*len(stored)]
			_, err := io.ReadFull(in, got)
			if err == nil && bytes.Equal(got, hashBytes(stored)) {
				continue
			}
			if err != nil && !errors.Is(err, io.EOF) && !errors.Is(err, io.ErrUnexpectedEOF) {
				return err
			}
			at := tlog.StoredHashIndex(0, int64(n)) * 32
			if err := t.f.Truncate(at); err != nil {
				return err
			}
			if _, err := t.f.Seek(at, io.SeekStart); err != nil {
				return err
			}
			out = bufio.NewWriterSize(t.f, 64<<10)
		}
		if _, err := out.Write(hashBytes(stored)); err != nil {
			return err
		}
	}
	if out != nil {
		return out.Flush()
	}
	return t.f.Truncate(tlog.StoredHashCount(int64(len(links))) * 32)
}

func hashBytes(hashes [][32]byte) []byte {
	b := make([]byte, 0, 32*len(hashes))
	for _, h := range hashes {
		b = append(b, h[:]...)
	}
	return b
}

// add кладёт звено в границу, его хранимые хеши — в файл. Ошибку записи
// отдаёт один раз — когда файл отказал. Звать под chainMu.
func (t *linkTree) add(linkHash [32]byte) error {
	n := int64(t.front.Size)
	stored := t.front.Push(proof.LinkLeaf(linkHash))
	if t.failed.Load() != nil {
		return nil
	}
	if _, err := t.f.WriteAt(hashBytes(stored), tlog.StoredHashIndex(0, n)*32); err != nil {
		t.failed.Store(&err)
		return err
	}
	return nil
}

// size и root — текущая голова. Звать под chainMu.
func (t *linkTree) size() uint64   { return t.front.Size }
func (t *linkTree) root() [32]byte { return t.front.Root() }

// ReadHashes — tlog.HashReader над файлом. Хеши размера, который уже был
// головой, не меняются: читать их можно без chainMu.
func (t *linkTree) ReadHashes(indexes []int64) ([]tlog.Hash, error) {
	if len(indexes) == 0 {
		return nil, nil
	}
	if p := t.failed.Load(); p != nil {
		return nil, fmt.Errorf("store: writing %s failed (%v): restart the store, it rebuilds the file", treeFileName, *p)
	}
	out := make([]tlog.Hash, len(indexes))
	for i, idx := range indexes {
		if _, err := t.f.ReadAt(out[i][:], idx*32); err != nil {
			return nil, fmt.Errorf("store: %s, hash %d: %w", treeFileName, idx, err)
		}
	}
	return out, nil
}

// frontierAt — граница дерева размера m по файлу.
func (t *linkTree) frontierAt(m uint64) (proof.Frontier, error) {
	hashes, err := t.ReadHashes(proof.FrontierIndexes(m))
	if err != nil {
		return proof.Frontier{}, err
	}
	nodes := make([][32]byte, len(hashes))
	for i, h := range hashes {
		nodes[i] = h
	}
	return proof.NewFrontier(m, nodes)
}

// agreesLocked — root действительно корень дерева из m звеньев этой цепи:
// на текущем размере — прямо по границе в памяти, на прежнем — по
// доказательству продолжения из файла до текущего корня. Звать под chainMu.
func (t *linkTree) agreesLocked(m uint64, root [32]byte) error {
	n := t.front.Size
	switch {
	case m == 0 || m > n:
		return fmt.Errorf("store: no head %d in a chain of %d links", m, n)
	case m == n:
		if root != t.front.Root() {
			return errTreeFile
		}
		return nil
	}
	p, err := tlog.ProveTree(int64(n), int64(m), t)
	if err != nil {
		return err
	}
	if tlog.CheckTree(p, int64(n), t.front.Root(), int64(m), root) != nil {
		return errTreeFile
	}
	return nil
}

func (t *linkTree) close() error { return t.f.Close() }

// bundleHead — граница дерева перед первым звеном пакета и подписанная точка
// на последнем: ими пакет привязывает свои звенья к голове. Граница — из
// файла, корень считается по ней и звеньям пакета и до подписи сверяется с
// границей в памяти. Без chainMu: замок берётся только на сверку.
func (s *Store) bundleHead(links []auditchain.Record) ([][]byte, proof.Checkpoint, error) {
	front, root, err := s.bundleRoot(links)
	if err != nil {
		return nil, proof.Checkpoint{}, err
	}
	s.chainMu.Lock()
	err = s.tree.agreesLocked(links[len(links)-1].Seq, root)
	s.chainMu.Unlock()
	if err != nil {
		return nil, proof.Checkpoint{}, err
	}
	return front.Bytes(), proof.SignCheckpoint(s.signer, links[len(links)-1].Seq, root), nil
}

// bundleHeadLocked — то же под chainMu (пакет одной улики собирается под
// ним целиком).
func (s *Store) bundleHeadLocked(links []auditchain.Record) ([][]byte, proof.Checkpoint, error) {
	front, root, err := s.bundleRoot(links)
	if err != nil {
		return nil, proof.Checkpoint{}, err
	}
	if err := s.tree.agreesLocked(links[len(links)-1].Seq, root); err != nil {
		return nil, proof.Checkpoint{}, err
	}
	return front.Bytes(), proof.SignCheckpoint(s.signer, links[len(links)-1].Seq, root), nil
}

// bundleRoot — граница перед звеном links[0] и корень на последнем звене.
func (s *Store) bundleRoot(links []auditchain.Record) (proof.Frontier, [32]byte, error) {
	front, err := s.tree.frontierAt(links[0].Seq - 1)
	if err != nil {
		return proof.Frontier{}, [32]byte{}, err
	}
	f := front
	f.Nodes = append([][32]byte(nil), front.Nodes...)
	for _, l := range links {
		f.Push(proof.LinkLeaf(auditchain.Hash(l)))
	}
	return front, f.Root(), nil
}

// checkpointLocked — подписанная точка текущей головы; ok = false — цепь
// пуста. Звать под chainMu.
func (s *Store) checkpointLocked() (proof.Checkpoint, bool) {
	if s.tree.size() == 0 {
		return proof.Checkpoint{}, false
	}
	return proof.SignCheckpoint(s.signer, s.tree.size(), s.tree.root()), true
}
