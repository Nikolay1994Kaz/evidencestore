package proof

import (
	"crypto/sha256"
	"fmt"
	"math/bits"

	"golang.org/x/mod/sumdb/tlog"

	"github.com/Nikolay1994Kaz/evidencestore/internal/auditchain"
)

// Дерево звеньев (DECISIONS п. 30). Запись k (с нуля) — звено k+1; хеш
// записи — SHA-256(0x00 ‖ хеш звена), узел — SHA-256(0x01 ‖ левый ‖
// правый), как в RFC 6962. Математика дерева — golang.org/x/mod/sumdb/tlog
// (база контрольных сумм Go). Ядро (auditchain) дерева не знает: оно
// производное от хешей звеньев.

// LinkLeaf — хеш записи дерева для звена с хешем linkHash.
func LinkLeaf(linkHash [32]byte) [32]byte { return tlog.RecordHash(linkHash[:]) }

// Frontier — граница дерева: корни совершенных поддеревьев, на которые
// раскладывается размер Size, слева направо, от большего к меньшему. Из
// границы перед звеном и хешей звеньев после неё корень считается на любом
// размере дальше: пакет списком не длиннее log₂N хешей привязывает свои
// звенья к голове.
type Frontier struct {
	Size  uint64
	Nodes [][32]byte
}

// NewFrontier — граница размера size из её узлов; узлов столько, сколько
// единиц в двоичной записи size.
func NewFrontier(size uint64, nodes [][32]byte) (Frontier, error) {
	if len(nodes) != bits.OnesCount64(size) {
		return Frontier{}, fmt.Errorf("the tree frontier before link %d has %d hashes, not %d", size+1, len(nodes), bits.OnesCount64(size))
	}
	return Frontier{Size: size, Nodes: append([][32]byte(nil), nodes...)}, nil
}

// FrontierOfLinks — граница дерева над звеньями links, с первого звена цепи.
func FrontierOfLinks(links []auditchain.Record) Frontier {
	var f Frontier
	for _, l := range links {
		f.Push(LinkLeaf(auditchain.Hash(l)))
	}
	return f
}

// Push добавляет запись дерева и отдаёт хеши, которые она дописывает в
// хранимые (tlog.StoredHashes): свой и узлы поддеревьев, которые она
// замкнула, снизу вверх.
func (f *Frontier) Push(leaf [32]byte) [][32]byte {
	stored := [][32]byte{leaf}
	f.Nodes = append(f.Nodes, leaf)
	f.Size++
	for s := f.Size; s != 0 && s&1 == 0; s >>= 1 {
		n := len(f.Nodes)
		node := [32]byte(tlog.NodeHash(f.Nodes[n-2], f.Nodes[n-1]))
		f.Nodes = append(f.Nodes[:n-2], node)
		stored = append(stored, node)
	}
	return stored
}

// Root — корень дерева размера Size; у пустого — SHA-256 пустой строки, как
// в RFC 6962 и tlog (точек пустой цепи хранилище не подписывает).
func (f Frontier) Root() [32]byte {
	if len(f.Nodes) == 0 {
		return sha256.Sum256(nil)
	}
	h := f.Nodes[len(f.Nodes)-1]
	for i := len(f.Nodes) - 2; i >= 0; i-- {
		h = tlog.NodeHash(f.Nodes[i], h)
	}
	return h
}

// Bytes — узлы границы для пакета.
func (f Frontier) Bytes() [][]byte {
	out := make([][]byte, len(f.Nodes))
	for i := range f.Nodes {
		out[i] = f.Nodes[i][:]
	}
	return out
}

// FrontierIndexes — индексы хранимых хешей (tlog.StoredHashIndex) узлов
// границы размера size, слева направо.
func FrontierIndexes(size uint64) []int64 {
	var out []int64
	var lo uint64
	for k := 63; k >= 0; k-- {
		if size&(1<<uint(k)) == 0 {
			continue
		}
		out = append(out, tlog.StoredHashIndex(k, int64(lo>>uint(k))))
		lo += 1 << uint(k)
	}
	return out
}

// linkRoots — корни дерева звеньев на номерах звеньев пакета: по границе
// перед первым звеном (frontier, из пакета) и хешам звеньев подряд.
// rootAt(seq) — корень дерева из seq звеньев, если звено seq в пакете.
func linkRoots(frontier [][]byte, first uint64, hashes [][32]byte) (rootAt func(uint64) ([32]byte, bool), err error) {
	if first == 0 || first+uint64(len(hashes)) < first {
		return nil, fmt.Errorf("the links of the bundle are numbered from %d: the chain starts at link 1", first)
	}
	nodes := make([][32]byte, len(frontier))
	for i, n := range frontier {
		if len(n) != 32 {
			return nil, fmt.Errorf("hash %d of the tree frontier is not 32 bytes", i)
		}
		copy(nodes[i][:], n)
	}
	f, err := NewFrontier(first-1, nodes)
	if err != nil {
		return nil, err
	}
	roots := make([][32]byte, len(hashes))
	for i, h := range hashes {
		f.Push(LinkLeaf(h))
		roots[i] = f.Root()
	}
	return func(seq uint64) ([32]byte, bool) {
		if seq < first || seq-first >= uint64(len(roots)) {
			return [32]byte{}, false
		}
		return roots[seq-first], true
	}, nil
}
