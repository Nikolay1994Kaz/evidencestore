package auditchain

import (
	"crypto/sha256"
	"fmt"
)

// Дерево Меркла над батчем листьев.
//
// ЗАЧЕМ ОНО ЗДЕСЬ. Цепь платит объёмом за каждую запись и не может быть
// сжата. Дерево меняет «запись на событие» на «запись на тик»: в цепь идёт
// один корень, события лежат листьями рядом. Доказательство того, что
// конкретная улика в цепи есть, становится путём длиной log₂N — при тысяче
// событий в батче это десять хешей, около 350 Б.
//
// ⭐ПОБОЧНОЕ СВОЙСТВО, КОТОРОЕ ВАЖНЕЕ ЭКОНОМИИ. Путь Меркла доказывает
// ВКЛЮЧЕНИЕ СВОЕГО листа, не раскрывая соседних. Можно доказать «эта улика
// в журнале есть и не менялась», не показывая проверяющему ничего про другие
// улики того же батча. Прямая запись такого не умеет:
// чтобы проверить цепь, её надо прочесть целиком.
//
// ⚠ДВЕ ИЗВЕСТНЫЕ ЛОВУШКИ ДЕРЕВЬЕВ МЕРКЛА, ОБОЙДЁННЫЕ ПО ПОСТРОЕНИЮ.
//
//  1. ВТОРОЙ ПРООБРАЗ. Если лист и внутренний узел хешируются одинаково,
//     внутренний узел можно предъявить как лист: путь сойдётся к тому же
//     корню, и «доказательство» будет верным для события, которого не было.
//     Лечится разделением доменов — лист хешируется с префиксом 0x00, узел с
//     0x01, и пространства не пересекаются.
//  2. МАЛЛЕАБИЛЬНОСТЬ НЕЧЁТНОГО УРОВНЯ. Классический приём «продублировать
//     последний узел» даёт двум РАЗНЫМ наборам листьев один корень
//     (CVE-2012-2459 в биткойне). Здесь нечётный узел поднимается на уровень
//     выше БЕЗ изменения — дублирования нет, значит нет и подмены.
//
// УЗЕЛ ЛИСТА НЕСЁТ ПРИЗНАК «МЕТКА TSA» (P-23, после v0.3.1). Внизу дерева лежит
// не хеш листа, а хеш с префиксом 0x02 от признака (1 — лист метки, 0 — любой
// другой) и хеша листа. Сверке обещания по меткам нужно видеть все листья
// перед уликой, чтобы метку нельзя было спрятать, но о чужом листе ей нужно
// знать одно — метка ли он. Теперь чужой лист показывается одним хешем: его
// узел считается с признаком 0, и метку, показанную так, выдаёт корень звена.
// Метка, вписанная в звено с признаком 0 с самого начала, не годится нигде:
// там, где лист раскрыт целиком (края окна, T1), признак берётся из типа, и
// корень не сходится. Хеш листа (LeafHash) остался прежним: на нём держатся
// ссылки цепочки источника и хвосты.
const (
	domainLeaf     byte = 0x00
	domainNode     byte = 0x01
	domainLeafNode byte = 0x02
)

// LeafHash — хеш листа.
func LeafHash(l Leaf) [32]byte {
	return sha256.Sum256(encodeLeafForHash(l))
}

// LeafNode — узел листа в дереве звена: хеш листа вместе с признаком «это
// метка TSA».
func LeafNode(l Leaf) [32]byte {
	_, node := leafNode(l)
	return node
}

// HiddenLeafNode — узел листа, показанного одним хешем: такой лист — не
// метка.
func HiddenLeafNode(leafHash [32]byte) [32]byte {
	return nodeOfLeaf(false, leafHash)
}

// MerkleRootOfNodes — корень над готовыми узлами листьев (LeafNode,
// HiddenLeafNode) в порядке листьев.
func MerkleRootOfNodes(nodes [][32]byte) [32]byte {
	return merkleRootOf(nodes)
}

// leafNode — хеш листа и его узел в дереве звена.
func leafNode(l Leaf) (leafHash, node [32]byte) {
	leafHash = LeafHash(l)
	return leafHash, nodeOfLeaf(l.Type == EventTimestamp, leafHash)
}

func nodeOfLeaf(stamp bool, leafHash [32]byte) [32]byte {
	var buf [2 + hashSize]byte
	buf[0] = domainLeafNode
	if stamp {
		buf[1] = 1
	}
	copy(buf[2:], leafHash[:])
	return sha256.Sum256(buf[:])
}

// nodeHash — хеш внутреннего узла из двух детей.
func nodeHash(left, right [32]byte) [32]byte {
	var buf [1 + 2*hashSize]byte
	buf[0] = domainNode
	copy(buf[1:1+hashSize], left[:])
	copy(buf[1+hashSize:], right[:])
	return sha256.Sum256(buf[:])
}

// MerkleRoot — корень над листьями в порядке их добавления.
//
// Пустой батч даёт нулевой корень; звено над ним не строится (см. LinkBatch),
// поэтому наружу это значение не выходит.
func MerkleRoot(leaves []Leaf) [32]byte {
	level := make([][32]byte, len(leaves))
	for i, l := range leaves {
		level[i] = LeafNode(l)
	}
	return merkleRootOf(level)
}

// merkleRootOf — корень над уже посчитанными хешами листьев.
func merkleRootOf(hashes [][32]byte) [32]byte {
	if len(hashes) == 0 {
		return [32]byte{}
	}
	level := append([][32]byte(nil), hashes...)
	for len(level) > 1 {
		level = nextLevel(level)
	}
	return level[0]
}

// nextLevel сворачивает уровень попарно. Нечётный последний узел поднимается
// как есть — см. ловушку 2 в шапке файла.
func nextLevel(level [][32]byte) [][32]byte {
	next := make([][32]byte, 0, (len(level)+1)/2)
	for i := 0; i < len(level); i += 2 {
		if i+1 == len(level) {
			next = append(next, level[i])
			continue
		}
		next = append(next, nodeHash(level[i], level[i+1]))
	}
	return next
}

// ProofStep — одно звено пути от листа к корню.
//
// SiblingLeft говорит, с какой стороны стоит сосед. Без этого флага порядок
// склейки пришлось бы угадывать, а nodeHash(a,b) ≠ nodeHash(b,a) — и проверка
// либо разошлась бы, либо (хуже) стала бы принимать перестановку листьев.
type ProofStep struct {
	Hash        [32]byte
	SiblingLeft bool
}

// MerkleTree — уровни дерева звена. Пути всех листьев звена берутся из одного
// дерева: строить его на каждый лист значит платить k² за звено (P-58), а при
// всплеске и догоняющем приёме звено — это тысячи листьев.
type MerkleTree struct {
	levels [][][32]byte
}

// NewMerkleTree строит дерево над листьями звена.
func NewMerkleTree(leaves []Leaf) *MerkleTree {
	level := make([][32]byte, len(leaves))
	for i, l := range leaves {
		level[i] = LeafNode(l)
	}
	t := &MerkleTree{levels: [][][32]byte{level}}
	for len(level) > 1 {
		level = nextLevel(level)
		t.levels = append(t.levels, level)
	}
	return t
}

// Proof — путь включения листа с индексом idx.
func (t *MerkleTree) Proof(idx int) ([]ProofStep, error) {
	if idx < 0 || idx >= len(t.levels[0]) {
		return nil, fmt.Errorf("auditchain: leaf %d is outside a batch of %d", idx, len(t.levels[0]))
	}
	var path []ProofStep
	pos := idx
	for _, level := range t.levels[:len(t.levels)-1] {
		// Одинокий последний узел поднимается без соседа — шага в пути нет.
		if pos != len(level)-1 || len(level)%2 != 1 {
			if pos%2 == 0 {
				path = append(path, ProofStep{Hash: level[pos+1], SiblingLeft: false})
			} else {
				path = append(path, ProofStep{Hash: level[pos-1], SiblingLeft: true})
			}
		}
		pos /= 2
	}
	return path, nil
}

// MerkleProof строит путь включения листа с индексом idx. Для одного листа; пути
// многих листьев звена — через NewMerkleTree.
func MerkleProof(leaves []Leaf, idx int) ([]ProofStep, error) {
	return NewMerkleTree(leaves).Proof(idx)
}

// VerifyProof проверяет, что лист входит в батч с этим корнем.
//
// Проверяющему не нужны ни остальные листья, ни сама цепь — только лист, путь
// и корень, который он взял из звена. Это и есть «докажи свою улику, не
// показывая чужих».
func VerifyProof(l Leaf, path []ProofStep, root [32]byte) bool {
	h := LeafNode(l)
	for _, step := range path {
		if step.SiblingLeft {
			h = nodeHash(step.Hash, h)
		} else {
			h = nodeHash(h, step.Hash)
		}
	}
	return h == root
}
