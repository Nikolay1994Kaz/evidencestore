package auditchain

import (
	"fmt"
)

// ScanVerifiedLeaves — ScanLeaves с проверкой: листья каждого звена
// пересчитываются в корень Меркла и сверяются с корнем в звене. Лист,
// подменённый вместе с CRC кадра, иначе не видит никто, кроме сборки пакета
// доказательств по этому звену, а по листьям строятся индексы и сверка
// кейринга с цепью.
//
// links — звенья цепи (ReadChain) по порядку. Листья после последнего
// звена (ещё без корня) отдаются как есть: их накроет следующее звено.
// Листьев меньше, чем обещают звенья, — ErrLeavesMissing.
func ScanVerifiedLeaves(dir string, links []Record, fn func(num uint64, l Leaf) error) error {
	type batch struct {
		seq   uint64
		first uint64
		end   uint64
		root  [32]byte
	}
	batches := make([]batch, 0, len(links))
	var next uint64
	for _, l := range links {
		p, err := DecodeBatchPayload(l.Payload)
		if err != nil {
			return fmt.Errorf("auditchain: link %d: %w", l.Seq, err)
		}
		if p.FirstLeaf != next {
			return fmt.Errorf("auditchain: link %d covers leaves from %d, expected %d", l.Seq, p.FirstLeaf, next)
		}
		next = p.FirstLeaf + uint64(p.Count)
		batches = append(batches, batch{seq: l.Seq, first: p.FirstLeaf, end: next, root: p.Root})
	}
	cur := 0
	var hashes [][32]byte
	err := ScanLeaves(dir, func(num uint64, l Leaf) error {
		if cur < len(batches) {
			hashes = append(hashes, LeafHash(l))
			if num+1 == batches[cur].end {
				if merkleRootOf(hashes) != batches[cur].root {
					return fmt.Errorf("auditchain: leaves %d…%d do not match the root of link %d: a leaf was replaced",
						batches[cur].first, num, batches[cur].seq)
				}
				cur, hashes = cur+1, hashes[:0]
			}
		}
		return fn(num, l)
	})
	if err != nil {
		return err
	}
	if cur < len(batches) {
		return fmt.Errorf("%w: link %d promises leaves up to %d, the disk holds fewer", ErrLeavesMissing, batches[cur].seq, batches[cur].end-1)
	}
	return nil
}
