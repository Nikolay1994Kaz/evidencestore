package store

import (
	"crypto/ed25519"
	"fmt"

	"github.com/Nikolay1994Kaz/evidencestore/internal/config"
	"github.com/Nikolay1994Kaz/evidencestore/internal/evidence"
	"github.com/Nikolay1994Kaz/evidencestore/internal/gateway"
	"github.com/Nikolay1994Kaz/evidencestore/internal/proof"
)

// Журнал гейтвея (content_type pipelock/recorder). Каждая принятая строка
// проверяется (gateway.Tracker): хэш записи, сцепка с предыдущей, подпись
// контрольной точки. Вердикт ложится в цепь листом рядом с уликой, в порядке
// журнала улик, поэтому пачки такого источника принимаются по одной.
// Проверка ничего не отвергает: битая или подменённая запись принимается
// как пришла, а вердикт говорит, что с ней не так.

// gwMark — контрольная точка или поломка в цепочке гейтвея: по ним пакет
// доказательств находит точку, накрывшую запись.
type gwMark struct {
	pos, leaf  uint64
	ns         string // цепочка гейтвея (gateway.Verdict.Namespace)
	checkpoint bool   // контрольная точка с подписью (проверенной или без ключа)
	broken     bool   // запись не цела: дальше неё сцепка не доказана
}

type gwItem struct {
	header evidence.Header
	pos    uint64
	body   []byte
}

func newTracker(src config.Source) *gateway.Tracker {
	if src.ContentType != config.GatewayContentType {
		return nil
	}
	var key ed25519.PublicKey
	if src.GatewayKey != "" {
		key, _ = gateway.ParseKey(src.GatewayKey) // проверен config.Validate
	}
	return gateway.NewTracker(key)
}

// recordGateway проверяет записи и кладёт вердикты в цепь. Зовётся под
// st.gwMu, записи — в порядке позиций.
func (s *Store) recordGateway(st *sourceState, items []gwItem) {
	for _, it := range items {
		s.appendGatewayVerdict(st, it.header, it.pos, st.gw.Check(it.body))
	}
}

func (s *Store) appendGatewayVerdict(st *sourceState, h evidence.Header, pos uint64, v gateway.Verdict) {
	s.chainMu.Lock()
	num := s.appendLeafLocked(proof.GatewayLeaf(h, pos, v))
	s.indexGatewayLocked(h.Source, pos, num, v)
	s.chainMu.Unlock()
	st.gwVerified = pos
	if !v.Clean() {
		st.gwProblems.Add(1)
		s.log.Warn("gateway journal: entry is not intact", "source", h.Source, "seq", h.Seq,
			"gateway_seq", v.Seq, "link", v.Link, "hash_ok", v.HashOK, "signature", v.Signature, "problem", v.Problem)
	}
}

func (s *Store) indexGatewayLocked(source string, pos, leaf uint64, v gateway.Verdict) {
	s.gwLeaf[pos] = leaf
	broken := !v.Clean()
	cp := !broken && v.Type == "checkpoint" && v.Sig != ""
	if cp || broken {
		s.gwMarks[source] = append(s.gwMarks[source], gwMark{pos: pos, leaf: leaf, ns: v.Namespace(), checkpoint: cp, broken: broken})
	}
}

// gatewayProofLocked — часть пакета для улики гейтвея: лист вердикта и
// первая контрольная точка той же цепочки после неё, если до неё нет
// поломок. nil — у улики нет вердикта (не журнал гейтвея).
func (s *Store) gatewayProofLocked(source string, pos uint64) (*proof.GatewayProof, error) {
	leaf, ok := s.gwLeaf[pos]
	if !ok {
		return nil, nil
	}
	inc, err := s.inclusionLocked(leaf)
	if err != nil {
		return nil, err
	}
	_, v, err := proof.ParseGatewayLeaf(inc.Leaf.Chain())
	if err != nil {
		return nil, fmt.Errorf("store: %w", err)
	}
	g := &proof.GatewayProof{Entry: inc}
	if !v.Clean() {
		return g, nil
	}
	for _, m := range s.gwMarks[source] {
		if m.pos <= pos || m.ns != v.Namespace() {
			continue
		}
		if m.broken {
			break
		}
		if m.checkpoint {
			cp, err := s.inclusionLocked(m.leaf)
			if err != nil {
				return nil, err
			}
			g.Checkpoint = &cp
			break
		}
	}
	return g, nil
}
