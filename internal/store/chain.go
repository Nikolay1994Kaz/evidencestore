package store

import (
	"encoding/json"
	"fmt"
	"sort"
	"strconv"

	"evidencestore/internal/auditchain"
	"evidencestore/internal/evidence"
	"evidencestore/internal/proof"
	"evidencestore/internal/tsa"
)

// chainScan — что подъём узнал из цепи.
type chainScan struct {
	keyEvents map[string]string // последнее событие каждого ключа
	maxPos    uint64            // наибольшая позиция улики в цепи
	maxSeq    map[string]uint64 // наибольший номер в цепи у каждого источника
	silent    map[string]bool   // источники, чьё последнее событие в цепи — «молчит»
}

// scanChain поднимает индексы цепи одним проходом по листьям: где лежит
// лист каждой улики, какие метки TSA уже в цепи, какое последнее событие у
// каждого ключа. Листья каждого звена сверяются с его корнем: подменённый
// лист не попадает в индексы и в сверку кейринга.
func (s *Store) scanChain() (chainScan, error) {
	cs := chainScan{keyEvents: map[string]string{}, maxSeq: map[string]uint64{}, silent: map[string]bool{}}
	links, err := auditchain.ReadChain(s.chainDir)
	if err != nil {
		return cs, err
	}
	for _, l := range links {
		p, err := auditchain.DecodeBatchPayload(l.Payload)
		if err != nil {
			return cs, fmt.Errorf("chain link %d: %w", l.Seq, err)
		}
		if p.FirstLeaf != s.linked {
			return cs, fmt.Errorf("chain link %d covers leaves from %d, expected %d", l.Seq, p.FirstLeaf, s.linked)
		}
		s.links = append(s.links, linkRef{seq: l.Seq, first: p.FirstLeaf, count: uint64(p.Count)})
		s.linked = p.FirstLeaf + uint64(p.Count)
	}

	err = auditchain.ScanVerifiedLeaves(s.chainDir, links, func(num uint64, l auditchain.Leaf) error {
		s.nextLeaf = num + 1
		switch l.Type {
		case auditchain.EventEvidence:
			pos, _, err := proof.ParseEvidenceLeaf(l)
			if err != nil {
				return fmt.Errorf("chain leaf %d: %w", num, err)
			}
			s.setEvLeaf(pos, num)
			cs.maxPos = max(cs.maxPos, pos)
			if seq, err := strconv.ParseUint(l.Subject, 10, 64); err == nil {
				cs.maxSeq[l.Scope] = max(cs.maxSeq[l.Scope], seq)
			}
			delete(cs.silent, l.Scope)
		case auditchain.EventSilence:
			cs.silent[l.Scope] = true
		case auditchain.EventTimestamp:
			head, err := strconv.ParseUint(l.Subject, 10, 64)
			if err != nil {
				return fmt.Errorf("chain leaf %d: timestamp without head", num)
			}
			gen, err := tsa.GenTime(l.Payload)
			if err != nil {
				return fmt.Errorf("chain leaf %d: %w", num, err)
			}
			s.tokens = append(s.tokens, tokenRef{head: head, leaf: num, gen: gen})
			s.lastStamped = max(s.lastStamped, head)
			s.stampedLeaves = num + 1
		case auditchain.EventKeyState:
			cs.keyEvents[l.Scope] = l.Subject
		case auditchain.EventEpoch:
			var ev epochEvent
			if err := json.Unmarshal(l.Payload, &ev); err != nil {
				return fmt.Errorf("chain leaf %d: collector epoch: %w", num, err)
			}
			if st := s.sources[l.Scope]; st != nil && ev.Reason != epochRefused {
				st.epoch = ev.Epoch
			}
		case auditchain.EventGateway:
			pos, v, err := proof.ParseGatewayLeaf(l)
			if err != nil {
				return fmt.Errorf("chain leaf %d: %w", num, err)
			}
			s.indexGatewayLocked(l.Scope, pos, num, v)
			if st := s.sources[l.Scope]; st != nil && st.gw != nil {
				st.gw.Resume(v)
				st.gwVerified = max(st.gwVerified, pos)
			}
		}
		return nil
	})
	if err != nil {
		return cs, err
	}
	if got, want := s.nextLeaf-s.linked, uint64(s.chain.Pending()); got != want {
		return cs, fmt.Errorf("chain: %d leaves without a link on disk, carrier holds %d", got, want)
	}
	return cs, nil
}

func (s *Store) setEvLeaf(pos, leaf uint64) {
	for uint64(len(s.evLeaf)) < pos {
		s.evLeaf = append(s.evLeaf, 0)
	}
	s.evLeaf[pos-1] = leaf + 1
}

// onCommit — крючок журнала улик: после fsync пачки её улики встают в цепь
// листьями, в порядке журнала.
func (s *Store) onCommit(first uint64, records [][]byte) {
	s.chainMu.Lock()
	defer s.chainMu.Unlock()
	for i, rec := range records {
		sealed, err := evidence.Unmarshal(rec)
		if err != nil {
			// Байты сделал сам Ingest; сюда не попасть. Если попали — молчать
			// нельзя: улика на диске есть, а в цепи её не будет до рестарта.
			s.log.Error("evidence in log does not parse; chain catch-up on restart", "pos", first+uint64(i), "err", err)
			continue
		}
		s.appendEvidenceLocked(sealed.Header, first+uint64(i), evidence.Digest(rec))
	}
}

func (s *Store) appendEvidenceLocked(h evidence.Header, pos uint64, digest [32]byte) {
	num := s.appendLeafLocked(proof.EvidenceLeaf(h, pos, digest))
	s.setEvLeaf(pos, num)
}

func (s *Store) appendLeafLocked(l auditchain.Leaf) uint64 {
	s.chain.Append(l)
	num := s.nextLeaf
	s.nextLeaf++
	return num
}

// appendEvent кладёт в цепь событие (ключи, пропуски, молчание, запуск).
func (s *Store) appendEvent(typ auditchain.EventType, scope, subject string, payload []byte) uint64 {
	s.chainMu.Lock()
	defer s.chainMu.Unlock()
	return s.appendLeafLocked(auditchain.Leaf{
		UnixNano: s.nowTime().UnixNano(),
		Type:     typ,
		Scope:    scope,
		Subject:  subject,
		Payload:  payload,
	})
}

func (s *Store) appendJSONEvent(typ auditchain.EventType, scope, subject string, v any) {
	payload, err := json.Marshal(v)
	if err != nil {
		s.log.Error("event payload", "err", err)
		return
	}
	s.appendEvent(typ, scope, subject, payload)
}

// flush сворачивает накопившиеся листья в звено.
func (s *Store) flush() error {
	s.chainMu.Lock()
	defer s.chainMu.Unlock()
	return s.flushLocked()
}

func (s *Store) flushLocked() error {
	if s.nextLeaf == s.linked {
		return nil
	}
	head, err := s.chain.Flush()
	if err != nil {
		return fmt.Errorf("chain flush: %w", err)
	}
	s.links = append(s.links, linkRef{seq: head.Seq, first: s.linked, count: s.nextLeaf - s.linked})
	s.linked = s.nextLeaf
	return nil
}

// linkOf — звено, накрывшее лист с номером leaf.
func (s *Store) linkOfLocked(leaf uint64) (linkRef, bool) {
	i := sort.Search(len(s.links), func(i int) bool { return s.links[i].first+s.links[i].count > leaf })
	if i == len(s.links) || leaf < s.links[i].first {
		return linkRef{}, false
	}
	return s.links[i], true
}

// Statement — голова, подписанная ключом хранилища.
func (s *Store) Statement() auditchain.Statement {
	s.chainMu.Lock()
	defer s.chainMu.Unlock()
	h := s.chain.Head()
	return s.signer.Sign(h, len(s.links), s.nowTime().Unix())
}
