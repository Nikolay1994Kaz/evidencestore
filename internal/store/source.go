package store

import (
	"errors"
	"fmt"
	"sort"
	"strconv"
	"time"

	"github.com/Nikolay1994Kaz/evidencestore/internal/auditchain"
	"github.com/Nikolay1994Kaz/evidencestore/internal/evidence"
	"github.com/Nikolay1994Kaz/evidencestore/internal/keyring"
	"github.com/Nikolay1994Kaz/evidencestore/internal/proof"
)

// ProofSource собирает пакет по источнику за окно (DECISIONS, п. 28): все
// записи источника между хвостами нижней и верхней меток, с путями Меркла —
// чужие листья в них только хэшами. Метки выбираются, как у пакета за окно:
// нижняя — последняя раньше начала окна больше чем на секунду, верхняя —
// первая позже конца больше чем на минуту. withDEK — приложить улики с
// ключами записей; toHead — довести звенья до этой головы (свидетель).
//
// Окно, край которого приходится на метку до хвостов источников (хранилище
// обновилось позже), или записи в нём без ссылок — отказ: такое окно
// отвечает только пакет за окно.
func (s *Store) ProofSource(source string, from, to time.Time, withDEK bool, toHead uint64) (proof.SourceBundle, error) {
	switch {
	case source == "":
		return proof.SourceBundle{}, fmt.Errorf("%w: name the source", ErrWindow)
	case from.IsZero() || to.IsZero():
		return proof.SourceBundle{}, fmt.Errorf("%w: both ends of the window are required", ErrWindow)
	case to.Before(from):
		return proof.SourceBundle{}, fmt.Errorf("%w: the window ends before it starts", ErrWindow)
	case s.tsaURL == "" && s.tsaLocal == nil:
		return proof.SourceBundle{}, fmt.Errorf("%w: the store has no TSA, and a window is bounded by time-stamps", ErrWindow)
	}
	s.mu.Lock()
	_, known := s.sources[source]
	s.mu.Unlock()
	if !known {
		return proof.SourceBundle{}, fmt.Errorf("%w: source %s", ErrNotFound, source)
	}

	s.chainMu.Lock()
	if err := s.flushLocked(); err != nil {
		s.chainMu.Unlock()
		return proof.SourceBundle{}, err
	}
	upper := -1
	for i, t := range s.tokens {
		if t.gen.After(to.Add(proof.ReceiveSkew)) {
			upper = i
			break
		}
	}
	if upper < 0 {
		s.chainMu.Unlock()
		return proof.SourceBundle{}, fmt.Errorf("%w: no time-stamp after %s, a minute past the window, yet: the store takes one every tsa.every while records arrive and at least once an hour",
			ErrWindow, to.Add(proof.ReceiveSkew).UTC().Format(time.RFC3339))
	}
	lower := -1
	for i := upper - 1; i >= 0; i-- {
		if s.tokens[i].gen.Before(from.Add(-proof.ReceiveSlack)) {
			lower = i
			break
		}
	}
	top, ok := s.linkOfLocked(s.tokens[upper].leaf)
	tokIdx := int(s.tokens[upper].leaf - top.first)
	var lowerHead, first, lowerTok uint64
	if lower >= 0 {
		lowerHead, lowerTok = s.tokens[lower].head, s.tokens[lower].leaf
		i := sort.Search(len(s.links), func(i int) bool { return s.links[i].seq >= lowerHead })
		if i == len(s.links) || s.links[i].seq != lowerHead {
			ok = false
		} else {
			first = s.links[i].first
		}
	}
	head := s.chain.Head().Seq
	s.chainMu.Unlock()
	if !ok {
		return proof.SourceBundle{}, errors.New("store: the time-stamps of the window are not linked")
	}
	end := top.first + top.count
	if end-first > maxWindowLeaves {
		return proof.SourceBundle{}, fmt.Errorf("%w: the window spans %d leaves of the chain, more than %d in one bundle: ask for shorter windows", ErrWindow, end-first, maxWindowLeaves)
	}
	last := top.seq
	if toHead > last {
		if toHead > head {
			return proof.SourceBundle{}, fmt.Errorf("store: head %d is not in the chain yet: the head is %d", toHead, head)
		}
		last = toHead
	}

	links, err := auditchain.ReadLinks(s.chainDir, max(lowerHead, 1), last)
	if err != nil {
		return proof.SourceBundle{}, err
	}
	leaves, err := auditchain.ReadLeafRange(s.chainDir, first, end)
	if err != nil {
		return proof.SourceBundle{}, err
	}
	// leavesOf — листья звена из прочитанного.
	leavesOf := func(l auditchain.Record) ([]auditchain.Leaf, error) {
		p, err := auditchain.DecodeBatchPayload(l.Payload)
		if err != nil {
			return nil, err
		}
		return leaves[p.FirstLeaf-first : p.FirstLeaf-first+uint64(p.Count)], nil
	}
	const predates = "%w: the time-stamp %s the window was taken before the store laid source tails at time-stamps: ask for a later window, or for a window bundle (proof -window)"

	b := proof.SourceBundle{Version: proof.WindowVersion, Kind: proof.SourceKind, Source: source,
		From: from.UTC(), To: to.UTC(), LowerHead: lowerHead}
	for _, l := range links {
		b.Links = append(b.Links, proof.FromLink(l))
	}
	if lowerHead > 0 {
		ls, err := leavesOf(links[0])
		if err != nil {
			return proof.SourceBundle{}, err
		}
		if len(ls) != 1 || ls[0].Type != auditchain.EventTails {
			return proof.SourceBundle{}, fmt.Errorf(predates, ErrWindow, "before")
		}
		tails := proof.FromLeaf(ls[0])
		b.LowerTails = &tails
		b.LowerToken = leaves[lowerTok-first].Payload
	}
	for _, l := range links {
		if l.Seq <= lowerHead || l.Seq > top.seq {
			continue
		}
		ls, err := leavesOf(l)
		if err != nil {
			return proof.SourceBundle{}, err
		}
		if l.Seq == top.seq {
			if tokIdx != len(ls)-2 || ls[tokIdx+1].Type != auditchain.EventTails {
				return proof.SourceBundle{}, fmt.Errorf(predates, ErrWindow, "after")
			}
			if b.UpperToken, err = placedLeaf(l.Seq, ls, tokIdx); err != nil {
				return proof.SourceBundle{}, err
			}
			if b.UpperTails, err = placedLeaf(l.Seq, ls, tokIdx+1); err != nil {
				return proof.SourceBundle{}, err
			}
			ls = ls[:tokIdx]
		}
		for idx, leaf := range ls {
			if leaf.Type != auditchain.EventEvidence || leaf.Scope != source {
				continue
			}
			if _, linked := proof.EvidencePrev(leaf); !linked {
				return proof.SourceBundle{}, fmt.Errorf("%w: records of %s in this window were written before the store linked them: ask for a window bundle (proof -window)", ErrWindow, source)
			}
			rec := proof.SourceRecord{}
			if rec.Leaf, err = placedLeaf(l.Seq, ls, idx); err != nil {
				return proof.SourceBundle{}, err
			}
			if withDEK {
				if rec.Evidence, rec.DEK, err = s.sealedWithKey(leaf); err != nil {
					return proof.SourceBundle{}, err
				}
			}
			b.Records = append(b.Records, rec)
		}
	}
	// Раскрытия хвостов своего источника: внизу — его последний лист до
	// нижних хвостов, вверху — последняя запись в пакете или тот же лист.
	if lowerHead > 0 {
		if seq, num, found := s.lastLeafBefore(source, first); found {
			ls, err := auditchain.ReadLeaves(s.chainDir, num, 1)
			if err != nil {
				return proof.SourceBundle{}, err
			}
			b.LowerOpen = proof.TailOf(proof.Tail{Source: source, Seq: seq, Hash: auditchain.LeafHash(ls[0])})
		}
	}
	b.UpperOpen = b.LowerOpen
	if n := len(b.Records); n > 0 {
		l := b.Records[n-1].Leaf.Leaf.Chain()
		seq, _ := strconv.ParseUint(l.Subject, 10, 64)
		b.UpperOpen = proof.TailOf(proof.Tail{Source: source, Seq: seq, Hash: auditchain.LeafHash(l)})
	}
	// Своя сверка до выдачи: раскрытия сходятся с листами хвостов.
	if b.LowerTails != nil {
		if _, err := proof.OpenTail(b.LowerTails.Chain(), source, b.LowerOpen); err != nil {
			return proof.SourceBundle{}, fmt.Errorf("store: lower tails of %s: %w", source, err)
		}
	}
	if _, err := proof.OpenTail(b.UpperTails.Leaf.Chain(), source, b.UpperOpen); err != nil {
		return proof.SourceBundle{}, fmt.Errorf("store: upper tails of %s: %w", source, err)
	}
	// Заявление — о последнем звене пакета; подписано при выдаче.
	tail := links[len(links)-1]
	b.Statement = s.signer.Sign(auditchain.Head{Seq: tail.Seq, Hash: auditchain.Hash(tail)}, int(tail.Seq), s.nowTime().Unix())
	return b, nil
}

// lastLeafBefore — последний лист улики источника раньше листа limit: номер
// записи и номер листа. Листья ложатся в порядке журнала улик, а не номеров,
// поэтому смотрятся все номера источника.
func (s *Store) lastLeafBefore(source string, limit uint64) (seq, leaf uint64, ok bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	st := s.sources[source]
	if st == nil {
		return 0, 0, false
	}
	s.chainMu.Lock()
	defer s.chainMu.Unlock()
	for q := uint64(1); q <= st.maxSeq; q++ {
		pos := st.seqs.get(q)
		if pos == 0 || pos > uint64(len(s.evLeaf)) || s.evLeaf[pos-1] == 0 {
			continue
		}
		if l := s.evLeaf[pos-1] - 1; l < limit && (!ok || l > leaf) {
			seq, leaf, ok = q, l, true
		}
	}
	return seq, leaf, ok
}

// placedLeaf — лист idx звена seq с путём Меркла и местом.
func placedLeaf(seq uint64, leaves []auditchain.Leaf, idx int) (proof.PlacedLeaf, error) {
	path, err := auditchain.MerkleProof(leaves, idx)
	if err != nil {
		return proof.PlacedLeaf{}, err
	}
	p := proof.PlacedLeaf{Inclusion: proof.Inclusion{Leaf: proof.FromLeaf(leaves[idx]), LinkSeq: seq}, Index: idx}
	for _, st := range path {
		p.Path = append(p.Path, proof.Step{Hash: st.Hash[:], Left: st.SiblingLeft})
	}
	return p, nil
}

// sealedWithKey — улика под листом и ключ её записи. Ключ месяца уничтожен
// или ждёт уничтожения — без ключа: улика доказывается, тело — нет.
func (s *Store) sealedWithKey(leaf auditchain.Leaf) ([]byte, []byte, error) {
	pos, _, err := proof.ParseEvidenceLeaf(leaf)
	if err != nil {
		return nil, nil, err
	}
	data, err := s.evlog.Read(pos)
	if err != nil {
		return nil, nil, err
	}
	sealed, err := evidence.Unmarshal(data)
	if err != nil {
		return nil, nil, err
	}
	dek, err := s.keys.UnwrapDEK(sealed.Envelope)
	switch {
	case err == nil:
		return data, dek, nil
	case errors.Is(err, keyring.ErrKeyDestroyed), errors.Is(err, keyring.ErrKeyPending):
		return data, nil, nil
	}
	return nil, nil, err
}
