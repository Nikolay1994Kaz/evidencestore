package store

import (
	"errors"
	"fmt"
	"sort"
	"strconv"
	"time"

	"github.com/Nikolay1994Kaz/evidencestore/internal/auditchain"
	"github.com/Nikolay1994Kaz/evidencestore/internal/evidence"
	"github.com/Nikolay1994Kaz/evidencestore/internal/gateway"
	"github.com/Nikolay1994Kaz/evidencestore/internal/keyring"
	"github.com/Nikolay1994Kaz/evidencestore/internal/proof"
)

// ProofSource собирает пакет по источнику за окно (DECISIONS, п. 28): все
// записи источника между нижними и верхними хвостами, с путями Меркла —
// чужие листья в них только хэшами. Нижняя метка — последняя раньше начала
// окна больше чем на секунду, её хвосты — нижний край; закрывающая — первая
// позже конца больше чем на proof.WindowEdge, её токен лежит в пакете;
// верхний край — хвосты следующей метки, после этого токена. withDEK —
// приложить улики с ключами записей; toHead — довести звенья до этой головы
// (свидетель).
//
// Окно, край которого приходится на метку без хвостов источников
// (хранилище обновилось позже), или записи в нём без ссылок — отказ: такое
// окно отвечает только пакет за окно.
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
	closing := -1
	for i, t := range s.tokens {
		if t.gen.After(to.Add(proof.WindowEdge)) {
			closing = i
			break
		}
	}
	if closing < 0 {
		s.chainMu.Unlock()
		return proof.SourceBundle{}, fmt.Errorf("%w: no time-stamp after %s, %s past the window, yet: the store takes one every tsa.every while records arrive and at least once an hour",
			ErrWindow, to.Add(proof.WindowEdge).UTC().Format(time.RFC3339), proof.WindowEdge)
	}
	// Верхний край — хвосты первой метки, заверившей звено после токена
	// закрывающей: всё, что легло в цепь до её времени, — до них (п. 28).
	// Хвосты самой закрывающей лежат до её токена, и нижней границы времени у
	// них нет: метку над ними можно взять когда угодно и дописать в цепь —
	// такой токен над звеном до закрывающего здесь и пропускается.
	cl := s.tokens[closing]
	clTok, cok := s.linkOfLocked(cl.leaf)
	upper := -1
	for i := closing + 1; i < len(s.tokens); i++ {
		if s.tokens[i].head > clTok.seq {
			upper = i
			break
		}
	}
	if upper < 0 {
		s.chainMu.Unlock()
		return proof.SourceBundle{}, fmt.Errorf("%w: the window is closed by the time-stamp of %s, and a one-source bundle ends at the source tails of the time-stamp after it, not taken yet: the store takes one every tsa.every while records arrive and at least once an hour; evidencestore stamp takes one at once",
			ErrWindow, cl.gen.UTC().Format(time.RFC3339))
	}
	lower := -1
	for i := closing - 1; i >= 0; i-- {
		if s.tokens[i].gen.Before(from.Add(-proof.ReceiveSlack)) {
			lower = i
			break
		}
	}
	linkAt := func(seq uint64) (linkRef, bool) {
		i := sort.Search(len(s.links), func(i int) bool { return s.links[i].seq >= seq })
		if i == len(s.links) || s.links[i].seq != seq {
			return linkRef{}, false
		}
		return s.links[i], true
	}
	up := s.tokens[upper]
	top, ok := linkAt(up.head)
	// Звено токена верхней метки: пакет доходит до него — токен края лежит
	// в цепи листом (п. 28).
	upTok, tok := s.linkOfLocked(up.leaf)
	ok = ok && tok && cok
	var low linkRef
	var lowTok uint64
	if lower >= 0 {
		lowTok = s.tokens[lower].leaf
		var lok bool
		low, lok = linkAt(s.tokens[lower].head)
		ok = ok && lok
	}
	head := s.chain.Head().Seq
	s.chainMu.Unlock()
	if !ok {
		return proof.SourceBundle{}, errors.New("store: the time-stamps of the window are not linked")
	}
	first, end := low.first, upTok.first+upTok.count
	if end-first > maxWindowLeaves {
		return proof.SourceBundle{}, fmt.Errorf("%w: the window spans %d leaves of the chain, more than %d in one bundle: ask for shorter windows", ErrWindow, end-first, maxWindowLeaves)
	}
	last := upTok.seq
	if toHead > last {
		if toHead > head {
			return proof.SourceBundle{}, fmt.Errorf("store: head %d is not in the chain yet: the head is %d", toHead, head)
		}
		last = toHead
	}

	links, err := auditchain.ReadLinks(s.chainDir, max(low.seq, 1), last)
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
	// linkRec — прочитанное звено по номеру.
	linkRec := func(seq uint64) auditchain.Record { return links[seq-links[0].Seq] }
	// edge — край пакета: звено хвостов и лист токена метки над ним с путём
	// Меркла (токен лежит в цепи позже звена хвостов).
	edge := func(l auditchain.Record, tokLeaf uint64, which string) (proof.SourceEdge, error) {
		ls, err := leavesOf(l)
		if err != nil {
			return proof.SourceEdge{}, err
		}
		if len(ls) != 1 || ls[0].Type != auditchain.EventTails {
			return proof.SourceEdge{}, fmt.Errorf("%w: the time-stamp %s the window was taken before the store laid source tails at time-stamps: ask for a later window, or for a window bundle (proof -window)", ErrWindow, which)
		}
		s.chainMu.Lock()
		tl, ok := s.linkOfLocked(tokLeaf)
		s.chainMu.Unlock()
		if !ok {
			return proof.SourceEdge{}, errors.New("store: the token of a time-stamp is not linked")
		}
		tls, err := leavesOf(linkRec(tl.seq))
		if err != nil {
			return proof.SourceEdge{}, err
		}
		inc, err := inclusionAt(tl.seq, tls, int(tokLeaf-tl.first))
		if err != nil {
			return proof.SourceEdge{}, err
		}
		tails := proof.FromLeaf(ls[0])
		return proof.SourceEdge{Head: l.Seq, Tails: &tails, Token: inc}, nil
	}

	b := proof.SourceBundle{Version: proof.WindowVersion, Kind: proof.SourceKind, Source: source,
		From: from.UTC(), To: to.UTC()}
	for _, l := range links {
		b.Links = append(b.Links, proof.FromLink(l))
	}
	if lower >= 0 {
		if b.Lower, err = edge(links[0], lowTok, "before"); err != nil {
			return proof.SourceBundle{}, err
		}
	}
	if b.Upper, err = edge(linkRec(top.seq), up.leaf, "after"); err != nil {
		return proof.SourceBundle{}, err
	}
	cls, err := leavesOf(linkRec(clTok.seq))
	if err != nil {
		return proof.SourceBundle{}, err
	}
	if b.Closing, err = inclusionAt(clTok.seq, cls, int(cl.leaf-clTok.first)); err != nil {
		return proof.SourceBundle{}, err
	}
	verdicts := map[uint64]proof.Inclusion{}
	for _, l := range links {
		if l.Seq <= low.seq || l.Seq >= top.seq {
			continue
		}
		ls, err := leavesOf(l)
		if err != nil {
			return proof.SourceBundle{}, err
		}
		for idx, leaf := range ls {
			if leaf.Scope != source {
				continue
			}
			switch leaf.Type {
			case auditchain.EventEvidence:
				if _, linked := proof.EvidencePrev(leaf); !linked {
					return proof.SourceBundle{}, fmt.Errorf("%w: records of %s in this window were written before the store linked them: ask for a window bundle (proof -window)", ErrWindow, source)
				}
				rec := proof.SourceRecord{}
				if rec.Leaf, err = inclusionAt(l.Seq, ls, idx); err != nil {
					return proof.SourceBundle{}, err
				}
				if withDEK {
					if rec.Evidence, rec.DEK, err = s.sealedWithKey(leaf); err != nil {
						return proof.SourceBundle{}, err
					}
				}
				b.Records = append(b.Records, rec)
			case auditchain.EventGateway:
				pos, _, err := proof.ParseGatewayLeaf(leaf)
				if err != nil {
					return proof.SourceBundle{}, fmt.Errorf("store: %w", err)
				}
				if verdicts[pos], err = inclusionAt(l.Seq, ls, idx); err != nil {
					return proof.SourceBundle{}, err
				}
			}
		}
	}
	// Вердикт — к своей записи: запись журнала гейтвея без него esverify не
	// примет.
	for i, rec := range b.Records {
		pos, _, err := proof.ParseEvidenceLeaf(rec.Leaf.Leaf.Chain())
		if err != nil {
			return proof.SourceBundle{}, err
		}
		if v, ok := verdicts[pos]; ok {
			b.Records[i].Verdict = &v
		}
	}
	// Раскрытия хвостов своего источника: внизу — его последний лист до
	// нижних хвостов, вверху — последняя запись в пакете или тот же лист;
	// соли — свои у каждого листа хвостов. Вид — каким он был при метке:
	// конфиг источника могли сменить, и тогда проверка назовёт смену вида.
	open := func(tails *proof.Leaf, t proof.Tail) *proof.TailOpen {
		for _, kind := range []string{s.tailKind(source), "", gateway.ContentType} {
			t.Kind = kind
			if o := proof.TailOf(t); tails != nil {
				if _, err := proof.OpenTail(tails.Chain(), source, o); err == nil {
					return o
				}
			}
		}
		t.Kind = s.tailKind(source)
		return proof.TailOf(t)
	}
	var tail *proof.Tail
	if lower >= 0 {
		if seq, num, found := s.lastLeafBefore(source, low.first); found {
			ls, err := auditchain.ReadLeaves(s.chainDir, num, 1)
			if err != nil {
				return proof.SourceBundle{}, err
			}
			tail = &proof.Tail{Source: source, Seq: seq, Hash: auditchain.LeafHash(ls[0]), Salt: s.tailSalt(low.first, source), Kind: s.tailKind(source)}
			b.Lower.Open = open(b.Lower.Tails, *tail)
		}
	}
	if n := len(b.Records); n > 0 {
		l := b.Records[n-1].Leaf.Leaf.Chain()
		seq, _ := strconv.ParseUint(l.Subject, 10, 64)
		tail = &proof.Tail{Source: source, Seq: seq, Hash: auditchain.LeafHash(l), Kind: s.tailKind(source)}
	}
	if tail != nil {
		tail.Salt = s.tailSalt(top.first, source)
		b.Upper.Open = open(b.Upper.Tails, *tail)
	}
	// Своя сверка до выдачи: раскрытия сходятся с листами хвостов.
	if b.Lower.Tails != nil {
		if _, err := proof.OpenTail(b.Lower.Tails.Chain(), source, b.Lower.Open); err != nil {
			return proof.SourceBundle{}, fmt.Errorf("store: lower tails of %s: %w", source, err)
		}
	}
	if _, err := proof.OpenTail(b.Upper.Tails.Chain(), source, b.Upper.Open); err != nil {
		return proof.SourceBundle{}, fmt.Errorf("store: upper tails of %s: %w", source, err)
	}
	// Заявление — о последнем звене пакета; подписано при выдаче.
	tailLink := links[len(links)-1]
	b.Statement = s.signer.Sign(auditchain.Head{Seq: tailLink.Seq, Hash: auditchain.Hash(tailLink)}, int(tailLink.Seq), s.nowTime().Unix())
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
	st.seqs.each(func(q, pos uint64) {
		if pos == 0 || pos > uint64(len(s.evLeaf)) || s.evLeaf[pos-1] == 0 {
			return
		}
		if l := s.evLeaf[pos-1] - 1; l < limit && (!ok || l > leaf) {
			seq, leaf, ok = q, l, true
		}
	})
	return seq, leaf, ok
}

// inclusionAt — лист idx звена seq с путём Меркла.
func inclusionAt(seq uint64, leaves []auditchain.Leaf, idx int) (proof.Inclusion, error) {
	path, err := auditchain.MerkleProof(leaves, idx)
	if err != nil {
		return proof.Inclusion{}, err
	}
	inc := proof.Inclusion{Leaf: proof.FromLeaf(leaves[idx]), LinkSeq: seq}
	for _, st := range path {
		inc.Path = append(inc.Path, proof.Step{Hash: st.Hash[:], Left: st.SiblingLeft})
	}
	return inc, nil
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
