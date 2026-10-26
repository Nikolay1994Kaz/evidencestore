package store

import (
	"errors"
	"fmt"
	"sort"
	"time"

	"github.com/Nikolay1994Kaz/evidencestore/internal/auditchain"
	"github.com/Nikolay1994Kaz/evidencestore/internal/evidence"
	"github.com/Nikolay1994Kaz/evidencestore/internal/keyring"
	"github.com/Nikolay1994Kaz/evidencestore/internal/proof"
)

// ErrWindow — пакет за окно не собрать: окно задано неверно, верхней метки
// ещё нет или листьев больше предела. Админка отвечает 400.
var ErrWindow = errors.New("store: window")

// maxWindowLeaves — предел листьев в пакете за окно: пакет собирается и
// отдаётся целиком в памяти. Больше — окно просят разбить. Переменная —
// чтобы тест проверил отказ без четверти миллиона записей.
var maxWindowLeaves uint64 = 250_000

// ProofWindow собирает пакет за окно (DECISIONS, п. 27): все листья цепи
// между двумя метками TSA. Нижняя — последняя, время которой раньше начала
// окна больше чем на секунду; верхняя — первая, время которой позже конца
// окна больше чем на минуту: по правилам времени приёма (proof.ReceiveSlack,
// ReceiveSkew) запись с временем в окне лежит между ними. Меток пакет не
// ставит, как и пакет одной улики.
//
// source — приложить улики этого источника с участка вместе с ключами
// записей (withDEK обязателен: без ключей они ничего не добавят). toHead —
// довести звенья не меньше чем до этой головы (свидетель).
//
// Под замком цепи — только индексы меток и звеньев; звенья и листья
// читаются с диска без него, каждый файл листьев — один раз (Z-11): они
// дописываются, но не меняются.
func (s *Store) ProofWindow(from, to time.Time, source string, withDEK bool, toHead uint64) (proof.WindowBundle, error) {
	switch {
	case from.IsZero() || to.IsZero():
		return proof.WindowBundle{}, fmt.Errorf("%w: both ends of the window are required", ErrWindow)
	case to.Before(from):
		return proof.WindowBundle{}, fmt.Errorf("%w: the window ends before it starts", ErrWindow)
	case withDEK && source == "":
		return proof.WindowBundle{}, fmt.Errorf("%w: record keys go with one source's records: name it with -source", ErrWindow)
	case source != "" && !withDEK:
		return proof.WindowBundle{}, fmt.Errorf("%w: -source attaches that source's records with their record keys: add -dek", ErrWindow)
	case s.tsaURL == "" && s.tsaLocal == nil:
		return proof.WindowBundle{}, fmt.Errorf("%w: the store has no TSA, and a window is bounded by time-stamps", ErrWindow)
	}
	if source != "" {
		s.mu.Lock()
		_, ok := s.sources[source]
		s.mu.Unlock()
		if !ok {
			return proof.WindowBundle{}, fmt.Errorf("%w: source %s", ErrNotFound, source)
		}
	}

	s.chainMu.Lock()
	if err := s.flushLocked(); err != nil {
		s.chainMu.Unlock()
		return proof.WindowBundle{}, err
	}
	upper := -1
	for i, t := range s.tokens {
		if t.gen.After(to.Add(proof.ReceiveSkew)) {
			upper = i
			break
		}
	}
	if upper < 0 {
		latest := "there is none yet"
		if n := len(s.tokens); n > 0 {
			latest = "the latest is " + s.tokens[n-1].gen.UTC().Format(time.RFC3339)
		}
		s.chainMu.Unlock()
		return proof.WindowBundle{}, fmt.Errorf("%w: no time-stamp after %s, a minute past the window (%s): the store takes one every tsa.every while records arrive and at least once an hour; evidencestore stamp takes one now if anything entered the chain since the last",
			ErrWindow, to.Add(proof.ReceiveSkew).UTC().Format(time.RFC3339), latest)
	}
	var lowerHead uint64
	for i := upper - 1; i >= 0; i-- {
		if s.tokens[i].gen.Before(from.Add(-proof.ReceiveSlack)) {
			lowerHead = s.tokens[i].head
			break
		}
	}
	end, ok := s.linkOfLocked(s.tokens[upper].leaf)
	var first uint64
	if lowerHead > 0 {
		i := sort.Search(len(s.links), func(i int) bool { return s.links[i].seq >= lowerHead })
		if i == len(s.links) || s.links[i].seq != lowerHead {
			ok = false
		} else {
			first = s.links[i].first + s.links[i].count
		}
	}
	head := s.chain.Head().Seq
	s.chainMu.Unlock()
	if !ok {
		return proof.WindowBundle{}, errors.New("store: the time-stamps of the window are not linked")
	}
	if n := end.first + end.count - first; n > maxWindowLeaves {
		return proof.WindowBundle{}, fmt.Errorf("%w: the window holds %d leaves, more than %d in one bundle: ask for shorter windows", ErrWindow, n, maxWindowLeaves)
	}
	last := end.seq
	if toHead > last {
		if toHead > head {
			return proof.WindowBundle{}, fmt.Errorf("store: head %d is not in the chain yet: the head is %d", toHead, head)
		}
		last = toHead
	}

	links, err := auditchain.ReadLinks(s.chainDir, max(lowerHead, 1), last)
	if err != nil {
		return proof.WindowBundle{}, err
	}
	leaves, err := auditchain.ReadLeafRange(s.chainDir, first, end.first+end.count)
	if err != nil {
		return proof.WindowBundle{}, err
	}
	b := proof.WindowBundle{
		Version: proof.WindowVersion, Kind: proof.WindowKind,
		From: from.UTC(), To: to.UTC(), LowerHead: lowerHead, StretchEnd: end.seq,
		Links: make([]proof.Link, len(links)), Leaves: make([]proof.Leaf, len(leaves)),
	}
	for i, l := range links {
		b.Links[i] = proof.FromLink(l)
	}
	for i, l := range leaves {
		b.Leaves[i] = proof.FromLeaf(l)
	}
	// Заявление — о последнем звене пакета; подписано при выдаче.
	tail := links[len(links)-1]
	b.Statement = s.signer.Sign(auditchain.Head{Seq: tail.Seq, Hash: auditchain.Hash(tail)}, int(tail.Seq), s.nowTime().Unix())
	if source != "" {
		if b.Records, err = s.windowRecords(leaves, source); err != nil {
			return proof.WindowBundle{}, err
		}
	}
	return b, nil
}

// windowRecords — улики источника с участка и ключи их записей. Ключ месяца
// уничтожен или ждёт уничтожения — улика идёт без ключа: пакет доказывает её
// существование и неизменность, только без тела.
func (s *Store) windowRecords(leaves []auditchain.Leaf, source string) ([]proof.WindowRecord, error) {
	var out []proof.WindowRecord
	for _, l := range leaves {
		if l.Type != auditchain.EventEvidence || l.Scope != source {
			continue
		}
		pos, _, err := proof.ParseEvidenceLeaf(l)
		if err != nil {
			return nil, err
		}
		data, err := s.evlog.Read(pos)
		if err != nil {
			return nil, err
		}
		sealed, err := evidence.Unmarshal(data)
		if err != nil {
			return nil, err
		}
		rec := proof.WindowRecord{Evidence: data}
		dek, err := s.keys.UnwrapDEK(sealed.Envelope)
		switch {
		case err == nil:
			rec.DEK = dek
		case errors.Is(err, keyring.ErrKeyDestroyed), errors.Is(err, keyring.ErrKeyPending):
		default:
			return nil, err
		}
		out = append(out, rec)
	}
	return out, nil
}
