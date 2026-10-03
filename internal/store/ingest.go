package store

import (
	"fmt"
	"time"

	"evidencestore/internal/auditchain"
	"evidencestore/internal/config"
	"evidencestore/internal/evidence"
	"evidencestore/internal/proof"
)

// MaxBatch — наибольшее число записей в одном приёме.
const MaxBatch = 512

// Incoming — запись от сборщика.
type Incoming struct {
	Seq  uint64
	Body []byte
}

// Result — итог по одной записи.
type Result struct {
	Seq      uint64
	Status   string // "accepted" — записана сейчас; "duplicate" — была принята раньше
	Position uint64
	Digest   [32]byte
	Promise  *proof.Promise // только у принятых сейчас
}

const (
	StatusAccepted  = "accepted"
	StatusDuplicate = "duplicate"
)

// Ingest принимает пачку записей источника. Источник берётся из
// клиентского сертификата (пакет server), никогда из тела запроса.
//
// Без ошибки — все записи пачки на диске (новые) или были там раньше
// (повторы). С ошибкой — ни одна новая запись не подтверждена; повтор той
// же пачки безопасен: принятые раньше ответят «duplicate».
func (s *Store) Ingest(source string, recs []Incoming) (_ []Result, err error) {
	defer func() {
		if err != nil {
			s.ingestErrors.Add(1)
		}
	}()
	if len(recs) == 0 {
		return nil, nil
	}
	if len(recs) > MaxBatch {
		return nil, fmt.Errorf("%w: %d records in one batch, at most %d", ErrBadRecord, len(recs), MaxBatch)
	}
	if err := s.Healthy(); err != nil {
		return nil, err
	}
	// Журнал гейтвея — по одной пачке: вердикт записи зависит от предыдущей,
	// и считать их надо в порядке журнала улик.
	s.mu.Lock()
	gst := s.sources[source]
	s.mu.Unlock()
	if gst != nil && gst.gw != nil {
		gst.gwMu.Lock()
		defer gst.gwMu.Unlock()
	}

	// 1. Под замком: повторы, резерв номеров, время приёма.
	results := make([]Result, len(recs))
	type fresh struct {
		i      int
		header evidence.Header
		body   []byte
	}
	var news []fresh
	s.mu.Lock()
	st, ok := s.sources[source]
	switch {
	case s.closed:
		s.mu.Unlock()
		return nil, ErrClosed
	case !ok || !st.known:
		s.mu.Unlock()
		return nil, fmt.Errorf("%w: %q", ErrUnknownSource, source)
	case st.cfg.Disabled:
		s.mu.Unlock()
		return nil, fmt.Errorf("%w: %q", ErrSourceDisabled, source)
	}
	seen := map[uint64]bool{}
	for i, r := range recs {
		var err error
		switch {
		case r.Seq == 0:
			err = fmt.Errorf("%w: seq must be > 0", ErrBadRecord)
		case seen[r.Seq]:
			err = fmt.Errorf("%w: seq %d twice in one batch", ErrBadRecord, r.Seq)
		case len(r.Body) > evidence.MaxBodyLen:
			err = fmt.Errorf("%w: body of seq %d is %d bytes, at most %d", ErrBadRecord, r.Seq, len(r.Body), evidence.MaxBodyLen)
		case st.inflight[r.Seq]:
			err = fmt.Errorf("%w: seq %d", ErrInFlight, r.Seq)
		}
		if err != nil {
			s.mu.Unlock()
			return nil, err
		}
		seen[r.Seq] = true
		results[i].Seq = r.Seq
		if pos := st.seqs.get(r.Seq); pos != 0 {
			results[i].Status, results[i].Position = StatusDuplicate, pos
			st.dups.Add(1)
			continue
		}
		news = append(news, fresh{i: i, header: evidence.Header{
			Source: source, Seq: r.Seq, ReceivedAt: s.clockLocked(), ContentType: st.cfg.ContentType,
		}, body: r.Body})
	}
	for _, n := range news {
		st.inflight[n.header.Seq] = true
	}
	s.mu.Unlock()

	release := func() {
		s.mu.Lock()
		for _, n := range news {
			delete(st.inflight, n.header.Seq)
		}
		s.mu.Unlock()
	}
	if len(news) == 0 {
		return results, nil
	}

	// 2. Печать вне замков: шифрование — самая дорогая часть пути.
	data := make([][]byte, len(news))
	for j, n := range news {
		if err := s.ensureScope(n.header.Scope()); err != nil {
			release()
			return nil, err
		}
		sealed, err := evidence.Record{Header: n.header, Body: n.body}.Seal(s.keys)
		if err != nil {
			release()
			return nil, err
		}
		if data[j], err = sealed.Marshal(); err != nil {
			release()
			return nil, err
		}
	}

	// 3. Журнал улик: вернулся без ошибки — на диске, листья уже в цепи.
	first, err := s.evlog.Append(data)
	if err != nil {
		release()
		return nil, err
	}

	// 3а. Журнал гейтвея: вердикты листами в цепь, в порядке журнала.
	if st.gw != nil {
		items := make([]gwItem, len(news))
		for j, n := range news {
			items[j] = gwItem{header: n.header, pos: first + uint64(j), body: n.body}
		}
		s.recordGateway(st, items)
	}

	// 4. Индекс принятых, пропуски номеров, обещания.
	mmd := s.cfg.Chain.PromiseMMD.D()
	s.mu.Lock()
	for j, n := range news {
		pos := first + uint64(j)
		delete(st.inflight, n.header.Seq)
		s.indexLocked(st, n.header, pos)
		r := &results[n.i]
		r.Status, r.Position, r.Digest = StatusAccepted, pos, evidence.Digest(data[j])
		p := proof.Promise{
			Source: source, Seq: n.header.Seq, Position: pos, Digest: r.Digest[:],
			ReceivedAt: n.header.ReceivedAt, Deadline: n.header.ReceivedAt + int64(mmd),
			PublicKey: s.signer.PublicKeyString(),
		}
		p.Signature = s.signer.SignMessage(proof.PromiseBytes(p))
		r.Promise = &p
	}
	gaps := st.takeGaps()
	s.mu.Unlock()
	for _, g := range gaps {
		s.appendJSONEvent(auditchain.EventGap, source, "", g)
		s.log.Warn("sequence gap", "source", source, "from", g.From, "to", g.To)
	}
	return results, nil
}

// gap — пропуск номеров: записи [From, To] источник не прислал.
type gap struct {
	From uint64 `json:"from"`
	To   uint64 `json:"to"`
}

// indexRecord — индекс принятой улики при подъёме журнала.
func (s *Store) indexRecord(h evidence.Header, pos uint64) {
	s.mu.Lock()
	defer s.mu.Unlock()
	st, ok := s.sources[h.Source]
	if !ok {
		// Источник выведен из реестра, а его улики остались: хранить и
		// выдавать доказательства — да, принимать новые — нет.
		st = &sourceState{cfg: config.Source{Name: h.Source, Disabled: true}, inflight: map[uint64]bool{}}
		s.sources[h.Source] = st
	}
	s.indexLocked(st, h, pos)
	st.pendingGaps = nil // на подъёме пропуски не переобъявляются: они уже в цепи
}

func (s *Store) indexLocked(st *sourceState, h evidence.Header, pos uint64) {
	st.seqs.set(h.Seq, pos)
	st.count++
	if t := time.Unix(0, h.ReceivedAt); t.After(st.lastAt) {
		st.lastAt = t
	}
	st.silent = false
	if h.Seq > st.maxSeq {
		// Пропуск — номера между прежним максимумом и этим, которых нет и
		// которые не пишутся прямо сейчас другим запросом.
		lo, hi := st.maxSeq+1, h.Seq-1
		switch {
		case lo > hi:
		case hi-lo+1 > maxGapScan:
			st.pendingGaps = append(st.pendingGaps, gap{lo, hi}) // огромный прыжок: целиком
		default:
			var from uint64
			for q := lo; q <= hi; q++ {
				missing := st.seqs.get(q) == 0 && !st.inflight[q]
				switch {
				case missing && from == 0:
					from = q
				case !missing && from != 0:
					st.pendingGaps = append(st.pendingGaps, gap{from, q - 1})
					from = 0
				}
			}
			if from != 0 {
				st.pendingGaps = append(st.pendingGaps, gap{from, hi})
			}
		}
		st.maxSeq = h.Seq
	}
}

// maxGapScan — сколько номеров пропуска перебирать поштучно.
const maxGapScan = 1 << 16

func (st *sourceState) takeGaps() []gap {
	g := st.pendingGaps
	st.pendingGaps = nil
	return g
}

// LastSeq — наибольший принятый номер источника: сборщик после
// переустановки продолжает отсюда, а не с единицы.
func (s *Store) LastSeq(source string) (uint64, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	st, ok := s.sources[source]
	if !ok || !st.known {
		return 0, fmt.Errorf("%w: %q", ErrUnknownSource, source)
	}
	return st.maxSeq, nil
}

// seqIndex — номер у источника → позиция в журнале. Номера идут подряд,
// поэтому хранятся плотными кусками, а не картой: 8 байт на запись.
type seqIndex struct {
	chunks map[uint64]*[seqChunk]uint64
}

const seqChunk = 4096

func (x *seqIndex) get(seq uint64) uint64 {
	if x.chunks == nil {
		return 0
	}
	c := x.chunks[seq/seqChunk]
	if c == nil {
		return 0
	}
	return c[seq%seqChunk]
}

func (x *seqIndex) set(seq, pos uint64) {
	if x.chunks == nil {
		x.chunks = map[uint64]*[seqChunk]uint64{}
	}
	c := x.chunks[seq/seqChunk]
	if c == nil {
		c = new([seqChunk]uint64)
		x.chunks[seq/seqChunk] = c
	}
	c[seq%seqChunk] = pos
}
