package store

import (
	"bytes"
	"errors"
	"fmt"
	"maps"
	"slices"
	"strings"
	"time"

	"evidencestore/internal/auditchain"
	"evidencestore/internal/config"
	"evidencestore/internal/evidence"
	"evidencestore/internal/keyring"
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
	Status   string
	Position uint64
	Digest   [32]byte
	Promise  *proof.Promise
}

const (
	// StatusAccepted — записана сейчас.
	StatusAccepted = "accepted"
	// StatusDuplicate — это же тело принято раньше. Обещание — то же, что
	// при приёме: сборщик, упавший до записи обещания, получает его на повторе.
	StatusDuplicate = "duplicate"
)

// Ingest принимает пачку записей источника. Источник берётся из
// клиентского сертификата (пакет server), никогда из тела запроса.
//
// Без ошибки — все записи пачки на диске (новые) или были там раньше с тем
// же телом (повторы). С ошибкой — ни одна новая запись не подтверждена;
// повтор той же пачки безопасен: принятые раньше ответят «duplicate».
// Номер, занятый другим телом, — ErrSeqConflict для всей пачки.
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
	if err := s.anchored(); err != nil {
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
	var dups []int // номер уже занят: тело сверяется вне замка
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
			results[i].Position = pos
			dups = append(dups, i)
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
	// 1а. Повторы номера: то же ли тело. Конфликт отвергает пачку целиком:
	// иначе записи второго сборщика легли бы вперемешку с записями первого.
	var conflicts []string
	for _, i := range dups {
		reason, err := s.checkDuplicate(st, recs[i], &results[i])
		if err != nil {
			release()
			return nil, err
		}
		if reason != "" {
			conflicts = append(conflicts, fmt.Sprintf("seq %d: %s", recs[i].Seq, reason))
		}
	}
	if len(conflicts) > 0 {
		release()
		return nil, fmt.Errorf("%w: source %q: %s", ErrSeqConflict, source, strings.Join(conflicts, "; "))
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
	s.mu.Lock()
	for j, n := range news {
		pos := first + uint64(j)
		delete(st.inflight, n.header.Seq)
		s.indexLocked(st, n.header, pos)
		r := &results[n.i]
		r.Status, r.Position, r.Digest = StatusAccepted, pos, evidence.Digest(data[j])
		p := s.promise(n.header, pos, r.Digest)
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

// promise — подписанное обещание по принятой улике. Ed25519 детерминирован:
// пока promise_mmd не менялся, повтор получает те же байты, что приём.
func (s *Store) promise(h evidence.Header, pos uint64, digest [32]byte) proof.Promise {
	p := proof.Promise{
		Source: h.Source, Seq: h.Seq, Position: pos, Digest: digest[:],
		ReceivedAt: h.ReceivedAt, Deadline: h.ReceivedAt + int64(s.cfg.Chain.PromiseMMD.D()),
		PublicKey: s.signer.PublicKeyString(),
	}
	p.Signature = s.signer.SignMessage(proof.PromiseBytes(p))
	return p
}

// checkDuplicate — номер уже занят (позиция — в res). Тело сверяется с
// принятым: оно вскрывается ключом месяца. То же тело — «duplicate» с
// обещанием, reason пуст. Иначе reason — почему повтор не принят: другое
// тело (сборщик откатили к старой копии или второй сборщик с тем же
// сертификатом) или тело нечем сверить (ключ месяца ждёт уничтожения или
// уничтожен); событие — в цепи.
func (s *Store) checkDuplicate(st *sourceState, r Incoming, res *Result) (reason string, _ error) {
	data, err := s.evlog.Read(res.Position)
	if err != nil {
		return "", err
	}
	sealed, err := evidence.Unmarshal(data)
	if err != nil {
		return "", fmt.Errorf("evidence log position %d: %w", res.Position, err)
	}
	res.Digest = evidence.Digest(data)
	body, err := sealed.Open(s.keys)
	switch {
	case err == nil && bytes.Equal(body, r.Body):
		res.Status = StatusDuplicate
		p := s.promise(sealed.Header, res.Position, res.Digest)
		res.Promise = &p
		st.dups.Add(1)
		return "", nil
	case err == nil:
		reason = "another body under a taken seq: the collector was rolled back to an old copy, or another collector uses the source certificate"
	case errors.Is(err, keyring.ErrKeyPending):
		reason = "the accepted body is sealed under a month key pending destruction and cannot be compared (cancelling the destruction lets the resend through)"
	case errors.Is(err, keyring.ErrKeyDestroyed):
		reason = "the accepted body is erased (month key destroyed) and cannot be compared"
	default:
		return "", err
	}
	st.conflicts.Add(1)
	s.log.Error("seq conflict", "source", sealed.Source, "seq", r.Seq, "position", res.Position, "reason", reason)
	s.appendJSONEvent(auditchain.EventConflict, sealed.Source, "", seqConflict{Seq: r.Seq, Position: res.Position, Reason: reason})
	return reason, nil
}

// seqConflict — событие в цепи: под занятым номером пришло другое тело.
type seqConflict struct {
	Seq      uint64 `json:"seq"`
	Position uint64 `json:"position"` // принятая улика с этим номером
	Reason   string `json:"reason"`
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
		st.pendingGaps = append(st.pendingGaps, st.gapsIn(st.maxSeq+1, h.Seq-1)...)
		st.maxSeq = h.Seq
	}
}

// gapsIn — отрезки номеров из [lo, hi], которых нет в индексе и которые не
// пишутся сейчас. Огромный прыжок — одним отрезком, без перебора.
func (st *sourceState) gapsIn(lo, hi uint64) []gap {
	switch {
	case lo > hi:
		return nil
	case hi-lo+1 > maxGapScan:
		return []gap{{lo, hi}}
	}
	var out []gap
	var from uint64
	for q := lo; q <= hi; q++ {
		missing := st.seqs.get(q) == 0 && !st.inflight[q]
		switch {
		case missing && from == 0:
			from = q
		case !missing && from != 0:
			out = append(out, gap{from, q - 1})
			from = 0
		}
	}
	if from != 0 {
		out = append(out, gap{from, hi})
	}
	return out
}

// announceTailGaps объявляет пропуски у улик, которые не успели лечь в цепь
// до падения: событие о пропуске жило в памяти и пропало вместе с
// процессом. Считается по индексу после подъёма всего журнала: номер, которого
// нет между последним номером источника в цепи и наибольшим принятым, —
// пропуск.
func (s *Store) announceTailGaps(chainedMax map[string]uint64, tailSources map[string]bool) {
	type ev struct {
		source string
		g      gap
	}
	var evs []ev
	s.mu.Lock()
	for _, name := range slices.Sorted(maps.Keys(tailSources)) {
		if st := s.sources[name]; st != nil {
			for _, g := range st.gapsIn(chainedMax[name]+1, st.maxSeq) {
				evs = append(evs, ev{name, g})
			}
		}
	}
	s.mu.Unlock()
	for _, e := range evs {
		s.appendJSONEvent(auditchain.EventGap, e.source, "", e.g)
		s.log.Warn("sequence gap (found on restart)", "source", e.source, "from", e.g.From, "to", e.g.To)
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
// поэтому хранятся плотными кусками по 4096: 8 байт на запись. Кусок
// начинается картой и становится массивом, когда в нём набирается
// seqDenseAt номеров: номера вразброс (1, 4097, 8193, …) не стоят по 32 КиБ.
type seqIndex struct {
	chunks map[uint64]*seqChunkIdx
}

type seqChunkIdx struct {
	dense  *[seqChunk]uint64
	sparse map[uint16]uint64
}

const (
	seqChunk   = 4096
	seqDenseAt = 256
)

func (x *seqIndex) get(seq uint64) uint64 {
	c := x.chunks[seq/seqChunk]
	switch {
	case c == nil:
		return 0
	case c.dense != nil:
		return c.dense[seq%seqChunk]
	}
	return c.sparse[uint16(seq%seqChunk)]
}

func (x *seqIndex) set(seq, pos uint64) {
	if x.chunks == nil {
		x.chunks = map[uint64]*seqChunkIdx{}
	}
	c := x.chunks[seq/seqChunk]
	if c == nil {
		c = &seqChunkIdx{sparse: map[uint16]uint64{}}
		x.chunks[seq/seqChunk] = c
	}
	if c.dense != nil {
		c.dense[seq%seqChunk] = pos
		return
	}
	c.sparse[uint16(seq%seqChunk)] = pos
	if len(c.sparse) >= seqDenseAt {
		c.dense = new([seqChunk]uint64)
		for i, p := range c.sparse {
			c.dense[i] = p
		}
		c.sparse = nil
	}
}
