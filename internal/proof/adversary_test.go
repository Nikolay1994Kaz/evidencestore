package proof

import (
	"cmp"
	"encoding/base64"
	"fmt"
	mrand "math/rand/v2"
	"os"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/Nikolay1994Kaz/evidencestore/internal/auditchain"
	"github.com/Nikolay1994Kaz/evidencestore/internal/evidence"
)

// Симуляция нечестного владельца (DECISIONS, «Когда разбор заканчивается»:
// класс находки — в постоянную проверку; заход 27.10, третий).
//
// Владелец держит ключ подписи и пишет код хранилища сам: придерживает
// записи и токены, дописывает копии старых токенов и токены, взятые позже над
// старыми головами, ставит звеньям самое раннее время, какое пропускают
// проверки, сдвигает время приёма вперёд в пределах, которые сверяет
// сборщик, пишет себе срок обещания (Q-57) и сам выбирает метки и края
// пакетов. Не может одного — переписать цепь под метками TSA; хвосты
// источников у него честные (их ложь названа в README, Not proven).
// Правило: запись, принятая в окне (по настоящему времени, с запасом на
// отставание и сдвиг времени приёма), есть в сводке каждого проходящего
// пакета за это окно и по источнику или названа в нём дырой — либо esverify
// -promise по её пакету показывает опоздание, какую бы T1 владелец ни
// предъявил.
//
// Половина сценариев — целевая атака: всё честно, кроме одной записи, которую
// владелец придерживает за метку, закрывающую окно вокруг неё, и прикрывает
// копией старого токена или заранее взятым и придержанным токеном.
//
// ADVSIM_SEEDS — сценариев, ADVSIM_SEED — один сценарий, ADVSIM_SHIFT — на
// сколько владелец сдвигает время приёма вперёд (по умолчанию — допуск, с
// которым время приёма в обещании сверяет сборщик: больший сдвиг сборщик
// выдаёт сам).

// ownerTolerance — сдвиг времени приёма, который сборщик не выдаёт:
// collector.receiveAhead по его часам, а они спешат до минуты (README) — до
// двух минут (Q-60). На него сужено окно, записи которого обязаны быть
// видны.
const ownerTolerance = 2 * time.Minute

func TestOwnerSim(t *testing.T) {
	seeds := 8 // в гейте; длинный прогон — ADVSIM_SEEDS=2000
	if v, err := strconv.Atoi(os.Getenv("ADVSIM_SEEDS")); err == nil && v > 0 {
		seeds = v
	}
	shift := ownerTolerance
	if v, err := time.ParseDuration(os.Getenv("ADVSIM_SHIFT")); err == nil {
		shift = v
	}
	only, single := os.LookupEnv("ADVSIM_SEED")
	failed, hidden := 0, 0
	var st ownerStats
	for i := range seeds {
		seed := uint64(i) + 1
		if single {
			if i > 0 {
				break
			}
			seed, _ = strconv.ParseUint(only, 10, 64)
		}
		msg, h := runOwnerSim(t, seed, shift, &st)
		hidden += h
		if msg != "" {
			failed++
			if failed <= 3 {
				t.Errorf("ADVSIM_SEED=%d:\n%s", seed, msg)
			}
		}
	}
	t.Logf("сценариев %d; окон %d, записей окна %d, проходящих пакетов за окно %d и по источнику %d, пакетов без записи окна %d — их выдало обещание: %d", seeds, st.windows, st.wanted, st.valid, st.validSource, st.missing, hidden)
	if failed > 0 {
		t.Errorf("провалено %d из %d сценариев", failed, seeds)
	}
}

type ownerRec struct {
	seq        uint64
	got, recv  time.Time // настоящее время приёма и время приёма в улике
	data       []byte
	digest     [32]byte
	link       uint64 // звено с листом улики; ноль — ещё не в цепи
	idx        int
	prev, hash [32]byte // ссылка листа на прежнюю запись и хэш самого листа
	promise    Promise
}

// ownerTail — звено хвостов перед честной меткой: хвост abs-core к этому
// месту цепи (has — записи уже были).
type ownerTail struct {
	leaf auditchain.Leaf
	tail Tail
	has  bool
}

type ownerTok struct {
	head    uint64
	gen     time.Time
	payload []byte
}

// ownerLeaf — лист, ожидающий звена или придержанный: улика или токен.
type ownerLeaf struct {
	until time.Time // придержан до этого момента
	leaf  auditchain.Leaf
	rec   *ownerRec
	tok   *ownerTok
}

// placedTok — лист токена в цепи: звено и место в нём.
type placedTok struct {
	ownerTok
	link uint64
	idx  int
}

type ownerSim struct {
	focused bool // целевая атака: прочие записи — честно
	stats   *ownerStats
	rng     *mrand.Rand
	w       *world
	start   time.Time
	shift   time.Duration
	seq     uint64
	recs    []*ownerRec
	toks    []*ownerTok // взятые токены
	pending []ownerLeaf
	held    []ownerLeaf
	placed  []placedTok
	last    Tail                   // последняя запись abs-core в цепи
	tails   map[uint64]ownerTail   // звено хвостов → хвост
	byHash  map[[32]byte]*ownerRec // хэш листа записи → запись
	trace   []string
}

func (s *ownerSim) note(format string, args ...any) {
	s.trace = append(s.trace, s.w.now.Format("15:04:05")+" "+fmt.Sprintf(format, args...))
}

// ownerStats — сколько всего проверено: без них зелёная симуляция ничего не
// говорит.
type ownerStats struct{ windows, wanted, valid, validSource, missing int }

func runOwnerSim(t *testing.T, seed uint64, shift time.Duration, st *ownerStats) (string, int) {
	s := &ownerSim{rng: mrand.New(mrand.NewPCG(seed, seed^0x51ed270b)), w: newWorld(t), shift: shift, stats: st,
		tails: map[uint64]ownerTail{}, byHash: map[[32]byte]*ownerRec{}}
	s.start = s.w.now
	s.w.wlink(auditchain.Leaf{Type: auditchain.EventStart})
	var target *ownerRec
	if s.rng.IntN(2) == 0 {
		s.focused = true
		target = s.attack()
	} else {
		for range 90 {
			s.step()
		}
	}
	// Конец: всё придержанное ложится, две метки закрывают последние окна.
	for len(s.held) > 0 {
		s.w.now = s.w.now.Add(time.Minute)
		s.release()
	}
	for range 2 {
		s.w.now = s.w.now.Add(3 * time.Minute)
		s.flush()
		s.tailsLink()
		s.stamp(uint64(len(s.w.links)), false)
		s.flush()
	}
	var bad []string
	hidden := 0
	for range 4 {
		b, h := s.checkWindow(target)
		bad = append(bad, b...)
		hidden += h
	}
	// Q-76 (заход 1 нового цикла, 28.10): правило README прямо — запись,
	// легшая после токена метки со временем позже минуты от её времени
	// приёма, проваливает -promise с
	// любым пакетом, какой может выдать владелец (любая T1, любая версия),
	// даже если пакеты за окно при этом не проходят.
	bad = append(bad, s.checkLate()...)
	if len(bad) == 0 {
		return "", hidden
	}
	return strings.Join(bad[:min(len(bad), 3)], "\n") + "\nход:\n  " + strings.Join(s.trace[max(0, len(s.trace)-60):], "\n  "), hidden
}

func (s *ownerSim) step() {
	s.release()
	switch r := s.rng.IntN(100); {
	case r < 30:
		d := []time.Duration{time.Second, 5 * time.Second, 20 * time.Second, time.Minute, 3 * time.Minute}[s.rng.IntN(5)]
		s.w.now = s.w.now.Add(d)
	case r < 55:
		s.receive(false)
	case r < 65:
		s.flush()
	case r < 80:
		if s.rng.IntN(5) > 0 {
			// Честная метка сворачивает хвост и кладёт хвосты; нечестная — нет.
			s.flush()
			s.tailsLink()
		}
		s.stamp(uint64(len(s.w.links)), true)
	case r < 87:
		// Токен над старой головой — взятый сейчас.
		s.stamp(1+uint64(s.rng.IntN(len(s.w.links))), true)
	case r < 94:
		// Копия листа токена, уже лежащего в цепи.
		if len(s.placed) > 0 {
			p := s.placed[s.rng.IntN(len(s.placed))]
			tok := p.ownerTok
			s.pending = append(s.pending, ownerLeaf{leaf: tokenLeaf(tok.head, tok.payload), tok: &tok})
			s.note("копия токена над головой %d (%s)", tok.head, tok.gen.Format("15:04:05"))
			s.flush()
		}
	default:
		// Придержанный токен — в цепь сейчас.
		if len(s.toks) > 0 {
			tok := s.toks[s.rng.IntN(len(s.toks))]
			s.pending = append(s.pending, ownerLeaf{leaf: tokenLeaf(tok.head, tok.payload), tok: tok})
			s.note("токен над головой %d (%s) ещё раз", tok.head, tok.gen.Format("15:04:05"))
		}
	}
}

// attack — целевая атака на одну запись X. До X владелец честен: записи
// ложатся сразу, метки — с хвостом и токеном сразу. Перед приёмом X он может
// взять токен над текущей головой и придержать его. X придерживается за
// несколько честных меток (одна из них закроет окно вокруг X), потом
// владелец кладёт перед X копию старого токена, придержанный токен или
// свежий токен над старой головой, и саму X; звенья — с самым ранним
// временем, какое пропускают проверки.
func (s *ownerSim) attack() *ownerRec {
	honest := func(n int) {
		for range n {
			switch r := s.rng.IntN(100); {
			case r < 40:
				s.w.now = s.w.now.Add([]time.Duration{time.Second, 10 * time.Second, 30 * time.Second, time.Minute}[s.rng.IntN(4)])
			case r < 75:
				s.receive(false)
			case r < 85:
				s.flush()
			default:
				s.flush()
				s.tailsLink()
				s.stamp(uint64(len(s.w.links)), false)
			}
		}
	}
	honest(25 + s.rng.IntN(20))
	var early *ownerTok
	if s.rng.IntN(2) == 0 {
		// Токен над текущей головой — в кармане до атаки.
		s.flush()
		if s.rng.IntN(2) == 0 {
			s.tailsLink()
		}
		head := uint64(len(s.w.links))
		imprint := HeadImprint(head, auditchain.Hash(s.w.links[head-1]))
		payload, err := s.w.tsa.Sign(imprint[:], nil)
		if err != nil {
			s.w.t.Fatal(err)
		}
		early = &ownerTok{head: head, gen: s.w.now, payload: payload}
		s.note("токен над головой %d взят и придержан", head)
	}
	s.w.now = s.w.now.Add(time.Duration(s.rng.Int64N(int64(30 * time.Second))))
	x := s.receive(true)
	// Честные метки после X: X ляжет сразу за той, что позже X на 2–8 минут
	// (её могут взять закрывающей окна вокруг X), или после 12 минут меток.
	hold := 12 * time.Minute
	if s.rng.IntN(2) == 0 {
		hold = 2*time.Minute + time.Duration(s.rng.Int64N(int64(6*time.Minute)))
	}
	if s.rng.IntN(2) == 0 {
		// Срок — на всё время, что X придержана, и ещё десять минут (Q-57).
		x.promise.Deadline = x.recv.Add(hold + 10*time.Minute).UnixNano()
		s.note("срок обещания записи %d — %s", x.seq, time.Unix(0, x.promise.Deadline).UTC().Format("15:04:05"))
	}
	for until := x.got.Add(hold); s.w.now.Before(until); {
		honest(5)
		s.w.now = s.w.now.Add(time.Minute)
		s.flush()
		s.tailsLink()
		s.stamp(uint64(len(s.w.links)), false)
	}
	// Прикрытие и сама X.
	switch s.rng.IntN(3) {
	case 0:
		if len(s.placed) > 0 {
			var old []placedTok
			for _, p := range s.placed {
				if p.gen.Before(x.got) {
					old = append(old, p)
				}
			}
			if len(old) > 0 {
				p := old[s.rng.IntN(len(old))]
				tok := p.ownerTok
				s.pending = append(s.pending, ownerLeaf{leaf: tokenLeaf(tok.head, tok.payload), tok: &tok})
				s.note("перед записью %d — копия токена над головой %d (%s)", x.seq, tok.head, tok.gen.Format("15:04:05"))
			}
		}
	case 1:
		if early != nil {
			s.pending = append(s.pending, ownerLeaf{leaf: tokenLeaf(early.head, early.payload), tok: early})
			s.note("перед записью %d — придержанный токен над головой %d (%s)", x.seq, early.head, early.gen.Format("15:04:05"))
		}
	default:
		head := 1 + uint64(s.rng.IntN(len(s.w.links)))
		imprint := HeadImprint(head, auditchain.Hash(s.w.links[head-1]))
		payload, err := s.w.tsa.Sign(imprint[:], nil)
		if err != nil {
			s.w.t.Fatal(err)
		}
		tok := &ownerTok{head: head, gen: s.w.now, payload: payload}
		s.pending = append(s.pending, ownerLeaf{leaf: tokenLeaf(head, payload), tok: tok})
		s.note("перед записью %d — свежий токен над старой головой %d", x.seq, head)
	}
	if s.rng.IntN(2) == 0 {
		s.flush()
	}
	for i, l := range s.held {
		if l.rec == x {
			s.pending = append(s.pending, l)
			s.held = slices.Delete(s.held, i, i+1)
			break
		}
	}
	s.flush()
	s.note("запись %d легла в звено %d", x.seq, x.link)
	honest(10)
	return x
}

// receive — запись пришла сейчас; время приёма в улике — с отставанием до
// ReceiveLag или сдвинутое вперёд до shift; срок обещания — MaxPromiseMMD
// или длиннее; запись ложится сразу или придерживается.
func (s *ownerSim) receive(target bool) *ownerRec {
	s.seq++
	got := s.w.now
	recv := got.Add(-time.Duration(s.rng.Int64N(int64(ReceiveLag))))
	if s.shift > 0 && (target || !s.focused) && s.rng.IntN(2) == 0 {
		recv = got.Add(time.Duration(1 + s.rng.Int64N(int64(s.shift))))
	}
	data := sealedBytes(s.w.t, s.seq, recv, "line "+strconv.FormatUint(s.seq, 10))
	r := &ownerRec{seq: s.seq, got: got, recv: recv, data: data, digest: evidence.Digest(data)}
	// Срок обещания владелец пишет себе сам: предел MaxPromiseMMD держит
	// только config.Validate его же хранилища (Q-57).
	mmd := MaxPromiseMMD
	if (target || !s.focused) && s.rng.IntN(3) == 0 {
		mmd = []time.Duration{MaxPromiseMMD + time.Second, 15 * time.Minute, time.Hour}[s.rng.IntN(3)]
	}
	r.promise = Promise{Source: "abs-core", Seq: s.seq, Position: s.seq, Digest: r.digest[:], ReceivedAt: recv.UnixNano(),
		Deadline: recv.Add(mmd).UnixNano(), PublicKey: base64.RawStdEncoding.EncodeToString(s.w.signer.PublicKey())}
	s.recs = append(s.recs, r)
	l := ownerLeaf{rec: r} // лист — когда ляжет в цепь: ссылка на прежнюю запись в порядке цепи
	switch {
	case target:
		l.until = got.Add(24 * time.Hour) // кладёт сама атака
		s.held = append(s.held, l)
		s.note("запись %d принята и придержана (время приёма %s)", s.seq, recv.Format("15:04:05"))
		return r
	case !s.focused && s.rng.IntN(5) < 2:
		l.until = got.Add([]time.Duration{30 * time.Second, 2 * time.Minute, 5 * time.Minute, 15 * time.Minute}[s.rng.IntN(4)])
		s.held = append(s.held, l)
		s.note("запись %d принята, придержана до %s (время приёма %s)", s.seq, l.until.Format("15:04:05"), recv.Format("15:04:05"))
		return r
	}
	s.pending = append(s.pending, l)
	s.note("запись %d принята (время приёма %s)", s.seq, recv.Format("15:04:05"))
	return r
}

// release — придержанное, чей срок вышел, ложится в очередь звена.
func (s *ownerSim) release() {
	s.held = slices.DeleteFunc(s.held, func(l ownerLeaf) bool {
		if l.until.After(s.w.now) {
			return false
		}
		s.pending = append(s.pending, l)
		return true
	})
}

// flush сворачивает очередь в звено. Время звена владелец ставит самое
// раннее, какое пропускают проверки: у звена с токеном — время метки минус
// ReceiveSkew (tokenLinkTime), у прочих — начало сценария. Лист записи
// ссылается на прежнюю запись в порядке цепи — у придержанной тоже.
func (s *ownerSim) flush() {
	if len(s.pending) == 0 {
		return
	}
	at := s.start
	var leaves []auditchain.Leaf
	for i, l := range s.pending {
		if r := l.rec; r != nil {
			r.prev = s.last.Hash
			l.leaf = EvidenceLeafLinked(evidence.Header{Source: "abs-core", Seq: r.seq, ReceivedAt: r.recv.UnixNano()}, r.seq, r.digest, r.prev)
			r.hash = auditchain.LeafHash(l.leaf)
			s.last = Tail{Source: "abs-core", Seq: r.seq, Hash: r.hash}
			s.byHash[r.hash] = r
			s.pending[i] = l
		}
		leaves = append(leaves, l.leaf)
		if l.tok != nil && l.tok.gen.Add(-ReceiveSkew).After(at) {
			at = l.tok.gen.Add(-ReceiveSkew)
		}
	}
	now := s.w.now
	s.w.now = at
	s.w.wlink(leaves...)
	s.w.now = now
	link := uint64(len(s.w.links))
	for i, l := range s.pending {
		switch {
		case l.rec != nil:
			l.rec.link, l.rec.idx = link, i
		case l.tok != nil:
			s.placed = append(s.placed, placedTok{ownerTok: *l.tok, link: link, idx: i})
		}
	}
	s.pending = s.pending[:0]
}

// tailsLink — звено хвостов перед честной меткой: один лист — хвост abs-core
// к этому месту цепи, как у хранилища перед запросом к TSA. Время звена —
// самое раннее, как у прочих звеньев без токена.
func (s *ownerSim) tailsLink() {
	link := uint64(len(s.w.links)) + 1
	t := ownerTail{tail: s.last, has: s.last.Seq != 0}
	var ts []Tail
	if t.has {
		t.tail.Salt = salt(link, "abs-core")
		ts = append(ts, t.tail)
	}
	t.leaf = TailsLeaf(ts, s.w.now.UnixNano())
	now := s.w.now
	s.w.now = s.start
	s.w.wlink(t.leaf)
	s.w.now = now
	s.tails[link] = t
}

// stamp берёт токен над головой head сейчас; токен ложится сразу или
// придерживается (hold).
func (s *ownerSim) stamp(head uint64, hold bool) {
	l := s.w.links[head-1]
	imprint := HeadImprint(head, auditchain.Hash(l))
	payload, err := s.w.tsa.Sign(imprint[:], nil)
	if err != nil {
		s.w.t.Fatal(err)
	}
	tok := &ownerTok{head: head, gen: s.w.now, payload: payload}
	s.toks = append(s.toks, tok)
	leaf := ownerLeaf{leaf: tokenLeaf(head, payload), tok: tok}
	if hold && s.rng.IntN(10) < 3 {
		leaf.until = s.w.now.Add([]time.Duration{10 * time.Second, time.Minute, 5 * time.Minute}[s.rng.IntN(3)])
		s.held = append(s.held, leaf)
		s.note("метка над головой %d, токен придержан до %s", head, leaf.until.Format("15:04:05"))
		return
	}
	s.pending = append(s.pending, leaf)
	s.flush()
	s.note("метка над головой %d", head)
}

// checkWindow — окно наугад: каждая запись окна либо видна в каждом
// проходящем пакете за окно и по источнику, либо её обещание нарушено при
// любой T1.
func (s *ownerSim) checkWindow(target *ownerRec) (bad []string, hidden int) {
	var from, to time.Time
	if target != nil {
		from = target.got.Add(-ReceiveLag - time.Second - time.Duration(s.rng.Int64N(int64(5*time.Minute))))
		to = target.got.Add(ownerTolerance + time.Second + time.Duration(s.rng.Int64N(int64(5*time.Minute))))
	} else {
		end := s.w.now.Add(-10 * time.Minute)
		if !end.After(s.start.Add(2 * time.Minute)) {
			return nil, 0
		}
		from = s.start.Add(time.Minute + time.Duration(s.rng.Int64N(int64(end.Sub(s.start)))))
		to = from.Add(30*time.Second + time.Duration(s.rng.Int64N(int64(10*time.Minute))))
	}
	var want []*ownerRec
	for _, r := range s.recs {
		if r.got.After(from.Add(ReceiveLag)) && r.got.Before(to.Add(-ownerTolerance)) {
			want = append(want, r)
		}
	}
	if len(want) == 0 {
		return nil, 0
	}
	s.stats.windows++
	s.stats.wanted += len(want)
	trust := s.w.trust()
	// Свежая метка над последней головой: верхняя граница пакета записи
	// владельцу всегда доступна.
	top := uint64(len(s.w.links))
	topImprint := HeadImprint(top, auditchain.Hash(s.w.links[top-1]))
	topTok, err := s.w.tsa.Sign(topImprint[:], nil)
	if err != nil {
		s.w.t.Fatal(err)
	}
	lowers := []uint64{0}
	for _, p := range s.placed {
		if p.gen.Before(from.Add(-ReceiveSlack)) && !slices.Contains(lowers, p.head) {
			lowers = append(lowers, p.head)
		}
	}
	var ends []uint64
	for _, p := range s.placed {
		if !slices.Contains(ends, p.link) {
			ends = append(ends, p.link)
		}
	}
	promiseHolds := map[uint64]bool{} // запись → её обещание проходит хоть с одной T1
	checked := map[uint64]bool{}
	// seen — пакет прошёл и показал записи first–last (records — сколько):
	// запись окна вне этого — спрятана, и её обязано выдать обещание.
	seen := func(records int, first, last uint64, what string) {
		for _, r := range want {
			if records > 0 && r.seq >= first && r.seq <= last {
				continue // в сводке или названа дырой
			}
			s.stats.missing++
			if !checked[r.seq] {
				checked[r.seq] = true
				promiseHolds[r.seq] = s.promiseHolds(r, top, topTok, trust)
			}
			if promiseHolds[r.seq] {
				bad = append(bad, fmt.Sprintf("запись %d (принята %s, время приёма %s, звено %d) спрятана: %s за окно %s – %s проходит без неё, и её обещание выполнено",
					r.seq, r.got.Format("15:04:05"), r.recv.Format("15:04:05"), r.link, what, from.Format("15:04:05"), to.Format("15:04:05")))
			} else {
				hidden++
			}
		}
	}
	for _, low := range lowers {
		for _, e := range ends {
			if e <= low {
				continue
			}
			wr := VerifyWindow(s.w.window(low, e, from, to), trust, from, to)
			if !wr.Valid() {
				continue
			}
			s.stats.valid++
			var sum SourceSummary
			for _, src := range wr.Sources {
				if src.Name == "abs-core" {
					sum = src
				}
			}
			seen(sum.Records, sum.FirstSeq, sum.LastSeq, fmt.Sprintf("пакет (нижняя голова %d, конец участка %d)", low, e))
		}
	}

	// Пакеты по источнику. Край — звено хвостов и любой лист токена над ним
	// (копии тоже); нижний — с начала цепи или с метки раньше окна;
	// закрывающая метка — любой лист токена позже конца окна больше чем на
	// WindowEdge (копии и придержанные тоже); верхний край — после её листа.
	// Перебор урезан: нижних — начало цепи и два самых поздних, закрывающих
	// — четыре самых ранних в цепи, верхних — три самых ранних после неё.
	var edges []placedTok
	for _, p := range s.placed {
		if _, ok := s.tails[p.head]; ok {
			edges = append(edges, p)
		}
	}
	slices.SortStableFunc(edges, func(a, b placedTok) int { return cmp.Compare(a.head, b.head) })
	var srcLowers []placedTok
	for _, p := range edges {
		if from.After(p.gen.Add(ReceiveSlack)) {
			srcLowers = append(srcLowers, p)
		}
	}
	slices.SortStableFunc(srcLowers, func(a, b placedTok) int { return b.gen.Compare(a.gen) })
	srcLowers = append([]placedTok{{}}, srcLowers[:min(len(srcLowers), 2)]...)
	var closings []placedTok
	for _, p := range s.placed {
		if to.Before(p.gen.Add(-WindowEdge)) {
			closings = append(closings, p)
		}
	}
	slices.SortStableFunc(closings, func(a, b placedTok) int { return cmp.Compare(a.link, b.link) })
	for _, low := range srcLowers {
		for _, c := range closings[:min(len(closings), 4)] {
			n := 0
			for _, up := range edges {
				if up.head <= c.link || up.head <= low.head || n == 3 {
					continue
				}
				n++
				b, ok := s.sourceBundle(low, c, up, from, to)
				if !ok {
					continue
				}
				sr := VerifySource(b, trust, from, to)
				if !sr.Valid() {
					continue
				}
				s.stats.validSource++
				seen(sr.Records, sr.FirstSeq, sr.LastSeq, fmt.Sprintf("пакет по источнику (нижние хвосты %d, закрывающий токен в звене %d, верхние хвосты %d)", low.head, c.link, up.head))
			}
		}
	}
	return bad, hidden
}

// sourceBundle — пакет по abs-core: края low (голова ноль — с начала цепи)
// и up, закрывающая метка c; записи — по ссылкам от верхнего хвоста до
// нижнего. false — по ссылкам до нижнего хвоста не дойти.
func (s *ownerSim) sourceBundle(low, c, up placedTok, from, to time.Time) (SourceBundle, bool) {
	b := SourceBundle{Version: WindowVersion, Kind: SourceKind, Source: "abs-core", From: from, To: to}
	edge := func(p placedTok) (SourceEdge, Tail, bool) {
		t := s.tails[p.head]
		l := FromLeaf(t.leaf)
		e := SourceEdge{Head: p.head, Tails: &l, Token: s.w.inclusion(p.link, p.idx)}
		if t.has {
			e.Open = TailOf(t.tail)
		}
		return e, t.tail, t.has
	}
	var start [32]byte
	if low.head != 0 {
		var lt Tail
		b.Lower, lt, _ = edge(low)
		start = lt.Hash
	}
	var ut Tail
	var has bool
	b.Upper, ut, has = edge(up)
	b.Closing = s.w.inclusion(c.link, c.idx)
	var recs []*ownerRec
	for h := ut.Hash; has && h != start; h = recs[len(recs)-1].prev {
		r := s.byHash[h]
		if r == nil {
			return b, false
		}
		recs = append(recs, r)
	}
	slices.Reverse(recs)
	for _, r := range recs {
		b.Records = append(b.Records, SourceRecord{Leaf: s.w.inclusion(r.link, r.idx)})
	}
	end := max(up.link, low.link)
	for _, l := range s.w.links[max(low.head, 1)-1 : end] {
		b.Links = append(b.Links, FromLink(l))
	}
	last := s.w.links[end-1]
	b.Statement = s.w.signer.Sign(auditchain.Head{Seq: last.Seq, Hash: auditchain.Hash(last)}, int(last.Seq), s.w.now.Unix())
	return b, true
}

// promiseHolds — пакет записи проходит и её обещание выполнено хоть с одной
// T1, какую может предъявить владелец: любой лист токена в звене раньше
// звена записи.
func (s *ownerSim) promiseHolds(r *ownerRec, top uint64, topTok []byte, trust Trust) bool {
	for _, p := range s.placed {
		if p.link >= r.link {
			continue
		}
		// E1: версия пакета — поле JSON без подписи; владелец выдаёт и
		// пакет старой версии (2), который сверяется по времени звеньев.
		versions := []int{Version, 2}
		if os.Getenv("E1_V3ONLY") != "" {
			versions = []int{Version} // контроль: только пакеты версии 3
		}
		for _, v := range versions {
			b := Bundle{Version: v, Evidence: r.data, Inclusion: s.w.inclusion(r.link, r.idx),
				Upper: &Upper{HeadSeq: top, Token: topTok}, Lower: &Lower{Inclusion: s.w.inclusion(p.link, p.idx)}}
			// Версия 3: листья звеньев от головы под T1 до звена записи.
			if v >= 3 {
				for _, ls := range s.w.leaves[p.head:r.link] {
					for _, l := range ls {
						b.Stretch = append(b.Stretch, FromLeaf(l))
					}
				}
			}
			for _, l := range s.w.links[p.head-1 : top] {
				b.Links = append(b.Links, FromLink(l))
			}
			last := s.w.links[top-1]
			b.Statement = s.w.signer.Sign(auditchain.Head{Seq: last.Seq, Hash: auditchain.Hash(last)}, int(last.Seq), s.w.now.Unix())
			rep := Verify(b, trust)
			if rep.Valid() && CheckPromise(r.promise, rep, b, false) == nil {
				return true
			}
		}
	}
	return false
}

// checkLate — E1: записи, легшие после листа токена со временем TSA позже
// времени приёма + MaxPromiseMMD (что бы ни стояло в сроке), обязаны
// проваливать -promise при любой T1, любой версии пакета и любом листе (README: «a record held back past it fails
// the check»; правило меток).
func (s *ownerSim) checkLate() (bad []string) {
	trust := s.w.trust()
	top := uint64(len(s.w.links))
	topImprint := HeadImprint(top, auditchain.Hash(s.w.links[top-1]))
	topTok, err := s.w.tsa.Sign(topImprint[:], nil)
	if err != nil {
		s.w.t.Fatal(err)
	}
	for _, r := range s.recs {
		if r.link == 0 {
			continue
		}
		limit := time.Unix(0, r.promise.ReceivedAt+int64(MaxPromiseMMD))
		var worst time.Time
		for _, p := range s.placed {
			if (p.link < r.link || p.link == r.link && p.idx < r.idx) && p.gen.After(worst) {
				worst = p.gen
			}
		}
		if !worst.After(limit) {
			continue
		}
		if s.promiseHolds(r, top, topTok, trust) {
			bad = append(bad, fmt.Sprintf("запись %d (время приёма %s, предел срока %s) легла в звено %d после токена метки %s, а esverify -promise её пропускает",
				r.seq, r.recv.Format("15:04:05"), limit.UTC().Format("15:04:05"), r.link, worst.Format("15:04:05")))
		}
	}
	return bad
}

// Q-60: граница, которую держит сверка времени приёма у сборщика. Сдвиг
// больше receiveAhead (минута) сборщик выдаёт по своим часам, а они могут
// спешить до минуты: незамеченный сдвиг — почти две минуты. Запись X со
// сдвинутым временем приёма владелец придерживает за метку B, что закрывает
// окно (позже его конца на 2 мин 1 с), звено токена — задним числом ровно на
// ReceiveSkew. Сверка обещания по меткам выдаёт её, если время метки B позже
// времени приёма плюс минута: X, доставленную за 90 с до конца окна и раньше,
// — да. Доставленную за 50 с — нет: сдвиг уводит её время приёма за конец
// окна больше чем на минуту, и она — запись следующего окна (README: запись
// последних двух минут окна сдвиг уводит в следующее).
//
//	звено 1: [запуск]                         10:00, метка A над головой 1
//	звено 2: [токен A, abs-core 1 (10:02)]    10:02
//	звено 3: [молчит: other]                  10:05
//	                                          10:06:31, метка B над головой 3
//	звено 4: [токен B]                        10:05:31 — задним числом на минуту
//	звено 5: [X]                              10:05:31
//	                                          10:10, метка C над головой 5
//	звено 6: [токен C]                        10:10
func TestReceiveShiftBoundary(t *testing.T) {
	const collectorAhead = 59 * time.Second // часы сборщика спешат
	from, to := at(10, 1, 0), at(10, 4, 30)
	for _, c := range []struct {
		lead   time.Duration // за сколько до конца окна X доставлена
		hidden bool
	}{{50 * time.Second, true}, {90 * time.Second, false}, {2*time.Minute + time.Second, false}} {
		got := to.Add(-c.lead)
		// Позже ответа по часам сборщика на минуту без секунды: сборщик молчит.
		recv := got.Add(collectorAhead + time.Minute - time.Second)
		w := newWorld(t)
		w.now = at(10, 0, 0)
		w.wlink(auditchain.Leaf{Type: auditchain.EventStart})
		hA, tA := w.stamp()
		w.now = at(10, 2, 0)
		w.wlink(tokenLeaf(hA, tA), rec(t, 1, at(10, 2, 0)))
		w.now = at(10, 5, 0)
		w.wlink(auditchain.Leaf{UnixNano: w.now.UnixNano(), Type: auditchain.EventSilence, Scope: "other"})
		w.now = at(10, 6, 31)
		hB, tB := w.stamp()
		w.now = at(10, 5, 31)
		w.wlink(tokenLeaf(hB, tB))
		held := sealedBytes(t, 2, recv, "held back")
		w.wlink(evLeaf(t, held, 2))
		w.now = at(10, 10, 0)
		hC, tC := w.stamp()
		w.wlink(tokenLeaf(hC, tC))

		wr := VerifyWindow(w.window(1, 4, from, to), w.trust(), from, to)
		b := w.bundle(held, 5, 0, hC, tC, 2)
		r := Verify(b, w.trust())
		if !wr.Valid() || !r.Valid() {
			t.Fatalf("за %s до конца окна: пакет за окно %s, пакет записи %s", c.lead, wr.Verdict(), r.Verdict())
		}
		digest := evidence.Digest(held)
		p := Promise{Source: "abs-core", Seq: 2, Position: 2, Digest: digest[:], ReceivedAt: recv.UnixNano(),
			Deadline: recv.Add(MaxPromiseMMD).UnixNano(), PublicKey: base64.RawStdEncoding.EncodeToString(w.signer.PublicKey())}
		perr := CheckPromise(p, r, b, false)
		if hidden := perr == nil; hidden != c.hidden {
			t.Errorf("X доставлена за %s до конца окна, время приёма %s: пакет за окно без неё проходит, обещание: %v",
				c.lead, recv.Format("15:04:05"), perr)
		}
	}
}
