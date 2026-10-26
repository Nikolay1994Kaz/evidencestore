package proof

import (
	"encoding/json"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/Nikolay1994Kaz/evidencestore/internal/auditchain"
	"github.com/Nikolay1994Kaz/evidencestore/internal/evidence"
)

// Пакет по источнику на синтетической цепи: подделки, которых честное
// хранилище не выдаст (листья без ссылок, хвосты не на месте, номер в
// раскрытии не тот), — каждая согласована во всём, кроме проверяемого
// пункта. Путь через настоящее хранилище — в пакете store (source_test.go).

// srcOpts — отступления синтетической цепи от честной.
type srcOpts struct {
	unlinked   bool   // записи abs-core 2–4 — листья прежнего формата, без ссылок
	upperSeq   uint64 // номер abs-core в верхних хвостах (ноль — честный, 4)
	lowerExtra bool   // в звене нижних хвостов ещё один лист
	tokenFirst bool   // в звене 6 токен первым: хвосты не сразу за ним
	gap        bool   // abs-core 3 пришла под номером 6: номеров 3 и 5 источник не дал
}

// srcWorld — цепь хранилища с хвостами источников:
//
//	звено 1: [запуск, abs-core 1]                       10:00
//	звено 2: [хвосты: abs-core 1]                       метка A над головой 2 — 10:00
//	звено 3: [токен A, хвосты: abs-core 1]
//	звено 4: [abs-core 2, pipelock 1, abs-core 3]       10:05
//	звено 5: [хвосты: abs-core 3, pipelock 1]           метка B над головой 5 — 10:10
//	звено 6: [abs-core 4, токен B, хвосты: abs-core 4, pipelock 1]
//	звено 7: [abs-core 5]                               10:11
//
// abs-core 4 лёг, пока шёл запрос метки B. Окно 10:04–10:06 закрыто
// хвостами меток A и B.
type srcWorld struct {
	*world
	o    srcOpts
	recs map[uint64]auditchain.Leaf // листья abs-core по номеру
	tokA []byte
}

func newSrcWorld(t *testing.T, o srcOpts) *srcWorld {
	w := &srcWorld{world: newWorld(t), o: o, recs: map[uint64]auditchain.Leaf{}}
	var prev [32]byte
	add := func(seq uint64, when time.Time) auditchain.Leaf {
		num := seq
		if o.gap && seq == 3 {
			num = 6
		}
		data := sealedBytes(t, num, when, "line "+strconv.FormatUint(num, 10))
		l := EvidenceLeafLinked(evidence.Header{Source: "abs-core", Seq: num, ReceivedAt: when.UnixNano()}, seq, evidence.Digest(data), prev)
		if o.unlinked && seq > 1 {
			l = evLeaf(t, data, seq)
		}
		prev = auditchain.LeafHash(l)
		w.recs[seq] = l
		return l
	}
	other := EvidenceLeafLinked(evidence.Header{Source: "pipelock", Seq: 1, ReceivedAt: at(10, 5, 10).UnixNano()}, 100, [32]byte{1}, [32]byte{})
	tails := func(seq, absSeq uint64, withOther bool) auditchain.Leaf {
		ts := []Tail{{Source: "abs-core", Seq: absSeq, Hash: auditchain.LeafHash(w.recs[seq])}}
		if withOther {
			ts = append(ts, Tail{Source: "pipelock", Seq: 1, Hash: auditchain.LeafHash(other)})
		}
		return TailsLeaf(ts, w.now.UnixNano())
	}

	w.now = at(10, 0, 0)
	w.wlink(auditchain.Leaf{Type: auditchain.EventStart}, add(1, w.now))
	lower := []auditchain.Leaf{tails(1, 1, false)}
	if o.lowerExtra {
		lower = append(lower, auditchain.Leaf{Type: auditchain.EventStart})
	}
	w.wlink(lower...)
	hA, tA := w.stamp()
	w.tokA = tA
	w.wlink(tokenLeaf(hA, tA), tails(1, 1, false))
	w.now = at(10, 5, 0)
	w.wlink(add(2, w.now), other, add(3, at(10, 5, 30)))
	w.now = at(10, 10, 0)
	w.wlink(tails(3, 3, true))
	hB, tB := w.stamp()
	rec4 := add(4, w.now)
	upperSeq := uint64(4)
	if o.upperSeq != 0 {
		upperSeq = o.upperSeq
	}
	if o.tokenFirst {
		w.wlink(tokenLeaf(hB, tB), rec4, tails(4, upperSeq, true))
	} else {
		w.wlink(rec4, tokenLeaf(hB, tB), tails(4, upperSeq, true))
	}
	w.now = at(10, 11, 0)
	w.wlink(add(5, w.now))
	return w
}

func (w *srcWorld) placed(link uint64, idx int) PlacedLeaf {
	return PlacedLeaf{Inclusion: w.inclusion(link, idx), Index: idx}
}

// bundle — пакет по abs-core за окно from–to: звенья 2–6, нижние хвосты —
// в звене 2, верхние — в 6, записи 2–4.
func (w *srcWorld) bundle(from, to time.Time) SourceBundle {
	b := SourceBundle{Version: WindowVersion, Kind: SourceKind, Source: "abs-core", From: from, To: to, LowerHead: 2, LowerToken: w.tokA}
	lt := FromLeaf(w.leaves[1][0])
	b.LowerTails = &lt
	b.LowerOpen = TailOf(Tail{Source: "abs-core", Seq: 1, Hash: auditchain.LeafHash(w.recs[1])})
	tok, rec4 := 1, 0
	if w.o.tokenFirst {
		tok, rec4 = 0, 1
	}
	upperSeq := uint64(4)
	if w.o.upperSeq != 0 {
		upperSeq = w.o.upperSeq
	}
	b.UpperToken, b.UpperTails = w.placed(6, tok), w.placed(6, 2)
	b.UpperOpen = TailOf(Tail{Source: "abs-core", Seq: upperSeq, Hash: auditchain.LeafHash(w.recs[4])})
	b.Records = []SourceRecord{{Leaf: w.placed(4, 0)}, {Leaf: w.placed(4, 2)}, {Leaf: w.placed(6, rec4)}}
	w.sign(&b, 6)
	return b
}

// sign — звенья пакета до end и голова над end, подписанная ключом мира.
func (w *srcWorld) sign(b *SourceBundle, end uint64) {
	b.Links = nil
	for _, l := range w.links[max(b.LowerHead, 1)-1 : end] {
		b.Links = append(b.Links, FromLink(l))
	}
	last := w.links[end-1]
	b.Statement = w.signer.Sign(auditchain.Head{Seq: last.Seq, Hash: auditchain.Hash(last)}, int(last.Seq), w.now.Unix())
}

// sourceCheckFailed — пункт name провален, и в его объяснении есть detail.
func sourceCheckFailed(t *testing.T, r SourceReport, name, detail string) {
	t.Helper()
	if r.Valid() {
		t.Fatalf("подделка прошла:\n%s", r.Text())
	}
	for _, c := range r.Checks {
		if strings.HasPrefix(c.Name, name) {
			if c.OK || !strings.Contains(c.Detail, detail) {
				t.Fatalf("пункт %q: %v %q, ждали провал с %q:\n%s", name, c.OK, c.Detail, detail, r.Text())
			}
			return
		}
	}
	t.Fatalf("пункта %q нет в отчёте:\n%s", name, r.Text())
}

func TestSourceVerifies(t *testing.T) {
	w := newSrcWorld(t, srcOpts{})
	r := VerifySource(w.bundle(at(10, 4, 0), at(10, 6, 0)), w.trust(), time.Time{}, time.Time{})
	if !r.Valid() {
		t.Fatalf("пакет не прошёл:\n%s", r.Text())
	}
	if !r.FromBundle || r.Lower != at(10, 0, 0) || r.Upper != at(10, 10, 0) || r.LowerHead != 2 || r.UpperLink != 6 || r.HeadSeq != 6 ||
		r.Records != 3 || r.InWindow != 2 || r.FirstSeq != 2 || r.LastSeq != 4 || len(r.Holes) != 0 {
		t.Fatalf("отчёт: %+v", r)
	}
	text := r.Text()
	if !strings.Contains(text, "Every record abs-core put into the store's chain from the time-stamp of 2026-10-03 10:00:00 UTC to the time-stamp of 2026-10-03 10:10:00 UTC is in this bundle: records 2–4 (3, 2 received in the window)") ||
		!strings.HasSuffix(text, "VERIFIED\n") {
		t.Fatalf("отчёт:\n%s", text)
	}
	// Границы строгие, как у пакета за окно: запись до нижних хвостов
	// законно получает время T1 + 1 с, после верхних — T2 − 1 мин.
	for _, c := range []struct {
		from, to time.Time
		ok       bool
	}{
		{at(10, 0, 1), at(10, 6, 0), false},
		{at(10, 0, 1).Add(time.Nanosecond), at(10, 6, 0), true},
		{at(10, 4, 0), at(10, 9, 0), false},
		{at(10, 4, 0), at(10, 9, 0).Add(-time.Nanosecond), true},
		{at(10, 6, 0), at(10, 4, 0), false},
	} {
		r := VerifySource(w.bundle(at(10, 4, 0), at(10, 6, 0)), w.trust(), c.from, c.to)
		if r.Valid() != c.ok || r.FromBundle {
			t.Fatalf("окно %v – %v: %v\n%s", c.from, c.to, r.Valid(), r.Text())
		}
	}
	// Окна нет ни в пакете, ни у аудитора.
	sourceCheckFailed(t, VerifySource(w.bundle(time.Time{}, time.Time{}), w.trust(), time.Time{}, time.Time{}),
		"the time-stamps bracket the window", "no window")
}

// Пакет, доведённый до головы свидетеля: звенья за верхними хвостами есть,
// записи из них — нет.
func TestSourceToHead(t *testing.T) {
	w := newSrcWorld(t, srcOpts{})
	b := w.bundle(at(10, 4, 0), at(10, 6, 0))
	w.sign(&b, 7)
	if r := VerifySource(b, w.trust(), time.Time{}, time.Time{}); !r.Valid() || r.HeadSeq != 7 || r.UpperLink != 6 {
		t.Fatalf("до головы 7:\n%s", r.Text())
	}
	b.Records = append(b.Records, SourceRecord{Leaf: w.placed(7, 0)})
	sourceCheckFailed(t, VerifySource(b, w.trust(), time.Time{}, time.Time{}),
		"the records are the whole chain of the source between the tails", "after the upper tails in link 6")
}

func TestSourceForgedSynthetic(t *testing.T) {
	const (
		head  = "the head is signed with the store key"
		start = "the bundle starts at the beginning of the chain"
		lower = "the lower tails are the only leaf of the link the lower time-stamp certifies"
		upper = "the upper tails lie right after the token of the upper time-stamp"
		chain = "the records are the whole chain of the source between the tails"
	)
	for _, c := range []struct {
		name          string
		o             srcOpts
		forge         func(w *srcWorld, b *SourceBundle)
		check, detail string
	}{
		{"записи без ссылок", srcOpts{unlinked: true}, nil, chain, "has no link to the previous record"},
		{"номер в верхнем раскрытии не тот", srcOpts{upperSeq: 7}, nil, chain, "name record 7 of abs-core as the last, but the chain of its records ends at 4"},
		{"в звене нижних хвостов не только они", srcOpts{lowerExtra: true}, nil, lower, "does not hold just the lower tails"},
		{"хвосты не сразу за токеном", srcOpts{tokenFirst: true}, nil, upper, "the tails must come right after the token"},
		{"перед хвостами не токен", srcOpts{tokenFirst: true}, func(w *srcWorld, b *SourceBundle) {
			b.UpperToken = w.placed(6, 1)
		}, upper, "is not a TSA time-stamp"},
		{"звено выброшено", srcOpts{}, func(w *srcWorld, b *SourceBundle) {
			b.Links = append(b.Links[:2], b.Links[3:]...)
		}, "the links are chained by hash with no gaps", ""},
		{"хвосты — не последний лист звена", srcOpts{}, func(w *srcWorld, b *SourceBundle) {
			b.UpperTails = w.placed(6, 0)
		}, upper, "the tails must come right after the token"},
		{"голова — не последнее звено", srcOpts{}, func(w *srcWorld, b *SourceBundle) {
			b.Statement = w.signer.Sign(auditchain.Head{Seq: 5, Hash: auditchain.Hash(w.links[4])}, 5, w.now.Unix())
		}, head, "does not match the last link"},
		{"«с начала цепи», а звенья со второго", srcOpts{}, func(w *srcWorld, b *SourceBundle) {
			b.LowerHead = 0
		}, start, "starts at link 2"},
		{"звенья начинаются не с нижних хвостов", srcOpts{}, func(w *srcWorld, b *SourceBundle) {
			b.Links = b.Links[1:]
		}, lower, "the lower tails are said to lie in link 2"},
		{"нижних хвостов нет", srcOpts{}, func(w *srcWorld, b *SourceBundle) {
			b.LowerTails = nil
		}, lower, "carries no lower tails"},
		{"нижняя метка — над другой головой", srcOpts{}, func(w *srcWorld, b *SourceBundle) {
			b.LowerToken = w.leaves[5][1].Payload
		}, lower, "the lower time-stamp"},
		{"токен верхней метки — в другом звене", srcOpts{}, func(w *srcWorld, b *SourceBundle) {
			b.UpperToken = w.placed(3, 0)
		}, upper, "lies in link 3, the upper tails in link 6"},
		{"верхние хвосты не последние в звене", srcOpts{}, func(w *srcWorld, b *SourceBundle) {
			b.UpperToken, b.UpperTails = w.placed(6, 0), w.placed(6, 1)
		}, upper, "the tails must come right after the token"},
		{"запись чужого источника", srcOpts{}, func(w *srcWorld, b *SourceBundle) {
			b.Records[1].Leaf = w.placed(4, 1)
		}, chain, "record 2 of the bundle is not a record of abs-core"},
		{"лист хвостов вместо записи", srcOpts{}, func(w *srcWorld, b *SourceBundle) {
			l := w.placed(5, 0)
			l.Leaf.Scope, l.Leaf.Subject = "abs-core", "9"
			b.Records = append(b.Records[:2], SourceRecord{Leaf: l})
		}, chain, "record 3 of the bundle is not a record of abs-core"},
		{"запись переставлена", srcOpts{}, func(w *srcWorld, b *SourceBundle) {
			b.Records[0], b.Records[1] = b.Records[1], b.Records[0]
		}, chain, "record abs-core/3 does not refer to the record before it"},
		{"запись без пути", srcOpts{}, func(w *srcWorld, b *SourceBundle) {
			b.Records[0].Leaf.Path = nil
		}, chain, "record abs-core/2:"},
		{"последняя запись выброшена", srcOpts{}, func(w *srcWorld, b *SourceBundle) {
			b.Records = b.Records[:2]
		}, chain, "does not match the upper tails"},
	} {
		w := newSrcWorld(t, c.o)
		b := w.bundle(at(10, 4, 0), at(10, 6, 0))
		if c.forge != nil {
			c.forge(w, &b)
		}
		t.Run(c.name, func(t *testing.T) {
			sourceCheckFailed(t, VerifySource(b, w.trust(), time.Time{}, time.Time{}), c.check, c.detail)
		})
	}
}

// Номера между записями, которых источник не дал, — дыры в отчёте, а не
// провал: ссылки сходятся.
func TestSourceHoles(t *testing.T) {
	w := newSrcWorld(t, srcOpts{gap: true})
	r := VerifySource(w.bundle(at(10, 4, 0), at(10, 6, 0)), w.trust(), time.Time{}, time.Time{})
	if !r.Valid() || r.FirstSeq != 2 || r.LastSeq != 6 || len(r.Holes) != 2 || r.Holes[0] != (SeqRange{From: 3, To: 3}) || r.Holes[1] != (SeqRange{From: 5, To: 5}) {
		t.Fatalf("дыры %v:\n%s", r.Holes, r.Text())
	}
	if !strings.Contains(r.Text(), "numbers 3, 5 never reached the store") {
		t.Fatalf("отчёт:\n%s", r.Text())
	}
}

func TestTailsLeaf(t *testing.T) {
	a := Tail{Source: "abs-core", Seq: 3, Hash: [32]byte{3}}
	p := Tail{Source: "pipelock", Seq: 1, Hash: [32]byte{1}}
	l := TailsLeaf([]Tail{a, p}, 5)
	if auditchain.LeafHash(l) != auditchain.LeafHash(TailsLeaf([]Tail{p, a}, 5)) {
		t.Fatal("лист хвостов зависит от порядка источников")
	}
	if strings.Contains(string(l.Payload), "abs-core") || strings.Contains(string(l.Payload), "pipelock") {
		t.Fatalf("имена в листе хвостов открыты: %s", l.Payload)
	}
	if h, err := OpenTail(l, "abs-core", TailOf(a)); err != nil || h != a.Hash {
		t.Fatalf("раскрытие: %x, %v", h, err)
	}
	if h, err := OpenTail(l, "nobody", nil); err != nil || h != ([32]byte{}) {
		t.Fatalf("источника нет: %x, %v", h, err)
	}
	twice, _ := json.Marshal(tailsPayload{Sources: []tailEntry{tailEntryOf(a), tailEntryOf(a)}})
	for name, c := range map[string]struct {
		leaf auditchain.Leaf
		src  string
		open *TailOpen
		want string
	}{
		"не лист хвостов":        {auditchain.Leaf{Type: auditchain.EventStart}, "abs-core", TailOf(a), "not a tails leaf"},
		"предмет не разбирается": {auditchain.Leaf{Type: auditchain.EventTails, Payload: []byte("{")}, "abs-core", TailOf(a), "tails leaf"},
		"источник назван дважды": {auditchain.Leaf{Type: auditchain.EventTails, Payload: twice}, "abs-core", TailOf(a), "names abs-core twice"},
		"раскрыт неназванный":    {l, "nobody", TailOf(a), "does not name it"},
		"назван, но не раскрыт":  {l, "abs-core", nil, "does not open its tail"},
		"номер не тот":           {l, "abs-core", TailOf(Tail{Source: "abs-core", Seq: 4, Hash: a.Hash}), "does not match"},
		"хэш не тот":             {l, "abs-core", TailOf(Tail{Source: "abs-core", Seq: 3, Hash: [32]byte{4}}), "does not match"},
		"хэш не разбирается":     {l, "abs-core", &TailOpen{Seq: 3, Leaf: "zz"}, "does not parse"},
		"хэш короче":             {l, "abs-core", &TailOpen{Seq: 3, Leaf: "0300"}, "does not parse"},
		"раскрытие чужим именем": {l, "pipelock", TailOf(a), "does not match"},
	} {
		if _, err := OpenTail(c.leaf, c.src, c.open); err == nil || !strings.Contains(err.Error(), c.want) {
			t.Fatalf("%s: %v", name, err)
		}
	}
}

// tailEntryOf — запись листа хвостов, как её пишет TailsLeaf.
func tailEntryOf(t Tail) tailEntry {
	var p tailsPayload
	json.Unmarshal(TailsLeaf([]Tail{t}, 0).Payload, &p)
	return p.Sources[0]
}

func TestEvidenceLeafLinked(t *testing.T) {
	h := evidence.Header{Source: "abs-core", Seq: 7, ReceivedAt: 9}
	old := EvidenceLeaf(h, 3, [32]byte{5})
	linked := EvidenceLeafLinked(h, 3, [32]byte{5}, [32]byte{6})
	for _, l := range []auditchain.Leaf{old, linked} {
		if pos, digest, err := ParseEvidenceLeaf(l); err != nil || pos != 3 || digest != ([32]byte{5}) {
			t.Fatalf("лист %d байт: %d %x %v", len(l.Payload), pos, digest, err)
		}
	}
	if prev, ok := EvidencePrev(linked); !ok || prev != ([32]byte{6}) {
		t.Fatalf("ссылка: %x %v", prev, ok)
	}
	if _, ok := EvidencePrev(old); ok {
		t.Fatal("у листа прежнего формата нашлась ссылка")
	}
	for _, n := range []int{39, 41, 71, 73} {
		l := linked
		l.Payload = make([]byte, n)
		if _, _, err := ParseEvidenceLeaf(l); err == nil {
			t.Fatalf("лист %d байт разобран", n)
		}
		if _, ok := EvidencePrev(l); ok {
			t.Fatalf("у листа %d байт нашлась ссылка", n)
		}
	}
	tails := linked
	tails.Type = auditchain.EventTails
	if _, ok := EvidencePrev(tails); ok {
		t.Fatal("ссылка у листа не улики")
	}
}
