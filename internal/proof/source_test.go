package proof

import (
	"crypto/sha256"
	"encoding/json"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/Nikolay1994Kaz/evidencestore/internal/auditchain"
	"github.com/Nikolay1994Kaz/evidencestore/internal/evidence"
)

// Пакет по источнику на синтетической цепи: подделки, которых честное
// хранилище не выдаст (листья без ссылок, хвосты не одни в звене, номер в
// раскрытии не тот, переписанный край), — каждая согласована во всём, кроме
// проверяемого пункта. Путь через настоящее хранилище — в пакете store
// (source_test.go).

// srcOpts — отступления синтетической цепи от честной.
type srcOpts struct {
	unlinked   bool          // записи abs-core 2–4 — листья прежнего формата, без ссылок
	upperSeq   uint64        // номер abs-core в верхних хвостах (ноль — честный, 4)
	lowerExtra bool          // в звене нижних хвостов ещё один лист
	upperExtra bool          // в звене верхних хвостов ещё один лист
	gap        bool          // abs-core 2 пришла под номером 7: в цепи номера 7, 3, 4, а 5–6 нет
	late       bool          // abs-core 3 «принята» в 10:15, позже метки верхнего края
	early      bool          // abs-core 2 «принята» в 9:57, раньше нижней метки на 3 минуты
	backdate   uint64        // звено с токеном (3, 6 или 8) — со временем раньше метки
	backBy     time.Duration // насколько раньше (ноль — на 2 минуты)
}

// srcWorld — цепь хранилища с хвостами источников:
//
//	звено 1: [запуск, abs-core 1]                     10:00
//	звено 2: [хвосты: abs-core 1]                     метка A над головой 2 — 10:00
//	звено 3: [токен A]
//	звено 4: [abs-core 2, pipelock 1, abs-core 3]     10:05
//	звено 5: [хвосты: abs-core 3, pipelock 1]         метка B над головой 5 — 10:10
//	звено 6: [abs-core 4, токен B]                    abs-core 4 — пока шёл запрос
//	звено 7: [хвосты: abs-core 4, pipelock 1]         метка C над головой 7 — 10:11
//	звено 8: [токен C]
//	звено 9: [abs-core 5]                             10:12
//
// Окно 10:04–10:06: нижний край — хвосты в звене 2 (метка A), закрывает
// окно метка B (токен в звене 6), верхний край — хвосты в звене 7, после
// него (метка C).
type srcWorld struct {
	*world
	o    srcOpts
	recs map[uint64]auditchain.Leaf // листья abs-core по месту в мире
	toks [3][]byte                  // токены меток A, B и C
}

// salt — соль хвоста в листе хвостов звена link: у хранилища это хэш
// подписи, здесь — любое значение, своё для звена и источника.
func salt(link uint64, source string) [32]byte {
	return sha256.Sum256([]byte(strconv.FormatUint(link, 10) + source))
}

func newSrcWorld(t *testing.T, o srcOpts) *srcWorld {
	w := &srcWorld{world: newWorld(t), o: o, recs: map[uint64]auditchain.Leaf{}}
	var prev [32]byte
	add := func(at uint64, when time.Time) auditchain.Leaf {
		num := at
		if o.gap && at == 2 {
			num = 7
		}
		data := sealedBytes(t, num, when, "line "+strconv.FormatUint(num, 10))
		l := EvidenceLeafLinked(evidence.Header{Source: "abs-core", Seq: num, ReceivedAt: when.UnixNano()}, at, evidence.Digest(data), prev)
		if o.unlinked && at > 1 {
			l = evLeaf(t, data, at)
		}
		prev = auditchain.LeafHash(l)
		w.recs[at] = l
		return l
	}
	other := EvidenceLeafLinked(evidence.Header{Source: "pipelock", Seq: 1, ReceivedAt: at(10, 5, 10).UnixNano()}, 100, [32]byte{1}, [32]byte{})
	tails := func(link, at, seq uint64, withOther bool) auditchain.Leaf {
		ts := []Tail{{Source: "abs-core", Seq: seq, Hash: auditchain.LeafHash(w.recs[at]), Salt: salt(link, "abs-core")}}
		if withOther {
			ts = append(ts, Tail{Source: "pipelock", Seq: 1, Hash: auditchain.LeafHash(other), Salt: salt(link, "pipelock")})
		}
		return TailsLeaf(ts, w.now.UnixNano())
	}

	w.now = at(10, 0, 0)
	w.wlink(auditchain.Leaf{Type: auditchain.EventStart}, add(1, w.now))
	lower := []auditchain.Leaf{tails(2, 1, 1, false)}
	if o.lowerExtra {
		lower = append(lower, auditchain.Leaf{Type: auditchain.EventStart})
	}
	w.wlink(lower...)
	// Звено с токеном хранилище кладёт сразу после ответа TSA; backdate —
	// время звена задним числом.
	tokenLink := func(link uint64, leaves ...auditchain.Leaf) {
		now := w.now
		if o.backdate == link {
			by := o.backBy
			if by == 0 {
				by = 2 * time.Minute
			}
			w.now = now.Add(-by)
		}
		w.wlink(leaves...)
		w.now = now
	}
	hA, tA := w.stamp()
	tokenLink(3, tokenLeaf(hA, tA))
	w.now = at(10, 5, 0)
	t2, t3 := w.now, at(10, 5, 30)
	if o.early {
		t2 = at(9, 57, 0)
	}
	if o.late {
		t3 = at(10, 15, 0)
	}
	w.wlink(add(2, t2), other, add(3, t3))
	w.now = at(10, 10, 0)
	w.wlink(tails(5, 3, 3, true))
	hB, tB := w.stamp()
	tokenLink(6, add(4, w.now), tokenLeaf(hB, tB))
	w.now = at(10, 11, 0)
	upperSeq := uint64(4)
	if o.upperSeq != 0 {
		upperSeq = o.upperSeq
	}
	upper := []auditchain.Leaf{tails(7, 4, upperSeq, true)}
	if o.upperExtra {
		upper = append(upper, auditchain.Leaf{Type: auditchain.EventStart})
	}
	w.wlink(upper...)
	hC, tC := w.stamp()
	tokenLink(8, tokenLeaf(hC, tC))
	w.now = at(10, 12, 0)
	w.wlink(add(5, w.now))
	w.toks = [3][]byte{tA, tB, tC}
	return w
}

// bundle — пакет по abs-core за окно from–to: звенья 2–8 (до токена метки
// C), закрывающий токен B, записи 2–4.
func (w *srcWorld) bundle(from, to time.Time) SourceBundle {
	b := SourceBundle{Version: WindowVersion, Kind: SourceKind, Source: "abs-core", From: from, To: to}
	lt, ut := FromLeaf(w.leaves[1][0]), FromLeaf(w.leaves[6][0])
	upperSeq := uint64(4)
	if w.o.upperSeq != 0 {
		upperSeq = w.o.upperSeq
	}
	b.Lower = SourceEdge{Head: 2, Tails: &lt, Token: w.inclusion(3, 0),
		Open: TailOf(Tail{Source: "abs-core", Seq: 1, Hash: auditchain.LeafHash(w.recs[1]), Salt: salt(2, "abs-core")})}
	b.Upper = SourceEdge{Head: 7, Tails: &ut, Token: w.inclusion(8, 0),
		Open: TailOf(Tail{Source: "abs-core", Seq: upperSeq, Hash: auditchain.LeafHash(w.recs[4]), Salt: salt(7, "abs-core")})}
	b.Closing = w.inclusion(6, 1)
	b.Records = []SourceRecord{{Leaf: w.inclusion(4, 0)}, {Leaf: w.inclusion(4, 2)}, {Leaf: w.inclusion(6, 0)}}
	w.sign(&b, 8)
	return b
}

// sign — звенья пакета до end и голова над end, подписанная ключом мира.
func (w *srcWorld) sign(b *SourceBundle, end uint64) {
	b.Links = nil
	for _, l := range w.links[max(b.Lower.Head, 1)-1 : end] {
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

// Звено с токеном со временем задним числом (Q-33): у нижнего края, у
// закрывающей метки и у верхнего края пакет не проходит. Граница —
// ReceiveSkew: на минуту раньше метки — ещё честно.
func TestSourceBackdatedTokenLink(t *testing.T) {
	for _, c := range []struct {
		link  uint64
		check string
	}{{3, "the lower tails"}, {6, "the upper tails"}, {8, "the upper tails"}} {
		w := newSrcWorld(t, srcOpts{backdate: c.link})
		r := VerifySource(w.bundle(at(10, 4, 0), at(10, 6, 0)), w.trust(), time.Time{}, time.Time{})
		sourceCheckFailed(t, r, c.check, "backdated the link")
		w = newSrcWorld(t, srcOpts{backdate: c.link, backBy: ReceiveSkew + time.Second})
		r = VerifySource(w.bundle(at(10, 4, 0), at(10, 6, 0)), w.trust(), time.Time{}, time.Time{})
		sourceCheckFailed(t, r, c.check, "backdated the link")
		w = newSrcWorld(t, srcOpts{backdate: c.link, backBy: ReceiveSkew})
		if r := VerifySource(w.bundle(at(10, 4, 0), at(10, 6, 0)), w.trust(), time.Time{}, time.Time{}); !r.Valid() {
			t.Fatalf("звено %d на ReceiveSkew раньше метки:\n%s", c.link, r.Text())
		}
	}
}

func TestSourceVerifies(t *testing.T) {
	w := newSrcWorld(t, srcOpts{})
	r := VerifySource(w.bundle(at(10, 4, 0), at(10, 6, 0)), w.trust(), time.Time{}, time.Time{})
	if !r.Valid() {
		t.Fatalf("пакет не прошёл:\n%s", r.Text())
	}
	if !r.FromBundle || r.Lower != at(10, 0, 0) || r.Upper != at(10, 10, 0) || r.UpperEdge != at(10, 11, 0) || r.LowerHead != 2 || r.UpperHead != 7 || r.HeadSeq != 8 ||
		r.Records != 3 || r.InWindow != 2 || r.FirstSeq != 2 || r.LastSeq != 4 || len(r.Holes) != 0 {
		t.Fatalf("отчёт: %+v", r)
	}
	text := r.Text()
	if !strings.Contains(text, "Every record abs-core put into the store's chain from the source tails laid right before the time-stamp of 2026-10-03 10:00:00 UTC to the first source tails laid after the time-stamp of 2026-10-03 10:10:00 UTC is in this bundle: records 2–4 (3, 2 received in the window)") ||
		!strings.HasSuffix(text, "VERIFIED\n") {
		t.Fatalf("отчёт:\n%s", text)
	}
	// Границы строгие: запись до нижнего края законно получает время T1 + 1 с,
	// запись после верхнего — позже T2 − WindowEdge.
	for _, c := range []struct {
		from, to time.Time
		ok       bool
	}{
		{at(10, 0, 1), at(10, 6, 0), false},
		{at(10, 0, 1).Add(time.Nanosecond), at(10, 6, 0), true},
		{at(10, 4, 0), at(10, 8, 0), false},
		{at(10, 4, 0), at(10, 8, 0).Add(-time.Nanosecond), true},
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

// Пакет, доведённый до головы свидетеля: звенья за верхним краем есть,
// записи из них — нет.
func TestSourceToHead(t *testing.T) {
	w := newSrcWorld(t, srcOpts{})
	b := w.bundle(at(10, 4, 0), at(10, 6, 0))
	w.sign(&b, 9)
	if r := VerifySource(b, w.trust(), time.Time{}, time.Time{}); !r.Valid() || r.HeadSeq != 9 || r.UpperHead != 7 {
		t.Fatalf("до головы 9:\n%s", r.Text())
	}
	b.Records = append(b.Records, SourceRecord{Leaf: w.inclusion(9, 0)})
	sourceCheckFailed(t, VerifySource(b, w.trust(), time.Time{}, time.Time{}),
		"the records are the whole chain of the source between the tails", "after the upper tails in link 7")
}

// Владелец ключа переписывает звено верхних хвостов — занижает хвост, чтобы
// спрятать запись, — и подписывает новую голову. Метка над звеном прежняя:
// она заверяет настоящее звено, и пакет не проходит (Q-01).
func TestSourceRewrittenUpperEdge(t *testing.T) {
	w := newSrcWorld(t, srcOpts{})
	b := w.bundle(at(10, 4, 0), at(10, 6, 0))
	forged := TailsLeaf([]Tail{{Source: "abs-core", Seq: 2, Hash: auditchain.LeafHash(w.recs[2]), Salt: salt(7, "abs-core")}}, w.now.UnixNano())
	h6 := w.links[5]
	var first uint64
	for _, ls := range w.leaves[:6] {
		first += uint64(len(ls))
	}
	link, err := auditchain.LinkBatch(auditchain.Head{Seq: h6.Seq, Hash: auditchain.Hash(h6)}, w.now.UnixNano(), first, []auditchain.Leaf{forged})
	if err != nil {
		t.Fatal(err)
	}
	// Звено токена C — тоже заново, сцепленное с поддельным краем: токен в
	// нём тот же.
	eight := w.leaves[7]
	link8, err := auditchain.LinkBatch(auditchain.Head{Seq: link.Seq, Hash: auditchain.Hash(link)}, w.now.UnixNano(), first+1, eight)
	if err != nil {
		t.Fatal(err)
	}
	path, err := auditchain.MerkleProof(eight, 0)
	if err != nil {
		t.Fatal(err)
	}
	tok := Inclusion{Leaf: FromLeaf(eight[0]), LinkSeq: 8}
	for _, st := range path {
		tok.Path = append(tok.Path, Step{Hash: st.Hash[:], Left: st.SiblingLeft})
	}
	ft := FromLeaf(forged)
	b.Upper.Tails = &ft
	b.Upper.Token = tok
	b.Upper.Open = TailOf(Tail{Source: "abs-core", Seq: 2, Hash: auditchain.LeafHash(w.recs[2]), Salt: salt(7, "abs-core")})
	b.Records = b.Records[:1]
	b.Links[len(b.Links)-2] = FromLink(link)
	b.Links[len(b.Links)-1] = FromLink(link8)
	b.Statement = w.signer.Sign(auditchain.Head{Seq: link8.Seq, Hash: auditchain.Hash(link8)}, int(link8.Seq), w.now.Unix())
	sourceCheckFailed(t, VerifySource(b, w.trust(), time.Time{}, time.Time{}),
		"the upper tails are the only leaf of a link certified by a time-stamp", "the time-stamp")
}

// Свежая метка над старым звеном хвостов (B, посреди окна), взятая после
// окна и дописанная в конец цепи, — без переписи. Краем это звено не стать:
// перед ним нет токена позже окна, а закрывающий токен B лежит после него.
func TestSourceFreshTokenOverOldTails(t *testing.T) {
	w := newSrcWorld(t, srcOpts{})
	w.now = at(10, 20, 0)
	imprint := HeadImprint(5, auditchain.Hash(w.links[4]))
	fresh, err := w.tsa.Sign(imprint[:], nil)
	if err != nil {
		t.Fatal(err)
	}
	w.wlink(tokenLeaf(5, fresh)) // звено 10
	b := w.bundle(at(10, 4, 0), at(10, 6, 0))
	ut := FromLeaf(w.leaves[4][0])
	b.Upper = SourceEdge{Head: 5, Tails: &ut, Token: w.inclusion(10, 0),
		Open: TailOf(Tail{Source: "abs-core", Seq: 3, Hash: auditchain.LeafHash(w.recs[3]), Salt: salt(5, "abs-core")})}
	b.Records = b.Records[:2] // запись 4 спрятана
	w.sign(&b, 10)
	for name, c := range map[string]struct {
		closing      Inclusion
		check, cause string
	}{
		"закрывает метка A — до края":    {w.inclusion(3, 0), "the time-stamps bracket the window", "before time-stamp T2 2026-10-03 10:00:00 UTC"},
		"закрывает метка B — после края": {w.inclusion(6, 1), "the upper tails are the only leaf of a link certified by a time-stamp", "lies in link 6, not before the upper tails in link 5"},
	} {
		t.Run(name, func(t *testing.T) {
			b.Closing = c.closing
			sourceCheckFailed(t, VerifySource(b, w.trust(), time.Time{}, time.Time{}), c.check, c.cause)
		})
	}
}

func TestSourceForgedSynthetic(t *testing.T) {
	const (
		head  = "the head is signed with the store key"
		start = "the bundle starts at the beginning of the chain"
		lower = "the lower tails are the only leaf of the link the lower time-stamp certifies"
		upper = "the upper tails are the only leaf of a link certified by a time-stamp"
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
		{"в звене нижних хвостов не только они", srcOpts{lowerExtra: true}, nil, lower, "does not hold just the tails"},
		{"в звене верхних хвостов не только они", srcOpts{upperExtra: true}, nil, upper, "does not hold just the tails"},
		{"звено выброшено", srcOpts{}, func(w *srcWorld, b *SourceBundle) {
			b.Links = append(b.Links[:1], b.Links[2:]...)
		}, "the links are chained by hash with no gaps", ""},
		{"голова — не последнее звено", srcOpts{}, func(w *srcWorld, b *SourceBundle) {
			b.Statement = w.signer.Sign(auditchain.Head{Seq: 4, Hash: auditchain.Hash(w.links[3])}, 4, w.now.Unix())
		}, head, "does not match the last link"},
		{"«с начала цепи», а звенья со второго", srcOpts{}, func(w *srcWorld, b *SourceBundle) {
			b.Lower.Head = 0
		}, start, "starts at link 2"},
		{"нижних хвостов нет", srcOpts{}, func(w *srcWorld, b *SourceBundle) {
			b.Lower.Tails = nil
		}, lower, "carries no tails for link 2"},
		{"нижняя метка — над другой головой", srcOpts{}, func(w *srcWorld, b *SourceBundle) {
			b.Lower.Token = w.inclusion(6, 1)
		}, lower, "is not a time-stamp token over link 2"},
		{"токен верхней метки — до края", srcOpts{}, func(w *srcWorld, b *SourceBundle) {
			b.Upper.Token = w.inclusion(6, 1)
		}, upper, "not after link 7 it certifies"},
		{"верхняя метка — над другой головой", srcOpts{}, func(w *srcWorld, b *SourceBundle) {
			b.Upper.Token = w.inclusion(9, 0)
			w.sign(b, 9)
		}, upper, "is not a time-stamp token over link 7"},
		{"закрывающего токена нет", srcOpts{}, func(w *srcWorld, b *SourceBundle) {
			b.Closing = Inclusion{}
		}, upper, "the token of the time-stamp that closes the window"},
		{"закрывающий токен — после края", srcOpts{}, func(w *srcWorld, b *SourceBundle) {
			b.Closing = w.inclusion(8, 0)
		}, upper, "lies in link 8, not before the upper tails in link 7"},
		{"закрывающий лист — не токен", srcOpts{}, func(w *srcWorld, b *SourceBundle) {
			b.Closing = w.inclusion(6, 0)
		}, upper, "is not a time-stamp token"},
		{"край — хвосты самой закрывающей метки", srcOpts{}, func(w *srcWorld, b *SourceBundle) {
			ut := FromLeaf(w.leaves[4][0])
			b.Upper = SourceEdge{Head: 5, Tails: &ut, Token: w.inclusion(6, 1),
				Open: TailOf(Tail{Source: "abs-core", Seq: 3, Hash: auditchain.LeafHash(w.recs[3]), Salt: salt(5, "abs-core")})}
			b.Records = b.Records[:2]
			w.sign(b, 6)
		}, upper, "lies in link 6, not before the upper tails in link 5"},
		{"верхний край — звено записей", srcOpts{}, func(w *srcWorld, b *SourceBundle) {
			b.Upper.Head = 4
		}, upper, "does not hold just the tails"},
		{"токен верхней метки — не из цепи", srcOpts{}, func(w *srcWorld, b *SourceBundle) {
			b.Upper.Token.LinkSeq = 9
			w.sign(b, 9)
		}, upper, "the token of the time-stamp"},
		{"верхнего края нет в пакете", srcOpts{}, func(w *srcWorld, b *SourceBundle) {
			b.Upper.Head = 9
		}, upper, "link 9 is not in the bundle"},
		{"соль раскрытия не та", srcOpts{}, func(w *srcWorld, b *SourceBundle) {
			b.Upper.Open = TailOf(Tail{Source: "abs-core", Seq: 4, Hash: auditchain.LeafHash(w.recs[4]), Salt: salt(2, "abs-core")})
		}, upper, "does not match the tails leaf"},
		{"запись чужого источника", srcOpts{}, func(w *srcWorld, b *SourceBundle) {
			b.Records[1].Leaf = w.inclusion(4, 1)
		}, chain, "record 2 of the bundle is not a record of abs-core"},
		{"лист хвостов вместо записи", srcOpts{}, func(w *srcWorld, b *SourceBundle) {
			l := w.inclusion(5, 0)
			l.Leaf.Scope, l.Leaf.Subject = "abs-core", "9"
			b.Records = append(b.Records, SourceRecord{Leaf: l})
		}, chain, "record 4 of the bundle is not a record of abs-core"},
		{"запись переставлена", srcOpts{}, func(w *srcWorld, b *SourceBundle) {
			b.Records[0], b.Records[1] = b.Records[1], b.Records[0]
		}, chain, "record abs-core/3 does not refer to the record before it"},
		{"запись без пути", srcOpts{}, func(w *srcWorld, b *SourceBundle) {
			b.Records[0].Leaf.Path = nil
		}, chain, "record abs-core/2:"},
		{"последняя запись выброшена", srcOpts{}, func(w *srcWorld, b *SourceBundle) {
			b.Records = b.Records[:1]
		}, chain, "does not match the upper tails"},
		{"время приёма позже метки верхнего края", srcOpts{late: true}, nil, "every receive time lies between the time-stamps of the edges", "later than"},
		{"время приёма раньше нижней метки", srcOpts{early: true}, nil, "every receive time lies between the time-stamps of the edges", "is not later than"},
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

// Номера между записями, которых в цепи нет, — дыры в отчёте, а не провал:
// ссылки сходятся.
func TestSourceHoles(t *testing.T) {
	w := newSrcWorld(t, srcOpts{gap: true})
	r := VerifySource(w.bundle(at(10, 4, 0), at(10, 6, 0)), w.trust(), time.Time{}, time.Time{})
	if !r.Valid() || r.FirstSeq != 3 || r.LastSeq != 7 || len(r.Holes) != 1 || r.Holes[0] != (SeqRange{From: 5, To: 6}) {
		t.Fatalf("дыры %v:\n%s", r.Holes, r.Text())
	}
	if !strings.Contains(r.Text(), "numbers 5–6 are not in the chain between the edges") || !strings.Contains(r.Text(), "or the store lost them after accepting them") {
		t.Fatalf("отчёт:\n%s", r.Text())
	}
}

func TestTailsLeaf(t *testing.T) {
	a := Tail{Source: "abs-core", Seq: 3, Hash: [32]byte{3}, Salt: [32]byte{30}}
	p := Tail{Source: "pipelock", Seq: 1, Hash: [32]byte{1}, Salt: [32]byte{10}, Kind: "pipelock/recorder"}
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
	// Хэш чужого листа и имя известны (сосед в пути Меркла, словарь), а
	// номер не подобрать: соли аудитор не знает (Q-04).
	var entries tailsPayload
	if err := json.Unmarshal(l.Payload, &entries); err != nil {
		t.Fatal(err)
	}
	for _, e := range entries.Sources {
		for q := uint64(0); q < 1000; q++ {
			for _, guess := range [][32]byte{{}, p.Hash} {
				commit := tailCommit("pipelock", q, p.Hash, guess, p.Kind)
				if e.Commit == hexOf(commit) {
					t.Fatalf("номер чужого источника подобран: %d", q)
				}
			}
		}
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
		"номер не тот":           {l, "abs-core", TailOf(Tail{Source: "abs-core", Seq: 4, Hash: a.Hash, Salt: a.Salt}), "does not match"},
		"хэш не тот":             {l, "abs-core", TailOf(Tail{Source: "abs-core", Seq: 3, Hash: [32]byte{4}, Salt: a.Salt}), "does not match"},
		"соль не та":             {l, "abs-core", TailOf(Tail{Source: "abs-core", Seq: 3, Hash: a.Hash, Salt: [32]byte{31}}), "does not match"},
		"вид не тот":             {l, "abs-core", TailOf(Tail{Source: "abs-core", Seq: 3, Hash: a.Hash, Salt: a.Salt, Kind: "pipelock/recorder"}), "does not match"},
		"хэш не разбирается":     {l, "abs-core", &TailOpen{Seq: 3, Leaf: "zz", Salt: hexOf(a.Salt)}, "hash does not parse"},
		"хэш короче":             {l, "abs-core", &TailOpen{Seq: 3, Leaf: "0300", Salt: hexOf(a.Salt)}, "hash does not parse"},
		"соль не разбирается":    {l, "abs-core", &TailOpen{Seq: 3, Leaf: hexOf(a.Hash), Salt: "zz"}, "salt does not parse"},
		"соль короче":            {l, "abs-core", &TailOpen{Seq: 3, Leaf: hexOf(a.Hash), Salt: "1e"}, "salt does not parse"},
		"раскрытие чужим именем": {l, "pipelock", TailOf(a), "does not match"},
	} {
		if _, err := OpenTail(c.leaf, c.src, c.open); err == nil || !strings.Contains(err.Error(), c.want) {
			t.Fatalf("%s: %v", name, err)
		}
	}
}

func hexOf(b [32]byte) string { return TailOf(Tail{Hash: b}).Leaf }

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
