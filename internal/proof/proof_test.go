package proof

import (
	"crypto/ed25519"
	"encoding/base64"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/Nikolay1994Kaz/evidencestore/internal/auditchain"
	"github.com/Nikolay1994Kaz/evidencestore/internal/evidence"
	"github.com/Nikolay1994Kaz/evidencestore/internal/tsa"
)

// Синтетическая цепь: каждую проверку Verify стережёт свой тест, в котором
// подделка согласована во всём, кроме ровно этой проверки. Интеграционные
// тесты (пакет store) так не умеют: там проверки прикрывают друг друга.
//
//	звено 1: [запуск]
//	метка T1 над головой 1 → звено 2: [токен T1]
//	звено 3: [улика 1, улика 2]
//	звено 4: [событие]
//	метка T2 над головой 4 → звено 5: [токен T2]
//	подписанная голова 5

type world struct {
	t      *testing.T
	links  []auditchain.Record
	leaves [][]auditchain.Leaf
	signer *auditchain.Signer
	tsa    *tsa.Authority
	now    time.Time
}

func newWorld(t *testing.T) *world {
	t.Helper()
	signer, err := auditchain.LoadOrCreateSigner(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	a, err := tsa.NewAuthority(false)
	if err != nil {
		t.Fatal(err)
	}
	w := &world{t: t, signer: signer, tsa: a, now: time.Date(2026, 10, 3, 10, 0, 0, 0, time.UTC)}
	a.Now = func() time.Time { return w.now }
	return w
}

func (w *world) head() auditchain.Head {
	if len(w.links) == 0 {
		return auditchain.Head{}
	}
	l := w.links[len(w.links)-1]
	return auditchain.Head{Seq: l.Seq, Hash: auditchain.Hash(l)}
}

func (w *world) link(leaves ...auditchain.Leaf) {
	w.t.Helper()
	r, err := auditchain.LinkBatch(w.head(), w.now.UnixNano(), 0, leaves)
	if err != nil {
		w.t.Fatal(err)
	}
	w.links = append(w.links, r)
	w.leaves = append(w.leaves, leaves)
}

func (w *world) stamp() (uint64, []byte) {
	w.t.Helper()
	h := w.head()
	imprint := HeadImprint(h.Seq, h.Hash)
	token, err := w.tsa.Sign(imprint[:], nil)
	if err != nil {
		w.t.Fatal(err)
	}
	return h.Seq, token
}

func tokenLeaf(head uint64, token []byte) auditchain.Leaf {
	return auditchain.Leaf{Type: auditchain.EventTimestamp, Subject: strconv.FormatUint(head, 10), Payload: token}
}

func sealedBytes(t *testing.T, seq uint64, at time.Time, body string) []byte {
	t.Helper()
	b, err := evidence.Sealed{
		Header:   evidence.Header{Source: "abs-core", Seq: seq, ReceivedAt: at.UnixNano(), ContentType: "syslog"},
		Envelope: []byte("EV1-not-really-a-sealed-" + body),
	}.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func evLeaf(t *testing.T, data []byte, pos uint64) auditchain.Leaf {
	t.Helper()
	s, err := evidence.Unmarshal(data)
	if err != nil {
		t.Fatal(err)
	}
	return EvidenceLeaf(s.Header, pos, evidence.Digest(data))
}

func (w *world) inclusion(linkSeq uint64, idx int) Inclusion {
	w.t.Helper()
	leaves := w.leaves[linkSeq-1]
	path, err := auditchain.MerkleProof(leaves, idx)
	if err != nil {
		w.t.Fatal(err)
	}
	inc := Inclusion{Leaf: FromLeaf(leaves[idx]), LinkSeq: linkSeq}
	for _, p := range path {
		inc.Path = append(inc.Path, Step{Hash: p.Hash[:], Left: p.SiblingLeft})
	}
	return inc
}

func (w *world) bundle(evidenceBytes []byte, evLink uint64, evIdx int, upperHead uint64, upperToken []byte, lowerLink uint64) Bundle {
	w.t.Helper()
	b := Bundle{Version: Version, Evidence: evidenceBytes, Inclusion: w.inclusion(evLink, evIdx)}
	if upperToken != nil {
		b.Upper = &Upper{HeadSeq: upperHead, Token: upperToken}
	}
	if lowerLink != 0 {
		b.Lower = &Lower{Inclusion: w.inclusion(lowerLink, 0)}
		// Версия 3: листья звеньев от головы под T1 до звена улики.
		if head, err := strconv.ParseUint(b.Lower.Inclusion.Leaf.Subject, 10, 64); err == nil && head < evLink {
			for _, ls := range w.leaves[head:evLink] {
				for _, l := range ls {
					b.Stretch = append(b.Stretch, FromLeaf(l))
				}
			}
		}
	}
	for _, l := range w.links {
		b.Links = append(b.Links, FromLink(l))
	}
	b.Statement = w.signer.Sign(w.head(), len(w.links), w.now.Unix())
	return b
}

func (w *world) trust() Trust {
	return Trust{StoreKey: w.signer.PublicKey(), TSA: w.tsa.Trust()}
}

// standard строит мир по схеме в шапке; улика — вторая в звене 3.
func standard(t *testing.T, e2 []byte) (*world, Bundle) {
	w := newWorld(t)
	w.wlink(auditchain.Leaf{Type: auditchain.EventStart})
	h1, t1 := w.stamp()
	w.now = w.now.Add(time.Second)
	w.wlink(tokenLeaf(h1, t1))
	e1 := sealedBytes(t, 1, w.now.Add(time.Second), "first")
	if e2 == nil {
		e2 = sealedBytes(t, 2, w.now.Add(2*time.Second), "second")
	}
	w.now = w.now.Add(3 * time.Second)
	w.wlink(evLeaf(t, e1, 1), evLeaf(t, e2, 2))
	w.wlink(auditchain.Leaf{Type: auditchain.EventGap, Scope: "abs-core"})
	w.now = w.now.Add(time.Second)
	h4, t2 := w.stamp()
	w.wlink(tokenLeaf(h4, t2))
	return w, w.bundle(e2, 3, 1, h4, t2, 2)
}

func mustFail(t *testing.T, name string, b Bundle, trust Trust) {
	t.Helper()
	if r := Verify(b, trust); r.Valid() {
		t.Fatalf("%s: подделка прошла проверку:\n%s", name, r.Text())
	}
}

func TestStandardBundleVerifies(t *testing.T) {
	w, b := standard(t, nil)
	r := Verify(b, w.trust())
	if !r.Valid() || r.Lower.IsZero() || r.Upper.IsZero() || r.Header.Seq != 2 || r.Position != 2 {
		t.Fatalf("исходный пакет:\n%s", r.Text())
	}
	if r.Lower.After(r.Upper) {
		t.Fatalf("T1 %v позже T2 %v", r.Lower, r.Upper)
	}
}

// Лист в цепи согласован (путь сходится), но описывает другую улику.
// Без подмены тот же пакет проходит: падать он обязан именно на сверке листа.
func TestLeafMustDescribeEvidence(t *testing.T) {
	cases := map[string]func(*auditchain.Leaf){
		"без подмены": nil,
		"номер":       func(l *auditchain.Leaf) { l.Subject = "3" },
		"источник":    func(l *auditchain.Leaf) { l.Scope = "crm" },
		"время":       func(l *auditchain.Leaf) { l.UnixNano++ },
		"отпечаток":   func(l *auditchain.Leaf) { l.Payload[len(l.Payload)-1] ^= 1 },
	}
	for name, mutate := range cases {
		w := newWorld(t)
		w.link(auditchain.Leaf{Type: auditchain.EventStart})
		e2 := sealedBytes(t, 2, w.now.Add(-time.Second), "second")
		leaf := evLeaf(t, e2, 2)
		if mutate != nil {
			mutate(&leaf)
		}
		w.link(leaf)
		h, tok := w.stamp()
		w.link(tokenLeaf(h, tok))
		b := w.bundle(e2, 2, 0, h, tok, 0)
		if mutate == nil {
			if r := Verify(b, w.trust()); !r.Valid() {
				t.Fatalf("без подмены пакет не прошёл:\n%s", r.Text())
			}
			continue
		}
		mustFail(t, name, b, w.trust())
	}
}

// Подменённое звено со своим корнем: путь сходится, метки целы (T2 над
// следующим звеном), но звено после него ссылается на хэш настоящего.
func TestForgedLinkBreaksHashChain(t *testing.T) {
	w, b := standard(t, nil)
	forged := sealedBytes(t, 2, time.Date(2026, 10, 3, 10, 0, 3, 0, time.UTC), "forged")
	leaves := []auditchain.Leaf{w.leaves[2][0], evLeaf(t, forged, 2)}
	fake, err := auditchain.LinkBatch(auditchain.Head{Seq: 2, Hash: auditchain.Hash(w.links[1])}, w.links[2].UnixNano, 0, leaves)
	if err != nil {
		t.Fatal(err)
	}
	w.leaves[2] = leaves
	b.Evidence = forged
	b.Inclusion = w.inclusion(3, 1)
	b.Links[2] = FromLink(fake)
	mustFail(t, "подменённое звено", b, w.trust())
}

// Голова подписана чужим ключом, всё остальное верно.
func TestStatementMustBeSignedByPinnedKey(t *testing.T) {
	w, b := standard(t, nil)
	other, _ := auditchain.LoadOrCreateSigner(t.TempDir())
	b.Statement = other.Sign(w.head(), len(w.links), w.now.Unix())
	mustFail(t, "чужой ключ", b, w.trust())
	trust := w.trust()
	trust.StoreKey = ed25519.PublicKey(other.PublicKey())
	if r := Verify(b, trust); !r.Valid() {
		t.Fatalf("с ключом подписавшего пакет проходит:\n%s", r.Text())
	}
}

// Подпись верна, но голова — не последнее звено пакета.
func TestStatementMustMatchLastLink(t *testing.T) {
	w, b := standard(t, nil)
	b.Statement = w.signer.Sign(auditchain.Head{Seq: 5, Hash: auditchain.Hash(w.links[3])}, 5, w.now.Unix())
	mustFail(t, "голова не та", b, w.trust())
}

// Настоящая метка, но над головой раньше звена улики: она улику не
// покрывает.
func TestUpperMustCoverEvidence(t *testing.T) {
	w := newWorld(t)
	w.link(auditchain.Leaf{Type: auditchain.EventStart})
	h1, early := w.stamp()
	e := sealedBytes(t, 1, w.now, "x")
	w.link(evLeaf(t, e, 1))
	w.link(tokenLeaf(h1, early))
	mustFail(t, "ранняя метка как T2", w.bundle(e, 2, 0, h1, early, 0), w.trust())
}

// Настоящая метка в цепи, но в звене после улики: нижней границей она не
// служит.
func TestLowerMustPrecedeEvidence(t *testing.T) {
	w := newWorld(t)
	w.link(auditchain.Leaf{Type: auditchain.EventStart})
	e := sealedBytes(t, 1, w.now, "x")
	w.link(evLeaf(t, e, 1))
	h2, tok := w.stamp()
	w.link(tokenLeaf(h2, tok))
	mustFail(t, "поздняя метка как T1", w.bundle(e, 2, 0, h2, tok, 3), w.trust())
}

// Время приёма по часам хранилища позже метки над ним — часы врут.
func TestReceivedAtAfterUpperIsCaught(t *testing.T) {
	w := newWorld(t)
	w.link(auditchain.Leaf{Type: auditchain.EventStart})
	e := sealedBytes(t, 1, w.now.Add(time.Hour), "from the future")
	w.link(evLeaf(t, e, 1))
	h, tok := w.stamp()
	w.link(tokenLeaf(h, tok))
	mustFail(t, "время приёма из будущего", w.bundle(e, 2, 0, h, tok, 0), w.trust())
}

func TestPromise(t *testing.T) {
	w, b := standard(t, nil)
	r := Verify(b, w.trust())
	p := Promise{Source: "abs-core", Seq: 2, Position: 2, Digest: r.Digest[:], ReceivedAt: r.Header.ReceivedAt,
		Deadline: r.Header.ReceivedAt + int64(time.Minute), PublicKey: base64.RawStdEncoding.EncodeToString(w.signer.PublicKey())}
	p.Signature = w.signer.SignMessage(PromiseBytes(p))
	if err := VerifyPromise(p, w.signer.PublicKey()); err != nil {
		t.Fatal(err)
	}
	if err := CheckPromise(p, r, b, false); err != nil {
		t.Fatal(err)
	}
	bad := p
	bad.Deadline--
	if VerifyPromise(bad, w.signer.PublicKey()) == nil {
		t.Fatal("изменённое обещание прошло")
	}
	// Время звеньев в сверку обещания не входит (пакет версии 3 сверяется по
	// меткам — TestPromiseStamps).
	// Без T1 время звена — только слово хранилища.
	nr := r
	nr.Lower = time.Time{}
	if CheckPromise(p, nr, b, false) == nil {
		t.Fatal("обещание сверено без метки перед уликой")
	}
	if err := CheckPromise(p, nr, b, true); err != nil {
		t.Fatalf("-allow-no-tsa: %v", err)
	}
	other := p
	other.Digest = make([]byte, 32)
	if CheckPromise(other, r, b, false) == nil {
		t.Fatal("обещание про другие байты прошло")
	}
}

// Q-33: запись, придержанная владельцем и положенная в цепь после метки,
// закрывающей окно, со временем звена задним числом. Пакет за окно её не
// видит (она за участком), T1 в её собственном пакете выбирает хранилище —
// годится любая метка раньше звена. Опоздание выдаёт обещание: самое
// позднее время звеньев от T1 до звена записи — у звена токена B, а его
// время не раньше времени метки минус ReceiveSkew. Задним числом и звено
// токена — тогда не проходит пакет за окно.
//
//	звено 1: [запуск]                         10:00, метка A над головой 1
//	звено 2: [токен A, abs-core 1 (10:02)]    10:02
//	звено 3: [событие]                        10:07 (задним числом — 10:05:30)
//	                                          10:09, метка B над головой 3
//	звено 4: [токен B]                        10:09 (задним числом — 10:05:30)
//	звено 5: [abs-core 2 (принята 10:05)]     положено в 10:20, время звена — 10:05:30
//	                                          10:20, метка C над головой 5
//	звено 6: [токен C]                        10:20
func TestPromiseHeldBackRecord(t *testing.T) {
	for _, backdateB := range []bool{false, true} {
		w := newWorld(t)
		w.now = at(10, 0, 0)
		w.wlink(auditchain.Leaf{Type: auditchain.EventStart})
		hA, tA := w.stamp()
		w.now = at(10, 2, 0)
		w.wlink(tokenLeaf(hA, tA), rec(t, 1, at(10, 2, 0)))
		w.now = at(10, 7, 0)
		silence := auditchain.Leaf{UnixNano: w.now.UnixNano(), Type: auditchain.EventSilence, Scope: "other"}
		if backdateB {
			w.now = at(10, 5, 30)
		}
		w.wlink(silence)
		w.now = at(10, 9, 0)
		hB, tB := w.stamp()
		if backdateB {
			w.now = at(10, 5, 30)
		}
		w.wlink(tokenLeaf(hB, tB))
		held := sealedBytes(t, 2, at(10, 5, 0), "held back")
		w.now = at(10, 5, 30)
		w.wlink(evLeaf(t, held, 2))
		w.now = at(10, 20, 0)
		hC, tC := w.stamp()
		w.wlink(tokenLeaf(hC, tC))

		from, to := at(10, 1, 0), at(10, 6, 0)
		wr := VerifyWindow(w.window(1, 4, from, to), w.trust(), from, to)
		b := w.bundle(held, 5, 0, hC, tC, 2)
		r := Verify(b, w.trust())
		if !r.Valid() {
			t.Fatalf("задним числом %v: пакет записи с T1 = A:\n%s", backdateB, r.Text())
		}
		digest := evidence.Digest(held)
		p := Promise{Source: "abs-core", Seq: 2, Position: 2, Digest: digest[:], ReceivedAt: at(10, 5, 0).UnixNano(),
			Deadline: at(10, 6, 0).UnixNano(), PublicKey: base64.RawStdEncoding.EncodeToString(w.signer.PublicKey())}
		perr := CheckPromise(p, r, b, false)
		honest := Verify(w.bundle(held, 5, 0, hC, tC, 4), w.trust())
		// Сверка по меткам: токен B лежит перед записью, время его метки
		// позже срока — опоздание видно, задним числом звенья или нет.
		if perr == nil || !strings.Contains(perr.Error(), "link 4") {
			t.Fatalf("задним числом %v: обещание: %v", backdateB, perr)
		}
		if !backdateB {
			if !wr.Valid() {
				t.Fatalf("пакет за окно %s", wr.Verdict())
			}
			continue
		}
		// Звено токена B задним числом выдают и пакет за окно, и пакет записи
		// с T1 = B.
		if wr.Valid() || honest.Valid() {
			t.Fatalf("пакет за окно %s; пакет записи с T1 = B %s", wr.Verdict(), honest.Verdict())
		}
		checkFailed(t, wr, "every TSA time-stamp in the stretch verifies")
		if !strings.Contains(honest.Text(), "backdated the link") {
			t.Fatalf("пакет записи с T1 = B:\n%s", honest.Text())
		}
	}
}

// Q-57: срок в обещании пишет само хранилище. Владелец, поменявший код,
// подписывает срок в час и придерживает запись за метку, что закрывает окно,
// — в цепь она ложится честно, без звеньев задним числом. Пакет за окно и
// пакет по источнику проходят без неё, пакет записи — тоже; обещание её
// выдаёт: время звена сверяется с ReceivedAt + MaxPromiseMMD, что бы ни
// стояло в сроке.
//
// Пакет за окно — цепь честная:
//
//	звено 1: [запуск]                         10:00, метка A над головой 1
//	звено 2: [токен A, abs-core 1 (10:02)]    10:02
//	звено 3: [молчит: other]                  10:07
//	                                          10:09, метка B над головой 3
//	звено 4: [токен B]                        10:09 — закрывает окно 10:01–10:06
//	звено 5: [abs-core 2 (принята 10:05)]     10:20 — придержана за B
//	                                          10:21, метка C над головой 5
//	звено 6: [токен C]                        10:21
//
// Пакет по источнику — мир srcWorld (окно 10:04–10:06), запись abs-core 6
// принята в 10:05:45 и легла в 10:13, после верхнего края.
func TestPromiseDeadlineCapped(t *testing.T) {
	promise := func(w *world, data []byte, seq uint64, recv time.Time, mmd time.Duration) Promise {
		digest := evidence.Digest(data)
		p := Promise{Source: "abs-core", Seq: seq, Position: seq, Digest: digest[:], ReceivedAt: recv.UnixNano(),
			Deadline: recv.Add(mmd).UnixNano(), PublicKey: base64.RawStdEncoding.EncodeToString(w.signer.PublicKey())}
		p.Signature = w.signer.SignMessage(PromiseBytes(p))
		return p
	}
	t.Run("window", func(t *testing.T) {
		w := newWorld(t)
		w.now = at(10, 0, 0)
		w.wlink(auditchain.Leaf{Type: auditchain.EventStart})
		hA, tA := w.stamp()
		w.now = at(10, 2, 0)
		w.wlink(tokenLeaf(hA, tA), rec(t, 1, at(10, 2, 0)))
		w.now = at(10, 7, 0)
		w.wlink(auditchain.Leaf{UnixNano: w.now.UnixNano(), Type: auditchain.EventSilence, Scope: "other"})
		w.now = at(10, 9, 0)
		hB, tB := w.stamp()
		w.wlink(tokenLeaf(hB, tB))
		held := sealedBytes(t, 2, at(10, 5, 0), "held back")
		w.now = at(10, 20, 0)
		w.wlink(evLeaf(t, held, 2))
		w.now = at(10, 21, 0)
		hC, tC := w.stamp()
		w.wlink(tokenLeaf(hC, tC))

		from, to := at(10, 1, 0), at(10, 6, 0)
		wr := VerifyWindow(w.window(1, 4, from, to), w.trust(), from, to)
		if !wr.Valid() {
			t.Fatalf("пакет за окно:\n%s", wr.Text())
		}
		for _, s := range wr.Sources {
			if s.Name == "abs-core" && s.LastSeq >= 2 {
				t.Fatalf("пакет за окно показал придержанную запись: %+v", s)
			}
		}
		b := w.bundle(held, 5, 0, hC, tC, 2)
		r := Verify(b, w.trust())
		if !r.Valid() {
			t.Fatalf("пакет записи:\n%s", r.Text())
		}
		for _, mmd := range []time.Duration{MaxPromiseMMD, 20 * time.Minute, time.Hour} {
			if err := CheckPromise(promise(w, held, 2, at(10, 5, 0), mmd), r, b, false); err == nil || !strings.Contains(err.Error(), "lies before the record") {
				t.Errorf("срок %s: запись легла через 15 минут, обещание: %v", mmd, err)
			}
		}
	})
	t.Run("source", func(t *testing.T) {
		w := newSrcWorld(t, srcOpts{})
		recv := at(10, 5, 45)
		data := sealedBytes(t, 6, recv, "held back")
		sx, _ := evidence.Unmarshal(data)
		w.now = at(10, 13, 0)
		w.wlink(EvidenceLeafLinked(sx.Header, 6, evidence.Digest(data), auditchain.LeafHash(w.recs[5]))) // звено 10
		hD, tD := w.stamp()
		w.wlink(tokenLeaf(hD, tD)) // звено 11

		from, to := at(10, 4, 0), at(10, 6, 0)
		sr := VerifySource(w.bundle(from, to), w.trust(), from, to)
		if !sr.Valid() || sr.LastSeq >= 6 {
			t.Fatalf("пакет по источнику (записи %d–%d):\n%s", sr.FirstSeq, sr.LastSeq, sr.Text())
		}
		b := w.world.bundle(data, 10, 0, hD, tD, 3) // T1 — метка A
		r := Verify(b, w.trust())
		if !r.Valid() {
			t.Fatalf("пакет записи:\n%s", r.Text())
		}
		if err := CheckPromise(promise(w.world, data, 6, recv, time.Hour), r, b, false); err == nil || !strings.Contains(err.Error(), "lies before the record") {
			t.Fatalf("срок в час: запись легла через 7 минут, обещание: %v", err)
		}
	})
	// Обещание хранилища v0.2.0 с promise_mmd в 5 минут: запись, легшая за
	// минуту, проходит; легшая через две минуты — нет, хотя свой срок
	// хранилище выдержало.
	// Обещание хранилища v0.2.0 с promise_mmd в 5 минут: честная запись
	// проходит (перед ней лишь метка T1); срок раньше времени приёма — отказ.
	t.Run("long promise_mmd", func(t *testing.T) {
		w, b := standard(t, nil)
		r := Verify(b, w.trust())
		recv := time.Unix(0, r.Header.ReceivedAt)
		p := promise(w, b.Evidence, 2, recv, 5*time.Minute)
		if err := CheckPromise(p, r, b, false); !r.Valid() || err != nil {
			t.Fatalf("срок 5 минут: пакет %s; обещание: %v", r.Verdict(), err)
		}
		back := p
		back.Deadline = p.ReceivedAt - 1
		if err := CheckPromise(back, r, b, false); err == nil || !strings.Contains(err.Error(), "earlier than the receive time") {
			t.Fatalf("срок раньше времени приёма: %v", err)
		}
	})
}

// Почему тело закрыто, отчёт называет верно. Ключ не выдан — одна причина
// (так бывает и после стирания). Выданный ключ не подошёл — другая: тело
// или ключ подменены, и это видно в проверках.
func TestNotesTellWhyBodyIsClosed(t *testing.T) {
	closed := func(r Report) string {
		for _, n := range r.Notes() {
			if strings.HasPrefix(n, "body not opened") {
				return n
			}
		}
		return ""
	}
	w, b := standard(t, nil)
	if n := closed(Verify(b, w.trust())); !strings.Contains(n, "carries no record key") {
		t.Errorf("без ключа записи: %q", n)
	}
	b.DEK = make([]byte, 32)
	r := Verify(b, w.trust())
	if r.Valid() {
		t.Fatal("чужой ключ записи вскрыл тело")
	}
	if n := closed(r); !strings.Contains(n, "does not fit") {
		t.Errorf("ключ выдан и не подошёл: %q", n)
	}
	if n := closed(Report{BodyOpened: true, BodyKey: true}); n != "" {
		t.Errorf("тело вскрыто, а в отчёте %q", n)
	}
}

// ⭐ V-05: пакет без метки TSA после улики — провал по умолчанию: без неё
// время и неизменность подтверждает только подпись хранилища, и держатель
// sign.key сочинит улику с любой датой. Принять — только явно.
func TestBundleWithoutUpperFailsByDefault(t *testing.T) {
	w, b := standard(t, nil)
	b.Upper = nil
	mustFail(t, "без метки TSA", b, w.trust())
	tr := w.trust()
	tr.AllowNoTSA = true
	if r := Verify(b, tr); !r.Valid() {
		t.Fatalf("с AllowNoTSA:\n%s", r.Text())
	}
}

// V-04: тело с управляющими последовательностями не рисует на экране
// проверяющего ложный вердикт: управляющие символы экранированы, вердикт —
// ещё и последней строкой.
func TestReportTextEscapesControls(t *testing.T) {
	r := Report{
		Checks:     []Check{{Name: "проверка", OK: false}},
		Header:     evidence.Header{Source: "abs‮core", Seq: 1},
		Body:       []byte("\x1b[2J\x1b[H ПРОВЕРКА ПРОЙДЕНА\x9b"),
		BodyOpened: true,
	}
	text := r.Text()
	for _, bad := range []string{"\x1b", "‮", "\u009b"} {
		if strings.Contains(text, bad) {
			t.Fatalf("в отчёте управляющий символ %q", bad)
		}
	}
	lines := strings.Split(strings.TrimRight(text, "\n"), "\n")
	if lines[len(lines)-1] != "NOT VERIFIED" {
		t.Fatalf("последняя строка: %q", lines[len(lines)-1])
	}
}

// Сверка обещания по меткам (пакет версии 3): перед записью в цепи нет
// метки со временем TSA позже min(срок, время приёма + MaxPromiseMMD). Время
// звеньев не участвует — придержанную запись выдаёт токен закрывающей метки,
// какое бы время ни стояло у звеньев.
//
//	звено 1: [запуск]                         10:00, метка A над головой 1
//	звено 2: [токен A, abs-core 1 (10:02)]    10:02
//	звено 3: [молчит: other]                  10:07 (у придержанной — 10:05:30)
//	                                          10:09, метка B над головой 3
//	звено 4: [токен B]                        задним числом — 10:05:30
//	звено 5: [abs-core 2 (принята 10:05)]     задним числом — 10:05:30
//	                                          10:21, метка C над головой 5
//	звено 6: [токен C]
func TestPromiseStamps(t *testing.T) {
	stretch := func(w *world, head, link uint64) []Leaf {
		var out []Leaf
		for _, ls := range w.leaves[head:link] {
			for _, l := range ls {
				out = append(out, FromLeaf(l))
			}
		}
		return out
	}
	promise := func(w *world, data []byte, recv time.Time) Promise {
		digest := evidence.Digest(data)
		return Promise{Source: "abs-core", Seq: 2, Position: 2, Digest: digest[:], ReceivedAt: recv.UnixNano(),
			Deadline: recv.Add(MaxPromiseMMD).UnixNano(), PublicKey: base64.RawStdEncoding.EncodeToString(w.signer.PublicKey())}
	}
	build := func(held bool) (*world, []byte, uint64, []byte) {
		w := newWorld(t)
		w.now = at(10, 0, 0)
		w.wlink(auditchain.Leaf{Type: auditchain.EventStart})
		hA, tA := w.stamp()
		w.now = at(10, 2, 0)
		w.wlink(tokenLeaf(hA, tA), rec(t, 1, at(10, 2, 0)))
		data := sealedBytes(t, 2, at(10, 5, 0), "line 2")
		if !held {
			w.now = at(10, 5, 1)
			w.wlink(evLeaf(t, data, 2)) // звено 3: запись вовремя
		}
		w.now = at(10, 7, 0)
		if held {
			w.now = at(10, 5, 30) // владелец датирует задним числом все звенья
		}
		w.wlink(auditchain.Leaf{UnixNano: w.now.UnixNano(), Type: auditchain.EventSilence, Scope: "other"})
		w.now = at(10, 9, 0)
		hB, tB := w.stamp()
		w.now = at(10, 5, 30) // задним числом — время звеньев сверке не мешает
		w.wlink(tokenLeaf(hB, tB))
		if held {
			w.wlink(evLeaf(t, data, 2)) // звено 5: придержана за B
		}
		w.now = at(10, 21, 0)
		hC, tC := w.stamp()
		w.wlink(tokenLeaf(hC, tC))
		return w, data, hC, tC
	}

	// Честно: запись в звене 3, до метки B.
	w, data, hC, tC := build(false)
	b := w.bundle(data, 3, 0, hC, tC, 2)
	b.Version, b.Stretch = Version, stretch(w, 1, 3)
	r := Verify(b, w.trust())
	if err := CheckPromise(promise(w, data, at(10, 5, 0)), r, b, false); !r.Valid() || err != nil {
		t.Fatalf("честная запись: пакет %s; обещание: %v", r.Verdict(), err)
	}

	// Придержана за метку B, все звенья задним числом: по времени звеньев
	// (версия 2) — «выполнено», по меткам — нет.
	w, data, hC, tC = build(true)
	b = w.bundle(data, 5, 0, hC, tC, 2)
	p := promise(w, data, at(10, 5, 0))
	old := b
	old.Version, old.Stretch = 2, nil
	if err := CheckPromise(p, Verify(old, w.trust()), old, false); err == nil || !strings.Contains(err.Error(), "ask the store") {
		t.Fatalf("пакет версии 2 (по времени звеньев придержанная запись не видна) сверен: %v", err)
	}
	b.Version, b.Stretch = Version, stretch(w, 1, 5)
	r = Verify(b, w.trust())
	if err := CheckPromise(p, r, b, false); !r.Valid() || err == nil || !strings.Contains(err.Error(), "link 4") {
		t.Fatalf("придержанная запись: пакет %s; обещание: %v", r.Verdict(), err)
	}
	// Листья не убрать и не добавить: корни звеньев сверяются.
	short := b
	short.Stretch = slices.Clone(b.Stretch)
	short.Stretch = slices.Delete(short.Stretch, 2, 3) // лист токена B
	if err := CheckPromise(p, r, short, false); err == nil || !strings.Contains(err.Error(), "Merkle root") {
		t.Fatalf("убран лист токена: %v", err)
	}
	long := b
	long.Stretch = append(slices.Clone(b.Stretch), FromLeaf(auditchain.Leaf{Type: auditchain.EventStart}))
	if err := CheckPromise(p, r, long, false); err == nil {
		t.Fatal("лишний лист прошёл")
	}
	// Без T1 — только с -allow-no-tsa.
	none := b
	none.Lower, none.Stretch = nil, nil
	nr := Verify(none, w.trust())
	if CheckPromise(p, nr, none, false) == nil || CheckPromise(p, nr, none, true) != nil {
		t.Fatal("пакет без T1")
	}
}
