package proof

import (
	"encoding/json"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/Nikolay1994Kaz/evidencestore/internal/auditchain"
	"github.com/Nikolay1994Kaz/evidencestore/internal/evidence"
	"github.com/Nikolay1994Kaz/evidencestore/internal/gateway"
)

// Пакет за окно на синтетической цепи: подделки, которых честное хранилище
// не выдаст (дубль номера, время приёма не по меткам), — каждая согласована
// во всём, кроме проверяемого пункта. Путь через настоящее хранилище —
// в пакете store (window_test.go).

// wlink — звено с верным номером первого листа: окну он важен (world.link
// пишет ноль — пакету одной улики это всё равно).
func (w *world) wlink(leaves ...auditchain.Leaf) {
	w.t.Helper()
	var first uint64
	for _, ls := range w.leaves {
		first += uint64(len(ls))
	}
	r, err := auditchain.LinkBatch(w.head(), w.now.UnixNano(), first, leaves)
	if err != nil {
		w.t.Fatal(err)
	}
	w.links = append(w.links, r)
	w.leaves = append(w.leaves, leaves)
}

// window — пакет за окно над миром: участок после головы lowerHead (ноль —
// с начала цепи) до звена end, голова подписана ключом мира.
func (w *world) window(lowerHead, end uint64, from, to time.Time) WindowBundle {
	w.t.Helper()
	b := WindowBundle{Version: WindowVersion, Kind: WindowKind, From: from, To: to, LowerHead: lowerHead, StretchEnd: end}
	for _, l := range w.links[max(lowerHead, 1)-1 : end] {
		b.Links = append(b.Links, FromLink(l))
	}
	for _, ls := range w.leaves[lowerHead:end] {
		for _, l := range ls {
			b.Leaves = append(b.Leaves, FromLeaf(l))
		}
	}
	last := w.links[end-1]
	b.Statement = w.signer.Sign(auditchain.Head{Seq: last.Seq, Hash: auditchain.Hash(last)}, int(last.Seq), w.now.Unix())
	return b
}

func at(hh, mm, ss int) time.Time { return time.Date(2026, 10, 3, hh, mm, ss, 0, time.UTC) }

// windowWorld строит цепь:
//
//	звено 1: [запуск]                                  10:00, метка A над головой 1
//	звено 2: [токен A, улики из mid…]                  10:05
//	                                                   10:10, метка B над головой 2
//	звено 3: [токен B, улики из tail…]                 10:10:01
//
// Окно 10:04–10:06 закрыто метками A и B.
func windowWorld(t *testing.T, mid, tail []auditchain.Leaf) *world {
	w := newWorld(t)
	w.now = at(10, 0, 0)
	w.wlink(auditchain.Leaf{Type: auditchain.EventStart})
	hA, tA := w.stamp()
	w.now = at(10, 5, 0)
	w.wlink(append([]auditchain.Leaf{tokenLeaf(hA, tA)}, mid...)...)
	w.now = at(10, 10, 0)
	hB, tB := w.stamp()
	w.now = at(10, 10, 1)
	w.wlink(append([]auditchain.Leaf{tokenLeaf(hB, tB)}, tail...)...)
	return w
}

// rec — лист улики abs-core/seq, принятой в момент when.
func rec(t *testing.T, seq uint64, when time.Time) auditchain.Leaf {
	return evLeaf(t, sealedBytes(t, seq, when, "line "+strconv.FormatUint(seq, 10)), seq)
}

func checkFailed(t *testing.T, r WindowReport, name string) {
	t.Helper()
	for _, c := range r.Checks {
		if strings.HasPrefix(c.Name, name) {
			if c.OK {
				t.Fatalf("пункт %q прошёл, а не должен:\n%s", name, r.Text())
			}
			if r.Valid() {
				t.Fatalf("пакет прошёл с проваленным пунктом %q", name)
			}
			return
		}
	}
	t.Fatalf("пункта %q нет в отчёте:\n%s", name, r.Text())
}

func TestWindowVerifies(t *testing.T) {
	w := windowWorld(t,
		[]auditchain.Leaf{rec(t, 1, at(10, 4, 59)), rec(t, 2, at(10, 5, 0))},
		[]auditchain.Leaf{rec(t, 3, at(10, 10, 1))})
	r := VerifyWindow(w.window(1, 3, at(10, 4, 0), at(10, 6, 0)), w.trust(), time.Time{}, time.Time{})
	if !r.Valid() {
		t.Fatalf("пакет не прошёл:\n%s", r.Text())
	}
	if !r.FromBundle || r.Lower != at(10, 0, 0) || r.Upper != at(10, 10, 0) || r.StretchEnd != 3 || r.Leaves != 5 {
		t.Fatalf("окно из пакета %v, T1 %v, T2 %v, конец %d, листьев %d", r.FromBundle, r.Lower, r.Upper, r.StretchEnd, r.Leaves)
	}
	if len(r.Sources) != 1 {
		t.Fatalf("источники: %+v", r.Sources)
	}
	s := r.Sources[0]
	if s.Name != "abs-core" || s.Records != 3 || s.InWindow != 2 || s.FirstSeq != 1 || s.LastSeq != 3 || len(s.Unexplained) != 0 {
		t.Fatalf("сводка: %+v", s)
	}
	if text := r.Text(); !strings.Contains(text, "Every record the store put into its chain from head 1") || !strings.HasSuffix(text, "VERIFIED\n") {
		t.Fatalf("отчёт:\n%s", text)
	}
	// Окно аудитора шире меток — не проходит.
	if r := VerifyWindow(w.window(1, 3, at(10, 4, 0), at(10, 6, 0)), w.trust(), at(9, 59, 30), at(10, 6, 0)); r.Valid() {
		t.Fatalf("окно, начатое до T1, прошло:\n%s", r.Text())
	}
	r = VerifyWindow(w.window(1, 3, at(10, 4, 0), at(10, 6, 0)), w.trust(), at(10, 4, 0), at(10, 9, 30))
	checkFailed(t, r, "the time-stamps bracket the window")
	// Своё окно внутри меток — проходит, и отчёт говорит, что окно аудитора.
	if r := VerifyWindow(w.window(1, 3, at(10, 4, 0), at(10, 6, 0)), w.trust(), at(10, 1, 0), at(10, 8, 0)); !r.Valid() || r.FromBundle {
		t.Fatalf("окно аудитора внутри меток:\n%s", r.Text())
	}
	// Границы строгие: запись до участка законно получает время T1 + 1 с, а
	// запись после — T2 − 1 мин; окно, касающееся их, — не полное.
	for _, c := range []struct {
		from, to time.Time
		ok       bool
	}{
		{at(10, 0, 1), at(10, 6, 0), false},
		{at(10, 0, 1).Add(time.Nanosecond), at(10, 6, 0), true},
		{at(10, 4, 0), at(10, 9, 0), false},
		{at(10, 4, 0), at(10, 9, 0).Add(-time.Nanosecond), true},
	} {
		if r := VerifyWindow(w.window(1, 3, at(10, 4, 0), at(10, 6, 0)), w.trust(), c.from, c.to); r.Valid() != c.ok {
			t.Fatalf("окно %v – %v: прошло %v, ждали %v", c.from, c.to, r.Valid(), c.ok)
		}
	}
}

// Окно с начала цепи: нижней метки нет, участок — с первого звена.
func TestWindowFromChainStart(t *testing.T) {
	w := windowWorld(t, []auditchain.Leaf{rec(t, 1, at(10, 5, 0))}, nil)
	r := VerifyWindow(w.window(0, 3, at(9, 0, 0), at(10, 6, 0)), w.trust(), time.Time{}, time.Time{})
	if !r.Valid() || !r.FromStart || !r.Lower.IsZero() {
		t.Fatalf("окно с начала цепи:\n%s", r.Text())
	}
	// Пакет «с начала цепи», который начинается не с первого звена.
	b := w.window(1, 3, at(9, 0, 0), at(10, 6, 0))
	b.LowerHead = 0
	checkFailed(t, VerifyWindow(b, w.trust(), time.Time{}, time.Time{}), "the bundle holds every leaf")

	// То же там, где номера листьев этого не выдают: world.link пишет первым
	// листом каждого звена ноль, и звено 2 «начинается с листа 0». Начало
	// цепи узнаётся только по номеру первого звена и нулевому хэшу прежнего.
	w2 := newWorld(t)
	w2.link(auditchain.Leaf{Type: auditchain.EventStart})
	w2.link(rec(t, 1, at(10, 0, 0)))
	l2 := w2.links[1]
	b = WindowBundle{Version: WindowVersion, Kind: WindowKind, From: at(9, 0, 0), To: at(9, 30, 0), StretchEnd: 2,
		Links: []Link{FromLink(l2)}, Leaves: []Leaf{FromLeaf(w2.leaves[1][0])},
		Statement: w2.signer.Sign(auditchain.Head{Seq: 2, Hash: auditchain.Hash(l2)}, 2, w2.now.Unix())}
	checkFailed(t, VerifyWindow(b, w2.trust(), time.Time{}, time.Time{}), "the bundle holds every leaf")
}

// Номер у источника дважды — провал: честное хранилище кладёт улику в цепь
// один раз (повтор — обещание без листа, другое тело — событие конфликта).
func TestWindowDuplicateRecord(t *testing.T) {
	r1 := rec(t, 1, at(10, 5, 0))
	w := windowWorld(t, []auditchain.Leaf{r1, rec(t, 2, at(10, 5, 1)), r1}, nil)
	checkFailed(t, VerifyWindow(w.window(1, 3, at(10, 4, 0), at(10, 6, 0)), w.trust(), time.Time{}, time.Time{}),
		"every record leaf parses, and every record number appears once")
}

// Время приёма сверяется с ПЕРВОЙ меткой над звеном улики: поздняя метка C
// не прикрывает время позже B — в пакете одной улики хранилище выбрало бы C.
func TestWindowReceiveTimeAgainstFirstStamp(t *testing.T) {
	w := windowWorld(t, []auditchain.Leaf{rec(t, 1, at(10, 5, 0)), rec(t, 2, at(10, 12, 0))}, nil)
	w.now = at(10, 13, 0)
	hC, tC := w.stamp()
	w.now = at(10, 13, 1)
	w.wlink(tokenLeaf(hC, tC))
	r := VerifyWindow(w.window(1, 4, at(10, 4, 0), at(10, 6, 0)), w.trust(), time.Time{}, time.Time{})
	checkFailed(t, r, "every receive time lies between the time-stamps around its record")
	if !strings.Contains(r.Text(), "abs-core/2") {
		t.Fatalf("отчёт не называет улику:\n%s", r.Text())
	}

	// Улика после метки A со временем раньше A минус минута.
	w = windowWorld(t, nil, []auditchain.Leaf{rec(t, 1, at(9, 58, 59))})
	checkFailed(t, VerifyWindow(w.window(1, 3, at(10, 4, 0), at(10, 6, 0)), w.trust(), time.Time{}, time.Time{}),
		"every receive time lies between the time-stamps around its record")

	// Нижняя граница — ПОСЛЕДНЯЯ метка раньше звена улики: улика за меткой B
	// со временем 10:05 лжёт, хотя метку A (10:00) она не нарушает.
	w = windowWorld(t, nil, nil)
	w.wlink(rec(t, 1, at(10, 5, 0)))
	w.now = at(10, 20, 0)
	hC, tC = w.stamp()
	w.wlink(tokenLeaf(hC, tC))
	checkFailed(t, VerifyWindow(w.window(1, 5, at(10, 4, 0), at(10, 6, 0)), w.trust(), time.Time{}, time.Time{}),
		"every receive time lies between the time-stamps around its record")
}

// Приложенные улики сверяются со своими листами: отпечаток, время приёма в
// листе (оно вне отпечатка: хранилище могло подписать лист с чужим временем),
// улика с участка, по одному разу.
func TestWindowAttachedRecords(t *testing.T) {
	seven := sealedBytes(t, 7, at(10, 5, 0), "seven")
	good := windowWorld(t, []auditchain.Leaf{evLeaf(t, seven, 1)}, nil)
	verify := func(w *world, records ...[]byte) WindowReport {
		b := w.window(1, 3, at(10, 4, 0), at(10, 6, 0))
		for _, r := range records {
			b.Records = append(b.Records, WindowRecord{Evidence: r})
		}
		return VerifyWindow(b, w.trust(), time.Time{}, time.Time{})
	}
	r := verify(good, seven)
	if !r.Valid() || r.Attached != 1 || len(r.Bodies) != 0 || !strings.Contains(r.Text(), "1 of the 1 records attached carry no record key") {
		t.Fatalf("улика без ключа:\n%s", r.Text())
	}
	const name = "the records attached are in the stretch"
	checkFailed(t, verify(good, sealedBytes(t, 8, at(10, 5, 0), "eight")), name)
	checkFailed(t, verify(good, sealedBytes(t, 7, at(10, 5, 0), "not seven")), name)
	checkFailed(t, verify(good, seven, seven), name)

	// Лист с отпечатком улики, но другим временем приёма.
	s, err := evidence.Unmarshal(seven)
	if err != nil {
		t.Fatal(err)
	}
	h := s.Header
	h.ReceivedAt = at(10, 5, 1).UnixNano()
	odd := windowWorld(t, []auditchain.Leaf{EvidenceLeaf(h, 1, evidence.Digest(seven))}, nil)
	checkFailed(t, verify(odd, seven), name)
}

// Пропуски: записанные в цепь — в сводке; дыры без записи — в замечаниях.
func TestWindowGapsAndUnexplained(t *testing.T) {
	gap, _ := json.Marshal(SeqRange{From: 3, To: 4})
	w := windowWorld(t, []auditchain.Leaf{
		rec(t, 1, at(10, 5, 0)), rec(t, 2, at(10, 5, 0)),
		{Type: auditchain.EventGap, Scope: "abs-core", Payload: gap},
		rec(t, 5, at(10, 5, 1)), rec(t, 9, at(10, 5, 2)),
	}, nil)
	r := VerifyWindow(w.window(1, 3, at(10, 4, 0), at(10, 6, 0)), w.trust(), time.Time{}, time.Time{})
	if !r.Valid() {
		t.Fatalf("пакет не прошёл:\n%s", r.Text())
	}
	s := r.Sources[0]
	if len(s.Gaps) != 1 || s.Gaps[0] != (SeqRange{3, 4}) || len(s.Unexplained) != 1 || s.Unexplained[0] != (SeqRange{6, 8}) {
		t.Fatalf("пропуски %v, необъяснённые %v", s.Gaps, s.Unexplained)
	}
	if text := r.Text(); !strings.Contains(text, "abs-core: numbers 6–8 are not in the stretch") || !strings.Contains(text, "gap 3–4") {
		t.Fatalf("отчёт:\n%s", text)
	}
}

// События источников в сводке: молчание, связь со сборщиком, конфликт,
// вердикты гейтвея.
func TestWindowEventsSummary(t *testing.T) {
	ok, _ := json.Marshal(gatewayPayload{Pos: 1, Verdict: gateway.Verdict{Seq: 1, HashOK: true}})
	bad, _ := json.Marshal(gatewayPayload{Pos: 2, Verdict: gateway.Verdict{Seq: 2, Problem: "hash mismatch"}})
	w := windowWorld(t, []auditchain.Leaf{
		{Type: auditchain.EventSilence, Scope: "abs-core", UnixNano: at(10, 5, 0).UnixNano()},
		{Type: auditchain.EventContact, Scope: "abs-core", Subject: "lost", UnixNano: at(10, 5, 0).UnixNano()},
		{Type: auditchain.EventContact, Scope: "abs-core", Subject: "back", UnixNano: at(10, 5, 30).UnixNano()},
		{Type: auditchain.EventConflict, Scope: "abs-core"},
		{Type: auditchain.EventGateway, Scope: "pipelock", Subject: "1", Payload: ok},
		{Type: auditchain.EventGateway, Scope: "pipelock", Subject: "2", Payload: bad},
	}, nil)
	r := VerifyWindow(w.window(1, 3, at(10, 4, 0), at(10, 6, 0)), w.trust(), time.Time{}, time.Time{})
	if !r.Valid() || len(r.Sources) != 2 {
		t.Fatalf("пакет:\n%s", r.Text())
	}
	a, p := r.Sources[0], r.Sources[1]
	if a.Records != 0 || len(a.Silences) != 1 || len(a.ContactLost) != 1 || len(a.ContactBack) != 1 || a.Conflicts != 1 {
		t.Fatalf("abs-core: %+v", a)
	}
	if p.Gateway != 2 || p.GatewayBroken != 1 {
		t.Fatalf("pipelock: %+v", p)
	}
	text := r.Text()
	for _, want := range []string{"abs-core: no records", "collector lost contact at 2026-10-03 10:05:00 UTC", "collector back at 2026-10-03 10:05:30 UTC", "1 seq conflicts", "2 gateway entries, 1 broken", "silent at"} {
		if !strings.Contains(text, want) {
			t.Fatalf("в отчёте нет %q:\n%s", want, text)
		}
	}
}

// Метки участка: нижней нет, верхней нет, метка над головой, которая её же и
// держит, испорченный токен.
func TestWindowStamps(t *testing.T) {
	w := windowWorld(t, []auditchain.Leaf{rec(t, 1, at(10, 5, 0))}, nil)
	// Участок обрезан до звена 2: метка на нём одна — нижняя.
	checkFailed(t, VerifyWindow(w.window(1, 2, at(10, 4, 0), at(10, 6, 0)), w.trust(), time.Time{}, time.Time{}),
		"a TSA time-stamp in the stretch after the window (T2)")

	// Нижняя голова, над которой метки нет: участок «после головы 3», а
	// меток после неё в цепи нет.
	w2 := windowWorld(t, nil, nil)
	w2.wlink(auditchain.Leaf{Type: auditchain.EventStart})
	checkFailed(t, VerifyWindow(w2.window(3, 4, at(10, 15, 0), at(10, 16, 0)), w2.trust(), time.Time{}, time.Time{}),
		"a TSA time-stamp certifies the head the stretch starts after (T1)")

	// Токен в звене 2 «заверяет» голову 2 — ту, что его же и держит.
	w3 := newWorld(t)
	w3.now = at(10, 0, 0)
	w3.wlink(auditchain.Leaf{Type: auditchain.EventStart})
	_, tok := w3.stamp()
	w3.wlink(tokenLeaf(2, tok))
	checkFailed(t, VerifyWindow(w3.window(1, 2, at(10, 4, 0), at(10, 6, 0)), w3.trust(), time.Time{}, time.Time{}),
		"every TSA time-stamp in the stretch verifies")

	// Испорченный токен, уже лежащий в цепи: корни сходятся, метка — нет.
	w4 := newWorld(t)
	w4.now = at(10, 0, 0)
	w4.wlink(auditchain.Leaf{Type: auditchain.EventStart})
	h, bad := w4.stamp()
	bad[len(bad)/2] ^= 1
	w4.now = at(10, 10, 0)
	hB, tB := w4.stamp()
	w4.wlink(tokenLeaf(h, bad), tokenLeaf(hB, tB))
	checkFailed(t, VerifyWindow(w4.window(1, 2, at(10, 4, 0), at(10, 6, 0)), w4.trust(), time.Time{}, time.Time{}),
		"every TSA time-stamp in the stretch verifies")
}

// Вид пакета и версия: старый разбор отказывает пакету за окно внятно.
func TestWindowKindAndVersion(t *testing.T) {
	w := windowWorld(t, nil, nil)
	data, _ := json.Marshal(w.window(1, 3, at(10, 4, 0), at(10, 6, 0)))
	if kind, err := BundleKind(data); err != nil || kind != WindowKind {
		t.Fatalf("вид пакета %q, %v", kind, err)
	}
	if _, err := Parse(data); err == nil || !strings.Contains(err.Error(), "bundle version 2, supported 1") {
		t.Fatalf("разбор пакета одной улики принял окно: %v", err)
	}
	if _, err := ParseWindow(data); err != nil {
		t.Fatal(err)
	}
	single, _ := json.Marshal(Bundle{Version: Version})
	if kind, err := BundleKind(single); err != nil || kind != "" {
		t.Fatalf("вид пакета одной улики %q, %v", kind, err)
	}
	if _, err := ParseWindow(single); err == nil {
		t.Fatal("пакет одной улики разобран как окно")
	}
}

// Имя источника из пакета не управляет терминалом проверяющего.
func TestWindowTextEscapes(t *testing.T) {
	w := windowWorld(t, []auditchain.Leaf{{Type: auditchain.EventSilence, Scope: "abs\x1b[31m-core"}}, nil)
	r := VerifyWindow(w.window(1, 3, at(10, 4, 0), at(10, 6, 0)), w.trust(), time.Time{}, time.Time{})
	if text := r.Text(); strings.Contains(text, "\x1b") || !strings.Contains(text, `abs\u001b[31m-core`) {
		t.Fatalf("отчёт:\n%q", text)
	}
}

func TestUnexplained(t *testing.T) {
	for _, c := range []struct {
		seqs []uint64
		gaps []SeqRange
		want string
	}{
		{[]uint64{1, 2, 3}, nil, "[]"},
		{[]uint64{1, 5}, nil, "[2–4]"},
		{[]uint64{1, 5}, []SeqRange{{2, 4}}, "[]"},
		{[]uint64{1, 9}, []SeqRange{{3, 4}, {6, 6}}, "[2 5 7–8]"},
		{[]uint64{1, 9}, []SeqRange{{1, 20}}, "[]"},
		{[]uint64{3, 3, 4}, nil, "[]"},
	} {
		got := unexplained(c.seqs, c.gaps)
		var parts []string
		for _, g := range got {
			parts = append(parts, g.String())
		}
		if s := "[" + strings.Join(parts, " ") + "]"; s != c.want {
			t.Fatalf("unexplained(%v, %v) = %s, want %s", c.seqs, c.gaps, s, c.want)
		}
	}
}
