package store

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/Nikolay1994Kaz/evidencestore/internal/auditchain"
	"github.com/Nikolay1994Kaz/evidencestore/internal/evidence"
	"github.com/Nikolay1994Kaz/evidencestore/internal/keyring"
	"github.com/Nikolay1994Kaz/evidencestore/internal/proof"
	"github.com/Nikolay1994Kaz/evidencestore/internal/tsa"
)

// Пакет по источнику на настоящем хранилище (DECISIONS, п. 28).

// sourceStore — два источника в одном окне, по часам теста:
//
//	10:00 abs-core 1–3, pipelock 1–2, метка A
//	10:05 abs-core 4–6, pipelock 3–5
//	10:10 метка B
//	10:11 abs-core 7–8, метка C
func sourceStore(t *testing.T) (*Store, *clock) {
	t.Helper()
	c := newClock()
	s := openStore(t, testConfig(t), c)
	ingest(t, s, "abs-core", 1, 3)
	ingest(t, s, "pipelock", 1, 2)
	mustStamp(t, s)
	c.add(5 * time.Minute)
	ingest(t, s, "abs-core", 4, 6)
	ingest(t, s, "pipelock", 3, 5)
	c.add(5 * time.Minute)
	mustStamp(t, s)
	c.add(time.Minute)
	ingest(t, s, "abs-core", 7, 8)
	mustStamp(t, s)
	return s, c
}

// wholeChainSource — вся цепочка источника одним пакетом: от начала цепи до
// последней метки, как wholeChainWindow. Симуляции проверяют им, что честная
// история — падения, подъёмы, повторная привязка листьев — даёт цепочку
// источника без разрыва.
func wholeChainSource(s *Store, source string, trust proof.Trust) (proof.SourceReport, error) {
	s.chainMu.Lock()
	var last time.Time
	if n := len(s.tokens); n > 0 {
		last = s.tokens[n-1].gen
	}
	s.chainMu.Unlock()
	if last.IsZero() {
		return proof.SourceReport{}, errors.New("в цепи нет меток")
	}
	from, to := time.Unix(1, 0).UTC(), last.Add(-proof.ReceiveSkew-time.Nanosecond)
	b, err := s.ProofSource(source, from, to, false, 0)
	if err != nil {
		return proof.SourceReport{}, err
	}
	return proof.VerifySource(b, trust, from, to), nil
}

// midChainSource — пакет по источнику от метки в середине цепи до последней:
// нижние хвосты и их раскрытие после падений и подъёмов. ok = false — меток
// меньше трёх или они слишком близко: окна между ними нет.
func midChainSource(s *Store, source string, trust proof.Trust) (r proof.SourceReport, ok bool, err error) {
	s.chainMu.Lock()
	n := len(s.tokens)
	var mid, last time.Time
	if n >= 3 {
		mid, last = s.tokens[n/2].gen, s.tokens[n-1].gen
	}
	s.chainMu.Unlock()
	from, to := mid.Add(proof.ReceiveSlack+time.Nanosecond), last.Add(-proof.ReceiveSkew-time.Nanosecond)
	if n < 3 || !to.After(from) {
		return r, false, nil
	}
	b, err := s.ProofSource(source, from, to, false, 0)
	if err != nil {
		return r, true, err
	}
	return proof.VerifySource(b, trust, from, to), true, nil
}

// sourceFailedChecks — проваленные пункты отчёта одной строкой.
func sourceFailedChecks(r proof.SourceReport) string {
	var out []string
	for _, c := range r.Checks {
		if !c.OK {
			out = append(out, c.Name+": "+c.Detail)
		}
	}
	return strings.Join(out, "; ")
}

func sourceRoundTrip(t *testing.T, b proof.SourceBundle) proof.SourceBundle {
	t.Helper()
	data, err := json.Marshal(b)
	if err != nil {
		t.Fatal(err)
	}
	out, err := proof.ParseSource(data)
	if err != nil {
		t.Fatal(err)
	}
	return out
}

func sourceFailed(t *testing.T, r proof.SourceReport, name string) {
	t.Helper()
	if r.Valid() {
		t.Fatalf("подделка прошла:\n%s", r.Text())
	}
	for _, c := range r.Checks {
		if strings.HasPrefix(c.Name, name) && !c.OK {
			return
		}
	}
	t.Fatalf("провален не пункт %q:\n%s", name, r.Text())
}

// ⭐ Окно 10:04–10:06 по abs-core: записи 4–6 с телами, цепочка от нижних
// хвостов (A) до верхних (B); pipelock в пакете не виден ни записями, ни
// именем.
func TestSourceProof(t *testing.T) {
	s, _ := sourceStore(t)
	b, err := s.ProofSource("abs-core", clockAt(10, 4, 0), clockAt(10, 6, 0), true, 0)
	if err != nil {
		t.Fatal(err)
	}
	r := proof.VerifySource(sourceRoundTrip(t, b), trustOf(t, s), time.Time{}, time.Time{})
	if !r.Valid() {
		t.Fatalf("пакет не прошёл:\n%s", r.Text())
	}
	if r.Records != 3 || r.InWindow != 3 || r.FirstSeq != 4 || r.LastSeq != 6 || len(r.Bodies) != 3 || len(r.Holes) != 0 {
		t.Fatalf("записей %d (%d в окне), номера %d–%d, тел %d, дыры %v", r.Records, r.InWindow, r.FirstSeq, r.LastSeq, len(r.Bodies), r.Holes)
	}
	if !r.Lower.Equal(clockAt(10, 0, 0)) || !r.Upper.Equal(clockAt(10, 10, 0)) {
		t.Fatalf("T1 %v, T2 %v", r.Lower, r.Upper)
	}
	for _, body := range r.Bodies {
		if want := fmt.Sprintf("abs-core event %d", body.Seq); string(body.Body) != want {
			t.Fatalf("тело %d: %q", body.Seq, body.Body)
		}
	}
	data, _ := json.Marshal(b)
	if bytes.Contains(data, []byte("pipelock")) {
		t.Fatal("в пакете по abs-core видно имя pipelock")
	}
	for _, rec := range b.Records {
		if rec.Leaf.Leaf.Scope != "abs-core" {
			t.Fatalf("в пакете лист %s", rec.Leaf.Leaf.Scope)
		}
	}
	// Метки выбираются по допускам: окно до 10:09:30 закрывает C (B ближе
	// минуты к концу), окно с 10:00:00.5 — начало цепи (A ближе секунды).
	for _, c := range []struct {
		from, to    time.Time
		upper       time.Time
		fromStart   bool
		first, last uint64
	}{
		{clockAt(10, 4, 0), clockAt(10, 9, 30), clockAt(10, 11, 0), false, 4, 8},
		{clockAt(10, 0, 0).Add(500 * time.Millisecond), clockAt(10, 6, 0), clockAt(10, 10, 0), true, 1, 6},
	} {
		b, err := s.ProofSource("abs-core", c.from, c.to, false, 0)
		if err != nil {
			t.Fatal(err)
		}
		r := proof.VerifySource(sourceRoundTrip(t, b), trustOf(t, s), time.Time{}, time.Time{})
		if !r.Valid() || !r.Upper.Equal(c.upper) || r.FromStart != c.fromStart || r.FirstSeq != c.first || r.LastSeq != c.last {
			t.Fatalf("окно %v – %v:\n%s", c.from, c.to, r.Text())
		}
	}
	// Тот же час по pipelock — его записи 3–5.
	pb, err := s.ProofSource("pipelock", clockAt(10, 4, 0), clockAt(10, 6, 0), false, 0)
	if err != nil {
		t.Fatal(err)
	}
	if r := proof.VerifySource(sourceRoundTrip(t, pb), trustOf(t, s), time.Time{}, time.Time{}); !r.Valid() || r.FirstSeq != 3 || r.LastSeq != 5 || r.Attached != 0 {
		t.Fatalf("pipelock:\n%s", r.Text())
	}
}

// Окно до первой метки: с начала цепи, цепочка источника — с нулей.
func TestSourceProofFromChainStart(t *testing.T) {
	s, _ := sourceStore(t)
	b, err := s.ProofSource("abs-core", clockAt(9, 0, 0), clockAt(9, 30, 0), false, 0)
	if err != nil {
		t.Fatal(err)
	}
	r := proof.VerifySource(sourceRoundTrip(t, b), trustOf(t, s), time.Time{}, time.Time{})
	if !r.Valid() || !r.FromStart || r.FirstSeq != 1 || r.LastSeq != 3 || r.InWindow != 0 {
		t.Fatalf("с начала цепи:\n%s", r.Text())
	}
}

// Хранилище подделывает пакет: выбросить запись из середины или с конца,
// переставить, раскрыть хвосты иначе — всё видно без чужих листьев.
func TestSourceProofForged(t *testing.T) {
	s, _ := sourceStore(t)
	good, err := s.ProofSource("abs-core", clockAt(10, 4, 0), clockAt(10, 6, 0), true, 0)
	if err != nil {
		t.Fatal(err)
	}
	if len(good.Records) != 3 || good.LowerOpen == nil || good.UpperOpen == nil {
		t.Fatalf("раскладка теста поменялась: записей %d", len(good.Records))
	}
	trust := trustOf(t, s)
	clone := func() proof.SourceBundle { return sourceRoundTrip(t, good) }
	verify := func(b proof.SourceBundle) proof.SourceReport {
		return proof.VerifySource(b, trust, time.Time{}, time.Time{})
	}
	const chain = "the records are the whole chain of the source between the tails"

	b := clone()
	b.Records = append(b.Records[:1], b.Records[2:]...)
	sourceFailed(t, verify(b), chain)

	b = clone()
	b.Records = b.Records[:2]
	sourceFailed(t, verify(b), chain)

	b = clone()
	b.Records = b.Records[1:]
	sourceFailed(t, verify(b), chain)

	b = clone()
	b.Records[0], b.Records[1] = b.Records[1], b.Records[0]
	sourceFailed(t, verify(b), chain)

	// Конец, сдвинутый вместе с раскрытием: верхние хвосты не сходятся.
	b = clone()
	b.Records = b.Records[:2]
	l := b.Records[1].Leaf.Leaf.Chain()
	b.UpperOpen = proof.TailOf(proof.Tail{Source: "abs-core", Seq: 5, Hash: auditchain.LeafHash(l)})
	sourceFailed(t, verify(b), "the upper tails")

	// Раскрытие снято: хвосты называют источник.
	b = clone()
	b.LowerOpen = nil
	sourceFailed(t, verify(b), "the lower tails")
	b = clone()
	b.UpperOpen.Seq++
	sourceFailed(t, verify(b), "the upper tails")

	// Лист нижних хвостов подменён.
	b = clone()
	b.LowerTails.Payload = append([]byte(nil), b.LowerTails.Payload...)
	b.LowerTails.Payload[len(b.LowerTails.Payload)/2] ^= 1
	sourceFailed(t, verify(b), "the lower tails")

	// Запись с места после токена верхней метки и лист чужого звена.
	b = clone()
	b.Records[2].Leaf.Index++
	sourceFailed(t, verify(b), chain)

	// Окно аудитора шире меток.
	if r := proof.VerifySource(clone(), trust, clockAt(9, 59, 0), clockAt(10, 6, 0)); r.Valid() {
		t.Fatalf("окно до T1 прошло:\n%s", r.Text())
	}
	// Приложенное тело чужим ключом записи.
	b = clone()
	b.Records[0].DEK, b.Records[1].DEK = b.Records[1].DEK, b.Records[0].DEK
	sourceFailed(t, verify(b), "the records attached")
}

// Окно без записей источника: пакет пуст, нижнее и верхнее раскрытия —
// один и тот же лист, abs-core 8.
func TestSourceProofEmptyWindow(t *testing.T) {
	s, c := sourceStore(t)
	c.add(5 * time.Minute)
	ingest(t, s, "pipelock", 6, 6)
	mustStamp(t, s) // 10:16
	b, err := s.ProofSource("abs-core", clockAt(10, 11, 2), clockAt(10, 14, 0), false, 0)
	if err != nil {
		t.Fatal(err)
	}
	r := proof.VerifySource(sourceRoundTrip(t, b), trustOf(t, s), time.Time{}, time.Time{})
	if !r.Valid() || r.Records != 0 || b.LowerOpen == nil || *b.LowerOpen != *b.UpperOpen || b.LowerOpen.Seq != 8 ||
		!strings.Contains(r.Text(), "is in this bundle: no records") {
		t.Fatalf("пустое окно:\n%s", r.Text())
	}
}

// Цепочка источника переживает перезапуск: первая запись после подъёма
// ссылается на последнюю до него.
func TestSourceProofAcrossRestart(t *testing.T) {
	c := newClock()
	cfg := testConfig(t)
	s := openStore(t, cfg, c)
	ingest(t, s, "abs-core", 1, 3)
	mustStamp(t, s) // 10:00
	s.Close()
	c.add(5 * time.Minute)
	s = openStore(t, cfg, c)
	ingest(t, s, "abs-core", 4, 6)
	c.add(5 * time.Minute)
	mustStamp(t, s) // 10:10
	b, err := s.ProofSource("abs-core", clockAt(10, 4, 0), clockAt(10, 6, 0), false, 0)
	if err != nil {
		t.Fatal(err)
	}
	if r := proof.VerifySource(sourceRoundTrip(t, b), trustOf(t, s), time.Time{}, time.Time{}); !r.Valid() || r.FirstSeq != 4 || r.LastSeq != 6 || b.LowerOpen.Seq != 3 {
		t.Fatalf("через перезапуск:\n%s", r.Text())
	}
}

// Свидетель голов — как у пакета за окно: голова свидетеля за концом пакета
// — проси пакет до неё (-to-head), с ней пакет проходит.
func TestSourceProofWitness(t *testing.T) {
	s, _ := sourceStore(t)
	head := s.Statement()
	trust := trustOf(t, s)
	trust.Witness = &proof.Witness{Heads: []proof.PublishedHead{{Name: "head.json", Statement: head}}}
	b, err := s.ProofSource("abs-core", clockAt(10, 4, 0), clockAt(10, 6, 0), false, 0)
	if err != nil {
		t.Fatal(err)
	}
	sourceFailed(t, proof.VerifySource(sourceRoundTrip(t, b), trust, time.Time{}, time.Time{}), "the chain in the bundle agrees with the heads the witness saw")
	if b, err = s.ProofSource("abs-core", clockAt(10, 4, 0), clockAt(10, 6, 0), false, head.HeadSeq); err != nil {
		t.Fatal(err)
	}
	r := proof.VerifySource(sourceRoundTrip(t, b), trust, time.Time{}, time.Time{})
	if !r.Valid() || !r.WitnessChecked || r.WitnessHead != head.HeadSeq || r.UpperLink >= head.HeadSeq {
		t.Fatalf("голова свидетеля %d:\n%s", head.HeadSeq, r.Text())
	}

	// Свидетель видел голову посреди пакета (звено улик 4–6): с пакетом она
	// сходится, но верхние хвосты не закрепляет — такой головы у свидетеля
	// ещё нет.
	mid := b.LowerHead + 2
	_, chainDir, _ := dirs(s.cfg)
	links, err := auditchain.ReadLinks(chainDir, mid, mid)
	if err != nil {
		t.Fatal(err)
	}
	trust.Witness = &proof.Witness{Heads: []proof.PublishedHead{{Name: "mid.json",
		Statement: s.signer.Sign(auditchain.Head{Seq: mid, Hash: auditchain.Hash(links[0])}, int(mid), 0)}}}
	if b, err = s.ProofSource("abs-core", clockAt(10, 4, 0), clockAt(10, 6, 0), false, 0); err != nil {
		t.Fatal(err)
	}
	if r := proof.VerifySource(sourceRoundTrip(t, b), trust, time.Time{}, time.Time{}); !r.Valid() || !r.WitnessNone || r.WitnessHead != 0 {
		t.Fatalf("голова свидетеля посреди пакета (%d):\n%s", mid, r.Text())
	}
}

// oldStamp — метка, как её ставило хранилище до хвостов источников: токен
// над текущей головой, без хвостов до запроса и после токена.
func oldStamp(t *testing.T, s *Store) {
	t.Helper()
	s.chainMu.Lock()
	defer s.chainMu.Unlock()
	if err := s.flushLocked(); err != nil {
		t.Fatal(err)
	}
	head := s.chain.Head()
	imprint := proof.HeadImprint(head.Seq, head.Hash)
	token, err := s.tsaLocal.Sign(imprint[:], nil)
	if err != nil {
		t.Fatal(err)
	}
	info, err := tsa.Verify(token, imprint, s.tsaTrust)
	if err != nil {
		t.Fatal(err)
	}
	num := s.appendLeafLocked(auditchain.Leaf{UnixNano: s.nowTime().UnixNano(), Type: auditchain.EventTimestamp,
		Subject: strconv.FormatUint(head.Seq, 10), Payload: token})
	s.tokens = append(s.tokens, tokenRef{head: head.Seq, leaf: num, gen: info.GenTime})
	s.lastStamped = max(s.lastStamped, head.Seq)
	s.stampedLeaves = num + 1
	if err := s.flushLocked(); err != nil {
		t.Fatal(err)
	}
}

// Окно, край которого — метка без хвостов (до обновления), или записи в нём
// без ссылок: отказ с подсказкой про пакет за окно, а не пакет, который не
// пройдёт проверку. Пакет за окно за те же окна есть.
func TestSourceProofPredatesTails(t *testing.T) {
	c := newClock()
	s := openStore(t, testConfig(t), c)
	ingest(t, s, "abs-core", 1, 2)
	oldStamp(t, s) // 10:00
	c.add(5 * time.Minute)
	ingest(t, s, "abs-core", 3, 3)
	c.add(5 * time.Minute)
	mustStamp(t, s) // 10:10
	c.add(5 * time.Minute)
	ingest(t, s, "abs-core", 4, 4)
	s.chainMu.Lock() // запись прежнего формата, без ссылки
	s.appendLeafLocked(proof.EvidenceLeaf(evidence.Header{Source: "abs-core", Seq: 5, ReceivedAt: c.now().UnixNano()}, 5, [32]byte{5}))
	s.chainMu.Unlock()
	c.add(5 * time.Minute)
	mustStamp(t, s) // 10:20
	c.add(5 * time.Minute)
	ingest(t, s, "abs-core", 6, 6)
	c.add(5 * time.Minute)
	oldStamp(t, s) // 10:30
	for _, w := range []struct {
		name     string
		from, to time.Time
		want     string
	}{
		{"нижняя метка без хвостов", clockAt(10, 4, 0), clockAt(10, 6, 0), "the time-stamp before the window was taken before the store laid source tails"},
		{"запись без ссылки", clockAt(10, 14, 0), clockAt(10, 16, 0), "were written before the store linked them"},
		{"верхняя метка без хвостов", clockAt(10, 24, 0), clockAt(10, 26, 0), "the time-stamp after the window was taken before the store laid source tails"},
	} {
		_, err := s.ProofSource("abs-core", w.from, w.to, false, 0)
		if !errors.Is(err, ErrWindow) || !strings.Contains(err.Error(), "proof -window") || !strings.Contains(err.Error(), w.want) {
			t.Fatalf("%s: %v", w.name, err)
		}
		if _, err := s.ProofWindow(w.from, w.to, "", false, 0); err != nil {
			t.Fatalf("%s, пакет за окно: %v", w.name, err)
		}
	}
}

func TestSourceProofRefusals(t *testing.T) {
	s, _ := sourceStore(t)
	for _, tc := range []struct {
		name     string
		source   string
		from, to time.Time
		want     error
	}{
		{"без источника", "", clockAt(10, 4, 0), clockAt(10, 6, 0), ErrWindow},
		{"неизвестный источник", "nobody", clockAt(10, 4, 0), clockAt(10, 6, 0), ErrNotFound},
		{"конец раньше начала", "abs-core", clockAt(10, 6, 0), clockAt(10, 4, 0), ErrWindow},
		{"верхней метки ещё нет", "abs-core", clockAt(10, 10, 30), clockAt(10, 11, 0), ErrWindow},
	} {
		if _, err := s.ProofSource(tc.source, tc.from, tc.to, false, 0); !errors.Is(err, tc.want) {
			t.Fatalf("%s: %v", tc.name, err)
		}
	}
	defer func(n uint64) { maxWindowLeaves = n }(maxWindowLeaves)
	maxWindowLeaves = 3
	if _, err := s.ProofSource("abs-core", clockAt(10, 4, 0), clockAt(10, 6, 0), false, 0); !errors.Is(err, ErrWindow) {
		t.Fatalf("предел листьев: %v", err)
	}
}

// Ключ месяца ждёт уничтожения: записи без ключей, пакет проходит.
func TestSourceProofKeyPending(t *testing.T) {
	s, _ := sourceStore(t)
	scope := "abs-core/2026-09"
	if err := s.Deactivate(true, scope); err != nil {
		t.Fatal(err)
	}
	if _, err := s.ScheduleDestroy(context.Background(), scope, time.Hour, []keyring.Approval{{Who: "operator"}, {Who: "security"}}); err != nil {
		t.Fatal(err)
	}
	b, err := s.ProofSource("abs-core", clockAt(10, 4, 0), clockAt(10, 6, 0), true, 0)
	if err != nil {
		t.Fatal(err)
	}
	r := proof.VerifySource(sourceRoundTrip(t, b), trustOf(t, s), time.Time{}, time.Time{})
	if !r.Valid() || r.Attached != 3 || len(r.Bodies) != 0 || !strings.Contains(r.Text(), "3 of the 3 records attached carry no record key") {
		t.Fatalf("без ключей:\n%s", r.Text())
	}
}
