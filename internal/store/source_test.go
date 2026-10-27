package store

import (
	"bytes"
	"context"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/Nikolay1994Kaz/evidencestore/internal/auditchain"
	"github.com/Nikolay1994Kaz/evidencestore/internal/config"
	"github.com/Nikolay1994Kaz/evidencestore/internal/evidence"
	"github.com/Nikolay1994Kaz/evidencestore/internal/keyring"
	"github.com/Nikolay1994Kaz/evidencestore/internal/proof"
	"github.com/Nikolay1994Kaz/evidencestore/internal/ship"
	"github.com/Nikolay1994Kaz/evidencestore/internal/tsa"
)

// Пакет по источнику на настоящем хранилище (DECISIONS, п. 28).

// sourceStore — два источника в одном окне, по часам теста:
//
//	10:00 abs-core 1–3, pipelock 1–2, метка A
//	10:05 abs-core 4–6, pipelock 3–5
//	10:10 метка B, сразу за ней B′ (её хвосты — верхний край окон, которые
//	      закрывает B)
//	10:11 abs-core 7–8, метка C, сразу за ней C′
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
	mustStampNow(t, s)
	c.add(time.Minute)
	ingest(t, s, "abs-core", 7, 8)
	mustStamp(t, s)
	mustStampNow(t, s)
	return s, c
}

// wholeChainSource — вся цепочка источника одним пакетом: от начала цепи до
// последней метки, как wholeChainWindow. Симуляции проверяют им, что честная
// история — падения, подъёмы, повторная привязка листьев — даёт цепочку
// источника без разрыва.
func wholeChainSource(s *Store, source string, trust proof.Trust) (proof.SourceReport, error) {
	// Окно закрывает предпоследняя метка: хвосты последней — верхний край.
	s.chainMu.Lock()
	var last time.Time
	if n := len(s.tokens); n > 1 {
		last = s.tokens[n-2].gen
	}
	s.chainMu.Unlock()
	if last.IsZero() {
		return proof.SourceReport{}, errors.New("в цепи меньше двух меток")
	}
	from, to := time.Unix(1, 0).UTC(), last.Add(-proof.WindowEdge-time.Nanosecond)
	b, err := s.ProofSource(source, from, to, false, 0)
	if err != nil {
		return proof.SourceReport{}, err
	}
	return proof.VerifySource(b, trust, from, to), nil
}

// midChainSource — пакет по источнику от метки в середине цепи до
// предпоследней (хвосты последней — верхний край): нижние хвосты и их
// раскрытие после падений и подъёмов. ok = false — меток меньше четырёх или
// они слишком близко: окна между ними нет.
func midChainSource(s *Store, source string, trust proof.Trust) (r proof.SourceReport, ok bool, err error) {
	s.chainMu.Lock()
	n := len(s.tokens)
	var mid, last time.Time
	if n >= 4 {
		mid, last = s.tokens[n/2-1].gen, s.tokens[n-2].gen
	}
	s.chainMu.Unlock()
	from, to := mid.Add(proof.ReceiveSlack+time.Nanosecond), last.Add(-proof.WindowEdge-time.Nanosecond)
	if n < 4 || !to.After(from) {
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
	// Метки выбираются по допускам: окно до 10:08:30 закрывает C (B ближе
	// двух минут к концу), окно с 10:00:00.5 — начало цепи (A ближе секунды).
	for _, c := range []struct {
		from, to    time.Time
		upper       time.Time
		fromStart   bool
		first, last uint64
	}{
		{clockAt(10, 4, 0), clockAt(10, 8, 30), clockAt(10, 11, 0), false, 4, 8},
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
	if !r.Valid() || !r.FromStart || r.FirstSeq != 1 || r.LastSeq != 6 || r.InWindow != 0 {
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
	if len(good.Records) != 3 || good.Lower.Open == nil || good.Upper.Open == nil {
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

	// Конец, сдвинутый вместе с раскрытием (соль та же): верхние хвосты не
	// сходятся.
	b = clone()
	b.Records = b.Records[:2]
	l := b.Records[1].Leaf.Leaf.Chain()
	salt, _ := hex.DecodeString(b.Upper.Open.Salt)
	b.Upper.Open = proof.TailOf(proof.Tail{Source: "abs-core", Seq: 5, Hash: auditchain.LeafHash(l), Salt: [32]byte(salt)})
	sourceFailed(t, verify(b), "the upper tails")

	// Раскрытие снято: хвосты называют источник.
	b = clone()
	b.Lower.Open = nil
	sourceFailed(t, verify(b), "the lower tails")
	b = clone()
	b.Upper.Open.Seq++
	sourceFailed(t, verify(b), "the upper tails")

	// Лист нижних хвостов подменён.
	b = clone()
	b.Lower.Tails.Payload = append([]byte(nil), b.Lower.Tails.Payload...)
	b.Lower.Tails.Payload[len(b.Lower.Tails.Payload)/2] ^= 1
	sourceFailed(t, verify(b), "the lower tails")

	// Путь записи не ведёт к корню её звена.
	b = clone()
	b.Records[2].Leaf.Path = b.Records[2].Leaf.Path[1:]
	sourceFailed(t, verify(b), chain)

	// Окно аудитора шире меток.
	if r := proof.VerifySource(clone(), trust, clockAt(9, 59, 0), clockAt(10, 6, 0)); r.Valid() {
		t.Fatalf("окно до T1 прошло:\n%s", r.Text())
	}
	// Приложенное тело чужим ключом записи.
	b = clone()
	b.Records[0].DEK, b.Records[1].DEK = b.Records[1].DEK, b.Records[0].DEK
	sourceFailed(t, verify(b), "the records attached")

	// Тело одной записи не приложено: пакет проходит, отчёт это называет.
	b = clone()
	b.Records[1].Evidence, b.Records[1].DEK = nil, nil
	if r := verify(b); !r.Valid() || !strings.Contains(r.Text(), "1 of the 3 records come without their evidence") {
		t.Fatalf("тело снято:\n%s", r.Text())
	}
}

// Окно без записей источника: пакет пуст, нижнее и верхнее раскрытия —
// один и тот же лист, abs-core 8.
func TestSourceProofEmptyWindow(t *testing.T) {
	s, c := sourceStore(t)
	c.add(5 * time.Minute)
	ingest(t, s, "pipelock", 6, 6)
	mustStamp(t, s) // 10:16
	mustStampNow(t, s)
	b, err := s.ProofSource("abs-core", clockAt(10, 11, 2), clockAt(10, 13, 0), false, 0)
	if err != nil {
		t.Fatal(err)
	}
	r := proof.VerifySource(sourceRoundTrip(t, b), trustOf(t, s), time.Time{}, time.Time{})
	if !r.Valid() || r.Records != 0 || b.Lower.Open == nil || b.Upper.Open == nil || b.Lower.Open.Leaf != b.Upper.Open.Leaf ||
		b.Lower.Open.Seq != 8 || b.Upper.Open.Seq != 8 || b.Lower.Open.Salt == b.Upper.Open.Salt ||
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
	mustStampNow(t, s)
	b, err := s.ProofSource("abs-core", clockAt(10, 4, 0), clockAt(10, 6, 0), false, 0)
	if err != nil {
		t.Fatal(err)
	}
	if r := proof.VerifySource(sourceRoundTrip(t, b), trustOf(t, s), time.Time{}, time.Time{}); !r.Valid() || r.FirstSeq != 4 || r.LastSeq != 6 || b.Lower.Open.Seq != 3 {
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
	if !r.Valid() || !r.WitnessChecked || r.WitnessHead != head.HeadSeq || r.UpperHead >= head.HeadSeq {
		t.Fatalf("голова свидетеля %d:\n%s", head.HeadSeq, r.Text())
	}

	// Свидетель видел голову посреди пакета (звено улик 4–6): с пакетом она
	// сходится, но верхние хвосты не закрепляет — такой головы у свидетеля
	// ещё нет.
	mid := b.Lower.Head + 2
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
// над текущей головой, без хвостов перед запросом.
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
	mustStampNow(t, s) // 10:25 — верхний край окна 10:14–10:16
	c.add(2 * time.Minute)
	ingest(t, s, "abs-core", 6, 6)
	c.add(3 * time.Minute)
	mustStamp(t, s) // 10:30 — закрывает окно 10:24–10:26
	c.add(time.Minute)
	ingest(t, s, "abs-core", 7, 7)
	oldStamp(t, s) // 10:31 — её звено и было бы верхним краем
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

// Q-07: падение между листьями и звеном тика метки (токен и верхние хвосты
// уже на диске, звена над ними нет). После подъёма они уходят в одно звено с
// листьями подъёма (догон, «запуск»), хвосты уже не последние в звене — и
// пакет по источнику за любое окно, которое закрывает эта метка, хранилище
// не собирает: отказ «метка взята до того, как хранилище стало класть хвосты».
func TestSourceProofAfterCrashInStampTick(t *testing.T) {
	c := newClock()
	cfg := testConfig(t)
	s, err := Open(cfg, Options{Logger: quiet, Now: c.now, NoBackground: true})
	if err != nil {
		t.Fatal(err)
	}
	ingest(t, s, "abs-core", 1, 3)
	mustStamp(t, s) // A, 10:00
	c.add(5 * time.Minute)
	ingest(t, s, "abs-core", 4, 6) // 10:05
	c.add(5 * time.Minute)

	// Метка B (10:10): первое свёртывание — хвосты перед запросом, второе —
	// токен и хвосты после него; второе падает между листьями и звеном.
	links := 0
	s.chain.SetBeforeWrite(func(phase string) error {
		if phase == "link" {
			links++
			if links == 3 {
				return errors.New("питание пропало (тест)")
			}
		}
		return nil
	})
	if _, err := s.Stamp(context.Background()); err == nil {
		t.Fatal("падение не сработало")
	}
	s.chain.SetBeforeWrite(nil)
	s.Close()

	c.add(time.Minute)
	s, err = Open(cfg, Options{Logger: quiet, Now: c.now, NoBackground: true})
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	mustStamp(t, s) // якорь после подъёма
	ingest(t, s, "abs-core", 7, 8)
	c.add(5 * time.Minute)
	mustStamp(t, s) // C

	// Окно 10:04–10:06: верхняя — B (первая позже 10:07).
	_, err = s.ProofSource("abs-core", clockAt(10, 4, 0), clockAt(10, 6, 0), false, 0)
	t.Logf("пакет по источнику: %v", err)
	if err != nil {
		t.Errorf("честное хранилище не собирает пакет по источнику после падения в тике метки: %v", err)
	}
	// Пакет за окно — собирается и проходит.
	wb, werr := s.ProofWindow(clockAt(10, 4, 0), clockAt(10, 6, 0), "", false, 0)
	if werr != nil {
		t.Fatal(werr)
	}
	if r := proof.VerifyWindow(wb, trustOf(t, s), time.Time{}, time.Time{}); !r.Valid() {
		t.Fatalf("пакет за окно:\n%s", r.Text())
	}
}

// tailCommitOf — обязательство на хвост источника source в листе хвостов
// (как его видит аудитор: по метке-хэшу имени, которое он подобрал).
func tailCommitOf(t *testing.T, l proof.Leaf, source string) string {
	t.Helper()
	var p struct {
		Sources []struct {
			Tag    string `json:"tag"`
			Commit string `json:"commit"`
		} `json:"sources"`
	}
	if err := json.Unmarshal(l.Payload, &p); err != nil {
		t.Fatal(err)
	}
	tag := proof.TailTag(source)
	want := hex.EncodeToString(tag[:])
	for _, e := range p.Sources {
		if e.Tag == want {
			return e.Commit
		}
	}
	return ""
}

// Q-04. Пакет по источнику abs-core выдаёт внешнему аудитору, были ли
// записи у чужого источника (pipelock) между метками: обязательство на хвост
// детерминировано (имя, номер, хэш листа), поэтому одинаковое обязательство в
// нижних и верхних хвостах значит «записей не было», разное — «были». Имя
// проверяется подбором (README это признаёт), а вот время активности —
// README обещает, что его не видно («but not their record numbers or
// times»). Вдобавок число листьев в каждом звене (Count в звеньях пакета)
// минус свои записи даёт активность всех прочих по тикам.
func TestSourceProofHidesForeignActivity(t *testing.T) {
	c := newClock()
	s := openStore(t, testConfig(t), c)
	ingest(t, s, "abs-core", 1, 3)
	ingest(t, s, "pipelock", 1, 2)
	mustStamp(t, s) // A, 10:00
	c.add(5 * time.Minute)
	ingest(t, s, "abs-core", 4, 6)
	ingest(t, s, "pipelock", 3, 5) // pipelock активен между A и B
	c.add(5 * time.Minute)
	mustStamp(t, s) // B, 10:10
	c.add(5 * time.Minute)
	ingest(t, s, "abs-core", 7, 8) // pipelock молчит между B и C
	c.add(5 * time.Minute)
	mustStamp(t, s) // C, 10:20
	mustStampNow(t, s)

	trust := trustOf(t, s)
	check := func(from, to time.Time) (changed bool, foreign int) {
		t.Helper()
		b, err := s.ProofSource("abs-core", from, to, false, 0)
		if err != nil {
			t.Fatal(err)
		}
		if r := proof.VerifySource(b, trust, from, to); !r.Valid() {
			t.Fatalf("пакет не прошёл:\n%s", r.Text())
		}
		data, _ := json.Marshal(b)
		if json.Valid(data) && containsName(data, "pipelock") {
			t.Fatal("имя pipelock в пакете открытым текстом")
		}
		// Что видит аудитор abs-core про pipelock, зная только имя:
		lo := tailCommitOf(t, *b.Lower.Tails, "pipelock")
		hi := tailCommitOf(t, *b.Upper.Tails, "pipelock")
		if lo == "" || hi == "" {
			t.Fatalf("pipelock нет в хвостах: %q %q", lo, hi)
		}
		return lo != hi, 0
	}

	changed1, foreign1 := check(clockAt(10, 4, 0), clockAt(10, 6, 0))
	changed2, foreign2 := check(clockAt(10, 14, 0), clockAt(10, 16, 0))
	t.Logf("окно 10:04–10:06: хвост pipelock изменился = %v, чужих листьев между хвостами = %d", changed1, foreign1)
	t.Logf("окно 10:14–10:16: хвост pipelock изменился = %v, чужих листьев между хвостами = %d", changed2, foreign2)
	if changed1 && !changed2 {
		t.Errorf("УТЕЧКА: по пакетам abs-core аудитор видит, что pipelock писал между 10:00 и 10:10 и молчал между 10:10 и 10:20 " +
			"(обязательства в нижних и верхних хвостах разные/одинаковые); README: «not their record numbers or times»")
	}
}

func containsName(data []byte, name string) bool {
	for i := 0; i+len(name) <= len(data); i++ {
		if string(data[i:i+len(name)]) == name {
			return true
		}
	}
	return false
}

// slowTSA — служба меток по HTTP поверх встроенной: запрос ждёт, пока тест
// его не отпустит (ответ настоящей TSA идёт от долей секунды до секунд).
func slowTSA(t *testing.T, s *Store) (asked <-chan struct{}, release chan<- struct{}) {
	t.Helper()
	local := s.tsaLocal
	ask, rel := make(chan struct{}, 1), make(chan struct{})
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		der, _ := io.ReadAll(r.Body)
		var req struct {
			Version        int
			MessageImprint struct {
				HashAlgorithm pkix.AlgorithmIdentifier
				HashedMessage []byte
			}
			Nonce   *big.Int `asn1:"optional"`
			CertReq bool     `asn1:"optional,default:false"`
		}
		if _, err := asn1.Unmarshal(der, &req); err != nil {
			http.Error(w, err.Error(), 400)
			return
		}
		ask <- struct{}{}
		<-rel
		token, err := local.Sign(req.MessageImprint.HashedMessage, req.Nonce)
		if err != nil {
			http.Error(w, err.Error(), 500)
			return
		}
		resp, _ := asn1.Marshal(struct {
			Status struct{ Status int }
			Token  asn1.RawValue
		}{Token: asn1.RawValue{FullBytes: token}})
		w.Write(resp)
	}))
	t.Cleanup(srv.Close)
	s.tsaLocal, s.tsaURL = nil, srv.URL
	return ask, rel
}

// Q-06. Голова под меткой TSA не доходит до свидетеля, если, пока шёл
// запрос к TSA, в цепь легло новое звено и обход свидетеля (раз в
// witness.every) поставил в очередь и отправил эту новую текущую голову:
// queueWitnessLocked(head, stamped) видит head.Seq <= witnessQueued, а
// последняя в очереди — не она (P-09 закрыл только случай «она последняя»).
// Пакет по улике кончается головой под T2 (P-06), у свидетеля её нет, и
// esverify -heads отвечает NOT VERIFIED, пока не попросят пакет длиннее.
// README: «the head under every TSA time-stamp, which is where proof bundles end».
func TestStampedHeadReachesWitnessAfterNewerHead(t *testing.T) {
	c := newClock()
	wdir := t.TempDir()
	s := openStore(t, testConfig(t, withWitness(wdir)), c)
	ctx := context.Background()
	ingest(t, s, "abs-core", 1, 3)
	mustStamp(t, s) // T1
	if err := s.WitnessOnce(ctx); err != nil {
		t.Fatal(err)
	}
	c.add(time.Minute)
	ingest(t, s, "abs-core", 4, 6)

	asked, release := slowTSA(t, s)
	done := make(chan error, 1)
	var stamped uint64
	go func() {
		h, err := s.Stamp(ctx) // T2: хвосты перед запросом, запрос висит
		stamped = h
		done <- err
	}()
	<-asked
	// Пока TSA отвечает: пришла запись, тик свернул звено, обход свидетеля.
	c.add(time.Second)
	ingest(t, s, "abs-core", 7, 7)
	if err := s.flush(); err != nil {
		t.Fatal(err)
	}
	if err := s.WitnessOnce(ctx); err != nil {
		t.Fatal(err)
	}
	close(release)
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	if err := s.WitnessOnce(ctx); err != nil { // следующий обход
		t.Fatal(err)
	}

	tr := trustOf(t, s)
	tr.Witness = witnessHeads(t, wdir)
	var seqs []uint64
	has := false
	for _, h := range tr.Witness.Heads {
		seqs = append(seqs, h.Statement.HeadSeq)
		has = has || h.Statement.HeadSeq == stamped
	}
	t.Logf("голова под T2: %d; головы у свидетеля: %v", stamped, seqs)
	b, err := s.Proof("abs-core", 5, false)
	if err != nil {
		t.Fatal(err)
	}
	r := proof.Verify(b, tr)
	if !has || !r.Valid() {
		t.Errorf("голова %d под меткой T2 у свидетеля: %v; пакет по abs-core/5 (кончается головой %d) с -heads:\n%s",
			stamped, has, b.Upper.HeadSeq, r.Text())
	}
}

// Q-08. Пакет по источнику называет дыру в номерах «never reached the
// store», хотя хранилище эти записи приняло (у сборщика подписанные
// обещания) и потеряло: подъём из отставшей копии — случай, который README
// описывает как штатный («What the store accepted after the last copy is
// lost with the disk: collectors keep the signed promises as proof»). Отчёт
// аудитору снимает с хранилища вину неверным утверждением; пакет за окно в
// том же случае пишет осторожно: «entered the chain outside the window, or
// the store lost them».
func TestSourceProofLostRecordsWording(t *testing.T) {
	c := newClock()
	ctx := context.Background()
	remoteDir := t.TempDir()
	cfg := testConfig(t, func(c *config.Config) {
		c.Replica.URL = "file://" + remoteDir
		c.Keys.BackupDir = t.TempDir()
	})
	s := openStore(t, cfg, c)
	remote, err := ship.OpenRemote(cfg.Replica.URL)
	if err != nil {
		t.Fatal(err)
	}
	ingest(t, s, "abs-core", 1, 1)
	mustStamp(t, s) // A, 10:00
	c.add(time.Minute)
	ingest(t, s, "abs-core", 2, 3)
	mustStamp(t, s)
	if _, err := s.ShipOnce(ctx, remote); err != nil {
		t.Fatal(err)
	}
	c.add(time.Minute)
	res := ingest(t, s, "abs-core", 4, 6) // приняты, обещания у сборщика
	for _, r := range res {
		if r.Status != StatusAccepted || r.Promise == nil {
			t.Fatalf("запись %d не принята: %+v", r.Seq, r)
		}
	}
	mustStamp(t, s)
	pub := s.PublicKey()
	s.Close()

	// Диск умер; подъём из копии, которая 4–6 не застала. Сборщик держит
	// обещания на 4–6 и шлёт дальше 7–9.
	s2 := openStore(t, restoreFromCopy(t, cfg, remote, pub), c)
	c.add(time.Minute)
	ingest(t, s2, "abs-core", 7, 9)
	c.add(5 * time.Minute)
	mustStamp(t, s2)
	c.add(2 * time.Minute)
	mustStampNow(t, s2)

	from, to := clockAt(10, 0, 2), clockAt(10, 5, 0)
	b, err := s2.ProofSource("abs-core", from, to, false, 0)
	if err != nil {
		t.Fatal(err)
	}
	r := proof.VerifySource(b, trustOf(t, s2), from, to)
	if !r.Valid() {
		t.Fatalf("пакет не прошёл:\n%s", r.Text())
	}
	text := r.Text()
	t.Logf("отчёт:\n%s", text)
	if len(r.Holes) > 0 && strings.Contains(text, "never reached the store") {
		t.Errorf("отчёт пакета по источнику утверждает, что номера %v «never reached the store», а хранилище их приняло и выдало подписанные обещания", r.Holes)
	}
}

// Q-09. Пакет по источнику журнала гейтвея (pipelock/recorder) проходит и
// выдаёт тело записи, которую хранилище при приёме признало поломанной
// (хэш записи не сходится): вердиктов гейтвея в пакете по источнику нет
// вовсе — ни части gateway, ни листьев вердиктов. Пакет одной улики по той
// же записи — NOT VERIFIED. README («What is proven»): «A gateway record
// whose bundle lacks the gateway part does not verify». Пакет за окно хотя
// бы считает поломки в сводке источника; пакет по источнику — нет.
func TestSourceProofGatewayVerdicts(t *testing.T) {
	key := pipelockKey(t)
	c := newClock()
	s := openStore(t, testConfig(t, withGateway(key)), c)
	ingest(t, s, "abs-core", 1, 1)
	mustStamp(t, s) // нижняя метка, 10:00
	c.add(time.Minute)
	ingestLines(t, s, 1, readLines(t, filepath.Join(pipelockVectors, "tampered.jsonl")))
	c.add(5 * time.Minute)
	mustStamp(t, s) // верхняя, 10:06
	mustStampNow(t, s)

	single, err := s.Proof("agent-gw", 3, true) // запись гейтвея seq 2, в ней изменён байт
	if err != nil {
		t.Fatal(err)
	}
	tr := gatewayTrust(t, s, key)
	if r := proof.Verify(single, tr); r.Valid() {
		t.Fatalf("ПАРНЫЙ КОНТРОЛЬ: пакет одной улики по поломанной записи прошёл:\n%s", r.Text())
	}

	from, to := clockAt(10, 0, 30), clockAt(10, 3, 30)
	b, err := s.ProofSource("agent-gw", from, to, true, 0)
	if err != nil {
		t.Fatal(err)
	}
	r := proof.VerifySource(b, trustOf(t, s), from, to)
	t.Logf("пакет по источнику agent-gw:\n%s", r.Text())
	var bodyOf3 []byte
	for _, body := range r.Bodies {
		if body.Seq == 3 {
			bodyOf3 = body.Body
		}
	}
	if !r.Valid() || bodyOf3 != nil || !slices.Contains(r.GatewayBroken, 3) || !strings.Contains(r.Text(), "gateway journal records 3 were found broken") {
		t.Fatalf("поломанная запись 3: тело %d байт, поломанные %v:\n%s", len(bodyOf3), r.GatewayBroken, r.Text())
	}
	// Вердикты переставлены между записями: вердикт о чужой записи.
	if len(b.Records) > 1 {
		sw := sourceRoundTrip(t, b)
		sw.Records[0].Verdict, sw.Records[1].Verdict = sw.Records[1].Verdict, sw.Records[0].Verdict
		if r := proof.VerifySource(sw, trustOf(t, s), from, to); r.Valid() || !strings.Contains(r.Text(), "is about another record") {
			t.Fatalf("вердикт чужой записи прошёл:\n%s", r.Text())
		}
	}
	// Вердикт снят с записи гейтвея, улика приложена: пакет не проходит.
	for i := range b.Records {
		b.Records[i].Verdict = nil
	}
	if r := proof.VerifySource(b, trustOf(t, s), from, to); r.Valid() || !strings.Contains(r.Text(), "lacks the store's verdict") {
		t.Fatalf("запись гейтвея без вердикта прошла:\n%s", r.Text())
	}
}

// Q-10: ответ TSA дольше proof.StampLatency в цепь не ложится — что легло,
// пока шёл запрос, лежит после заверенной головы, и граница окна пакетов
// (proof.WindowEdge) держится на коротком запросе. Повтор берёт те же хвосты.
func TestSlowTSAAnswerIsNotUsed(t *testing.T) {
	c := newClock()
	s := openStore(t, testConfig(t), c)
	ingest(t, s, "abs-core", 1, 1)
	asked, release := slowTSA(t, s)
	done := make(chan error, 1)
	go func() {
		_, err := s.Stamp(context.Background())
		done <- err
	}()
	<-asked
	c.add(proof.StampLatency + time.Second)
	close(release)
	if err := <-done; err == nil || !strings.Contains(err.Error(), "the time-stamp is not used") {
		t.Fatalf("долгий ответ TSA: %v", err)
	}
	s.chainMu.Lock()
	tokens, head := len(s.tokens), s.chain.Head().Seq
	s.chainMu.Unlock()
	if tokens != 0 || head != s.preTailsHead {
		t.Fatalf("меток %d, голова %d, хвосты перед запросом %d", tokens, head, s.preTailsHead)
	}
}

// Q-02: к пакету за окно прикладываются только улики из заверенной части
// участка — записи, легшие в цепь, пока шёл запрос верхней метки, метка не
// заверяет, и esverify их не примет.
func TestWindowProofAttachesCertifiedOnly(t *testing.T) {
	c := newClock()
	s := openStore(t, testConfig(t), c)
	ingest(t, s, "abs-core", 1, 3)
	mustStamp(t, s) // 10:00
	c.add(5 * time.Minute)
	ingest(t, s, "abs-core", 4, 6)
	c.add(5 * time.Minute)
	asked, release := slowTSA(t, s)
	done := make(chan error, 1)
	go func() {
		_, err := s.Stamp(context.Background())
		done <- err
	}()
	<-asked
	ingest(t, s, "abs-core", 7, 7) // пока шёл запрос: после головы под меткой
	if err := s.flush(); err != nil {
		t.Fatal(err)
	}
	close(release)
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	b, err := s.ProofWindow(clockAt(10, 4, 0), clockAt(10, 6, 0), "abs-core", true, 0)
	if err != nil {
		t.Fatal(err)
	}
	r := proof.VerifyWindow(roundTrip(t, b), trustOf(t, s), time.Time{}, time.Time{})
	if !r.Valid() || len(b.Records) != 3 || r.Attached != 3 || len(r.Sources) != 1 || r.Sources[0].LastSeq != 6 {
		t.Fatalf("приложено %d:\n%s", len(b.Records), r.Text())
	}
}

// Q-19 и Q-26: верхний край — звено хвостов метки B посреди окна. Свежая
// метка над ним, дописанная в конец цепи, краем его не делает: перед ним нет
// токена позже окна (proof, TestSourceFreshTokenOverOldTails). Остаётся
// перепись: цепь после B заново — свежий закрывающий токен, новые хвосты без
// записей 5–6, метка над ними. Её опровергает свидетель (-heads); без него
// перепись в пределах часа после окна не отличить (README, Not proven).
func TestSourceProofFreshTokenNeedsRewrite(t *testing.T) {
	c := newClock() // 10:00
	wdir := t.TempDir()
	s := openStore(t, testConfig(t, withWitness(wdir)), c)
	const src = "abs-core"
	ingest(t, s, src, 1, 2)
	mustStamp(t, s) // A, 10:00
	c.add(3 * time.Minute)
	ingest(t, s, src, 3, 4) // 10:03
	c.add(2 * time.Minute)
	mustStamp(t, s) // B, 10:05 — посреди окна
	c.add(2 * time.Minute)
	ingest(t, s, src, 5, 6) // 10:07 — их и прятали бы
	c.add(10 * time.Minute)
	mustStamp(t, s) // C, 10:17
	mustStampNow(t, s)
	for i := 0; i < 2; i++ {
		if err := s.WitnessOnce(context.Background()); err != nil {
			t.Fatal(err)
		}
	}
	from, to := clockAt(10, 1, 0), clockAt(10, 10, 0)
	trust := trustOf(t, s)
	trust.Witness = witnessHeads(t, wdir)
	honest, err := s.ProofSource(src, from, to, false, 0)
	if err != nil {
		t.Fatal(err)
	}
	if r := proof.VerifySource(honest, trust, from, to); !r.Valid() || r.Records != 4 {
		t.Fatalf("честный пакет: %d записей\n%s", r.Records, r.Text())
	}

	var pb uint64
	for _, tok := range s.tokens {
		if tok.gen.Equal(clockAt(10, 5, 0)) {
			pb = tok.head
		}
	}
	links, err := auditchain.ReadLinks(s.chainDir, honest.Lower.Head, pb)
	if err != nil || pb == 0 {
		t.Fatalf("звено B %d: %v", pb, err)
	}
	linkB := links[len(links)-1]
	bp, _ := auditchain.DecodeBatchPayload(linkB.Payload)
	c.add(3 * time.Minute) // 10:20
	// Цепь после B переписана: закрывающий токен (над B), хвосты, где
	// последняя запись abs-core — 4, токен над ними; голова переподписана.
	sign := func(h auditchain.Record) []byte {
		imprint := proof.HeadImprint(h.Seq, auditchain.Hash(h))
		tok, err := s.tsaLocal.Sign(imprint[:], nil)
		if err != nil {
			t.Fatal(err)
		}
		return tok
	}
	at := c.now().UnixNano()
	link := func(prev auditchain.Record, first uint64, l auditchain.Leaf) auditchain.Record {
		r, err := auditchain.LinkBatch(auditchain.Head{Seq: prev.Seq, Hash: auditchain.Hash(prev)}, at, first, []auditchain.Leaf{l})
		if err != nil {
			t.Fatal(err)
		}
		return r
	}
	closeLeaf := auditchain.Leaf{UnixNano: at, Type: auditchain.EventTimestamp, Subject: strconv.FormatUint(linkB.Seq, 10), Payload: sign(linkB)}
	l1 := link(linkB, bp.FirstLeaf+1, closeLeaf)
	var lastRec auditchain.Leaf
	forged := honest
	forged.Records = nil
	for _, rec := range honest.Records {
		if rec.Leaf.LinkSeq < linkB.Seq {
			forged.Records = append(forged.Records, rec)
			lastRec = rec.Leaf.Leaf.Chain()
		}
	}
	tail := proof.Tail{Source: src, Seq: 4, Hash: auditchain.LeafHash(lastRec), Salt: s.tailSalt(bp.FirstLeaf+2, src)}
	tailsLeaf := proof.TailsLeaf([]proof.Tail{tail}, at)
	l2 := link(l1, bp.FirstLeaf+2, tailsLeaf)
	edgeLeaf := auditchain.Leaf{UnixNano: at, Type: auditchain.EventTimestamp, Subject: strconv.FormatUint(l2.Seq, 10), Payload: sign(l2)}
	l3 := link(l2, bp.FirstLeaf+3, edgeLeaf)
	forged.Links = nil
	for _, l := range append(links, l1, l2, l3) {
		forged.Links = append(forged.Links, proof.FromLink(l))
	}
	tails := proof.FromLeaf(tailsLeaf)
	forged.Upper = proof.SourceEdge{Head: l2.Seq, Tails: &tails, Token: proof.Inclusion{Leaf: proof.FromLeaf(edgeLeaf), LinkSeq: l3.Seq}, Open: proof.TailOf(tail)}
	forged.Closing = proof.Inclusion{Leaf: proof.FromLeaf(closeLeaf), LinkSeq: l1.Seq}
	forged.Statement = s.signer.Sign(auditchain.Head{Seq: l3.Seq, Hash: auditchain.Hash(l3)}, int(l3.Seq), 0)

	sourceFailed(t, proof.VerifySource(forged, trust, from, to), "the chain in the bundle agrees with the heads the witness saw")
	// Без свидетеля переписанное со свежей меткой в пределах часа после окна
	// не отличить (README, Not proven): T2 — 10:20, в обычном ритме меток.
	trust.Witness = nil
	if r := proof.VerifySource(forged, trust, from, to); !r.Valid() || !r.Upper.Equal(clockAt(10, 20, 0)) || r.Records != 2 {
		t.Fatalf("без свидетеля:\n%s", r.Text())
	}
}

// Q-20: метка не кладёт хвосты перед запросом, пока пачка журнала гейтвея
// посреди приёма: иначе хвосты встали бы между уликой и её вердиктом, и
// честный пакет по источнику не нашёл бы вердикт до края.
func TestStampWaitsForGatewayBatch(t *testing.T) {
	key := pipelockKey(t)
	c := newClock()
	s := openStore(t, testConfig(t, withGateway(key)), c)
	ingest(t, s, "abs-core", 1, 1)
	s.mu.Lock()
	st := s.sources["agent-gw"]
	s.mu.Unlock()
	st.gwMu.Lock() // пачка гейтвея: улика в цепи, вердикта ещё нет
	done := make(chan error, 1)
	go func() {
		_, err := s.Stamp(context.Background())
		done <- err
	}()
	select {
	case err := <-done:
		st.gwMu.Unlock()
		t.Fatalf("метка прошла посреди пачки журнала гейтвея: %v", err)
	case <-time.After(200 * time.Millisecond):
	}
	st.gwMu.Unlock()
	if err := <-done; err != nil {
		t.Fatal(err)
	}
}

// Q-23: пакеты по источнику и за окно кончаются звеном токена верхней метки
// — его голова уходит свидетелю сразу, головой под меткой: честный пакет с
// -heads проходит без -to-head, даже если в цепь успело лечь новое звено до
// обхода свидетеля.
func TestSourceProofEndsAtWitnessHead(t *testing.T) {
	c := newClock()
	wdir := t.TempDir()
	s := openStore(t, testConfig(t, withWitness(wdir)), c)
	ctx := context.Background()
	ingest(t, s, "abs-core", 1, 2)
	mustStamp(t, s) // A, 10:00
	c.add(3 * time.Minute)
	ingest(t, s, "abs-core", 3, 4)
	c.add(5 * time.Minute)
	mustStamp(t, s)                // B, 10:08 — закрывает окно
	ingest(t, s, "pipelock", 1, 1) // после метки, до обхода свидетеля
	if err := s.flush(); err != nil {
		t.Fatal(err)
	}
	c.add(time.Minute)
	mustStamp(t, s)                // C, 10:09 — её хвосты: верхний край пакета по источнику
	ingest(t, s, "pipelock", 2, 2) // после метки, до обхода свидетеля
	if err := s.flush(); err != nil {
		t.Fatal(err)
	}
	if err := s.WitnessOnce(ctx); err != nil {
		t.Fatal(err)
	}
	from, to := clockAt(10, 1, 0), clockAt(10, 5, 0)
	tr := trustOf(t, s)
	tr.Witness = witnessHeads(t, wdir)
	b, err := s.ProofSource("abs-core", from, to, false, 0)
	if err != nil {
		t.Fatal(err)
	}
	if r := proof.VerifySource(b, tr, from, to); !r.Valid() || r.WitnessHead != b.Statement.HeadSeq {
		t.Fatalf("пакет по источнику с -heads (кончается звеном %d):\n%s", b.Statement.HeadSeq, r.Text())
	}
	w, err := s.ProofWindow(from, to, "", false, 0)
	if err != nil {
		t.Fatal(err)
	}
	if r := proof.VerifyWindow(w, tr, from, to); !r.Valid() || r.WitnessHead != w.StretchEnd {
		t.Fatalf("пакет за окно с -heads (кончается звеном %d):\n%s", w.StretchEnd, r.Text())
	}
}

// Улика в пакете по источнику — только при своём листе: вердикт сверяется по
// ячейке пакета, и тело поломанной записи гейтвея, переложенное в ячейку
// другой записи с чистым вердиктом (у самой поломанной вердикт и тело сняты),
// иначе вскрывалось бы, а поломанных в отчёте не было бы. Подписанное при
// этом не тронуто — ключ не нужен.
func TestSourceProofBodyStaysWithItsLeaf(t *testing.T) {
	key := pipelockKey(t)
	c := newClock()
	s := openStore(t, testConfig(t, withGateway(key)), c)
	ingest(t, s, "abs-core", 1, 1)
	mustStamp(t, s) // нижняя метка, 10:00
	c.add(time.Minute)
	ingestLines(t, s, 1, readLines(t, filepath.Join(pipelockVectors, "tampered.jsonl")))
	c.add(5 * time.Minute)
	mustStamp(t, s) // верхняя, 10:06
	mustStampNow(t, s)
	from, to := clockAt(10, 0, 30), clockAt(10, 3, 30)
	honest, err := s.ProofSource("agent-gw", from, to, true, 0)
	if err != nil {
		t.Fatal(err)
	}
	tr := trustOf(t, s)
	r := proof.VerifySource(honest, tr, from, to)
	if !r.Valid() || !slices.Contains(r.GatewayBroken, 3) {
		t.Fatalf("честный пакет:\n%s", r.Text())
	}
	// Ключа месяца нет только у нерасшифрованных по сроку: тело поломанной
	// записи не вскрыто нарочно, ключ к нему приложен.
	if strings.Contains(r.Text(), "carry no record key") {
		t.Fatalf("тело поломанной записи названо записью без ключа:\n%s", r.Text())
	}

	b := sourceRoundTrip(t, honest)
	broken, other := -1, -1
	for i, rec := range b.Records {
		switch rec.Leaf.Leaf.Chain().Subject {
		case "3":
			broken = i
		case "4":
			other = i
		}
	}
	if broken < 0 || other < 0 {
		t.Fatal("нет записей 3 и 4")
	}
	b.Records[other].Evidence, b.Records[other].DEK = b.Records[broken].Evidence, b.Records[broken].DEK
	b.Records[broken].Evidence, b.Records[broken].DEK, b.Records[broken].Verdict = nil, nil, nil
	if fr := proof.VerifySource(b, tr, from, to); fr.Valid() {
		t.Fatalf("тело записи 3 в ячейке записи 4 принято:\n%s", fr.Text())
	} else if !strings.Contains(fr.Text(), "goes with its own leaf") {
		t.Fatalf("отказ не по месту улики:\n%s", fr.Text())
	}
}

// Пакет журнала гейтвея без улик (без -dek): вердикты хранилища не
// снимаются — вид источника лежит в хвостах под обязательством, и у каждой
// записи журнала гейтвея вердикт обязан быть. Иначе поломанная запись
// пропала бы из отчёта, а README обещает её назвать.
func TestSourceProofGatewayVerdictsWithoutBodies(t *testing.T) {
	key := pipelockKey(t)
	c := newClock()
	s := openStore(t, testConfig(t, withGateway(key)), c)
	ingest(t, s, "abs-core", 1, 1)
	mustStamp(t, s) // 10:00
	c.add(time.Minute)
	ingestLines(t, s, 1, readLines(t, filepath.Join(pipelockVectors, "tampered.jsonl")))
	c.add(5 * time.Minute)
	mustStamp(t, s) // 10:06
	mustStampNow(t, s)
	from, to := clockAt(10, 0, 30), clockAt(10, 3, 30)
	b, err := s.ProofSource("agent-gw", from, to, false, 0)
	if err != nil {
		t.Fatal(err)
	}
	tr := trustOf(t, s)
	if r := proof.VerifySource(b, tr, from, to); !r.Valid() || !slices.Contains(r.GatewayBroken, 3) {
		t.Fatalf("честный пакет без -dek: поломанные %v\n%s", r.GatewayBroken, r.Text())
	}
	stripped := sourceRoundTrip(t, b)
	for i := range stripped.Records {
		stripped.Records[i].Verdict = nil
	}
	if r := proof.VerifySource(stripped, tr, from, to); r.Valid() || !strings.Contains(r.Text(), "lacks the store's verdict, and the tails name agent-gw a gateway journal") {
		t.Fatalf("вердикты сняты, поломанная запись 3 не названа:\n%s", r.Text())
	}
	// Вид в раскрытии сменить нельзя: он под обязательством.
	plain := sourceRoundTrip(t, stripped)
	plain.Upper.Open.Kind = ""
	if r := proof.VerifySource(plain, tr, from, to); r.Valid() {
		t.Fatalf("раскрытие без вида принято:\n%s", r.Text())
	}
	// Источник не журнал гейтвея — вердиктов от него не требуют.
	a, err := s.ProofSource("abs-core", from, clockAt(10, 3, 30), false, 0)
	if err != nil {
		t.Fatal(err)
	}
	if r := proof.VerifySource(a, tr, from, to); !r.Valid() || a.Upper.Open == nil || a.Upper.Open.Kind != "" {
		t.Fatalf("abs-core:\n%s", r.Text())
	}
}

// Номер источника прыгнул далеко вперёд (сборщик ошибся или подделан):
// пакет по источнику ищет последнюю запись до края по индексу номеров, а не
// перебором от 1 до последнего номера — иначе запрос висел бы под замками
// хранилища, и приём стоял.
func TestSourceProofAfterSeqJump(t *testing.T) {
	c := newClock()
	s := openStore(t, testConfig(t), c)
	ingest(t, s, "abs-core", 1, 2)
	mustStamp(t, s) // 10:00
	c.add(3 * time.Minute)
	ingest(t, s, "abs-core", 1<<40, 1<<40)
	c.add(5 * time.Minute)
	mustStamp(t, s) // 10:08
	mustStampNow(t, s)
	done := make(chan error, 1)
	go func() {
		_, err := s.ProofSource("abs-core", clockAt(10, 1, 0), clockAt(10, 5, 0), false, 0)
		done <- err
	}()
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(20 * time.Second):
		t.Fatal("пакет по источнику перебирает номера до 2^40")
	}
}

// Вид источника сменился между краями (журнал гейтвея стал обычным
// источником — конфиг поменяли): хранилище раскрывает хвосты с тем видом,
// что был при метке, и пакет не проходит с ясной причиной, а не молча без
// вердиктов.
func TestSourceProofKindChanged(t *testing.T) {
	key := pipelockKey(t)
	c := newClock()
	cfg := testConfig(t, withGateway(key))
	s := openStore(t, cfg, c)
	ingestLines(t, s, 1, readLines(t, filepath.Join(pipelockVectors, "tampered.jsonl"))[:2])
	mustStamp(t, s) // 10:00
	s.Close()
	for i := range cfg.Sources {
		if cfg.Sources[i].Name == "agent-gw" {
			cfg.Sources[i].ContentType, cfg.Sources[i].GatewayKey = "syslog", ""
		}
	}
	c.add(time.Minute)
	s = openStore(t, cfg, c)
	ingest(t, s, "agent-gw", 3, 3)
	c.add(5 * time.Minute)
	mustStamp(t, s) // 10:06
	mustStampNow(t, s)
	from, to := clockAt(10, 0, 30), clockAt(10, 3, 30)
	b, err := s.ProofSource("agent-gw", from, to, false, 0)
	if err != nil {
		t.Fatal(err)
	}
	if r := proof.VerifySource(b, trustOf(t, s), from, to); r.Valid() || !strings.Contains(r.Text(), `the tails name the kind of agent-gw "pipelock/recorder" at the lower edge and "" at the upper one`) {
		t.Fatalf("смена вида:\n%s", r.Text())
	}
}

// Хранилище солгало о виде источника в хвостах (журнал гейтвея назван
// обычным): без улик снятые вердикты не видны — это ложь в цепи, как
// заниженный хвост. С уликами (-dek) вид записи виден по самой улике, и
// запись журнала гейтвея без вердикта не проходит.
func TestSourceProofGatewayKindLie(t *testing.T) {
	key := pipelockKey(t)
	c := newClock()
	s := openStore(t, testConfig(t, withGateway(key)), c)
	s.gwSources["agent-gw"] = false
	ingest(t, s, "abs-core", 1, 1)
	mustStamp(t, s) // 10:00
	c.add(time.Minute)
	ingestLines(t, s, 1, readLines(t, filepath.Join(pipelockVectors, "tampered.jsonl")))
	c.add(5 * time.Minute)
	mustStamp(t, s) // 10:06
	mustStampNow(t, s)
	from, to := clockAt(10, 0, 30), clockAt(10, 3, 30)
	b, err := s.ProofSource("agent-gw", from, to, true, 0)
	if err != nil {
		t.Fatal(err)
	}
	if b.Upper.Open == nil || b.Upper.Open.Kind != "" {
		t.Fatal("хвосты назвали журнал гейтвея журналом гейтвея")
	}
	for i := range b.Records {
		b.Records[i].Verdict = nil
	}
	if r := proof.VerifySource(b, trustOf(t, s), from, to); r.Valid() || !strings.Contains(r.Text(), "is a gateway journal entry, and the bundle lacks the store's verdict on it") {
		t.Fatalf("вердикты сняты, улики приложены:\n%s", r.Text())
	}
}

// Свежая метка над старыми хвостами, дописанная в цепь сразу за
// закрывающей, верхним краем не становится и честный пакет не ломает:
// край — хвосты первой метки над звеном после закрывающего токена.
func TestSourceProofSkipsAppendedOldTailsToken(t *testing.T) {
	c := newClock()
	s := openStore(t, testConfig(t), c)
	ingest(t, s, "abs-core", 1, 2)
	mustStamp(t, s) // A, 10:00
	c.add(3 * time.Minute)
	ingest(t, s, "abs-core", 3, 4)
	c.add(2 * time.Minute)
	mustStamp(t, s) // B, 10:05 — посреди окна
	c.add(2 * time.Minute)
	ingest(t, s, "abs-core", 5, 6)
	c.add(10 * time.Minute)
	mustStamp(t, s) // C, 10:17 — закрывает окно

	// Владелец дописывает свежий токен над хвостами B.
	var pb uint64
	for _, tok := range s.tokens {
		if tok.gen.Equal(clockAt(10, 5, 0)) {
			pb = tok.head
		}
	}
	links, err := auditchain.ReadLinks(s.chainDir, pb, pb)
	if err != nil || pb == 0 {
		t.Fatalf("звено B %d: %v", pb, err)
	}
	imprint := proof.HeadImprint(pb, auditchain.Hash(links[0]))
	fresh, err := s.tsaLocal.Sign(imprint[:], nil)
	if err != nil {
		t.Fatal(err)
	}
	info, err := tsa.Verify(fresh, imprint, s.tsaTrust)
	if err != nil {
		t.Fatal(err)
	}
	s.chainMu.Lock()
	num := s.appendLeafLocked(auditchain.Leaf{UnixNano: c.now().UnixNano(), Type: auditchain.EventTimestamp, Subject: strconv.FormatUint(pb, 10), Payload: fresh})
	s.tokens = append(s.tokens, tokenRef{head: pb, leaf: num, gen: info.GenTime})
	if err := s.flushLocked(); err != nil {
		t.Fatal(err)
	}
	s.chainMu.Unlock()
	c.add(time.Minute)
	mustStampNow(t, s) // D — её хвосты и есть верхний край

	from, to := clockAt(10, 1, 0), clockAt(10, 10, 0)
	b, err := s.ProofSource("abs-core", from, to, false, 0)
	if err != nil {
		t.Fatal(err)
	}
	if r := proof.VerifySource(b, trustOf(t, s), from, to); !r.Valid() || r.LastSeq != 6 {
		t.Fatalf("честный пакет с дописанным токеном в цепи:\n%s", r.Text())
	}
}
