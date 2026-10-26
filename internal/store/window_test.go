package store

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/Nikolay1994Kaz/evidencestore/internal/auditchain"
	"github.com/Nikolay1994Kaz/evidencestore/internal/config"
	"github.com/Nikolay1994Kaz/evidencestore/internal/keyring"
	"github.com/Nikolay1994Kaz/evidencestore/internal/proof"
)

// Пакет за окно на настоящем хранилище (DECISIONS, п. 27). Подделки, которые
// согласованы во всём, кроме одного пункта, — в пакете proof.

// windowStore — приём вокруг трёх меток, по часам теста:
//
//	10:00 улики 1–3, метка A
//	10:05 улики 4–6
//	10:10 метка B
//	10:11 улики 7–8, метка C
//
// Метка сворачивает хвост цепи в звено, кладёт хвосты источников одни в
// следующее звено и заверяет его (п. 28), а токен с хвостами за ним — ещё в
// следующее: звено 2 — улики 1–3, 3 — хвосты (A заверяет голову 3), 4 —
// токен A и хвосты, 5 — улики 4–6, 6 — хвосты (B), 7 — токен B и хвосты.
func windowStore(t *testing.T, opt Options) (*Store, *clock, *config.Config) {
	t.Helper()
	c := newClock()
	cfg := testConfig(t)
	opt.Logger, opt.Now, opt.NoBackground = quiet, c.now, true
	s, err := Open(cfg, opt)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Close() })
	ingest(t, s, "abs-core", 1, 3)
	mustStamp(t, s)
	c.add(5 * time.Minute)
	ingest(t, s, "abs-core", 4, 6)
	c.add(5 * time.Minute)
	mustStamp(t, s)
	c.add(time.Minute)
	ingest(t, s, "abs-core", 7, 8)
	mustStamp(t, s)
	return s, c, cfg
}

func clockAt(hh, mm, ss int) time.Time { return time.Date(2026, 9, 25, hh, mm, ss, 0, time.UTC) }

// roundTrip — пакет через JSON, как он уходит аудитору.
func roundTrip(t *testing.T, b proof.WindowBundle) proof.WindowBundle {
	t.Helper()
	data, err := json.Marshal(b)
	if err != nil {
		t.Fatal(err)
	}
	out, err := proof.ParseWindow(data)
	if err != nil {
		t.Fatal(err)
	}
	return out
}

// chainLeaves — все листья цепи с диска.
func chainLeaves(t *testing.T, cfg *config.Config) []auditchain.Leaf {
	t.Helper()
	var all []auditchain.Leaf
	_, chainDir, _ := dirs(cfg)
	if err := auditchain.ScanLeaves(chainDir, func(_ uint64, l auditchain.Leaf) error {
		all = append(all, l)
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	return all
}

// stretchOf — листья цепи, которые обязан нести пакет: после звена нижней
// головы до конца звена StretchEnd.
func stretchOf(t *testing.T, s *Store, cfg *config.Config, b proof.WindowBundle) []proof.Leaf {
	t.Helper()
	s.chainMu.Lock()
	var first uint64
	if b.LowerHead > 0 {
		l := s.links[b.LowerHead-1]
		first = l.first + l.count
	}
	end := s.links[b.StretchEnd-1]
	s.chainMu.Unlock()
	var out []proof.Leaf
	for _, l := range chainLeaves(t, cfg)[first : end.first+end.count] {
		out = append(out, proof.FromLeaf(l))
	}
	return out
}

// wholeChainWindow — вся цепь одним пакетом за окно: от начала цепи до
// последней метки (окно кончается чуть раньше чем за минуту до её времени,
// так что верхняя — она: граница строгая). Возвращает отчёт проверки и номера улик по источникам в порядке
// листьев. Симуляции проверяют им, что честная история хранилища проходит
// правила окна целиком.
func wholeChainWindow(s *Store, trust proof.Trust) (proof.WindowReport, map[string][]uint64, error) {
	s.chainMu.Lock()
	var last time.Time
	if n := len(s.tokens); n > 0 {
		last = s.tokens[n-1].gen
	}
	s.chainMu.Unlock()
	if last.IsZero() {
		return proof.WindowReport{}, nil, errors.New("в цепи нет меток")
	}
	from, to := time.Unix(1, 0).UTC(), last.Add(-proof.ReceiveSkew-time.Nanosecond)
	b, err := s.ProofWindow(from, to, "", false, 0)
	if err != nil {
		return proof.WindowReport{}, nil, err
	}
	seqs := map[string][]uint64{}
	for _, l := range b.Leaves {
		if l.Type == uint8(auditchain.EventEvidence) {
			q, _ := strconv.ParseUint(l.Subject, 10, 64)
			seqs[l.Scope] = append(seqs[l.Scope], q)
		}
	}
	return proof.VerifyWindow(b, trust, from, to), seqs, nil
}

// failedChecks — проваленные пункты отчёта одной строкой.
func failedChecks(r proof.WindowReport) string {
	var out []string
	for _, c := range r.Checks {
		if !c.OK {
			out = append(out, c.Name+": "+c.Detail)
		}
	}
	return strings.Join(out, "; ")
}

func failedCheck(t *testing.T, r proof.WindowReport, name string) {
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

// ⭐ Окно 10:04–10:06: нижняя метка A (10:00), верхняя B (10:10). Пакет несёт
// ровно листья цепи между головой под A и звеном с токеном B — улики 4–6;
// 7–8 легли в цепь после токена B, их в пакете нет. Тела — ключами записей.
func TestWindowProof(t *testing.T) {
	s, _, cfg := windowStore(t, Options{})
	b, err := s.ProofWindow(clockAt(10, 4, 0), clockAt(10, 6, 0), "abs-core", true, 0)
	if err != nil {
		t.Fatal(err)
	}
	r := proof.VerifyWindow(roundTrip(t, b), trustOf(t, s), time.Time{}, time.Time{})
	if !r.Valid() {
		t.Fatalf("пакет не прошёл:\n%s", r.Text())
	}
	if !r.Lower.Equal(clockAt(10, 0, 0)) || !r.Upper.Equal(clockAt(10, 10, 0)) || r.FromStart {
		t.Fatalf("T1 %v, T2 %v, с начала %v", r.Lower, r.Upper, r.FromStart)
	}
	if !reflect.DeepEqual(b.Leaves, stretchOf(t, s, cfg, b)) {
		t.Fatalf("листья пакета — не участок цепи: %d листьев", len(b.Leaves))
	}
	if len(r.Sources) != 1 {
		t.Fatalf("источники: %+v", r.Sources)
	}
	if src := r.Sources[0]; src.Records != 3 || src.InWindow != 3 || src.FirstSeq != 4 || src.LastSeq != 6 {
		t.Fatalf("сводка: %+v", src)
	}
	if len(r.Bodies) != 3 || r.Attached != 3 {
		t.Fatalf("тел %d из %d", len(r.Bodies), r.Attached)
	}
	for _, body := range r.Bodies {
		if want := fmt.Sprintf("abs-core event %d", body.Seq); string(body.Body) != want {
			t.Fatalf("тело %d: %q", body.Seq, body.Body)
		}
	}
	// Заявление — о последнем звене пакета, оно же конец участка.
	if last := b.Links[len(b.Links)-1].Seq; b.Statement.HeadSeq != last || last != b.StretchEnd {
		t.Fatalf("заявление о голове %d, последнее звено %d, конец участка %d", b.Statement.HeadSeq, last, b.StretchEnd)
	}
	// Без -source пакет не несёт улик, только листья.
	nb, err := s.ProofWindow(clockAt(10, 4, 0), clockAt(10, 6, 0), "", false, 0)
	if err != nil || len(nb.Records) != 0 {
		t.Fatalf("без -source: %d улик, %v", len(nb.Records), err)
	}
}

// Окно до первой метки: участок с первого звена цепи.
func TestWindowProofFromChainStart(t *testing.T) {
	s, _, cfg := windowStore(t, Options{})
	b, err := s.ProofWindow(clockAt(9, 0, 0), clockAt(9, 30, 0), "", false, 0)
	if err != nil {
		t.Fatal(err)
	}
	r := proof.VerifyWindow(roundTrip(t, b), trustOf(t, s), time.Time{}, time.Time{})
	if !r.Valid() || !r.FromStart || b.LowerHead != 0 || b.Links[0].Seq != 1 {
		t.Fatalf("пакет с начала цепи (нижняя голова %d):\n%s", b.LowerHead, r.Text())
	}
	if !reflect.DeepEqual(b.Leaves, stretchOf(t, s, cfg, b)) {
		t.Fatal("листья пакета — не участок цепи")
	}
	if src := r.Sources[0]; src.FirstSeq != 1 || src.InWindow != 0 {
		t.Fatalf("сводка: %+v", src)
	}
}

func TestWindowProofRefusals(t *testing.T) {
	s, c, _ := windowStore(t, Options{})
	for _, tc := range []struct {
		name     string
		from, to time.Time
		source   string
		dek      bool
		want     error
	}{
		{"конец раньше начала", clockAt(10, 6, 0), clockAt(10, 4, 0), "", false, ErrWindow},
		{"верхней метки ещё нет", clockAt(10, 10, 30), clockAt(10, 11, 0), "", false, ErrWindow},
		{"-source без -dek", clockAt(10, 4, 0), clockAt(10, 6, 0), "abs-core", false, ErrWindow},
		{"-dek без -source", clockAt(10, 4, 0), clockAt(10, 6, 0), "", true, ErrWindow},
		{"неизвестный источник", clockAt(10, 4, 0), clockAt(10, 6, 0), "nobody", true, ErrNotFound},
		{"нет окна", time.Time{}, clockAt(10, 6, 0), "", false, ErrWindow},
	} {
		if _, err := s.ProofWindow(tc.from, tc.to, tc.source, tc.dek, 0); !errors.Is(err, tc.want) {
			t.Fatalf("%s: %v", tc.name, err)
		}
	}
	// Верхняя метка появилась — окно собирается.
	c.add(2 * time.Minute)
	ingest(t, s, "abs-core", 9, 9)
	mustStamp(t, s)
	if _, err := s.ProofWindow(clockAt(10, 10, 30), clockAt(10, 11, 0), "", false, 0); err != nil {
		t.Fatal(err)
	}
	// Нижняя — ПОСЛЕДНЯЯ метка не позже начала окна минус минута (из A, B, C
	// — C в 10:11), верхняя — первая не раньше конца плюс минута (E в 10:14).
	c.add(time.Minute)
	ingest(t, s, "abs-core", 10, 10)
	mustStamp(t, s)
	s.chainMu.Lock()
	var headC, linkE uint64
	for _, tk := range s.tokens {
		switch {
		case tk.gen.Equal(clockAt(10, 11, 0)):
			headC = tk.head
		case tk.gen.Equal(clockAt(10, 14, 0)):
			l, _ := s.linkOfLocked(tk.leaf)
			linkE = l.seq
		}
	}
	s.chainMu.Unlock()
	if b, err := s.ProofWindow(clockAt(10, 12, 30), clockAt(10, 12, 45), "", false, 0); err != nil || headC == 0 || b.LowerHead != headC || b.StretchEnd != linkE {
		t.Fatalf("нижняя голова %d (ждали %d), конец %d (ждали %d): %v", b.LowerHead, headC, b.StretchEnd, linkE, err)
	}
	// Границы строгие, как в проверке: метка C (10:11) меньше чем за секунду
	// до начала окна — нижней берётся B; метка D ровно через минуту после
	// конца (10:13) — верхней берётся E. Пакет проходит.
	s.chainMu.Lock()
	var headB uint64
	for _, tk := range s.tokens {
		if tk.gen.Equal(clockAt(10, 10, 0)) {
			headB = tk.head
		}
	}
	s.chainMu.Unlock()
	b, err := s.ProofWindow(clockAt(10, 11, 0).Add(500*time.Millisecond), clockAt(10, 12, 0), "", false, 0)
	if err != nil || b.LowerHead != headB || b.StretchEnd != linkE {
		t.Fatalf("нижняя голова %d (ждали %d), конец %d (ждали %d): %v", b.LowerHead, headB, b.StretchEnd, linkE, err)
	}
	if r := proof.VerifyWindow(roundTrip(t, b), trustOf(t, s), time.Time{}, time.Time{}); !r.Valid() {
		t.Fatalf("пакет на строгих границах:\n%s", r.Text())
	}
	// До головы, которой ещё нет, пакет не тянется.
	if _, err := s.ProofWindow(clockAt(10, 4, 0), clockAt(10, 6, 0), "", false, 1000); err == nil {
		t.Fatal("пакет до несуществующей головы собран")
	}
	// Предел листьев.
	defer func(n uint64) { maxWindowLeaves = n }(maxWindowLeaves)
	maxWindowLeaves = 3
	if _, err := s.ProofWindow(clockAt(10, 4, 0), clockAt(10, 6, 0), "", false, 0); !errors.Is(err, ErrWindow) || !strings.Contains(err.Error(), "shorter windows") {
		t.Fatalf("предел листьев: %v", err)
	}
}

// Хранилище подделывает пакет своим же ключом подписи: выбросить лист,
// обрезать участок, сдвинуть начало, переписать звено, приложить чужое — всё
// видно. Против переписывания стоят метки TSA.
func TestWindowProofForgedByStore(t *testing.T) {
	s, _, cfg := windowStore(t, Options{})
	good, err := s.ProofWindow(clockAt(10, 4, 0), clockAt(10, 6, 0), "abs-core", true, 0)
	if err != nil {
		t.Fatal(err)
	}
	trust := trustOf(t, s)
	clone := func() proof.WindowBundle { return roundTrip(t, good) }
	verify := func(b proof.WindowBundle) proof.WindowReport {
		return proof.VerifyWindow(b, trust, time.Time{}, time.Time{})
	}
	sign := func(b *proof.WindowBundle, last auditchain.Record) {
		b.Statement = s.signer.Sign(auditchain.Head{Seq: last.Seq, Hash: auditchain.Hash(last)}, int(last.Seq), 0)
	}
	_, chainDir, _ := dirs(cfg)
	links, err := auditchain.ReadLinks(chainDir, 1, good.StretchEnd)
	if err != nil {
		t.Fatal(err)
	}
	link := func(seq uint64) auditchain.Record { return links[seq-1] }
	if len(good.Links) != 5 || good.LowerHead != 3 || good.StretchEnd != 7 || len(good.Leaves) != 8 {
		t.Fatalf("раскладка теста поменялась: звеньев %d, нижняя голова %d, конец %d, листьев %d",
			len(good.Links), good.LowerHead, good.StretchEnd, len(good.Leaves))
	}
	// Звенья 3…7; листья: [токен A, хвосты] (звено 4), [улики 4–6] (5),
	// [хвосты перед запросом B] (6), [токен B, хвосты] (7).

	b := clone()
	b.Leaves = append(b.Leaves[:2], b.Leaves[3:]...)
	failedCheck(t, verify(b), "the bundle holds every leaf")

	b = clone()
	b.Leaves[1], b.Leaves[2] = b.Leaves[2], b.Leaves[1]
	failedCheck(t, verify(b), "the bundle holds every leaf")

	// Конец участка заявлен дальше звеньев пакета: отчёт назвал бы ложный
	// конец, а свидетеля сверяли бы от него.
	b = clone()
	b.StretchEnd = 8
	failedCheck(t, verify(b), "the bundle holds every leaf")

	// Конец участка отрезан вместе с токеном B, голова переподписана.
	b = clone()
	b.Links, b.Leaves, b.StretchEnd = b.Links[:4], b.Leaves[:6], 6
	sign(&b, link(6))
	failedCheck(t, verify(b), "a TSA time-stamp in the stretch after the window (T2)")

	// Начало сдвинуто за улики 4–6: участок после головы под B.
	b = clone()
	b.Links, b.Leaves, b.LowerHead = b.Links[3:], b.Leaves[6:], 6
	failedCheck(t, verify(b), "the time-stamps bracket the window")

	// Улика 5 выброшена из звена 5, звенья 5–7 пересчитаны и сцеплены
	// заново, голова переподписана: корни сходятся, но метка B заверяла
	// прежнюю голову 6.
	b = clone()
	p5, _ := auditchain.DecodeBatchPayload(link(5).Payload)
	l5, err := auditchain.LinkBatch(auditchain.Head{Seq: 4, Hash: auditchain.Hash(link(4))}, link(5).UnixNano, p5.FirstLeaf,
		[]auditchain.Leaf{b.Leaves[2].Chain(), b.Leaves[4].Chain()})
	if err != nil {
		t.Fatal(err)
	}
	l6, err := auditchain.LinkBatch(auditchain.Head{Seq: 5, Hash: auditchain.Hash(l5)}, link(6).UnixNano, p5.FirstLeaf+2,
		[]auditchain.Leaf{b.Leaves[5].Chain()})
	if err != nil {
		t.Fatal(err)
	}
	l7, err := auditchain.LinkBatch(auditchain.Head{Seq: 6, Hash: auditchain.Hash(l6)}, link(7).UnixNano, p5.FirstLeaf+3,
		[]auditchain.Leaf{b.Leaves[6].Chain(), b.Leaves[7].Chain()})
	if err != nil {
		t.Fatal(err)
	}
	b.Links = []proof.Link{proof.FromLink(link(3)), proof.FromLink(link(4)), proof.FromLink(l5), proof.FromLink(l6), proof.FromLink(l7)}
	b.Leaves = append(b.Leaves[:3], b.Leaves[4:]...)
	sign(&b, l7)
	failedCheck(t, verify(b), "every TSA time-stamp in the stretch verifies")

	// Голова подписана своим ключом, но не над последним звеном пакета.
	b = clone()
	sign(&b, link(6))
	failedCheck(t, verify(b), "the head is signed with the store key")

	// Чужой ключ подписи.
	other, err := auditchain.LoadOrCreateSigner(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	b = clone()
	b.Statement = other.Sign(auditchain.Head{Seq: 7, Hash: auditchain.Hash(link(7))}, 7, 0)
	failedCheck(t, verify(b), "the head is signed with the store key")

	// Приложенные улики: испорченный байт, чужой ключ записи, улика не с участка.
	b = clone()
	b.Records[0].Evidence[len(b.Records[0].Evidence)-1] ^= 1
	failedCheck(t, verify(b), "the records attached")
	b = clone()
	b.Records[0].DEK, b.Records[1].DEK = b.Records[1].DEK, b.Records[0].DEK
	failedCheck(t, verify(b), "the records attached")
	outside, err := s.Proof("abs-core", 1, true)
	if err != nil {
		t.Fatal(err)
	}
	b = clone()
	b.Records = append(b.Records, proof.WindowRecord{Evidence: outside.Evidence, DEK: outside.DEK})
	failedCheck(t, verify(b), "the records attached")
	// Лист этой улики подложен за концом участка: лишний лист — провал, иначе
	// приложенная улика сослалась бы на лист, которого в цепи участка нет.
	b = clone()
	b.Leaves = append(b.Leaves, outside.Inclusion.Leaf)
	b.Records = append(b.Records, proof.WindowRecord{Evidence: outside.Evidence, DEK: outside.DEK})
	failedCheck(t, verify(b), "the bundle holds every leaf")
	b = clone()
	b.Records = append(b.Records, b.Records[0])
	failedCheck(t, verify(b), "the records attached")

	// Окно аудитора шире меток.
	if r := proof.VerifyWindow(clone(), trust, clockAt(9, 59, 0), clockAt(10, 6, 0)); r.Valid() {
		t.Fatalf("окно до T1 прошло:\n%s", r.Text())
	}
}

// Ключ месяца ждёт уничтожения: улики идут без ключей, пакет доказывает их
// существование, а тел нет — и отчёт это называет.
func TestWindowProofKeyPending(t *testing.T) {
	s, _, _ := windowStore(t, Options{})
	scope := "abs-core/2026-09"
	if err := s.Deactivate(true, scope); err != nil {
		t.Fatal(err)
	}
	if _, err := s.ScheduleDestroy(context.Background(), scope, time.Hour, []keyring.Approval{{Who: "operator"}, {Who: "security"}}); err != nil {
		t.Fatal(err)
	}
	b, err := s.ProofWindow(clockAt(10, 4, 0), clockAt(10, 6, 0), "abs-core", true, 0)
	if err != nil {
		t.Fatal(err)
	}
	r := proof.VerifyWindow(roundTrip(t, b), trustOf(t, s), time.Time{}, time.Time{})
	if !r.Valid() || r.Attached != 3 || len(r.Bodies) != 0 {
		t.Fatalf("улик %d, тел %d:\n%s", r.Attached, len(r.Bodies), r.Text())
	}
	if !strings.Contains(r.Text(), "3 of the 3 records attached carry no record key") {
		t.Fatalf("отчёт:\n%s", r.Text())
	}
}

// Участок через несколько файлов листьев: каждый читается один раз, листья
// идут подряд через границы файлов.
func TestWindowProofAcrossLeafFiles(t *testing.T) {
	s, c, cfg := windowStore(t, Options{chainSegment: 256})
	for q := uint64(9); q <= 40; q++ {
		c.add(time.Second)
		ingest(t, s, "abs-core", q, q)
		if err := s.flush(); err != nil {
			t.Fatal(err)
		}
	}
	c.add(2 * time.Minute)
	mustStamp(t, s)
	_, chainDir, _ := dirs(cfg)
	files, _ := filepath.Glob(filepath.Join(chainDir, "leaves_*.log"))
	b, err := s.ProofWindow(clockAt(10, 4, 0), clockAt(10, 11, 10), "abs-core", true, 0)
	if err != nil {
		t.Fatal(err)
	}
	r := proof.VerifyWindow(roundTrip(t, b), trustOf(t, s), time.Time{}, time.Time{})
	if !r.Valid() || len(files) < 4 {
		t.Fatalf("файлов листьев %d:\n%s", len(files), r.Text())
	}
	if !reflect.DeepEqual(b.Leaves, stretchOf(t, s, cfg, b)) {
		t.Fatal("листья пакета — не участок цепи")
	}
	if src := r.Sources[0]; src.FirstSeq != 4 || src.LastSeq != 40 || len(r.Bodies) != 37 {
		t.Fatalf("сводка %+v, тел %d", src, len(r.Bodies))
	}
	// Файл листьев посреди участка пропал — пакет не собирается. Файл берётся
	// по номерам листьев: начинается внутри участка.
	s.chainMu.Lock()
	lower, upper := s.links[b.LowerHead-1], s.links[b.StretchEnd-1]
	s.chainMu.Unlock()
	inside := ""
	for _, f := range files {
		first, err := strconv.ParseUint(strings.TrimSuffix(strings.TrimPrefix(filepath.Base(f), "leaves_"), ".log"), 10, 64)
		if err == nil && first > lower.first+lower.count && first < upper.first+upper.count {
			inside = f
			break
		}
	}
	if inside == "" {
		t.Fatalf("нет файла листьев внутри участка: %v", files)
	}
	if err := os.Remove(inside); err != nil {
		t.Fatal(err)
	}
	if _, err := s.ProofWindow(clockAt(10, 4, 0), clockAt(10, 11, 10), "", false, 0); !errors.Is(err, auditchain.ErrLeavesMissing) {
		t.Fatalf("пропавший файл листьев: %v", err)
	}
}

// Свидетель голов: пакет, который не доходит до головы свидетеля, не
// проходит; с -to-head доходит и проходит.
func TestWindowProofWitness(t *testing.T) {
	s, _, _ := windowStore(t, Options{})
	if err := s.flush(); err != nil { // токен C — в звено после участка
		t.Fatal(err)
	}
	head := s.Statement()
	trust := trustOf(t, s)
	trust.Witness = &proof.Witness{Heads: []proof.PublishedHead{{Name: "head.json", Statement: head}}}

	b, err := s.ProofWindow(clockAt(10, 4, 0), clockAt(10, 6, 0), "", false, 0)
	if err != nil {
		t.Fatal(err)
	}
	failedCheck(t, proof.VerifyWindow(roundTrip(t, b), trust, time.Time{}, time.Time{}), "the chain in the bundle agrees with the heads the witness saw")

	b, err = s.ProofWindow(clockAt(10, 4, 0), clockAt(10, 6, 0), "", false, head.HeadSeq)
	if err != nil {
		t.Fatal(err)
	}
	r := proof.VerifyWindow(roundTrip(t, b), trust, time.Time{}, time.Time{})
	if !r.Valid() || r.WitnessHead != head.HeadSeq || b.StretchEnd >= head.HeadSeq {
		t.Fatalf("голова свидетеля %d, конец участка %d:\n%s", r.WitnessHead, b.StretchEnd, r.Text())
	}

	// Свидетель видел голову посреди участка: с пакетом она сходится, но
	// закрепляет не весь участок — закрепляющей головы у свидетеля ещё нет.
	_, chainDir, _ := dirs(s.cfg)
	links, err := auditchain.ReadLinks(chainDir, 4, 4)
	if err != nil {
		t.Fatal(err)
	}
	trust.Witness = &proof.Witness{Heads: []proof.PublishedHead{{Name: "mid.json",
		Statement: s.signer.Sign(auditchain.Head{Seq: 4, Hash: auditchain.Hash(links[0])}, 4, 0)}}}
	b, err = s.ProofWindow(clockAt(10, 4, 0), clockAt(10, 6, 0), "", false, 0)
	if err != nil {
		t.Fatal(err)
	}
	r = proof.VerifyWindow(roundTrip(t, b), trust, time.Time{}, time.Time{})
	if !r.Valid() || !r.WitnessNone || r.WitnessHead != 0 {
		t.Fatalf("голова свидетеля посреди участка (конец %d): %+v\n%s", b.StretchEnd, r.WitnessHead, r.Text())
	}
}

// Тела прикладываются только для названного источника; чужие улики окна —
// листьями.
func TestWindowProofOneSource(t *testing.T) {
	c := newClock()
	s := openStore(t, testConfig(t), c)
	mustStamp(t, s)
	c.add(5 * time.Minute)
	ingest(t, s, "abs-core", 1, 2)
	ingest(t, s, "pipelock", 1, 3)
	c.add(5 * time.Minute)
	mustStamp(t, s)
	b, err := s.ProofWindow(clockAt(10, 4, 0), clockAt(10, 6, 0), "abs-core", true, 0)
	if err != nil {
		t.Fatal(err)
	}
	r := proof.VerifyWindow(roundTrip(t, b), trustOf(t, s), time.Time{}, time.Time{})
	if !r.Valid() || len(r.Sources) != 2 || r.Attached != 2 || len(r.Bodies) != 2 {
		t.Fatalf("источников %d, улик %d, тел %d:\n%s", len(r.Sources), r.Attached, len(r.Bodies), r.Text())
	}
	for _, body := range r.Bodies {
		if body.Source != "abs-core" {
			t.Fatalf("тело чужого источника: %s/%d", body.Source, body.Seq)
		}
	}
}
