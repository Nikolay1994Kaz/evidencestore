package store

import (
	"errors"
	"fmt"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/Nikolay1994Kaz/evidencestore/internal/config"
	"github.com/Nikolay1994Kaz/evidencestore/internal/evidence"
	"github.com/Nikolay1994Kaz/evidencestore/internal/keyring"
	"github.com/Nikolay1994Kaz/evidencestore/internal/proof"
)

// Третий заход по ветке месяцев (P-81…P-87): окно аудитора шире пакета, улика
// без ключа, квитанции ключей, ключ, закрытый посреди выдачи, значение субъекта
// «как записано».

// ⭐ P-81: окно аудитора шире окна пакета и заходит в соседний месяц с живым
// ключом. В том месяце у пакета нет ни одной улики, но это не «закрытый
// месяц»: вне своего окна хранилище улик не кладёт никогда, и записи окна
// аудитора там — недостача. До правки такой пакет проходил с заметкой о
// стёртом ключе.
func TestWiderAuditorWindowIntoLiveMonth(t *testing.T) {
	s, _, from, to := monthStore(t)
	trust := trustOf(t, s)
	windows := []struct {
		name     string
		from, to time.Time
	}{
		// Пакет только за сентябрь, аудитор заходит в октябрь (записи 4, 5).
		{"пакет за сентябрь", from, time.Date(2026, 9, 30, 23, 59, 0, 0, time.UTC)},
		// Пакет только за октябрь, аудитор заходит в сентябрь (записи 2, 3).
		{"пакет за октябрь", time.Date(2026, 10, 1, 0, 0, 30, 0, time.UTC), to},
	}
	const ask = "come without their evidence: ask for a bundle over this window"
	for _, w := range windows {
		src, err := s.ProofSource("agent", w.from, w.to, true, 0)
		if err != nil {
			t.Fatal(err)
		}
		r := proof.VerifySource(sourceRoundTrip(t, src), trust, from, to)
		sourceFailed(t, r, "the records attached match their leaves")
		if !strings.Contains(r.Text(), "2 records received in the window "+ask) {
			t.Fatalf("%s, -source -dek:\n%s", w.name, r.Text())
		}
		// Своим окном пакет проходит: записи вне него — листья, а не месяц-лист.
		if r := proof.VerifySource(sourceRoundTrip(t, src), trust, time.Time{}, time.Time{}); !r.Valid() || r.LeafOnly != 0 {
			t.Fatalf("%s, -source -dek своим окном:\n%s", w.name, r.Text())
		}

		sub, err := s.ProofSubject("agent", "a", w.from, w.to, 0)
		if err != nil {
			t.Fatal(err)
		}
		r = proof.VerifySource(sourceRoundTrip(t, sub), trust, from, to)
		sourceFailed(t, r, "the records attached match their leaves")
		if !strings.Contains(r.Text(), ask) {
			t.Fatalf("%s, -subject:\n%s", w.name, r.Text())
		}

		win, err := s.ProofWindow(w.from, w.to, "agent", true, 0)
		if err != nil {
			t.Fatal(err)
		}
		rw := proof.VerifyWindow(roundTrip(t, win), trust, from, to)
		failedCheck(t, rw, "the records attached are in the stretch")
		if !strings.Contains(rw.Text(), ask) {
			t.Fatalf("%s, -window -dek:\n%s", w.name, rw.Text())
		}
	}
}

// P-81, честная половина: месяц, чей ключ закрыт, внутри окна пакета —
// листом, и окно аудитора, совпавшее с окном пакета, это принимает. Пакет за
// октябрь при окне аудитора, заходящем в стёртый сентябрь, — всё равно
// недостача: из него не видно, что сентябрь закрыт, и ответ — пакет за окно
// аудитора.
func TestLeafMonthInsideBundleWindow(t *testing.T) {
	s, c, from, to := monthStore(t)
	trust := trustOf(t, s)
	destroyMonth(t, s, c, "agent/2026-09")
	src, err := s.ProofSource("agent", from, to, true, 0)
	if err != nil {
		t.Fatal(err)
	}
	if r := proof.VerifySource(sourceRoundTrip(t, src), trust, from, to); !r.Valid() || r.LeafOnly != 2 ||
		!slices.Equal(r.LeafOnlyMonths, []string{"agent/2026-09"}) || !slices.Equal(bodySeqs(r.Bodies), []uint64{4, 5}) {
		t.Fatalf("сентябрь листом в окне пакета:\n%s", r.Text())
	}
	// Пакет за октябрь, аудитор шире — в сентябрь: недостача и тут.
	oct, err := s.ProofSource("agent", time.Date(2026, 10, 1, 0, 0, 30, 0, time.UTC), to, true, 0)
	if err != nil {
		t.Fatal(err)
	}
	sourceFailed(t, proof.VerifySource(sourceRoundTrip(t, oct), trust, from, to), "the records attached match their leaves")
}

// ⭐ P-83: после P-80 месяц с закрытым ключом идёт листом, а не уликой без
// ключа. Улика без ключа значит одно: ключ сняли из пакета или хранилище его
// придержало. Стиранием отчёт её больше не объясняет: снятый ключ одной
// неудобной записи живого октября прикрылся бы сроком хранения.
func TestKeylessEvidenceIsNotErasure(t *testing.T) {
	s, _, from, to := monthStore(t)
	trust := trustOf(t, s)
	src, err := s.ProofSource("agent", from, to, true, 0)
	if err != nil {
		t.Fatal(err)
	}
	f := sourceRoundTrip(t, src)
	for i := range f.Records {
		if len(f.Records[i].Evidence) > 0 && seqOf(t, f.Records[i]) == 5 {
			f.Records[i].DEK = nil
		}
	}
	r := proof.VerifySource(sourceRoundTrip(t, f), trust, time.Time{}, time.Time{})
	if !r.Valid() || r.Keyless() != 1 || !strings.Contains(r.Text(), "1 of the 4 records attached carry no record key: "+proof.KeylessReasons) ||
		strings.Contains(r.Text(), "retention") {
		t.Fatalf("снятый ключ живого месяца:\n%s", r.Text())
	}

	win, err := s.ProofWindow(from, to, "agent", true, 0)
	if err != nil {
		t.Fatal(err)
	}
	w := roundTrip(t, win)
	for i, rec := range w.Records {
		if sealed, _ := evidence.Unmarshal(rec.Evidence); sealed.Seq == 5 {
			w.Records[i].DEK = nil
		}
	}
	rw := proof.VerifyWindow(roundTrip(t, w), trust, time.Time{}, time.Time{})
	if !rw.Valid() || rw.Keyless() != 1 || !strings.Contains(rw.Text(), proof.KeylessReasons) || strings.Contains(rw.Text(), "retention") {
		t.Fatalf("снятый ключ живого месяца, пакет за окно:\n%s", rw.Text())
	}
}

// ⭐ P-84: квитанция ключа лежит в цепи. Пакет за окно, накрывший уничтожение,
// несёт её листом, и отчёт её называет: ею проверяют, что месяц закрыло само
// хранилище, а не кто-то вынул улики месяца из пакета.
func TestWindowListsKeyReceipts(t *testing.T) {
	s, c, _, _ := monthStore(t)
	from := c.now()
	c.add(time.Minute)
	destroyMonth(t, s, c, "agent/2026-09")
	to := c.now()
	c.add(5 * time.Minute)
	mustStamp(t, s)
	mustStampNow(t, s)
	win, err := s.ProofWindow(from, to, "", false, 0)
	if err != nil {
		t.Fatal(err)
	}
	r := proof.VerifyWindow(roundTrip(t, win), trustOf(t, s), time.Time{}, time.Time{})
	// Закрывают месяц только pending-destruction и destroyed (R2-01).
	var states []string
	for _, kr := range r.KeyReceipts {
		if kr.Scope != "agent/2026-09" {
			continue
		}
		states = append(states, kr.State)
		if want := kr.State == "pending-destruction" || strings.HasPrefix(kr.State, "destroyed"); kr.Closes != want || kr.Final != strings.HasPrefix(kr.State, "destroyed") {
			t.Fatalf("квитанция %+v: closes %v, final %v", kr, kr.Closes, kr.Final)
		}
	}
	if !r.Valid() || !slices.Contains(states, "deactivated") || !slices.Contains(states, "pending-destruction") || !slices.ContainsFunc(states, func(s string) bool { return strings.HasPrefix(s, "destroyed") }) {
		t.Fatalf("квитанции сентября: %v\n%s", states, r.Text())
	}
	text := r.Text()
	closing, _, _ := strings.Cut(text[strings.Index(text, "; closing: "):], "; not closing: ")
	if !strings.Contains(text, `the stretch holds the store's key receipts`) || !strings.Contains(text, "deactivated does not close it") ||
		!strings.Contains(closing, `"agent/2026-09" "pending-destruction" (op "schedule-destroy") at`) || strings.Contains(closing, `"deactivated"`) ||
		!strings.Contains(text, `; not closing: "agent/2026-09" "deactivated"`) {
		t.Fatalf("отчёт молчит, какие квитанции закрывают месяц:\n%s", text)
	}
}

// ⭐ R2-01: квитанция deactivated есть у любого прошлого месяца — хранилище
// деактивирует его само через несколько минут после конца. Пакет за окно через
// полночь, из которого вынули улики живого сентября, несёт и месяц листом, и эту
// квитанцию; до правки отчёт перечислял её наравне с уничтожением, а заметка
// звала квитанцию доказательством, что месяц закрыло хранилище. Теперь отчёт
// говорит, что последняя квитанция сентября его не закрывает. Честный пакет над
// заявкой на уничтожение говорит, что закрывает, — и что заявку можно отменить.
func TestDeactivatedReceiptDoesNotCloseMonth(t *testing.T) {
	c := newClock()
	c.set(time.Date(2026, 9, 30, 23, 50, 0, 0, time.UTC))
	s := openStore(t, testConfig(t, withSubjects), c)
	in := func(seq uint64, body []byte) {
		t.Helper()
		if _, err := s.Ingest("agent", []Incoming{{Seq: seq, Body: body}}); err != nil {
			t.Fatal(err)
		}
	}
	in(1, subjectLine("a", "до окна"))
	mustStamp(t, s)
	c.add(5 * time.Minute) // 23:55
	in(2, subjectLine("a", "сентябрь"))
	in(3, subjectLine("b", "чужой диалог"))
	c.add(10 * time.Minute) // 00:05
	in(4, subjectLine("a", "октябрь"))
	in(5, subjectLine("b", "чужой диалог в октябре"))
	c.add(2 * time.Minute) // 00:07 — обслуживание деактивирует сентябрь
	if err := s.deactivatePastMonths(c.now()); err != nil {
		t.Fatal(err)
	}
	c.add(3 * time.Minute)
	mustStamp(t, s)
	mustStampNow(t, s)
	from, to := time.Date(2026, 9, 30, 23, 54, 0, 0, time.UTC), time.Date(2026, 10, 1, 0, 6, 0, 0, time.UTC)
	trust := trustOf(t, s)
	win, err := s.ProofWindow(from, to, "agent", true, 0)
	if err != nil {
		t.Fatal(err)
	}
	if len(win.Records) != 4 {
		t.Fatalf("честный пакет: %d улик", len(win.Records))
	}
	forged := roundTrip(t, win)
	forged.Records = slices.DeleteFunc(forged.Records, func(rec proof.WindowRecord) bool {
		sealed, err := evidence.Unmarshal(rec.Evidence)
		return err == nil && sealed.Scope() == "agent/2026-09"
	})
	r := proof.VerifyWindow(roundTrip(t, forged), trust, time.Time{}, time.Time{})
	// Вынуть весь месяц — признанный предел: пакет проходит, но отчёт не вправе
	// выдать квитанцию deactivated за закрытие.
	if !r.Valid() || r.LeafOnly != 2 || !strings.Contains(r.Text(), `the last receipt of "agent/2026-09" in this stretch does not close it`) ||
		strings.Contains(r.Text(), `"agent/2026-09" in this stretch is pending-destruction`) {
		t.Fatalf("вынутый живой сентябрь с квитанцией deactivated:\n%s", r.Text())
	}

	// Честно: заявка на уничтожение сентября — месяц листом, последняя квитанция
	// участка закрывает его, и заявку можно отменить.
	c.add(time.Minute)
	if _, err := s.ScheduleDestroy(t.Context(), "agent/2026-09", time.Hour, []keyring.Approval{{Who: "operator"}, {Who: "security"}}); err != nil {
		t.Fatal(err)
	}
	to2 := c.now()
	c.add(5 * time.Minute)
	mustStamp(t, s)
	mustStampNow(t, s)
	honest, err := s.ProofWindow(from, to2, "agent", true, 0)
	if err != nil {
		t.Fatal(err)
	}
	r = proof.VerifyWindow(roundTrip(t, honest), trust, time.Time{}, time.Time{})
	if !r.Valid() || r.LeafOnly != 2 || !strings.Contains(r.Text(), `the last receipt of "agent/2026-09" in this stretch is pending-destruction`) ||
		!strings.Contains(r.Text(), "a destruction can be cancelled after this stretch") {
		t.Fatalf("честный пакет над заявкой:\n%s", r.Text())
	}
}

// ⭐ P-86: ключ месяца закрыли посреди выдачи — после решения «месяц открыт», до
// выдачи пакета. Пакет собирается заново, и месяц идёт листом: ни заголовков,
// ни меток закрытого месяца пакет не уносит. Пакет одной улики с меткой —
// отказ, как если бы его попросили мигом позже.
func TestMonthClosedMidIssue(t *testing.T) {
	s, _, from, to := monthStore(t)
	trust := trustOf(t, s)
	approvals := []keyring.Approval{{Who: "operator"}, {Who: "security"}}
	const sep = "agent/2026-09"
	if err := s.Deactivate(true, sep); err != nil {
		t.Fatal(err)
	}
	// closeOnce — хук, который закрывает сентябрь при первой проверке. Прямо в
	// кейринге: у пакета одной улики хук зовётся под замком цепи, а квитанция в
	// цепь пишется под ним же.
	closeOnce := func() *int {
		n := new(int)
		s.issueHook = func() {
			if *n++; *n == 1 {
				if _, err := s.keys.ScheduleDestroyFrom(sep, s.nowTime(), time.Hour, approvals); err != nil {
					t.Error(err)
				}
			}
		}
		return n
	}
	reopenSep := func() {
		t.Helper()
		s.issueHook = nil
		if _, err := s.keys.CancelDestroy(sep, approvals); err != nil {
			t.Fatal(err)
		}
	}

	calls := closeOnce()
	src, err := s.ProofSource("agent", from, to, true, 0)
	if err != nil || *calls != 2 {
		t.Fatalf("-source -dek: %v, проверок %d", err, *calls)
	}
	if r := proof.VerifySource(sourceRoundTrip(t, src), trust, time.Time{}, time.Time{}); !r.Valid() || r.LeafOnly != 2 ||
		!slices.Equal(r.LeafOnlyMonths, []string{sep}) || !slices.Equal(bodySeqs(r.Bodies), []uint64{4, 5}) {
		t.Fatalf("-source -dek, сентябрь закрыт посреди выдачи:\n%s", r.Text())
	}
	reopenSep()

	calls = closeOnce()
	sub, err := s.ProofSubject("agent", "a", from, to, 0)
	if err != nil || *calls != 2 {
		t.Fatalf("-subject: %v, проверок %d", err, *calls)
	}
	if len(sub.Subject.Labels) != 1 || sub.Subject.Labels[0].Scope != "agent/2026-10" {
		t.Fatalf("метки после закрытия сентября посреди выдачи: %+v", sub.Subject.Labels)
	}
	for _, rec := range sub.Records {
		if len(rec.Evidence) > 0 && seqOf(t, rec) <= 3 {
			t.Fatalf("улика сентября %d в пакете по субъекту", seqOf(t, rec))
		}
	}
	if r := proof.VerifySource(sourceRoundTrip(t, sub), trust, time.Time{}, time.Time{}); !r.Valid() || r.SubjectNoLabel != 2 ||
		!slices.Equal(bodySeqs(r.Bodies), []uint64{4}) {
		t.Fatalf("-subject, сентябрь закрыт посреди выдачи:\n%s", r.Text())
	}
	reopenSep()

	calls = closeOnce()
	win, err := s.ProofWindow(from, to, "agent", true, 0)
	if err != nil || *calls != 2 {
		t.Fatalf("-window -dek: %v, проверок %d", err, *calls)
	}
	if r := proof.VerifyWindow(roundTrip(t, win), trust, time.Time{}, time.Time{}); !r.Valid() || r.LeafOnly != 2 || len(win.Records) != 2 {
		t.Fatalf("-window -dek, сентябрь закрыт посреди выдачи:\n%s", r.Text())
	}
	reopenSep()

	calls = closeOnce()
	if _, err := s.ProofTo("agent", 2, true, 0); !errors.Is(err, ErrLabelErased) || *calls != 1 {
		t.Fatalf("одна улика с меткой, сентябрь закрыт посреди выдачи: %v, проверок %d", err, *calls)
	}
	reopenSep()
	// Месяц открыт — пакет выдаётся с первого раза.
	n := 0
	s.issueHook = func() { n++ }
	if _, err := s.ProofSource("agent", from, to, true, 0); err != nil || n != 1 {
		t.Fatalf("без закрытия: %v, проверок %d", err, n)
	}
}

// reissue не крутится вечно: месяц, который закрывают при каждой сборке, —
// отказ ErrReissue после reissueAttempts попыток, а сервер отвечает 409.
func TestReissueGivesUp(t *testing.T) {
	n := 0
	if _, err := reissue(func() (int, error) { n++; return 0, fmt.Errorf("%w: x", ErrReissue) }); !errors.Is(err, ErrReissue) || n != reissueAttempts {
		t.Fatalf("сдался после %d попыток: %v", n, err)
	}
	n = 0
	v, err := reissue(func() (int, error) {
		if n++; n == 1 {
			return 0, ErrReissue
		}
		return 7, nil
	})
	if err != nil || v != 7 || n != 2 {
		t.Fatalf("вторая попытка: %d, %v, попыток %d", v, err, n)
	}
	n = 0
	if _, err := reissue(func() (int, error) { n++; return 0, ErrWindow }); !errors.Is(err, ErrWindow) || n != 1 {
		t.Fatalf("другой отказ повторён %d раз: %v", n, err)
	}
}

// E3-02: хранилище без TSA пакет по источнику не собирает, и отказ пакету одной
// улики с меткой стёртого месяца его не советует.
func TestLabelErasedHintWithoutTSA(t *testing.T) {
	c := newClock()
	cfg := testConfig(t, withSubjects, func(cfg *config.Config) { cfg.TSA = config.TSA{} })
	s := openStore(t, cfg, c)
	if _, err := s.Ingest("agent", []Incoming{{Seq: 1, Body: subjectLine("a", "x")}}); err != nil {
		t.Fatal(err)
	}
	c.set(time.Date(2026, 10, 3, 10, 0, 0, 0, time.UTC))
	destroyMonth(t, s, c, "agent/2026-09")
	_, err := s.ProofTo("agent", 1, false, 0)
	if !errors.Is(err, ErrLabelErased) || strings.Contains(err.Error(), "one-source bundle") || !strings.Contains(err.Error(), "-show-label") {
		t.Fatalf("отказ без TSA: %v", err)
	}
	// С TSA совет есть: subjectStore.
	s2, c2, _ := subjectStore(t)
	destroyMonth(t, s2, c2, "agent/2026-09")
	if _, err := s2.ProofTo("agent", 3, false, 0); !errors.Is(err, ErrLabelErased) || !strings.Contains(err.Error(), "a one-source bundle over a window around it") {
		t.Fatalf("отказ с TSA: %v", err)
	}
}

// ⭐ T-01: значение субъекта сравнивается как записано. Байты не UTF-8 и
// одиночные суррогаты разбор json заменяет на U+FFFD, и до правки записи
// «c-\xff», «c-\xfe» и «c-\ud800» шли под меткой клиента «c-�», а их тела
// «называли» его. Теперь такие записи метки не получают, а пакет по значению,
// которое метку получить не может, — отказ.
func TestSubjectValueAsWritten(t *testing.T) {
	c := newClock()
	s := openStore(t, testConfig(t, withSubjects), c)
	in := func(seq uint64, body string) {
		t.Helper()
		if _, err := s.Ingest("agent", []Incoming{{Seq: seq, Body: []byte(body)}}); err != nil {
			t.Fatal(err)
		}
	}
	in(1, `{"client":"до окна"}`)
	mustStamp(t, s)
	c.add(5 * time.Minute)
	in(2, "{\"client\":\"c-\xff\"}")
	in(3, "{\"client\":\"c-\xfe\"}")
	in(4, `{"client":"c-\ud800"}`)
	in(5, `{"client":"c-�"}`)
	in(6, `{"client":"c-😀"}`)
	c.add(5 * time.Minute)
	mustStamp(t, s)
	mustStampNow(t, s)
	for seq, want := range map[uint64]string{2: "", 3: "", 4: "", 5: "c-�", 6: "c-\U0001F600"} {
		data, err := s.evlog.Read(s.sources["agent"].seqs.get(seq))
		if err != nil {
			t.Fatal(err)
		}
		sealed, err := evidence.Unmarshal(data)
		if err != nil {
			t.Fatal(err)
		}
		switch {
		case want == "" && !sealed.Subject.IsZero():
			t.Fatalf("запись %d с меткой, хотя значение не как записано", seq)
		case want != "" && sealed.Subject != labelOf(t, s, want):
			t.Fatalf("запись %d: не метка %q", seq, want)
		}
	}
	from, to := clockAt(10, 4, 0), clockAt(10, 6, 0)
	b, err := s.ProofSubject("agent", "c-�", from, to, 0)
	if err != nil {
		t.Fatal(err)
	}
	r := proof.VerifySource(sourceRoundTrip(t, b), trustOf(t, s), time.Time{}, time.Time{})
	if !r.Valid() || !slices.Equal(bodySeqs(r.Bodies), []uint64{5}) || r.SubjectUnlabeled != 3 {
		t.Fatalf("пакет по c-�:\n%s", r.Text())
	}
	// Запрос значением, которое метку не получит, — отказ, а не «под меткой
	// пусто» (T-06).
	for name, subject := range map[string]string{"не UTF-8": "c-\xff", "длиннее предела": strings.Repeat("x", evidence.MaxSubjectLen+1)} {
		if _, err := s.ProofSubject("agent", subject, from, to, 0); !errors.Is(err, ErrWindow) || !strings.Contains(err.Error(), "gets no label at intake") {
			t.Fatalf("%s: %v", name, err)
		}
	}
	if _, err := s.ProofSubject("agent", strings.Repeat("x", evidence.MaxSubjectLen), from, to, 0); err != nil {
		t.Fatalf("значение на пределе: %v", err)
	}
}

// ⭐ P-90 (R1-01, R2-01, RT-01): квитанция не говорит, был ли месяц закрыт, когда
// выдан пакет. (а) Пакет выдан, пока сентябрь открыт, ключ закрыли потом, а
// держатель пакета вынул улики сентября: квитанция лежит в звене после головы
// пакета. (б) Уничтожение отменили, пакет выдан после отмены, улики вынуты:
// отмена — квитанция deactivated с операцией cancel-destroy, она месяц не
// закрывает. До правки заметка звала квитанцию доказательством, что «никто не
// вынимал»; теперь она говорит, что квитанция этого не датирует, и чем
// проверить: свежим пакетом, пока ключ жив.
func TestReceiptDoesNotDateTheBundle(t *testing.T) {
	s, c, from, to := monthStore(t)
	trust := trustOf(t, s)
	approvals := []keyring.Approval{{Who: "operator"}, {Who: "security"}}
	const sep = "agent/2026-09"
	early, err := s.ProofSource("agent", from, to, true, 0)
	if err != nil {
		t.Fatal(err)
	}
	wFrom := c.now()
	c.add(time.Minute)
	if err := s.Deactivate(true, sep); err != nil {
		t.Fatal(err)
	}
	if _, err := s.ScheduleDestroy(t.Context(), sep, time.Hour, approvals); err != nil {
		t.Fatal(err)
	}
	c.add(time.Minute)
	if _, err := s.CancelDestroy(sep, approvals); err != nil {
		t.Fatal(err)
	}
	wTo := c.now()
	c.add(5 * time.Minute)
	mustStamp(t, s)
	mustStampNow(t, s)
	afterCancel, err := s.ProofSource("agent", from, to, true, 0)
	if err != nil {
		t.Fatal(err)
	}

	win, err := s.ProofWindow(wFrom, wTo, "", false, 0)
	if err != nil {
		t.Fatal(err)
	}
	rw := proof.VerifyWindow(roundTrip(t, win), trust, time.Time{}, time.Time{})
	var got []string
	var pendingLink uint64
	for _, kr := range rw.KeyReceipts {
		if kr.Scope != sep {
			continue
		}
		got = append(got, kr.State+"/"+kr.Op)
		if kr.State == "pending-destruction" {
			pendingLink = kr.Link
		}
	}
	if !rw.Valid() || !slices.Equal(got, []string{"deactivated/deactivate", "pending-destruction/schedule-destroy", "deactivated/cancel-destroy"}) {
		t.Fatalf("квитанции сентября: %v\n%s", got, rw.Text())
	}
	// (а): заявка легла в цепь позже головы пакета, выданного до неё.
	if pendingLink <= early.Checkpoint.Size {
		t.Fatalf("квитанция в звене %d, голова раннего пакета %d", pendingLink, early.Checkpoint.Size)
	}
	// Отмена — среди незакрывающих, с операцией.
	if _, notClosing, ok := strings.Cut(rw.Text(), "; not closing: "); !ok || !strings.Contains(notClosing, `"agent/2026-09" "deactivated" (op "cancel-destroy") at`) {
		t.Fatalf("отмена в отчёте не названа:\n%s", rw.Text())
	}

	for name, b := range map[string]proof.SourceBundle{"выдан до закрытия": early, "выдан после отмены": afterCancel} {
		f := sourceRoundTrip(t, b)
		for i := range f.Records {
			if len(f.Records[i].Evidence) > 0 && seqOf(t, f.Records[i]) <= 3 {
				f.Records[i].Evidence, f.Records[i].DEK = nil, nil
			}
		}
		r := proof.VerifySource(sourceRoundTrip(t, f), trust, time.Time{}, time.Time{})
		// Вынуть весь месяц — признанный предел; заметка не выдаёт квитанцию за
		// доказательство и говорит, как проверить.
		if !r.Valid() || r.LeafOnly != 2 || strings.Contains(r.Text(), "nobody stripped") ||
			!strings.Contains(r.Text(), "ask the store for the same bundle again: while the month key lives, a fresh bundle carries the month's evidence") ||
			!strings.Contains(r.Text(), "This bundle does not carry the time it was issued, so a receipt does not show that the month was closed already then") {
			t.Fatalf("%s, сентябрь вынут:\n%s", name, r.Text())
		}
	}
	// Так проверка и решается: свежий пакет после отмены несёт улики сентября.
	if r := proof.VerifySource(sourceRoundTrip(t, afterCancel), trust, time.Time{}, time.Time{}); !r.Valid() || r.LeafOnly != 0 || !slices.Equal(bodySeqs(r.Bodies), []uint64{2, 3, 4, 5}) {
		t.Fatalf("свежий пакет после отмены:\n%s", r.Text())
	}
}
