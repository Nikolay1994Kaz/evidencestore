package store

import (
	"context"
	"errors"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/Nikolay1994Kaz/evidencestore/internal/evidence"
	"github.com/Nikolay1994Kaz/evidencestore/internal/keyring"
	"github.com/Nikolay1994Kaz/evidencestore/internal/proof"
)

// Ключ меток выведен из ключа месяца (DECISIONS, п. 32): уничтожен ключ месяца —
// метки месяца не посчитает никто, и записи клиента после стирания к нему не
// привести.

// destroyMonth уничтожает ключ месяца насовсем: заявка двоих, срок ожидания по
// часам теста, затем CompleteDue.
func destroyMonth(t *testing.T, s *Store, c *clock, scope string) {
	t.Helper()
	ctx := context.Background()
	if err := s.Deactivate(true, scope); err != nil {
		t.Fatal(err)
	}
	if _, err := s.ScheduleDestroy(ctx, scope, time.Nanosecond, []keyring.Approval{{Who: "operator"}, {Who: "security"}}); err != nil {
		t.Fatal(err)
	}
	c.add(time.Hour)
	if _, err := s.CompleteDue(ctx); err != nil {
		t.Fatal(err)
	}
	if ki, _ := s.keyInfo(scope); ki.State != keyring.Destroyed {
		t.Fatalf("ключ %s не уничтожен: %v", scope, ki.State)
	}
}

// ⭐ Стирание стирает и метки. До правки ключ меток шёл из sign.key, жил вместе с
// цепью, и после уничтожения ключа месяца хранилище по номеру клиента находило
// все его записи: когда, сколько и какой длины.
func TestSubjectLabelDiesWithMonthKey(t *testing.T) {
	s, c, cfg := subjectStore(t)
	scope := "agent/2026-09"
	before := labelOf(t, s, "a")
	destroyMonth(t, s, c, scope)

	// Ключа меток месяца больше нет: метку не посчитать ни для кого.
	if _, err := s.keys.DeriveKey(scope, subjectKeyDomain); !errors.Is(err, keyring.ErrKeyDestroyed) {
		t.Fatalf("ключ меток после уничтожения: %v", err)
	}
	for _, who := range []string{"a", "b", "nobody"} {
		if _, ok, err := s.subjectLabel(scope, "agent", "client", who); ok || err != nil {
			t.Fatalf("метка %q после уничтожения: %v, %v", who, ok, err)
		}
	}

	// Пакет по клиенту a за окно стёртого месяца: меток в заявлении нет, ключей
	// нет, записи с меткой ничьи; пакет честный и проходит.
	from, to := clockAt(10, 1, 0), clockAt(10, 7, 30)
	check := func(s *Store) {
		t.Helper()
		b, err := s.ProofSubject("agent", "a", from, to, 0)
		if err != nil {
			t.Fatal(err)
		}
		if len(b.Subject.Labels) != 0 {
			t.Fatalf("метка стёртого месяца в пакете: %+v", b.Subject.Labels)
		}
		for _, rec := range b.Records {
			if len(rec.DEK) > 0 {
				t.Fatal("ключ записи стёртого месяца")
			}
		}
		r := proof.VerifySource(sourceRoundTrip(t, b), trustOf(t, s), time.Time{}, time.Time{})
		// Окно 10:01–10:07:30: записи 2, 3 (a), 4 (b) с меткой, 5, 6 без.
		if !r.Valid() || r.SubjectRecords != 0 || r.SubjectNoLabel != 3 || r.SubjectUnlabeled != 2 || len(r.Bodies) != 0 ||
			!slices.Equal(r.SubjectNoLabelMonths, []string{scope}) {
			t.Fatalf("пакет стёртого месяца:\n%s", r.Text())
		}
		if !strings.Contains(r.Text(), "lie in months the bundle names no label for (\"agent/2026-09\")") ||
			!strings.Contains(r.Text(), "0 records under the label, the other 5 of the 5 in the window stay closed") {
			t.Fatalf("отчёт молчит, почему записи ничьи:\n%s", r.Text())
		}
	}
	check(s)

	// Метка в заголовке записи осталась (она под отпечатком), но сравнить её не с
	// чем: прежняя метка a больше не выводится ниоткуда.
	pos := s.sources["agent"].seqs.get(3)
	data, err := s.evlog.Read(pos)
	if err != nil {
		t.Fatal(err)
	}
	sealed, err := evidence.Unmarshal(data)
	if err != nil || sealed.Subject != before {
		t.Fatalf("метка в записи: %v", err)
	}

	// После перезапуска так же: состояние ключа в keyring.dat.
	s.Close()
	again, err := reopen(cfg, c)
	if err != nil {
		t.Fatal(err)
	}
	defer again.Close()
	if _, ok, err := again.subjectLabel(scope, "agent", "client", "a"); ok || err != nil {
		t.Fatalf("метка после перезапуска: %v, %v", ok, err)
	}
	check(again)
}

// Метки свои у каждого месяца: записи клиента в сентябре и октябре разными
// метками не связать. Пакет через границу месяцев несёт метку на месяц и
// открывает записи обоих; стёрт сентябрь — открыт только октябрь.
// monthStore — окно через полночь 30.09 → 01.10:
//
//	23:50 запись 1 (a), метка: нижний край
//	23:55 записи 2 (a), 3 (b) — сентябрь
//	00:05 записи 4 (a), 5 (b) — октябрь
//	00:10 метка и сразу за ней ещё одна: верхний край
func monthStore(t *testing.T) (s *Store, c *clock, from, to time.Time) {
	t.Helper()
	c = newClock()
	c.set(time.Date(2026, 9, 30, 23, 50, 0, 0, time.UTC))
	s = openStore(t, testConfig(t, withSubjects), c)
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
	c.add(10 * time.Minute) // 00:05, октябрь
	in(4, subjectLine("a", "октябрь"))
	in(5, subjectLine("b", "чужой диалог в октябре"))
	c.add(5 * time.Minute)
	mustStamp(t, s)
	mustStampNow(t, s)
	return s, c, time.Date(2026, 9, 30, 23, 54, 0, 0, time.UTC), time.Date(2026, 10, 1, 0, 6, 0, 0, time.UTC)
}

func TestSubjectLabelsPerMonth(t *testing.T) {
	s, c, from, to := monthStore(t)
	trust := trustOf(t, s)

	sep, ok, err := s.subjectLabel("agent/2026-09", "agent", "client", "a")
	if err != nil || !ok {
		t.Fatal(err)
	}
	oct, ok, err := s.subjectLabel("agent/2026-10", "agent", "client", "a")
	if err != nil || !ok || sep == oct {
		t.Fatalf("метки a в двух месяцах: %x %x, %v", sep, oct, err)
	}

	b, err := s.ProofSubject("agent", "a", from, to, 0)
	if err != nil {
		t.Fatal(err)
	}
	want := []proof.SubjectLabel{{Scope: "agent/2026-09", Tag: sep[:]}, {Scope: "agent/2026-10", Tag: oct[:]}}
	if !slices.EqualFunc(b.Subject.Labels, want, func(x, y proof.SubjectLabel) bool { return x.Scope == y.Scope && string(x.Tag) == string(y.Tag) }) {
		t.Fatalf("метки в заявлении: %+v", b.Subject.Labels)
	}
	r := proof.VerifySource(sourceRoundTrip(t, b), trust, time.Time{}, time.Time{})
	if !r.Valid() || !slices.Equal(bodySeqs(r.Bodies), []uint64{2, 4}) || r.SubjectRecords != 2 || r.SubjectOthers != 2 {
		t.Fatalf("два месяца:\n%s", r.Text())
	}

	// Метки месяцев переставлены: октябрьская запись сверяется с меткой своего
	// месяца из заголовка, а не из заявления, и её ключ — отказ.
	f := sourceRoundTrip(t, b)
	f.Subject.Labels[0].Tag, f.Subject.Labels[1].Tag = f.Subject.Labels[1].Tag, f.Subject.Labels[0].Tag
	sourceFailed(t, proof.VerifySource(sourceRoundTrip(t, f), trust, time.Time{}, time.Time{}), "record keys come only with")

	// Сентябрь стёрт: метка только у октября, сентябрьские записи ничьи.
	destroyMonth(t, s, c, "agent/2026-09")
	b, err = s.ProofSubject("agent", "a", from, to, 0)
	if err != nil {
		t.Fatal(err)
	}
	if len(b.Subject.Labels) != 1 || b.Subject.Labels[0].Scope != "agent/2026-10" {
		t.Fatalf("метки после стирания сентября: %+v", b.Subject.Labels)
	}
	r = proof.VerifySource(sourceRoundTrip(t, b), trust, time.Time{}, time.Time{})
	if !r.Valid() || !slices.Equal(bodySeqs(r.Bodies), []uint64{4}) || r.SubjectRecords != 1 || r.SubjectNoLabel != 2 || r.SubjectOthers != 1 ||
		!slices.Equal(r.SubjectNoLabelMonths, []string{"agent/2026-09"}) {
		t.Fatalf("после стирания сентября:\n%s", r.Text())
	}
}

// Подделка 1 (замечания 08.11): тело открыто в сентябре, а метку октября пакет
// заменил чужой (её видно в заголовке записи 5 того же пакета) и снял ключи
// октября. Сентябрьское тело не привязывает октябрьскую метку: записи под ней —
// не записи субъекта.
func TestSubjectMonthLabelNeedsItsOwnBody(t *testing.T) {
	s, _, from, to := monthStore(t)
	b, err := s.ProofSubject("agent", "a", from, to, 0)
	if err != nil {
		t.Fatal(err)
	}
	f := sourceRoundTrip(t, b)
	var other []byte
	for i := range f.Records {
		if len(f.Records[i].Evidence) == 0 {
			continue
		}
		sealed, _ := evidence.Unmarshal(f.Records[i].Evidence)
		if sealed.Scope() == "agent/2026-10" {
			f.Records[i].DEK = nil
			if sealed.Seq == 5 {
				other = sealed.Subject[:]
			}
		}
	}
	f.Subject.Labels[1].Tag = other
	r := proof.VerifySource(sourceRoundTrip(t, f), trustOf(t, s), time.Time{}, time.Time{})
	// Подпись и цепь целы, так что пакет проходит; но записью a названа только
	// сентябрьская запись 2, а запись 5 под подменённой меткой — непривязанная.
	if !r.Valid() || r.SubjectRecords != 1 || r.SubjectOpened != 1 || r.SubjectUnbound != 1 ||
		!slices.Equal(r.SubjectUnboundMonths, []string{"agent/2026-10"}) {
		t.Fatalf("записи b в октябре названы записями a: под меткой %d, не привязано %d\n%s", r.SubjectRecords, r.SubjectUnbound, r.Text())
	}
	for _, want := range []string{
		`1 of the 4 records received in the window, 1 of them open, the other 3 stay closed`,
		`1 records lie under the labels the bundle names for "agent/2026-10", and no body of those months is open`,
		`nothing here says these records are "a"'s`,
	} {
		if !strings.Contains(r.Text(), want) {
			t.Fatalf("в отчёте нет %q:\n%s", want, r.Text())
		}
	}
}

// Подделка 2: метка сентября убрана из заявления, ключи сентября сняты. Пакет
// не доказывает, что ключ уничтожен, и отчёт не вправе так говорить.
func TestSubjectMissingLabelIsNotProofOfErasure(t *testing.T) {
	s, _, from, to := monthStore(t)
	b, err := s.ProofSubject("agent", "a", from, to, 0)
	if err != nil {
		t.Fatal(err)
	}
	f := sourceRoundTrip(t, b)
	for i := range f.Records {
		if len(f.Records[i].Evidence) > 0 {
			if sealed, _ := evidence.Unmarshal(f.Records[i].Evidence); sealed.Scope() == "agent/2026-09" {
				f.Records[i].DEK = nil
			}
		}
	}
	f.Subject.Labels = f.Subject.Labels[1:]
	r := proof.VerifySource(sourceRoundTrip(t, f), trustOf(t, s), time.Time{}, time.Time{})
	text := r.Text()
	if !r.Valid() || r.SubjectNoLabel != 2 || r.SubjectRecords != 1 ||
		!strings.Contains(text, `2 records received in the window lie in months the bundle names no label for ("agent/2026-09")`) ||
		!strings.Contains(text, "the bundle is not signed and does not show that: anyone can take a label out of it") ||
		strings.Contains(text, "no one can compute the label, the store included") {
		t.Fatalf("отчёт выдаёт отсутствие метки за доказанное стирание:\n%s", text)
	}
}
