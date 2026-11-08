package store

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/Nikolay1994Kaz/evidencestore/internal/config"
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
			// Стёртый месяц — листом: ни улики (метки и длины), ни ключа (P-77).
			if len(rec.DEK) > 0 || len(rec.Evidence) > 0 {
				t.Fatal("улика или ключ записи стёртого месяца")
			}
		}
		r := proof.VerifySource(sourceRoundTrip(t, b), trustOf(t, s), time.Time{}, time.Time{})
		// Окно 10:01–10:07:30: записи 2–6 листом, чьи они — не видно, есть ли у
		// них метка — тоже.
		if !r.Valid() || r.SubjectRecords != 0 || r.SubjectNoLabel != 5 || r.SubjectUnlabeled != 0 || len(r.Bodies) != 0 ||
			!slices.Equal(r.SubjectNoLabelMonths, []string{scope}) {
			t.Fatalf("пакет стёртого месяца:\n%s", r.Text())
		}
		if !strings.Contains(r.Text(), "lie in months the bundle names no label for (\"agent/2026-09\")") ||
			!strings.Contains(r.Text(), "0 records under the label, the other 5 of the 5 in the window stay closed") ||
			!strings.Contains(r.Text(), "5 records received in the window come without their evidence: they lie in months the bundle names no label for") {
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
		`1 of the 4 records received in the window, 1 of them open, 1 more under its label in months where none of its bodies opens, the other 2 stay closed; no body of the subject is open in "agent/2026-10"`,
		`no body of "a" is open in "agent/2026-10"`,
		`1 records lie under the labels the bundle names for "agent/2026-10", and nothing here says they are "a"'s`,
		`1 records of the subject, 1 of them open, 1 more under its label in months where none of its bodies opens, 2 others closed`,
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
		!strings.Contains(text, "the bundle is not signed and does not show which, or whether a label was just taken out of it") ||
		!strings.Contains(text, `no body of "a" is open in "agent/2026-09"`) ||
		strings.Contains(text, "no one can compute the label, the store included") {
		t.Fatalf("отчёт выдаёт отсутствие метки за доказанное стирание:\n%s", text)
	}
}

// P-76: data_dir сборки 07.11 (записи версии 2, метки из sign.key) этот выпуск
// не поднимает: иначе записи клиента молча ушли бы в «чужие». Отказ называет
// причину.
func TestSignKeyLabelsStopStart(t *testing.T) {
	s, _, cfg := subjectStore(t)
	s.Close()
	patchRecord(t, cfg, "agent", 3, func(rec []byte) { rec[0] = 2 }) // так лежит запись сборки 07.11
	_, err := reopen(cfg, newClock())
	if !errors.Is(err, evidence.ErrSignKeyLabels) || !strings.Contains(err.Error(), "does not carry over") {
		t.Fatalf("запуск на записях версии 2: %v", err)
	}
}

// ⭐ P-75 (К1): метку октября заменили такой, что не совпадёт ни с одной
// записью, — случайными байтами, меткой a соседнего месяца, меткой из чужого
// пакета, — и сняли ключи октября. Цепь и подпись целы, пакет проходит; запись
// a за октябрь стоит среди чужих. Отчёт обязан назвать октябрь месяцем без
// открытого тела a — и тогда, когда пакет честный и у a в октябре записей нет.
func TestSubjectMonthWithoutOpenBodyIsNamed(t *testing.T) {
	s, _, from, to := monthStore(t)
	trust := trustOf(t, s)
	b, err := s.ProofSubject("agent", "a", from, to, 0)
	if err != nil {
		t.Fatal(err)
	}
	nobody, err := s.ProofSubject("agent", "nobody", from, to, 0)
	if err != nil {
		t.Fatal(err)
	}
	sepOfA := b.Subject.Labels[0].Tag
	octOfNobody := nobody.Subject.Labels[1].Tag
	const oct = `"agent/2026-10"`
	for name, tag := range map[string][]byte{
		"случайные байты":        []byte("0123456789abcdef"),
		"метка соседнего месяца": sepOfA,
		"метка из чужого пакета": octOfNobody,
	} {
		f := sourceRoundTrip(t, b)
		f.Subject.Labels[1].Tag = tag
		for i := range f.Records {
			if len(f.Records[i].Evidence) > 0 {
				if sealed, _ := evidence.Unmarshal(f.Records[i].Evidence); sealed.Scope() == "agent/2026-10" {
					f.Records[i].DEK = nil
				}
			}
		}
		r := proof.VerifySource(sourceRoundTrip(t, f), trust, time.Time{}, time.Time{})
		text := r.Text()
		if !r.Valid() || r.SubjectRecords != 1 || !slices.Equal(r.SubjectUnconfirmedMonths, []string{"agent/2026-10"}) ||
			!strings.Contains(text, `no body of the subject is open in `+oct+`, and its records there are not shown`) ||
			!strings.Contains(text, `no body of "a" is open in `+oct) || !strings.Contains(text, "nothing here shows that it has none there") {
			t.Fatalf("%s: октябрь не назван месяцем без открытого тела:\n%s", name, text)
		}
	}

	// Честный пакет без записей a в октябре говорит то же: отличить его от
	// подделки нельзя, поэтому оговорка — про каждый такой месяц.
	c := newClock()
	c.set(time.Date(2026, 9, 30, 23, 50, 0, 0, time.UTC))
	s2 := openStore(t, testConfig(t, withSubjects), c)
	in := func(seq uint64, body []byte) {
		t.Helper()
		if _, err := s2.Ingest("agent", []Incoming{{Seq: seq, Body: body}}); err != nil {
			t.Fatal(err)
		}
	}
	in(1, subjectLine("a", "до окна"))
	mustStamp(t, s2)
	c.add(5 * time.Minute)
	in(2, subjectLine("a", "сентябрь"))
	c.add(10 * time.Minute)
	in(3, subjectLine("b", "октябрь, только b"))
	c.add(5 * time.Minute)
	mustStamp(t, s2)
	mustStampNow(t, s2)
	h, err := s2.ProofSubject("agent", "a", from, to, 0)
	if err != nil {
		t.Fatal(err)
	}
	r := proof.VerifySource(sourceRoundTrip(t, h), trustOf(t, s2), time.Time{}, time.Time{})
	if !r.Valid() || !slices.Equal(r.SubjectUnconfirmedMonths, []string{"agent/2026-10"}) ||
		!strings.Contains(r.Text(), `no body of the subject is open in `+oct) {
		t.Fatalf("честный пакет без записей a в октябре:\n%s", r.Text())
	}
}

// P-77 (С5): метка a за сентябрь, выданная до стирания, после стирания ни с чем
// не сопоставляется в пакетах по субъекту: записи стёртого месяца идут листом,
// без заголовков. В пакете -source -dek заголовки остаются (docs/bundles.md).
func TestIssuedLabelFindsNothingAfterErasure(t *testing.T) {
	s, c, _ := subjectStore(t)
	from, to := clockAt(10, 1, 0), clockAt(10, 7, 30)
	early, err := s.ProofSubject("agent", "a", from, to, 0)
	if err != nil {
		t.Fatal(err)
	}
	issued := early.Subject.Labels[0].Tag // аудитор сохранил метку a
	destroyMonth(t, s, c, "agent/2026-09")
	matches := func(b proof.SourceBundle) int {
		n := 0
		for _, rec := range b.Records {
			if len(rec.Evidence) == 0 {
				continue
			}
			if sealed, _ := evidence.Unmarshal(rec.Evidence); string(sealed.Subject[:]) == string(issued) {
				n++
			}
		}
		return n
	}
	for _, who := range []string{"a", "b", "nobody"} {
		later, err := s.ProofSubject("agent", who, from, to, 0)
		if err != nil {
			t.Fatal(err)
		}
		if n := matches(later); n != 0 {
			t.Fatalf("пакет по %q после стирания: выданная метка a нашла %d записей", who, n)
		}
	}
	dek, err := s.ProofSource("agent", from, to, true, 0)
	if err != nil {
		t.Fatal(err)
	}
	if matches(dek) != 2 {
		t.Fatal("пакет -source -dek: предел в docs/bundles.md описан не так, как есть")
	}
}

// Мелко (замечания 08.11): закрытый текущий месяц отвечает тем же отказом,
// что у источника без метки (ErrScopeClosed — 409), а не 503 с ERROR в журнале.
func TestClosedMonthRefusesLabelledIntakeLikeUnlabelled(t *testing.T) {
	s, _, _ := subjectStore(t)
	ingest(t, s, "abs-core", 1, 1)
	for _, scope := range []string{"agent/2026-09", "abs-core/2026-09"} {
		if err := s.Deactivate(true, scope); err != nil {
			t.Fatal(err)
		}
	}
	try := func(stage string, seq uint64) {
		t.Helper()
		_, labelled := s.Ingest("agent", []Incoming{{Seq: seq, Body: subjectLine("a", stage)}})
		_, plain := s.Ingest("abs-core", []Incoming{{Seq: seq, Body: []byte(stage)}})
		if !errors.Is(labelled, keyring.ErrScopeClosed) || !errors.Is(plain, keyring.ErrScopeClosed) {
			t.Fatalf("%s: с меткой %v, без метки %v", stage, labelled, plain)
		}
	}
	try("закрыт для записи", 10)
	// Ждёт уничтожения: ключ меток не выводится — раньше это давало 503.
	for _, scope := range []string{"agent/2026-09", "abs-core/2026-09"} {
		if _, err := s.ScheduleDestroy(context.Background(), scope, time.Hour, []keyring.Approval{{Who: "operator"}, {Who: "security"}}); err != nil {
			t.Fatal(err)
		}
	}
	try("ждёт уничтожения", 11)
}

// Мелко (замечания 08.11): перезапуск при отстающем резерве. Пакет по субъекту
// за прошлые записи читается, как -source -dek; приём источника с меткой ведёт
// себя так же, как у того же источника без subject_field.
func TestBackupDownDoesNotBlockSubjectBundles(t *testing.T) {
	run := func(label bool) (ingestErr, subjectErr error) {
		c := newClock()
		backupDir := t.TempDir()
		cfg := testConfig(t, func(cfg *config.Config) {
			src := config.Source{Name: "agent", ContentType: "application/json"}
			if label {
				src.SubjectField = "client"
			}
			cfg.Sources = append(cfg.Sources, src)
			cfg.Keys.BackupDir = backupDir
		})
		s := openStore(t, cfg, c)
		if _, err := s.Ingest("agent", []Incoming{{Seq: 1, Body: subjectLine("a", "до окна")}}); err != nil {
			t.Fatal(err)
		}
		mustStamp(t, s)
		c.add(5 * time.Minute)
		if _, err := s.Ingest("agent", []Incoming{{Seq: 2, Body: subjectLine("a", "в окне")}}); err != nil {
			t.Fatal(err)
		}
		c.add(5 * time.Minute)
		mustStamp(t, s)
		mustStampNow(t, s)
		s.Close()
		if err := os.Chmod(backupDir, 0o500); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { os.Chmod(backupDir, 0o700) })
		again, err := reopen(cfg, c)
		if err != nil {
			t.Fatal(err)
		}
		defer again.Close()
		if probe := filepath.Join(backupDir, "probe"); os.WriteFile(probe, nil, 0o600) == nil {
			os.Remove(probe)
			t.Skip("резерв пишется и без прав на запись: тест запущен от root")
		}
		_, ingestErr = again.Ingest("agent", []Incoming{{Seq: 3, Body: subjectLine("a", "после перезапуска")}})
		if label {
			b, err := again.ProofSubject("agent", "a", clockAt(10, 4, 0), clockAt(10, 6, 0), 0)
			if err == nil {
				if r := proof.VerifySource(sourceRoundTrip(t, b), trustOf(t, again), time.Time{}, time.Time{}); !r.Valid() || len(r.Bodies) != 1 {
					err = errors.New(r.Text())
				}
			}
			subjectErr = err
		}
		return ingestErr, subjectErr
	}
	plainErr, _ := run(false)
	labelErr, subjectErr := run(true)
	if subjectErr != nil {
		t.Fatalf("пакет по субъекту при отстающем резерве: %v", subjectErr)
	}
	// Сравнивается вид отказа, а не текст: в тексте — пути временных каталогов.
	kind := func(err error) string {
		switch {
		case err == nil:
			return "принято"
		case errors.Is(err, keyring.ErrBackupPending):
			return "резерв"
		case errors.Is(err, keyring.ErrNotBackedUp):
			return "ключ не в резерве"
		}
		return err.Error()
	}
	if kind(labelErr) != kind(plainErr) {
		t.Fatalf("приём с меткой и без расходится: %v / %v", labelErr, plainErr)
	}
}
