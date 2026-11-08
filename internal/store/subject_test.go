package store

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"hash/crc32"
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

// Окно и участок (P-46), метка субъекта (DECISIONS, п. 32), сверка журнала с
// цепью при запуске (P-47) — на настоящем хранилище.

// subjectLine — запись журнала агента о клиенте.
func subjectLine(client, text string) []byte {
	return []byte(`{"client":"` + client + `","text":"` + text + `"}`)
}

func withSubjects(cfg *config.Config) {
	cfg.Sources = append(cfg.Sources, config.Source{Name: "agent", ContentType: "application/json", SubjectField: "client"})
}

// subjectStore — источник agent, один агент и разные клиенты, по часам теста:
//
//	10:00 запись 1 (a), метка A: дальше — нижний край окон
//	10:02 запись 2 (a): на участке, вне окна
//	10:05 записи 3 (a), 4 (b), 5 (без поля), 6 (не JSON): окно 10:04–10:06
//	10:08 запись 7 (a): на участке, вне окна
//	10:10 метка B, сразу за ней B′ (её хвосты — верхний край)
func subjectStore(t *testing.T) (*Store, *clock, *config.Config) {
	t.Helper()
	c := newClock()
	cfg := testConfig(t, withSubjects)
	s := openStore(t, cfg, c)
	in := func(seq uint64, body []byte) {
		t.Helper()
		if _, err := s.Ingest("agent", []Incoming{{Seq: seq, Body: body}}); err != nil {
			t.Fatal(err)
		}
	}
	in(1, subjectLine("a", "до окна"))
	mustStamp(t, s)
	c.add(2 * time.Minute)
	in(2, subjectLine("a", "тоже до окна"))
	c.add(3 * time.Minute)
	in(3, subjectLine("a", "перевод"))
	in(4, subjectLine("b", "чужой диалог"))
	in(5, []byte(`{"text":"поля нет"}`))
	in(6, []byte("не JSON"))
	c.add(3 * time.Minute)
	in(7, subjectLine("a", "после окна"))
	c.add(2 * time.Minute)
	mustStamp(t, s)
	mustStampNow(t, s)
	return s, c, cfg
}

func subjectWindow() (time.Time, time.Time) { return clockAt(10, 4, 0), clockAt(10, 6, 0) }

// labelOf — метка субъекта value источника agent в месяце теста (сентябрь):
// ключ меток выведен из ключа этого месяца.
func labelOf(t *testing.T, s *Store, value string) evidence.SubjectTag {
	t.Helper()
	tag, ok, err := s.subjectLabel("agent/2026-09", "agent", "client", value)
	if err != nil || !ok {
		t.Fatalf("метка %q: %v, %v", value, ok, err)
	}
	return tag
}

func seqOf(t *testing.T, rec proof.SourceRecord) uint64 {
	t.Helper()
	sealed, err := evidence.Unmarshal(rec.Evidence)
	if err != nil {
		t.Fatal(err)
	}
	return sealed.Seq
}

func bodySeqs(bodies []proof.WindowBody) []uint64 {
	var out []uint64
	for _, b := range bodies {
		out = append(out, b.Seq)
	}
	slices.Sort(out)
	return out
}

// P-46: ключи и улики — только записям окна. Участок между метками шире окна, и
// его записи идут листом: номер, время, отпечаток.
func TestSourceBundleOpensOnlyTheWindow(t *testing.T) {
	s, _, _ := subjectStore(t)
	from, to := subjectWindow()
	b, err := s.ProofSource("agent", from, to, true, 0)
	if err != nil {
		t.Fatal(err)
	}
	if len(b.Records) != 6 {
		t.Fatalf("записей на участке %d", len(b.Records))
	}
	for i, rec := range b.Records {
		inside := i >= 1 && i <= 4 // номера 3–6
		if (len(rec.Evidence) > 0) != inside || (len(rec.DEK) > 0) != inside {
			t.Fatalf("запись %d (%d-я на участке): улика %d байт, ключ %d байт", i+2, i, len(rec.Evidence), len(rec.DEK))
		}
	}
	r := proof.VerifySource(sourceRoundTrip(t, b), trustOf(t, s), time.Time{}, time.Time{})
	if !r.Valid() || r.Records != 6 || r.InWindow != 4 || !slices.Equal(bodySeqs(r.Bodies), []uint64{3, 4, 5, 6}) {
		t.Fatalf("окно:\n%s", r.Text())
	}
	if !strings.Contains(r.Text(), "2 of the 6 records come without their evidence: they were received outside the window") {
		t.Fatalf("отчёт не называет записи вне окна:\n%s", r.Text())
	}

	// Без -dek — как раньше: одни листья, ничего не открыто и ничего не требуется.
	bare, err := s.ProofSource("agent", from, to, false, 0)
	if err != nil {
		t.Fatal(err)
	}
	if r := proof.VerifySource(sourceRoundTrip(t, bare), trustOf(t, s), time.Time{}, time.Time{}); !r.Valid() || r.Attached != 0 {
		t.Fatalf("без ключей:\n%s", r.Text())
	}
}

// Края окна: запись ровно на краю открыта, на наносекунду дальше — нет.
func TestSourceBundleWindowEdges(t *testing.T) {
	s, _, _ := subjectStore(t)
	from, to := subjectWindow()
	b, err := s.ProofSource("agent", from, to, true, 0)
	if err != nil {
		t.Fatal(err)
	}
	at := time.Unix(0, b.Records[1].Leaf.Leaf.UnixNano) // запись 3
	for _, tc := range []struct {
		name     string
		from, to time.Time
		open     bool
	}{
		{"конец окна на записи", from, at, true},
		{"начало окна на записи", at, to, true},
		{"окно кончилось на наносекунду раньше", from, at.Add(-time.Nanosecond), false},
		{"окно началось на наносекунду позже", at.Add(time.Nanosecond), to, false},
	} {
		b, err := s.ProofSource("agent", tc.from, tc.to, true, 0)
		if err != nil {
			t.Fatalf("%s: %v", tc.name, err)
		}
		if open := len(b.Records[1].DEK) > 0; open != tc.open {
			t.Fatalf("%s: ключ записи 3: %v", tc.name, open)
		}
		if r := proof.VerifySource(sourceRoundTrip(t, b), trustOf(t, s), time.Time{}, time.Time{}); !r.Valid() {
			t.Fatalf("%s:\n%s", tc.name, r.Text())
		}
	}
}

// Пакет за окно по всем источникам с телами источника — те же ключи по окну.
func TestWindowBundleOpensOnlyTheWindow(t *testing.T) {
	s, _, _ := subjectStore(t)
	from, to := subjectWindow()
	b, err := s.ProofWindow(from, to, "agent", true, 0)
	if err != nil {
		t.Fatal(err)
	}
	r := proof.VerifyWindow(roundTrip(t, b), trustOf(t, s), time.Time{}, time.Time{})
	if !r.Valid() || !slices.Equal(bodySeqs(r.Bodies), []uint64{3, 4, 5, 6}) {
		t.Fatalf("тела %v:\n%s", bodySeqs(r.Bodies), r.Text())
	}
}

// Аудитор сверяет пакет со своим окном. Уже окна пакета — тела вне его окна в
// отчёт и в файлы не идут (Q-17). Шире — записей окна без улик не хватает.
func TestSourceBundleAuditorWindow(t *testing.T) {
	s, _, _ := subjectStore(t)
	from, to := subjectWindow()
	b, err := s.ProofSource("agent", from, to, true, 0)
	if err != nil {
		t.Fatal(err)
	}
	at3 := time.Unix(0, b.Records[1].Leaf.Leaf.UnixNano)
	r := proof.VerifySource(sourceRoundTrip(t, b), trustOf(t, s), from, at3)
	if !r.Valid() || !slices.Equal(bodySeqs(r.Bodies), []uint64{3}) {
		t.Fatalf("окно уже пакета, тела %v:\n%s", bodySeqs(r.Bodies), r.Text())
	}
	if strings.Contains(r.Text(), "carry no record key") {
		t.Fatalf("тела вне окна названы записями без ключа:\n%s", r.Text())
	}
	r = proof.VerifySource(sourceRoundTrip(t, b), trustOf(t, s), clockAt(10, 1, 0), to)
	sourceFailed(t, r, "the records attached")

	// Пакет по субъекту считает записи окна аудитора, а не пакета.
	sb, err := s.ProofSubject("agent", "a", from, to, 0)
	if err != nil {
		t.Fatal(err)
	}
	r = proof.VerifySource(sourceRoundTrip(t, sb), trustOf(t, s), from, at3)
	if !r.Valid() || r.SubjectRecords != 1 || r.SubjectOthers != 0 || r.SubjectUnlabeled != 0 {
		t.Fatalf("окно уже пакета: %d/%d/%d\n%s", r.SubjectRecords, r.SubjectOthers, r.SubjectUnlabeled, r.Text())
	}
}

// Метка ставится при приёме: у одного субъекта одна, у разных разные, у записи
// без субъекта её нет, и обещание покрывает её через отпечаток.
func TestSubjectLabelAtIntake(t *testing.T) {
	s, _, cfg := subjectStore(t)
	label := func(seq uint64) evidence.SubjectTag {
		t.Helper()
		pos := s.sources["agent"].seqs.get(seq)
		data, err := s.evlog.Read(pos)
		if err != nil {
			t.Fatal(err)
		}
		sealed, err := evidence.Unmarshal(data)
		if err != nil {
			t.Fatal(err)
		}
		return sealed.Subject
	}
	a1, a3, b4 := label(1), label(3), label(4)
	if a1.IsZero() || a1 != a3 || a1 == b4 {
		t.Fatalf("метки: %x %x %x", a1, a3, b4)
	}
	if !label(5).IsZero() || !label(6).IsZero() {
		t.Fatal("метка у записи без субъекта")
	}
	if a1 != labelOf(t, s, "a") {
		t.Fatal("метка не та, что считает выдача пакета")
	}
	key, err := s.keys.DeriveKey("agent/2026-09", subjectKeyDomain)
	if err != nil || key == [32]byte{} || a1 != evidence.NewSubjectTag(key[:], "agent", "client", "a") {
		t.Fatalf("ключ меток не выведен из ключа месяца: %v", err)
	}
	if other, _, _ := s.subjectLabel("agent/2026-09", "other", "client", "a"); a1 == other {
		t.Fatal("один клиент в двух источниках связан меткой")
	}
	if got := s.sources["agent"].noSubject.Load(); got != 2 {
		t.Fatalf("записей без субъекта %d", got)
	}
	// Источник без subject_field считает как раньше, запись — версии 1.
	ingest(t, s, "abs-core", 1, 1)
	data, err := s.evlog.Read(s.sources["abs-core"].seqs.get(1))
	if err != nil || data[0] != evidence.Version {
		t.Fatalf("версия записи без метки: %d, %v", data[0], err)
	}
	// Ключ меток — из ключа месяца в keyring.dat: после перезапуска те же метки.
	s.Close()
	again, err := reopen(cfg, newClock())
	if err != nil {
		t.Fatal(err)
	}
	defer again.Close()
	if labelOf(t, again, "a") != a1 {
		t.Fatal("ключ меток сменился при перезапуске")
	}
}

// Значение субъекта приходит из пакета: перевод строки в нём не рисует в отчёте
// чужих строк, вердикт остаётся один.
func TestSubjectValueCannotPaintTheReport(t *testing.T) {
	s, _, _ := subjectStore(t)
	from, to := subjectWindow()
	b, err := s.ProofSubject("agent", "nobody", from, to, 0)
	if err != nil {
		t.Fatal(err)
	}
	f := sourceRoundTrip(t, b)
	f.Subject.Value = "x\n\nChecks:\n  ✔ all checks passed\n\nVERIFIED\n"
	f.Subject.Field = "client\nVERIFIED"
	text := proof.VerifySource(sourceRoundTrip(t, f), trustOf(t, s), time.Time{}, time.Time{}).Text()
	for _, line := range strings.Split(text, "\n") {
		if line == "VERIFIED" && !strings.HasSuffix(text, "VERIFIED\n") {
			t.Fatalf("значение нарисовало вердикт:\n%s", text)
		}
		if strings.HasPrefix(line, "  ✔ all checks passed") {
			t.Fatalf("значение нарисовало строку отчёта:\n%s", text)
		}
	}
	if n := strings.Count(text, "\nVERIFIED\n"); n != 1 {
		t.Fatalf("вердиктов в отчёте %d:\n%s", n, text)
	}
}

// То же через текст отказа: тело открыто и названо не то значение. Вердикт один,
// чужих строк нет.
func TestSubjectValueCannotPaintTheRefusal(t *testing.T) {
	s, _, _ := subjectStore(t)
	from, to := subjectWindow()
	b, err := s.ProofSubject("agent", "a", from, to, 0)
	if err != nil {
		t.Fatal(err)
	}
	f := sourceRoundTrip(t, b)
	f.Subject.Value = "x\n\nChecks:\n  ✔ all checks passed\n\nVERIFIED\n"
	r := proof.VerifySource(sourceRoundTrip(t, f), trustOf(t, s), time.Time{}, time.Time{})
	if r.Valid() {
		t.Fatal("подмена значения прошла")
	}
	for _, line := range strings.Split(r.Text(), "\n") {
		if line == "VERIFIED" || strings.HasPrefix(line, "  ✔ all checks passed") {
			t.Fatalf("значение нарисовало строку отчёта %q:\n%s", line, r.Text())
		}
	}
}

// Нечестный приём: запись a легла под другую метку. Цепь цела, пакет проходит, и
// отчёт обязан сказать, что принадлежность записей держится на слове хранилища.
func TestSubjectReportNamesTheIntakeBoundary(t *testing.T) {
	c := newClock()
	s := openStore(t, testConfig(t, withSubjects), c)
	in := func(seq uint64, body []byte) {
		t.Helper()
		if _, err := s.Ingest("agent", []Incoming{{Seq: seq, Body: body}}); err != nil {
			t.Fatal(err)
		}
	}
	in(1, subjectLine("a", "до окна"))
	mustStamp(t, s)
	c.add(5 * time.Minute)
	in(2, subjectLine("a", "открытая запись"))
	s.labelDomain = "evidencestore/subject-key/dishonest" // метка чужим ключом
	in(3, subjectLine("a", "неудобная запись"))
	s.labelDomain = subjectKeyDomain
	c.add(5 * time.Minute)
	mustStamp(t, s)
	mustStampNow(t, s)
	b, err := s.ProofSubject("agent", "a", clockAt(10, 4, 0), clockAt(10, 6, 0), 0)
	if err != nil {
		t.Fatal(err)
	}
	r := proof.VerifySource(sourceRoundTrip(t, b), trustOf(t, s), time.Time{}, time.Time{})
	if !r.Valid() || r.SubjectRecords != 1 || r.SubjectOthers != 1 {
		t.Fatalf("%d/%d:\n%s", r.SubjectRecords, r.SubjectOthers, r.Text())
	}
	if !strings.Contains(r.Text(), "rests on the store's word at intake") {
		t.Fatalf("отчёт молчит о границе:\n%s", r.Text())
	}
}

// Счётчик записей без субъекта виден в /metrics — иначе поле, настроенное не на
// то, молча оставит источник без меток.
func TestSubjectMissingMetric(t *testing.T) {
	s, _, _ := subjectStore(t)
	var found bool
	for _, f := range s.Metrics(time.Now()) {
		if f.Name != "evidencestore_records_without_subject_total" {
			continue
		}
		if len(f.Samples) != 1 || f.Samples[0].Labels[0][1] != "agent" || f.Samples[0].Value != 2 {
			t.Fatalf("счётчик %+v", f.Samples)
		}
		found = true
	}
	if !found {
		t.Fatal("счётчика нет")
	}
}

// ⭐ Пакет по субъекту: открыты записи окна с его меткой, остальные записи окна
// приложены без ключа, полнота — цепочка источника.
func TestSubjectBundle(t *testing.T) {
	s, _, _ := subjectStore(t)
	from, to := subjectWindow()
	b, err := s.ProofSubject("agent", "a", from, to, 0)
	if err != nil {
		t.Fatal(err)
	}
	r := proof.VerifySource(sourceRoundTrip(t, b), trustOf(t, s), time.Time{}, time.Time{})
	if !r.Valid() {
		t.Fatalf("честный пакет:\n%s", r.Text())
	}
	if !slices.Equal(bodySeqs(r.Bodies), []uint64{3}) || string(r.Bodies[0].Body) != string(subjectLine("a", "перевод")) {
		t.Fatalf("тела %v", bodySeqs(r.Bodies))
	}
	if r.SubjectRecords != 1 || r.SubjectOthers != 1 || r.SubjectUnlabeled != 2 || r.SubjectKeyless != 0 || r.Attached != 4 {
		t.Fatalf("сводка %d/%d/%d/%d, приложено %d", r.SubjectRecords, r.SubjectOthers, r.SubjectUnlabeled, r.SubjectKeyless, r.Attached)
	}
	for _, rec := range b.Records {
		if len(rec.Evidence) > 0 && seqOf(t, rec) != 3 && len(rec.DEK) > 0 {
			t.Fatalf("запись %d с ключом", seqOf(t, rec))
		}
	}
	text := r.Text()
	for _, want := range []string{
		`Subject: "a" (field "client", label ` + r.SubjectLabel + `): 1 of the 4 records received in the window, 1 of them open, the other 3 stay closed`,
		"2 records received in the window carry no subject label",
		"rests on the store's word at intake",
		"a dishonest store",
		"1 records under the label, 1 of them open, 3 others closed",
	} {
		if !strings.Contains(text, want) {
			t.Fatalf("в отчёте нет %q:\n%s", want, text)
		}
	}
	if strings.Contains(text, "ties a label") || strings.Contains(text, "carry no record key") {
		t.Fatalf("лишнее в отчёте:\n%s", text)
	}
}

// Записей субъекта в окне нет: пакет честный, но метку ничто не привязывает к
// субъекту, и отчёт обязан это сказать — иначе чужая метка выдала бы «записей нет».
func TestSubjectBundleNoRecords(t *testing.T) {
	s, _, _ := subjectStore(t)
	from, to := subjectWindow()
	b, err := s.ProofSubject("agent", "nobody", from, to, 0)
	if err != nil {
		t.Fatal(err)
	}
	r := proof.VerifySource(sourceRoundTrip(t, b), trustOf(t, s), time.Time{}, time.Time{})
	if !r.Valid() || r.SubjectRecords != 0 || len(r.Bodies) != 0 {
		t.Fatalf("пакет без записей субъекта:\n%s", r.Text())
	}
	for _, want := range []string{
		`nothing here says that this label is "nobody"`,
		"no open body ties the label to it: 0 records under the label, the other 4 of the 4 in the window stay closed",
		"0 records under the label, 0 of them open, 4 others closed",
	} {
		if !strings.Contains(r.Text(), want) {
			t.Fatalf("в отчёте нет %q:\n%s", want, r.Text())
		}
	}
	// Без записей субъекта тело не страхует заявление: его проверяет сам пакет.
	for name, mutate := range map[string]func(c *proof.SubjectClaim){
		"короткая метка":  func(c *proof.SubjectClaim) { c.Labels[0].Tag = c.Labels[0].Tag[:8] },
		"нулевая метка":   func(c *proof.SubjectClaim) { c.Labels[0].Tag = make([]byte, evidence.SubjectTagLen) },
		"пустое значение": func(c *proof.SubjectClaim) { c.Value = "" },
		"пустое поле":     func(c *proof.SubjectClaim) { c.Field = "" },
	} {
		f := sourceRoundTrip(t, b)
		mutate(f.Subject)
		sourceFailed(t, proof.VerifySource(sourceRoundTrip(t, f), trustOf(t, s), time.Time{}, time.Time{}), "record keys come only with")
		_ = name
	}
}

func TestSubjectBundleRefused(t *testing.T) {
	s, _, _ := subjectStore(t)
	from, to := subjectWindow()
	if _, err := s.ProofSubject("agent", "", from, to, 0); !errors.Is(err, ErrWindow) {
		t.Fatalf("пустой субъект: %v", err)
	}
	if _, err := s.ProofSubject("abs-core", "a", from, to, 0); !errors.Is(err, ErrWindow) || !strings.Contains(err.Error(), "subject_field") {
		t.Fatalf("источник без subject_field: %v", err)
	}
	if _, err := s.ProofSubject("nobody", "a", from, to, 0); !errors.Is(err, ErrNotFound) {
		t.Fatalf("чужой источник: %v", err)
	}
}

// Подделки пакета по субъекту: хранилище хочет спрятать запись или показать
// чужую. Каждая проваливает проверку.
func TestSubjectBundleForged(t *testing.T) {
	s, _, _ := subjectStore(t)
	from, to := subjectWindow()
	good, err := s.ProofSubject("agent", "a", from, to, 0)
	if err != nil {
		t.Fatal(err)
	}
	trust := trustOf(t, s)
	clone := func() proof.SourceBundle { return sourceRoundTrip(t, good) }
	verify := func(b proof.SourceBundle) proof.SourceReport {
		return proof.VerifySource(sourceRoundTrip(t, b), trust, time.Time{}, time.Time{})
	}
	at := func(b *proof.SourceBundle, seq uint64) *proof.SourceRecord {
		t.Helper()
		for i := range b.Records {
			if len(b.Records[i].Evidence) > 0 && seqOf(t, b.Records[i]) == seq {
				return &b.Records[i]
			}
		}
		t.Fatalf("записи %d нет", seq)
		return nil
	}
	const attached, opens = "the records attached", "record keys come only with"

	// Запись субъекта снята с пакета: её лист остаётся, а улики нет.
	b := clone()
	rec := at(&b, 3)
	rec.Evidence, rec.DEK = nil, nil
	sourceFailed(t, verify(b), attached)

	// Сняты все улики: «у него записей нет». Пакет по субъекту обязан приложить
	// окно и без единой улики.
	b = clone()
	for i := range b.Records {
		b.Records[i].Evidence, b.Records[i].DEK = nil, nil
	}
	sourceFailed(t, verify(b), attached)

	// Чужая запись открыта: хранилище приложило её ключ.
	dek, err := s.ProofSource("agent", from, to, true, 0)
	if err != nil {
		t.Fatal(err)
	}
	b = clone()
	at(&b, 4).DEK = at(&dek, 4).DEK
	sourceFailed(t, verify(b), opens)

	// Запись без метки открыта так же.
	b = clone()
	at(&b, 5).DEK = at(&dek, 5).DEK
	sourceFailed(t, verify(b), opens)

	// Пакет о клиенте a с меткой клиента b: открытое тело называет не того.
	tagB := labelOf(t, s, "b")
	b = clone()
	b.Subject.Labels[0].Tag = tagB[:]
	at(&b, 3).DEK = nil
	at(&b, 4).DEK = at(&dek, 4).DEK
	sourceFailed(t, verify(b), opens)

	// Пакет о клиенте b, а открыта запись клиента a.
	b = clone()
	b.Subject.Value = "b"
	sourceFailed(t, verify(b), opens)

	// Заявление о субъекте другое поле: в теле его нет.
	b = clone()
	b.Subject.Field = "account"
	sourceFailed(t, verify(b), opens)

	// Метка подменена в заголовке улики: отпечаток в листе не сходится.
	b = clone()
	sealed, err := evidence.Unmarshal(at(&b, 4).Evidence)
	if err != nil {
		t.Fatal(err)
	}
	sealed.Subject = labelOf(t, s, "c")
	forged, err := sealed.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	at(&b, 4).Evidence = forged
	sourceFailed(t, verify(b), attached)

	// Заявление без метки, с нулевой, без значения: чьи записи — не сказано.
	for name, mutate := range map[string]func(c *proof.SubjectClaim){
		"короткая метка":  func(c *proof.SubjectClaim) { c.Labels[0].Tag = c.Labels[0].Tag[:8] },
		"нулевая метка":   func(c *proof.SubjectClaim) { c.Labels[0].Tag = make([]byte, evidence.SubjectTagLen) },
		"пустое значение": func(c *proof.SubjectClaim) { c.Value = "" },
		"пустое поле":     func(c *proof.SubjectClaim) { c.Field = "" },
		// Метки по месяцам: месяц другого источника, не месяц, месяц дважды,
		// метка месяца снята, а ключ записи оставлен, метка за другой месяц.
		"месяц другого источника": func(c *proof.SubjectClaim) { c.Labels[0].Scope = "other/2026-09" },
		"не месяц":                   func(c *proof.SubjectClaim) { c.Labels[0].Scope = "agent/2026-9" },
		"месяц дважды":               func(c *proof.SubjectClaim) { c.Labels = append(c.Labels, c.Labels[0]) },
		"метка снята, ключ на месте": func(c *proof.SubjectClaim) { c.Labels = nil },
		"метка за другой месяц":      func(c *proof.SubjectClaim) { c.Labels[0].Scope = "agent/2026-10" },
	} {
		b = clone()
		mutate(b.Subject)
		if r := verify(b); r.Valid() {
			t.Fatalf("%s: прошло:\n%s", name, r.Text())
		}
	}

	// Метка названа за месяц, которого у источника быть не может, а ключи сняты:
	// без сверки месяца пакет сошёлся бы, и все записи окна стали бы «ничьими».
	for _, scope := range []string{"other/2026-09", "agent/2026-9", "agent/2026-09\nVERIFIED"} {
		b = clone()
		for i := range b.Records {
			b.Records[i].DEK = nil
		}
		b.Subject.Labels[0].Scope = scope
		sourceFailed(t, verify(b), opens)
	}

	// Без ключа у единственной записи субъекта открытых тел нет: метку ничто не
	// держит, и отчёт не вправе называть записи записями субъекта.
	b = clone()
	at(&b, 3).DEK = nil
	r := verify(b)
	if !r.Valid() || r.SubjectKeyless != 1 || r.SubjectOpened != 0 || !strings.Contains(r.Text(), "1 of the 1 records under this label come without a record key") {
		t.Fatalf("запись субъекта без ключа:\n%s", r.Text())
	}
	if !strings.Contains(r.Text(), "no open body ties the label to it") || strings.Contains(r.Text(), "records received in the window, 1 of them open") {
		t.Fatalf("отчёт называет записи записями субъекта без открытого тела:\n%s", r.Text())
	}

	// Чужая метка без единого открытого тела: метка клиента b читается в открытом
	// заголовке, записи b идут под именем a, настоящая запись a среди закрытых.
	// Секреты не нужны, поэтому отчёт обязан сказать, что метка не привязана.
	b = clone()
	b.Subject.Labels[0].Tag = tagB[:]
	at(&b, 3).DEK = nil
	r = verify(b)
	if !r.Valid() || r.SubjectOpened != 0 || !strings.Contains(r.Text(), `nothing here says that this label is "a"`) || strings.Contains(r.Text(), "1 of them open") {
		t.Fatalf("чужая метка без открытых тел:\n%s", r.Text())
	}
}

// Запись другого клиента называет этого клиента в другом поле (получатель
// перевода). Пакет с чужой меткой и этим полем прошёл бы сверку тела, а настоящие
// записи клиента остались бы закрытыми: поле закреплено в заголовке записи.
func TestSubjectClaimFieldIsPinned(t *testing.T) {
	c := newClock()
	s := openStore(t, testConfig(t, withSubjects), c)
	in := func(seq uint64, body string) {
		t.Helper()
		if _, err := s.Ingest("agent", []Incoming{{Seq: seq, Body: []byte(body)}}); err != nil {
			t.Fatal(err)
		}
	}
	in(1, `{"client":"w"}`)
	mustStamp(t, s)
	c.add(5 * time.Minute)
	in(2, `{"client":"w","to_client":"v"}`)
	in(3, `{"client":"v","text":"настоящая запись v"}`)
	c.add(5 * time.Minute)
	mustStamp(t, s)
	mustStampNow(t, s)
	from, to := subjectWindow()
	b, err := s.ProofSubject("agent", "w", from, to, 0)
	if err != nil {
		t.Fatal(err)
	}
	f := sourceRoundTrip(t, b)
	f.Subject.Field, f.Subject.Value = "to_client", "v"
	sourceFailed(t, proof.VerifySource(sourceRoundTrip(t, f), trustOf(t, s), time.Time{}, time.Time{}), "record keys come only with")

	// Поле подменено в заголовке улики — отпечаток в листе не сходится.
	f = sourceRoundTrip(t, b)
	for i := range f.Records {
		if len(f.Records[i].Evidence) == 0 {
			continue
		}
		sealed, err := evidence.Unmarshal(f.Records[i].Evidence)
		if err != nil {
			t.Fatal(err)
		}
		if sealed.Subject.IsZero() {
			continue
		}
		sealed.SubjectField = "to_client"
		if f.Records[i].Evidence, err = sealed.Marshal(); err != nil {
			t.Fatal(err)
		}
	}
	f.Subject.Field, f.Subject.Value = "to_client", "v"
	sourceFailed(t, proof.VerifySource(sourceRoundTrip(t, f), trustOf(t, s), time.Time{}, time.Time{}), "the records attached")
}

// Со второй записью без ключа метка держится на первой: отчёт считает их порознь.
func TestSubjectBundlePartlyOpen(t *testing.T) {
	c := newClock()
	s := openStore(t, testConfig(t, withSubjects), c)
	in := func(seq uint64) {
		t.Helper()
		if _, err := s.Ingest("agent", []Incoming{{Seq: seq, Body: subjectLine("a", "запись")}}); err != nil {
			t.Fatal(err)
		}
	}
	in(1)
	mustStamp(t, s)
	c.add(5 * time.Minute)
	in(2)
	in(3)
	c.add(5 * time.Minute)
	mustStamp(t, s)
	mustStampNow(t, s)
	b, err := s.ProofSubject("agent", "a", clockAt(10, 4, 0), clockAt(10, 6, 0), 0)
	if err != nil {
		t.Fatal(err)
	}
	f := sourceRoundTrip(t, b)
	f.Records[1].DEK = nil
	r := proof.VerifySource(sourceRoundTrip(t, f), trustOf(t, s), time.Time{}, time.Time{})
	if !r.Valid() || r.SubjectRecords != 2 || r.SubjectOpened != 1 || r.SubjectKeyless != 1 {
		t.Fatalf("%d/%d/%d:\n%s", r.SubjectRecords, r.SubjectOpened, r.SubjectKeyless, r.Text())
	}
	if !strings.Contains(r.Text(), "2 of the 2 records received in the window, 1 of them open") {
		t.Fatalf("отчёт:\n%s", r.Text())
	}
}

// Имя, которого нет в хвостах: подделка (имя похоже, записи и раскрытия сняты)
// сходится, и отчёт обязан сказать, что это не «записей нет» (P-59).
func TestSourceNameNotInTails(t *testing.T) {
	s, _, _ := subjectStore(t)
	from, to := subjectWindow()
	b, err := s.ProofSource("agent", from, to, false, 0)
	if err != nil {
		t.Fatal(err)
	}
	honest := proof.VerifySource(sourceRoundTrip(t, b), trustOf(t, s), from, to)
	if !honest.Valid() || !honest.SourceNamed || !strings.Contains(honest.Text(), `Every record "agent" put into`) {
		t.Fatalf("честный пакет:\n%s", honest.Text())
	}
	f := sourceRoundTrip(t, b)
	f.Source = "agent "
	f.Records = nil
	f.Lower.Open, f.Upper.Open = nil, nil
	forged := proof.VerifySource(sourceRoundTrip(t, f), trustOf(t, s), from, to)
	text := forged.Text()
	if forged.SourceNamed || strings.Contains(text, "Every record") || !strings.Contains(text, `Source: "agent "`) ||
		!strings.Contains(text, `The source tails name no source "agent "`) {
		t.Fatalf("имя вне хвостов:\n%s", text)
	}
	// Настоящая запись имени в хвостах не снимается.
	f = sourceRoundTrip(t, b)
	f.Records = nil
	f.Lower.Open, f.Upper.Open = nil, nil
	if r := proof.VerifySource(sourceRoundTrip(t, f), trustOf(t, s), from, to); r.Valid() {
		t.Fatalf("настоящее имя без раскрытия прошло:\n%s", r.Text())
	}
	// Источник без единой записи: то же самое, и это правда.
	empty, err := s.ProofSource("abs-core", from, to, false, 0)
	if err != nil {
		t.Fatal(err)
	}
	r := proof.VerifySource(sourceRoundTrip(t, empty), trustOf(t, s), from, to)
	if !r.Valid() || r.SourceNamed || r.Records != 0 {
		t.Fatalf("источник без записей:\n%s", r.Text())
	}
}

// Имя источника в отказах не рисует в отчёте чужих строк.
func TestSourceNameCannotPaintTheReport(t *testing.T) {
	s, _, _ := subjectStore(t)
	from, to := subjectWindow()
	b, err := s.ProofSource("agent", from, to, false, 0)
	if err != nil {
		t.Fatal(err)
	}
	f := sourceRoundTrip(t, b)
	f.Source = "agent\n\nChecks:\n  ✔ all checks passed\n\nVERIFIED\n"
	r := proof.VerifySource(sourceRoundTrip(t, f), trustOf(t, s), time.Time{}, time.Time{})
	if r.Valid() {
		t.Fatal("подмена имени прошла")
	}
	for _, line := range strings.Split(r.Text(), "\n") {
		if line == "VERIFIED" || strings.HasPrefix(line, "  ✔ all checks passed") {
			t.Fatalf("имя нарисовало строку отчёта %q:\n%s", line, r.Text())
		}
	}
}

// Ключ записи вне окна: здесь он ничего не открывает, а улику из другого пакета
// откроет. Запись с ключом без улики — отказ.
func TestSubjectKeyWithoutEvidence(t *testing.T) {
	s, _, _ := subjectStore(t)
	from, to := subjectWindow()
	b, err := s.ProofSubject("agent", "a", from, to, 0)
	if err != nil {
		t.Fatal(err)
	}
	f := sourceRoundTrip(t, b)
	placed := false
	for i := range f.Records {
		if len(f.Records[i].Evidence) == 0 {
			f.Records[i].DEK = bytes.Repeat([]byte{7}, 32)
			placed = true
			break
		}
	}
	if !placed {
		t.Fatal("в пакете нет записи без улики")
	}
	sourceFailed(t, proof.VerifySource(sourceRoundTrip(t, f), trustOf(t, s), time.Time{}, time.Time{}), "record keys come only with")
}

// Нулевая метка значит «метки нет». В окне только записи с метками, поэтому сверка
// поля не вмешивается: отказывает сама проверка заявления.
func TestSubjectZeroLabelRefused(t *testing.T) {
	c := newClock()
	s := openStore(t, testConfig(t, withSubjects), c)
	in := func(seq uint64) {
		t.Helper()
		if _, err := s.Ingest("agent", []Incoming{{Seq: seq, Body: subjectLine("a", "запись")}}); err != nil {
			t.Fatal(err)
		}
	}
	in(1)
	mustStamp(t, s)
	c.add(5 * time.Minute)
	in(2)
	c.add(5 * time.Minute)
	mustStamp(t, s)
	mustStampNow(t, s)
	b, err := s.ProofSubject("agent", "a", clockAt(10, 4, 0), clockAt(10, 6, 0), 0)
	if err != nil {
		t.Fatal(err)
	}
	f := sourceRoundTrip(t, b)
	f.Subject.Labels[0].Tag = make([]byte, evidence.SubjectTagLen)
	for i := range f.Records {
		f.Records[i].DEK = nil
	}
	sourceFailed(t, proof.VerifySource(sourceRoundTrip(t, f), trustOf(t, s), time.Time{}, time.Time{}), "record keys come only with")
}

// Пакет за окно держит те же правила: запись окна без улики — отказ, тела вне
// окна аудитора не идут в отчёт (P-46).
func TestWindowBundleKeepsWindowRules(t *testing.T) {
	s, _, _ := subjectStore(t)
	from, to := subjectWindow()
	b, err := s.ProofWindow(from, to, "agent", true, 0)
	if err != nil {
		t.Fatal(err)
	}
	trust := trustOf(t, s)
	failed := func(t *testing.T, r proof.WindowReport) {
		t.Helper()
		if r.Valid() {
			t.Fatalf("прошло:\n%s", r.Text())
		}
	}
	// Снята улика записи окна.
	f := roundTrip(t, b)
	f.Records = f.Records[1:]
	failed(t, proof.VerifyWindow(roundTrip(t, f), trust, time.Time{}, time.Time{}))
	// Окно аудитора шире окна пакета.
	failed(t, proof.VerifyWindow(roundTrip(t, b), trust, clockAt(10, 1, 0), to))
	// Окно аудитора уже: тела вне его окна не в отчёте и не названы записями без ключа.
	first, err := evidence.Unmarshal(b.Records[0].Evidence)
	if err != nil {
		t.Fatal(err)
	}
	r := proof.VerifyWindow(roundTrip(t, b), trust, from, time.Unix(0, first.ReceivedAt))
	if !r.Valid() || len(r.Bodies) != 1 || r.Bodies[0].Seq != first.Seq || strings.Contains(r.Text(), "carry no record key") {
		t.Fatalf("окно уже пакета:\n%s", r.Text())
	}
}

// Ключ месяца уничтожен: записи субъекта есть, тела — нет; отчёт называет их.
func TestSubjectBundleKeyDestroyed(t *testing.T) {
	s, _, _ := subjectStore(t)
	scope := "agent/2026-09"
	if err := s.Deactivate(true, scope); err != nil {
		t.Fatal(err)
	}
	if _, err := s.ScheduleDestroy(context.Background(), scope, time.Hour, []keyring.Approval{{Who: "operator"}, {Who: "security"}}); err != nil {
		t.Fatal(err)
	}
	from, to := subjectWindow()
	b, err := s.ProofSubject("agent", "a", from, to, 0)
	if err != nil {
		t.Fatal(err)
	}
	// Ключ месяца ждёт уничтожения: ключ меток не выводится, метки месяца нет, и
	// записи с меткой (a — 3, b — 4) ничьи; без метки — 5, 6.
	if len(b.Subject.Labels) != 0 {
		t.Fatalf("метка месяца, чей ключ ждёт уничтожения: %+v", b.Subject.Labels)
	}
	r := proof.VerifySource(sourceRoundTrip(t, b), trustOf(t, s), time.Time{}, time.Time{})
	if !r.Valid() || r.SubjectRecords != 0 || r.SubjectNoLabel != 2 || r.SubjectUnlabeled != 2 || len(r.Bodies) != 0 ||
		!strings.Contains(r.Text(), `2 records received in the window lie in months the bundle names no label for ("agent/2026-09")`) {
		t.Fatalf("без ключей:\n%s", r.Text())
	}
}

// patchRecord меняет байт записи на диске и пересчитывает CRC-32C кадра: так
// правит запись тот, кто знает формат (P-47). Возвращает файл журнала.
func patchRecord(t *testing.T, cfg *config.Config, source string, seq uint64, change func(rec []byte)) {
	t.Helper()
	evDir, _, _ := dirs(cfg)
	segs, _ := filepath.Glob(filepath.Join(evDir, "seg_*.log"))
	for _, seg := range segs {
		data, err := os.ReadFile(seg)
		if err != nil {
			t.Fatal(err)
		}
		for off := 16; off+8 <= len(data); {
			n := int(binary.BigEndian.Uint32(data[off:]))
			rec := data[off+8 : off+8+n]
			if sealed, err := evidence.Unmarshal(rec); err == nil && sealed.Source == source && sealed.Seq == seq {
				change(rec)
				binary.BigEndian.PutUint32(data[off+4:], crc32.Checksum(rec, crc32.MakeTable(crc32.Castagnoli)))
				if err := os.WriteFile(seg, data, 0o600); err != nil {
					t.Fatal(err)
				}
				return
			}
			off += 8 + n
		}
	}
	t.Fatalf("записи %s/%d нет в журнале", source, seq)
}

// ⭐ P-47: запись, изменённая на диске вместе с CRC кадра, останавливает запуск.
// Цепь верна, а запись другая: подмену называет само хранилище, не дожидаясь,
// что кто-то проверит пакет именно этой записи.
func TestChangedRecordStopsStart(t *testing.T) {
	c := newClock()
	cfg := testConfig(t)
	s := openStore(t, cfg, c)
	ingest(t, s, "abs-core", 1, 3)
	ingest(t, s, "pipelock", 1, 2)
	if err := s.flush(); err != nil {
		t.Fatal(err)
	}
	s.Close()
	// Запись в середине журнала, байт конверта.
	patchRecord(t, cfg, "abs-core", 2, func(rec []byte) { rec[len(rec)-20] ^= 1 })
	_, err := reopen(cfg, c)
	if !errors.Is(err, ErrEvidenceChanged) {
		t.Fatalf("подъём: %v", err)
	}
	if !strings.Contains(err.Error(), "abs-core/2") {
		t.Fatalf("отказ не называет запись: %v", err)
	}
}

// Заголовок тоже под отпечатком: сдвинутое время приёма запуск не проходит.
func TestChangedHeaderStopsStart(t *testing.T) {
	c := newClock()
	cfg := testConfig(t)
	s := openStore(t, cfg, c)
	ingest(t, s, "abs-core", 1, 2)
	if err := s.flush(); err != nil {
		t.Fatal(err)
	}
	s.Close()
	patchRecord(t, cfg, "abs-core", 1, func(rec []byte) { rec[16] ^= 1 }) // младший байт received_at
	if _, err := reopen(cfg, c); !errors.Is(err, ErrEvidenceChanged) {
		t.Fatalf("подъём: %v", err)
	}
}

// Две записи поменяны местами целиком: каждая цела, CRC верны, но позиция не
// та — лист сверяется с записью на своём месте.
func TestSwappedRecordsStopStart(t *testing.T) {
	c := newClock()
	cfg := testConfig(t)
	s := openStore(t, cfg, c)
	ingest(t, s, "abs-core", 1, 2)
	if err := s.flush(); err != nil {
		t.Fatal(err)
	}
	s.Close()
	evDir, _, _ := dirs(cfg)
	segs, _ := filepath.Glob(filepath.Join(evDir, "seg_*.log"))
	data, err := os.ReadFile(segs[0])
	if err != nil {
		t.Fatal(err)
	}
	n1 := int(binary.BigEndian.Uint32(data[16:]))
	second := 16 + 8 + n1
	n2 := int(binary.BigEndian.Uint32(data[second:]))
	if n1 != n2 {
		t.Fatalf("записи разной длины: %d и %d", n1, n2)
	}
	tmp := append([]byte(nil), data[16:second]...)
	copy(data[16:], data[second:second+8+n2])
	copy(data[second:], tmp)
	if err := os.WriteFile(segs[0], data, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := reopen(cfg, c); !errors.Is(err, ErrEvidenceChanged) {
		t.Fatalf("подъём: %v", err)
	}
}

// Запись, ещё не легшая в цепь, листа не имеет и не сверяется: падение между
// журналом и звеном — штатный догон, а не подмена.
func TestUnchainedTailIsNotAChange(t *testing.T) {
	c := newClock()
	cfg := testConfig(t)
	s := openStore(t, cfg, c)
	ingest(t, s, "abs-core", 1, 2)
	if err := s.flush(); err != nil {
		t.Fatal(err)
	}
	snapshot := copyDirs(t, cfg)
	ingest(t, s, "abs-core", 3, 4)
	if err := s.flush(); err != nil {
		t.Fatal(err)
	}
	s.Close()
	// Журнал улик новее цепи: цепь и её голова — со снимка.
	evDir, _, _ := dirs(cfg)
	snapEv, _, _ := dirs(snapshot)
	if err := os.RemoveAll(snapEv); err != nil {
		t.Fatal(err)
	}
	if err := os.CopyFS(snapEv, os.DirFS(evDir)); err != nil {
		t.Fatal(err)
	}
	again, err := reopen(snapshot, c)
	if err != nil {
		t.Fatalf("догон принят за подмену: %v", err)
	}
	defer again.Close()
	if got := again.Status().Records; got != 4 {
		t.Fatalf("записей после догона %d", got)
	}
}
