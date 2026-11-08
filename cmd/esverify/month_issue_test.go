package main

import (
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

// Третий заход по ветке месяцев (P-81…P-87) — через esverify: -bodies называет
// всё, чего не записал, и окно аудитора шире пакета — отказ.

// midnightWorld — окно через полночь 31.10 → 01.11: запись 2 (c-1) в октябре,
// 3 (c-1) и 4 (c-2) в ноябре.
func midnightWorld(t *testing.T) (w subjectWorld, from, to time.Time) {
	t.Helper()
	w = openWorldAt(t, []config.Source{{Name: "agent", ContentType: "application/json", SubjectField: "client"}},
		time.Date(2026, 10, 31, 23, 50, 0, 0, time.UTC))
	w.line(t, "agent", 1, `{"client":"c-1"}`)
	w.stamp(t)
	w.advance(5 * time.Minute) // 23:55, октябрь
	w.line(t, "agent", 2, `{"client":"c-1","m":"oct"}`)
	w.advance(10 * time.Minute) // 00:05, ноябрь
	w.line(t, "agent", 3, `{"client":"c-1","m":"nov"}`)
	w.line(t, "agent", 4, `{"client":"c-2","m":"nov"}`)
	w.advance(5 * time.Minute)
	w.closeUp(t)
	return w, time.Date(2026, 10, 31, 23, 54, 0, 0, time.UTC), time.Date(2026, 11, 1, 0, 6, 0, 0, time.UTC)
}

func awaitDestruction(t *testing.T, w subjectWorld, scope string) {
	t.Helper()
	if err := w.s.Deactivate(true, scope); err != nil {
		t.Fatal(err)
	}
	if _, err := w.s.ScheduleDestroy(t.Context(), scope, time.Hour, []keyring.Approval{{Who: "operator"}, {Who: "security"}}); err != nil {
		t.Fatal(err)
	}
}

func written(t *testing.T, dir string) []string {
	t.Helper()
	files, _ := os.ReadDir(dir)
	var out []string
	for _, f := range files {
		out = append(out, f.Name())
	}
	return out
}

// ⭐ T-05, E1-02, T-03: -bodies записал часть тел. О месяце, пришедшем листом,
// и об уликах без ключа он говорит в stderr — как о месяцах без открытого тела
// субъекта (P-75); код 0, -json чист.
func TestBodiesNameWhatTheyLeaveOut(t *testing.T) {
	w, from, to := midnightWorld(t)
	awaitDestruction(t, w, "agent/2026-10")
	src, err := w.s.ProofSource("agent", from, to, true, 0)
	if err != nil {
		t.Fatal(err)
	}
	win, err := w.s.ProofWindow(from, to, "agent", true, 0)
	if err != nil {
		t.Fatal(err)
	}
	const leaf = `the bundle carries no evidence for "agent/2026-10": their records are not among the bodies written`
	for name, b := range map[string]any{"source": src, "window": win} {
		dir := filepath.Join(w.dir, "bodies-"+name)
		code, out, errOut := w.run(t, w.file(t, name+".json", b), "-bodies", dir, "-json")
		if code != exitValid || !strings.Contains(errOut, "2 bodies written") || !strings.Contains(errOut, leaf) ||
			!slices.Equal(written(t, dir), []string{"agent-3", "agent-4"}) || !strings.HasPrefix(out, "{") {
			t.Fatalf("%s: код %d, файлы %v\n%s", name, code, written(t, dir), errOut)
		}
	}

	// Ключ записи 4 снят: тело не записано, и -bodies это говорит.
	for i := range src.Records {
		if len(src.Records[i].Evidence) > 0 {
			if sealed, _ := evidence.Unmarshal(src.Records[i].Evidence); sealed.Seq == 4 {
				src.Records[i].DEK = nil
			}
		}
	}
	for i := range win.Records {
		if sealed, _ := evidence.Unmarshal(win.Records[i].Evidence); sealed.Seq == 4 {
			win.Records[i].DEK = nil
		}
	}
	const keyless = "1 records of the window come with their evidence and without their record key, and their bodies are not among those written: " + proof.KeylessReasons
	for name, b := range map[string]any{"source": src, "window": win} {
		dir := filepath.Join(w.dir, "keyless-"+name)
		code, _, errOut := w.run(t, w.file(t, "keyless-"+name+".json", b), "-bodies", dir)
		if code != exitValid || !strings.Contains(errOut, "1 bodies written") || !strings.Contains(errOut, keyless) || !strings.Contains(errOut, leaf) {
			t.Fatalf("%s без ключа записи 4: код %d\n%s", name, code, errOut)
		}
	}

	// Пакет по субъекту: октябрь без метки назван месяцем без открытого тела, а
	// улики чужой записи 4 без ключа — не «снятые ключи»: ключ им и не положен.
	sub, err := w.s.ProofSubject("agent", "c-1", from, to, 0)
	if err != nil {
		t.Fatal(err)
	}
	code, _, errOut := w.run(t, w.file(t, "subject.json", sub), "-bodies", filepath.Join(w.dir, "subject"))
	if code != exitValid || !strings.Contains(errOut, "1 bodies written") || !strings.Contains(errOut, `no body of "c-1" is open in "agent/2026-10"`) ||
		strings.Contains(errOut, "without their record key") || strings.Contains(errOut, "carries no evidence for") {
		t.Fatalf("честный пакет по субъекту: код %d\n%s", code, errOut)
	}
}

// ⭐ P-81 через esverify: пакет за ноябрь, окно аудитора заходит в октябрь, оба
// ключа живы. Отказ и прежний совет; тела не пишутся.
func TestWiderAuditorWindowThroughEsverify(t *testing.T) {
	w, from, to := midnightWorld(t)
	nov := time.Date(2026, 11, 1, 0, 0, 30, 0, time.UTC)
	src, err := w.s.ProofSource("agent", nov, to, true, 0)
	if err != nil {
		t.Fatal(err)
	}
	win, err := w.s.ProofWindow(nov, to, "agent", true, 0)
	if err != nil {
		t.Fatal(err)
	}
	sub, err := w.s.ProofSubject("agent", "c-1", nov, to, 0)
	if err != nil {
		t.Fatal(err)
	}
	for name, b := range map[string]any{"source": src, "window": win, "subject": sub} {
		dir := filepath.Join(w.dir, "wide-"+name)
		code, out, errOut := w.run(t, w.file(t, "wide-"+name+".json", b), "-bodies", dir,
			"-from", from.Format(time.RFC3339), "-to", to.Format(time.RFC3339))
		if code != exitInvalid || !strings.Contains(out, "1 records received in the window come without their evidence: ask for a bundle over this window") ||
			!strings.Contains(errOut, "bodies not written") || len(written(t, dir)) != 0 {
			t.Fatalf("%s: код %d, файлы %v\n%s\n%s", name, code, written(t, dir), out, errOut)
		}
		// Окном пакета — проходит.
		if code, out, _ := w.run(t, w.file(t, "own-"+name+".json", b)); code != exitValid {
			t.Fatalf("%s своим окном: код %d\n%s", name, code, out)
		}
	}
}

// E4-08: пакет -window -source S -dek, у S в окне записей нет, у другого
// источника есть. -bodies не советует взять -dek снова: ключи уже просили.
func TestBodiesKeysForQuietSource(t *testing.T) {
	w := openWorld(t, []config.Source{{Name: "aaa", ContentType: "syslog"}, {Name: "zzz", ContentType: "syslog"}})
	w.line(t, "aaa", 1, "a1")
	w.line(t, "zzz", 1, "z1")
	w.stamp(t)
	w.advance(5 * time.Minute)
	w.line(t, "aaa", 2, "a2")
	w.advance(5 * time.Minute)
	w.closeUp(t)
	win, err := w.s.ProofWindow(w.from, w.to, "zzz", true, 0)
	if err != nil {
		t.Fatal(err)
	}
	code, _, errOut := w.run(t, w.file(t, "quiet.json", win), "-bodies", filepath.Join(w.dir, "bodies"))
	if code != exitUsage || !strings.Contains(errOut, `it says it carries the keys of "zzz", and that source has no records received in the window`) ||
		strings.Contains(errOut, "-dek") {
		t.Fatalf("код %d: %s", code, errOut)
	}
}

// E2-02: под меткой пусто, тел нет. Сообщение -bodies называет каждый месяц окна
// без открытого тела субъекта, а не только месяц без метки: подменённая метка
// ноября прятала бы запись c-1 там.
func TestBodiesNothingNamesEveryMonth(t *testing.T) {
	w, from, to := midnightWorld(t)
	awaitDestruction(t, w, "agent/2026-10")
	honest, err := w.s.ProofSubject("agent", "c-1", from, to, 0)
	if err != nil {
		t.Fatal(err)
	}
	forged := honest
	forged.Subject = &proof.SubjectClaim{Field: honest.Subject.Field, Value: honest.Subject.Value,
		Labels: []proof.SubjectLabel{{Scope: "agent/2026-11", Tag: []byte("0123456789abcdef")}}}
	forged.Records = append([]proof.SourceRecord(nil), honest.Records...)
	for i := range forged.Records {
		forged.Records[i].DEK = nil
	}
	code, out, errOut := w.run(t, w.file(t, "forged.json", forged), "-bodies", filepath.Join(w.dir, "forged"))
	if code != exitValid || !strings.Contains(errOut, `no body of "c-1" is open in "agent/2026-10", "agent/2026-11"`) ||
		!strings.Contains(errOut, `(the bundle names no label for "agent/2026-10")`) ||
		!strings.Contains(out, `no body of the subject is open in "agent/2026-10", "agent/2026-11", and its records there are not shown`) {
		t.Fatalf("подделка ноября: код %d\n%s\n%s", code, out, errOut)
	}
}

// E2-03: пакет без ключей с дописанной пометкой with_keys или keys_for: месяц
// листом выглядит как стёртый, и -bodies говорит, что так выглядит и пакет, из
// которого вынули улики, и чем это проверить.
func TestBodiesLeafOnlyCaveat(t *testing.T) {
	w := newSubjectWorld(t)
	src, err := w.s.ProofSource("agent", w.from, w.to, false, 0)
	if err != nil {
		t.Fatal(err)
	}
	win, err := w.s.ProofWindow(w.from, w.to, "", false, 0)
	if err != nil {
		t.Fatal(err)
	}
	src.WithKeys = true
	win.KeysFor = "agent"
	for name, b := range map[string]any{"source": src, "window": win} {
		code, _, errOut := w.run(t, w.file(t, name+".json", b), "-bodies", filepath.Join(w.dir, "bodies-"+name))
		if code != exitUsage || !strings.Contains(errOut, "anyone can take a month's evidence out of a bundle, and the with_keys and keys_for marks are not signed") ||
			!strings.Contains(errOut, proof.ReceiptsPath) {
			t.Fatalf("%s: код %d: %s", name, code, errOut)
		}
	}
}
