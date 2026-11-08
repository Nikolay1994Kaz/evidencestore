package main

import (
	"fmt"
	"path/filepath"
	"testing"

	"github.com/Nikolay1994Kaz/evidencestore/internal/proof"
)

// Пробелы покрытия нового кода (тестировщик T, третий раунд): мутанты T3,
// T16, T19 не ловил ни один тест proof и esverify, T18 — лишь иногда.

// T3: голова 8 положена дважды (хранилище после перезапуска отдало ту же
// голову ещё раз: подпись детерминирована, байты те же). Проверяющий держит
// файл поздней версии, ранняя находит его по ETag. Время головы — самой
// ранней версии, в каком бы порядке fromS3 ни перебирал кандидатов (ETag,
// затем номер версии в имени файла).
func TestHeadsGapEarliestOfTwoVersions(t *testing.T) {
	w := newLyWorld(t)
	objs := w.objs("witness", lyAWS, 0)
	var again lyObj
	for _, o := range objs {
		if o.seq == 8 {
			again = o
		}
	}
	again.vid, again.at = "v-8-again", lyDay(10, 20, 0)
	dir := t.TempDir()
	writeVersions(t, filepath.Join(dir, "versions.json"), append(objs, again), false)
	var files []lyObj
	for _, o := range objs {
		if o.seq != 8 {
			files = append(files, o)
		}
	}
	writeVersionFiles(t, dir, append(files, again), byVID)
	code, text, rep := w.verify(w.honest, dir)
	if code != exitValid || jsonWitness(rep) != lyOK8 {
		t.Fatalf("голова дважды, файл поздней версии: код %d %s\n%s", code, jsonWitness(rep), text)
	}
}

// T16: два бакета, у второго версия без файла, полученная раньше головы,
// которую этот бакет получил первой, и лежащая за пакетом: её надо скачать —
// меряет её голова её списка, а не другого.
func TestHeadsGapMissingVersionOwnList(t *testing.T) {
	w := newLyWorld(t)
	b1 := w.objs("witness", lyAWS, 0)
	b2 := w.objs("witness", lyMinIO, 3_000_000_000, 2, 3, 8, 10, 11, 12) // только 13 и 14, на 3 с позже
	// Версия под номером 20 — за участком пакета до 13: её мерит только
	// голова её списка (13, 10:12:08), а не голова первого бакета (8, 10:00:25).
	missing := lyObj{key: "witness/heads/00000000000000000020.json", vid: "not-downloaded", seq: 20, at: lyDay(10, 5, 0)}
	dir := t.TempDir()
	writeVersions(t, filepath.Join(dir, "versions.json"), b1, false)
	writeVersionFiles(t, dir, b1, byVID)
	missing.data = []byte("not downloaded") // ETag не совпадёт ни с одним файлом
	writeVersions(t, filepath.Join(dir, "b2/versions.json"), append(append([]lyObj(nil), b2...), missing), false)
	writeVersionFiles(t, filepath.Join(dir, "b2"), b2, byVID)
	code, text, _ := w.verify(w.bundleTo(13), dir)
	if code != exitInvalid {
		t.Fatalf("версия без файла во втором бакете не в счёт: код %d\n%s", code, text)
	}
	mustHave(t, "версия без файла во втором бакете", text, `version "not-downloaded", received at 2026-11-08 10:05:00 UTC`, "download every version of the heads")
}

// T19: заметка «без времени» — если хоть один свидетель закрепил по номеру
// (P-94), и тогда, когда самую дальнюю голову закрепил свидетель со временем,
// а его имя в обходе раньше: S3 без головы 8 закрепляет 10 по времени, газета
// в 10:02 — 9 по номеру.
func TestHeadsGapUntimedNoteAny(t *testing.T) {
	w := newLyWorld(t)
	objs := w.objs("witness", lyAWS, 0, 8)
	dir := t.TempDir()
	writeVersions(t, filepath.Join(dir, "versions.json"), objs, false)
	writeVersionFiles(t, dir, objs, byVID)
	lyWrite(t, filepath.Join(dir, "mail/2026-11-08.json"), w.statements["1002"])
	code, text, rep := w.verify(w.honest, dir)
	if code != exitValid || jsonWitness(rep) != "valid=true head=10 received=2026-11-08T10:03:05Z refused=0 fork=0" {
		t.Fatalf("S3 и газета: код %d %s\n%s", code, jsonWitness(rep), text)
	}
	mustHave(t, "S3 и газета", text, "heads without a time of receipt in mail: head 9, first by number", proof.WitnessUntimedNote)
}

// T18: отчёт не зависит от порядка обхода свидетелей (P-102). Тесты проекта
// ловят обход без сортировки лишь иногда: порядок в map случаен, и строку
// с двумя свидетелями он угадывает через раз. Здесь — четыре свидетеля и
// двадцать прогонов: текст каждый раз один и тот же, свидетели — по именам.
func TestHeadsGapReportOrder(t *testing.T) {
	w := newLyWorld(t)
	dir := t.TempDir()
	objs := w.objs("witness", lyAWS, 0)
	writeVersions(t, filepath.Join(dir, "a/versions.json"), objs, false)
	writeVersions(t, filepath.Join(dir, "b/versions.json"), objs, false)
	writeVersionFiles(t, dir, objs, byVID)
	lyWrite(t, filepath.Join(dir, "collector/checkpoints.jsonl"), w.journal(uint64(8), lyDay(10, 0, 26)))
	lyWrite(t, filepath.Join(dir, "mail/2026-11-08.json"), w.statements["1002"])
	want := "head 9, the last of the heads each witness received first (S3 (versions list a/versions.json): head 8, received first at 2026-11-08 10:00:25 UTC; " +
		"S3 (versions list b/versions.json): head 8, received first at 2026-11-08 10:00:25 UTC; heads without a time of receipt in mail: head 9, first by number; " +
		"the collector's journal in collector: head 8, received first at 2026-11-08 10:00:26 UTC)"
	for i := 0; i < 20; i++ {
		code, text := w.run(w.honest, "-heads", dir)
		if code != exitValid {
			t.Fatalf("прогон %d: код %d\n%s", i, code, text)
		}
		mustHave(t, fmt.Sprintf("прогон %d", i), text, want)
	}
}
