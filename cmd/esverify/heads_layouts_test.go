package main

import (
	"fmt"
	"path/filepath"
	"testing"
	"time"

	"github.com/Nikolay1994Kaz/evidencestore/internal/proof"
)

// Честные каталоги через esverify -heads DIR (тестировщик T, третий раунд).
// Для каждой раскладки: честный пакет проходит (или совет исполним — пакет
// по совету проходит); отчёт и -json называют голову и время. Закрепление по
// времени, а не по номеру, проверяется честно: у бакета нет головы 8, а
// голова 10 пришла позже 11 (Q-06) — закрепляет 11, и пакет до 10 просят
// длиннее (по номеру закрепила бы 10).

const lyOK8 = "valid=true head=8 received=2026-11-08T10:00:25Z refused=0 fork=0"

// late10 — у бакета нет головы 8, голова 10 пришла позже 11.
func late10(objs []lyObj) []lyObj {
	for i := range objs {
		if objs[i].seq == 10 {
			objs[i].at = lyDay(10, 3, 9)
		}
	}
	return objs
}

// byTime — закрепляет 11, полученная первой: пакет до 10 просят до 11, пакет
// до 11 проходит.
func (w *lyWorld) byTime(t *testing.T, what, dir, received string) {
	t.Helper()
	code, text, rep := w.verify(w.honest, dir)
	if code != exitInvalid || rep["valid"] != false {
		t.Fatalf("%s: пакет до 10 прошёл, хотя первой пришла 11: код %d\n%s", what, code, text)
	}
	mustHave(t, what, text, "the bundle ends at link 10, before head 11 the witness received first, at "+received+": request a bundle up to it (evidencestore proof -to-head 11)")
	long := w.bundleTo(11)
	code, text, rep = w.verify(long, dir)
	if code != exitValid || rep["witness_head"] != float64(11) {
		t.Fatalf("%s: пакет по совету -to-head 11 не прошёл: код %d %s\n%s", what, code, jsonWitness(rep), text)
	}
}

func TestHeadsLayoutS3(t *testing.T) {
	w := newLyWorld(t)
	for _, l := range []struct {
		name, list string
		file       func(lyObj) string
	}{
		{"плоско", "versions.json", byVID},
		{"по ключам", "versions.json", func(o lyObj) string { return o.key + "/" + o.vid + ".json" }},
		{"вложенно", "bucket/versions.json", func(o lyObj) string { return "bucket/objects/" + o.vid + ".json" }},
		{"список в корне, файлы глубоко", "versions.json", func(o lyObj) string { return "dl/2026/11/08/" + o.vid + ".json" }},
	} {
		for _, v1 := range []bool{false, true} {
			name := fmt.Sprintf("%s, CLI v1 %v", l.name, v1)
			t.Run(name, func(t *testing.T) {
				dir := t.TempDir()
				objs := w.objs("witness", lyAWS, 0)
				writeVersions(t, filepath.Join(dir, l.list), objs, v1)
				writeVersionFiles(t, dir, objs, l.file)
				code, text, rep := w.verify(w.honest, dir)
				if code != exitValid || jsonWitness(rep) != lyOK8 {
					t.Fatalf("честный пакет: код %d %s\n%s", code, jsonWitness(rep), text)
				}
				mustHave(t, name, text, "head 8, which the witness received first, at 2026-11-08 10:00:25 UTC",
					"8 heads signed with the store key, 0 of 8 entries are not such heads, 8 versions in the S3 versions list")
				mustNot(t, name, text, proof.WitnessUntimedNote, "collector")

				dir = t.TempDir()
				objs = late10(w.objs("witness", lyAWS, 0, 8))
				writeVersions(t, filepath.Join(dir, l.list), objs, v1)
				writeVersionFiles(t, dir, objs, l.file)
				w.byTime(t, name, dir, "2026-11-08 10:03:06 UTC")
			})
		}
	}
}

func TestHeadsLayoutTwoBuckets(t *testing.T) {
	w := newLyWorld(t)
	b1 := w.objs("witness", lyAWS, 0)
	b2 := w.objs("witness", lyMinIO, 3*time.Second) // второй бакет получает те же головы на 3 с позже
	t.Run("в своих подкаталогах", func(t *testing.T) {
		dir := t.TempDir()
		writeVersions(t, filepath.Join(dir, "b1/versions.json"), b1, false)
		writeVersionFiles(t, filepath.Join(dir, "b1"), b1, byVID)
		writeVersions(t, filepath.Join(dir, "b2/versions.json"), b2, true)
		writeVersionFiles(t, filepath.Join(dir, "b2"), b2, byVID)
		code, text, rep := w.verify(w.honest, dir)
		if code != exitValid || jsonWitness(rep) != lyOK8 {
			t.Fatalf("два бакета: код %d %s\n%s", code, jsonWitness(rep), text)
		}
		mustHave(t, "два бакета", text, "head 8, the last of the heads each witness received first (S3 (versions list b1/versions.json): head 8, received first at 2026-11-08 10:00:25 UTC; S3 (versions list b2/versions.json): head 8, received first at 2026-11-08 10:00:28 UTC)",
			"0 of 16 entries are not such heads, 16 versions in the S3 versions list")
		mustNot(t, "два бакета", text, proof.WitnessUntimedNote)
	})
	t.Run("списки и файлы в корне", func(t *testing.T) {
		dir := t.TempDir()
		writeVersions(t, filepath.Join(dir, "versions-b1.json"), b1, false)
		writeVersions(t, filepath.Join(dir, "versions-b2.json"), b2, false)
		writeVersionFiles(t, dir, append(append([]lyObj(nil), b1...), b2...), byVID)
		code, text, rep := w.verify(w.honest, dir)
		if code != exitValid || jsonWitness(rep) != lyOK8 {
			t.Fatalf("два бакета в корне: код %d %s\n%s", code, jsonWitness(rep), text)
		}
		mustHave(t, "два бакета в корне", text, "S3 (versions list versions-b1.json): head 8, received first at 2026-11-08 10:00:25 UTC",
			"S3 (versions list versions-b2.json): head 8, received first at 2026-11-08 10:00:28 UTC")
	})
	t.Run("второй бакет начат позже", func(t *testing.T) {
		dir := t.TempDir()
		late := w.objs("witness", lyMinIO, 3*time.Second, 2, 3, 8, 10, 11, 12) // только 13 и 14
		writeVersions(t, filepath.Join(dir, "b1/versions.json"), b1, false)
		writeVersionFiles(t, filepath.Join(dir, "b1"), b1, byVID)
		writeVersions(t, filepath.Join(dir, "b2/versions.json"), late, false)
		writeVersionFiles(t, filepath.Join(dir, "b2"), late, byVID)
		code, text, _ := w.verify(w.honest, dir)
		if code != exitInvalid {
			t.Fatalf("второй бакет начат позже: код %d\n%s", code, text)
		}
		mustHave(t, "второй бакет начат позже", text, "before head 13 the witness received first, at 2026-11-08 10:12:08 UTC: request a bundle up to it (evidencestore proof -to-head 13)")
		code, text, rep := w.verify(w.bundleTo(13), dir)
		if code != exitValid || jsonWitness(rep) != "valid=true head=13 received=2026-11-08T10:12:08Z refused=0 fork=0" {
			t.Fatalf("пакет по совету: код %d %s\n%s", code, jsonWitness(rep), text)
		}
		mustHave(t, "пакет по совету", text, "S3 (versions list b1/versions.json): head 8, received first at 2026-11-08 10:00:25 UTC; S3 (versions list b2/versions.json): head 13, received first at 2026-11-08 10:12:08 UTC")
	})
	t.Run("по времени, а не по номеру", func(t *testing.T) {
		dir := t.TempDir()
		x1, x2 := late10(w.objs("witness", lyAWS, 0, 8)), late10(w.objs("witness", lyMinIO, 0, 8))
		writeVersions(t, filepath.Join(dir, "b1/versions.json"), x1, false)
		writeVersionFiles(t, filepath.Join(dir, "b1"), x1, byVID)
		writeVersions(t, filepath.Join(dir, "b2/versions.json"), x2, false)
		writeVersionFiles(t, filepath.Join(dir, "b2"), x2, byVID)
		w.byTime(t, "два бакета", dir, "2026-11-08 10:03:06 UTC")
	})
}

// Старый и новый список одного бакета: проверяющий снял список вчера и
// сегодня и положил оба.
func TestHeadsLayoutOldNewList(t *testing.T) {
	w := newLyWorld(t)
	all := w.objs("witness", lyAWS, 0)
	var old []lyObj
	for _, o := range all {
		if !o.at.After(lyDay(10, 1, 0)) {
			old = append(old, o)
		}
	}
	t.Run("в корне", func(t *testing.T) {
		dir := t.TempDir()
		writeVersions(t, filepath.Join(dir, "versions-20261108T1001.json"), old, false)
		writeVersions(t, filepath.Join(dir, "versions.json"), all, false)
		writeVersionFiles(t, dir, all, byVID)
		code, text, rep := w.verify(w.honest, dir)
		if code != exitValid || jsonWitness(rep) != lyOK8 {
			t.Fatalf("старый и новый список: код %d %s\n%s", code, jsonWitness(rep), text)
		}
		mustHave(t, "старый и новый список", text, "S3 (versions list versions-20261108T1001.json): head 8, received first at 2026-11-08 10:00:25 UTC",
			"S3 (versions list versions.json): head 8, received first at 2026-11-08 10:00:25 UTC")
	})
	t.Run("каждый в своём подкаталоге", func(t *testing.T) {
		dir := t.TempDir()
		writeVersions(t, filepath.Join(dir, "1001/versions.json"), old, false)
		writeVersionFiles(t, filepath.Join(dir, "1001"), old, byVID)
		writeVersions(t, filepath.Join(dir, "1300/versions.json"), all, false)
		writeVersionFiles(t, filepath.Join(dir, "1300"), all, byVID)
		code, text, rep := w.verify(w.honest, dir)
		if code != exitValid || jsonWitness(rep) != lyOK8 {
			t.Fatalf("старый и новый список в подкаталогах: код %d %s\n%s", code, jsonWitness(rep), text)
		}
	})
	t.Run("старый снят до записи", func(t *testing.T) {
		dir := t.TempDir()
		writeVersions(t, filepath.Join(dir, "versions-1000.json"), all[:2], false) // головы 2 и 3
		writeVersions(t, filepath.Join(dir, "versions.json"), all, false)
		writeVersionFiles(t, dir, all, byVID)
		code, text, rep := w.verify(w.honest, dir)
		if code != exitValid || jsonWitness(rep) != lyOK8 {
			t.Fatalf("старый список до записи: код %d %s\n%s", code, jsonWitness(rep), text)
		}
		mustHave(t, "старый список до записи", text, "head 8, which the witness received first, at 2026-11-08 10:00:25 UTC")
	})
}

// Сборщик со всеми тремя файлами (как пишет internal/collector/head.go:
// checkpoint.json — одна запись без перевода строки, журнал и расхождения —
// строками), без приставки в своём подкаталоге и с приставкой в корне: один
// свидетель, его последняя голова пакет не удлиняет.
func TestHeadsLayoutCollectorFiles(t *testing.T) {
	w := newLyWorld(t)
	journal := w.journal(uint64(8), lyDay(10, 0, 26), uint64(12), lyDay(10, 3, 6), uint64(14), lyDay(10, 12, 6))
	last := w.record(14, lyDay(10, 12, 6))
	conflict := w.conflict(14, 11, lyDay(10, 12, 30), "the store's chain went back from 14 links to 11")
	for _, l := range []struct{ name, prefix, label string }{
		{"в своём подкаталоге", "A/", "the collector's journal in A"},
		{"с приставкой в корне", "A-", "the collector's journal A-* in the heads directory"},
		{"с приставкой в подкаталоге", "spool/a.", "the collector's journal a.* in spool"},
	} {
		t.Run(l.name, func(t *testing.T) {
			dir := t.TempDir()
			lyWrite(t, filepath.Join(dir, l.prefix+"checkpoints.jsonl"), journal)
			lyWrite(t, filepath.Join(dir, l.prefix+"checkpoint.json"), last)
			lyWrite(t, filepath.Join(dir, l.prefix+"checkpoints-conflict.jsonl"), conflict)
			code, text, rep := w.verify(w.honest, dir)
			if code != exitValid || jsonWitness(rep) != "valid=true head=8 received=2026-11-08T10:00:26Z refused=1 fork=0" {
				t.Fatalf("три файла сборщика: код %d %s\n%s", code, jsonWitness(rep), text)
			}
			mustHave(t, l.name, text, "head 8, which the witness received first, at 2026-11-08 10:00:26 UTC",
				"3 heads signed with the store key, 0 of 6 entries are not such heads", "a collector refused 1 heads")
			mustNot(t, l.name, text, proof.WitnessUntimedNote)
			// Тот же свидетель в отчёте под своим именем, когда свидетелей два.
			lyWrite(t, filepath.Join(dir, "mail/statement.json"), w.statements["1002"])
			_, text, _ = w.verify(w.honest, dir)
			mustHave(t, l.name+", с газетой", text, l.label+": head 8, received first at 2026-11-08 10:00:26 UTC")
		})
	}
	t.Run("сборщик пишет редко", func(t *testing.T) {
		dir := t.TempDir()
		lyWrite(t, filepath.Join(dir, "A/checkpoints.jsonl"), w.journal(uint64(12), lyDay(10, 3, 6), uint64(14), lyDay(10, 12, 6)))
		lyWrite(t, filepath.Join(dir, "A/checkpoint.json"), last)
		code, text, _ := w.verify(w.honest, dir)
		if code != exitInvalid {
			t.Fatalf("сборщик пишет редко: код %d\n%s", code, text)
		}
		mustHave(t, "сборщик пишет редко", text, "before head 12 the witness received first, at 2026-11-08 10:03:06 UTC: request a bundle up to it (evidencestore proof -to-head 12)")
		code, text, rep := w.verify(w.bundleTo(12), dir)
		if code != exitValid || jsonWitness(rep) != "valid=true head=12 received=2026-11-08T10:03:06Z refused=0 fork=0" {
			t.Fatalf("пакет по совету: код %d %s\n%s", code, jsonWitness(rep), text)
		}
	})
}

// Сборщики в одном каталоге под разными именами: каждый — свой свидетель.
func TestHeadsLayoutCollectorsOneDir(t *testing.T) {
	w := newLyWorld(t)
	t.Run("приставки", func(t *testing.T) {
		dir := t.TempDir()
		lyWrite(t, filepath.Join(dir, "A-checkpoints.jsonl"), w.journal(uint64(8), lyDay(10, 0, 26), uint64(12), lyDay(10, 3, 6)))
		lyWrite(t, filepath.Join(dir, "A-checkpoint.json"), w.record(12, lyDay(10, 3, 6)))
		lyWrite(t, filepath.Join(dir, "B-checkpoints.jsonl"), w.journal(uint64(8), lyDay(10, 0, 27), uint64(14), lyDay(10, 12, 7)))
		lyWrite(t, filepath.Join(dir, "B-checkpoint.json"), w.record(14, lyDay(10, 12, 7)))
		code, text, rep := w.verify(w.honest, dir)
		if code != exitValid || jsonWitness(rep) != "valid=true head=8 received=2026-11-08T10:00:26Z refused=0 fork=0" {
			t.Fatalf("два сборщика с приставками: код %d %s\n%s", code, jsonWitness(rep), text)
		}
		mustHave(t, "два сборщика с приставками", text,
			"(the collector's journal A-* in the heads directory: head 8, received first at 2026-11-08 10:00:26 UTC; the collector's journal B-* in the heads directory: head 8, received first at 2026-11-08 10:00:27 UTC)")
	})
	t.Run("свои имена", func(t *testing.T) {
		dir := t.TempDir()
		lyWrite(t, filepath.Join(dir, "spool/collector-a.jsonl"), w.journal(uint64(8), lyDay(10, 0, 26)))
		lyWrite(t, filepath.Join(dir, "spool/collector-b.jsonl"), w.journal(uint64(10), lyDay(10, 3, 6)))
		code, text, rep := w.verify(w.honest, dir)
		if code != exitValid || jsonWitness(rep) != "valid=true head=10 received=2026-11-08T10:03:06Z refused=0 fork=0" {
			t.Fatalf("два сборщика под своими именами: код %d %s\n%s", code, jsonWitness(rep), text)
		}
		mustHave(t, "два сборщика под своими именами", text, "the collector's journal collector-a.jsonl in spool: head 8, received first at 2026-11-08 10:00:26 UTC",
			"the collector's journal collector-b.jsonl in spool: head 10, received first at 2026-11-08 10:03:06 UTC")
	})
}

// Газета: evidencestore statement, раз в день письмом. Без времени —
// первая по номеру с заметкой; совет исполним.
func TestHeadsLayoutNewspaper(t *testing.T) {
	w := newLyWorld(t)
	s1002, err := proof.ParseCheckpoint(w.statements["1002"])
	if err != nil {
		t.Fatal(err)
	}
	s1015, err := proof.ParseCheckpoint(w.statements["1015"])
	if err != nil {
		t.Fatal(err)
	}
	if s1002.Size != 9 || s1015.Size != 14 {
		t.Fatalf("газета: головы %d и %d", s1002.Size, s1015.Size)
	}
	dir := t.TempDir()
	lyWrite(t, filepath.Join(dir, "mail/2026-11-08-1015.json"), w.statements["1015"])
	code, text, _ := w.verify(w.honest, dir)
	if code != exitInvalid {
		t.Fatalf("газета после пакета: код %d\n%s", code, text)
	}
	mustHave(t, "газета после пакета", text, "the bundle ends at link 10, before head 14 the witness saw: request a bundle up to it (evidencestore proof -to-head 14)")
	code, text, rep := w.verify(w.bundleTo(14), dir)
	if code != exitValid || jsonWitness(rep) != "valid=true head=14 received=<nil> refused=0 fork=0" {
		t.Fatalf("газета, пакет по совету: код %d %s\n%s", code, jsonWitness(rep), text)
	}
	mustHave(t, "газета, пакет по совету", text, "head 14, which the witness saw", proof.WitnessUntimedNote)

	lyWrite(t, filepath.Join(dir, "mail/2026-11-08-1002.json"), w.statements["1002"])
	code, text, rep = w.verify(w.honest, dir)
	if code != exitValid || jsonWitness(rep) != "valid=true head=9 received=<nil> refused=0 fork=0" {
		t.Fatalf("две газеты: код %d %s\n%s", code, jsonWitness(rep), text)
	}
	mustHave(t, "две газеты", text, "head 9, which the witness saw", proof.WitnessUntimedNote)
}

// Все вместе: S3 со списком, сборщик, газета.
func TestHeadsLayoutMixed(t *testing.T) {
	w := newLyWorld(t)
	dir := t.TempDir()
	objs := w.objs("witness", lyAWS, 0)
	writeVersions(t, filepath.Join(dir, "s3/versions.json"), objs, false)
	writeVersionFiles(t, filepath.Join(dir, "s3"), objs, byVID)
	lyWrite(t, filepath.Join(dir, "collector/checkpoints.jsonl"), w.journal(uint64(8), lyDay(10, 0, 26), uint64(12), lyDay(10, 3, 6)))
	lyWrite(t, filepath.Join(dir, "collector/checkpoint.json"), w.record(12, lyDay(10, 3, 6)))
	lyWrite(t, filepath.Join(dir, "mail/2026-11-08.json"), w.statements["1002"])
	code, text, rep := w.verify(w.honest, dir)
	if code != exitValid || jsonWitness(rep) != "valid=true head=9 received=<nil> refused=0 fork=0" {
		t.Fatalf("смешанный каталог: код %d %s\n%s", code, jsonWitness(rep), text)
	}
	mustHave(t, "смешанный каталог", text, "head 9, the last of the heads each witness received first (S3 (versions list s3/versions.json): head 8, received first at 2026-11-08 10:00:25 UTC; heads without a time of receipt in mail: head 9, first by number; the collector's journal in collector: head 8, received first at 2026-11-08 10:00:26 UTC)",
		proof.WitnessUntimedNote)
}

// Объекты в бакете в форме файлов сборщика (их пишет тот, у кого ключи
// записи): строка журнала с ранним received_at, checkpoint.json, строка
// расхождений, называющая честную голову 10 отвергнутой, два журнала строк.
// Голова из них — только голова со временем версии (P-96, P-100): честный
// пакет проходит, как без них.
func TestHeadsLayoutBucketCollectorForms(t *testing.T) {
	w := newLyWorld(t)
	early := lyDay(9, 0, 0)
	objs := w.objs("witness", lyAWS, 0)
	key := func(n uint64) string { return fmt.Sprintf("witness/heads/%020d.json", n) }
	objs = append(objs,
		lyObj{key: key(13), vid: "x-journal", seq: 13, data: w.journal(uint64(13), early), at: lyDay(10, 20, 0)},
		lyObj{key: key(14), vid: "x-conflict", seq: 14, data: w.conflict(12, 10, early, "the store signed two different heads of 10 links"), at: lyDay(10, 20, 1)},
		lyObj{key: key(12), vid: "x-last", seq: 12, data: w.record(12, early), at: lyDay(10, 20, 2)},
		lyObj{key: key(11), vid: "x-two", seq: 11, data: w.journal(uint64(10), early, uint64(11), early), at: lyDay(10, 20, 3)},
	)
	for _, l := range []struct {
		name string
		file func(lyObj) string
	}{{"плоско", byVID}, {"по ключам", func(o lyObj) string { return o.key + "/" + o.vid + ".json" }}} {
		t.Run(l.name, func(t *testing.T) {
			dir := t.TempDir()
			writeVersions(t, filepath.Join(dir, "versions.json"), objs, false)
			writeVersionFiles(t, dir, objs, l.file)
			code, text, rep := w.verify(w.honest, dir)
			if code != exitValid || jsonWitness(rep) != lyOK8 {
				t.Fatalf("объекты в форме файлов сборщика: код %d %s\n%s", code, jsonWitness(rep), text)
			}
			mustHave(t, l.name, text, "head 8, which the witness received first, at 2026-11-08 10:00:25 UTC",
				"8 heads signed with the store key, 0 of 14 entries are not such heads, 12 versions in the S3 versions list")
			mustNot(t, l.name, text, "collector", "09:00:00", proof.WitnessUntimedNote)
		})
	}
}
