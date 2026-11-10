package main

import (
	"crypto/md5"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Nikolay1994Kaz/evidencestore/internal/proof"
)

// Реалистичные каталоги проверяющего через CLI esverify -heads DIR (тестировщик
// T, 08.11). Честная голова H пакета раскладывается по свидетелям так, как её
// кладут настоящие инструменты: документы S3 (versions.json + <vid>.json, CLI
// v1 и v2, MinIO), журналы сборщиков в своих подкаталогах и в корне, газета
// evidencestore statement, вложенные пути. Проверяется: честный пакет проходит;
// отчёт и -json верны (голова, время, заметка «без времени»); лишний файл не
// ослабляет; неполный список версий даёт исполнимый совет.

type cliHeads struct {
	w    world
	head proof.Checkpoint
	seq  uint64
}

func cliWorld(t *testing.T) cliHeads {
	t.Helper()
	w := newWorld(t)
	data, err := os.ReadFile(w.bundle)
	if err != nil {
		t.Fatal(err)
	}
	b, err := proof.Parse(data)
	if err != nil {
		t.Fatal(err)
	}
	return cliHeads{w: w, head: b.Checkpoint, seq: b.Checkpoint.Size}
}

func (c cliHeads) headJSON(t *testing.T) []byte {
	t.Helper()
	d, err := c.head.JSON()
	if err != nil {
		t.Fatal(err)
	}
	return d
}

func writeFile(t *testing.T, dir, name string, data []byte) {
	t.Helper()
	p := filepath.Join(dir, name)
	if err := os.MkdirAll(filepath.Dir(p), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, data, 0o600); err != nil {
		t.Fatal(err)
	}
}

func etagOf(data []byte) string {
	sum := md5.Sum(data)
	return hex.EncodeToString(sum[:])
}

// versionsJSON строит корректный список версий для набора (key, vid, etag, time).
func versionsJSON(entries ...map[string]string) []byte {
	var vs []map[string]any
	dm := []any{}
	for _, e := range entries {
		vs = append(vs, map[string]any{"Key": e["key"], "VersionId": e["vid"],
			"ETag": `"` + e["etag"] + `"`, "LastModified": e["at"], "IsLatest": true, "Size": 1})
	}
	out, _ := json.Marshal(map[string]any{"Versions": vs, "DeleteMarkers": dm})
	return out
}

func collectorLine(t *testing.T, head proof.Checkpoint, at string) []byte {
	t.Helper()
	var c map[string]any
	hj, _ := head.JSON()
	_ = json.Unmarshal(hj, &c)
	data, err := json.Marshal(map[string]any{"received_at": at, "checkpoint": c})
	if err != nil {
		t.Fatal(err)
	}
	return append(data, '\n')
}

func TestHeadsRealisticDirs(t *testing.T) {
	// S3 документами, CLI v2: versions.json + <vid>.json в своём подкаталоге.
	t.Run("s3-v2-documents", func(t *testing.T) {
		c := cliWorld(t)
		dir := filepath.Join(c.w.dir, "s3v2")
		head := c.headJSON(t)
		writeFile(t, dir, "v-7.json", head)
		key := fmt.Sprintf("backups/abs/heads/%020d.json", c.seq)
		writeFile(t, dir, "versions.json", versionsJSON(map[string]string{
			"key": key, "vid": "v-7", "etag": etagOf(head), "at": "2026-10-26T10:11:00+00:00"}))
		code, out := c.w.run(t, "-heads", dir, "-json")
		var rep map[string]any
		if err := json.Unmarshal([]byte(out), &rep); err != nil || code != exitValid ||
			rep["witness_head"] != float64(c.seq) || rep["witness_received"] != "2026-10-26T10:11:00Z" {
			t.Fatalf("S3 v2: код %d, %v\n%s", code, err, out)
		}
		if code, out := c.w.run(t, "-heads", dir); code != exitValid ||
			!strings.Contains(out, "received first, at 2026-10-26 10:11:00 UTC") || strings.Contains(out, proof.WitnessUntimedNote) {
			t.Fatalf("S3 v2 текст: код %d\n%s", code, out)
		}
	})

	// S3 документами, CLI v1: время «…000Z».
	t.Run("s3-v1-documents", func(t *testing.T) {
		c := cliWorld(t)
		dir := filepath.Join(c.w.dir, "s3v1")
		head := c.headJSON(t)
		writeFile(t, dir, "v-1.json", head)
		key := fmt.Sprintf("w/heads/%020d.json", c.seq)
		writeFile(t, dir, "versions.json", versionsJSON(map[string]string{
			"key": key, "vid": "v-1", "etag": etagOf(head), "at": "2026-10-26T10:12:00.000Z"}))
		code, out := c.w.run(t, "-heads", dir, "-json")
		var rep map[string]any
		if err := json.Unmarshal([]byte(out), &rep); err != nil || code != exitValid ||
			rep["witness_received"] != "2026-10-26T10:12:00Z" {
			t.Fatalf("S3 v1: код %d, %v\n%s", code, err, out)
		}
	})

	// Несколько сборщиков, каждый в своём подкаталоге: оба со временем, пакет
	// доходит до головы каждого; отчёт называет обоих.
	t.Run("collectors-own-subdirs", func(t *testing.T) {
		c := cliWorld(t)
		dir := filepath.Join(c.w.dir, "collectors")
		writeFile(t, dir, "A/checkpoints.jsonl", collectorLine(t, c.head, "2026-10-26T10:11:00Z"))
		writeFile(t, dir, "A/checkpoint.json", collectorLine(t, c.head, "2026-10-26T10:21:00Z")) // последняя голова — как пишет сборщик
		writeFile(t, dir, "B/checkpoints.jsonl", collectorLine(t, c.head, "2026-10-26T10:13:00Z"))
		code, out := c.w.run(t, "-heads", dir, "-json")
		var rep map[string]any
		if err := json.Unmarshal([]byte(out), &rep); err != nil || code != exitValid || rep["witness_head"] != float64(c.seq) {
			t.Fatalf("два сборщика: код %d, %v\n%s", code, err, out)
		}
		if code, out := c.w.run(t, "-heads", dir); code != exitValid || strings.Contains(out, proof.WitnessUntimedNote) ||
			!strings.Contains(out, "the collector's journal in A: head") || !strings.Contains(out, "the collector's journal in B: head") {
			t.Fatalf("два сборщика, текст: код %d\n%s", code, out)
		}
	})

	// Сборщик в корне каталога (dir == "."): «the heads directory».
	t.Run("collector-at-root", func(t *testing.T) {
		c := cliWorld(t)
		dir := filepath.Join(c.w.dir, "rootcoll")
		writeFile(t, dir, "checkpoints.jsonl", collectorLine(t, c.head, "2026-10-26T10:11:00Z"))
		if code, out := c.w.run(t, "-heads", dir); code != exitValid || !strings.Contains(out, "received first, at 2026-10-26 10:11:00 UTC") {
			t.Fatalf("сборщик в корне: код %d\n%s", code, out)
		}
	})

	// Газета evidencestore statement (голова без времени) + сборщик со временем:
	// свидетель без времени закрепляет по номеру, заметка есть.
	t.Run("newspaper-plus-collector", func(t *testing.T) {
		c := cliWorld(t)
		dir := filepath.Join(c.w.dir, "mixed")
		writeFile(t, dir, "statement.json", c.headJSON(t)) // газета: голова без времени, в корне
		writeFile(t, dir, "collA/checkpoints.jsonl", collectorLine(t, c.head, "2026-10-26T10:11:00Z"))
		code, out := c.w.run(t, "-heads", dir, "-json")
		var rep map[string]any
		if err := json.Unmarshal([]byte(out), &rep); err != nil || code != exitValid || rep["witness_head"] != float64(c.seq) {
			t.Fatalf("газета+сборщик: код %d, %v\n%s", code, err, out)
		}
		if code, out := c.w.run(t, "-heads", dir); code != exitValid || !strings.Contains(out, proof.WitnessUntimedNote) ||
			!strings.Contains(out, "heads without a time of receipt in the heads directory") {
			t.Fatalf("газета+сборщик, заметка: код %d\n%s", code, out)
		}
	})

	// Смешанная вложенная раскладка: S3 в nested/s3, сборщик в nested/deep/coll.
	t.Run("nested-mixed", func(t *testing.T) {
		c := cliWorld(t)
		dir := filepath.Join(c.w.dir, "nest")
		head := c.headJSON(t)
		writeFile(t, dir, "s3/v-9.json", head)
		key := fmt.Sprintf("p/heads/%020d.json", c.seq)
		writeFile(t, dir, "s3/versions.json", versionsJSON(map[string]string{
			"key": key, "vid": "v-9", "etag": etagOf(head), "at": "2026-10-26T10:10:00+00:00"}))
		writeFile(t, dir, "deep/coll/checkpoints.jsonl", collectorLine(t, c.head, "2026-10-26T10:15:00Z"))
		code, out := c.w.run(t, "-heads", dir, "-json")
		var rep map[string]any
		if err := json.Unmarshal([]byte(out), &rep); err != nil || code != exitValid {
			t.Fatalf("вложенная раскладка: код %d, %v\n%s", code, err, out)
		}
		// S3 получил голову в 10:10, сборщик в 10:15 — закрепляет голова каждого,
		// самое раннее время у S3; witness_received — время самой дальней головы
		// (один номер у всех) = самое раннее.
		if code, out := c.w.run(t, "-heads", dir); code != exitValid ||
			!strings.Contains(out, "S3 (versions list s3/versions.json)") || !strings.Contains(out, "the collector's journal in deep/coll") {
			t.Fatalf("вложенная раскладка, текст: код %d\n%s", code, out)
		}
	})

	// Лишний файл в каталоге не ослабляет: посторонний текст и копия головы
	// рядом не отменяют заметку «без времени» и не ломают честный пакет.
	t.Run("stray-file-does-not-weaken", func(t *testing.T) {
		c := cliWorld(t)
		dir := filepath.Join(c.w.dir, "stray")
		writeFile(t, dir, "statement.json", c.headJSON(t)) // газета без времени
		_, base := c.w.run(t, "-heads", dir)
		if !strings.Contains(base, proof.WitnessUntimedNote) {
			t.Fatalf("без лишнего файла заметки нет:\n%s", base)
		}
		writeFile(t, dir, "README.txt", []byte("notes for the auditor"))
		writeFile(t, dir, "sub/random.json", []byte(`{"hello":"world"}`))
		code, out := c.w.run(t, "-heads", dir)
		if code != exitValid || !strings.Contains(out, proof.WitnessUntimedNote) {
			t.Fatalf("лишний файл убрал заметку/сломал пакет: код %d\n%s", code, out)
		}
	})

	// Неполный список версий: версия названа, файла нет — честный пакет не
	// проходит, и совет исполним (скачать все версии).
	t.Run("incomplete-versions-list-advice", func(t *testing.T) {
		c := cliWorld(t)
		dir := filepath.Join(c.w.dir, "incomplete")
		head := c.headJSON(t)
		writeFile(t, dir, "v-1.json", head)
		key := fmt.Sprintf("w/heads/%020d.json", c.seq)
		writeFile(t, dir, "versions.json", versionsJSON(
			map[string]string{"key": key, "vid": "v-1", "etag": etagOf(head), "at": "2026-10-26T10:11:00+00:00"},
			map[string]string{"key": key, "vid": "v-2", "etag": "00112233445566778899aabbccddeeff", "at": "2026-10-26T10:09:00+00:00"}))
		code, out := c.w.run(t, "-heads", dir)
		if code != exitInvalid || !strings.Contains(out, `version "v-2"`) || !strings.Contains(out, "download every version of the heads") {
			t.Fatalf("неполный список: код %d\n%s", code, out)
		}
	})
}
