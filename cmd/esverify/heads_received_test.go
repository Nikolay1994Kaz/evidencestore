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

// P-21 через esverify: каталог голов с выводом aws s3api list-object-versions.
// Голова пакета, скачанная по версии, находит в списке своё время получения;
// отчёт и -json его называют. Без списка — первая по номеру и замечание.
func TestHeadsReceivedTimes(t *testing.T) {
	w := newWorld(t)
	data, err := os.ReadFile(w.bundle)
	if err != nil {
		t.Fatal(err)
	}
	b, err := proof.Parse(data)
	if err != nil {
		t.Fatal(err)
	}
	head, _ := b.Checkpoint.JSON()
	dir := filepath.Join(w.dir, "witness-s3")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "v-1.json"), head, 0o600); err != nil {
		t.Fatal(err)
	}
	code, out := w.run(t, "-heads", dir)
	if code != exitValid || !strings.Contains(out, proof.WitnessUntimedNote) {
		t.Fatalf("без списка версий: код %d\n%s", code, out)
	}

	sum := md5.Sum(head)
	list := fmt.Sprintf(`{"Versions":[{"Key":"w/heads/%020d.json","VersionId":"v-1","ETag":"\"%s\"","LastModified":"2026-10-26T10:11:00+00:00","IsLatest":true}],"DeleteMarkers":[]}`,
		b.Checkpoint.Size, hex.EncodeToString(sum[:]))
	if err := os.WriteFile(filepath.Join(dir, "versions.json"), []byte(list), 0o600); err != nil {
		t.Fatal(err)
	}
	code, out = w.run(t, "-heads", dir, "-json")
	var rep map[string]any
	if err := json.Unmarshal([]byte(out), &rep); err != nil || code != exitValid || rep["witness_head"] != float64(b.Checkpoint.Size) ||
		rep["witness_received"] != "2026-10-26T10:11:00Z" {
		t.Fatalf("со списком версий: код %d, %v\n%s", code, err, out)
	}
	if code, out := w.run(t, "-heads", dir); code != exitValid || !strings.Contains(out, "which the witness received first, at 2026-10-26 10:11:00 UTC") ||
		strings.Contains(out, proof.WitnessUntimedNote) {
		t.Fatalf("отчёт со списком версий: код %d\n%s", code, out)
	}
}

// Пакеты за окно и по источнику через esverify: время закрепляющей головы — в
// -json, без списка версий — null (тестировщик T, 08.11).
func TestHeadsReceivedWindowSource(t *testing.T) {
	w := newSubjectWorld(t)
	src, err := w.s.ProofSource("agent", w.from, w.to, false, 0)
	if err != nil {
		t.Fatal(err)
	}
	win, err := w.s.ProofWindow(w.from, w.to, "", false, 0)
	if err != nil {
		t.Fatal(err)
	}
	for name, c := range map[string]struct {
		bundle any
		head   proof.Checkpoint
	}{"source": {src, src.Checkpoint}, "window": {win, win.Checkpoint}} {
		bundle := w.file(t, name+".json", c.bundle)
		dir := filepath.Join(w.dir, "heads-"+name)
		head, err := c.head.JSON()
		if err != nil {
			t.Fatal(err)
		}
		if err := os.MkdirAll(dir, 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dir, "v-1.json"), head, 0o600); err != nil {
			t.Fatal(err)
		}
		var rep map[string]any
		code, out, _ := w.run(t, bundle, "-heads", dir, "-json")
		if err := json.Unmarshal([]byte(out), &rep); err != nil || code != exitValid || rep["witness_head"] != float64(c.head.Size) ||
			rep["witness_received"] != nil {
			t.Fatalf("%s без списка версий: код %d, %v\n%s", name, code, err, out)
		}
		sum := md5.Sum(head)
		list := fmt.Sprintf(`{"Versions":[{"Key":"w/heads/%020d.json","VersionId":"v-1","ETag":"\"%s\"","LastModified":"2026-10-26T10:11:00+00:00"}]}`,
			c.head.Size, hex.EncodeToString(sum[:]))
		if err := os.WriteFile(filepath.Join(dir, "versions.json"), []byte(list), 0o600); err != nil {
			t.Fatal(err)
		}
		code, out, _ = w.run(t, bundle, "-heads", dir, "-json")
		if err := json.Unmarshal([]byte(out), &rep); err != nil || code != exitValid || rep["witness_received"] != "2026-10-26T10:11:00Z" {
			t.Fatalf("%s со списком версий: код %d, %v\n%s", name, code, err, out)
		}
	}
}
