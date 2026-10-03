package gateway

import (
	"bufio"
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"testing"
	"time"
)

// Настоящий бортовой журнал Pipelock v3.6.0 (testdata/pipelock-v3.6.0,
// VERSION — тег и коммит): сессия из 34 записей в 5 шардах с 6 подписанными
// контрольными точками, вторая сессия после перезапуска и копия первого
// шарда с одним изменённым байтом в summary записи seq 2. Его же цепочку
// принимают сам Pipelock (CLI и VerifyChain) и независимая проверка на
// Python; испорченную копию все отвергают на seq 2.
const vectors = "testdata/pipelock-v3.6.0"

func vectorKey(t *testing.T) []byte {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join(vectors, "pubkey.hex"))
	if err != nil {
		t.Fatal(err)
	}
	k, err := ParseKey(string(raw))
	if err != nil {
		t.Fatal(err)
	}
	return k
}

// fileLines — строки файла как есть, без перевода строки.
func fileLines(t *testing.T, path string) [][]byte {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var out [][]byte
	sc := bufio.NewScanner(bytes.NewReader(data))
	sc.Buffer(nil, 1<<20)
	for sc.Scan() {
		out = append(out, append([]byte(nil), sc.Bytes()...))
	}
	if err := sc.Err(); err != nil {
		t.Fatal(err)
	}
	return out
}

// sessionLines — строки шардов сессии по порядку. Шард называется
// evidence-<сессия>-<seq первой записи>.jsonl; порядок — по числу, а не по
// строке: «-16» идёт после «-8».
func sessionLines(t *testing.T, dir string) [][]byte {
	t.Helper()
	paths, err := filepath.Glob(filepath.Join(dir, "evidence-*.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	first := func(p string) int {
		n, err := strconv.Atoi(strings.TrimSuffix(p[strings.LastIndexByte(p, '-')+1:], ".jsonl"))
		if err != nil {
			t.Fatalf("имя шарда %s: %v", p, err)
		}
		return n
	}
	sort.Slice(paths, func(i, j int) bool { return first(paths[i]) < first(paths[j]) })
	var out [][]byte
	for _, p := range paths {
		out = append(out, fileLines(t, p)...)
	}
	return out
}

// ⭐ Хэши и подписи Pipelock повторяются байт в байт: все записи целы и
// сцеплены, все контрольные точки подписаны закреплённым ключом.
func TestPipelockRecorderVectors(t *testing.T) {
	tr := NewTracker(vectorKey(t))
	checkpoints := 0
	for _, s := range []struct {
		dir     string
		entries int
	}{
		{filepath.Join(vectors, "session1"), 34},
		{filepath.Join(vectors, "session2"), 0}, // после перезапуска — своя цепочка с genesis
	} {
		lines := sessionLines(t, s.dir)
		if s.entries != 0 && len(lines) != s.entries {
			t.Fatalf("%s: %d записей, ожидали %d", s.dir, len(lines), s.entries)
		}
		for i, l := range lines {
			v := tr.Check(l)
			want := LinkOK
			if i == 0 {
				want = LinkGenesis
			}
			if !v.Clean() || v.Link != want || v.Seq != uint64(i) {
				t.Fatalf("%s, запись %d: %+v", s.dir, i, v)
			}
			if v.Type == "checkpoint" {
				checkpoints++
				if v.Signature != SigValid {
					t.Fatalf("контрольная точка seq %d: %s", v.Seq, v.Signature)
				}
			}
		}
	}
	if checkpoints < 6 {
		t.Fatalf("контрольных точек %d, в первой сессии их 6", checkpoints)
	}
}

// Один изменённый байт в summary записи seq 2: хэш этой записи не сходится,
// остальные целы. Сцепка не рвётся — prev_hash следующей указывает на
// заявленный хэш, — поэтому ловит именно пересчёт хэша.
func TestPipelockTamperedEntry(t *testing.T) {
	tr := NewTracker(vectorKey(t))
	caught := false
	for _, l := range fileLines(t, filepath.Join(vectors, "tampered.jsonl")) {
		v := tr.Check(l)
		if v.Seq == 2 {
			caught = !v.HashOK && !v.Clean() && v.Problem != ""
			continue
		}
		if !v.Clean() {
			t.Fatalf("запись seq %d задета чужой порчей: %+v", v.Seq, v)
		}
	}
	if !caught {
		t.Fatal("изменённая запись seq 2 прошла проверку")
	}
}

// detail хэшируется байтами из строки. Перекодированный (Go экранирует
// & < > и меняет порядок ключей) он уже не сходится — поэтому разбор не
// трогает его байты.
func TestDetailBytesAreHashedAsWritten(t *testing.T) {
	for _, l := range sessionLines(t, filepath.Join(vectors, "session1")) {
		e, err := ParseEntry(l)
		if err != nil {
			t.Fatal(err)
		}
		var generic any
		if err := json.Unmarshal(e.Detail, &generic); err != nil {
			t.Fatal(err)
		}
		re, _ := json.Marshal(generic)
		if bytes.Equal(re, e.Detail) {
			continue
		}
		e.Detail = re
		if h, _ := e.ComputeHash(); h == e.Hash {
			t.Fatalf("seq %d: хэш сошёлся и после перекодирования detail", e.Seq)
		}
		return
	}
	t.Fatal("в векторах нет записи, чей detail меняется при перекодировании")
}

// Pipelock хэширует время, приведённое к UTC и записанное заново: та же
// минута, записанная со смещением, даёт тот же хэш. Значит, и проверка
// обязана приводить время, а не хэшировать строку из файла.
func TestTimestampNormalizedLikePipelock(t *testing.T) {
	line := sessionLines(t, filepath.Join(vectors, "session1"))[0]
	e, err := ParseEntry(line)
	if err != nil {
		t.Fatal(err)
	}
	ts := e.Timestamp.UTC().Format(time.RFC3339Nano)
	shifted := e.Timestamp.In(time.FixedZone("+05", 5*3600)).Format(time.RFC3339Nano)
	if ts == shifted {
		t.Fatal("сдвиг времени не изменил строку")
	}
	moved := bytes.Replace(line, []byte(`"ts":"`+ts+`"`), []byte(`"ts":"`+shifted+`"`), 1)
	if bytes.Equal(moved, line) {
		t.Fatalf("в строке нет %q", ts)
	}
	if v := NewTracker(nil).Check(moved); !v.HashOK {
		t.Fatalf("время со смещением: %+v", v)
	}
}
