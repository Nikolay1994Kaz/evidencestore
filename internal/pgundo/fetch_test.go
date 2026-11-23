package pgundo

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Nikolay1994Kaz/evidencestore/internal/config"
)

// Записи транзакции достаются из хранилища по номерам из справочника: пакет на
// каждую, тело — только после проверки. Запись, которой в хранилище ещё нет,
// ждут; транзакцию, которой нет в справочнике, — тоже, но не дольше Wait.
func TestFetchTakesTheRecordsNamedByTheIndex(t *testing.T) {
	dir := t.TempDir()
	store := filepath.Join(dir, "store")
	os.Mkdir(store, 0o700)
	for seq, body := range map[int]string{5: "part one", 6: "part two", 7: "another transaction"} {
		os.WriteFile(filepath.Join(store, fmt.Sprint(seq)), []byte(body), 0o600)
	}
	index := filepath.Join(dir, "index.jsonl")
	// Первая строка о транзакции 9 устарела (сборщик упал до последней части):
	// верна последняя.
	os.WriteFile(index, []byte(`{"xid":9,"first_seq":3,"last_seq":4,"commit_lsn":"0/1"}`+"\n"+
		`{"xid":9,"first_seq":5,"last_seq":6,"commit_lsn":"0/1"}`+"\n"), 0o600)
	// Выдача пакета: «-seq N -out FILE» — запись N хранилища в FILE. Первая
	// попытка на каждую запись не удаётся: запись ещё не дошла до хранилища.
	proof := []string{"sh", "-c", `test -e "` + dir + `/tried-$2" || { touch "` + dir + `/tried-$2"; echo "not in the store yet" >&2; exit 1; }; cp "` + store + `/$2" "$4"`, "proof"}
	// Проверка: «-proof FILE -body FILE».
	verify := []string{"sh", "-c", `cp "$2" "$4"; echo verified >>"` + dir + `/verified"`, "verify"}
	f := &Fetcher{Index: "index.jsonl", Proof: proof, Verify: verify, Stamp: []string{"sh", "-c", `echo stamp >>"` + dir + `/stamps"`}}
	if err := f.Validate(dir); err != nil {
		t.Fatal(err)
	}
	if f.Index != index || f.Wait.D() != 15*time.Second {
		t.Fatalf("defaults: %+v", f)
	}
	lines, err := f.Fetch(9)
	if err != nil {
		t.Fatal(err)
	}
	if len(lines) != 2 || string(lines[0]) != "part one" || string(lines[1]) != "part two" {
		t.Fatalf("fetched %q", lines)
	}
	if data, _ := os.ReadFile(filepath.Join(dir, "verified")); strings.Count(string(data), "verified") != 2 {
		t.Fatalf("verify ran: %q", data)
	}
	if data, _ := os.ReadFile(filepath.Join(dir, "stamps")); strings.Count(string(data), "stamp") != 4 {
		t.Fatalf("stamp ran before each of the four proof attempts: %q", data)
	}

	// Проверка не прошла — тела нет, ошибка называет запись и причину.
	f.Wait = config.Duration(50 * time.Millisecond)
	f.Verify = []string{"sh", "-c", `echo "NOT VERIFIED: the bundle does not match the pinned store key" >&2; exit 1`, "verify"}
	if _, err := f.Fetch(9); err == nil || !strings.Contains(err.Error(), "record 5") || !strings.Contains(err.Error(), "NOT VERIFIED") {
		t.Fatalf("an unverified record was taken: %v", err)
	}
	if _, err := f.Fetch(10); err == nil || !strings.Contains(err.Error(), "not in the collector's index") {
		t.Fatalf("a transaction that is not in the index: %v", err)
	}
	for name, bad := range map[string]*Fetcher{"no index": {Proof: proof, Verify: verify}, "no proof": {Index: "i", Verify: verify}, "no verify": {Index: "i", Proof: proof}} {
		if err := bad.Validate(dir); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

// Транзакция без намерения шлюза — в справочнике отпечатком: откатить её из
// хранилища нечем, и Fetch говорит это, не трогая хранилище (DECISIONS, п. 42).
func TestFetchRefusesAFingerprint(t *testing.T) {
	dir := t.TempDir()
	index := filepath.Join(dir, "index.jsonl")
	if err := os.WriteFile(index, []byte(`{"xid":77,"kind":"fingerprint","first_seq":5,"last_seq":5,"changes":1}`+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	f := &Fetcher{Index: index, Proof: []string{"false"}, Verify: []string{"false"}}
	if _, err := f.Fetch(77); !errors.Is(err, ErrRefused) || !strings.Contains(err.Error(), "did not come through the gateway") || !strings.Contains(err.Error(), "in record 5") {
		t.Fatalf("%v", err)
	}
}
