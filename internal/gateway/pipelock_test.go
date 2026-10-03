package gateway

import (
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"
	"testing"
)

// line — запись журнала с заданными полями; хэш произвольный: эти тесты
// проверяют сцепку и подписи, а не проекцию (её проверяют настоящие файлы
// Pipelock в vectors_test.go).
func line(seq uint64, prev, hash, typ string, detail any) []byte {
	d, _ := json.Marshal(detail)
	return fmt.Appendf(nil, `{"v":2,"seq":%d,"ts":"2026-10-03T10:00:00Z","session_id":"s1","type":%q,"transport":"forward","summary":"x","detail":%s,"prev_hash":%q,"hash":%q}`,
		seq, typ, d, prev, hash)
}

func TestLinkOutcomes(t *testing.T) {
	tr := NewTracker(nil)
	for i, tc := range []struct {
		line []byte
		want string
	}{
		{line(0, Genesis, "h0", "request", nil), LinkGenesis},
		{line(1, "h0", "h1", "request", nil), LinkOK},
		{line(3, "h2", "h3", "request", nil), LinkBroken}, // запись 2 пропала
		{line(4, "h3", "h4", "request", nil), LinkOK},     // одна поломка — одна ошибка
	} {
		if got := tr.Check(tc.line).Link; got != tc.want {
			t.Fatalf("запись %d: %s, ожидали %s", i, got, tc.want)
		}
	}
	// Цепочка, начатая не с нас, и отдельная цепочка другого писателя.
	other := NewTracker(nil)
	if got := other.Check(line(7, "h6", "h7", "request", nil)).Link; got != LinkFirstSeen {
		t.Fatalf("середина цепочки: %s", got)
	}
	v3 := []byte(`{"v":3,"seq":0,"ts":"2026-10-03T10:00:00Z","session_id":"s1","chain_kind":"proxy","writer_instance_id":"w2","type":"request","transport":"forward","summary":"x","detail":null,"prev_hash":"genesis","hash":"z0"}`)
	if got := tr.Check(v3).Link; got != LinkGenesis {
		t.Fatalf("новая цепочка другого писателя: %s", got)
	}
	// После рестарта состояние поднимается из вердикта.
	resumed := NewTracker(nil)
	resumed.Resume(Verdict{Session: "s1", Hash: "h4"})
	if got := resumed.Check(line(5, "h4", "h5", "request", nil)).Link; got != LinkOK {
		t.Fatalf("после Resume: %s", got)
	}
}

func TestCheckpointSignature(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(nil)
	otherPub, _, _ := ed25519.GenerateKey(nil)
	sig := hex.EncodeToString(ed25519.Sign(priv, []byte("h1")))
	cp := line(2, "h1", "h2", "checkpoint", map[string]any{"entry_count": 2, "first_seq": 0, "last_seq": 1, "signature": sig})

	for name, tc := range map[string]struct {
		key  ed25519.PublicKey
		want string
	}{
		"свой ключ":  {pub, SigValid},
		"чужой ключ": {otherPub, SigInvalid},
		"без ключа":  {nil, SigNoKey},
	} {
		v := NewTracker(tc.key).Check(cp)
		if v.Signature != tc.want || v.Sig != sig {
			t.Fatalf("%s: %s, sig=%q", name, v.Signature, v.Sig)
		}
	}
	// Проверяющий проверяет подпись сам, своим ключом.
	v := NewTracker(nil).Check(cp)
	if err := VerifyCheckpoint(pub, v); err != nil {
		t.Fatal(err)
	}
	if err := VerifyCheckpoint(otherPub, v); err == nil {
		t.Fatal("подпись сошлась с чужим ключом")
	}
	v.PrevHash = "h0" // подменили состояние цепочки
	if err := VerifyCheckpoint(pub, v); err == nil {
		t.Fatal("подпись сошлась над подменённым prev_hash")
	}
	unsigned := line(2, "h1", "h2", "checkpoint", map[string]any{"entry_count": 2})
	if v := NewTracker(pub).Check(unsigned); v.Signature != SigInvalid || v.Problem == "" {
		t.Fatalf("контрольная точка без подписи: %+v", v)
	}
}

// Строки, которые Pipelock сам не принял бы, получают вердикт с причиной, а
// не молчаливое «цело».
func TestBadEntries(t *testing.T) {
	tr := NewTracker(nil)
	for name, tc := range map[string]struct{ line, problem string }{
		"не JSON":            {`not json`, "not a JSON object"},
		"не объект":          {`[1,2]`, "not a JSON object"},
		"повтор ключа":       {`{"v":2,"seq":1,"summary":"a","summary":"b","prev_hash":"genesis","hash":"x"}`, "duplicate key"},
		"неизвестная версия": {`{"v":9,"seq":1,"ts":"2026-10-03T10:00:00Z","prev_hash":"genesis","hash":"x"}`, "unsupported entry version"},
		"нулевой байт":       {`{"v":2,"seq":1,"ts":"2026-10-03T10:00:00Z","summary":"a\u0000b","prev_hash":"genesis","hash":"x"}`, "contains NUL"},
		"v3 без писателя":    {`{"v":3,"seq":1,"ts":"2026-10-03T10:00:00Z","session_id":"s","prev_hash":"genesis","hash":"x"}`, "v3 entry without"},
		"v2 с полями v3":     {`{"v":2,"seq":1,"ts":"2026-10-03T10:00:00Z","chain_kind":"proxy","prev_hash":"genesis","hash":"x"}`, "legacy entry"},
	} {
		v := tr.Check([]byte(tc.line))
		if v.Clean() || !strings.Contains(v.Problem, tc.problem) {
			t.Errorf("%s: вердикт %+v, ожидали причину %q", name, v, tc.problem)
		}
	}
}

func TestParseKey(t *testing.T) {
	pub, _, _ := ed25519.GenerateKey(nil)
	k, err := ParseKey(" " + hex.EncodeToString(pub) + "\n")
	if err != nil || !k.Equal(pub) {
		t.Fatalf("%v, %v", k, err)
	}
	for _, bad := range []string{"", "zz", hex.EncodeToString(pub[:31])} {
		if _, err := ParseKey(bad); err == nil {
			t.Errorf("принят ключ %q", bad)
		}
	}
}
