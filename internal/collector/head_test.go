package collector

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Nikolay1994Kaz/evidencestore/internal/auditchain"
	"github.com/Nikolay1994Kaz/evidencestore/internal/config"
	"github.com/Nikolay1994Kaz/evidencestore/internal/proof"
	"github.com/Nikolay1994Kaz/evidencestore/internal/tsa"
)

// headsOf — головы из файла сборщика, как их прочтёт esverify -heads.
func headsOf(t *testing.T, path string) []proof.PublishedHead {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return proof.ParseHeads(filepath.Base(path), data)
}

func (r *rig) storeKey(t *testing.T) ed25519.PublicKey {
	t.Helper()
	pub, err := base64.RawStdEncoding.DecodeString(r.st.PublicKey())
	if err != nil {
		t.Fatal(err)
	}
	return pub
}

// Сборщик — свидетель голов: принимает голову из каждого ответа, если она
// продолжает прежнюю, и кладёт в журнал голов; после перезапуска продолжает
// с последней сохранённой. Журнал голов годится для esverify -heads: пакет
// записи до головы сборщика проходит сверку, и голова её закрепляет.
func TestCollectorWitnessesHeads(t *testing.T) {
	r := newRig(t)
	r.cfg.CheckpointEvery = config.Duration(time.Nanosecond)
	c := r.collector(t)
	if c.head == nil {
		t.Fatal("первая голова не принята")
	}
	first := c.head.Size
	appendLines(t, r.cfg.File, "line 1\n", "line 2\n")
	cycle(t, c)
	if _, err := r.st.Stamp(context.Background()); err != nil {
		t.Fatal(err)
	}
	appendLines(t, r.cfg.File, "line 3\n")
	cycle(t, c)
	if c.head.Size <= first {
		t.Fatalf("голова не продвинулась: %d", c.head.Size)
	}

	c.Close()
	c = r.collector(t)
	if c.head == nil || c.head.Size == 0 {
		t.Fatal("после перезапуска голова не поднята")
	}
	appendLines(t, r.cfg.File, "line 4\n")
	cycle(t, c)
	if _, err := os.Stat(filepath.Join(r.cfg.SpoolDir, headConflictFile)); !os.IsNotExist(err) {
		t.Fatalf("у честного хранилища расхождение: %v", err)
	}

	heads := headsOf(t, filepath.Join(r.cfg.SpoolDir, headsFile))
	var prev uint64
	for _, h := range heads {
		if err := proof.VerifyCheckpoint(h.Checkpoint, r.storeKey(t)); err != nil || h.Checkpoint.Size < prev {
			t.Fatalf("журнал голов: %s, размер %d после %d: %v", h.Name, h.Checkpoint.Size, prev, err)
		}
		prev = h.Checkpoint.Size
	}
	if len(heads) < 2 || heads[len(heads)-1].Checkpoint.Size != c.head.Size {
		t.Fatalf("в журнале голов %d, последняя не та, что держит сборщик", len(heads))
	}
	last := headsOf(t, filepath.Join(r.cfg.SpoolDir, headFile))
	if len(last) != 1 || last[0].Checkpoint.Size != c.head.Size {
		t.Fatalf("checkpoint.json: %+v", last)
	}

	// Пакет записи 1 до головы сборщика: голова его закрепляет.
	b, err := r.st.ProofTo("abs-core", 1, false, c.head.Size)
	if err != nil {
		t.Fatal(err)
	}
	a, err := tsa.LoadAuthority(filepath.Join(r.dataDir, "tsa-local"))
	if err != nil {
		t.Fatal(err)
	}
	trust := proof.Trust{StoreKey: r.storeKey(t), TSA: a.Trust(), Witness: &proof.Witness{Heads: heads}}
	rep := proof.Verify(b, trust)
	if !rep.Valid() || rep.WitnessHead == 0 {
		t.Fatalf("пакет со свидетелем-сборщиком:\n%s", rep.Text())
	}
}

// Хранилище, подписавшее вторую историю, сборщик ловит: та же длина с
// другим корнем, цепь короче прежней, доказательство продолжения, которое
// не сходится, — расхождение; обе головы — в checkpoints-conflict.jsonl,
// прежняя остаётся последней, записи доставляются дальше. Голова новее без
// доказательства и голова без подписи хранилища — только предупреждение.
// Честная голова снова принимается.
func TestCollectorCatchesRewrittenChain(t *testing.T) {
	var tamper atomic.Pointer[func(map[string]json.RawMessage)]
	r := newRig(t, func(h http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
			f := tamper.Load()
			if f == nil {
				h.ServeHTTP(w, req)
				return
			}
			rec := httptest.NewRecorder()
			h.ServeHTTP(rec, req)
			var out map[string]json.RawMessage
			if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
				t.Error(err)
			}
			if rec.Code == http.StatusOK {
				(*f)(out)
			}
			w.WriteHeader(rec.Code)
			json.NewEncoder(w).Encode(out)
		})
	})
	r.cfg.CheckpointEvery = config.Duration(time.Nanosecond)
	var logs bytes.Buffer
	c, err := New(r.cfg, slog.New(slog.NewTextHandler(&logs, nil)))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { c.Close() })
	if err := c.Bootstrap(context.Background()); err != nil {
		t.Fatal(err)
	}
	appendLines(t, r.cfg.File, "line 0\n")
	cycle(t, c)
	if _, err := r.st.Stamp(context.Background()); err != nil {
		t.Fatal(err)
	}
	appendLines(t, r.cfg.File, "line 1\n")
	cycle(t, c)
	held := *c.head
	if held.Size < 2 {
		t.Fatalf("раскладка теста поменялась: голова сборщика %d", held.Size)
	}
	// Ключ подписи хранилища — у владельца, который переписывает историю.
	owner, err := auditchain.LoadOrCreateSigner(filepath.Join(r.dataDir, "chain"))
	if err != nil {
		t.Fatal(err)
	}
	set := func(out map[string]json.RawMessage, cp proof.Checkpoint, consistency [][]byte) {
		out["checkpoint"], _ = json.Marshal(cp)
		out["consistency"], _ = json.Marshal(consistency)
	}
	conflicts := func() int {
		data, _ := os.ReadFile(filepath.Join(r.cfg.SpoolDir, headConflictFile))
		return bytes.Count(data, []byte("\n"))
	}
	line := 2
	for i, tc := range []struct {
		name     string
		f        func(out map[string]json.RawMessage)
		conflict bool
	}{
		{"та же длина, другой корень", func(out map[string]json.RawMessage) {
			set(out, proof.SignCheckpoint(owner, held.Size, [32]byte{1}), nil)
		}, true},
		{"цепь короче", func(out map[string]json.RawMessage) {
			set(out, proof.SignCheckpoint(owner, held.Size-1, [32]byte{2}), nil)
		}, true},
		{"доказательство не сходится", func(out map[string]json.RawMessage) {
			var cp proof.Checkpoint
			var consistency [][]byte
			json.Unmarshal(out["checkpoint"], &cp)
			json.Unmarshal(out["consistency"], &consistency)
			if cp.Size <= held.Size || len(consistency) == 0 {
				t.Errorf("честный ответ: голова %d, доказательство из %d хешей", cp.Size, len(consistency))
			}
			set(out, proof.SignCheckpoint(owner, cp.Size, [32]byte{3}), consistency)
		}, true},
		{"новее без доказательства", func(out map[string]json.RawMessage) {
			set(out, proof.SignCheckpoint(owner, held.Size+5, [32]byte{4}), nil)
		}, false},
		{"без подписи хранилища", func(out map[string]json.RawMessage) {
			cp := proof.SignCheckpoint(owner, held.Size, [32]byte{5})
			cp.Signature[0] ^= 1
			set(out, cp, nil)
		}, false},
	} {
		before := conflicts()
		if _, err := r.st.Proof("abs-core", 1, false); err != nil { // хвост цепи — в звено: цепь растёт
			t.Fatal(err)
		}
		tamper.Store(&tc.f)
		appendLines(t, r.cfg.File, fmt.Sprintf("line %d\n", line))
		line++
		cycle(t, c) // записи доставлены, хотя голова не та
		tamper.Store(nil)
		if c.Pending() != 0 || c.Acked() != uint64(line) { // «line k» — запись k+1
			t.Fatalf("%s: в буфере %d, подтверждено до %d", tc.name, c.Pending(), c.Acked())
		}
		if c.head.Size != held.Size || !bytes.Equal(c.head.Root, held.Root) {
			t.Fatalf("%s: последней стала голова %d", tc.name, c.head.Size)
		}
		if got := conflicts() - before; got != map[bool]int{true: 1, false: 0}[tc.conflict] {
			t.Fatalf("%s (%d): записей о расхождении %d", tc.name, i, got)
		}
	}
	if !strings.Contains(logs.String(), "level=ERROR") || !strings.Contains(logs.String(), "without a proof") {
		t.Fatalf("журнал сборщика:\n%s", logs.String())
	}
	// Обе головы каждого расхождения подписаны хранилищем и видны -heads.
	heads := headsOf(t, filepath.Join(r.cfg.SpoolDir, headConflictFile))
	if len(heads) != 6 {
		t.Fatalf("голов в файле расхождений %d", len(heads))
	}
	for _, h := range heads {
		if err := proof.VerifyCheckpoint(h.Checkpoint, r.storeKey(t)); err != nil {
			t.Fatalf("%s: %v", h.Name, err)
		}
	}

	// Честный ответ: голова продолжает прежнюю и принимается.
	appendLines(t, r.cfg.File, fmt.Sprintf("line %d\n", line))
	cycle(t, c)
	if _, err := r.st.Proof("abs-core", 1, false); err != nil { // хвост цепи — в звено
		t.Fatal(err)
	}
	appendLines(t, r.cfg.File, fmt.Sprintf("line %d\n", line+1))
	cycle(t, c)
	if c.head.Size <= held.Size {
		t.Fatalf("честная голова не принята: %d", c.head.Size)
	}
}

// Голова в checkpoint.json, которую не подписал закреплённый ключ
// (store_key сменили), откладывается, и сборщик принимает голову заново —
// доставку она не останавливает.
func TestUnverifiedHeadIsSetAside(t *testing.T) {
	r := newRig(t)
	c := r.collector(t)
	c.Close()
	path := filepath.Join(r.cfg.SpoolDir, headFile)
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var rec headRecord
	if err := json.Unmarshal(data, &rec); err != nil {
		t.Fatal(err)
	}
	rec.Checkpoint.Signature[0] ^= 1
	if err := writeJSON(path, rec); err != nil {
		t.Fatal(err)
	}
	c, err = New(r.cfg, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { c.Close() })
	if c.head != nil {
		t.Fatal("неподписанная голова принята")
	}
	if _, err := os.Stat(path + ".unverified"); err != nil {
		t.Fatal(err)
	}
	if err := c.Bootstrap(context.Background()); err != nil || c.head == nil {
		t.Fatalf("голова не принята заново: %v", err)
	}
}

// Журнал голов и файл расхождений пополняются не чаще checkpoint_every:
// новая голова в промежутке принимается, но на диск не ложится, повторное
// расхождение не пишется.
func TestHeadCadence(t *testing.T) {
	var tamper atomic.Pointer[func(map[string]json.RawMessage)]
	r := newRig(t, func(h http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
			f := tamper.Load()
			if f == nil {
				h.ServeHTTP(w, req)
				return
			}
			rec := httptest.NewRecorder()
			h.ServeHTTP(rec, req)
			var out map[string]json.RawMessage
			json.Unmarshal(rec.Body.Bytes(), &out)
			if rec.Code == http.StatusOK {
				(*f)(out)
			}
			w.WriteHeader(rec.Code)
			json.NewEncoder(w).Encode(out)
		})
	})
	now := time.Date(2026, 11, 1, 10, 0, 0, 0, time.UTC)
	c, err := New(r.cfg, quiet)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { c.Close() })
	c.now = func() time.Time { return now }
	if err := c.Bootstrap(context.Background()); err != nil {
		t.Fatal(err)
	}
	lines := func(name string) int {
		data, _ := os.ReadFile(filepath.Join(r.cfg.SpoolDir, name))
		return bytes.Count(data, []byte("\n"))
	}
	n := 0
	grow := func() {
		t.Helper()
		appendLines(t, r.cfg.File, fmt.Sprintf("line %d\n", n))
		n++
		cycle(t, c)
		if _, err := r.st.Proof("abs-core", 1, false); err != nil { // хвост цепи — в звено
			t.Fatal(err)
		}
		appendLines(t, r.cfg.File, fmt.Sprintf("line %d\n", n))
		n++
		cycle(t, c)
	}
	grow()
	first := c.head.Size
	grow()
	if c.head.Size <= first || lines(headsFile) != 1 {
		t.Fatalf("голова %d после %d, в журнале %d", c.head.Size, first, lines(headsFile))
	}
	now = now.Add(r.cfg.CheckpointEvery.D())
	grow()
	if lines(headsFile) != 2 {
		t.Fatalf("через checkpoint_every в журнале %d", lines(headsFile))
	}

	owner, err := auditchain.LoadOrCreateSigner(filepath.Join(r.dataDir, "chain"))
	if err != nil {
		t.Fatal(err)
	}
	fork := func(out map[string]json.RawMessage) {
		out["checkpoint"], _ = json.Marshal(proof.SignCheckpoint(owner, c.head.Size, [32]byte{7}))
		delete(out, "consistency")
	}
	tamper.Store(&fork)
	for range 3 {
		appendLines(t, r.cfg.File, fmt.Sprintf("line %d\n", n))
		n++
		cycle(t, c)
	}
	if lines(headConflictFile) != 1 {
		t.Fatalf("расхождений в файле %d", lines(headConflictFile))
	}
	now = now.Add(r.cfg.CheckpointEvery.D())
	appendLines(t, r.cfg.File, fmt.Sprintf("line %d\n", n))
	cycle(t, c)
	if lines(headConflictFile) != 2 {
		t.Fatalf("через checkpoint_every расхождений %d", lines(headConflictFile))
	}
}
