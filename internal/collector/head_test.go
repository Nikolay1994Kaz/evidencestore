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
	if set := setAside(t, r.cfg.SpoolDir); len(set) != 2 {
		t.Fatalf("отложено %v, ждали checkpoint.json и журнал голов", set)
	}
	if err := c.Bootstrap(context.Background()); err != nil || c.head == nil {
		t.Fatalf("голова не принята заново: %v", err)
	}

	// Испорченный файл — так же: отложен, сборщик стартует.
	c.Close()
	if err := os.WriteFile(path, []byte("{not json"), 0o600); err != nil {
		t.Fatal(err)
	}
	c, err = New(r.cfg, quiet)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { c.Close() })
	found := false
	for _, p := range setAside(t, r.cfg.SpoolDir) {
		data, _ := os.ReadFile(p)
		found = found || string(data) == "{not json"
	}
	if c.head != nil || !found {
		t.Fatalf("испорченный файл головы: голова %v, отложен = %v", c.head, found)
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

// setAside — отложенные файлы голов в spool_dir.
func setAside(t *testing.T, dir string) []string {
	t.Helper()
	set, err := filepath.Glob(filepath.Join(dir, "*.unverified-*"))
	if err != nil {
		t.Fatal(err)
	}
	return set
}

// tamperRig — стенд, где ответ хранилища можно подменить (голову и
// доказательство в нём).
func tamperRig(t *testing.T) (*rig, *atomic.Pointer[func(map[string]json.RawMessage)]) {
	t.Helper()
	tamper := &atomic.Pointer[func(map[string]json.RawMessage)]{}
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
	return r, tamper
}

// growChain — две строки доставлены, между ними хвост цепи свёрнут в звено:
// голова в последнем ответе новее прежней.
func growChain(t *testing.T, r *rig, c *Collector, n *int) {
	t.Helper()
	appendLines(t, r.cfg.File, fmt.Sprintf("line %d\n", *n))
	*n++
	cycle(t, c)
	if _, err := r.st.Proof("abs-core", 1, false); err != nil {
		t.Fatal(err)
	}
	appendLines(t, r.cfg.File, fmt.Sprintf("line %d\n", *n))
	*n++
	cycle(t, c)
}

// Файлы голов не пишутся (на их месте каталоги: кончилось место, чужие
// права) — сборщик стартует, записи доставляются, ошибка — в журнал; при
// расхождении тоже. checkpoint.json пишется раньше журнала голов и держит
// последнюю голову, хотя журнал отказал (P-28).
func TestHeadFilesFailDeliveryGoesOn(t *testing.T) {
	r, tamper := tamperRig(t)
	r.cfg.CheckpointEvery = config.Duration(time.Nanosecond)
	for _, name := range []string{headsFile, headConflictFile} {
		if err := os.MkdirAll(filepath.Join(r.cfg.SpoolDir, name), 0o700); err != nil {
			t.Fatal(err)
		}
	}
	var logs bytes.Buffer
	c, err := New(r.cfg, slog.New(slog.NewTextHandler(&logs, nil)))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { c.Close() })
	if err := c.Bootstrap(context.Background()); err != nil {
		t.Fatal(err)
	}
	n := 0
	for range 3 {
		growChain(t, r, c, &n)
	}
	if c.Pending() != 0 || c.Acked() != uint64(n) || c.head == nil {
		t.Fatalf("доставка при отказе файлов голов: в буфере %d, подтверждено %d из %d", c.Pending(), c.Acked(), n)
	}
	if last := headsOf(t, c.headPath()); len(last) != 1 || last[0].Checkpoint.Size != c.head.Size {
		t.Fatalf("checkpoint.json не держит последнюю голову %d: %+v", c.head.Size, last)
	}
	owner, err := auditchain.LoadOrCreateSigner(filepath.Join(r.dataDir, "chain"))
	if err != nil {
		t.Fatal(err)
	}
	fork := func(out map[string]json.RawMessage) {
		out["checkpoint"], _ = json.Marshal(proof.SignCheckpoint(owner, c.head.Size, [32]byte{9}))
	}
	tamper.Store(&fork)
	appendLines(t, r.cfg.File, fmt.Sprintf("line %d\n", n))
	n++
	cycle(t, c)
	if c.Pending() != 0 || c.Acked() != uint64(n) {
		t.Fatalf("доставка при расхождении и отказе его файла: в буфере %d", c.Pending())
	}
	if !strings.Contains(logs.String(), "was not written to spool_dir") || !strings.Contains(logs.String(), "does not extend the head") {
		t.Fatalf("журнал сборщика:\n%s", logs.String())
	}
}

// Принятая голова ложится на диск и тогда, когда хранилище отвечает той же
// головой (через checkpoint_every после прошлой записи), и при остановке.
func TestHeadSavedWhenQuietAndOnClose(t *testing.T) {
	r := newRig(t)
	now := time.Date(2026, 11, 1, 10, 0, 0, 0, time.UTC)
	c, err := New(r.cfg, quiet)
	if err != nil {
		t.Fatal(err)
	}
	c.now = func() time.Time { return now }
	if err := c.Bootstrap(context.Background()); err != nil {
		t.Fatal(err)
	}
	saved := func() uint64 {
		t.Helper()
		h := headsOf(t, c.headPath())
		return h[0].Checkpoint.Size
	}
	n := 0
	first := saved()
	growChain(t, r, c, &n)
	if c.head.Size <= first || saved() != first {
		t.Fatalf("голова %d принята, на диске %d (ждали прежнюю %d)", c.head.Size, saved(), first)
	}
	now = now.Add(r.cfg.CheckpointEvery.D())
	if err := c.SendOnce(context.Background()); err != nil { // пульс: та же голова
		t.Fatal(err)
	}
	if saved() != c.head.Size {
		t.Fatalf("в тишине голова %d не легла на диск (там %d)", c.head.Size, saved())
	}
	growChain(t, r, c, &n)
	held := c.head.Size
	c.Close()
	if saved() != held {
		t.Fatalf("при остановке голова %d не легла на диск (там %d)", held, saved())
	}
}

// Хранилище дольше трёх checkpoint_every не показывает головы,
// продолжающей принятую (голова без доказательства), — ошибка в журнал
// сборщика: он тем временем не свидетель.
func TestHeadStaleIsAnError(t *testing.T) {
	r, tamper := tamperRig(t)
	now := time.Date(2026, 11, 1, 10, 0, 0, 0, time.UTC)
	var logs bytes.Buffer
	c, err := New(r.cfg, slog.New(slog.NewTextHandler(&logs, nil)))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { c.Close() })
	c.now = func() time.Time { return now }
	if err := c.Bootstrap(context.Background()); err != nil {
		t.Fatal(err)
	}
	noProof := func(out map[string]json.RawMessage) { delete(out, "consistency") }
	tamper.Store(&noProof)
	n := 0
	every := r.cfg.CheckpointEvery.D()
	for range 2 {
		now = now.Add(every)
		growChain(t, r, c, &n)
	}
	if strings.Contains(logs.String(), "has not shown a head") {
		t.Fatalf("ошибка раньше трёх checkpoint_every:\n%s", logs.String())
	}
	for range 3 {
		now = now.Add(every)
		growChain(t, r, c, &n)
	}
	if !strings.Contains(logs.String(), "has not shown a head") || c.Pending() != 0 {
		t.Fatalf("нет ошибки больше трёх checkpoint_every без доказательств (в буфере %d):\n%s", c.Pending(), logs.String())
	}
}

// Оборванная последняя строка файла голов (падение посреди записи)
// отрезается при запуске: к ней не приклеится следующая.
func TestTornHeadLineIsCut(t *testing.T) {
	r := newRig(t)
	c := r.collector(t)
	c.Close()
	journal := filepath.Join(r.cfg.SpoolDir, headsFile)
	whole, err := os.ReadFile(journal)
	if err != nil || len(whole) == 0 {
		t.Fatalf("журнал голов: %v", err)
	}
	if err := os.WriteFile(journal, append(append([]byte(nil), whole...), whole[:len(whole)/2]...), 0o600); err != nil {
		t.Fatal(err)
	}
	c = r.collector(t)
	if data, _ := os.ReadFile(journal); string(data) != string(whole) {
		t.Fatalf("обрывок не отрезан:\n%q", data)
	}
}

// Хранилище отвечает прежней головой сборщика, хотя он доставляет записи
// (свидетель заморожен), — ошибка через три checkpoint_every; в тишине (ничего
// не доставлено) та же голова тревоги не даёт (P-37).
func TestHeadFrozenIsAnError(t *testing.T) {
	r, tamper := tamperRig(t)
	now := time.Date(2026, 11, 1, 10, 0, 0, 0, time.UTC)
	var logs bytes.Buffer
	c, err := New(r.cfg, slog.New(slog.NewTextHandler(&logs, nil)))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { c.Close() })
	c.now = func() time.Time { return now }
	if err := c.Bootstrap(context.Background()); err != nil {
		t.Fatal(err)
	}
	every := r.cfg.CheckpointEvery.D()
	for range 5 { // тишина: только пульс, голова та же
		now = now.Add(every)
		if err := c.SendOnce(context.Background()); err != nil {
			t.Fatal(err)
		}
	}
	if strings.Contains(logs.String(), "has not shown a head") {
		t.Fatalf("тревога в тишине:\n%s", logs.String())
	}
	held, err := json.Marshal(*c.head)
	if err != nil {
		t.Fatal(err)
	}
	frozen := func(out map[string]json.RawMessage) {
		out["checkpoint"] = held
		delete(out, "consistency")
	}
	tamper.Store(&frozen)
	n := 0
	for range 5 {
		now = now.Add(every)
		growChain(t, r, c, &n)
	}
	if !strings.Contains(logs.String(), "has not shown a head") || c.Pending() != 0 {
		t.Fatalf("заморозка прежней головой без тревоги (в буфере %d):\n%s", c.Pending(), logs.String())
	}
}

// Пока хранилище не отвечало, отсчёт «нет головы» стоит: после долгого
// простоя первый ответ без головы (копия ещё не прошла) тревоги не даёт.
func TestHeadOutageNotCounted(t *testing.T) {
	r, tamper := tamperRig(t)
	now := time.Date(2026, 11, 1, 10, 0, 0, 0, time.UTC)
	var logs bytes.Buffer
	c, err := New(r.cfg, slog.New(slog.NewTextHandler(&logs, nil)))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { c.Close() })
	c.now = func() time.Time { return now }
	if err := c.Bootstrap(context.Background()); err != nil {
		t.Fatal(err)
	}
	noHead := func(out map[string]json.RawMessage) { delete(out, "checkpoint"); delete(out, "consistency") }
	tamper.Store(&noHead)
	now = now.Add(5 * r.cfg.CheckpointEvery.D()) // хранилище недоступно, ответов нет
	if err := c.SendOnce(context.Background()); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(logs.String(), "has not shown a head") {
		t.Fatalf("тревога сразу после простоя:\n%s", logs.String())
	}
}

// Пока идут расхождения, принятая голова всё равно ложится на диск: после
// падения сборщик продолжит с неё, а не со старшей.
func TestHeadSavedDuringConflict(t *testing.T) {
	r, tamper := tamperRig(t)
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
	n := 0
	growChain(t, r, c, &n) // новая голова принята, на диск ещё не легла
	held := c.head.Size
	owner, err := auditchain.LoadOrCreateSigner(filepath.Join(r.dataDir, "chain"))
	if err != nil {
		t.Fatal(err)
	}
	fork := func(out map[string]json.RawMessage) {
		out["checkpoint"], _ = json.Marshal(proof.SignCheckpoint(owner, held, [32]byte{8}))
	}
	tamper.Store(&fork)
	now = now.Add(r.cfg.CheckpointEvery.D())
	appendLines(t, r.cfg.File, fmt.Sprintf("line %d\n", n))
	cycle(t, c)
	if h := headsOf(t, c.headPath()); h[0].Checkpoint.Size != held {
		t.Fatalf("при расхождении на диске голова %d, принята %d", h[0].Checkpoint.Size, held)
	}
}

// checkpoint.json пропал, а журнал голов есть: сборщик продолжает с
// последней головы журнала, а не берёт первую попавшуюся на веру.
func TestHeadResumedFromJournal(t *testing.T) {
	r := newRig(t)
	r.cfg.CheckpointEvery = config.Duration(time.Nanosecond)
	c := r.collector(t)
	n := 0
	growChain(t, r, c, &n)
	held := *c.head
	c.Close()
	if err := os.Remove(c.headPath()); err != nil {
		t.Fatal(err)
	}
	c2, err := New(r.cfg, quiet)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { c2.Close() })
	if c2.head == nil || c2.head.Size != held.Size || !bytes.Equal(c2.head.Root, held.Root) {
		t.Fatalf("после потери checkpoint.json голова %+v, ждали %d из журнала", c2.head, held.Size)
	}
}
