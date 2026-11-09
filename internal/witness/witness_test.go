package witness

import (
	"bufio"
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"golang.org/x/mod/sumdb/tlog"

	"github.com/Nikolay1994Kaz/evidencestore/internal/auditchain"
	"github.com/Nikolay1994Kaz/evidencestore/internal/cosign"
	"github.com/Nikolay1994Kaz/evidencestore/internal/proof"
)

// chain — журнал в памяти: дерево RFC 6962 над случайными листьями и ключ
// хранилища, которым подписываются головы.
type chain struct {
	t      *testing.T
	signer *auditchain.Signer
	hashes []tlog.Hash
	n      int64
}

func newChain(t *testing.T) *chain {
	t.Helper()
	s, err := auditchain.LoadOrCreateSigner(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	return &chain{t: t, signer: s}
}

func (c *chain) ReadHashes(idx []int64) ([]tlog.Hash, error) {
	out := make([]tlog.Hash, len(idx))
	for i, x := range idx {
		out[i] = c.hashes[x]
	}
	return out, nil
}

func (c *chain) grow(k int) {
	c.t.Helper()
	for range k {
		var data [16]byte
		rand.Read(data[:])
		hs, err := tlog.StoredHashes(c.n, data[:], c)
		if err != nil {
			c.t.Fatal(err)
		}
		c.hashes = append(c.hashes, hs...)
		c.n++
	}
}

func (c *chain) root(n int64) [32]byte {
	h, err := tlog.TreeHash(n, c)
	if err != nil {
		c.t.Fatal(err)
	}
	return h
}

func (c *chain) proof(n, m int64) [][32]byte {
	if m == 0 || m == n {
		return nil
	}
	p, err := tlog.ProveTree(n, m, c)
	if err != nil {
		c.t.Fatal(err)
	}
	out := make([][32]byte, len(p))
	for i, h := range p {
		out[i] = h
	}
	return out
}

func (c *chain) note(n int64) []byte {
	cp := proof.SignCheckpoint(c.signer, uint64(n), c.root(n))
	return cp.Note(c.signer.PublicKey())
}

func (c *chain) origin() string { return proof.OriginFor(c.signer.PublicKey()) }

type rig struct {
	t   *testing.T
	w   *Server
	ts  *httptest.Server
	key cosign.Signer
	dir string
}

func newRig(t *testing.T, dir string, chains ...*chain) *rig {
	t.Helper()
	_, priv, _ := ed25519.GenerateKey(rand.Reader)
	key, err := cosign.NewSigner("witness.example/w1", priv)
	if err != nil {
		t.Fatal(err)
	}
	return reopen(t, dir, key, chains...)
}

func reopen(t *testing.T, dir string, key cosign.Signer, chains ...*chain) *rig {
	t.Helper()
	return reopenLog(t, dir, key, nil, chains...)
}

// reopenLog — reopen с журналом процесса log.
func reopenLog(t *testing.T, dir string, key cosign.Signer, log *slog.Logger, chains ...*chain) *rig {
	t.Helper()
	var logs []Log
	for _, c := range chains {
		logs = append(logs, Log{Origin: c.origin(), Key: c.signer.PublicKey()})
	}
	w, err := New(key, logs, dir, log)
	if err != nil {
		t.Fatal(err)
	}
	ts := httptest.NewServer(w.Handler())
	t.Cleanup(ts.Close)
	return &rig{t: t, w: w, ts: ts, key: key, dir: dir}
}

func (r *rig) add(body []byte) (int, string, string) {
	r.t.Helper()
	resp, err := http.Post(r.ts.URL+"/add-checkpoint", "text/plain", bytes.NewReader(body))
	if err != nil {
		r.t.Fatal(err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, string(b), resp.Header.Get("Content-Type")
}

// cosigned — ответ 200 — одна строка подписи свидетеля, которая сходится с
// головой n цепи c.
func (r *rig) mustCosign(c *chain, old, n int64) uint64 {
	r.t.Helper()
	code, body, _ := r.add(cosign.AddCheckpoint(uint64(old), c.proof(n, old), c.note(n)))
	if code != http.StatusOK {
		r.t.Fatalf("голова %d от %d: %d %s", n, old, code, body)
	}
	name, sig, err := cosign.ParseSigLine(strings.TrimSuffix(body, "\n"))
	if err != nil || name != r.key.Name || strings.Count(body, "\n") != 1 {
		r.t.Fatalf("ответ свидетеля %q: %v", body, err)
	}
	at, err := r.key.Verifier().Verify(cosign.CheckpointText(c.origin(), uint64(n), c.root(n)), sig)
	if err != nil {
		r.t.Fatalf("подпись свидетеля над головой %d: %v", n, err)
	}
	return at
}

func TestWitnessCosignsExtensions(t *testing.T) {
	c := newChain(t)
	r := newRig(t, t.TempDir(), c)
	c.grow(5)
	r.mustCosign(c, 0, 5)
	c.grow(7)
	r.mustCosign(c, 5, 12)
	r.mustCosign(c, 12, 12) // та же голова — подпись заново
	if n, ok := r.w.Latest(c.origin()); !ok || n != 12 {
		t.Fatalf("последняя подписанная: %d %v", n, ok)
	}
	// После перезапуска свидетель помнит последнюю.
	r2 := reopen(t, r.dir, r.key, c)
	if code, body, ctype := r2.add(cosign.AddCheckpoint(0, nil, c.note(12))); code != http.StatusConflict || body != "12\n" || ctype != "text/x.tlog.size" {
		t.Fatalf("после перезапуска old 0: %d %q %q", code, body, ctype)
	}
	c.grow(1)
	r2.mustCosign(c, 12, 13)
}

func TestWitnessRefusals(t *testing.T) {
	c := newChain(t)
	r := newRig(t, t.TempDir(), c)
	c.grow(8)
	r.mustCosign(c, 0, 4)

	stranger := newChain(t)
	stranger.grow(3)
	forged := newChain(t) // тот же размер, другая история
	forged.grow(8)
	good := proof.SignCheckpoint(c.signer, 8, c.root(8))
	flipped := bytes.Clone(good.Signature)
	flipped[0] ^= 1
	badSig := withLogSig(c, 8, c.signer.PublicKey(), flipped)
	other := newChain(t)
	foreign := withLogSig(c, 8, other.signer.PublicKey(), make([]byte, 64)) // чужой номер ключа под именем хранилища

	cases := []struct {
		name string
		body []byte
		code int
	}{
		{"чужое хранилище", cosign.AddCheckpoint(0, nil, stranger.note(3)), http.StatusNotFound},
		{"испорченная подпись хранилища", cosign.AddCheckpoint(4, c.proof(8, 4), badSig), http.StatusForbidden},
		{"подпись чужим ключом под тем же именем", cosign.AddCheckpoint(4, c.proof(8, 4), foreign), http.StatusForbidden},
		{"old больше размера", cosign.AddCheckpoint(9, nil, c.note(8)), http.StatusBadRequest},
		{"не тот old", cosign.AddCheckpoint(3, c.proof(8, 3), c.note(8)), http.StatusConflict},
		{"мусор", []byte("hello"), http.StatusBadRequest},
		{"другая история", cosign.AddCheckpoint(4, forged.proof(8, 4), sameKey(t, c, forged, 8)), http.StatusUnprocessableEntity},
		{"доказательство не того отрезка", cosign.AddCheckpoint(4, c.proof(8, 5), c.note(8)), http.StatusUnprocessableEntity},
		{"тот же размер с доказательством", cosign.AddCheckpoint(4, [][32]byte{{1}}, c.note(4)), http.StatusUnprocessableEntity},
		{"строка подписи не разбирается", cosign.AddCheckpoint(4, c.proof(8, 4), append(c.note(8), "not a signature line\n"...)), http.StatusBadRequest},
	}
	for _, tc := range cases {
		if code, body, _ := r.add(tc.body); code != tc.code {
			t.Errorf("%s: %d %q, ждали %d", tc.name, code, body, tc.code)
		}
	}
	// Та же голова 4 с другим корнем — развилка: 422 и запись в журнал отказов.
	if code, _, _ := r.add(cosign.AddCheckpoint(4, nil, sameKey(t, c, forged, 4))); code != http.StatusUnprocessableEntity {
		t.Fatalf("развилка на размере 4: %d", code)
	}
	if n, _ := r.w.Latest(c.origin()); n != 4 {
		t.Fatalf("после отказов последняя %d, ждали 4", n)
	}
	// Повтор той же развилки журнал не раздувает.
	r.add(cosign.AddCheckpoint(4, nil, sameKey(t, c, forged, 4)))
	// В журнале отказов — только развилка одного размера: обе головы подписаны
	// хранилищем, и строка несёт обе. Несошедшееся доказательство — не улика:
	// его подставляет отправитель.
	refusals := readRefusals(t, r.dir)
	if len(refusals) != 1 {
		t.Fatalf("в журнале отказов %d строк, ждали 1 (развилка на размере 4): %v", len(refusals), refusals)
	}
	rf := refusals[0]
	if rf.Origin != c.origin() || rf.Size != 4 || !strings.Contains(rf.Note, "\n4\n") || !strings.Contains(rf.Cosigned, "— witness.example/w1 ") {
		t.Fatalf("строка отказа: %+v", rf)
	}
	if bytes.Contains([]byte(rf.Note), []byte("— witness.example/w1")) {
		t.Fatalf("в улике — чужие строки подписей: %q", rf.Note)
	}
}

// Кто угодно с подписанной хранилищем головой может прислать мусорное
// доказательство: журнал отказов от этого не растёт.
func TestWitnessGarbageProofIsNotEvidence(t *testing.T) {
	c := newChain(t)
	r := newRig(t, t.TempDir(), c)
	c.grow(10)
	r.mustCosign(c, 0, 5)
	junk := [][32]byte{{1}, {2}, {3}}
	for range 20 {
		if code, _, _ := r.add(cosign.AddCheckpoint(5, junk, c.note(10))); code != http.StatusUnprocessableEntity {
			t.Fatalf("мусорное доказательство: %d", code)
		}
	}
	if refusals := readRefusals(t, r.dir); len(refusals) != 0 {
		t.Fatalf("мусорное доказательство попало в журнал отказов: %d строк", len(refusals))
	}
	r.mustCosign(c, 5, 10)
}

// Заметка, которую свидетель хранит и отдаёт мониторам, — текст точки, одна
// подпись хранилища и подпись свидетеля, сколько бы строк ни пришло в запросе
// (повтор, чужие ключи, в том числе с длинным именем, строка под именем
// самого свидетеля).
func TestWitnessStoredNoteIsClean(t *testing.T) {
	c := newChain(t)
	r := newRig(t, t.TempDir(), c)
	c.grow(4)
	r.mustCosign(c, 0, 4)
	note := c.note(4)
	text, sigs, _ := cosign.SplitNote(note)
	junk := "— " + r.key.Name + " " + base64.StdEncoding.EncodeToString(append(binary.BigEndian.AppendUint32(nil, r.key.ID), make([]byte, 72)...))
	// Чужой ключ с именем длиннее 255 байт — signed-note имя не ограничивает:
	// строку пропускают, а не отвергают заметку.
	long := "— " + strings.Repeat("x", 300) + " AAAAAAAA"
	poisoned := string(text) + "\n" + sigs[0] + "\n" + sigs[0] + "\n" + junk + "\n— other.example/k AAAAAAAA\n" + long + "\n"
	if code, body, _ := r.add(cosign.AddCheckpoint(4, nil, []byte(poisoned))); code != http.StatusOK {
		t.Fatalf("та же голова с лишними строками: %d %s", code, body)
	}
	resp, err := http.Get(r.ts.URL + "/" + OriginHash(c.origin()) + "/checkpoint")
	if err != nil {
		t.Fatal(err)
	}
	got, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	_, gotSigs, err := cosign.SplitNote(got)
	if err != nil || len(gotSigs) != 2 || gotSigs[0] != sigs[0] || !strings.HasPrefix(gotSigs[1], "— "+r.key.Name+" ") {
		t.Fatalf("заметка свидетеля: %q %v", got, err)
	}
}

// withLogSig — голова n цепи c с подписью sig под номером ключа pub.
func withLogSig(c *chain, n int64, pub ed25519.PublicKey, sig []byte) []byte {
	text := cosign.CheckpointText(c.origin(), uint64(n), c.root(n))
	return append(append(text, '\n'), cosign.LogSignature(c.origin(), pub, sig)...)
}

// sameKey — голова size цепи forged, подписанная ключом хранилища c: так
// выглядит вторая история того же хранилища.
func sameKey(t *testing.T, c, forged *chain, size int64) []byte {
	t.Helper()
	cp := proof.SignCheckpoint(c.signer, uint64(size), forged.root(size))
	return cp.Note(c.signer.PublicKey())
}

func readRefusals(t *testing.T, dir string) []refusal {
	t.Helper()
	f, err := os.Open(filepath.Join(dir, refusedFile))
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	var out []refusal
	sc := bufio.NewScanner(f)
	sc.Buffer(nil, 1<<20)
	for sc.Scan() {
		var rf refusal
		if err := json.Unmarshal(sc.Bytes(), &rf); err != nil {
			t.Fatal(err)
		}
		out = append(out, rf)
	}
	return out
}

// Доказательство от размера 0 обязано быть пустым; голова размера 0 — с
// корнем пустого дерева.
func TestWitnessZeroSizes(t *testing.T) {
	c := newChain(t)
	r := newRig(t, t.TempDir(), c)
	c.grow(4)
	if code, _, _ := r.add(cosign.AddCheckpoint(0, [][32]byte{{1}}, c.note(4))); code != http.StatusUnprocessableEntity {
		t.Fatalf("непустое доказательство от 0: %d", code)
	}
	zero := proof.SignCheckpoint(c.signer, 0, [32]byte{1}).Note(c.signer.PublicKey())
	if code, _, _ := r.add(cosign.AddCheckpoint(0, nil, zero)); code != http.StatusUnprocessableEntity {
		t.Fatalf("размер 0 с непустым корнем: %d", code)
	}
}

// Сверка размера и запись — атомарно: из многих одновременных запросов от
// одной головы проходит один, остальные получают 409, и состояние не
// откатывается.
func TestWitnessConcurrentRequestsDoNotRollBack(t *testing.T) {
	c := newChain(t)
	r := newRig(t, t.TempDir(), c)
	c.grow(64)
	r.mustCosign(c, 0, 1)
	// Все 63 запроса входят в свидетеля разом: без общего замка на сверку и
	// запись подпись получили бы несколько.
	const n = 63
	var arrived sync.WaitGroup
	arrived.Add(n)
	inner := r.w.Handler()
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		arrived.Done()
		arrived.Wait()
		inner.ServeHTTP(w, req)
	}))
	defer ts.Close()
	r.ts = ts
	var wg sync.WaitGroup
	codes := make([]int, n)
	for i := range codes {
		n := int64(i + 2)
		wg.Add(1)
		go func() {
			defer wg.Done()
			codes[n-2], _, _ = r.add(cosign.AddCheckpoint(1, c.proof(n, 1), c.note(n)))
		}()
	}
	wg.Wait()
	ok := 0
	for _, code := range codes {
		switch code {
		case http.StatusOK:
			ok++
		case http.StatusConflict:
		default:
			t.Fatalf("код %d", code)
		}
	}
	latest, _ := r.w.Latest(c.origin())
	if ok != 1 || latest < 2 {
		t.Fatalf("подписано %d из 63 (ждали ровно одну), последняя %d", ok, latest)
	}
	r2 := reopen(t, r.dir, r.key, c)
	if back, _ := r2.w.Latest(c.origin()); back != latest {
		t.Fatalf("на диске %d, в памяти было %d", back, latest)
	}
}

// Часы отступили немного (подстройка NTP) — подписи не идут назад. Часы
// убежали вперёд, и их поправили — подписи снова берут текущее время, а не
// застревают на убежавшем навсегда (и после перезапуска).
func TestWitnessTimeIsMonotonic(t *testing.T) {
	c := newChain(t)
	dir := t.TempDir()
	r := newRig(t, dir, c)
	now := time.Unix(1_800_000_000, 0)
	r.w.Now = func() time.Time { return now }
	c.grow(5)
	t1 := r.mustCosign(c, 0, 2)
	now = now.Add(-2 * time.Second)
	if t2 := r.mustCosign(c, 2, 3); t2 != t1 {
		t.Fatalf("часы отступили на 2 с: подпись %d после %d", t2, t1)
	}
	now = now.Add(30 * 365 * 24 * time.Hour) // убежали на 30 лет
	far := r.mustCosign(c, 3, 4)
	now = now.Add(-30 * 365 * 24 * time.Hour) // поправили
	r2 := reopen(t, dir, r.key, c)
	r2.w.Now = func() time.Time { return now }
	if t3 := r2.mustCosign(c, 4, 5); t3 >= far || t3 != uint64(now.Unix()) {
		t.Fatalf("после поправки часов подпись %d (убежавшая %d, сейчас %d)", t3, far, now.Unix())
	}
}

// Свидетель не забывает: состояние убрали (или подняли старое из копии), а
// журнал подписанного помнит голову новее — свидетель не стартует; иначе он
// подписал бы тем же ключом вторую историю.
func TestWitnessRefusesToForget(t *testing.T) {
	c := newChain(t)
	dir := t.TempDir()
	r := newRig(t, dir, c)
	c.grow(6)
	r.mustCosign(c, 0, 3)
	statePath := filepath.Join(dir, stateDir, OriginHash(c.origin())+".json")
	old, err := os.ReadFile(statePath)
	if err != nil {
		t.Fatal(err)
	}
	r.mustCosign(c, 3, 6)
	r.w.Close()

	// Состояние подняли из старой копии: голова 3 при подписанной 6.
	if err := os.WriteFile(statePath, old, 0o600); err != nil {
		t.Fatal(err)
	}
	var logs []Log
	logs = append(logs, Log{Origin: c.origin(), Key: c.signer.PublicKey()})
	if _, err := New(r.key, logs, dir, nil); err == nil || !strings.Contains(err.Error(), "older than head 6") {
		t.Fatalf("откат состояния: %v", err)
	}
	// Состояние убрали совсем.
	os.Remove(statePath)
	if _, err := New(r.key, logs, dir, nil); err == nil || !strings.Contains(err.Error(), "is missing") || !strings.Contains(err.Error(), "new key") {
		t.Fatalf("пропавшее состояние: %v", err)
	}
}

func TestWitnessCheckpointEndpoint(t *testing.T) {
	c := newChain(t)
	r := newRig(t, t.TempDir(), c)
	if resp, _ := http.Get(r.ts.URL + "/" + OriginHash(c.origin()) + "/checkpoint"); resp.StatusCode != http.StatusNotFound {
		t.Fatalf("до первой подписи: %d", resp.StatusCode)
	}
	c.grow(3)
	r.mustCosign(c, 0, 3)
	resp, err := http.Get(r.ts.URL + "/" + OriginHash(c.origin()) + "/checkpoint")
	if err != nil {
		t.Fatal(err)
	}
	note, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	text, sigs, err := cosign.SplitNote(note)
	if err != nil || len(sigs) != 2 {
		t.Fatalf("точка свидетеля %q: %v", note, err)
	}
	if err := cosign.VerifyLogSignature(text, sigs, c.origin(), c.signer.PublicKey()); err != nil {
		t.Fatal(err)
	}
	_, sig, _ := cosign.ParseSigLine(sigs[1])
	if _, err := r.key.Verifier().Verify(text, sig); err != nil {
		t.Fatalf("подпись свидетеля в точке: %v", err)
	}
}

// Испорченное состояние — не «ещё не подписывал»: свидетель не стартует, а
// не подписывает с нуля любую историю.
func TestWitnessDamagedStateStops(t *testing.T) {
	c := newChain(t)
	dir := t.TempDir()
	r := newRig(t, dir, c)
	c.grow(2)
	r.mustCosign(c, 0, 2)
	path := filepath.Join(dir, stateDir, OriginHash(c.origin())+".json")
	if err := os.WriteFile(path, []byte("{"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := New(r.key, []Log{{Origin: c.origin(), Key: c.signer.PublicKey()}}, dir, nil); err == nil {
		t.Fatal("свидетель стартовал с испорченным состоянием")
	}
	// И без журнала подписанного (каталог прежней версии): испорченное
	// состояние — не «ещё не подписывали».
	r.w.Close()
	os.Remove(filepath.Join(dir, cosignedFile))
	if _, err := New(r.key, []Log{{Origin: c.origin(), Key: c.signer.PublicKey()}}, dir, nil); err == nil || !strings.Contains(err.Error(), "does not parse") {
		t.Fatalf("без журнала подписанного свидетель стартовал с испорченным состоянием: %v", err)
	}
}

func TestLockIsExclusive(t *testing.T) {
	dir := t.TempDir()
	l, err := Lock(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	if _, err := Lock(dir); err == nil {
		t.Fatal("второй замок на тот же каталог")
	}
}

func TestBodyLimit(t *testing.T) {
	c := newChain(t)
	r := newRig(t, t.TempDir(), c)
	big := fmt.Sprintf("old 0\n\n%s", strings.Repeat("x", MaxBody))
	if code, body, _ := r.add([]byte(big)); code != http.StatusBadRequest || !strings.Contains(body, "too large") {
		t.Fatalf("тело больше предела: %d %q", code, body)
	}
}

// Оборванная последняя строка журнала подписанного (падение посреди записи)
// отрезается при запуске: следующая подпись ложится целой строкой, и
// следующий запуск проходит.
func TestWitnessLedgerTornTail(t *testing.T) {
	c := newChain(t)
	dir := t.TempDir()
	r := newRig(t, dir, c)
	c.grow(4)
	r.mustCosign(c, 0, 2)
	r.w.Close()
	ledger := filepath.Join(dir, cosignedFile)
	f, err := os.OpenFile(ledger, os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	f.WriteString(`{"origin":"` + c.origin() + `","si`)
	f.Close()
	r2 := reopen(t, dir, r.key, c)
	r2.mustCosign(c, 2, 4)
	r2.w.Close()
	if _, err := New(r.key, []Log{{Origin: c.origin(), Key: c.signer.PublicKey()}}, dir, nil); err != nil {
		t.Fatalf("после оборванной строки свидетель не стартует: %v", err)
	}
	data, _ := os.ReadFile(ledger)
	if bytes.Contains(data, []byte(`"si{`)) || !bytes.HasSuffix(data, []byte("\n")) {
		t.Fatalf("журнал подписанного: %q", data)
	}
}

// Та же голова снова (публичная заметка из GET …/checkpoint): ответ — уже
// данная подпись, на диск ничего не пишется.
func TestWitnessReplayWritesNothing(t *testing.T) {
	c := newChain(t)
	dir := t.TempDir()
	r := newRig(t, dir, c)
	now := time.Unix(1_800_000_000, 0)
	r.w.Now = func() time.Time { return now }
	c.grow(3)
	t1 := r.mustCosign(c, 0, 3)
	ledger := filepath.Join(dir, cosignedFile)
	before, _ := os.ReadFile(ledger)
	statePath := filepath.Join(dir, stateDir, OriginHash(c.origin())+".json")
	stateBefore, _ := os.ReadFile(statePath)
	now = now.Add(time.Hour)
	for range 20 {
		if t2 := r.mustCosign(c, 3, 3); t2 != t1 {
			t.Fatalf("повтор той же головы — новая подпись: время %d, было %d", t2, t1)
		}
	}
	after, _ := os.ReadFile(ledger)
	stateAfter, _ := os.ReadFile(statePath)
	if !bytes.Equal(before, after) || !bytes.Equal(stateBefore, stateAfter) {
		t.Fatalf("повторы той же головы писали на диск: журнал %d → %d байт", len(before), len(after))
	}
}

// syncBuf — журнал процесса в памяти для нескольких горутин.
type syncBuf struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (b *syncBuf) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.b.Write(p)
}

func (b *syncBuf) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.b.String()
}

// Повтор одной развилки — 422 каждый раз, но строка в журнал процесса и в
// журнал отказов одна: пару голов пришлёт кто угодно, у кого она есть, и
// залить журнал процесса свидетеля нельзя (T).
func TestWitnessForkLoggedOnce(t *testing.T) {
	c, forged := newChain(t), newChain(t)
	c.grow(4)
	forged.grow(4)
	_, priv, _ := ed25519.GenerateKey(rand.Reader)
	key, err := cosign.NewSigner("witness.example/w1", priv)
	if err != nil {
		t.Fatal(err)
	}
	var out syncBuf
	r := reopenLog(t, t.TempDir(), key, slog.New(slog.NewTextHandler(&out, nil)), c)
	r.mustCosign(c, 0, 4)
	for range 5 {
		if code, _, _ := r.add(cosign.AddCheckpoint(4, nil, sameKey(t, c, forged, 4))); code != http.StatusUnprocessableEntity {
			t.Fatalf("развилка: %d", code)
		}
	}
	if n := strings.Count(out.String(), "refused a checkpoint"); n != 1 || len(readRefusals(t, r.dir)) != 1 {
		t.Fatalf("пять повторов одной развилки: %d строк в журнале процесса, %d в журнале отказов", n, len(readRefusals(t, r.dir)))
	}
}

// Журнал подписанного больше предела при старте сжимается до последней
// головы каждого журнала: старт не читает годами растущий файл, а защита от
// забывания остаётся (T).
func TestWitnessLedgerCompacted(t *testing.T) {
	defer func(v int64) { compactLedgerAbove = v }(compactLedgerAbove)
	compactLedgerAbove = 1
	c, other := newChain(t), newChain(t)
	dir := t.TempDir()
	r := newRig(t, dir, c, other)
	c.grow(6)
	other.grow(2)
	r.mustCosign(other, 0, 2)
	r.mustCosign(c, 0, 2)
	r.mustCosign(c, 2, 4)
	statePath := filepath.Join(dir, stateDir, OriginHash(c.origin())+".json")
	old, err := os.ReadFile(statePath)
	if err != nil {
		t.Fatal(err)
	}
	r.mustCosign(c, 4, 6)
	r.w.Close()

	r2 := reopen(t, dir, r.key, c, other)
	data, err := os.ReadFile(filepath.Join(dir, cosignedFile))
	if err != nil {
		t.Fatal(err)
	}
	if n := bytes.Count(data, []byte("\n")); n != 2 || !bytes.Contains(data, []byte(`"size":6`)) {
		t.Fatalf("после сжатия в журнале %d строк: %s", n, data)
	}
	if _, err := os.Stat(filepath.Join(dir, cosignedFile+".tmp")); !os.IsNotExist(err) {
		t.Fatalf("временный файл сжатия остался: %v", err)
	}
	c.grow(7)
	r2.mustCosign(c, 6, 7) // дописывается после сжатия целой строкой
	r2.w.Close()

	// Состояние подняли из старой копии: сжатый журнал помнит голову 7.
	if err := os.WriteFile(statePath, old, 0o600); err != nil {
		t.Fatal(err)
	}
	logs := []Log{{Origin: c.origin(), Key: c.signer.PublicKey()}, {Origin: other.origin(), Key: other.signer.PublicKey()}}
	if _, err := New(r.key, logs, dir, nil); err == nil || !strings.Contains(err.Error(), "older than head 7") {
		t.Fatalf("откат состояния после сжатия: %v", err)
	}
}

// Граница правила времени: ровно 10 минут назад — прежнее время подписи, на
// секунду больше (и после перезапуска, по состоянию) — текущее (T).
func TestWitnessTimeRuleBoundary(t *testing.T) {
	c := newChain(t)
	dir := t.TempDir()
	r := newRig(t, dir, c)
	now := time.Unix(1_800_000_000, 0)
	r.w.Now = func() time.Time { return now }
	c.grow(4)
	t1 := r.mustCosign(c, 0, 2)
	now = now.Add(-maxClockStepBack)
	if t2 := r.mustCosign(c, 2, 3); t2 != t1 {
		t.Fatalf("ровно 10 минут назад: %d, прежняя %d", t2, t1)
	}
	r.w.Close()
	r2 := reopen(t, dir, r.key, c)
	now = time.Unix(int64(t1), 0).Add(-maxClockStepBack - time.Second)
	r2.w.Now = func() time.Time { return now }
	if t3 := r2.mustCosign(c, 3, 4); t3 != uint64(now.Unix()) {
		t.Fatalf("на 10 минут и секунду назад после перезапуска: %d, сейчас %d, прежняя %d", t3, now.Unix(), t1)
	}
}
