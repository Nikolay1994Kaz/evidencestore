package store

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"maps"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Nikolay1994Kaz/evidencestore/internal/config"
	"github.com/Nikolay1994Kaz/evidencestore/internal/cosign"
	"github.com/Nikolay1994Kaz/evidencestore/internal/proof"
	"github.com/Nikolay1994Kaz/evidencestore/internal/ship"
	"github.com/Nikolay1994Kaz/evidencestore/internal/witness"
)

// liveWitness — настоящий свидетель C2SP (internal/witness) за httptest:
// ключ свидетеля известен до хранилища, а ключ хранилища — после его
// открытия, поэтому свидетель заводится в attach. down — свидетель отвечает
// 503.
type liveWitness struct {
	t    *testing.T
	key  cosign.Signer
	dir  string
	srv  atomic.Pointer[witness.Server]
	ts   *httptest.Server
	down atomic.Bool
	hits atomic.Int64
	// conflicts — ответов 409: свидетель назвал свой размер.
	conflicts atomic.Int64
	// corrupt — в ответе 200 испорчен последний байт подписи (имя и номер
	// ключа верные); plain409 — ответ 409 без типа text/x.tlog.size; hang —
	// свидетель не отвечает, пока клиент не бросит запрос.
	corrupt, plain409, hang atomic.Bool
}

func newLiveWitness(t *testing.T, name string) *liveWitness {
	return startLiveWitness(t, name, false)
}

// startLiveWitness — свидетель за httptest, с tls — за HTTPS с сертификатом
// httptest (его УЦ — w.caFile).
func startLiveWitness(t *testing.T, name string, tls bool) *liveWitness {
	t.Helper()
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	key, err := cosign.NewSigner(name, priv)
	if err != nil {
		t.Fatal(err)
	}
	w := &liveWitness{t: t, key: key, dir: t.TempDir()}
	h := http.HandlerFunc(func(rw http.ResponseWriter, r *http.Request) {
		w.hits.Add(1)
		srv := w.srv.Load()
		if w.down.Load() || srv == nil {
			http.Error(rw, "down", http.StatusServiceUnavailable)
			return
		}
		if w.hang.Load() {
			// Тело дочитано: тогда сервер видит, что клиент бросил запрос.
			io.Copy(io.Discard, r.Body)
			<-r.Context().Done()
			return
		}
		rec := httptest.NewRecorder()
		srv.Handler().ServeHTTP(rec, r)
		body := rec.Body.Bytes()
		if rec.Code == http.StatusConflict {
			w.conflicts.Add(1)
		}
		if w.corrupt.Load() && rec.Code == http.StatusOK {
			name, sig, err := cosign.ParseSigLine(strings.TrimSuffix(string(body), "\n"))
			if err != nil {
				t.Errorf("ответ свидетеля %q: %v", body, err)
			} else {
				sig[len(sig)-1] ^= 1
				body = []byte(cosign.SigLine(name, sig))
			}
		}
		if w.plain409.Load() && rec.Code == http.StatusConflict {
			rec.Header().Set("Content-Type", "text/plain; charset=utf-8")
		}
		maps.Copy(rw.Header(), rec.Header())
		rw.WriteHeader(rec.Code)
		rw.Write(body)
	})
	if tls {
		w.ts = httptest.NewTLSServer(h)
	} else {
		w.ts = httptest.NewServer(h)
	}
	t.Cleanup(w.ts.Close)
	return w
}

// caFile — сертификат HTTPS свидетеля в PEM: его УЦ для witness.cosigners[].ca.
func (w *liveWitness) caFile() string {
	w.t.Helper()
	path := filepath.Join(w.t.TempDir(), "witness-ca.pem")
	data := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: w.ts.Certificate().Raw})
	if err := os.WriteFile(path, data, 0o600); err != nil {
		w.t.Fatal(err)
	}
	return path
}

// option — свидетель в witness.cosigners хранилища.
func (w *liveWitness) option() func(*config.Config) {
	return func(c *config.Config) {
		c.Witness.Cosigners = append(c.Witness.Cosigners, config.Cosigner{URL: w.ts.URL, Key: w.key.Verifier().String()})
	}
}

// attach заводит свидетеля для хранилища s (его ключ уже есть).
func (w *liveWitness) attach(s *Store) {
	w.t.Helper()
	pub, err := base64.RawStdEncoding.DecodeString(s.PublicKey())
	if err != nil {
		w.t.Fatal(err)
	}
	srv, err := witness.New(w.key, []witness.Log{{Origin: proof.OriginFor(pub), Key: pub}}, w.dir, quiet)
	if err != nil {
		w.t.Fatal(err)
	}
	w.srv.Store(srv)
}

func (w *liveWitness) trust(t *testing.T, s *Store) proof.Trust {
	tr := trustOf(t, s)
	tr.Cosigners = append(tr.Cosigners, w.key.Verifier())
	return tr
}

func mustCosign(t *testing.T, s *Store) {
	t.Helper()
	if err := s.CosignOnce(context.Background()); err != nil {
		t.Fatal(err)
	}
}

// ⭐ Свидетель подписывает головы, подписи ложатся в журнал и едут в пакетах:
// пакет одной улики, за окно и по источнику проходят с ключом свидетеля, и
// каждый закрепляет голова не раньше своего звена.
func TestCosignedBundles(t *testing.T) {
	c := newClock()
	w := newLiveWitness(t, "witness.example/w1")
	s := openStore(t, testConfig(t, w.option()), c)
	w.attach(s)
	ingest(t, s, "abs-core", 1, 3)
	mustStamp(t, s)
	mustCosign(t, s)
	c.add(5 * time.Minute)
	ingest(t, s, "abs-core", 4, 6)
	c.add(5 * time.Minute)
	mustStamp(t, s)
	mustCosign(t, s)
	c.add(time.Minute)
	ingest(t, s, "abs-core", 7, 8)
	mustStamp(t, s)
	mustCosign(t, s)
	c.add(time.Minute)
	mustStamp(t, s)
	mustCosign(t, s)

	tr := w.trust(t, s)
	b, err := s.Proof("abs-core", 5, false)
	if err != nil {
		t.Fatal(err)
	}
	r := proof.Verify(b, tr)
	if !r.Valid() || len(r.Cosigned) != 1 || r.Cosigned[0].Size < r.LinkSeq || r.Cosigned[0].Size > b.Checkpoint.Size {
		t.Fatalf("пакет одной улики:\n%s", r.Text())
	}
	from, to := clockAt(10, 4, 0), clockAt(10, 6, 0)
	wb, err := s.ProofWindow(from, to, "", false, 0)
	if err != nil {
		t.Fatal(err)
	}
	wr := proof.VerifyWindow(roundTrip(t, wb), tr, time.Time{}, time.Time{})
	if !wr.Valid() || len(wr.Cosigned) != 1 || wr.Cosigned[0].Size < wb.StretchEnd {
		t.Fatalf("пакет за окно:\n%s", wr.Text())
	}
	sb, err := s.ProofSource("abs-core", from, to, false, 0)
	if err != nil {
		t.Fatal(err)
	}
	sr := proof.VerifySource(sb, tr, time.Time{}, time.Time{})
	if !sr.Valid() || len(sr.Cosigned) != 1 || sr.Cosigned[0].Size < sb.Upper.Token.LinkSeq {
		t.Fatalf("пакет по источнику:\n%s", sr.Text())
	}

	if q := s.cosigners[0].queue; len(q) != 0 {
		t.Fatalf("после подписи в очереди %d голов", len(q))
	}
	// Свидетель знает ровно ту голову, что хранилище записало последней.
	st := s.Status()
	if len(st.Cosigners) != 1 || st.Cosigners[0].Head == 0 || st.Cosigners[0].LastError != "" {
		t.Fatalf("status: %+v", st.Cosigners)
	}
	if n, _ := w.srv.Load().Latest(proof.OriginFor(tr.StoreKey)); n != st.Cosigners[0].Head {
		t.Fatalf("у свидетеля голова %d, хранилище знает %d", n, st.Cosigners[0].Head)
	}
}

// Журнал подписей переживает перезапуск: пакет несёт подпись и тогда, когда
// свидетель недоступен. После запуска хранилище спрашивает свидетеля с
// последней головы в журнале подписей — она и есть его голова, так что 409 нет.
func TestCosignJournalAcrossRestart(t *testing.T) {
	c := newClock()
	w := newLiveWitness(t, "witness.example/w1")
	cfg := testConfig(t, w.option())
	s := openStore(t, cfg, c)
	w.attach(s)
	ingest(t, s, "abs-core", 1, 3)
	mustStamp(t, s)
	mustCosign(t, s)
	c.add(time.Minute)
	mustStamp(t, s)
	mustCosign(t, s)
	before, err := s.Proof("abs-core", 2, false)
	if err != nil {
		t.Fatal(err)
	}
	s.Close()

	s2, err := reopen(cfg, c)
	if err != nil {
		t.Fatal(err)
	}
	defer s2.Close()
	w.down.Store(true)
	after, err := s2.Proof("abs-core", 2, false)
	if err != nil {
		t.Fatal(err)
	}
	if len(after.Cosignatures) != 1 || string(after.Cosignatures[0].Sig) != string(before.Cosignatures[0].Sig) {
		t.Fatalf("после перезапуска подписи в пакете: %+v, до: %+v", after.Cosignatures, before.Cosignatures)
	}
	if r := proof.Verify(after, w.trust(t, s2)); !r.Valid() {
		t.Fatalf("пакет после перезапуска:\n%s", r.Text())
	}
	w.down.Store(false)
	ingest(t, s2, "abs-core", 4, 4)
	mustStamp(t, s2)
	hits := w.hits.Load()
	mustCosign(t, s2)
	if w.hits.Load() == hits || w.conflicts.Load() != 0 {
		t.Fatalf("после перезапуска к свидетелю %d запросов, ответов 409 — %d: ждали подписи с головы из журнала", w.hits.Load()-hits, w.conflicts.Load())
	}
	if st := s2.Status(); st.Cosigners[0].LastError != "" || st.Cosigners[0].Head != s2.Head().Seq {
		t.Fatalf("после перезапуска: %+v, голова %d", st.Cosigners, s2.Head().Seq)
	}
}

// Свидетель недоступен: головы под метками ждут в очереди, ошибка видна в
// status; вернулся — уходят все, и пакет закрепляет ранняя голова.
func TestCosignWhileWitnessDown(t *testing.T) {
	c := newClock()
	w := newLiveWitness(t, "witness.example/w1")
	s := openStore(t, testConfig(t, w.option()), c)
	w.attach(s)
	w.down.Store(true)
	ingest(t, s, "abs-core", 1, 3)
	mustStamp(t, s)
	if err := s.CosignOnce(context.Background()); err == nil {
		t.Fatal("подпись от недоступного свидетеля")
	}
	st := s.Status()
	if st.Cosigners[0].Errors != 1 || st.Cosigners[0].LastError == "" {
		t.Fatalf("status при недоступном свидетеле: %+v", st.Cosigners)
	}
	c.add(time.Minute)
	ingest(t, s, "abs-core", 4, 4)
	mustStamp(t, s)
	w.down.Store(false)
	mustCosign(t, s)
	b, err := s.Proof("abs-core", 2, false)
	if err != nil {
		t.Fatal(err)
	}
	r := proof.Verify(b, w.trust(t, s))
	if !r.Valid() || r.Cosigned[0].Size > b.Upper.HeadSeq {
		t.Fatalf("после возвращения свидетеля:\n%s", r.Text())
	}
	if st := s.Status(); st.Cosigners[0].LastError != "" {
		t.Fatalf("ошибка осталась после удачи: %+v", st.Cosigners)
	}
}

// Свидетель держит другую историю этого хранилища (его состояние —
// голова с чужим корнем): доказательство не сходится, ответ 422 — тревога,
// и голова остаётся в очереди, а не уходит молча.
func TestCosignRefusedIsAlarm(t *testing.T) {
	c := newClock()
	w := newLiveWitness(t, "witness.example/w1")
	s := openStore(t, testConfig(t, w.option()), c)
	w.attach(s)
	ingest(t, s, "abs-core", 1, 3)
	mustStamp(t, s)
	mustCosign(t, s)
	origin := proof.OriginFor(w.trust(t, s).StoreKey)
	size, _ := w.srv.Load().Latest(origin)
	// Состояние свидетеля: та же голова, другой корень.
	path := filepath.Join(w.dir, "state", witness.OriginHash(origin)+".json")
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	other := make([]byte, 32)
	other[0] = 1
	data = []byte(strings.Replace(string(data), `"root":"`, `"root":"`+base64.StdEncoding.EncodeToString(other)+`","old_root":"`, 1))
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
	// Журнал подписанного свидетель бы сверил с состоянием и не стартовал:
	// здесь свидетель «видел» другую историю с самого начала.
	if err := os.Remove(filepath.Join(w.dir, "cosigned.jsonl")); err != nil {
		t.Fatal(err)
	}
	w.attach(s) // свидетель перечитал состояние
	ingest(t, s, "abs-core", 4, 4)
	mustStamp(t, s)
	err = s.CosignOnce(context.Background())
	if err == nil || !strings.Contains(err.Error(), "holds another history") {
		t.Fatalf("развилка у свидетеля: %v", err)
	}
	st := s.Status()
	if !st.Cosigners[0].Refused || st.Cosigners[0].Head != size {
		t.Fatalf("status после отказа: %+v", st.Cosigners)
	}
	if len(s.cosigners[0].queue) == 0 {
		t.Fatal("отвергнутая голова ушла из очереди")
	}
	if err := s.CosignOnce(context.Background()); err == nil {
		t.Fatal("тревога пропала на втором обходе")
	}

	// Убрать состояние свидетеля — не выход: он забыл бы, что подписал, и
	// подписал бы тем же ключом вторую историю. Хранилище это видит (409 с
	// размером младше подписанного по его журналу) — тревога, а не «с нуля».
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	w.attach(s)
	err = s.CosignOnce(context.Background())
	if err == nil || !strings.Contains(err.Error(), "lost its state") {
		t.Fatalf("свидетель без состояния: %v", err)
	}
	if st := s.Status(); !st.Cosigners[0].LostState {
		t.Fatalf("status: %+v", st.Cosigners)
	}
	if n, ok := w.srv.Load().Latest(origin); ok {
		t.Fatalf("свидетель без состояния подписал голову %d", n)
	}
}

// Свидетель потерял состояние, а хранилище перезапустилось: оно спрашивает не
// с нуля, а с последней головы этого свидетеля в журнале подписей, — и видит
// потерю (409 «0»), вместо того чтобы получить подпись «первой» головы.
func TestCosignWitnessLostStateAfterRestart(t *testing.T) {
	c := newClock()
	w := newLiveWitness(t, "witness.example/w1")
	cfg := testConfig(t, w.option())
	s := openStore(t, cfg, c)
	w.attach(s)
	ingest(t, s, "abs-core", 1, 3)
	mustStamp(t, s)
	mustCosign(t, s)
	origin := proof.OriginFor(w.trust(t, s).StoreKey)
	s.Close()
	// Свидетель потерял каталог данных целиком (тот же ключ).
	os.RemoveAll(w.dir)
	os.MkdirAll(w.dir, 0o700)
	s2, err := reopen(cfg, c)
	if err != nil {
		t.Fatal(err)
	}
	defer s2.Close()
	w.attach(s2)
	ingest(t, s2, "abs-core", 4, 4)
	mustStamp(t, s2)
	err = s2.CosignOnce(context.Background())
	if err == nil || !strings.Contains(err.Error(), "lost its state") {
		t.Fatalf("после перезапуска хранилища: %v", err)
	}
	if st := s2.Status(); !st.Cosigners[0].LostState {
		t.Fatalf("status: %+v", st.Cosigners)
	}
	if n, ok := w.srv.Load().Latest(origin); ok {
		t.Fatalf("свидетель без состояния подписал голову %d как первую", n)
	}
}

// Падение между ответом свидетеля и записью в журнал: свидетель держит голову,
// подписи которой у хранилища нет. После запуска хранилище узнаёт её из 409 и
// просит подписать снова: пакет до неё (-to-head) несёт её подпись.
func TestCosignRecoversLostCosignature(t *testing.T) {
	c := newClock()
	w := newLiveWitness(t, "witness.example/w1")
	cfg := testConfig(t, w.option())
	s := openStore(t, cfg, c)
	w.attach(s)
	ingest(t, s, "abs-core", 1, 3)
	mustStamp(t, s)
	mustCosign(t, s)
	origin := proof.OriginFor(w.trust(t, s).StoreKey)
	latest, _ := w.srv.Load().Latest(origin)
	s.Close()
	// Последняя строка журнала (подпись головы latest) не легла на диск.
	path := filepath.Join(cfg.DataDir, filepath.FromSlash(cosignFile))
	data, _ := os.ReadFile(path)
	var keep []byte
	for line := range bytes.Lines(data) {
		var r cosigRecord
		json.Unmarshal(line, &r)
		if r.Size < latest {
			keep = append(keep, line...)
		}
	}
	os.WriteFile(path, keep, 0o600)
	s2, err := reopen(cfg, c)
	if err != nil {
		t.Fatal(err)
	}
	defer s2.Close()
	if s2.hasCosig(w.key.Verifier(), latest) {
		t.Fatal("подпись головы осталась в журнале")
	}
	ingest(t, s2, "abs-core", 4, 4)
	mustStamp(t, s2)
	mustCosign(t, s2)
	if !s2.hasCosig(w.key.Verifier(), latest) {
		t.Fatalf("подпись головы %d, которую держит свидетель, не запрошена снова", latest)
	}
	b, err := s2.ProofTo("abs-core", 3, false, latest)
	if err != nil {
		t.Fatal(err)
	}
	if r := proof.Verify(b, w.trust(t, s2)); !r.Valid() || r.Cosigned[0].Size > latest {
		t.Fatalf("пакет до головы %d:\n%s", latest, r.Text())
	}
}

// Свидетель отвечает перенаправлением на другой адрес: хранилище туда не
// идёт, голова уходит только по адресу из конфигурации.
func TestCosignNoRedirects(t *testing.T) {
	c := newClock()
	var elsewhere atomic.Int64
	other := httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, r *http.Request) { elsewhere.Add(1) }))
	defer other.Close()
	redirect := httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, r *http.Request) {
		http.Redirect(rw, r, other.URL+"/add-checkpoint", http.StatusTemporaryRedirect)
	}))
	defer redirect.Close()
	w := newLiveWitness(t, "witness.example/w1")
	s := openStore(t, testConfig(t, func(cf *config.Config) {
		cf.Witness.Cosigners = []config.Cosigner{{URL: redirect.URL, Key: w.key.Verifier().String()}}
	}), c)
	ingest(t, s, "abs-core", 1, 1)
	mustStamp(t, s)
	if err := s.CosignOnce(context.Background()); err == nil || !strings.Contains(err.Error(), "HTTP 307") {
		t.Fatalf("перенаправление: %v", err)
	}
	if elsewhere.Load() != 0 {
		t.Fatalf("голова ушла по перенаправлению: %d запросов", elsewhere.Load())
	}
}

// Зависший свидетель не держит остановку хранилища: обход отменяется, когда
// хранилище закрывается (контекст stopCtx, как в фоновом цикле).
func TestCosignCloseNotHeldByHangingWitness(t *testing.T) {
	c := newClock()
	w := newLiveWitness(t, "witness.example/w1")
	s := openStore(t, testConfig(t, w.option()), c)
	w.attach(s)
	w.hang.Store(true)
	ingest(t, s, "abs-core", 1, 1)
	mustStamp(t, s)
	ctx, cancel := s.stopCtx(time.Minute)
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- s.CosignOnce(ctx) }()
	time.Sleep(200 * time.Millisecond)
	start := time.Now()
	close(s.stop)
	select {
	case <-done:
	case <-time.After(10 * time.Second):
		t.Fatal("обход ждёт зависшего свидетеля после остановки")
	}
	if d := time.Since(start); d > 5*time.Second {
		t.Fatalf("остановка ждала свидетеля %v", d)
	}
	s.stop = make(chan struct{}) // Close закроет свой
}

// С копией наружу текущая голова под нагрузкой всегда дальше копии; свидетелю
// уходит голова копии, и подписанная голова идёт за копией каждый обход, а не
// раз в метку TSA.
func TestCosignFollowsCopyWithoutStamps(t *testing.T) {
	c := newClock()
	ctx := context.Background()
	w := newLiveWitness(t, "witness.example/w1")
	cfg, remote := replicaConfig(t)
	w.option()(cfg)
	s := openStore(t, cfg, c)
	w.attach(s)
	ingest(t, s, "abs-core", 1, 2)
	mustStamp(t, s)
	origin := proof.OriginFor(w.trust(t, s).StoreKey)
	var seq uint64 = 3
	for round := range 5 {
		ingest(t, s, "abs-core", seq, seq)
		seq++
		if err := s.flush(); err != nil {
			t.Fatal(err)
		}
		if _, err := s.ShipOnce(ctx, remote); err != nil {
			t.Fatal(err)
		}
		ingest(t, s, "abs-core", seq, seq) // голова снова дальше копии
		seq++
		if err := s.flush(); err != nil {
			t.Fatal(err)
		}
		mustCosign(t, s)
		n, _ := w.srv.Load().Latest(origin)
		if shipped := s.replicaShipped.Load(); n != shipped {
			t.Fatalf("обход %d: свидетель на голове %d, копия держит %d", round, n, shipped)
		}
	}
}

// Свидетель подписал больше звеньев, чем есть в цепи: тревога, голов не
// уходит; но размер в следующем обходе спрашивается у свидетеля заново, и
// когда свидетель — снова позади цепи (его сбросили, или знание хранилища
// было ложным), подписи идут дальше без перезапуска.
func TestCosignWitnessAheadHeals(t *testing.T) {
	c := newClock()
	w := newLiveWitness(t, "witness.example/w1")
	s := openStore(t, testConfig(t, w.option()), c)
	w.attach(s)
	ingest(t, s, "abs-core", 1, 3)
	mustStamp(t, s)
	mustCosign(t, s)
	cs := s.cosigners[0]
	cs.size, cs.known = s.Head().Seq+100, true // как после подъёма из старой копии
	ingest(t, s, "abs-core", 4, 4)
	mustStamp(t, s)
	err := s.CosignOnce(context.Background())
	if err == nil || !strings.Contains(err.Error(), "this chain has fewer links") {
		t.Fatalf("свидетель впереди цепи: %v", err)
	}
	if len(cs.queue) == 0 {
		t.Fatal("голова ушла из очереди при тревоге")
	}
	mustCosign(t, s)
	if st := s.Status(); st.Cosigners[0].Head != s.Head().Seq || st.Cosigners[0].LastError != "" {
		t.Fatalf("после второго обхода: %+v, голова %d", st.Cosigners, s.Head().Seq)
	}
}

// Ключ свидетеля в конфигурации не тот, что у свидетеля: подпись другого
// ключа хранилище не берёт — в журнал ничего не ложится.
func TestCosignWrongKeyConfigured(t *testing.T) {
	c := newClock()
	w := newLiveWitness(t, "witness.example/w1")
	impostor := newLiveWitness(t, "witness.example/w1") // то же имя, другой ключ
	cfg := testConfig(t, func(cf *config.Config) {
		cf.Witness.Cosigners = []config.Cosigner{{URL: w.ts.URL, Key: impostor.key.Verifier().String()}}
	})
	s := openStore(t, cfg, c)
	w.attach(s)
	ingest(t, s, "abs-core", 1, 3)
	mustStamp(t, s)
	err := s.CosignOnce(context.Background())
	if err == nil || !strings.Contains(err.Error(), "without a cosignature by its configured key") {
		t.Fatalf("подпись чужого ключа: %v", err)
	}
	if fi, err := os.Stat(filepath.Join(cfg.DataDir, filepath.FromSlash(cosignFile))); err != nil || fi.Size() != 0 {
		t.Fatalf("журнал подписей после чужой подписи: %v %v", fi, err)
	}
}

// Свидетель не обгоняет копию наружу: голова, которой нет в копии, не
// уходит; после прохода копии — уходит.
func TestCosignNeverAheadOfCopy(t *testing.T) {
	c := newClock()
	ctx := context.Background()
	w := newLiveWitness(t, "witness.example/w1")
	cfg, remote := replicaConfig(t)
	w.option()(cfg)
	s := openStore(t, cfg, c)
	w.attach(s)
	ingest(t, s, "abs-core", 1, 3)
	mustStamp(t, s)
	mustCosign(t, s)
	origin := proof.OriginFor(w.trust(t, s).StoreKey)
	if n, ok := w.srv.Load().Latest(origin); ok {
		t.Fatalf("свидетель подписал голову %d раньше копии", n)
	}
	if _, err := s.ShipOnce(ctx, remote); err != nil {
		t.Fatal(err)
	}
	mustCosign(t, s)
	n, ok := w.srv.Load().Latest(origin)
	if !ok || n > s.replicaShipped.Load() {
		t.Fatalf("после копии: свидетель %d, копия %d", n, s.replicaShipped.Load())
	}
}

// Журнал подписей: оборванная последняя строка отрезается, чужие и битые
// строки не идут в пакеты, хранилище стартует.
func TestCosignJournalDamage(t *testing.T) {
	c := newClock()
	w := newLiveWitness(t, "witness.example/w1")
	cfg := testConfig(t, w.option())
	s := openStore(t, cfg, c)
	w.attach(s)
	ingest(t, s, "abs-core", 1, 3)
	mustStamp(t, s)
	mustCosign(t, s)
	// Цепь уходит дальше последней подписанной головы: строка «голова длины
	// цепи» ниже — не повтор последней верной.
	ingest(t, s, "abs-core", 4, 4)
	if err := s.flush(); err != nil {
		t.Fatal(err)
	}
	pub, _ := base64.RawStdEncoding.DecodeString(s.PublicKey())
	chainLen := s.Head().Seq
	s.Close()
	path := filepath.Join(cfg.DataDir, filepath.FromSlash(cosignFile))
	good, err := os.ReadFile(path)
	if err != nil || len(good) == 0 {
		t.Fatalf("журнал: %v", err)
	}
	// Перед настоящей строкой — та же голова с испорченной подписью (имя и
	// номер ключа верные) и голова, подписанная свидетелем над корнем, которого
	// нет в цепи: в пакет не идёт ни одна, иначе пакет бы не прошёл.
	var rec cosigRecord
	firstLine, _, _ := bytes.Cut(good, []byte("\n"))
	if err := json.Unmarshal(firstLine, &rec); err != nil {
		t.Fatal(err)
	}
	forged := rec
	forged.Sig = bytes.Clone(rec.Sig)
	forged.Sig[len(forged.Sig)-1] ^= 1
	foreign := rec
	foreign.Root = make([]byte, 32)
	foreign.Root[0] = 7
	foreign.Sig = w.key.Cosign(cosign.CheckpointText(proof.OriginFor(pub), rec.Size, [32]byte(foreign.Root)), uint64(c.now().Unix()-60))
	line := func(r cosigRecord) string {
		b, _ := json.Marshal(r)
		return string(b) + "\n"
	}
	// После настоящих строк — голова за концом цепи: в пакеты и в status она
	// не идёт.
	beyond := rec
	beyond.Size = 1 << 40
	beyond.Sig = w.key.Cosign(cosign.CheckpointText(proof.OriginFor(pub), beyond.Size, [32]byte(rec.Root)), uint64(c.now().Unix()))
	// Последняя целая строка — голова длины цепи с испорченной подписью: при
	// запуске она не берётся, и status с запросом к свидетелю опираются на
	// последнюю верную.
	tail := rec
	tail.Size = chainLen
	tail.Sig = bytes.Clone(rec.Sig)
	tail.Sig[len(tail.Sig)-1] ^= 1
	var lastGood uint64
	for l := range bytes.Lines(good) {
		var r cosigRecord
		json.Unmarshal(l, &r)
		lastGood = max(lastGood, r.Size)
	}
	// Первой — та же испорченная голова длины цепи: завышенный размер в
	// начале не прячет верные строки после неё.
	damaged := line(tail) + `{"name":"witness.example/w1","size":1,"root":"AAAA","sig":"AAAA"}` + "\n" +
		`not json` + "\n" + line(forged) + line(foreign) + line(beyond) + string(good) + line(tail) + `{"name":"witness.example/w1","si`
	if err := os.WriteFile(path, []byte(damaged), 0o600); err != nil {
		t.Fatal(err)
	}
	s2, err := reopen(cfg, c)
	if err != nil {
		t.Fatal(err)
	}
	defer s2.Close()
	b, err := s2.Proof("abs-core", 2, false)
	if err != nil {
		t.Fatal(err)
	}
	// Пакет закрепляет та же ранняя подпись, что до порчи: испорченные строки
	// того же размера её не спрятали.
	if r := proof.Verify(b, w.trust(t, s2)); !r.Valid() || len(b.Cosignatures) != 1 || b.Cosignatures[0].Size != rec.Size || !bytes.Equal(b.Cosignatures[0].Sig, rec.Sig) {
		t.Fatalf("пакет после порчи журнала:\n%s", r.Text())
	}
	if st := s2.Status(); st.Cosigners[0].Head != lastGood || s2.lastCosigned(w.key.Verifier()) != lastGood {
		t.Fatalf("status: свидетель подписал %d (по журналу %d), последняя верная строка — %d", st.Cosigners[0].Head, s2.lastCosigned(w.key.Verifier()), lastGood)
	}
	back, _ := os.ReadFile(path)
	if strings.HasSuffix(string(back), `"si`) || !strings.HasSuffix(string(back), "\n") {
		t.Fatalf("оборванная строка не отрезана: %q", back[len(back)-20:])
	}
}

// Пока свидетель C2SP недоступен, в очереди — все головы под метками и одна
// текущая, как у свидетеля S3; вернулся — подписаны все, очередь пуста.
func TestCosignQueueWhileDown(t *testing.T) {
	c := newClock()
	w := newLiveWitness(t, "witness.example/w1")
	s := openStore(t, testConfig(t, w.option()), c)
	w.attach(s)
	w.down.Store(true)
	for q := uint64(1); q <= 3; q++ {
		ingest(t, s, "abs-core", 2*q-1, 2*q-1)
		mustStamp(t, s)
		ingest(t, s, "abs-core", 2*q, 2*q) // новая текущая голова
		if err := s.flush(); err != nil {
			t.Fatal(err)
		}
		if err := s.CosignOnce(context.Background()); err == nil {
			t.Fatal("подпись от недоступного свидетеля")
		}
	}
	q := s.cosigners[0].queue
	stamped := 0
	for _, h := range q {
		if h.stamped {
			stamped++
		}
	}
	if len(q) != 7 || stamped != 6 || q[6].stamped {
		t.Fatalf("очередь к свидетелю C2SP: %+v", q)
	}
	w.down.Store(false)
	mustCosign(t, s)
	if n := len(s.cosignIdx[keyOf(w.key.Verifier())]); n != 7 || len(s.cosigners[0].queue) != 0 {
		t.Fatalf("подписано %d голов, в очереди %d", n, len(s.cosigners[0].queue))
	}
}

// Свидетель ответил подписью под своим именем и номером ключа, но подпись не
// сходится: хранилище её не берёт, журнал пуст. Следующий исправный ответ —
// после 409 свидетель подписывает ту же голову заново, и она ложится в журнал.
func TestCosignBrokenAnswerRefused(t *testing.T) {
	c := newClock()
	w := newLiveWitness(t, "witness.example/w1")
	cfg := testConfig(t, w.option())
	s := openStore(t, cfg, c)
	w.attach(s)
	w.corrupt.Store(true)
	ingest(t, s, "abs-core", 1, 3)
	mustStamp(t, s)
	err := s.CosignOnce(context.Background())
	if err == nil || !strings.Contains(err.Error(), "does not verify") {
		t.Fatalf("испорченная подпись свидетеля: %v", err)
	}
	if fi, err := os.Stat(filepath.Join(cfg.DataDir, filepath.FromSlash(cosignFile))); err != nil || fi.Size() != 0 {
		t.Fatalf("журнал подписей после испорченной подписи: %v %v", fi, err)
	}
	w.corrupt.Store(false)
	mustCosign(t, s)
	b, err := s.Proof("abs-core", 2, false)
	if err != nil {
		t.Fatal(err)
	}
	if r := proof.Verify(b, w.trust(t, s)); !r.Valid() || len(r.Cosigned) != 1 {
		t.Fatalf("после исправного ответа:\n%s", r.Text())
	}
}

// 409 без типа text/x.tlog.size — не ответ свидетеля о размере: хранилище ему
// не верит и ничего не отправляет дальше.
func TestCosign409NeedsSizeType(t *testing.T) {
	c := newClock()
	w := newLiveWitness(t, "witness.example/w1")
	cfg := testConfig(t, w.option())
	s := openStore(t, cfg, c)
	w.attach(s)
	ingest(t, s, "abs-core", 1, 3)
	mustStamp(t, s)
	mustCosign(t, s)
	s.Close()
	// Журнал подписей пропал: хранилище спросит с нуля и получит 409.
	os.Remove(filepath.Join(cfg.DataDir, filepath.FromSlash(cosignFile)))
	s2, err := reopen(cfg, c)
	if err != nil {
		t.Fatal(err)
	}
	defer s2.Close()
	w.plain409.Store(true)
	ingest(t, s2, "abs-core", 4, 4)
	mustStamp(t, s2)
	err = s2.CosignOnce(context.Background())
	if err == nil || !strings.Contains(err.Error(), "409 without the witness's tree size") {
		t.Fatalf("409 без типа размера: %v", err)
	}
	w.plain409.Store(false)
	mustCosign(t, s2)
}

// Свидетель за HTTPS со своим УЦ: с ca из конфигурации подписи идут, без
// него сертификат свидетеля не проверяется и подписи нет; ca без
// сертификатов — отказ запуска.
func TestCosignOverHTTPSWithCA(t *testing.T) {
	c := newClock()
	w := startLiveWitness(t, "witness.example/w1", true)
	ca := w.caFile()
	cfg := testConfig(t, func(cf *config.Config) {
		cf.Witness.Cosigners = []config.Cosigner{{URL: w.ts.URL, Key: w.key.Verifier().String(), CA: ca}}
	})
	s := openStore(t, cfg, c)
	w.attach(s)
	ingest(t, s, "abs-core", 1, 3)
	mustStamp(t, s)
	mustCosign(t, s)

	plain := testConfig(t, func(cf *config.Config) {
		cf.Witness.Cosigners = []config.Cosigner{{URL: w.ts.URL, Key: w.key.Verifier().String()}}
	})
	s2 := openStore(t, plain, c)
	ingest(t, s2, "abs-core", 1, 1)
	mustStamp(t, s2)
	if err := s2.CosignOnce(context.Background()); err == nil || !strings.Contains(err.Error(), "certificate") {
		t.Fatalf("свидетель за HTTPS без ca: %v", err)
	}

	junk := filepath.Join(t.TempDir(), "junk.pem")
	os.WriteFile(junk, []byte("not a certificate\n"), 0o600)
	bad := testConfig(t, func(cf *config.Config) {
		cf.Witness.Cosigners = []config.Cosigner{{URL: w.ts.URL, Key: w.key.Verifier().String(), CA: junk}}
	})
	if _, err := Open(bad, Options{Logger: quiet, Now: c.now, NoBackground: true}); err == nil || !strings.Contains(err.Error(), "holds no PEM certificates") {
		t.Fatalf("ca без сертификатов: %v", err)
	}
}

// Свидетели — параллельно: зависший свидетель съедает время обхода только у
// себя, второй подписывает в тот же обход.
func TestCosignSlowWitnessDoesNotStarveOthers(t *testing.T) {
	c := newClock()
	slow := newLiveWitness(t, "witness.example/slow")
	fast := newLiveWitness(t, "witness.example/fast")
	s := openStore(t, testConfig(t, slow.option(), fast.option()), c)
	slow.attach(s)
	fast.attach(s)
	slow.hang.Store(true)
	ingest(t, s, "abs-core", 1, 3)
	mustStamp(t, s)
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	err := s.CosignOnce(ctx)
	if err == nil || !strings.Contains(err.Error(), "witness.example/slow") || strings.Contains(err.Error(), "witness.example/fast") {
		t.Fatalf("обход с зависшим свидетелем: %v", err)
	}
	st := s.Status()
	if st.Cosigners[1].Name != "witness.example/fast" || st.Cosigners[1].Head == 0 || st.Cosigners[0].Head != 0 {
		t.Fatalf("status: %+v", st.Cosigners)
	}
}

// Журнал подписей едет в копию наружу и возвращается при подъёме: после
// потери диска пакеты старых записей несут те же подписи свидетеля, без
// -to-head и без самого свидетеля (он хранит только последнюю голову).
func TestCosignJournalInCopy(t *testing.T) {
	c := newClock()
	ctx := context.Background()
	w := newLiveWitness(t, "witness.example/w1")
	cfg, remote := replicaConfig(t)
	w.option()(cfg)
	s := openStore(t, cfg, c)
	w.attach(s)
	ingest(t, s, "abs-core", 1, 3)
	mustStamp(t, s)
	if _, err := s.ShipOnce(ctx, remote); err != nil {
		t.Fatal(err)
	}
	mustCosign(t, s)
	before, err := s.Proof("abs-core", 2, false)
	if err != nil || len(before.Cosignatures) != 1 {
		t.Fatalf("до потери диска: %v %+v", err, before.Cosignatures)
	}
	if _, err := s.ShipOnce(ctx, remote); err != nil { // журнал подписей — в копию
		t.Fatal(err)
	}
	w.down.Store(true)
	s2, err := restoreCopy(t, cfg, s, remote, c)
	if err != nil {
		t.Fatal(err)
	}
	defer s2.Close()
	after, err := s2.Proof("abs-core", 2, false)
	if err != nil {
		t.Fatal(err)
	}
	if len(after.Cosignatures) != 1 || !bytes.Equal(after.Cosignatures[0].Sig, before.Cosignatures[0].Sig) {
		t.Fatalf("после подъёма подписи в пакете: %+v, до: %+v", after.Cosignatures, before.Cosignatures)
	}
	if r := proof.Verify(after, w.trust(t, s2)); !r.Valid() {
		t.Fatalf("пакет после подъёма:\n%s", r.Text())
	}
}

// Подпись головы, которую свидетель держит, не пришла с первой попытки
// (испорченный ответ): в следующем обходе она запрашивается снова.
func TestCosignRecosignRetried(t *testing.T) {
	c := newClock()
	w := newLiveWitness(t, "witness.example/w1")
	cfg := testConfig(t, w.option())
	s := openStore(t, cfg, c)
	w.attach(s)
	ingest(t, s, "abs-core", 1, 3)
	mustStamp(t, s)
	mustCosign(t, s)
	origin := proof.OriginFor(w.trust(t, s).StoreKey)
	latest, _ := w.srv.Load().Latest(origin)
	s.Close()
	path := filepath.Join(cfg.DataDir, filepath.FromSlash(cosignFile))
	data, _ := os.ReadFile(path)
	var keep []byte
	for line := range bytes.Lines(data) {
		var r cosigRecord
		json.Unmarshal(line, &r)
		if r.Size < latest {
			keep = append(keep, line...)
		}
	}
	os.WriteFile(path, keep, 0o600)
	s2, err := reopen(cfg, c)
	if err != nil {
		t.Fatal(err)
	}
	defer s2.Close()
	ingest(t, s2, "abs-core", 4, 4)
	mustStamp(t, s2)
	w.corrupt.Store(true)
	if err := s2.CosignOnce(context.Background()); err == nil {
		t.Fatal("испорченный ответ на повторный запрос подписи принят")
	}
	w.corrupt.Store(false)
	mustCosign(t, s2)
	if !s2.hasCosig(w.key.Verifier(), latest) {
		t.Fatalf("подпись головы %d после неудачной попытки не запрошена снова", latest)
	}
}

// Журнал подписей в data_dir удалён, а копия его уже держит: журнал больше
// не копируется, но журнал улик и цепь копируются дальше.
func TestCosignJournalRemovedCopyGoesOn(t *testing.T) {
	c := newClock()
	ctx := context.Background()
	w := newLiveWitness(t, "witness.example/w1")
	cfg, remote := replicaConfig(t)
	w.option()(cfg)
	s := openStore(t, cfg, c)
	w.attach(s)
	ingest(t, s, "abs-core", 1, 3)
	mustStamp(t, s)
	if _, err := s.ShipOnce(ctx, remote); err != nil {
		t.Fatal(err)
	}
	mustCosign(t, s)
	if _, err := s.ShipOnce(ctx, remote); err != nil {
		t.Fatal(err)
	}
	s.Close()
	os.Remove(filepath.Join(cfg.DataDir, filepath.FromSlash(cosignFile)))
	s2, err := reopen(cfg, c)
	if err != nil {
		t.Fatal(err)
	}
	defer s2.Close()
	ingest(t, s2, "abs-core", 4, 6)
	mustStamp(t, s2)
	before := s2.replicaShipped.Load()
	if _, err := s2.ShipOnce(ctx, remote); err != nil {
		t.Fatalf("копия встала из-за журнала подписей: %v", err)
	}
	if after := s2.replicaShipped.Load(); after <= before {
		t.Fatalf("копия не пошла дальше: %d → %d", before, after)
	}
}

// Свидетель начат заново с новым ключом (потерял data_dir), прежний ключ — в
// old_keys: пакеты записей до смены несут подпись прежнего ключа и проходят у
// аудитора, закрепившего его; новому ключу хранилище шлёт головы с нуля, без
// ложной тревоги lost_state; прежнему — ничего. Без old_keys подписи прежнего
// ключа в пакеты не идут.
func TestCosignOldKeyStaysInBundles(t *testing.T) {
	c := newClock()
	w := newLiveWitness(t, "witness.example/w1")
	cfg := testConfig(t, w.option())
	s := openStore(t, cfg, c)
	w.attach(s)
	ingest(t, s, "abs-core", 1, 3)
	mustStamp(t, s)
	mustCosign(t, s)
	c.add(time.Minute)
	mustStamp(t, s)
	mustCosign(t, s)
	oldTrust := w.trust(t, s)
	before, err := s.Proof("abs-core", 2, false)
	if err != nil {
		t.Fatal(err)
	}
	if r := proof.Verify(before, oldTrust); !r.Valid() {
		t.Fatalf("до смены ключа:\n%s", r.Text())
	}
	s.Close()

	w2 := newLiveWitness(t, "witness.example/w1")
	cfg.Witness.Cosigners = []config.Cosigner{{URL: w2.ts.URL, Key: w2.key.Verifier().String(), OldKeys: []string{w.key.Verifier().String()}}}
	s2, err := reopen(cfg, c)
	if err != nil {
		t.Fatal(err)
	}
	w2.attach(s2)
	w.down.Store(true)
	hits := w.hits.Load()
	c.add(time.Minute)
	ingest(t, s2, "abs-core", 4, 4)
	mustStamp(t, s2)
	mustCosign(t, s2)
	if st := s2.Status().Cosigners[0]; st.LostState || st.LastError != "" || st.Head != s2.Head().Seq || w.hits.Load() != hits {
		t.Fatalf("после смены ключа: %+v, голова %d, к прежнему ключу запросов %d", st, s2.Head().Seq, w.hits.Load()-hits)
	}

	after, err := s2.Proof("abs-core", 2, false)
	if err != nil {
		t.Fatal(err)
	}
	if len(after.Cosignatures) != 2 {
		t.Fatalf("в пакете записи 2 подписей %d, ждали прежнего и нового ключа", len(after.Cosignatures))
	}
	if r := proof.Verify(after, oldTrust); !r.Valid() || len(r.Cosigned) != 1 || r.Cosigned[0].Key != fmt.Sprintf("%08x", w.key.Verifier().ID) {
		t.Fatalf("пакет записи 2 с прежним ключом:\n%s", r.Text())
	}
	// Новая запись — только новым ключом: прежний её не видел.
	b4, err := s2.Proof("abs-core", 4, false)
	if err != nil {
		t.Fatal(err)
	}
	if r := proof.Verify(b4, w2.trust(t, s2)); !r.Valid() || len(b4.Cosignatures) != 1 {
		t.Fatalf("пакет записи 4 с новым ключом (подписей %d):\n%s", len(b4.Cosignatures), r.Text())
	}
	s2.Close()

	// Прежний ключ убран из old_keys — его подписи в пакеты не идут.
	cfg.Witness.Cosigners[0].OldKeys = nil
	s3, err := reopen(cfg, c)
	if err != nil {
		t.Fatal(err)
	}
	defer s3.Close()
	b, err := s3.Proof("abs-core", 2, false)
	if err != nil {
		t.Fatal(err)
	}
	if len(b.Cosignatures) != 1 || proof.Verify(b, oldTrust).Valid() {
		t.Fatalf("без old_keys в пакете записи 2 подписей %d", len(b.Cosignatures))
	}
}

// После запуска время последней подписи — из журнала (время в подписи), а не
// ноль: иначе тревога «давно нет подписи» срабатывала бы после каждого запуска.
func TestCosignLastSuccessAfterRestart(t *testing.T) {
	c := newClock()
	w := newLiveWitness(t, "witness.example/w1")
	cfg := testConfig(t, w.option())
	s := openStore(t, cfg, c)
	w.attach(s)
	// Часы свидетеля на час впереди: время из подписи — не позже «сейчас».
	w.srv.Load().Now = func() time.Time { return time.Now().Add(time.Hour) }
	ingest(t, s, "abs-core", 1, 1)
	mustStamp(t, s)
	mustCosign(t, s)
	was := s.Status().Cosigners[0].LastAt
	s.Close()
	s2, err := reopen(cfg, c)
	if err != nil {
		t.Fatal(err)
	}
	defer s2.Close()
	got := s2.Status().Cosigners[0].LastAt
	if got.IsZero() || got.After(time.Now()) || was.Sub(got) > 2*time.Second {
		t.Fatalf("время последней подписи после запуска %v, до — %v", got, was)
	}
}

// Запись tree.hashes отказала («подпись текущей головы идёт дальше»): голову
// копии не снять, но головы под метками, которые копия уже держит, уходят
// свидетелю S3, а ошибка видна в счётчиках и last_error у обоих (P-124).
// Свидетелю C2SP без файла не построить доказательство продолжения — его
// головы ждут.
func TestCosignTreeFileFailureQueueGoesOn(t *testing.T) {
	c := newClock()
	ctx := context.Background()
	remoteDir, wdir := t.TempDir(), t.TempDir()
	w := newLiveWitness(t, "witness.example/w1")
	cfg := testConfig(t, withWitness(wdir), w.option(), func(cf *config.Config) {
		cf.Replica.URL = "file://" + remoteDir
		cf.Keys.BackupDir = t.TempDir()
	})
	s := openStore(t, cfg, c)
	w.attach(s)
	remote, err := ship.OpenRemote(cfg.Replica.URL)
	if err != nil {
		t.Fatal(err)
	}
	ingest(t, s, "abs-core", 1, 3)
	mustStamp(t, s)
	if _, err := s.ShipOnce(ctx, remote); err != nil {
		t.Fatal(err)
	}
	if err := s.WitnessOnce(ctx); err != nil {
		t.Fatal(err)
	}
	mustCosign(t, s)
	sent := len(witnessHeads(t, wdir).Heads)

	injected := errors.New("injected: writing tree.hashes failed")
	s.tree.failed.Store(&injected)
	c.add(time.Minute)
	ingest(t, s, "abs-core", 4, 6)
	mustStamp(t, s) // головы под меткой — в очередях обоих свидетелей
	if _, err := s.ShipOnce(ctx, remote); err != nil {
		t.Fatal(err)
	}
	ingest(t, s, "abs-core", 7, 7) // текущая голова снова дальше копии
	if err := s.flush(); err != nil {
		t.Fatal(err)
	}
	werr, cerr := s.WitnessOnce(ctx), s.CosignOnce(ctx)
	st := s.Status().Cosigners[0]
	if werr == nil || cerr == nil || s.witnessErrors.Load() == 0 || st.Errors == 0 || st.LastError == "" {
		t.Fatalf("ошибка головы копии не видна: %v / %v, witness_errors %d, cosigner %+v", werr, cerr, s.witnessErrors.Load(), st)
	}
	if got := len(witnessHeads(t, wdir).Heads); got == sent {
		t.Fatalf("головы под меткой свидетелю S3 не ушли: %d -> %d", sent, got)
	}
}
