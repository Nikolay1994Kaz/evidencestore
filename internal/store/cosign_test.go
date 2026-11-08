package store

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
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
	// corrupt — в ответе 200 испорчен последний байт подписи (имя и номер
	// ключа верные); plain409 — ответ 409 без типа text/x.tlog.size.
	corrupt, plain409 atomic.Bool
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
		rec := httptest.NewRecorder()
		srv.Handler().ServeHTTP(rec, r)
		body := rec.Body.Bytes()
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
// свидетель недоступен. Хранилище после запуска не знает размера у свидетеля,
// спрашивает с old 0 и по ответу 409 продолжает.
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
	if w.hits.Load()-hits < 2 {
		t.Fatalf("после перезапуска к свидетелю %d запросов: ждали 409 на old 0 и повтор", w.hits.Load()-hits)
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

	// Владелец свидетеля разобрался и принял историю хранилища: убрал его
	// состояние. Хранилище узнаёт это само (409 «0») и продолжает с нуля.
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	w.attach(s)
	mustCosign(t, s)
	if st := s.Status(); st.Cosigners[0].Refused || st.Cosigners[0].Head != s.Head().Seq || st.Cosigners[0].LastError != "" {
		t.Fatalf("после сброса свидетеля: %+v, голова %d", st.Cosigners, s.Head().Seq)
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
	if fi, err := os.Stat(filepath.Join(cfg.DataDir, cosignFile)); err != nil || fi.Size() != 0 {
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
	pub, _ := base64.RawStdEncoding.DecodeString(s.PublicKey())
	s.Close()
	path := filepath.Join(cfg.DataDir, cosignFile)
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
	damaged := `{"name":"witness.example/w1","size":1,"root":"AAAA","sig":"AAAA"}` + "\n" +
		`not json` + "\n" + line(forged) + line(foreign) + string(good) + `{"name":"witness.example/w1","si`
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
	if r := proof.Verify(b, w.trust(t, s2)); !r.Valid() || len(b.Cosignatures) != 1 || b.Cosignatures[0].Size == rec.Size && !bytes.Equal(b.Cosignatures[0].Sig, rec.Sig) {
		t.Fatalf("пакет после порчи журнала:\n%s", r.Text())
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
	if n := len(s.cosignIdx[w.key.Name]); n != 7 || len(s.cosigners[0].queue) != 0 {
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
	if fi, err := os.Stat(filepath.Join(cfg.DataDir, cosignFile)); err != nil || fi.Size() != 0 {
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
