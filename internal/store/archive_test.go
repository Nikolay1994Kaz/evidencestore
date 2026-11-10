package store

import (
	"context"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Nikolay1994Kaz/evidencestore/internal/config"
	"github.com/Nikolay1994Kaz/evidencestore/internal/proof"
	"github.com/Nikolay1994Kaz/evidencestore/internal/tsa"
)

// archiveTSA — вторая служба меток за httptest и файл её корня (PEM).
type archiveTSA struct {
	a    *tsa.Authority
	ts   *httptest.Server
	root string
	down atomic.Bool
	hits atomic.Int64
}

func newArchiveTSA(t *testing.T) *archiveTSA {
	t.Helper()
	a, err := tsa.NewAuthority(false)
	if err != nil {
		t.Fatal(err)
	}
	x := &archiveTSA{a: a}
	x.ts = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		x.hits.Add(1)
		if x.down.Load() {
			http.Error(w, "down", http.StatusServiceUnavailable)
			return
		}
		a.ServeHTTP(w, r)
	}))
	t.Cleanup(x.ts.Close)
	x.root = filepath.Join(t.TempDir(), "archive-root.pem")
	if err := os.WriteFile(x.root, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: a.Root().Raw}), 0o600); err != nil {
		t.Fatal(err)
	}
	return x
}

// option — вторая служба в tsa.archive хранилища.
func (x *archiveTSA) option() func(*config.Config) {
	return func(c *config.Config) { c.TSA.Archive = config.TSAArchive{URL: x.ts.URL, Trust: []string{x.root}} }
}

// trust — проверяющий верит службе хранилища и второй; revoked — сведения
// об отзыве: сертификат службы хранилища отозван по компрометации ключа в
// момент at (перечень проверяющего).
func (x *archiveTSA) trust(t *testing.T, s *Store, at time.Time) proof.Trust {
	t.Helper()
	tr := trustOf(t, s)
	pool := x509.NewCertPool()
	pool.AddCert(s.tsaLocal.Root())
	pool.AddCert(x.a.Root())
	tr.TSA = tsa.Trust{Roots: pool}
	list, _ := json.Marshal([]map[string]string{{"cert_sha256": tsa.Fingerprint(s.tsaLocal.Cert()), "revoked": at.UTC().Format(time.RFC3339), "reason": "keyCompromise"}})
	p := filepath.Join(t.TempDir(), "revoked.json")
	if err := os.WriteFile(p, list, 0o600); err != nil {
		t.Fatal(err)
	}
	tr.TSARevocations = tsa.NewRevocations(time.Now())
	if err := tr.TSARevocations.AddList(p); err != nil {
		t.Fatal(err)
	}
	checkedTSA(t, tr.TSARevocations, x.a)
	return tr
}

// checkedTSA — пустые CRL служб as: их отзыв проверен, и их метки могут быть
// POE (время другой метки показывает только метка с проверенным отзывом).
func checkedTSA(t *testing.T, r *tsa.Revocations, as ...*tsa.Authority) {
	t.Helper()
	for i, a := range as {
		der, err := a.RevocationList(r.Now.Add(-time.Hour), r.Now.Add(time.Hour))
		if err != nil {
			t.Fatal(err)
		}
		p := filepath.Join(t.TempDir(), fmt.Sprintf("tsa-%d.crl", i))
		if err := os.WriteFile(p, der, 0o600); err != nil {
			t.Fatal(err)
		}
		if err := r.AddCRL(p); err != nil {
			t.Fatal(err)
		}
	}
}

func mustArchive(t *testing.T, s *Store) {
	t.Helper()
	if err := s.ArchiveOnce(context.Background()); err != nil {
		t.Fatal(err)
	}
}

// ⭐ Сертификат службы хранилища отозван по компрометации ключа: время её
// меток ничего не доказывает. Метки второй службы над головами, где лежат
// её токены, показывают, что токены существовали раньше, — пакеты всех трёх
// видов проходят; без них — нет.
func TestArchiveRescuesCompromisedStamps(t *testing.T) {
	c := newClock()
	x := newArchiveTSA(t)
	s := openStore(t, testConfig(t, x.option()), c)
	ingest(t, s, "abs-core", 1, 3)
	mustStamp(t, s)
	c.add(5 * time.Minute)
	ingest(t, s, "abs-core", 4, 6)
	c.add(5 * time.Minute)
	mustStamp(t, s)
	c.add(time.Minute)
	ingest(t, s, "abs-core", 7, 8)
	mustStamp(t, s)
	c.add(time.Minute)
	mustStamp(t, s)
	mustArchive(t, s)
	if st := s.Status().TSAArchive; st == nil || st.Head != s.Head().Seq || st.LastError != "" || st.LastAt.IsZero() {
		t.Fatalf("status второй службы: %+v, голова %d", st, s.Head().Seq)
	}
	tr := x.trust(t, s, time.Now().Add(24*time.Hour))

	b, err := s.Proof("abs-core", 5, false)
	if err != nil {
		t.Fatal(err)
	}
	if b.Upper == nil || b.Upper.Inclusion == nil || len(b.Archive) == 0 {
		t.Fatalf("в пакете нет листа T2 или меток второй службы: %+v, %d", b.Upper, len(b.Archive))
	}
	if r := proof.Verify(b, tr); !r.Valid() {
		t.Fatalf("пакет одной улики:\n%s", r.Text())
	}
	b.Archive = nil
	if r := proof.Verify(b, tr); r.Valid() {
		t.Fatalf("без меток второй службы прошёл:\n%s", r.Text())
	}

	from, to := clockAt(10, 4, 0), clockAt(10, 6, 0)
	wb, err := s.ProofWindow(from, to, "", false, 0)
	if err != nil {
		t.Fatal(err)
	}
	if r := proof.VerifyWindow(roundTrip(t, wb), tr, time.Time{}, time.Time{}); !r.Valid() || len(wb.Archive) == 0 {
		t.Fatalf("пакет за окно (меток второй службы %d):\n%s", len(wb.Archive), r.Text())
	}
	sb, err := s.ProofSource("abs-core", from, to, false, 0)
	if err != nil {
		t.Fatal(err)
	}
	if r := proof.VerifySource(sb, tr, time.Time{}, time.Time{}); !r.Valid() || len(sb.Archive) == 0 {
		t.Fatalf("пакет по источнику (меток второй службы %d):\n%s", len(sb.Archive), r.Text())
	}
	sb.Archive = nil
	if r := proof.VerifySource(sb, tr, time.Time{}, time.Time{}); r.Valid() {
		t.Fatalf("пакет по источнику без меток второй службы прошёл:\n%s", r.Text())
	}
}

// Вторая служба спрашивается, только когда голова ушла дальше заверенной;
// недоступна — ошибка в status, журнал не трогается; вернулась — метка.
// Без второй службы пакет не длиннее головы T2 и без листа её токена.
func TestArchiveOnce(t *testing.T) {
	c := newClock()
	x := newArchiveTSA(t)
	s := openStore(t, testConfig(t, x.option()), c)
	ingest(t, s, "abs-core", 1, 1)
	mustStamp(t, s)
	mustArchive(t, s)
	hits := x.hits.Load()
	mustArchive(t, s)
	if x.hits.Load() != hits || hits == 0 {
		t.Fatalf("та же голова заверена снова: %d → %d запросов", hits, x.hits.Load())
	}
	ingest(t, s, "abs-core", 2, 2)
	mustStamp(t, s)
	x.down.Store(true)
	if err := s.ArchiveOnce(context.Background()); err == nil {
		t.Fatal("недоступная служба — без ошибки")
	}
	if st := s.Status().TSAArchive; st.Errors != 1 || st.LastError == "" {
		t.Fatalf("status при недоступной службе: %+v", st)
	}
	x.down.Store(false)
	mustArchive(t, s)
	if st := s.Status().TSAArchive; st.Head != s.Head().Seq || st.LastError != "" {
		t.Fatalf("status после возврата: %+v", st)
	}

	plain := openStore(t, testConfig(t), newClock())
	ingest(t, plain, "abs-core", 1, 1)
	mustStamp(t, plain)
	ingest(t, plain, "abs-core", 2, 2)
	mustStamp(t, plain)
	b, err := plain.Proof("abs-core", 1, false)
	if err != nil {
		t.Fatal(err)
	}
	if b.Upper.Inclusion != nil || b.Checkpoint.Size != b.Upper.HeadSeq || len(b.Archive) != 0 {
		t.Fatalf("без второй службы: лист T2 %v, голова пакета %d, T2 над %d", b.Upper.Inclusion, b.Checkpoint.Size, b.Upper.HeadSeq)
	}
}

// Токен, который не проверяется доверием tsa.archive.trust, в журнал не
// ложится.
func TestArchiveTokenVerified(t *testing.T) {
	c := newClock()
	x := newArchiveTSA(t)
	other := newArchiveTSA(t)
	cfg := testConfig(t, func(cf *config.Config) {
		cf.TSA.Archive = config.TSAArchive{URL: x.ts.URL, Trust: []string{other.root}} // корень не той службы
	})
	s := openStore(t, cfg, c)
	ingest(t, s, "abs-core", 1, 1)
	mustStamp(t, s)
	if err := s.ArchiveOnce(context.Background()); err == nil || !strings.Contains(err.Error(), "the token of") {
		t.Fatalf("токен чужой службы: %v", err)
	}
	if fi, err := os.Stat(filepath.Join(cfg.DataDir, filepath.FromSlash(archiveFile))); err != nil || fi.Size() != 0 {
		t.Fatalf("журнал второй службы: %v %v", fi, err)
	}
}

// Журнал второй службы переживает перезапуск и порчу (оборванная строка
// отрезается, голова за концом цепи не идёт в пакеты), едет в копию и
// возвращается при подъёме; удалённый — копия идёт дальше, с тревогой.
func TestArchiveJournal(t *testing.T) {
	c := newClock()
	ctx := context.Background()
	x := newArchiveTSA(t)
	cfg, remote := replicaConfig(t)
	x.option()(cfg)
	s := openStore(t, cfg, c)
	ingest(t, s, "abs-core", 1, 3)
	mustStamp(t, s)
	ingest(t, s, "abs-core", 4, 4)
	mustStamp(t, s)
	if _, err := s.ShipOnce(ctx, remote); err != nil {
		t.Fatal(err)
	}
	mustArchive(t, s)                                  // над головой копии
	if _, err := s.ShipOnce(ctx, remote); err != nil { // журнал — в копию
		t.Fatal(err)
	}
	before, err := s.Proof("abs-core", 2, false)
	if err != nil || len(before.Archive) == 0 {
		t.Fatalf("до подъёма: %v, меток второй службы %d", err, len(before.Archive))
	}
	s.Close()

	// Порча: перед настоящей строкой — та же голова с испорченным токеном,
	// после — голова за концом цепи и оборванная последняя строка.
	path := filepath.Join(cfg.DataDir, filepath.FromSlash(archiveFile))
	good, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var rec archiveRecord
	json.Unmarshal(good[:strings.IndexByte(string(good), '\n')], &rec)
	// Токен этой службы несёт её сертификат сам: второй раз, рядом с токеном,
	// журнал его не хранит и в пакет не кладёт (мутация R127).
	if len(rec.Cert) != 0 || len(rec.Chain) != 0 || len(before.Archive[0].Certs) != 0 {
		t.Fatalf("сертификат, который токен несёт сам, записан ещё раз: в журнале %d и %d байт, в пакете %d", len(rec.Cert), len(rec.Chain), len(before.Archive[0].Certs))
	}
	rec.Token = append([]byte(nil), rec.Token...)
	rec.Token[len(rec.Token)-1] ^= 1
	forged, _ := json.Marshal(rec)
	damaged := string(forged) + "\n" + string(good) + `{"size":99999,"root":"` + strings.Repeat("A", 43) + `=","token":"AA=="}` + "\n" + `{"size":1,"ro`
	if err := os.WriteFile(path, []byte(damaged), 0o600); err != nil {
		t.Fatal(err)
	}
	s2, err := reopen(cfg, c)
	if err != nil {
		t.Fatal(err)
	}
	b, err := s2.Proof("abs-core", 2, false)
	if err != nil || len(b.Archive) != len(before.Archive) || string(b.Archive[0].Token) != string(before.Archive[0].Token) {
		t.Fatalf("после порчи: %v, меток %d, до %d", err, len(b.Archive), len(before.Archive))
	}
	if back, _ := os.ReadFile(path); strings.HasSuffix(string(back), `"ro`) {
		t.Fatal("оборванная строка не отрезана")
	}
	s2.Close()

	s3, err := restoreCopy(t, cfg, s2, remote, c)
	if err != nil {
		t.Fatal(err)
	}
	after, err := s3.Proof("abs-core", 2, false)
	if err != nil || len(after.Archive) != len(before.Archive) || string(after.Archive[0].Token) != string(before.Archive[0].Token) {
		t.Fatalf("после подъёма: %v, меток второй службы %d", err, len(after.Archive))
	}
	s3.Close()
}

// Журнал второй службы удалён при остановленном хранилище: копия идёт
// дальше, журнал в неё больше не едет, и это видно тревогой.
func TestArchiveJournalRemovedCopyGoesOn(t *testing.T) {
	c := newClock()
	ctx := context.Background()
	x := newArchiveTSA(t)
	cfg, remote := replicaConfig(t)
	x.option()(cfg)
	s := openStore(t, cfg, c)
	ingest(t, s, "abs-core", 1, 3)
	mustStamp(t, s)
	if _, err := s.ShipOnce(ctx, remote); err != nil {
		t.Fatal(err)
	}
	mustArchive(t, s)
	if _, err := s.ShipOnce(ctx, remote); err != nil {
		t.Fatal(err)
	}
	s.Close()
	os.Remove(filepath.Join(cfg.DataDir, filepath.FromSlash(archiveFile)))
	s2, err := reopen(cfg, c)
	if err != nil {
		t.Fatal(err)
	}
	defer s2.Close()
	ingest(t, s2, "abs-core", 4, 6)
	mustStamp(t, s2)
	before := s2.replicaShipped.Load()
	if _, err := s2.ShipOnce(ctx, remote); err != nil {
		t.Fatalf("копия встала из-за журнала второй службы: %v", err)
	}
	if after := s2.replicaShipped.Load(); after <= before || !s2.archiveSkipped.Load() || s2.cosignSkipped.Load() {
		t.Fatalf("копия %d → %d, тревога журнала второй службы %v, журнала подписей %v", before, after, s2.archiveSkipped.Load(), s2.cosignSkipped.Load())
	}
}

// Сертификат службы отозван по компрометации, второй службы нет, есть
// свидетель C2SP: его подпись над головой звена токена T2 (хранилище отдаёт
// её свидетелю вместе с головой под меткой) — POE для T2. Пакет одной улики
// несёт лист T2 и эту подпись и проходит без -to-head, как и пакеты за окно
// и по источнику.
func TestWitnessRescuesCompromisedT2(t *testing.T) {
	c := newClock()
	w := newLiveWitness(t, "witness.example/w1")
	s := openStore(t, testConfig(t, w.option()), c)
	w.attach(s)
	ingest(t, s, "abs-core", 1, 3)
	mustStamp(t, s)
	mustCosign(t, s)
	c.add(5 * time.Minute)
	ingest(t, s, "abs-core", 4, 6)
	mustCosign(t, s) // обход свидетеля между записью и меткой: подпись раньше звена токена T2
	c.add(5 * time.Minute)
	mustStamp(t, s)
	mustCosign(t, s)
	c.add(time.Minute)
	ingest(t, s, "abs-core", 7, 8)
	mustStamp(t, s)
	mustCosign(t, s)

	tr := w.trust(t, s)
	list, _ := json.Marshal([]map[string]string{{"cert_sha256": tsa.Fingerprint(s.tsaLocal.Cert()), "revoked": time.Now().Add(24 * time.Hour).UTC().Format(time.RFC3339), "reason": "keyCompromise"}})
	p := filepath.Join(t.TempDir(), "revoked.json")
	os.WriteFile(p, list, 0o600)
	tr.TSARevocations = tsa.NewRevocations(time.Now())
	if err := tr.TSARevocations.AddList(p); err != nil {
		t.Fatal(err)
	}
	b, err := s.Proof("abs-core", 5, false)
	if err != nil {
		t.Fatal(err)
	}
	if b.Upper == nil || b.Upper.Inclusion == nil || len(b.Cosignatures) != 2 || b.Cosignatures[1].Size != b.Upper.Inclusion.LinkSeq {
		t.Fatalf("в пакете нет листа T2 или подписи над головой его звена: %+v", b.Cosignatures)
	}
	if r := proof.Verify(b, tr); !r.Valid() || !strings.Contains(r.Text(), "cosigned head") {
		t.Fatalf("пакет одной улики:\n%s", r.Text())
	}
	// Без подписи над звеном T2 — не проходит, и отчёт говорит почему.
	cut := b
	cut.Cosignatures = cut.Cosignatures[:1]
	if r := proof.Verify(cut, tr); r.Valid() || !strings.Contains(r.Text(), "time-stamp T2") {
		t.Fatalf("без подписи над звеном T2:\n%s", r.Text())
	}
	from, to := clockAt(10, 4, 0), clockAt(10, 6, 0)
	wb, err := s.ProofWindow(from, to, "", false, 0)
	if err != nil {
		t.Fatal(err)
	}
	if r := proof.VerifyWindow(roundTrip(t, wb), tr, time.Time{}, time.Time{}); !r.Valid() {
		t.Fatalf("за окно:\n%s", r.Text())
	}
	sb, err := s.ProofSource("abs-core", from, to, false, 0)
	if err != nil {
		t.Fatal(err)
	}
	if r := proof.VerifySource(sb, tr, time.Time{}, time.Time{}); !r.Valid() {
		t.Fatalf("по источнику:\n%s", r.Text())
	}
}

// Вторую службу сменили (другая служба, другой корень) или убрали из
// конфигурации: её прежние метки по-прежнему идут в пакеты — их токены
// проверены, когда записаны, а проверяющий верит той службе. Испорченная
// подпись токена строку по-прежнему выводит из оборота (TestArchiveJournal).
func TestArchiveServiceChanged(t *testing.T) {
	c := newClock()
	x := newArchiveTSA(t)
	cfg := testConfig(t, x.option())
	s := openStore(t, cfg, c)
	ingest(t, s, "abs-core", 1, 3)
	mustStamp(t, s)
	c.add(5 * time.Minute)
	ingest(t, s, "abs-core", 4, 6)
	c.add(5 * time.Minute)
	mustStamp(t, s)
	mustArchive(t, s)
	before, err := s.Proof("abs-core", 5, false)
	if err != nil || len(before.Archive) == 0 {
		t.Fatalf("до смены: %v, меток %d", err, len(before.Archive))
	}
	s.Close()
	tr := x.trust(t, s, time.Now().Add(24*time.Hour))

	y := newArchiveTSA(t)
	for name, archive := range map[string]config.TSAArchive{"другая служба": {URL: y.ts.URL, Trust: []string{y.root}}, "без второй службы": {}} {
		cfg.TSA.Archive = archive
		s2, err := reopen(cfg, c)
		if err != nil {
			t.Fatal(err)
		}
		after, err := s2.Proof("abs-core", 5, false)
		if err != nil || len(after.Archive) != len(before.Archive) || after.Upper.Inclusion == nil {
			s2.Close()
			t.Fatalf("%s: %v, меток второй службы %d, было %d", name, err, len(after.Archive), len(before.Archive))
		}
		if r := proof.Verify(after, tr); !r.Valid() {
			s2.Close()
			t.Fatalf("%s:\n%s", name, r.Text())
		}
		if st := s2.Status(); (st.TSAArchive == nil) != (archive.URL == "") {
			t.Errorf("%s: status %+v", name, st.TSAArchive)
		}
		s2.Close()
	}
}

// tsa.archive — та же служба под другим адресом (тот же ключ подписи): после
// компрометации её метки ничего не покажут. Метка не пишется, ошибка видна в
// status.
func TestArchiveSameTSARefused(t *testing.T) {
	c := newClock()
	var same atomic.Pointer[tsa.Authority]
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if a := same.Load(); a != nil {
			a.ServeHTTP(w, r)
			return
		}
		http.Error(w, "not yet", http.StatusServiceUnavailable)
	}))
	t.Cleanup(ts.Close)
	cfg := testConfig(t, func(cfg *config.Config) {
		cfg.TSA.Archive = config.TSAArchive{URL: ts.URL, Trust: []string{filepath.Join(cfg.DataDir, "tsa-local", "root.crt")}}
	})
	s := openStore(t, cfg, c)
	same.Store(s.tsaLocal)
	ingest(t, s, "abs-core", 1, 3)
	mustStamp(t, s)
	err := s.ArchiveOnce(context.Background())
	if st := s.Status().TSAArchive; err == nil || !strings.Contains(err.Error(), "same TSA") || st.Errors != 1 || st.Head != 0 || !strings.Contains(st.LastError, "same TSA") {
		t.Fatalf("та же служба: %v, status %+v", err, st)
	}
	if b, err := s.Proof("abs-core", 2, false); err != nil || len(b.Archive) != 0 {
		t.Fatalf("метка той же службы в пакете: %v %d", err, len(b.Archive))
	}
	// После перезапуска, до новой метки основной: её ключ — из последнего
	// токена цепи.
	s.Close()
	s2, err := reopen(cfg, c)
	if err != nil {
		t.Fatal(err)
	}
	defer s2.Close()
	same.Store(s2.tsaLocal)
	ingest(t, s2, "abs-core", 4, 4)
	if err := s2.ArchiveOnce(context.Background()); err == nil || !strings.Contains(err.Error(), "same TSA") {
		t.Fatalf("та же служба после перезапуска: %v", err)
	}
}

// Вторую службу сменили, потому что прежняя стала негодной: проверяющий
// больше не верит её корню (или её ключ отозван). Пакет записи до смены
// несёт от каждой службы её самую раннюю метку не раньше звена токена — и
// проходит по метке новой, хотя первая по журналу — метка прежней.
func TestArchiveEveryServiceInBundle(t *testing.T) {
	c := newClock()
	x := newArchiveTSA(t)
	cfg := testConfig(t, x.option())
	s := openStore(t, cfg, c)
	ingest(t, s, "abs-core", 1, 3)
	mustStamp(t, s)
	c.add(5 * time.Minute)
	ingest(t, s, "abs-core", 4, 6)
	c.add(5 * time.Minute)
	mustStamp(t, s)
	mustArchive(t, s)
	s.Close()

	y := newArchiveTSA(t)
	cfg.TSA.Archive = config.TSAArchive{URL: y.ts.URL, Trust: []string{y.root}}
	s2, err := reopen(cfg, c)
	if err != nil {
		t.Fatal(err)
	}
	defer s2.Close()
	c.add(time.Minute)
	ingest(t, s2, "abs-core", 7, 7)
	mustStamp(t, s2)
	mustArchive(t, s2)
	b, err := s2.Proof("abs-core", 5, false)
	if err != nil || len(b.Archive) != 2 || b.Archive[0].HeadSeq >= b.Archive[1].HeadSeq {
		t.Fatalf("метки второй службы в пакете: %v, %d (ждали прежней и новой)", err, len(b.Archive))
	}
	// Проверяющий верит основной и новой службе, основная скомпрометирована.
	tr := trustOf(t, s2)
	pool := x509.NewCertPool()
	pool.AddCert(s2.tsaLocal.Root())
	pool.AddCert(y.a.Root())
	tr.TSA = tsa.Trust{Roots: pool}
	list, _ := json.Marshal([]map[string]string{{"cert_sha256": tsa.Fingerprint(s2.tsaLocal.Cert()), "revoked": time.Now().Add(24 * time.Hour).UTC().Format(time.RFC3339), "reason": "keyCompromise"}})
	p := filepath.Join(t.TempDir(), "revoked.json")
	os.WriteFile(p, list, 0o600)
	tr.TSARevocations = tsa.NewRevocations(time.Now())
	if err := tr.TSARevocations.AddList(p); err != nil {
		t.Fatal(err)
	}
	checkedTSA(t, tr.TSARevocations, x.a, y.a)
	if r := proof.Verify(b, tr); !r.Valid() {
		t.Fatalf("пакет по метке новой службы:\n%s", r.Text())
	}
}

// Поле key строки журнала сверяется с ключом, которым подписан токен, когда
// строка впервые идёт в пакет: строка с чужим ключом (журнал лежит и в копии)
// не идёт и не прячет собой метки службы, чей ключ в ней назван, — громко в
// журнал процесса. Следующая строка той же службы — идёт.
func TestArchiveKeyFieldChecked(t *testing.T) {
	c := newClock()
	x := newArchiveTSA(t)
	cfg := testConfig(t, x.option())
	s := openStore(t, cfg, c)
	ingest(t, s, "abs-core", 1, 3)
	mustStamp(t, s)
	c.add(5 * time.Minute)
	ingest(t, s, "abs-core", 4, 6)
	c.add(5 * time.Minute)
	mustStamp(t, s)
	mustArchive(t, s)
	c.add(time.Minute)
	ingest(t, s, "abs-core", 7, 7)
	mustStamp(t, s)
	mustArchive(t, s)
	s.Close()

	path := filepath.Join(cfg.DataDir, filepath.FromSlash(archiveFile))
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	lines := strings.SplitAfter(string(data), "\n")
	var first, second archiveRecord
	json.Unmarshal([]byte(lines[0]), &first)
	json.Unmarshal([]byte(lines[1]), &second)
	first.Key = make([]byte, 32)
	first.Key[0] = 7
	forged, _ := json.Marshal(first)
	if err := os.WriteFile(path, []byte(string(forged)+"\n"+lines[1]), 0o600); err != nil {
		t.Fatal(err)
	}
	s2, err := reopen(cfg, c)
	if err != nil {
		t.Fatal(err)
	}
	defer s2.Close()
	b, err := s2.Proof("abs-core", 5, false)
	if err != nil || len(b.Archive) != 1 || b.Archive[0].HeadSeq != second.Size {
		t.Fatalf("строка с чужим key: %v, меток %d (ждали одну, над головой %d)", err, len(b.Archive), second.Size)
	}
}
