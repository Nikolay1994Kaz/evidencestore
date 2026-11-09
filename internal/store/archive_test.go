package store

import (
	"context"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
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
	return tr
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
