package store

// Тестировщик T, цикл 2 заход 2: вторая служба без своего сертификата в токене
// после смены или снятия tsa.archive (P-159 закрыт только при прежней настройке).

import (
	"encoding/asn1"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/Nikolay1994Kaz/evidencestore/internal/config"
	"github.com/Nikolay1994Kaz/evidencestore/internal/tsa"
)

// certlessTSA — служба меток за httptest, чьи токены без поля certificates.
func certlessTSA(t *testing.T) (*tsa.Authority, *httptest.Server) {
	a, err := tsa.NewAuthority(false)
	if err != nil {
		t.Fatal(err)
	}
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		rec := httptest.NewRecorder()
		a.ServeHTTP(rec, r)
		var resp asn1.RawValue
		if _, err := asn1.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
			http.Error(w, err.Error(), 500)
			return
		}
		var status, token asn1.RawValue
		rest, _ := asn1.Unmarshal(resp.Bytes, &status)
		asn1.Unmarshal(rest, &token)
		body := tlvC2(0x30, append(append([]byte(nil), status.FullBytes...), stripCerts(t, token.FullBytes)...))
		w.Header().Set("Content-Type", "application/timestamp-reply")
		w.Write(body)
	}))
	t.Cleanup(ts.Close)
	return a, ts
}

// bundles.md: метки второй службы «stay in use when tsa.archive changes or is
// removed»; configuration.md: «once kept, they go into the bundles even after
// tsa.archive points at another service or is removed». Для службы, что не
// кладёт свой сертификат в токен (P-159), — нет: строки журнала сверяются по
// tsa.archive.trust нынешней настройки.
func TestArchiveC2bTArchiveCertlessAfterConfigChange(t *testing.T) {
	a, ts := certlessTSA(t)
	dir := t.TempDir()
	root := filepath.Join(dir, "archive-root.pem")
	os.WriteFile(root, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: a.Root().Raw}), 0o600)
	cert := filepath.Join(dir, "archive-tsa.pem")
	os.WriteFile(cert, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: a.Cert().Raw}), 0o600)

	c := newClock()
	cfg := testConfig(t, func(c *config.Config) {
		c.TSA.Archive = config.TSAArchive{URL: ts.URL, Trust: []string{root, cert}}
	})
	s := openStore(t, cfg, c)
	ingest(t, s, "abs-core", 1, 3)
	mustStamp(t, s)
	c.add(5 * time.Minute)
	ingest(t, s, "abs-core", 4, 6)
	c.add(5 * time.Minute)
	mustStamp(t, s)
	mustArchive(t, s)
	if b, err := s.Proof("abs-core", 5, false); err != nil || len(b.Archive) == 0 {
		t.Fatalf("контроль: до перезапуска меток второй службы в пакете нет: %v", err)
	}
	s.Close()

	// tsa.archive убран.
	removed := *cfg
	removed.TSA.Archive = config.TSAArchive{}
	s2, err := reopen(&removed, c)
	if err != nil {
		t.Fatal(err)
	}
	b, err := s2.Proof("abs-core", 5, false)
	s2.Close()
	if err != nil {
		t.Fatal(err)
	}
	if len(b.Archive) == 0 {
		t.Errorf("tsa.archive убран: метки прежней второй службы в пакет не идут (bundles.md: stays in use when tsa.archive is removed)")
	}

	// tsa.archive указывает на другую службу (её корень — в доверии).
	other, ts2 := certlessTSA(t)
	root2 := filepath.Join(dir, "other-root.pem")
	os.WriteFile(root2, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: other.Root().Raw}), 0o600)
	changed := *cfg
	changed.TSA.Archive = config.TSAArchive{URL: ts2.URL, Trust: []string{root2}}
	s3, err := reopen(&changed, c)
	if err != nil {
		t.Fatal(err)
	}
	defer s3.Close()
	if b, err := s3.Proof("abs-core", 5, false); err != nil || len(b.Archive) == 0 {
		t.Errorf("tsa.archive сменён: метки прежней второй службы в пакет не идут: %v", err)
	}
}
