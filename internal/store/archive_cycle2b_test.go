package store

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

// r1: служба без сертификата в токене (P-159), затем tsa.archive сменили на
// другую службу или убрали. Документ: прежние строки идут в пакеты
// по-прежнему. SignedBy сверяет подписанта по доверию НОВОЙ службы — строки
// прежней негодны.
func TestArchiveC2bArchiveNoCertAfterArchiveChange(t *testing.T) {
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
	defer ts.Close()
	other := newArchiveTSA(t)
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
		t.Fatalf("до смены: %v", err)
	}
	s.Close()
	for name, arch := range map[string]config.TSAArchive{
		"другая служба": {URL: other.ts.URL, Trust: []string{other.root}},
		"убрана":        {},
	} {
		cfg.TSA.Archive = arch
		s2, err := reopen(cfg, c)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		b, err := s2.Proof("abs-core", 5, false)
		s2.Close()
		if err != nil {
			t.Fatal(err)
		}
		if len(b.Archive) == 0 {
			t.Errorf("tsa.archive %s: метки прежней службы (без сертификата в токене) в пакет не идут", name)
		}
	}
}
