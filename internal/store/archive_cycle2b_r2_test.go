package store

// Ревью цикла 2, заход 2 (r2): журнал второй службы при смене tsa.archive.

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

// R2-D. Вторая служба A не кладёт свой сертификат в токен (P-159), оператор
// дал его в tsa.archive.trust. Потом tsa.archive сменили на службу B или
// убрали. Документы: «stays in use when tsa.archive changes or is removed».
// Строки A сверяются SignedBy с доверием текущей второй службы — сертификата
// A в нём нет, строки помечаются негодными и в пакеты не идут.
func TestC2bR2ArchiveCertlessAfterSwitch(t *testing.T) {
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
		t.Fatalf("метки A в пакете нет до смены: %v", err)
	}
	s.Close()

	other := newArchiveTSA(t)
	for name, arch := range map[string]config.TSAArchive{
		"tsa.archive сменили на B": {URL: other.ts.URL, Trust: []string{other.root}},
		"tsa.archive убрали":       {},
	} {
		cfg.TSA.Archive = arch
		s2, err := reopen(cfg, c)
		if err != nil {
			t.Fatal(err)
		}
		b, err := s2.Proof("abs-core", 5, false)
		s2.Close()
		if err != nil {
			t.Fatal(err)
		}
		if len(b.Archive) == 0 {
			t.Errorf("%s: прежняя метка A в пакет не идёт", name)
		}
	}
}
