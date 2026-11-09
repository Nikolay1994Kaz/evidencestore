package store

// Находка захода 1 второго цикла (FINDINGS, P-159): служба без своего
// сертификата в токене.

import (
	"bytes"
	"encoding/asn1"
	"encoding/json"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Nikolay1994Kaz/evidencestore/internal/config"
	"github.com/Nikolay1994Kaz/evidencestore/internal/tsa"
)

func tlvC2(tag byte, b []byte) []byte {
	n := len(b)
	var l []byte
	switch {
	case n < 128:
		l = []byte{byte(n)}
	case n < 256:
		l = []byte{0x81, byte(n)}
	case n < 65536:
		l = []byte{0x82, byte(n >> 8), byte(n)}
	default:
		l = []byte{0x83, byte(n >> 16), byte(n >> 8), byte(n)}
	}
	return append(append([]byte{tag}, l...), b...)
}

// stripCerts — токен без поля certificates SignedData (служба, что не кладёт
// свой сертификат в токен; сертификат проверяющий берёт из доверия).
func stripCerts(t *testing.T, token []byte) []byte {
	t.Helper()
	var ci struct {
		Type    asn1.ObjectIdentifier
		Content asn1.RawValue `asn1:"explicit,tag:0"`
	}
	if _, err := asn1.Unmarshal(token, &ci); err != nil {
		t.Fatal(err)
	}
	var sd asn1.RawValue
	if _, err := asn1.Unmarshal(ci.Content.Bytes, &sd); err != nil {
		t.Fatal(err)
	}
	var out []byte
	for rest := sd.Bytes; len(rest) > 0; {
		var e asn1.RawValue
		var err error
		if rest, err = asn1.Unmarshal(rest, &e); err != nil {
			t.Fatal(err)
		}
		if e.Class == asn1.ClassContextSpecific && e.Tag == 0 {
			continue
		}
		out = append(out, e.FullBytes...)
	}
	typ, _ := asn1.Marshal(ci.Type)
	return tlvC2(0x30, append(typ, tlvC2(0xA0, tlvC2(0x30, out))...))
}

// P-159. Вторая служба не кладёт свой сертификат в токен, оператор дал его в
// tsa.archive.trust. Ключ строки журнала пишется по сертификату из доверия;
// после перезапуска он сверяется с тем же набором сертификатов (токен и
// доверие), и строки идут в пакеты, как до него.
func TestArchiveTokenWithoutCert(t *testing.T) {
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
	mustArchive(t, s) // токен проверен доверием tsa.archive и записан
	b, err := s.Proof("abs-core", 5, false)
	if err != nil || len(b.Archive) == 0 {
		t.Fatalf("до перезапуска меток второй службы в пакете нет: %v", err)
	}
	s.Close()
	s2, err := reopen(cfg, c)
	if err != nil {
		t.Fatal(err)
	}
	b, err = s2.Proof("abs-core", 5, false)
	if err != nil {
		t.Fatal(err)
	}
	if len(b.Archive) == 0 {
		t.Errorf("после перезапуска метка второй службы в пакет не идёт")
	} else if !bytes.Equal(b.Archive[0].Cert, a.Cert().Raw) {
		t.Errorf("токен без сертификата службы, а пакет его не несёт: проверяющему нужен сертификат в -tsa-trust")
	}
	s2.Close()

	// Строки без поля key (журнал прежней версии): ключ подписанта — по
	// токену и доверию второй службы.
	path := filepath.Join(cfg.DataDir, filepath.FromSlash(archiveFile))
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var out []byte
	for _, line := range strings.SplitAfter(string(data), "\n") {
		if line == "" {
			continue
		}
		var rec map[string]any
		if err := json.Unmarshal([]byte(line), &rec); err != nil {
			t.Fatal(err)
		}
		delete(rec, "key")
		l, _ := json.Marshal(rec)
		out = append(append(out, l...), '\n')
	}
	if err := os.WriteFile(path, out, 0o600); err != nil {
		t.Fatal(err)
	}
	s3, err := reopen(cfg, c)
	if err != nil {
		t.Fatal(err)
	}
	defer s3.Close()
	if b, err := s3.Proof("abs-core", 5, false); err != nil || len(b.Archive) == 0 {
		t.Errorf("строки без поля key: метка второй службы в пакет не идёт: %v", err)
	}
}
