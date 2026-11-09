package main

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"io"
	"log/slog"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Nikolay1994Kaz/evidencestore/internal/config"
	"github.com/Nikolay1994Kaz/evidencestore/internal/store"
	"github.com/Nikolay1994Kaz/evidencestore/internal/tsa"
)

// Хранилище с печатью организации на свой ключ: esverify с корнем центра
// печатей (-seal-trust) проверяет пакет без -store-key; с чужим корнем — нет;
// без обоих флагов — неверный вызов.
func TestSealTrustFlag(t *testing.T) {
	dir := t.TempDir()
	write := func(name string, data []byte) string {
		p := filepath.Join(dir, name)
		if err := os.WriteFile(p, data, 0o600); err != nil {
			t.Fatal(err)
		}
		return p
	}
	newCA := func(cn string) (*x509.Certificate, *ecdsa.PrivateKey) {
		k, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		tmpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: cn}, NotBefore: time.Date(2020, 1, 1, 0, 0, 0, 0, time.UTC), NotAfter: time.Date(2040, 1, 1, 0, 0, 0, 0, time.UTC),
			KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageCRLSign, BasicConstraintsValid: true, IsCA: true}
		der, _ := x509.CreateCertificate(rand.Reader, tmpl, tmpl, k.Public(), k)
		c, _ := x509.ParseCertificate(der)
		return c, k
	}
	root, rootKey := newCA("seal CA")
	orgKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	ot := &x509.Certificate{SerialNumber: big.NewInt(9), Subject: pkix.Name{CommonName: "Example Bank seal"}, NotBefore: time.Date(2020, 1, 1, 0, 0, 0, 0, time.UTC), NotAfter: time.Date(2040, 1, 1, 0, 0, 0, 0, time.UTC), KeyUsage: x509.KeyUsageDigitalSignature}
	der, _ := x509.CreateCertificate(rand.Reader, ot, root, orgKey.Public(), rootKey)
	org, _ := x509.ParseCertificate(der)

	cfg := &config.Config{
		DataDir: filepath.Join(dir, "data"), RootsDir: filepath.Join(dir, "roots"),
		TSA:     config.TSA{URL: "local"},
		Sources: []config.Source{{Name: "abs-core", ContentType: "syslog"}},
		Demo:    true,
	}
	cfg.Defaults()
	if _, err := store.Init(cfg); err != nil {
		t.Fatal(err)
	}
	statement, err := store.SealStatement(cfg)
	if err != nil {
		t.Fatal(err)
	}
	cms, err := tsa.Seal(orgKey, org, nil, statement, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	cfg.Seal.File = write("seal.p7s", cms)
	s, err := store.Open(cfg, store.Options{Logger: slog.New(slog.NewTextHandler(io.Discard, nil)), NoBackground: true})
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	if err := s.StampSeal(t.Context()); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Stamp(t.Context()); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Ingest("abs-core", []store.Incoming{{Seq: 1, Body: []byte("login admin")}}); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Stamp(t.Context()); err != nil {
		t.Fatal(err)
	}
	b, err := s.Proof("abs-core", 1, false)
	if err != nil {
		t.Fatal(err)
	}
	data, _ := json.Marshal(b)
	bundle := write("proof.json", data)
	tsaRoot := write("tsa-root.crt", s.TSARoot())
	sealRoot := write("seal-root.pem", pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: root.Raw}))
	other, _ := newCA("another CA")
	otherRoot := write("other-root.pem", pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: other.Raw}))

	var out, errb bytes.Buffer
	if code := run([]string{"-proof", bundle, "-seal-trust", sealRoot, "-tsa-trust", tsaRoot}, &out, &errb); code != exitValid || !strings.Contains(out.String(), "Example Bank seal") {
		t.Fatalf("по печати, без -store-key: %d\n%s%s", code, out.String(), errb.String())
	}
	out.Reset()
	if code := run([]string{"-proof", bundle, "-seal-trust", otherRoot, "-tsa-trust", tsaRoot}, &out, &errb); code != exitInvalid {
		t.Fatalf("чужой центр печатей: %d\n%s", code, out.String())
	}
	out.Reset()
	if code := run([]string{"-proof", bundle, "-store-key", s.PublicKey(), "-tsa-trust", tsaRoot}, &out, &errb); code != exitValid || !strings.Contains(out.String(), "-seal-trust") {
		t.Fatalf("печать без -seal-trust названа: %d\n%s", code, out.String())
	}
	errb.Reset()
	if code := run([]string{"-proof", bundle, "-tsa-trust", tsaRoot}, &out, &errb); code != exitUsage {
		t.Fatalf("без -store-key и -seal-trust: %d", code)
	}
}
