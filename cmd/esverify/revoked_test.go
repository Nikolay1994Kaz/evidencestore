package main

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/json"
	"encoding/pem"
	"io"
	"log/slog"
	"math/big"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Nikolay1994Kaz/evidencestore/internal/config"
	"github.com/Nikolay1994Kaz/evidencestore/internal/store"
	"github.com/Nikolay1994Kaz/evidencestore/internal/tsa"
)

// archivedWorld — хранилище с демо-службой меток и второй службой
// (tsa.archive) за httptest: пакет улики, ключ хранилища, корни обеих служб
// и перечень, где сертификат службы хранилища отозван по компрометации
// ключа завтра.
func archivedWorld(t *testing.T) (bundle, key, trust, archiveRoot, revoked string) {
	t.Helper()
	dir := t.TempDir()
	write := func(name string, data []byte) string {
		p := filepath.Join(dir, name)
		if err := os.WriteFile(p, data, 0o600); err != nil {
			t.Fatal(err)
		}
		return p
	}
	second, err := tsa.NewAuthority(false)
	if err != nil {
		t.Fatal(err)
	}
	ts := httptest.NewServer(second)
	t.Cleanup(ts.Close)
	archiveRoot = write("archive-root.pem", pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: second.Root().Raw}))
	cfg := &config.Config{
		DataDir: filepath.Join(dir, "data"), RootsDir: filepath.Join(dir, "roots"),
		TSA:     config.TSA{URL: "local", Archive: config.TSAArchive{URL: ts.URL, Trust: []string{archiveRoot}}},
		Sources: []config.Source{{Name: "abs-core", ContentType: "syslog"}},
		Demo:    true,
	}
	cfg.Defaults()
	if _, err := store.Init(cfg); err != nil {
		t.Fatal(err)
	}
	quiet := slog.New(slog.NewTextHandler(io.Discard, nil))
	s, err := store.Open(cfg, store.Options{Logger: quiet, NoBackground: true})
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	if _, err := s.Stamp(t.Context()); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Ingest("abs-core", []store.Incoming{{Seq: 1, Body: []byte("login admin")}}); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Stamp(t.Context()); err != nil {
		t.Fatal(err)
	}
	if err := s.ArchiveOnce(t.Context()); err != nil {
		t.Fatal(err)
	}
	b, err := s.Proof("abs-core", 1, false)
	if err != nil {
		t.Fatal(err)
	}
	if len(b.Archive) == 0 || b.Upper == nil || b.Upper.Inclusion == nil {
		t.Fatalf("в пакете нет меток второй службы или листа T2")
	}
	// Сертификат службы хранилища — демо-служба в data_dir.
	local, err := tsa.LoadAuthority(filepath.Join(cfg.DataDir, "tsa-local"))
	if err != nil {
		t.Fatal(err)
	}
	list, _ := json.Marshal([]map[string]string{{"cert_sha256": tsa.Fingerprint(local.Cert()), "revoked": time.Now().Add(24 * time.Hour).UTC().Format(time.RFC3339), "reason": "keyCompromise"}})
	data, _ := json.Marshal(b)
	return write("proof.json", data), write("store.key", []byte(s.PublicKey())), write("tsa-root.crt", s.TSARoot()), archiveRoot, write("revoked.json", list)
}

// -tsa-revoked: сертификат службы хранилища отозван по компрометации — пакет
// проходит только с корнем второй службы в -tsa-trust (её метка — POE); без
// сведений об отзыве отчёт говорит, что отзыв не проверен; негодный файл
// отзыва — неверный вызов.
func TestTSARevocationFlags(t *testing.T) {
	bundle, key, trust, archiveRoot, revoked := archivedWorld(t)
	var out, errb bytes.Buffer
	if code := run([]string{"-proof", bundle, "-store-key", key, "-tsa-trust", trust}, &out, &errb); code != exitValid || !strings.Contains(out.String(), "the revocation of the TSA certificates was not checked") {
		t.Fatalf("без сведений об отзыве: %d\n%s%s", code, out.String(), errb.String())
	}
	out.Reset()
	if code := run([]string{"-proof", bundle, "-store-key", key, "-tsa-trust", trust + "," + archiveRoot, "-tsa-revoked", revoked}, &out, &errb); code != exitValid || !strings.Contains(out.String(), "the archive time-stamp") {
		t.Fatalf("компрометация, вторая служба в доверии: %d\n%s%s", code, out.String(), errb.String())
	}
	out.Reset()
	if code := run([]string{"-proof", bundle, "-store-key", key, "-tsa-trust", trust, "-tsa-revoked", revoked}, &out, &errb); code != exitInvalid || !strings.Contains(out.String(), "is the root of that TSA in -tsa-trust?") {
		t.Fatalf("компрометация, второй службе не верят: %d\n%s%s", code, out.String(), errb.String())
	}
	bad := filepath.Join(t.TempDir(), "bad.json")
	os.WriteFile(bad, []byte(`[{"cert_sha256": "xyz"}]`), 0o600)
	errb.Reset()
	if code := run([]string{"-proof", bundle, "-store-key", key, "-tsa-trust", trust, "-tsa-revoked", bad}, &out, &errb); code != exitUsage || !strings.Contains(errb.String(), "cert_sha256") {
		t.Fatalf("негодный перечень: %d %s", code, errb.String())
	}
	errb.Reset()
	if code := run([]string{"-proof", bundle, "-store-key", key, "-tsa-trust", trust, "-tsa-crl", trust}, &out, &errb); code != exitUsage || !strings.Contains(errb.String(), "crl") {
		t.Fatalf("сертификат вместо CRL: %d %s", code, errb.String())
	}
}

// Перечни -tsa-revoked копятся (флаг повторяется или через запятую), как
// -tsa-crl, а не «последний побеждает»; второй список в одном файле и
// дельта-CRL — неверный вызов, а не молча неполная проверка.
func TestTSARevocationListsAndDelta(t *testing.T) {
	bundle, key, trust, _, revoked := archivedWorld(t)
	dir := t.TempDir()
	empty := filepath.Join(dir, "empty.json")
	os.WriteFile(empty, []byte(`[]`), 0o600)
	var out, errb bytes.Buffer
	for _, args := range [][]string{
		{"-tsa-revoked", revoked, "-tsa-revoked", empty},
		{"-tsa-revoked", empty + "," + revoked},
	} {
		out.Reset()
		if code := run(append([]string{"-proof", bundle, "-store-key", key, "-tsa-trust", trust}, args...), &out, &errb); code != exitInvalid {
			t.Fatalf("%v: %d\n%s", args, code, out.String())
		}
	}
	data, _ := os.ReadFile(revoked)
	both := filepath.Join(dir, "both.json")
	os.WriteFile(both, append([]byte("[]\n"), data...), 0o600)
	errb.Reset()
	if code := run([]string{"-proof", bundle, "-store-key", key, "-tsa-trust", trust, "-tsa-revoked", both}, &out, &errb); code != exitUsage || !strings.Contains(errb.String(), "data after the list") {
		t.Fatalf("два списка в файле: %d %s", code, errb.String())
	}
	// Дельта-CRL любого центра: отказ ещё при разборе.
	k, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "delta CA"}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageCRLSign, BasicConstraintsValid: true, IsCA: true}
	caDER, _ := x509.CreateCertificate(rand.Reader, tmpl, tmpl, k.Public(), k)
	ca, _ := x509.ParseCertificate(caDER)
	base, _ := asn1.Marshal(big.NewInt(1))
	der, err := x509.CreateRevocationList(rand.Reader, &x509.RevocationList{Number: big.NewInt(2), ThisUpdate: time.Now(), NextUpdate: time.Now().Add(time.Hour),
		ExtraExtensions: []pkix.Extension{{Id: asn1.ObjectIdentifier{2, 5, 29, 27}, Critical: true, Value: base}}}, ca, k)
	if err != nil {
		t.Fatal(err)
	}
	delta := filepath.Join(dir, "delta.crl")
	os.WriteFile(delta, der, 0o600)
	errb.Reset()
	if code := run([]string{"-proof", bundle, "-store-key", key, "-tsa-trust", trust, "-tsa-crl", delta}, &out, &errb); code != exitUsage || !strings.Contains(errb.String(), "delta CRL") {
		t.Fatalf("дельта-CRL: %d %s", code, errb.String())
	}
}
