package main

import (
	"bytes"
	"crypto/x509"
	"encoding/pem"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func readCert(t *testing.T, path string) *x509.Certificate {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	b, _ := pem.Decode(data)
	c, err := x509.ParseCertificate(b.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

// K-09: повторный dev-pki не затирает учебный УЦ (раньше новый УЦ делал
// негодными все выданные сертификаты): сертификаты выпускаются под прежним,
// существующие не перезаписываются.
func TestDevPKIKeepsCA(t *testing.T) {
	dir := t.TempDir()
	if err := cmdDevPKI([]string{"-out", dir, "-source", "abs-core"}); err != nil {
		t.Fatal(err)
	}
	before, _ := os.ReadFile(filepath.Join(dir, "ca.crt"))
	if err := cmdDevPKI([]string{"-out", dir, "-source", "pipelock"}); err != nil {
		t.Fatal(err)
	}
	after, _ := os.ReadFile(filepath.Join(dir, "ca.crt"))
	if !bytes.Equal(before, after) {
		t.Fatal("учебный УЦ перезаписан")
	}
	roots := x509.NewCertPool()
	roots.AddCert(readCert(t, filepath.Join(dir, "ca.crt")))
	for _, name := range []string{"abs-core", "pipelock", "server"} {
		c := readCert(t, filepath.Join(dir, name+".crt"))
		if _, err := c.Verify(x509.VerifyOptions{Roots: roots, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageAny}}); err != nil {
			t.Fatalf("%s не сходится с УЦ: %v", name, err)
		}
	}
	if err := cmdDevPKI([]string{"-out", dir, "-source", "abs-core"}); err == nil {
		t.Fatal("существующий сертификат перезаписан")
	}
}

// -subject — только для пакета по одному источнику за окно: отказ до обращения
// к хранилищу, живого сервера тесту не нужно.
func TestProofSubjectFlags(t *testing.T) {
	dir := t.TempDir()
	cfg := filepath.Join(dir, "store.json")
	data := `{"data_dir": "data", "roots_dir": "roots", "tsa": {"url": "local"}, "demo": true,
		"tls": {"cert": "s.crt", "key": "s.key", "client_ca": "ca.crt"},
		"keys": {"min_wait": "1s"}, "sources": [{"name": "agent", "content_type": "application/json", "subject_field": "client"}]}`
	if err := os.WriteFile(cfg, []byte(data), 0o600); err != nil {
		t.Fatal(err)
	}
	window := []string{"-from", "2026-11-07T10:00:00Z", "-to", "2026-11-07T10:01:00Z"}
	for name, tc := range map[string]struct {
		args []string
		want string
	}{
		"без источника":   {append([]string{"-subject", "c-1"}, window...), "-subject takes one source"},
		"пустое значение": {append([]string{"-subject", "", "-source", "agent", "-dek"}, window...), "-subject is empty"},
		"с -window":       {append([]string{"-subject", "c-1", "-source", "agent", "-window"}, window...), "-subject takes one source"},
		"с -dek":          {append([]string{"-subject", "c-1", "-source", "agent", "-dek"}, window...), "drop -dek"},
		"без окна":        {[]string{"-subject", "c-1", "-source", "agent"}, "a window takes both -from and -to"},
		"с -seq":          {append([]string{"-subject", "c-1", "-source", "agent", "-seq", "1"}, window...), "a window takes both -from and -to"},
		// -show-label — только у пакета одной улики: пакет за окно отдаёт месяц
		// с закрытым ключом листом (P-80).
		"-show-label с окном": {append([]string{"-show-label", "-source", "agent"}, window...), "-show-label is for a single-record bundle"},
	} {
		err := cmdProof(append([]string{"-config", cfg}, tc.args...))
		if err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Errorf("%s: %v", name, err)
		}
	}
}
