package main

import (
	"bytes"
	"crypto/x509"
	"encoding/pem"
	"os"
	"path/filepath"
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
