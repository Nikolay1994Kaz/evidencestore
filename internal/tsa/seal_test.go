package tsa

import (
	"bytes"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// Печать от openssl: содержимое — заявление байт в байт (без -binary openssl
// переводит строки в CRLF), подпись и цепочка до корня сходятся; печать с
// содержимым снаружи не принимается.
func TestSealOpenSSL(t *testing.T) {
	dir := filepath.Join("testdata", "seal")
	read := func(name string) []byte {
		data, err := os.ReadFile(filepath.Join(dir, name))
		if err != nil {
			t.Fatal(err)
		}
		return data
	}
	b, _ := pem.Decode(read("ca.crt"))
	ca, err := x509.ParseCertificate(b.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	pool := x509.NewCertPool()
	pool.AddCert(ca)
	statement := read("statement.txt")
	at := time.Date(2026, 11, 10, 0, 0, 0, 0, time.UTC)
	for name, want := range map[string][]byte{"seal.p7s": statement, "seal-crlf.p7s": bytes.ReplaceAll(statement, []byte("\n"), []byte("\r\n"))} {
		s, chains, err := VerifySeal(read(name), Trust{Roots: pool}, at)
		if err != nil || !bytes.Equal(s.Content, want) || len(chains) != 1 || s.Signer.Subject.CommonName != "Example Bank seal" || s.SigningTime.IsZero() {
			t.Fatalf("%s: %q %v %v", name, s.Content, len(chains), err)
		}
	}
	if _, err := OpenSeal(read("detached.p7s")); err == nil || !strings.Contains(err.Error(), "-nodetach") {
		t.Fatalf("печать без содержимого принята: %v", err)
	}
	if _, _, err := VerifySeal(read("seal.p7s"), Trust{Roots: x509.NewCertPool()}, at); err == nil {
		t.Fatal("печать без корня проверяющего принята")
	}
}

// Печать, поставленная этим кодом (ECDSA): подлинная проходит; изменённое
// содержимое, подпись другим ключом, сертификат без права подписи, истёкший
// на момент проверки — нет.
func TestSealVerify(t *testing.T) {
	root := issue(t, caTmpl(1, "seal root"), newKey(t), nil)
	ca := issue(t, caTmpl(2, "seal CA"), newKey(t), root)
	leafTmpl := func(serial int64, ku x509.KeyUsage) *x509.Certificate {
		return &x509.Certificate{SerialNumber: big.NewInt(serial), Subject: pkix.Name{Organization: []string{"Example Bank"}, CommonName: "seal"},
			NotBefore: time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC), NotAfter: time.Date(2028, 1, 1, 0, 0, 0, 0, time.UTC), KeyUsage: ku}
	}
	org := issue(t, leafTmpl(10, x509.KeyUsageContentCommitment), newKey(t), ca)
	at := time.Date(2026, 10, 1, 0, 0, 0, 0, time.UTC)
	content := []byte("evidencestore store key\nAAAA\n")
	der, err := Seal(org.key, org.cert, []*x509.Certificate{ca.cert}, content, at)
	if err != nil {
		t.Fatal(err)
	}
	pool := x509.NewCertPool()
	pool.AddCert(root.cert)
	trust := Trust{Roots: pool}
	s, chains, err := VerifySeal(der, trust, at)
	if err != nil || !bytes.Equal(s.Content, content) || len(chains) != 1 || len(chains[0]) != 3 || !s.SigningTime.Equal(at) {
		t.Fatalf("подлинная печать: %+v %d %v", s, len(chains), err)
	}
	// Содержимое изменено (тот же размер).
	bad := bytes.Replace(der, []byte("AAAA"), []byte("AAAB"), 1)
	if _, _, err := VerifySeal(bad, trust, at); err == nil || !strings.Contains(err.Error(), "digest") {
		t.Fatalf("изменённое содержимое: %v", err)
	}
	// Подпись ключом, которому сертификат не выдан.
	other := issue(t, leafTmpl(11, x509.KeyUsageDigitalSignature), newKey(t), ca)
	forged, _ := Seal(newKey(t), other.cert, []*x509.Certificate{ca.cert}, content, at)
	if _, _, err := VerifySeal(forged, trust, at); err == nil {
		t.Fatal("подпись чужим ключом принята")
	}
	// Сертификат только для шифрования.
	enc := issue(t, leafTmpl(12, x509.KeyUsageKeyEncipherment), newKey(t), ca)
	encSeal, _ := Seal(enc.key, enc.cert, []*x509.Certificate{ca.cert}, content, at)
	if _, _, err := VerifySeal(encSeal, trust, at); err == nil || !strings.Contains(err.Error(), "key usage") {
		t.Fatalf("сертификат без права подписи: %v", err)
	}
	// Цепочка — на момент печати: после истечения сертификата не сходится.
	if _, _, err := VerifySeal(der, trust, time.Date(2029, 1, 1, 0, 0, 0, 0, time.UTC)); err == nil {
		t.Fatal("печать истёкшим сертификатом принята")
	}
	// Мусор и обрывки не падают.
	for _, d := range [][]byte{nil, der[:len(der)/2], append(append([]byte(nil), der...), 0)} {
		if _, err := OpenSeal(d); err == nil {
			t.Fatalf("обрывок принят: %d байт", len(d))
		}
	}
}
