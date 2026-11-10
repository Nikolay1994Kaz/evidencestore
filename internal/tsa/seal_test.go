package tsa

import (
	"bytes"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
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

// Имя владельца печати: атрибут по имени или OID, значение — ровно.
func TestSubjectPin(t *testing.T) {
	name := pkix.Name{}
	name.FillFromRDNSequence(&pkix.RDNSequence{
		{{Type: asn1.ObjectIdentifier{2, 5, 4, 10}, Value: "Example Bank"}},
		{{Type: asn1.ObjectIdentifier{2, 5, 4, 11}, Value: "BIN123456789012"}},
		{{Type: asn1.ObjectIdentifier{2, 5, 4, 97}, Value: "NTRKZ-123456789012"}},
		{{Type: asn1.ObjectIdentifier{2, 5, 4, 3}, Value: "Example Bank seal"}},
	})
	for text, want := range map[string]bool{
		"O=Example Bank":                            true,
		"o=Example Bank":                            true,
		" OU =BIN123456789012":                      true,
		"organizationIdentifier=NTRKZ-123456789012": true,
		"2.5.4.97=NTRKZ-123456789012":               true,
		"CN=Example Bank seal":                      true,
		"O=Example bank":                            false,
		"O=Example Bank ":                           false,
		"O=Example":                                 false,
		"CN=Example Bank":                           false,
		"OU=Example Bank":                           false,
		"2.5.4.10=BIN123456789012":                  false,
		"serialNumber=BIN123456789012":              false,
	} {
		p, err := ParseSubjectPin(text)
		if err != nil {
			t.Fatalf("%q: %v", text, err)
		}
		if p.In(name) != want || p.String() != text {
			t.Errorf("%q: In = %v, want %v; String = %q", text, p.In(name), want, p)
		}
	}
	for _, bad := range []string{"", "Example Bank", "=Example Bank", "O=", "commonName=x", "2.5.x=y", "2=y", "2.-5=y", "2.05=y", "1.2.3"} {
		if _, err := ParseSubjectPin(bad); err == nil {
			t.Errorf("%q принят", bad)
		}
	}
}

// Печать, отступающая от правил в одном месте, не открывается — и говорит,
// в каком; правильная, в том числе с верным signingCertificateV2 и версией 3,
// открывается.
func TestSealShapes(t *testing.T) {
	root := issue(t, caTmpl(1, "seal root"), newKey(t), nil)
	org := issue(t, &x509.Certificate{SerialNumber: big.NewInt(10), Subject: pkix.Name{CommonName: "seal"},
		NotBefore: time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC), NotAfter: time.Date(2028, 1, 1, 0, 0, 0, 0, time.UTC), KeyUsage: x509.KeyUsageDigitalSignature}, newKey(t), root)
	other := issue(t, &x509.Certificate{SerialNumber: big.NewInt(11), Subject: pkix.Name{CommonName: "other"},
		NotBefore: time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC), NotAfter: time.Date(2028, 1, 1, 0, 0, 0, 0, time.UTC), KeyUsage: x509.KeyUsageDigitalSignature}, newKey(t), root)
	at := time.Date(2026, 10, 1, 0, 0, 0, 0, time.UTC)
	content := []byte("evidencestore store key\nAAAA\n")
	open := func(sh sealShape, content []byte) error {
		t.Helper()
		der, err := sealShaped(org.key, org.cert, nil, content, at, sh)
		if err != nil {
			t.Fatal(err)
		}
		_, err = OpenSeal(der)
		return err
	}
	for _, sh := range []sealShape{{}, {sdVersion: 3}, {essCert: org.cert}} {
		if err := open(sh, content); err != nil {
			t.Fatalf("%+v: %v", sh, err)
		}
	}
	for want, sh := range map[string]sealShape{
		"SignedData version 2":                        {sdVersion: 2},
		"SignerInfo version 3":                        {siVersion: 3},
		"2 signers, want one":                         {signers: 2},
		"no signed attributes":                        {noAttrs: true},
		"given twice":                                 {twice: true},
		"the content-type attribute is not data":      {attrType: oidTSTInfo},
		"the content is not data":                     {eType: oidTSTInfo},
		"not declared":                                {declared: oidSHA384},
		"not a SET":                                   {algsSequence: true},
		"carry parameters":                            {digestParams: true},
		"signing-certificate attribute names another": {essCert: other.cert},
	} {
		if err := open(sh, content); err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("%q: %v", want, err)
		}
	}
	if err := open(sealShape{}, bytes.Repeat([]byte("x"), MaxSealSize)); err == nil || !strings.Contains(err.Error(), "larger than") {
		t.Errorf("печать больше предела: %v", err)
	}
}
