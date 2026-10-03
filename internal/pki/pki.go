// Package pki — учебный удостоверяющий центр для демо и тестов: УЦ,
// сертификат сервера приёма и клиентские сертификаты сборщиков
// (CommonName = имя источника).
//
// В банке сертификаты выпускает его собственный УЦ; здесь — только чтобы
// стенд поднимался одной командой.
package pki

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"time"
)

// CA — учебный УЦ.
type CA struct {
	Cert *x509.Certificate
	Key  *ecdsa.PrivateKey
}

// NewCA заводит самоподписанный УЦ.
func NewCA(name string) (*CA, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	tmpl := &x509.Certificate{
		SerialNumber:          serial(),
		Subject:               pkix.Name{CommonName: name},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().AddDate(10, 0, 0),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		return nil, err
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, err
	}
	return &CA{Cert: cert, Key: key}, nil
}

// Issued — выпущенный сертификат с ключом.
type Issued struct {
	Cert *x509.Certificate
	Key  *ecdsa.PrivateKey
}

// Server выпускает сертификат сервера на имена и адреса hosts.
func (ca *CA) Server(hosts ...string) (*Issued, error) {
	tmpl := &x509.Certificate{
		Subject:     pkix.Name{CommonName: "evidencestore"},
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	for _, h := range hosts {
		if ip := net.ParseIP(h); ip != nil {
			tmpl.IPAddresses = append(tmpl.IPAddresses, ip)
		} else {
			tmpl.DNSNames = append(tmpl.DNSNames, h)
		}
	}
	return ca.issue(tmpl)
}

// Client выпускает сертификат сборщика источника source.
func (ca *CA) Client(source string) (*Issued, error) {
	return ca.issue(&x509.Certificate{
		Subject:     pkix.Name{CommonName: source},
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	})
}

func (ca *CA) issue(tmpl *x509.Certificate) (*Issued, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	tmpl.SerialNumber = serial()
	tmpl.NotBefore = time.Now().Add(-time.Hour)
	tmpl.NotAfter = time.Now().AddDate(2, 0, 0)
	tmpl.KeyUsage = x509.KeyUsageDigitalSignature
	der, err := x509.CreateCertificate(rand.Reader, tmpl, ca.Cert, &key.PublicKey, ca.Key)
	if err != nil {
		return nil, err
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, err
	}
	return &Issued{Cert: cert, Key: key}, nil
}

// WriteCert пишет сертификат в PEM.
func WriteCert(path string, c *x509.Certificate) error {
	return writePEM(path, "CERTIFICATE", c.Raw, 0o644)
}

// WriteKey пишет ключ в PEM (PKCS#8) с правами 0600.
func WriteKey(path string, k *ecdsa.PrivateKey) error {
	der, err := x509.MarshalPKCS8PrivateKey(k)
	if err != nil {
		return err
	}
	return writePEM(path, "PRIVATE KEY", der, 0o600)
}

// Write кладёт пару cert/key под именем name в каталог dir.
func (i *Issued) Write(dir, name string) error {
	if err := WriteCert(filepath.Join(dir, name+".crt"), i.Cert); err != nil {
		return err
	}
	return WriteKey(filepath.Join(dir, name+".key"), i.Key)
}

func writePEM(path, typ string, der []byte, mode os.FileMode) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	return os.WriteFile(path, pem.EncodeToMemory(&pem.Block{Type: typ, Bytes: der}), mode)
}

func serial() *big.Int {
	n, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 120))
	return n
}
