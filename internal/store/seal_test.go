package store

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Nikolay1994Kaz/evidencestore/internal/proof"
	"github.com/Nikolay1994Kaz/evidencestore/internal/tsa"
)

// sealOrg — центр печатей и сертификат печати организации.
func sealOrg(t *testing.T) (root, org *x509.Certificate, orgKey crypto.Signer) {
	t.Helper()
	rk, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	ok, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	rt := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "seal CA"}, NotBefore: time.Date(2020, 1, 1, 0, 0, 0, 0, time.UTC), NotAfter: time.Date(2040, 1, 1, 0, 0, 0, 0, time.UTC),
		KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageCRLSign, BasicConstraintsValid: true, IsCA: true}
	der, err := x509.CreateCertificate(rand.Reader, rt, rt, rk.Public(), rk)
	if err != nil {
		t.Fatal(err)
	}
	root, _ = x509.ParseCertificate(der)
	ot := &x509.Certificate{SerialNumber: big.NewInt(7), Subject: pkix.Name{Organization: []string{"Example Bank"}, CommonName: "Example Bank seal"},
		NotBefore: time.Date(2020, 1, 1, 0, 0, 0, 0, time.UTC), NotAfter: time.Date(2040, 1, 1, 0, 0, 0, 0, time.UTC), KeyUsage: x509.KeyUsageContentCommitment}
	der, err = x509.CreateCertificate(rand.Reader, ot, root, ok.Public(), rk)
	if err != nil {
		t.Fatal(err)
	}
	org, _ = x509.ParseCertificate(der)
	return root, org, ok
}

// Печать организации на ключ хранилища: хранилище проверяет её при запуске,
// берёт метку над ней и кладёт обе в пакеты всех трёх видов; проверяющий с
// корнем центра печатей обходится без -store-key. Метка переживает
// перезапуск. Печать на чужой ключ — хранилище не стартует.
func TestStoreSeal(t *testing.T) {
	c := newClock()
	cfg := testConfig(t)
	s := openStore(t, cfg, c)
	statement, err := SealStatement(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(string(statement), "evidencestore store key\n"+s.PublicKey()+"\n") {
		t.Fatalf("заявление: %q", statement)
	}
	s.Close()
	root, org, orgKey := sealOrg(t)
	cms, err := tsa.Seal(orgKey, org, nil, statement, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	cfg.Seal.File = filepath.Join(t.TempDir(), "seal.pem")
	os.WriteFile(cfg.Seal.File, pem.EncodeToMemory(&pem.Block{Type: "CMS", Bytes: cms}), 0o600)
	s2, err := reopen(cfg, c)
	if err != nil {
		t.Fatal(err)
	}
	ingest(t, s2, "abs-core", 1, 3)
	mustStamp(t, s2)
	c.add(5 * time.Minute)
	ingest(t, s2, "abs-core", 4, 6)
	c.add(5 * time.Minute)
	mustStamp(t, s2)
	c.add(time.Minute)
	ingest(t, s2, "abs-core", 7, 7)
	mustStamp(t, s2)
	c.add(time.Minute)
	mustStamp(t, s2)
	if err := s2.StampSeal(context.Background()); err != nil {
		t.Fatal(err)
	}
	if st := s2.Status().Seal; st == nil || !strings.Contains(st.By, "Example Bank seal") || st.Stamped.IsZero() {
		t.Fatalf("status: %+v", st)
	}
	pool := x509.NewCertPool()
	pool.AddCert(root)
	tr := trustOf(t, s2)
	tr.StoreKey = nil
	tr.SealTrust = &tsa.Trust{Roots: pool}
	pin, err := tsa.ParseSubjectPin("O=Example Bank")
	if err != nil {
		t.Fatal(err)
	}
	tr.SealSubject = []tsa.SubjectPin{pin}
	b, err := s2.Proof("abs-core", 5, false)
	if err != nil || b.Seal == nil || len(b.Seal.Token) == 0 {
		t.Fatalf("пакет одной улики: %v %+v", err, b.Seal)
	}
	if r := proof.Verify(b, tr); !r.Valid() {
		t.Fatalf("пакет одной улики по печати:\n%s", r.Text())
	}
	from, to := clockAt(10, 4, 0), clockAt(10, 6, 0)
	wb, err := s2.ProofWindow(from, to, "", false, 0)
	if err != nil || wb.Seal == nil {
		t.Fatalf("пакет за окно: %v", err)
	}
	if r := proof.VerifyWindow(roundTrip(t, wb), tr, time.Time{}, time.Time{}); !r.Valid() {
		t.Fatalf("пакет за окно по печати:\n%s", r.Text())
	}
	sb, err := s2.ProofSource("abs-core", from, to, false, 0)
	if err != nil || sb.Seal == nil {
		t.Fatalf("пакет по источнику: %v", err)
	}
	if r := proof.VerifySource(sb, tr, time.Time{}, time.Time{}); !r.Valid() {
		t.Fatalf("пакет по источнику по печати:\n%s", r.Text())
	}
	token := b.Seal.Token
	s2.Close()

	s3, err := reopen(cfg, c)
	if err != nil {
		t.Fatal(err)
	}
	if b, err := s3.Proof("abs-core", 5, false); err != nil || b.Seal == nil || string(b.Seal.Token) != string(token) {
		t.Fatalf("метка над печатью после перезапуска: %v", err)
	}
	s3.Close()

	// Метка в data_dir не над этой печатью — не в пакет; берётся новая.
	if err := os.WriteFile(filepath.Join(cfg.DataDir, sealTokenFile), token[:len(token)/2], 0o600); err != nil {
		t.Fatal(err)
	}
	s5, err := reopen(cfg, c)
	if err != nil {
		t.Fatal(err)
	}
	if b, err := s5.Proof("abs-core", 5, false); err != nil || b.Seal == nil || len(b.Seal.Token) != 0 || s5.Status().Seal.Stamped.IsZero() != true {
		t.Fatalf("испорченная метка над печатью попала в пакет: %v", err)
	}
	if err := s5.StampSeal(context.Background()); err != nil {
		t.Fatal(err)
	}
	if b, err := s5.Proof("abs-core", 5, false); err != nil || b.Seal == nil || len(b.Seal.Token) == 0 {
		t.Fatalf("новая метка над печатью: %v", err)
	}
	s5.Close()

	// Не печать в PEM.
	os.WriteFile(cfg.Seal.File, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: org.Raw}), 0o600)
	if s6, err := reopen(cfg, c); err == nil || !strings.Contains(err.Error(), "not CMS") {
		if s6 != nil {
			s6.Close()
		}
		t.Fatalf("сертификат вместо печати: %v", err)
	}

	other, err := tsa.Seal(orgKey, org, nil, []byte("evidencestore store key\nAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\n"), time.Now())
	if err != nil {
		t.Fatal(err)
	}
	os.WriteFile(cfg.Seal.File, other, 0o600)
	if s4, err := reopen(cfg, c); err == nil || !strings.Contains(err.Error(), "another key") {
		if s4 != nil {
			s4.Close()
		}
		t.Fatalf("печать на чужой ключ: %v", err)
	}
}
