package tsa

import (
	"bytes"
	"crypto/sha256"
	"crypto/x509"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// Фаззинг разбора того, что приходит снаружи: файлов CRL и перечня
// проверяющего, области CRL и токенов RFC 3161 из пакетов. Разбор не падает
// и не теряет данных молча: файл CRL либо отвергнут, либо в нём столько CRL,
// сколько блоков и элементов DER. Прогон: go test -fuzz=FuzzCRLFile
// ./internal/tsa/ (и так для каждой цели).

// fuzzSeeds — настоящий CRL службы с записью и токен над imprint.
func fuzzSeeds(f *testing.F) (crl, token []byte, a *Authority, imprint [32]byte) {
	f.Helper()
	a, err := NewAuthority(false)
	if err != nil {
		f.Fatal(err)
	}
	now := time.Date(2026, 10, 3, 0, 0, 0, 0, time.UTC)
	crl, err = a.RevocationList(now, now.Add(time.Hour), x509.RevocationListEntry{SerialNumber: big.NewInt(2), RevocationTime: now, ReasonCode: ReasonKeyCompromise})
	if err != nil {
		f.Fatal(err)
	}
	imprint = sha256.Sum256([]byte("head"))
	token, err = a.Sign(imprint[:], nil)
	if err != nil {
		f.Fatal(err)
	}
	return crl, token, a, imprint
}

func FuzzCRLFile(f *testing.F) {
	crl, _, _, _ := fuzzSeeds(f)
	block := pem.EncodeToMemory(&pem.Block{Type: "X509 CRL", Bytes: crl})
	f.Add(crl)
	f.Add(block)
	f.Add(append([]byte("Certificate Revocation List (CRL):\n"), block...))
	f.Add(pem.EncodeToMemory(&pem.Block{Type: "X509 CRL", Bytes: append(append([]byte(nil), crl...), crl...)}))
	f.Add(append(append([]byte(nil), block...), crl...))
	if data, err := os.ReadFile(filepath.Join("testdata", "openssl", "fixture-text.pem")); err == nil {
		f.Add(data)
	}
	f.Fuzz(func(t *testing.T, data []byte) {
		ders, err := crlBlocks(data)
		if err != nil {
			return
		}
		if len(ders) == 0 {
			t.Fatal("no CRL and no error")
		}
		if n := bytes.Count(data, []byte("-----BEGIN")); n > 0 && n > len(ders) {
			t.Fatalf("%d blocks begin, %d CRLs read", n, len(ders))
		}
		for _, der := range ders {
			if f, err := parseCRL("fuzz", der); err == nil {
				f.label()
			}
		}
	})
}

func FuzzRevocationList(f *testing.F) {
	fp := "7f83b1657ff1fc53b92dc18148a1d65dfc2d4b1fa3d677284addd200126d9069"
	f.Add([]byte(`[]`))
	f.Add([]byte(`[{"cert_sha256": "` + fp + `", "revoked": "2026-10-03T00:00:00Z", "reason": "keyCompromise", "invalidity": "2026-10-01T00:00:00Z"}]`))
	f.Add([]byte(`[{"cert_sha256": "` + fp + `", "revoked": "2026-10-03T00:00:00Z", "invalidity": null}]` + "\n"))
	f.Add([]byte(`[{"cert_sha256": "` + fp + `", "revoked": "2026-10-03T00:00:00Z", "reason": "keyCompromise", "reason": "superseded"}]`))
	f.Fuzz(func(t *testing.T, data []byte) {
		r := NewRevocations(time.Now())
		if err := r.addList("fuzz.json", data); err != nil {
			return
		}
		for _, es := range r.listed {
			for _, e := range es {
				if e.Time.IsZero() {
					t.Fatal("an entry with no revocation time")
				}
			}
		}
	})
}

func FuzzParseScope(f *testing.F) {
	uri := tlv(0x86, []byte("http://crl.example/a.crl"))
	f.Add(tlv(0x30, tlv(0xA0, tlv(0xA0, uri))))
	f.Add(tlv(0x30, append(tlv(0xA0, tlv(0xA0, uri)), tlv(0x81, []byte{0xff})...)))
	f.Add(tlv(0x30, tlv(0x83, []byte{0x07, 0x80})))
	f.Add(tlv(0x30, tlv(0x84, []byte{0xff})))
	f.Fuzz(func(t *testing.T, der []byte) {
		sc, _, err := parseScope(der)
		if err != nil {
			return
		}
		sc.covers(&x509.Certificate{CRLDistributionPoints: []string{"http://crl.example/a.crl"}})
		sc.covers(&x509.Certificate{IsCA: true})
		sc.why()
	})
}

// Токен из пакета — как его разбирает esverify: не падает, а проходит только
// подписанный службой над этим imprint.
func FuzzVerifyToken(f *testing.F) {
	_, token, a, imprint := fuzzSeeds(f)
	f.Add(token)
	f.Add(token[:len(token)/2])
	trust := a.Trust()
	f.Fuzz(func(t *testing.T, tok []byte) {
		info, err := Verify(tok, imprint, trust)
		if err != nil {
			return
		}
		if info.Signer == nil || len(info.Chains) == 0 {
			t.Fatal("verified with no signer or chain")
		}
		SignerKey(tok)
		GenTime(tok)
	})
}
