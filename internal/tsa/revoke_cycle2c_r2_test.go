package tsa

// Ревью цикла 2, заход 3 (r2): гипотезы по диффу 2c7da6d..dcef3db.

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"testing"
	"time"
)

// S1. findSigners: по SID подходят все сертификаты пула, и для каждого
// сверяется подпись (дорого) раньше атрибута signingCertificate (дёшево).
// Поле certificates не подписано: токен с сотней подложенных сертификатов
// того же issuer и номера, стоящих раньше настоящего, проверяется в сотню
// раз дольше. До диффа брался первый — и токен не проходил.
func TestC2cR2FindSignersCost(t *testing.T) {
	if testing.Short() {
		t.Skip("замер")
	}
	w := newRevWorld(t)
	imprint := sha256.Sum256([]byte("head"))
	clean, err := w.a.Sign(imprint[:], nil)
	if err != nil {
		t.Fatal(err)
	}
	var fakes []*x509.Certificate
	for i := range 130 {
		k, _ := ecdsa.GenerateKey(elliptic.P521(), rand.Reader)
		tmpl := *w.a.Cert()
		tmpl.PublicKey = nil
		der, err := x509.CreateCertificate(rand.Reader, &tmpl, w.a.Root(), k.Public(), w.a.rootKey)
		if err != nil {
			t.Fatal(err)
		}
		c, _ := x509.ParseCertificate(der)
		fakes = append(fakes, c)
		_ = i
	}
	// Токен с подложенными сертификатами впереди своего.
	stuffedTok, err := w.a.signWithLeading(imprint[:], fakes)
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("token sizes: clean %d, stuffed %d", len(clean), len(stuffedTok))
	if len(stuffedTok) > MaxTokenSize {
		t.Skipf("stuffed token too large: %d", len(stuffedTok))
	}
	measure := func(token []byte) time.Duration {
		start := time.Now()
		for range 10 {
			if _, err := Verify(token, imprint, w.a.Trust()); err != nil {
				t.Fatal(err)
			}
		}
		return time.Since(start) / 10
	}
	c, s := measure(clean), measure(stuffedTok)
	t.Logf("Verify: clean %v, stuffed %v (x%.0f)", c, s, float64(s)/float64(c))
	// Подпись сверяется только у названного атрибутом: остаётся разбор
	// сертификатов (около x13); подпись у каждого — около x970.
	if s > 100*c {
		t.Errorf("130 подложенных сертификатов с тем же SID: Verify в %.0f раз дольше — подпись сверяется у каждого", float64(s)/float64(c))
	}
}
