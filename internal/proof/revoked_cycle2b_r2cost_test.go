package proof

import (
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"math/big"
	"testing"
	"time"
)

// r2tlv — DER: тег, длина, содержимое.
func r2tlv(tag byte, b []byte) []byte {
	n := len(b)
	var l []byte
	switch {
	case n < 128:
		l = []byte{byte(n)}
	case n < 256:
		l = []byte{0x81, byte(n)}
	case n < 65536:
		l = []byte{0x82, byte(n >> 8), byte(n)}
	default:
		l = []byte{0x83, byte(n >> 16), byte(n >> 8), byte(n)}
	}
	return append(append([]byte{tag}, l...), b...)
}

// r2inject — тот же токен, в поле certificates SignedData которого
// дописаны certs. Подпись токена этого поля не покрывает: токен проходит
// tsa.Verify как прежде.
func r2inject(t *testing.T, token []byte, certs []*x509.Certificate) []byte {
	t.Helper()
	var ci struct {
		Type    asn1.ObjectIdentifier
		Content asn1.RawValue `asn1:"explicit,tag:0"`
	}
	if _, err := asn1.Unmarshal(token, &ci); err != nil {
		t.Fatal(err)
	}
	var sd asn1.RawValue
	if _, err := asn1.Unmarshal(ci.Content.Bytes, &sd); err != nil {
		t.Fatal(err)
	}
	var out []byte
	for rest := sd.Bytes; len(rest) > 0; {
		var e asn1.RawValue
		var err error
		if rest, err = asn1.Unmarshal(rest, &e); err != nil {
			t.Fatal(err)
		}
		if e.Class == asn1.ClassContextSpecific && e.Tag == 0 {
			body := append([]byte(nil), e.Bytes...)
			for _, c := range certs {
				body = append(body, c.Raw...)
			}
			out = append(out, r2tlv(0xA0, body)...)
			continue
		}
		out = append(out, e.FullBytes...)
	}
	typ, _ := asn1.Marshal(ci.Type)
	return r2tlv(0x30, append(typ, r2tlv(0xA0, r2tlv(0x30, out))...))
}

// R2-F. Сертификаты токена не подписаны (CMS SignedData.certificates): кто
// собирает пакет, дописывает в настоящую метку второй службы сколько угодно
// своих сертификатов. Все они — в Assessment.Known, и Verdicts для каждого
// Known перебирает весь пул с CheckSignature, когда имя издателя совпадает:
// |A|·|B| проверок подписи без кэша. Время проверки пакета растёт квадратично.
func TestC2bR2KnownCostQuadratic(t *testing.T) {
	jk := c2key(t)
	mk := func(serial int64, subj, iss string) *x509.Certificate {
		tmpl := &x509.Certificate{SerialNumber: big.NewInt(serial), Subject: pkix.Name{CommonName: subj}, NotBefore: c2date(2020, 1, 1), NotAfter: c2date(2040, 1, 1)}
		parent := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: iss}}
		der, err := x509.CreateCertificate(rand.Reader, tmpl, parent, jk.Public(), jk)
		if err != nil {
			t.Fatal(err)
		}
		c, _ := x509.ParseCertificate(der)
		return c
	}
	serial := int64(1000)
	for _, m := range []int{1, 2, 4, 8} {
		w, b := standard(t, nil)
		b.Upper.Inclusion = ptr(w.inclusion(5, 0))
		other, tr := otherTSA(t, w)
		cut := w.now.Add(2 * time.Hour)
		tr.TSARevocations = compromised(t, w.tsa, cut, w.now.Add(48*time.Hour))
		real := archiveOver(t, w, other, 5, cut.Add(-time.Hour))
		b.Archive = nil
		for i := 0; i < m; i++ {
			var junk []*x509.Certificate
			for j := 0; j < 70; j++ {
				serial++
				junk = append(junk, mk(serial, "J", "Q"))
				serial++
				junk = append(junk, mk(serial, "Q", "J"))
			}
			a := real
			a.Token = r2inject(t, real.Token, junk)
			b.Archive = append(b.Archive, a)
		}
		start := time.Now()
		r := Verify(b, tr)
		t.Logf("меток второй службы %d, дописанных сертификатов %d: %v (пункт отзыва есть: %v)", m, m*140, time.Since(start).Round(time.Millisecond), len(r.Checks) > 0)
	}
}
