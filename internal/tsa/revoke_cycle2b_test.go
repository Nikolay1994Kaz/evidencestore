package tsa

// Ревью цикла 2, заход 2 (r1): гипотезы по диффу ecad1a9..4d4f528.

import (
	"bytes"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"math/big"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func r1leafTmpl(serial int64, cn string, from, to time.Time) *x509.Certificate {
	return &x509.Certificate{SerialNumber: big.NewInt(serial), Subject: pkix.Name{CommonName: cn}, NotBefore: from, NotAfter: to,
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageTimeStamping}}
}

// H3. Перечень проверяющего без причины у сертификата центра (корень или
// промежуточный): было — ключ под подозрением (нужна POE), стало — как без
// компрометации: метки до даты в силе без POE.
func TestRevocationsC2bListNoReasonCA(t *testing.T) {
	dir := t.TempDir()
	root := issue(t, caTmpl(1, "r1 list root"), newKey(t), nil)
	ca := issue(t, caTmpl(10, "TSA CA"), newKey(t), root)
	gen := day(2026, 10, 1)
	_, info := tsaUnder(t, ca, day(2030, 1, 1), gen, []*x509.Certificate{root.cert}, ca.cert)
	for name, c := range map[string]*x509.Certificate{"root": root.cert, "intermediate": ca.cert} {
		list := filepath.Join(dir, name+".json")
		data, _ := json.Marshal([]map[string]string{{"cert_sha256": Fingerprint(c), "revoked": day(2026, 10, 20).Format(time.RFC3339)}})
		os.WriteFile(list, data, 0o600)
		r := NewRevocations(day(2026, 11, 2))
		if err := r.AddList(list); err != nil {
			t.Fatal(err)
		}
		r.AddCRL(ca.crlOf(t, dir, "ca.crl", day(2026, 11, 1), day(2026, 12, 1), nil))
		r.AddCRL(root.crlOf(t, dir, "root.crl", day(2026, 11, 1), day(2026, 12, 1), nil))
		v, err := r.Check(info.Chains, info.GenTime)
		t.Logf("%s listed without reason after the stamp: NeedPOE=%v err=%v", name, v.NeedPOE, err)
		if err == nil && !v.NeedPOE {
			t.Errorf("%s в перечне проверяющего без причины: метка до даты — в силе без POE (было: ключ под подозрением)", name)
		}
	}
}

// P-187. Подписант по номеру ключа: у перевыпущенного на тот же ключ
// сертификата номер ключа тот же. Токен без своего сертификата, оба — в
// доверии, прежний первым: годен тот, кого называет signingCertificate.
func TestSignerByKeyIDAmongRenewedCerts(t *testing.T) {
	root := issue(t, caTmpl(1, "skid root"), newKey(t), nil)
	ca := issue(t, caTmpl(10, "TSA CA"), newKey(t), root)
	k := newKey(t)
	skid := []byte{1, 2, 3, 4, 5, 6, 7, 8}
	tmpl := func(serial int64) *x509.Certificate {
		return &x509.Certificate{SerialNumber: big.NewInt(serial), Subject: pkix.Name{CommonName: "TSA"}, NotBefore: day(2025, 1, 1), NotAfter: day(2030, 1, 1),
			SubjectKeyId: skid, KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageTimeStamping}}
	}
	x1, x2 := issue(t, tmpl(1), k, ca), issue(t, tmpl(2), k, ca)
	a := &Authority{key: x2.key, cert: x2.cert, root: root.cert, policy: demoPolicy, Now: func() time.Time { return day(2026, 10, 1) }}
	a.SignByKeyID()
	a.WithoutCert()
	imprint := [32]byte{9}
	token, err := a.Sign(imprint[:], nil)
	if err != nil {
		t.Fatal(err)
	}
	pool := x509.NewCertPool()
	pool.AddCert(root.cert)
	info, err := Verify(token, imprint, Trust{Roots: pool, Intermediates: []*x509.Certificate{x1.cert, x2.cert, ca.cert}})
	if err != nil || !bytes.Equal(info.Signer.Raw, x2.cert.Raw) {
		t.Fatalf("подписант по номеру ключа, прежний сертификат в доверии первым: %v", err)
	}
}
