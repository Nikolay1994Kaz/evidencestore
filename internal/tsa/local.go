package tsa

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"sync"
	"time"
)

// Authority — локальная служба меток времени для тестов и демо без
// интернета. Токены настоящие (RFC 3161, CMS SignedData), но доверять им
// незачем: корень у неё свой и лежит рядом. В продакшне — TSA НУЦ.
type Authority struct {
	key     crypto.Signer
	cert    *x509.Certificate
	root    *x509.Certificate
	rootKey crypto.Signer // только у созданной в этом процессе; нужен тестам
	policy  asn1.ObjectIdentifier
	essCert *x509.Certificate     // тесты: чей хэш вписать в signingCertificateV2
	ctype   asn1.ObjectIdentifier // тесты: тип содержимого в подписанных атрибутах
	essV1   int                   // тесты: 1 — атрибут signingCertificate (v1, SHA-1) вместо v2, -1 — никакого
	acc     accuracy              // тесты: точность метки

	mu     sync.Mutex
	serial int64
	// Now — часы службы; nil — time.Now. Тесты двигают их, чтобы получить
	// метки с разным временем.
	Now func() time.Time
}

// demoPolicy — OID политики локальной службы (произвольная ветка).
var demoPolicy = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 99999, 1}

// NewAuthority заводит корень и сертификат службы. rsaKey — RSA-2048, как у
// НУЦ; иначе ECDSA P-256 (быстрее для тестов).
func NewAuthority(rsaKey bool) (*Authority, error) {
	newKey := func() (crypto.Signer, error) {
		if rsaKey {
			return rsa.GenerateKey(rand.Reader, 2048)
		}
		return ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	}
	rootKey, err := newKey()
	if err != nil {
		return nil, err
	}
	// Срок действия широкий: службе всё равно не доверяют, а тесты и демо
	// гоняют часы в прошлое и будущее.
	now := time.Now()
	notBefore := time.Date(2000, 1, 1, 0, 0, 0, 0, time.UTC)
	rootTmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "evidencestore demo TSA root"},
		NotBefore:             notBefore,
		NotAfter:              now.AddDate(20, 0, 0),
		KeyUsage:              x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	rootDER, err := x509.CreateCertificate(rand.Reader, rootTmpl, rootTmpl, rootKey.Public(), rootKey)
	if err != nil {
		return nil, err
	}
	root, _ := x509.ParseCertificate(rootDER)
	key, err := newKey()
	if err != nil {
		return nil, err
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      pkix.Name{CommonName: "evidencestore demo TSA"},
		NotBefore:    notBefore,
		NotAfter:     now.AddDate(20, 0, 0),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageTimeStamping},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, root, key.Public(), rootKey)
	if err != nil {
		return nil, err
	}
	cert, _ := x509.ParseCertificate(der)
	return &Authority{key: key, cert: cert, root: root, rootKey: rootKey, policy: demoPolicy}, nil
}

// Root — корневой сертификат: его проверяющий закрепляет у себя.
func (a *Authority) Root() *x509.Certificate { return a.root }

// Trust — доверие к этой службе для Verify.
func (a *Authority) Trust() Trust {
	pool := x509.NewCertPool()
	pool.AddCert(a.root)
	return Trust{Roots: pool}
}

func (a *Authority) contentType() asn1.ObjectIdentifier {
	if a.ctype != nil {
		return a.ctype
	}
	return oidTSTInfo
}

func (a *Authority) now() time.Time {
	if a.Now != nil {
		return a.Now()
	}
	return time.Now()
}

// Sign выпускает токен над готовым хэшем SHA-256.
func (a *Authority) Sign(imprint []byte, nonce *big.Int) ([]byte, error) {
	if len(imprint) != sha256.Size {
		return nil, errors.New("tsa: imprint must be SHA-256")
	}
	a.mu.Lock()
	a.serial++
	serial := a.serial
	a.mu.Unlock()

	tst, err := asn1.Marshal(tstInfo{
		Version:        1,
		Policy:         a.policy,
		MessageImprint: messageImprint{HashAlgorithm: pkix.AlgorithmIdentifier{Algorithm: oidSHA256}, HashedMessage: imprint},
		SerialNumber:   big.NewInt(serial),
		GenTime:        a.now().UTC().Truncate(time.Second),
		Accuracy:       a.acc,
		Nonce:          nonce,
	})
	if err != nil {
		return nil, err
	}
	digest := sha256.Sum256(tst)
	ess := a.cert
	if a.essCert != nil {
		ess = a.essCert
	}
	certHash := sha256.Sum256(ess.Raw)
	essAttr := attr(oidSigningCertV2, signingCertificateV2{Certs: []essCertIDv2{{CertHash: certHash[:]}}})
	if a.essV1 == 1 {
		h1 := sha1.Sum(ess.Raw)
		essAttr = attr(oidSigningCertV1, signingCertificateV1{Certs: []essCertIDv1{{CertHash: h1[:]}}})
	}
	all := []rawAttr{attr(oidContentType, a.contentType()), attr(oidMessageDigst, digest[:])}
	if a.essV1 >= 0 {
		all = append(all, essAttr)
	}
	attrs, err := attributesSet(all...)
	if err != nil {
		return nil, err
	}
	attrsDigest := sha256.Sum256(attrs)
	sig, err := a.key.Sign(rand.Reader, attrsDigest[:], crypto.SHA256)
	if err != nil {
		return nil, err
	}
	sigAlg := x509.SHA256WithRSA
	if _, ok := a.key.(*ecdsa.PrivateKey); ok {
		sigAlg = x509.ECDSAWithSHA256
	}
	si, err := asn1.Marshal(struct {
		Version            int
		SID                issuerAndSerial
		DigestAlgorithm    pkix.AlgorithmIdentifier
		SignedAttrs        asn1.RawValue
		SignatureAlgorithm pkix.AlgorithmIdentifier
		Signature          []byte
	}{
		Version:            1,
		SID:                issuerAndSerial{Issuer: asn1.RawValue{FullBytes: a.cert.RawIssuer}, Serial: a.cert.SerialNumber},
		DigestAlgorithm:    pkix.AlgorithmIdentifier{Algorithm: oidSHA256},
		SignedAttrs:        asn1.RawValue{FullBytes: append([]byte{0xA0}, attrs[1:]...)}, // [0] IMPLICIT
		SignatureAlgorithm: pkix.AlgorithmIdentifier{Algorithm: sigAlgOID(sigAlg)},
		Signature:          sig,
	})
	if err != nil {
		return nil, err
	}
	// Внешние слои собираем из готовых байтов (tlv): у полей с тегами
	// контекста encoding/asn1 легко завернуть значение дважды.
	eContent, _ := asn1.Marshal(tst) // OCTET STRING с TSTInfo
	tstType, _ := asn1.Marshal(oidTSTInfo)
	encap := tlv(0x30, append(tstType, tlv(0xA0, eContent)...))
	version, _ := asn1.Marshal(3)
	digestAlgs, _ := asn1.Marshal(pkix.AlgorithmIdentifier{Algorithm: oidSHA256})
	var sd []byte
	sd = append(sd, version...)
	sd = append(sd, tlv(0x31, digestAlgs)...)
	sd = append(sd, encap...)
	sd = append(sd, tlv(0xA0, a.cert.Raw)...) // certificates [0] IMPLICIT
	sd = append(sd, tlv(0x31, si)...)
	sdType, _ := asn1.Marshal(oidSignedData)
	return tlv(0x30, append(sdType, tlv(0xA0, tlv(0x30, sd))...)), nil
}

// ServeHTTP отвечает на запросы RFC 3161, как настоящая служба.
func (a *Authority) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	body, err := io.ReadAll(io.LimitReader(r.Body, 1<<16))
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	var req timeStampReq
	if _, err := asn1.Unmarshal(body, &req); err != nil || !req.MessageImprint.HashAlgorithm.Algorithm.Equal(oidSHA256) {
		writeResp(w, timeStampResp{Status: pkiStatusInfo{Status: 2}}) // rejection
		return
	}
	token, err := a.Sign(req.MessageImprint.HashedMessage, req.Nonce)
	if err != nil {
		writeResp(w, timeStampResp{Status: pkiStatusInfo{Status: 2}})
		return
	}
	writeResp(w, timeStampResp{Status: pkiStatusInfo{Status: 0}, Token: asn1.RawValue{FullBytes: token}})
}

func writeResp(w http.ResponseWriter, resp timeStampResp) {
	der, err := asn1.Marshal(resp)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/timestamp-reply")
	w.Write(der)
}

// Save кладёт ключ, сертификат и корень службы в каталог (PEM), Load
// поднимает их: демо-сервер переживает перезапуск с той же службой.
func (a *Authority) Save(dir string) error {
	keyDER, err := x509.MarshalPKCS8PrivateKey(a.key)
	if err != nil {
		return err
	}
	files := map[string][]byte{
		"tsa.key":  pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER}),
		"tsa.crt":  pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: a.cert.Raw}),
		"root.crt": pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: a.root.Raw}),
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	for name, data := range files {
		if err := os.WriteFile(filepath.Join(dir, name), data, 0o600); err != nil {
			return err
		}
	}
	return nil
}

// LoadAuthority поднимает службу, сохранённую Save.
func LoadAuthority(dir string) (*Authority, error) {
	read := func(name, typ string) ([]byte, error) {
		data, err := os.ReadFile(filepath.Join(dir, name))
		if err != nil {
			return nil, err
		}
		b, _ := pem.Decode(data)
		if b == nil || b.Type != typ {
			return nil, fmt.Errorf("tsa: %s: not a %s", name, typ)
		}
		return b.Bytes, nil
	}
	keyDER, err := read("tsa.key", "PRIVATE KEY")
	if err != nil {
		return nil, err
	}
	k, err := x509.ParsePKCS8PrivateKey(keyDER)
	if err != nil {
		return nil, err
	}
	signer, ok := k.(crypto.Signer)
	if !ok {
		return nil, errors.New("tsa: key is not a signer")
	}
	a := &Authority{key: signer, policy: demoPolicy}
	for name, dst := range map[string]**x509.Certificate{"tsa.crt": &a.cert, "root.crt": &a.root} {
		der, err := read(name, "CERTIFICATE")
		if err != nil {
			return nil, err
		}
		if *dst, err = x509.ParseCertificate(der); err != nil {
			return nil, err
		}
	}
	return a, nil
}

func sigAlgOID(alg x509.SignatureAlgorithm) asn1.ObjectIdentifier {
	if alg == x509.ECDSAWithSHA256 {
		return asn1.ObjectIdentifier{1, 2, 840, 10045, 4, 3, 2}
	}
	return asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 11}
}

type rawAttr struct {
	oid   asn1.ObjectIdentifier
	value any
}

func attr(oid asn1.ObjectIdentifier, value any) rawAttr { return rawAttr{oid, value} }

// attributesSet кодирует атрибуты как DER SET OF: элементы отсортированы по
// байтам, как требует DER.
func attributesSet(attrs ...rawAttr) ([]byte, error) {
	var encoded [][]byte
	for _, a := range attrs {
		v, err := asn1.Marshal(a.value)
		if err != nil {
			return nil, err
		}
		der, err := asn1.Marshal(attribute{Type: a.oid, Values: asn1.RawValue{FullBytes: tlv(0x31, v)}})
		if err != nil {
			return nil, err
		}
		encoded = append(encoded, der)
	}
	sort.Slice(encoded, func(i, j int) bool { return string(encoded[i]) < string(encoded[j]) })
	var body []byte
	for _, e := range encoded {
		body = append(body, e...)
	}
	return tlv(0x31, body), nil
}

// tlv кодирует тег, длину DER и содержимое.
func tlv(tag byte, content []byte) []byte {
	n := len(content)
	out := []byte{tag}
	switch {
	case n < 0x80:
		out = append(out, byte(n))
	case n < 0x100:
		out = append(out, 0x81, byte(n))
	case n < 0x10000:
		out = append(out, 0x82, byte(n>>8), byte(n))
	default:
		out = append(out, 0x83, byte(n>>16), byte(n>>8), byte(n))
	}
	return append(out, content...)
}
