package tsa

import (
	"bytes"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"fmt"
	"strconv"
	"strings"
	"time"
)

// Печать: CMS SignedData (RFC 5652) с вложенным содержимым (id-data),
// подписанная сертификатом X.509 — печатью организации или ЭЦП юрлица. Так
// организация ручается за байты: хранилище — за заявление «этот ключ подписи
// цепи — мой». Делается обычными средствами (openssl cms -sign -nodetach,
// NCALayer), проверяется офлайн: подпись над подписанными атрибутами,
// contentType и messageDigest, сертификат подписанта и его цепочка до корня
// проверяющего. Алгоритмы — RSA PKCS #1 v1.5 и ECDSA с SHA-2; ГОСТ — нет.

var (
	oidData        = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 7, 1}
	oidSigningTime = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 5}
)

// MaxSealSize — печать больше этого не разбирается: заявление в несколько
// строк и цепочка сертификатов укладываются с запасом.
const MaxSealSize = 64 << 10

// Sealed — печать, чья подпись сошлась.
type Sealed struct {
	Content []byte            // вложенное содержимое: на что поставлена печать
	Signer  *x509.Certificate // сертификат подписанта
	Certs   []*x509.Certificate
	// SigningTime — атрибут signingTime: время по часам подписанта, ничего
	// не доказывает; ноль — атрибута нет.
	SigningTime time.Time
}

// OpenSeal разбирает печать и сверяет её подпись сертификатом, который
// печать несёт (или из intermediates), — без цепочки до корня.
func OpenSeal(der []byte, intermediates ...*x509.Certificate) (Sealed, error) {
	fail := func(f string, a ...any) (Sealed, error) {
		return Sealed{}, fmt.Errorf("%w: seal: %s", ErrInvalid, fmt.Sprintf(f, a...))
	}
	if len(der) > MaxSealSize {
		return fail("larger than %d bytes", MaxSealSize)
	}
	var ci contentInfo
	if rest, err := asn1.Unmarshal(der, &ci); err != nil || len(rest) != 0 || !ci.ContentType.Equal(oidSignedData) {
		return fail("not a CMS SignedData")
	}
	var sd signedData
	if rest, err := asn1.Unmarshal(ci.Content.Bytes, &sd); err != nil || len(rest) != 0 {
		return fail("bad SignedData")
	}
	if sd.Version != 1 && sd.Version != 3 {
		return fail("SignedData version %d", sd.Version)
	}
	if !sd.EncapContentInfo.EContentType.Equal(oidData) {
		return fail("the content is not data (id-data)")
	}
	if len(sd.EncapContentInfo.EContent.Bytes) == 0 {
		return fail("no content inside: seal it attached (openssl cms -sign -nodetach)")
	}
	var content []byte
	if rest, err := asn1.Unmarshal(sd.EncapContentInfo.EContent.Bytes, &content); err != nil || len(rest) != 0 {
		return fail("bad content")
	}
	if len(sd.SignerInfos) != 1 {
		return fail("%d signers, want one", len(sd.SignerInfos))
	}
	si := sd.SignerInfos[0]
	if byKeyID := si.SID.Class == asn1.ClassContextSpecific && si.SID.Tag == 0; byKeyID && si.Version != 3 || !byKeyID && si.Version != 1 {
		return fail("SignerInfo version %d", si.Version)
	}
	if da := sd.DigestAlgorithms; da.Class != asn1.ClassUniversal || da.Tag != asn1.TagSet || !da.IsCompound {
		return fail("digest algorithms are not a SET")
	}
	declared := false
	for rest := sd.DigestAlgorithms.Bytes; len(rest) > 0; {
		var alg pkix.AlgorithmIdentifier
		var err error
		if rest, err = asn1.Unmarshal(rest, &alg); err != nil {
			return fail("bad digest algorithms")
		}
		declared = declared || alg.Algorithm.Equal(si.DigestAlgorithm.Algorithm)
	}
	if !declared || !plainParams(si.DigestAlgorithm) || !plainParams(si.SignatureAlgorithm) {
		return fail("the signer's algorithms are not declared or carry parameters")
	}
	hash, err := hashFor(si.DigestAlgorithm.Algorithm)
	if err != nil {
		return Sealed{}, err
	}
	var certs []*x509.Certificate
	if len(sd.Certificates.Bytes) > 0 {
		if certs, err = x509.ParseCertificates(sd.Certificates.Bytes); err != nil {
			return fail("bad certificates: %v", err)
		}
	}
	// Подписанные атрибуты обязательны: без них подпись — над содержимым, и
	// его тип ничем не закреплён.
	if len(si.SignedAttrs.FullBytes) == 0 {
		return fail("no signed attributes")
	}
	attrsSet := append([]byte{0x31}, si.SignedAttrs.FullBytes[1:]...)
	var ct, md []byte
	var at time.Time
	seen := map[string]bool{}
	for rest := si.SignedAttrs.Bytes; len(rest) > 0; {
		var a attribute
		if rest, err = asn1.Unmarshal(rest, &a); err != nil {
			return fail("bad signed attribute")
		}
		if seen[a.Type.String()] {
			return fail("signed attribute %v given twice", a.Type)
		}
		seen[a.Type.String()] = true
		switch {
		case a.Type.Equal(oidContentType):
			ct = a.Values.Bytes
		case a.Type.Equal(oidMessageDigst):
			md = a.Values.Bytes
		case a.Type.Equal(oidSigningTime):
			var t time.Time
			if _, err := asn1.Unmarshal(a.Values.Bytes, &t); err == nil {
				at = t.UTC()
			}
		}
	}
	var ctOID asn1.ObjectIdentifier
	if rest, err := asn1.Unmarshal(ct, &ctOID); err != nil || len(rest) != 0 || !ctOID.Equal(oidData) {
		return fail("the content-type attribute is not data")
	}
	var digest []byte
	if rest, err := asn1.Unmarshal(md, &digest); err != nil || len(rest) != 0 {
		return fail("bad message-digest attribute")
	}
	h := hash.New()
	h.Write(content)
	if !bytes.Equal(h.Sum(nil), digest) {
		return fail("the signed digest does not match the content")
	}
	// Подписант — из сертификатов, которые называет SID, тот, чья подпись
	// сходится и кого называет атрибут signingCertificate (CAdES), если он
	// есть (openssl cms без -cades его не пишет): по номеру ключа подходят
	// все сертификаты ключа.
	pool := append(append([]*x509.Certificate(nil), certs...), intermediates...)
	candidates := findSigners(si.SID, pool)
	if len(candidates) == 0 {
		return fail("the signer certificate is not in the seal")
	}
	var signer *x509.Certificate
	var firstErr error
	for _, c := range candidates {
		err := checkSignature(c, si.SignatureAlgorithm.Algorithm, hash, attrsSet, si.Signature)
		if err == nil {
			if a, ok := attrOf(si, oidSigningCertV2); ok {
				err = checkSigningCert(a, c)
			} else if a, ok := attrOf(si, oidSigningCertV1); ok {
				err = checkSigningCertV1(a, c)
			}
		}
		if err == nil {
			signer = c
			break
		}
		if firstErr == nil {
			firstErr = err
		}
	}
	if signer == nil {
		return Sealed{}, firstErr
	}
	if signer.KeyUsage != 0 && signer.KeyUsage&(x509.KeyUsageDigitalSignature|x509.KeyUsageContentCommitment) == 0 {
		return fail("the signer certificate may not sign (key usage)")
	}
	return Sealed{Content: content, Signer: signer, Certs: certs, SigningTime: at}, nil
}

// attrOf — значение подписанного атрибута oid.
func attrOf(si signerInfo, oid asn1.ObjectIdentifier) ([]byte, bool) {
	for rest := si.SignedAttrs.Bytes; len(rest) > 0; {
		var a attribute
		var err error
		if rest, err = asn1.Unmarshal(rest, &a); err != nil {
			return nil, false
		}
		if a.Type.Equal(oid) {
			return a.Values.Bytes, true
		}
	}
	return nil, false
}

// VerifySeal — OpenSeal и цепочка подписанта до корня trust на момент at:
// печать поставлена, пока сертификат действовал. chains — для сверки отзыва.
func VerifySeal(der []byte, trust Trust, at time.Time) (Sealed, [][]*x509.Certificate, error) {
	s, err := OpenSeal(der, trust.Intermediates...)
	if err != nil {
		return Sealed{}, nil, err
	}
	inter := x509.NewCertPool()
	for _, c := range append(append([]*x509.Certificate(nil), s.Certs...), trust.Intermediates...) {
		inter.AddCert(c)
	}
	chains, err := s.Signer.Verify(x509.VerifyOptions{Roots: trust.Roots, Intermediates: inter, CurrentTime: at, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageAny}})
	if err != nil {
		return Sealed{}, nil, fmt.Errorf("%w: seal: signer certificate: %v", ErrInvalid, err)
	}
	return s, chains, nil
}

// SubjectPin — атрибут имени владельца печати, которого требует проверяющий
// (esverify -seal-subject O=Example Bank): под корнем национального центра
// сертификаты у многих организаций, и печать любой из них иначе ручалась бы
// за любой ключ.
type SubjectPin struct {
	Type  asn1.ObjectIdentifier
	Value string
	text  string
}

// pinTypes — имена атрибутов, как их пишут в RFC 4514 и openssl.
var pinTypes = map[string]asn1.ObjectIdentifier{
	"CN":                     {2, 5, 4, 3},
	"SERIALNUMBER":           {2, 5, 4, 5},
	"C":                      {2, 5, 4, 6},
	"L":                      {2, 5, 4, 7},
	"ST":                     {2, 5, 4, 8},
	"STREET":                 {2, 5, 4, 9},
	"O":                      {2, 5, 4, 10},
	"OU":                     {2, 5, 4, 11},
	"ORGANIZATIONIDENTIFIER": {2, 5, 4, 97},
	"UID":                    {0, 9, 2342, 19200300, 100, 1, 1},
	"DC":                     {0, 9, 2342, 19200300, 100, 1, 25},
	"EMAILADDRESS":           {1, 2, 840, 113549, 1, 9, 1},
}

// ParseSubjectPin — ATTRIBUTE=VALUE: имя атрибута (O, OU, CN, serialNumber,
// organizationIdentifier, …) или его OID через точки, значение — ровно как в
// сертификате.
func ParseSubjectPin(text string) (SubjectPin, error) {
	name, value, ok := strings.Cut(text, "=")
	name = strings.TrimSpace(name)
	if !ok || name == "" || value == "" {
		return SubjectPin{}, fmt.Errorf("%q: want ATTRIBUTE=VALUE, such as O=Example Bank or 2.5.4.97=NTRKZ-123456789012", text)
	}
	if oid, ok := pinTypes[strings.ToUpper(name)]; ok {
		return SubjectPin{Type: oid, Value: value, text: text}, nil
	}
	var oid asn1.ObjectIdentifier
	for _, part := range strings.Split(name, ".") {
		n, err := strconv.Atoi(part)
		if err != nil || n < 0 || part != strconv.Itoa(n) {
			return SubjectPin{}, fmt.Errorf("%q: %q is neither an attribute name (O, OU, CN, serialNumber, organizationIdentifier, …) nor an OID", text, name)
		}
		oid = append(oid, n)
	}
	if len(oid) < 2 {
		return SubjectPin{}, fmt.Errorf("%q: %q is not an OID", text, name)
	}
	return SubjectPin{Type: oid, Value: value, text: text}, nil
}

func (p SubjectPin) String() string { return p.text }

// In — есть ли в имени атрибут этого типа ровно с этим значением.
func (p SubjectPin) In(n pkix.Name) bool {
	for _, a := range n.Names {
		if v, ok := a.Value.(string); ok && a.Type.Equal(p.Type) && v == p.Value {
			return true
		}
	}
	return false
}
