// Package tsa — метки времени RFC 3161: запрос к службе меток (TSA) и
// офлайн-проверка токена.
//
// ЗАЧЕМ. Локальная цепь защищает от того, кто не может переписать всё сразу;
// её владелец может отрезать хвост и пересчитать голову. TSA — свидетель
// снаружи: получает хэш головы (только хэш, ни тел, ни заголовков) и
// возвращает подписанный токен «такой хэш существовал в момент T». Проверить
// токен может кто угодно по сертификату TSA, без нас.
//
// TSA НУЦ РК (http://tsp.pki.gov.kz) проверен 25.09.2026: отвечает на
// обычный запрос RFC 3161 без учётной записи, подпись RSA/SHA-256, цепочка до
// корня root_rsa_2020.
//
// КАК УСТРОЕН ТОКЕН. Токен — CMS SignedData (RFC 5652), внутри TSTInfo:
// хэш, время, серийный номер. Подписаны не сами байты TSTInfo, а «подписанные
// атрибуты»: среди них отпечаток TSTInfo (messageDigest) и его тип. Проверка
// идёт в обратную сторону: подпись над атрибутами → отпечаток в атрибутах
// совпадает с TSTInfo → в TSTInfo наш хэш → сертификат подписанта ведёт к
// закреплённому корню и разрешён для меток времени.
//
// Пакет не тянет зависимостей: encoding/asn1 и crypto/x509 из стандартной
// библиотеки. Проверяющему меньше чужого кода, которому надо верить.
package tsa

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ecdsa"
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
	"strings"
	"time"
)

var (
	oidSignedData    = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 7, 2}
	oidTSTInfo       = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 16, 1, 4}
	oidContentType   = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 3}
	oidMessageDigst  = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 4}
	oidSigningCertV2 = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 16, 2, 47}
	oidSigningCertV1 = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 16, 2, 12}
	oidSHA256        = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 2, 1}
	oidSHA384        = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 2, 2}
	oidSHA512        = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 2, 3}
)

var (
	ErrRejected = errors.New("tsa: request rejected")
	ErrInvalid  = errors.New("tsa: invalid token")
)

// MaxTokenSize — предел ответа TSA и токена в цепи.
const MaxTokenSize = 64 << 10

type messageImprint struct {
	HashAlgorithm pkix.AlgorithmIdentifier
	HashedMessage []byte
}

type timeStampReq struct {
	Version        int
	MessageImprint messageImprint
	Nonce          *big.Int `asn1:"optional"`
	CertReq        bool     `asn1:"optional,default:false"`
}

type pkiStatusInfo struct {
	Status       int
	StatusString []asn1.RawValue `asn1:"optional"`
	FailInfo     asn1.BitString  `asn1:"optional"`
}

type timeStampResp struct {
	Status pkiStatusInfo
	Token  asn1.RawValue `asn1:"optional"`
}

type tstInfo struct {
	Version        int
	Policy         asn1.ObjectIdentifier
	MessageImprint messageImprint
	SerialNumber   *big.Int
	GenTime        time.Time `asn1:"generalized"`
	// Accuracy — конкретный тип, а не RawValue: необязательный RawValue без
	// тега съедает следующий элемент (здесь — nonce).
	Accuracy   accuracy      `asn1:"optional"`
	Ordering   bool          `asn1:"optional,default:false"`
	Nonce      *big.Int      `asn1:"optional"`
	TSA        asn1.RawValue `asn1:"optional,explicit,tag:0"`
	Extensions asn1.RawValue `asn1:"optional,tag:1"`
}

type accuracy struct {
	Seconds int `asn1:"optional"`
	Millis  int `asn1:"optional,tag:0"`
	Micros  int `asn1:"optional,tag:1"`
}

type contentInfo struct {
	ContentType asn1.ObjectIdentifier
	Content     asn1.RawValue `asn1:"explicit,tag:0"`
}

type encapContentInfo struct {
	EContentType asn1.ObjectIdentifier
	EContent     asn1.RawValue `asn1:"explicit,optional,tag:0"`
}

type signedData struct {
	Version          int
	DigestAlgorithms asn1.RawValue
	EncapContentInfo encapContentInfo
	Certificates     asn1.RawValue `asn1:"optional,tag:0"`
	CRLs             asn1.RawValue `asn1:"optional,tag:1"`
	SignerInfos      []signerInfo  `asn1:"set"`
}

type issuerAndSerial struct {
	Issuer asn1.RawValue
	Serial *big.Int
}

type signerInfo struct {
	Version            int
	SID                asn1.RawValue
	DigestAlgorithm    pkix.AlgorithmIdentifier
	SignedAttrs        asn1.RawValue `asn1:"optional,tag:0"`
	SignatureAlgorithm pkix.AlgorithmIdentifier
	Signature          []byte
	UnsignedAttrs      asn1.RawValue `asn1:"optional,tag:1"`
}

type attribute struct {
	Type   asn1.ObjectIdentifier
	Values asn1.RawValue
}

type essCertIDv2 struct {
	HashAlgorithm pkix.AlgorithmIdentifier `asn1:"optional"`
	CertHash      []byte
	IssuerSerial  asn1.RawValue `asn1:"optional"`
}

type signingCertificateV2 struct {
	Certs    []essCertIDv2
	Policies asn1.RawValue `asn1:"optional"`
}

// essCertIDv1 — ESSCertID (RFC 2634): хэш сертификата только SHA-1.
type essCertIDv1 struct {
	CertHash     []byte
	IssuerSerial asn1.RawValue `asn1:"optional"`
}

type signingCertificateV1 struct {
	Certs    []essCertIDv1
	Policies asn1.RawValue `asn1:"optional"`
}

// MaxAccuracy — точность метки хуже этой не принимается: метка «плюс-минус
// час» не годится в границы времени улики.
const MaxAccuracy = time.Minute

// Imprint — хэш, который уходит в TSA. Домен отделяет метку головы цепи от
// меток над чем-то ещё: токен не предъявить как заверение других байтов.
func Imprint(domain string, data []byte) [32]byte {
	h := sha256.New()
	h.Write([]byte(domain))
	h.Write(data)
	var out [32]byte
	h.Sum(out[:0])
	return out
}

// Request отправляет запрос RFC 3161 и возвращает токен. Токен сверяется
// с запросом (хэш и nonce), но не с корнем доверия: это делает Verify, у
// которого есть закреплённые сертификаты.
func Request(ctx context.Context, client *http.Client, url string, imprint [32]byte) ([]byte, error) {
	nonce, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 63))
	if err != nil {
		return nil, err
	}
	req, err := asn1.Marshal(timeStampReq{
		Version:        1,
		MessageImprint: messageImprint{HashAlgorithm: pkix.AlgorithmIdentifier{Algorithm: oidSHA256}, HashedMessage: imprint[:]},
		Nonce:          nonce,
		CertReq:        true,
	})
	if err != nil {
		return nil, err
	}
	hreq, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(req))
	if err != nil {
		return nil, err
	}
	hreq.Header.Set("Content-Type", "application/timestamp-query")
	resp, err := client.Do(hreq)
	if err != nil {
		return nil, fmt.Errorf("tsa: %w", err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, MaxTokenSize+1))
	if err != nil {
		return nil, fmt.Errorf("tsa: read response: %w", err)
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("%w: HTTP %d", ErrRejected, resp.StatusCode)
	}
	if len(body) > MaxTokenSize {
		return nil, fmt.Errorf("%w: response larger than %d bytes", ErrRejected, MaxTokenSize)
	}
	token, err := ParseResponse(body)
	if err != nil {
		return nil, err
	}
	info, err := parseToken(token)
	if err != nil {
		return nil, err
	}
	if !bytes.Equal(info.tst.MessageImprint.HashedMessage, imprint[:]) {
		return nil, fmt.Errorf("%w: token covers another hash", ErrInvalid)
	}
	if info.tst.Nonce == nil || info.tst.Nonce.Cmp(nonce) != 0 {
		return nil, fmt.Errorf("%w: nonce mismatch (replayed response?)", ErrInvalid)
	}
	return token, nil
}

// ParseResponse достаёт токен из ответа TSA, если запрос удовлетворён.
func ParseResponse(der []byte) ([]byte, error) {
	var resp timeStampResp
	rest, err := asn1.Unmarshal(der, &resp)
	if err != nil || len(rest) != 0 {
		return nil, fmt.Errorf("%w: unparsable response", ErrRejected)
	}
	// 0 — granted, 1 — grantedWithMods; остальное — отказ.
	if resp.Status.Status != 0 && resp.Status.Status != 1 {
		return nil, fmt.Errorf("%w: status %d", ErrRejected, resp.Status.Status)
	}
	if len(resp.Token.FullBytes) == 0 {
		return nil, fmt.Errorf("%w: granted without token", ErrRejected)
	}
	return resp.Token.FullBytes, nil
}

// Info — что доказывает проверенный токен.
type Info struct {
	GenTime time.Time // момент, не позже которого хэш существовал
	Serial  *big.Int
	Policy  asn1.ObjectIdentifier
	Signer  *x509.Certificate
}

// Trust — во что верит проверяющий: корни (у НУЦ — root_rsa_2020) и
// промежуточные сертификаты, если TSA не кладёт их в токен.
type Trust struct {
	Roots         *x509.CertPool
	Intermediates []*x509.Certificate
}

type parsed struct {
	tst      tstInfo
	tstDER   []byte
	signer   signerInfo
	certs    []*x509.Certificate
	attrsSet []byte // подписанные атрибуты в виде SET для проверки подписи
	attrs    []attribute
}

func parseToken(token []byte) (*parsed, error) {
	if len(token) > MaxTokenSize {
		return nil, fmt.Errorf("%w: token larger than %d bytes", ErrInvalid, MaxTokenSize)
	}
	var ci contentInfo
	if rest, err := asn1.Unmarshal(token, &ci); err != nil || len(rest) != 0 || !ci.ContentType.Equal(oidSignedData) {
		return nil, fmt.Errorf("%w: not a CMS SignedData", ErrInvalid)
	}
	var sd signedData
	if rest, err := asn1.Unmarshal(ci.Content.Bytes, &sd); err != nil || len(rest) != 0 {
		return nil, fmt.Errorf("%w: bad SignedData: %v", ErrInvalid, err)
	}
	if !sd.EncapContentInfo.EContentType.Equal(oidTSTInfo) {
		return nil, fmt.Errorf("%w: content is not TSTInfo", ErrInvalid)
	}
	var tstDER []byte
	if rest, err := asn1.Unmarshal(sd.EncapContentInfo.EContent.Bytes, &tstDER); err != nil || len(rest) != 0 {
		return nil, fmt.Errorf("%w: bad eContent", ErrInvalid)
	}
	p := &parsed{tstDER: tstDER}
	if rest, err := asn1.Unmarshal(tstDER, &p.tst); err != nil || len(rest) != 0 {
		return nil, fmt.Errorf("%w: bad TSTInfo: %v", ErrInvalid, err)
	}
	if p.tst.Version != 1 {
		return nil, fmt.Errorf("%w: TSTInfo version %d", ErrInvalid, p.tst.Version)
	}
	if sd.Version != 3 {
		return nil, fmt.Errorf("%w: SignedData version %d, TSTInfo needs 3", ErrInvalid, sd.Version)
	}
	if len(sd.SignerInfos) != 1 {
		return nil, fmt.Errorf("%w: %d signers, RFC 3161 requires one", ErrInvalid, len(sd.SignerInfos))
	}
	p.signer = sd.SignerInfos[0]
	// Версия подписанта задана способом его опознания (RFC 5652, 5.3).
	if want := 1; p.signer.SID.Class == asn1.ClassContextSpecific && p.signer.SID.Tag == 0 {
		if p.signer.Version != 3 {
			return nil, fmt.Errorf("%w: SignerInfo version %d", ErrInvalid, p.signer.Version)
		}
	} else if p.signer.Version != want {
		return nil, fmt.Errorf("%w: SignerInfo version %d", ErrInvalid, p.signer.Version)
	}
	// Алгоритм хэша подписанта обязан быть объявлен в списке SignedData.
	if da := sd.DigestAlgorithms; da.Class != asn1.ClassUniversal || da.Tag != asn1.TagSet || !da.IsCompound {
		return nil, fmt.Errorf("%w: digest algorithms are not a SET", ErrInvalid)
	}
	declared := false
	for rest := sd.DigestAlgorithms.Bytes; len(rest) > 0; {
		var alg pkix.AlgorithmIdentifier
		var err error
		if rest, err = asn1.Unmarshal(rest, &alg); err != nil {
			return nil, fmt.Errorf("%w: bad digest algorithms", ErrInvalid)
		}
		if !plainParams(alg) {
			return nil, fmt.Errorf("%w: digest algorithm with parameters", ErrInvalid)
		}
		declared = declared || alg.Algorithm.Equal(p.signer.DigestAlgorithm.Algorithm)
	}
	if !plainParams(p.signer.DigestAlgorithm) || !plainParams(p.signer.SignatureAlgorithm) {
		return nil, fmt.Errorf("%w: algorithm with parameters", ErrInvalid)
	}
	if !declared {
		return nil, fmt.Errorf("%w: signer digest algorithm not declared", ErrInvalid)
	}
	if len(sd.Certificates.Bytes) > 0 {
		certs, err := x509.ParseCertificates(sd.Certificates.Bytes)
		if err != nil {
			return nil, fmt.Errorf("%w: bad certificates: %v", ErrInvalid, err)
		}
		p.certs = certs
	}
	if len(p.signer.SignedAttrs.FullBytes) == 0 {
		return nil, fmt.Errorf("%w: no signed attributes", ErrInvalid)
	}
	// Подпись считается над атрибутами в кодировке SET OF (тег 0x31), а в
	// токене они лежат с неявным тегом [0]: меняем один байт тега.
	p.attrsSet = append([]byte{0x31}, p.signer.SignedAttrs.FullBytes[1:]...)
	for rest := p.signer.SignedAttrs.Bytes; len(rest) > 0; {
		var a attribute
		var err error
		if rest, err = asn1.Unmarshal(rest, &a); err != nil {
			return nil, fmt.Errorf("%w: bad signed attribute", ErrInvalid)
		}
		p.attrs = append(p.attrs, a)
	}
	return p, nil
}

func (p *parsed) attr(oid asn1.ObjectIdentifier) ([]byte, bool) {
	for _, a := range p.attrs {
		if a.Type.Equal(oid) {
			return a.Values.Bytes, true // содержимое SET: ровно одно значение
		}
	}
	return nil, false
}

// Verify проверяет токен целиком и офлайн: подпись TSA, связь подписи с
// TSTInfo, хэш внутри TSTInfo, цепочку сертификата подписанта до корня из
// trust и право сертификата ставить метки времени.
func Verify(token []byte, imprint [32]byte, trust Trust) (Info, error) {
	p, err := parseToken(token)
	if err != nil {
		return Info{}, err
	}
	mi := p.tst.MessageImprint
	if !mi.HashAlgorithm.Algorithm.Equal(oidSHA256) || !bytes.Equal(mi.HashedMessage, imprint[:]) {
		return Info{}, fmt.Errorf("%w: token covers another hash", ErrInvalid)
	}

	hash, err := hashFor(p.signer.DigestAlgorithm.Algorithm)
	if err != nil {
		return Info{}, err
	}
	ct, ok := p.attr(oidContentType)
	var ctOID asn1.ObjectIdentifier
	if !ok {
		return Info{}, fmt.Errorf("%w: no content-type attribute", ErrInvalid)
	}
	if _, err := asn1.Unmarshal(ct, &ctOID); err != nil || !ctOID.Equal(oidTSTInfo) {
		return Info{}, fmt.Errorf("%w: content-type attribute is not TSTInfo", ErrInvalid)
	}
	mdRaw, ok := p.attr(oidMessageDigst)
	var md []byte
	if !ok {
		return Info{}, fmt.Errorf("%w: no message-digest attribute", ErrInvalid)
	}
	if _, err := asn1.Unmarshal(mdRaw, &md); err != nil {
		return Info{}, fmt.Errorf("%w: bad message-digest attribute", ErrInvalid)
	}
	h := hash.New()
	h.Write(p.tstDER)
	if !bytes.Equal(h.Sum(nil), md) {
		return Info{}, fmt.Errorf("%w: signed digest does not match TSTInfo", ErrInvalid)
	}

	pool := append(append([]*x509.Certificate(nil), p.certs...), trust.Intermediates...)
	signer, err := findSigner(p.signer.SID, pool)
	if err != nil {
		return Info{}, err
	}
	if err := checkSignature(signer, p.signer.SignatureAlgorithm.Algorithm, hash, p.attrsSet, p.signer.Signature); err != nil {
		return Info{}, err
	}
	// RFC 3161, 2.4.1: сертификат подписанта называется подписанным
	// атрибутом — signingCertificateV2 (RFC 5816) или signingCertificate
	// (v1, SHA-1; так подписывает НУЦ РК). Без него подпись можно было бы
	// приписать другому сертификату с тем же ключом.
	if raw, ok := p.attr(oidSigningCertV2); ok {
		if err := checkSigningCert(raw, signer); err != nil {
			return Info{}, err
		}
	} else if raw, ok := p.attr(oidSigningCertV1); ok {
		if err := checkSigningCertV1(raw, signer); err != nil {
			return Info{}, err
		}
	} else {
		return Info{}, fmt.Errorf("%w: no signing-certificate attribute", ErrInvalid)
	}
	if acc := p.tst.Accuracy; acc.Seconds < 0 || acc.Millis < 0 || acc.Micros < 0 ||
		time.Duration(acc.Seconds)*time.Second+time.Duration(acc.Millis)*time.Millisecond+time.Duration(acc.Micros)*time.Microsecond > MaxAccuracy {
		return Info{}, fmt.Errorf("%w: accuracy %ds %dms %dus is worse than %v", ErrInvalid, acc.Seconds, acc.Millis, acc.Micros, MaxAccuracy)
	}
	// RFC 3161, 2.3: у сертификата службы ровно одно назначение — метки
	// времени. Go считает сертификат без EKU годным для всего, поэтому
	// проверяем явно.
	if len(signer.ExtKeyUsage) != 1 || signer.ExtKeyUsage[0] != x509.ExtKeyUsageTimeStamping || len(signer.UnknownExtKeyUsage) != 0 {
		return Info{}, fmt.Errorf("%w: signer certificate is not a time-stamping certificate", ErrInvalid)
	}
	inter := x509.NewCertPool()
	for _, c := range pool {
		inter.AddCert(c)
	}
	if _, err := signer.Verify(x509.VerifyOptions{
		Roots:         trust.Roots,
		Intermediates: inter,
		CurrentTime:   p.tst.GenTime,
		KeyUsages:     []x509.ExtKeyUsage{x509.ExtKeyUsageTimeStamping},
	}); err != nil {
		return Info{}, fmt.Errorf("%w: signer certificate: %v", ErrInvalid, err)
	}
	return Info{GenTime: p.tst.GenTime, Serial: p.tst.SerialNumber, Policy: p.tst.Policy, Signer: signer}, nil
}

// GenTime достаёт время из токена без проверки: для показа и поиска.
// Доверять ему можно только после Verify.
func GenTime(token []byte) (time.Time, error) {
	p, err := parseToken(token)
	if err != nil {
		return time.Time{}, err
	}
	return p.tst.GenTime, nil
}

func hashFor(oid asn1.ObjectIdentifier) (crypto.Hash, error) {
	switch {
	case oid.Equal(oidSHA256):
		return crypto.SHA256, nil
	case oid.Equal(oidSHA384):
		return crypto.SHA384, nil
	case oid.Equal(oidSHA512):
		return crypto.SHA512, nil
	}
	return 0, fmt.Errorf("%w: unsupported digest algorithm %v", ErrInvalid, oid)
}

func findSigner(sid asn1.RawValue, pool []*x509.Certificate) (*x509.Certificate, error) {
	if sid.Class == asn1.ClassContextSpecific && sid.Tag == 0 {
		for _, c := range pool {
			if len(c.SubjectKeyId) > 0 && bytes.Equal(c.SubjectKeyId, sid.Bytes) {
				return c, nil
			}
		}
		return nil, fmt.Errorf("%w: signer certificate not found", ErrInvalid)
	}
	var ias issuerAndSerial
	if _, err := asn1.Unmarshal(sid.FullBytes, &ias); err != nil {
		return nil, fmt.Errorf("%w: bad signer identifier", ErrInvalid)
	}
	for _, c := range pool {
		if bytes.Equal(c.RawIssuer, ias.Issuer.FullBytes) && c.SerialNumber.Cmp(ias.Serial) == 0 {
			return c, nil
		}
	}
	return nil, fmt.Errorf("%w: signer certificate not found", ErrInvalid)
}

var (
	oidRSA         = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 1}
	oidSHA256RSA   = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 11}
	oidSHA384RSA   = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 12}
	oidSHA512RSA   = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 13}
	oidECDSASHA256 = asn1.ObjectIdentifier{1, 2, 840, 10045, 4, 3, 2}
	oidECDSASHA384 = asn1.ObjectIdentifier{1, 2, 840, 10045, 4, 3, 3}
	oidECDSASHA512 = asn1.ObjectIdentifier{1, 2, 840, 10045, 4, 3, 4}
)

// checkSignature проверяет подпись над атрибутами. Заявленный алгоритм
// подписи обязан совпасть и с типом ключа подписанта, и с алгоритмом хэша:
// иначе поле с алгоритмом осталось бы непроверенным.
func checkSignature(cert *x509.Certificate, sigAlg asn1.ObjectIdentifier, hash crypto.Hash, signed, sig []byte) error {
	h := hash.New()
	h.Write(signed)
	digest := h.Sum(nil)
	var rsaAlg, ecAlg asn1.ObjectIdentifier
	switch hash {
	case crypto.SHA256:
		rsaAlg, ecAlg = oidSHA256RSA, oidECDSASHA256
	case crypto.SHA384:
		rsaAlg, ecAlg = oidSHA384RSA, oidECDSASHA384
	case crypto.SHA512:
		rsaAlg, ecAlg = oidSHA512RSA, oidECDSASHA512
	}
	switch pub := cert.PublicKey.(type) {
	case *rsa.PublicKey:
		if !sigAlg.Equal(oidRSA) && !sigAlg.Equal(rsaAlg) {
			return fmt.Errorf("%w: signature algorithm %v does not match RSA key and %v", ErrInvalid, sigAlg, hash)
		}
		if err := rsa.VerifyPKCS1v15(pub, hash, digest, sig); err != nil {
			return fmt.Errorf("%w: signature: %v", ErrInvalid, err)
		}
	case *ecdsa.PublicKey:
		if !sigAlg.Equal(ecAlg) {
			return fmt.Errorf("%w: signature algorithm %v does not match ECDSA key and %v", ErrInvalid, sigAlg, hash)
		}
		if !ecdsa.VerifyASN1(pub, digest, sig) {
			return fmt.Errorf("%w: signature does not verify", ErrInvalid)
		}
	default:
		return fmt.Errorf("%w: unsupported signer key %T", ErrInvalid, pub)
	}
	return nil
}

// checkSigningCert сверяет атрибут signingCertificateV2: подписант обязан
// быть ровно тем сертификатом, хэш которого TSA вписала в подписанные
// атрибуты. Без этого подпись можно было бы приписать другому сертификату
// с тем же ключом.
func checkSigningCert(raw []byte, signer *x509.Certificate) error {
	var sc signingCertificateV2
	if _, err := asn1.Unmarshal(raw, &sc); err != nil || len(sc.Certs) == 0 {
		return fmt.Errorf("%w: bad signing-certificate attribute", ErrInvalid)
	}
	id := sc.Certs[0]
	hash := crypto.SHA256
	if len(id.HashAlgorithm.Algorithm) > 0 {
		var err error
		if hash, err = hashFor(id.HashAlgorithm.Algorithm); err != nil {
			return err
		}
	}
	h := hash.New()
	h.Write(signer.Raw)
	if !bytes.Equal(h.Sum(nil), id.CertHash) {
		return fmt.Errorf("%w: signing-certificate attribute names another certificate", ErrInvalid)
	}
	return nil
}

// checkSigningCertV1 — то же для signingCertificate (v1): хэш SHA-1.
func checkSigningCertV1(raw []byte, signer *x509.Certificate) error {
	var sc signingCertificateV1
	if _, err := asn1.Unmarshal(raw, &sc); err != nil || len(sc.Certs) == 0 {
		return fmt.Errorf("%w: bad signing-certificate attribute", ErrInvalid)
	}
	h := sha1.Sum(signer.Raw)
	if !bytes.Equal(h[:], sc.Certs[0].CertHash) {
		return fmt.Errorf("%w: signing-certificate attribute names another certificate", ErrInvalid)
	}
	return nil
}

// LoadTrust читает сертификаты (DER или PEM) через запятую: самоподписанные
// становятся корнями, остальные — промежуточными. Для НУЦ РК:
// root_rsa_2020.cer,nca_rsa_2022.cer.
func LoadTrust(paths string) (Trust, error) {
	t := Trust{Roots: x509.NewCertPool()}
	roots := 0
	for _, path := range strings.Split(paths, ",") {
		path = strings.TrimSpace(path)
		if path == "" {
			continue
		}
		data, err := os.ReadFile(path)
		if err != nil {
			return Trust{}, fmt.Errorf("tsa: trust: %w", err)
		}
		var ders [][]byte
		for rest := data; ; {
			var b *pem.Block
			b, rest = pem.Decode(rest)
			if b == nil {
				break
			}
			if b.Type == "CERTIFICATE" {
				ders = append(ders, b.Bytes)
			}
		}
		if len(ders) == 0 {
			ders = [][]byte{data}
		}
		for _, der := range ders {
			c, err := x509.ParseCertificate(der)
			if err != nil {
				return Trust{}, fmt.Errorf("tsa: trust %s: %w", path, err)
			}
			if bytes.Equal(c.RawIssuer, c.RawSubject) && c.CheckSignatureFrom(c) == nil {
				t.Roots.AddCert(c)
				roots++
			} else {
				t.Intermediates = append(t.Intermediates, c)
			}
		}
	}
	if roots == 0 {
		return Trust{}, errors.New("tsa: trust: no root certificate")
	}
	return t, nil
}

// plainParams: у хэшей SHA-2 и подписей RSA/ECDSA параметров нет либо там
// NULL. Иное — изменённый или чужой формат, а не вариант нормы.
func plainParams(alg pkix.AlgorithmIdentifier) bool {
	p := alg.Parameters
	return len(p.FullBytes) == 0 || (p.Class == asn1.ClassUniversal && p.Tag == asn1.TagNull && len(p.Bytes) == 0)
}
