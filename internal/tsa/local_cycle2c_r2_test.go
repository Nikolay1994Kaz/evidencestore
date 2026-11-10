package tsa

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"math/big"
	"slices"
	"time"
)

// signWithLeading — Sign, но в поле certificates перед своим сертификатом
// лежат pre (поле не подписано): тест цены findSigners.
func (a *Authority) signWithLeading(imprint []byte, pre []*x509.Certificate) ([]byte, error) {
	tst, err := asn1.Marshal(tstInfo{
		Version:        1,
		Policy:         a.policy,
		MessageImprint: messageImprint{HashAlgorithm: pkix.AlgorithmIdentifier{Algorithm: oidSHA256}, HashedMessage: imprint},
		SerialNumber:   big.NewInt(7),
		GenTime:        a.now().UTC().Truncate(time.Second),
	})
	if err != nil {
		return nil, err
	}
	digest := sha256.Sum256(tst)
	certHash := sha256.Sum256(a.cert.Raw)
	attrs, err := attributesSet(attr(oidContentType, oidTSTInfo), attr(oidMessageDigst, digest[:]),
		attr(oidSigningCertV2, signingCertificateV2{Certs: []essCertIDv2{{CertHash: certHash[:]}}}))
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
	}{1, issuerAndSerial{Issuer: asn1.RawValue{FullBytes: a.cert.RawIssuer}, Serial: a.cert.SerialNumber},
		pkix.AlgorithmIdentifier{Algorithm: oidSHA256}, asn1.RawValue{FullBytes: append([]byte{0xA0}, attrs[1:]...)},
		pkix.AlgorithmIdentifier{Algorithm: sigAlgOID(sigAlg)}, sig})
	if err != nil {
		return nil, err
	}
	eContent, _ := asn1.Marshal(tst)
	tstType, _ := asn1.Marshal(oidTSTInfo)
	encap := tlv(0x30, append(tstType, tlv(0xA0, eContent)...))
	version, _ := asn1.Marshal(3)
	digestAlgs, _ := asn1.Marshal(pkix.AlgorithmIdentifier{Algorithm: oidSHA256})
	var certs []byte
	for _, c := range pre {
		certs = append(certs, c.Raw...)
	}
	certs = append(certs, slices.Clone(a.cert.Raw)...)
	var sd []byte
	sd = append(sd, version...)
	sd = append(sd, tlv(0x31, digestAlgs)...)
	sd = append(sd, encap...)
	sd = append(sd, tlv(0xA0, certs)...)
	sd = append(sd, tlv(0x31, si)...)
	sdType, _ := asn1.Marshal(oidSignedData)
	return tlv(0x30, append(sdType, tlv(0xA0, tlv(0x30, sd))...)), nil
}
