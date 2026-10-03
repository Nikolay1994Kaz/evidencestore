package proof

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
)

// PromiseDomain — домен подписанного обещания при приёме.
const PromiseDomain = "evidencestore/promise/v1"

// Promise — подписанное обещание хранилища, выданное сборщику при приёме:
// «принял (Source, Seq) с таким отпечатком в момент ReceivedAt, положил на
// позицию Position и включу в цепь не позже Deadline». Идея — SCT из
// Certificate Transparency (RFC 6962). Обещание остаётся у сборщика: если
// улика не появилась в цепи к сроку или появилась другой, у него на руках
// доказательство нарушения, подписанное самим хранилищем.
type Promise struct {
	Source     string `json:"source"`
	Seq        uint64 `json:"seq"`
	Position   uint64 `json:"position"`
	Digest     []byte `json:"digest"`
	ReceivedAt int64  `json:"received_at"` // unix-нс
	Deadline   int64  `json:"deadline"`    // unix-нс
	PublicKey  string `json:"pubkey"`
	Signature  []byte `json:"sig"`
}

// PromiseBytes — подписываемые байты: поля с префиксом длины, домен первым.
func PromiseBytes(p Promise) []byte {
	field := func(dst, f []byte) []byte {
		dst = binary.BigEndian.AppendUint32(dst, uint32(len(f)))
		return append(dst, f...)
	}
	b := field(nil, []byte(PromiseDomain))
	b = field(b, []byte(p.Source))
	b = binary.BigEndian.AppendUint64(b, p.Seq)
	b = binary.BigEndian.AppendUint64(b, p.Position)
	b = field(b, p.Digest)
	b = binary.BigEndian.AppendUint64(b, uint64(p.ReceivedAt))
	b = binary.BigEndian.AppendUint64(b, uint64(p.Deadline))
	return field(b, []byte(p.PublicKey))
}

// VerifyPromise проверяет подпись обещания по закреплённому ключу хранилища.
func VerifyPromise(p Promise, pinned ed25519.PublicKey) error {
	pub, err := base64.RawStdEncoding.DecodeString(p.PublicKey)
	if err != nil || len(pub) != ed25519.PublicKeySize {
		return errors.New("proof: promise public key unparsable")
	}
	if pinned != nil && !pinned.Equal(ed25519.PublicKey(pub)) {
		return errors.New("proof: promise signed by another key than the pinned one")
	}
	if !ed25519.Verify(ed25519.PublicKey(pub), PromiseBytes(p), p.Signature) {
		return errors.New("proof: promise signature does not verify")
	}
	return nil
}

// CheckPromise сверяет обещание с проверенным пакетом: та же улика, та же
// позиция, звено улики не позже срока по часам хранилища.
func CheckPromise(p Promise, r Report, linkTime int64) error {
	switch {
	case p.Source != r.Header.Source || p.Seq != r.Header.Seq:
		return fmt.Errorf("обещание про %s/%d, пакет про %s/%d", p.Source, p.Seq, r.Header.Source, r.Header.Seq)
	case string(p.Digest) != string(r.Digest[:]):
		return errors.New("отпечаток в обещании не совпадает с уликой в цепи — хранилище подменило улику после приёма")
	case p.Position != r.Position:
		return fmt.Errorf("обещана позиция %d, в цепи %d", p.Position, r.Position)
	case p.ReceivedAt != r.Header.ReceivedAt:
		return errors.New("время приёма в обещании не совпадает с уликой")
	case linkTime > p.Deadline:
		return errors.New("улика вошла в цепь позже обещанного срока")
	}
	return nil
}
