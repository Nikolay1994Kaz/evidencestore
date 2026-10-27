package proof

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"strconv"
	"time"
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

// MaxPromiseMMD — наибольший срок обещания (chain.promise_mmd), при котором
// запись из окна, придержанная за метку, что закрывает окно, срок
// пропускает: метка позже конца окна больше чем на WindowEdge, звено её
// токена — не раньше её времени минус ReceiveSkew (tokenLinkTime), и всё,
// что за ним, легло в цепь позже срока любой записи окна.
const MaxPromiseMMD = WindowEdge - ReceiveSkew

// CheckPromise сверяет обещание с проверенным пакетом: та же улика, та же
// позиция, звено улики не позже срока по часам хранилища.
//
// Время звена пишет само хранилище, поэтому берётся самое позднее время
// звеньев от звена после головы, которую заверила T1, до звена улики:
// звено легло в цепь не раньше любого прежнего. Если улику придержали за
// метку, что закрывает окно, звено её токена — в этом счёте: голова T1
// раньше него, либо T1 взята после него, и тогда её собственное звено не
// раньше её времени минус ReceiveSkew. Снизу время звена с токеном держит
// tokenLinkTime: самое позднее время выйдет за срок (Q-33). Не от звена
// токена T1: лист токена можно положить в цепь ещё раз или придержать
// токен — в конец живой цепи, прямо перед придержанной записью, — и звено
// закрывающего токена осталось бы до него (Q-47). Звено токена задним
// числом выдаст любой пакет, где этот токен виден, — пакет за окно, по
// источнику, пакет улики с этой меткой как T1. Сама голова T1 не в счёт:
// это звено хвостов перед запросом, и у первой метки после старта его
// время — часы хоста как есть; звенья между ней и токеном хранилище при
// первой метке не сворачивает (store.stampOnce). allowNoTSA — принять
// пакет без T1: тогда время звена — только слово хранилища.
func CheckPromise(p Promise, r Report, b Bundle, allowNoTSA bool) error {
	from := r.LinkSeq
	if b.Lower != nil && !r.Lower.IsZero() {
		// Голова уже сверена checkLower: она в пакете и раньше токена.
		head, _ := strconv.ParseUint(b.Lower.Inclusion.Leaf.Subject, 10, 64)
		from = head + 1
	}
	entered, at := int64(0), uint64(0)
	for _, l := range b.Links {
		if l.Seq >= from && l.Seq <= r.LinkSeq && (at == 0 || l.UnixNano > entered) {
			entered, at = l.UnixNano, l.Seq
		}
	}
	switch {
	case p.Source != r.Header.Source || p.Seq != r.Header.Seq:
		return fmt.Errorf("the promise is about %s/%d, the bundle about %s/%d", p.Source, p.Seq, r.Header.Source, r.Header.Seq)
	case string(p.Digest) != string(r.Digest[:]):
		return errors.New("the digest in the promise does not match the record in the chain: the store replaced the record after intake")
	case p.Position != r.Position:
		return fmt.Errorf("position %d was promised, the chain has %d", p.Position, r.Position)
	case p.ReceivedAt != r.Header.ReceivedAt:
		return errors.New("the receive time in the promise does not match the record")
	case r.Lower.IsZero() && !allowNoTSA:
		return errors.New("the bundle has no TSA time-stamp in the chain before the record: the time the record entered the chain is the store's word alone (esverify -allow-no-tsa accepts it)")
	case at == 0:
		return fmt.Errorf("link %d, which holds the record, is not in the bundle", r.LinkSeq)
	case entered > p.Deadline:
		return fmt.Errorf("the record entered the chain after the promised deadline %s: link %d, at or before the record's link %d, carries the time %s",
			fmtTime(time.Unix(0, p.Deadline)), at, r.LinkSeq, fmtTime(time.Unix(0, entered)))
	}
	return nil
}
