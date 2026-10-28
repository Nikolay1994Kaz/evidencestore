package proof

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"strconv"
	"time"

	"github.com/Nikolay1994Kaz/evidencestore/internal/auditchain"
	"github.com/Nikolay1994Kaz/evidencestore/internal/tsa"
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
// пропускает: метка позже конца окна больше чем на WindowEdge — позже
// времени приёма любой записи окна плюс MaxPromiseMMD, — и её токен лежит
// в цепи перед такой записью (checkStamps). Величина — со сверки по времени
// звеньев: звено токена — не раньше времени метки минус ReceiveSkew
// (tokenLinkTime). Срок в обещании пишет само хранилище, поэтому
// CheckPromise держит этот предел сам, что бы ни стояло в обещании.
const MaxPromiseMMD = WindowEdge - ReceiveSkew

// CheckPromise сверяет обещание с проверенным пакетом: та же улика, та же
// позиция, время приёма, и перед уликой в цепи нет метки со временем TSA
// позже времени приёма + MaxPromiseMMD (checkStamps; пакет версии 3).
//
// Предел — минута от времени приёма, что бы ни стояло в сроке. Длиннее
// срок не пускает: на минуте держится пакет за окно, и со сроком в час
// запись, придержанная за метку, что закрывает окно, свой срок выдержала бы
// (Q-57). Короче минуты срок — слово хранилища, которое по меткам честно не
// сверить: время приёма отстаёт от времени TSA до ReceiveLag, а v0.2.0
// подписывал promise_mmd от двух тиков (Q-77). Отличить запись v0.2.0 нечем:
// формат листа пишет тот, кто кладёт запись в цепь, — запись v0.2.0,
// догнанную этим выпуском после падения или подъёма из копии, он пишет со
// ссылкой, а лист без ссылки владелец выдаст и для своей записи (Q-80).
// Хранилище этого выпуска подписывает срок от 55 с и двух тиков до минуты,
// так что сверка мягче срока не больше чем на 5 с.
// Пакеты версий 1 и 2 не принимаются: версия — неподписанное поле, и время
// звеньев в них — слово хранилища (Q-76). allowNoTSA — принять пакет без
// T1: тогда время, когда запись легла в цепь, — только слово хранилища.
func CheckPromise(p Promise, r Report, b Bundle, allowNoTSA bool) error {
	limit := p.ReceivedAt + int64(MaxPromiseMMD)
	switch {
	case p.Source != r.Header.Source || p.Seq != r.Header.Seq:
		return fmt.Errorf("the promise is about %s/%d, the bundle about %s/%d", p.Source, p.Seq, r.Header.Source, r.Header.Seq)
	case string(p.Digest) != string(r.Digest[:]):
		return errors.New("the digest in the promise does not match the record in the chain: the store replaced the record after intake")
	case p.Position != r.Position:
		return fmt.Errorf("position %d was promised, the chain has %d", p.Position, r.Position)
	case p.ReceivedAt != r.Header.ReceivedAt:
		return errors.New("the receive time in the promise does not match the record")
	case p.Deadline < p.ReceivedAt:
		return fmt.Errorf("the promised deadline %s is earlier than the receive time %s", fmtTime(time.Unix(0, p.Deadline)), fmtTime(time.Unix(0, p.ReceivedAt)))
	case b.Version < 3:
		// Версия — поле JSON, его никто не подписывает: по нему правило не
		// выбирается. Время звеньев пишет само хранилище — владелец выдал бы
		// пакет версии 1 или 2 записи, придержанной за метку, а кто угодно
		// переписал бы так честный пакет версии 3 (Q-76).
		return fmt.Errorf("the bundle is version %d and carries no leaves before the record, so the promise cannot be checked against the time-stamps; ask the store for this record's bundle again (a store of this release builds version %d for any record, older ones included)", b.Version, Version)
	case r.Lower.IsZero():
		if !allowNoTSA {
			return errors.New("the bundle has no TSA time-stamp in the chain before the record: the time the record entered the chain is the store's word alone (esverify -allow-no-tsa accepts it)")
		}
		return nil
	}
	return checkStamps(r, b, limit)
}

// checkStamps — сверка обещания по меткам (пакет версии 3): перед уликой в
// цепи нет метки со временем TSA позже limit — время приёма +
// MaxPromiseMMD. Придержанная за метку, что закрывает окно, улика лежит
// после её токена, а время той метки позже limit; честное хранилище не
// кладёт токен мимо записи, взявшей время приёма до ответа TSA (барьер), и
// время звеньев здесь не участвует. Листья звеньев от головы под T1 до звена
// улики — в пакете, корни звеньев сверяются, так что метку не спрятать.
//
// Время метки берётся из токена без проверки подписи: токены в цепь кладёт
// хранилище, проверив их до цепи, и ложный токен со временем позже limit
// обвинил бы только того, кто его положил; спрятать настоящий нельзя —
// листья сверены с корнями звеньев (Q-79).
func checkStamps(r Report, b Bundle, limit int64) error {
	links, _, err := chainLinks(b.Links)
	if err != nil {
		return err
	}
	linkAt := func(seq uint64) (auditchain.Record, bool) {
		if seq < links[0].Seq || seq > links[len(links)-1].Seq {
			return auditchain.Record{}, false
		}
		return links[seq-links[0].Seq], true
	}
	head, _ := strconv.ParseUint(b.Lower.Inclusion.Leaf.Subject, 10, 64)
	hl, ok := linkAt(head)
	if !ok {
		return fmt.Errorf("link %d, which T1 certifies, is not in the bundle", head)
	}
	hp, err := batchOf(hl)
	if err != nil {
		return err
	}
	next := hp.FirstLeaf + uint64(hp.Count)
	leaves := make([]auditchain.Leaf, len(b.Stretch))
	for i, l := range b.Stretch {
		leaves[i] = l.chain()
	}
	rec := auditchain.LeafHash(b.Inclusion.Leaf.chain())
	var worst time.Time
	var worstLink uint64
	found := false
	at := 0
	for seq := head + 1; seq <= r.LinkSeq; seq++ {
		l, ok := linkAt(seq)
		if !ok {
			return fmt.Errorf("link %d is not in the bundle", seq)
		}
		p, err := batchOf(l)
		if err != nil {
			return err
		}
		n := int(p.Count)
		switch {
		case p.FirstLeaf != next:
			return fmt.Errorf("link %d covers leaves from %d, the link before it ends at %d", seq, p.FirstLeaf, next)
		case n > len(leaves)-at:
			return fmt.Errorf("link %d holds %d leaves, the bundle has %d more: leaves are left out", seq, n, len(leaves)-at)
		case auditchain.MerkleRoot(leaves[at:at+n]) != p.Root:
			return fmt.Errorf("the leaves of link %d do not give its Merkle root: a leaf was left out, added, changed or moved", seq)
		}
		for _, lf := range leaves[at : at+n] {
			if seq == r.LinkSeq && auditchain.LeafHash(lf) == rec {
				found = true
				break
			}
			if lf.Type != auditchain.EventTimestamp {
				continue
			}
			gen, err := tsa.GenTime(lf.Payload)
			if err != nil {
				return fmt.Errorf("the time-stamp in link %d: %w", seq, err)
			}
			if gen.After(worst) {
				worst, worstLink = gen, seq
			}
		}
		at += n
		next += uint64(n)
	}
	switch {
	case !found:
		return fmt.Errorf("the record is not among the leaves of link %d", r.LinkSeq)
	case at != len(leaves):
		return fmt.Errorf("the bundle has %d leaves beyond the record's link", len(leaves)-at)
	case worst.UnixNano() > limit:
		return fmt.Errorf("the time-stamp in link %d was taken at %s, more than %s after the receive time %s, and lies before the record: the record entered the chain after the deadline that window bundles rely on, whatever deadline the promise names",
			worstLink, fmtTime(worst), MaxPromiseMMD, fmtTime(time.Unix(0, r.Header.ReceivedAt)))
	}
	return nil
}
