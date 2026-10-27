package proof

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"slices"

	"github.com/Nikolay1994Kaz/evidencestore/internal/auditchain"
)

// Хвосты источников (DECISIONS, п. 28): лист события 13 — для каждого
// источника номер и хэш его последнего листа улики к этому месту цепи.
//
// Пакет по источнику несёт лист хвостов целиком, поэтому источники в нём
// закрыты: метка — хэш имени, обязательство — хэш имени, номера, хэша листа и
// соли. Соль своя у каждого источника в каждом листе хвостов, её знает только
// хранилище (store: HMAC от секрета, выведенного из ключа подписи), и пакет
// раскрывает её только для своего источника: аудитор сам считает метку,
// находит её в листе ровно раз и сверяет раскрытые номер, хэш и соль с
// обязательством. Про чужие источники видно, сколько их, и имя проверяется
// подбором по словарю; номер не подобрать, даже если хэш чужого листа виден
// в пути Меркла, и обязательства одного источника в разных листах хвостов не
// сравнить — не видно, были ли у него записи. Источника без записей в листе
// нет: его цепочка начинается с нулей.

const (
	tailTagDomain    = "evidencestore/tails/source/v1"
	tailCommitDomain = "evidencestore/tails/entry/v2"
)

// Tail — последний лист улики источника к месту хвостов, открытым видом.
type Tail struct {
	Source string
	Seq    uint64   // номер его записи у источника
	Hash   [32]byte // хэш листа (auditchain.LeafHash)
	Salt   [32]byte // соль обязательства
}

// TailOpen — раскрытие хвоста своего источника в пакете.
type TailOpen struct {
	Seq  uint64 `json:"seq"`
	Leaf string `json:"leaf"` // хэш листа, hex
	Salt string `json:"salt"` // соль, hex
}

type tailEntry struct {
	Tag    string `json:"tag"`    // хэш имени, hex
	Commit string `json:"commit"` // хэш имени, номера и хэша листа, hex
}

type tailsPayload struct {
	Sources []tailEntry `json:"sources"`
}

// TailTag — метка источника в листе хвостов.
func TailTag(source string) [32]byte {
	return sha256.Sum256(append([]byte(tailTagDomain+"\x00"), source...))
}

// tailCommit — обязательство на хвост источника: имя с длиной, номер, хэш,
// соль.
func tailCommit(source string, seq uint64, hash, salt [32]byte) [32]byte {
	var buf bytes.Buffer
	buf.WriteString(tailCommitDomain)
	binary.Write(&buf, binary.BigEndian, uint32(len(source)))
	buf.WriteString(source)
	binary.Write(&buf, binary.BigEndian, seq)
	buf.Write(hash[:])
	buf.Write(salt[:])
	return sha256.Sum256(buf.Bytes())
}

// TailsLeaf — лист хвостов. Записи — по метке: порядок источников на лист
// не влияет.
func TailsLeaf(tails []Tail, unixNano int64) auditchain.Leaf {
	entries := make([]tailEntry, 0, len(tails))
	for _, t := range tails {
		tag, commit := TailTag(t.Source), tailCommit(t.Source, t.Seq, t.Hash, t.Salt)
		entries = append(entries, tailEntry{Tag: hex.EncodeToString(tag[:]), Commit: hex.EncodeToString(commit[:])})
	}
	slices.SortFunc(entries, func(a, b tailEntry) int { return bytes.Compare([]byte(a.Tag), []byte(b.Tag)) })
	payload, _ := json.Marshal(tailsPayload{Sources: entries}) // строки: ошибки нет
	return auditchain.Leaf{UnixNano: unixNano, Type: auditchain.EventTails, Payload: payload}
}

// OpenTail находит в листе хвостов свой источник и сверяет раскрытие.
// Возвращает хэш последнего листа источника; источника в листе нет —
// нули, и раскрытия быть не должно.
func OpenTail(l auditchain.Leaf, source string, open *TailOpen) ([32]byte, error) {
	if l.Type != auditchain.EventTails {
		return [32]byte{}, errors.New("not a tails leaf")
	}
	var p tailsPayload
	if err := json.Unmarshal(l.Payload, &p); err != nil {
		return [32]byte{}, fmt.Errorf("tails leaf: %w", err)
	}
	tag := TailTag(source)
	want := hex.EncodeToString(tag[:])
	var found *tailEntry
	for i, e := range p.Sources {
		if e.Tag != want {
			continue
		}
		if found != nil {
			return [32]byte{}, fmt.Errorf("the tails leaf names %s twice", source)
		}
		found = &p.Sources[i]
	}
	switch {
	case found == nil && open == nil:
		return [32]byte{}, nil
	case found == nil:
		return [32]byte{}, fmt.Errorf("the bundle opens a tail of %s, but the tails leaf does not name it", source)
	case open == nil:
		return [32]byte{}, fmt.Errorf("the tails leaf names %s, but the bundle does not open its tail", source)
	}
	h, err := hex.DecodeString(open.Leaf)
	if err != nil || len(h) != 32 {
		return [32]byte{}, errors.New("the opened tail hash does not parse")
	}
	salt, err := hex.DecodeString(open.Salt)
	if err != nil || len(salt) != 32 {
		return [32]byte{}, errors.New("the opened tail salt does not parse")
	}
	hash := [32]byte(h)
	commit := tailCommit(source, open.Seq, hash, [32]byte(salt))
	if found.Commit != hex.EncodeToString(commit[:]) {
		return [32]byte{}, fmt.Errorf("the opened tail of %s does not match the tails leaf", source)
	}
	return hash, nil
}

// TailOf — раскрытие хвоста источника для пакета (хранилище).
func TailOf(t Tail) *TailOpen {
	return &TailOpen{Seq: t.Seq, Leaf: hex.EncodeToString(t.Hash[:]), Salt: hex.EncodeToString(t.Salt[:])}
}
