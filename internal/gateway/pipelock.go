// Package gateway проверяет журналы гейтвеев агентов при приёме. Сейчас —
// бортовой журнал Pipelock (flight recorder): JSONL, где каждая запись
// сцеплена с предыдущей хэшем, а контрольные точки подписаны ключом гейтвея.
//
// Хэш записи повторяет замороженные проекции Pipelock (internal/recorder,
// ComputeHash): SHA-256 по полям, разделённым нулевым байтом, порядок полей
// свой у версий 1, 2 и 3. detail хэшируется теми байтами, что лежат в
// строке журнала, без перекодирования: иначе меняется порядок ключей и
// верная цепочка выглядит битой. Подпись контрольной точки — Ed25519 над
// prev_hash самой контрольной точки (состояние цепочки перед ней).
//
// Проверка ничего не отвергает: улика принимается как пришла, а вердикт
// ложится в цепь рядом с ней. Лживый или битый источник записывается
// честно, и это видно.
package gateway

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"
)

// ContentType — тип улики для строк бортового журнала Pipelock.
const ContentType = "pipelock/recorder"

// Genesis — prev_hash первой записи цепочки.
const Genesis = "genesis"

// Entry — запись бортового журнала с полями, которые входят в хэш.
type Entry struct {
	Version          int
	Seq              uint64
	Timestamp        time.Time
	SessionID        string
	ChainKind        string
	WriterInstanceID string
	TraceID          string
	Type             string
	EventKind        string
	Transport        string
	Summary          string
	Detail           json.RawMessage // байты из строки, как есть
	RawRef           string
	PrevHash         string
	Hash             string
}

// wire — строка журнала. Поля, которых нет в хэше, не разбираются.
type wire struct {
	Version          int             `json:"v"`
	Seq              uint64          `json:"seq"`
	Timestamp        time.Time       `json:"ts"`
	SessionID        string          `json:"session_id"`
	ChainKind        string          `json:"chain_kind"`
	WriterInstanceID string          `json:"writer_instance_id"`
	TraceID          string          `json:"trace_id"`
	Type             string          `json:"type"`
	EventKind        string          `json:"event_kind"`
	Transport        string          `json:"transport"`
	Summary          string          `json:"summary"`
	Detail           json.RawMessage `json:"detail"`
	RawRef           string          `json:"raw_ref"`
	PrevHash         string          `json:"prev_hash"`
	Hash             string          `json:"hash"`
}

// ParseEntry разбирает строку журнала. Повтор ключа — ошибка: разные
// разборщики взяли бы разные значения, и хэш проверялся бы не над тем, что
// увидит другой.
func ParseEntry(line []byte) (Entry, error) {
	line = bytes.TrimRight(line, "\r\n")
	if err := noDuplicateKeys(line); err != nil {
		return Entry{}, err
	}
	var w wire
	if err := json.Unmarshal(line, &w); err != nil {
		return Entry{}, fmt.Errorf("gateway: entry: %w", err)
	}
	e := Entry(w)
	if e.Detail == nil {
		e.Detail = json.RawMessage("null")
	}
	return e, nil
}

func noDuplicateKeys(line []byte) error {
	dec := json.NewDecoder(bytes.NewReader(line))
	if t, err := dec.Token(); err != nil || t != json.Delim('{') {
		return errors.New("gateway: entry is not a JSON object")
	}
	seen := map[string]bool{}
	for dec.More() {
		t, err := dec.Token()
		if err != nil {
			return fmt.Errorf("gateway: entry: %w", err)
		}
		k, _ := t.(string)
		if seen[k] {
			return fmt.Errorf("gateway: entry: duplicate key %q", k)
		}
		seen[k] = true
		var skip json.RawMessage
		if err := dec.Decode(&skip); err != nil {
			return fmt.Errorf("gateway: entry: %w", err)
		}
	}
	return nil
}

// fields — проекция записи для хэша в порядке её версии. ok == false —
// версия неизвестна.
func (e Entry) fields() ([]string, bool) {
	head := []string{
		strconv.Itoa(e.Version),
		strconv.FormatUint(e.Seq, 10),
		e.Timestamp.UTC().Format(time.RFC3339Nano),
		e.SessionID,
	}
	tail := []string{e.Transport, e.Summary, string(e.Detail), e.RawRef, e.PrevHash}
	switch e.Version {
	case 1:
		return append(append(head, e.TraceID, e.Type), tail...), true
	case 2:
		return append(append(head, e.TraceID, e.Type, e.EventKind), tail...), true
	case 3:
		return append(append(head, e.ChainKind, e.WriterInstanceID, e.TraceID, e.Type, e.EventKind), tail...), true
	}
	return nil, false
}

// ComputeHash — хэш записи по проекции её версии.
func (e Entry) ComputeHash() (string, error) {
	fields, ok := e.fields()
	if !ok {
		return "", fmt.Errorf("gateway: unsupported entry version %d", e.Version)
	}
	h := sha256.New()
	for i, f := range fields {
		if i > 0 {
			h.Write([]byte{0})
		}
		h.Write([]byte(f))
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

// schemaProblem — то, что Pipelock сам отвергает при чтении: нулевой байт
// внутри поля делает проекцию неоднозначной; поля пространства цепочек
// есть только у версии 3 и там обязательны.
func (e Entry) schemaProblem() string {
	fields := map[string]string{
		"session_id": e.SessionID, "trace_id": e.TraceID, "type": e.Type,
		"transport": e.Transport, "summary": e.Summary, "raw_ref": e.RawRef,
		"prev_hash": e.PrevHash, "event_kind": e.EventKind,
		"chain_kind": e.ChainKind, "writer_instance_id": e.WriterInstanceID,
	}
	for name, v := range fields {
		if strings.ContainsRune(v, 0) {
			return name + " contains NUL"
		}
	}
	if e.Version == 3 && (e.ChainKind == "" || e.WriterInstanceID == "") {
		return "v3 entry without chain_kind or writer_instance_id"
	}
	if e.Version < 3 && (e.ChainKind != "" || e.WriterInstanceID != "") {
		return "legacy entry carries v3 namespace fields"
	}
	return ""
}

// namespace — какой цепочке принадлежит запись: у одного писателя своя.
func (e Entry) namespace() string {
	return e.SessionID + "\x00" + e.ChainKind + "\x00" + e.WriterInstanceID
}

// checkpointSignature — подпись из detail контрольной точки.
func (e Entry) checkpointSignature() ([]byte, error) {
	var d struct {
		Signature string `json:"signature"`
	}
	if err := json.Unmarshal(e.Detail, &d); err != nil {
		return nil, fmt.Errorf("checkpoint detail: %w", err)
	}
	if d.Signature == "" {
		return nil, errors.New("checkpoint without signature")
	}
	sig, err := hex.DecodeString(d.Signature)
	if err != nil || len(sig) != ed25519.SignatureSize {
		return nil, errors.New("checkpoint signature is not 64 bytes of hex")
	}
	return sig, nil
}

// Исходы сцепки.
const (
	LinkGenesis   = "genesis"    // первая запись цепочки
	LinkOK        = "linked"     // prev_hash = hash предыдущей принятой записи
	LinkFirstSeen = "first-seen" // цепочка началась не с нас: предыдущих записей мы не получали
	LinkBroken    = "broken"     // prev_hash не совпал: записи пропали, переставлены или подменены
)

// Исходы подписи контрольной точки.
const (
	SigValid   = "valid"
	SigInvalid = "invalid"
	SigNoKey   = "no-key" // ключ гейтвея не закреплён в реестре источников
)

// Verdict — что хранилище увидело в записи при приёме. Ложится в цепь
// листом рядом с уликой: открытые поля цепочки гейтвея (seq, hash,
// prev_hash) остаются проверяемыми и после уничтожения ключа месяца.
type Verdict struct {
	Seq       uint64 `json:"seq"`
	Session   string `json:"session,omitempty"`
	ChainKind string `json:"chain_kind,omitempty"`
	Writer    string `json:"writer,omitempty"`
	Type      string `json:"type,omitempty"`
	Hash      string `json:"hash,omitempty"`
	PrevHash  string `json:"prev_hash,omitempty"`
	HashOK    bool   `json:"hash_ok"`
	Link      string `json:"link,omitempty"`
	// Signature — исход проверки подписи контрольной точки; Sig — сама
	// подпись (hex), чтобы проверяющий проверил её своим ключом.
	Signature string `json:"signature,omitempty"`
	Sig       string `json:"sig,omitempty"`
	Problem   string `json:"problem,omitempty"`
}

// Clean — запись цела: хэш сошёлся, сцепка не разорвана, подпись (если
// это контрольная точка и ключ закреплён) верна.
func (v Verdict) Clean() bool {
	return v.Problem == "" && v.HashOK && v.Link != LinkBroken && v.Signature != SigInvalid
}

// Namespace — цепочка, которой принадлежит запись (сессия и писатель).
func (v Verdict) Namespace() string {
	return v.Session + "\x00" + v.ChainKind + "\x00" + v.Writer
}

// Tracker следит за цепочками одного источника: какой хэш принят последним
// в каждой. Записи подаются в порядке приёма.
type Tracker struct {
	key  ed25519.PublicKey
	last map[string]string // пространство цепочки → hash последней записи
}

// NewTracker — key nil: подписи контрольных точек не проверяются (SigNoKey).
func NewTracker(key ed25519.PublicKey) *Tracker {
	return &Tracker{key: key, last: map[string]string{}}
}

// Check проверяет очередную запись и двигает состояние цепочки.
func (t *Tracker) Check(line []byte) Verdict {
	e, err := ParseEntry(line)
	if err != nil {
		return Verdict{Problem: err.Error()}
	}
	v := Verdict{
		Seq: e.Seq, Session: e.SessionID, ChainKind: e.ChainKind, Writer: e.WriterInstanceID,
		Type: e.Type, Hash: e.Hash, PrevHash: e.PrevHash,
	}
	if p := e.schemaProblem(); p != "" {
		v.Problem = p
	} else if h, err := e.ComputeHash(); err != nil {
		v.Problem = err.Error()
	} else {
		v.HashOK = h == e.Hash
		if !v.HashOK {
			v.Problem = "hash does not match the entry"
		}
	}
	prev, seen := t.last[e.namespace()]
	switch {
	case e.PrevHash == Genesis && !seen:
		v.Link = LinkGenesis
	case !seen:
		v.Link = LinkFirstSeen
	case e.PrevHash == prev:
		v.Link = LinkOK
	default:
		v.Link = LinkBroken
	}
	// Состояние двигается и после поломки: один битый лист — одна ошибка, а
	// не каскад «разорвано» до конца цепочки.
	t.last[e.namespace()] = e.Hash
	if e.Type == "checkpoint" {
		t.checkpoint(e, &v)
	}
	return v
}

func (t *Tracker) checkpoint(e Entry, v *Verdict) {
	sig, err := e.checkpointSignature()
	if err != nil {
		v.Signature = SigInvalid
		if v.Problem == "" {
			v.Problem = err.Error()
		}
		return
	}
	v.Sig = hex.EncodeToString(sig)
	switch {
	case t.key == nil:
		v.Signature = SigNoKey
	case ed25519.Verify(t.key, []byte(e.PrevHash), sig):
		v.Signature = SigValid
	default:
		v.Signature = SigInvalid
		if v.Problem == "" {
			v.Problem = "checkpoint signature does not verify with the pinned gateway key"
		}
	}
}

// Resume восстанавливает состояние по вердикту, записанному раньше (из
// цепи после рестарта).
func (t *Tracker) Resume(v Verdict) {
	if v.Hash != "" {
		t.last[v.Namespace()] = v.Hash
	}
}

// VerifyCheckpoint проверяет подпись контрольной точки ключом
// проверяющего — без доверия к хранилищу.
func VerifyCheckpoint(key ed25519.PublicKey, v Verdict) error {
	if v.Type != "checkpoint" || v.Sig == "" {
		return errors.New("gateway: not a signed checkpoint")
	}
	sig, err := hex.DecodeString(v.Sig)
	if err != nil {
		return fmt.Errorf("gateway: checkpoint signature: %w", err)
	}
	if !ed25519.Verify(key, []byte(v.PrevHash), sig) {
		return errors.New("gateway: checkpoint signature does not verify")
	}
	return nil
}

// ParseKey разбирает открытый ключ гейтвея: 64 hex-символа.
func ParseKey(s string) (ed25519.PublicKey, error) {
	b, err := hex.DecodeString(strings.TrimSpace(s))
	if err != nil || len(b) != ed25519.PublicKeySize {
		return nil, errors.New("gateway: key must be 64 hex characters (Ed25519 public key)")
	}
	return ed25519.PublicKey(b), nil
}
