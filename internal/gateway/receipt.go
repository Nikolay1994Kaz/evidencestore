package gateway

// Общая квитанция шлюза — content_type "receipt/v1" (DECISIONS, п. 43).
//
// Шлюз — то, через что агент действует: MCP-сервер, платформа покупок. На
// каждый шаг действия он пишет строку JSONL и подписывает её своим ключом
// Ed25519. Строки одного шлюза сцеплены: prev — SHA-256 предыдущей строки,
// seq растёт на единицу. Хранилище при приёме проверяет подпись закреплённым
// ключом (gateway_key источника) и сцепку и кладёт вердикт в цепь рядом с
// уликой, как у журнала Pipelock. Ничего не отвергается.
//
// Подписаны ровно байты строки без поля sig. Шлюз пишет объект без sig
// (байты B, последний — «}»), подписывает "evidencestore/receipt/v1\n" ‖ B и
// дописывает подпись перед закрывающей скобкой: B без «}» + `,"sig":"<hex>"}`.
// Проверяющий отрезает этот хвост, возвращает «}» и проверяет те самые байты:
// каноническая форма JSON не нужна, а значит, и спорить о ней не с кем.
//
// В открытом вердикте — только шлюз, seq, хэши и исходы. Номер действия и
// шаг остаются в зашифрованном теле, поэтому источник квитанций метится по
// action, и пакет по одному действию не раскрывает остальных.

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

	"github.com/Nikolay1994Kaz/evidencestore/internal/evidence"
)

// ReceiptContentType — тип улики для общей квитанции шлюза.
const ReceiptContentType = "receipt/v1"

// Пределы полей квитанции.
const (
	MaxGatewayName    = 128 // имя шлюза: оно открыто в вердиктах
	MaxStep           = 64
	MaxRefs           = 64
	MaxApprovalFormat = 64
	MaxRefSource      = 255 // как имя источника хранилища
	// MaxSeq — 2^53 − 1: больше число JSON в JavaScript теряет точность, и
	// шлюз на Node и проверяющий на Go видели бы разные номера.
	MaxSeq = 1<<53 - 1
	// MaxReceiptLen — квитанция — одна запись хранилища: длиннее сборщик
	// режет строку на куски, и ни один кусок квитанцией не будет.
	MaxReceiptLen = evidence.MaxBodyLen
)

// receiptDomain отделяет подпись квитанции от других подписей тем же ключом.
const receiptDomain = "evidencestore/receipt/v1\n"

// sigPrefix и длина хвоста с подписью: `,"sig":"` + 128 hex + `"}`.
const (
	sigPrefix    = `,"sig":"`
	sigSuffixLen = len(sigPrefix) + 2*ed25519.SignatureSize + len(`"}`)
)

// receiptFields — поля квитанции v1 верхнего уровня.
var receiptFields = []string{"v", "gateway", "seq", "prev", "time", "action", "step", "refs", "approval", "body", "sig"}

// Ref — под каким субъектом то же действие записано в другом источнике
// хранилища: у базы — xid транзакции, у провайдера — номер платежа. По ним
// пакет по действию сводит источники (шаг 3, п. 42).
type Ref struct {
	Source  string `json:"source"`
	Subject string `json:"subject"`
}

// Approval — одобрение действия в том виде, в каком шлюз его получил
// (мандат покупателя, подтверждение оператора). Хранилище его не разбирает.
type Approval struct {
	Format     string `json:"format"`
	Credential string `json:"credential"`
}

// Receipt — разобранная квитанция. ParseReceipt заполняет всё, что смог
// разобрать, и при ошибке: по шлюзу, seq и prev ведётся сцепка.
type Receipt struct {
	Gateway  string
	Seq      uint64
	Prev     string
	Time     time.Time
	Action   string
	Step     string
	Refs     []Ref
	Approval *Approval
	Body     json.RawMessage // как в строке; nil — поля нет
	// Sig — подпись из хвоста строки; nil — хвоста с подписью нет.
	Sig []byte
	// Hash — SHA-256 строки (hex): его называет prev следующей квитанции.
	Hash   string
	signed []byte // B: строка без поля sig
}

// ParseReceipt разбирает строку квитанции. Ошибка — квитанция не по формату;
// поля, которые удалось разобрать, всё равно в Receipt.
func ParseReceipt(line []byte) (Receipt, error) {
	line = bytes.TrimRight(line, "\r\n")
	sum := sha256.Sum256(line)
	r := Receipt{Hash: hex.EncodeToString(sum[:])}
	if !utf8.Valid(line) {
		return r, errors.New("receipt is not valid UTF-8")
	}
	all, err := strictObject(line)
	if err != nil {
		return r, fmt.Errorf("receipt: %w", err)
	}
	var problem error
	note := func(err error) {
		if problem == nil {
			problem = err
		}
	}

	if b, sig, ok := splitSig(line); !ok {
		note(errors.New(`receipt: the line does not end with its signature, ,"sig":"<128 hex>"}`))
	} else if fields, err := strictObject(b); err != nil {
		note(fmt.Errorf("receipt without its signature: %w", err))
	} else if raw := all["sig"]; string(raw) != `"`+hex.EncodeToString(sig)+`"` || len(fields) != len(all)-1 {
		// Хвост похож на подпись, но поле sig строки — другое: подписанными
		// считались бы не те байты, что видит разборщик.
		note(errors.New("receipt: the signature at the end of the line is not its sig field"))
	} else {
		r.Sig, r.signed = sig, b
	}
	delete(all, "sig")

	for k := range all {
		if !slices.Contains(receiptFields, k) {
			// Имени поля в тексте нет: вердикт открыт навсегда.
			note(errors.New("receipt: a top-level field that receipt v1 does not have (it has v, gateway, seq, prev, time, action, step, refs, approval, body and sig)"))
			break
		}
	}
	if string(all["v"]) != "1" {
		note(errors.New(`receipt: "v" must be the number 1`))
	}
	if s, ok := evidence.JSONString(all["gateway"]); ok && validName(s, MaxGatewayName) {
		r.Gateway = s
	} else {
		note(fmt.Errorf(`receipt: "gateway" must be a string of 1 to %d letters, digits and . _ : -`, MaxGatewayName))
	}
	if n, ok := parseSeq(all["seq"]); ok {
		r.Seq = n
	} else {
		note(fmt.Errorf(`receipt: "seq" must be an integer from 1 to %d, written without sign, exponent or leading zeros`, uint64(MaxSeq)))
	}
	if s, ok := evidence.JSONString(all["prev"]); ok && (s == Genesis || isHash(s)) {
		r.Prev = s
	} else {
		note(errors.New(`receipt: "prev" must be "genesis" or 64 lowercase hex characters`))
	}
	if s, ok := evidence.JSONString(all["time"]); !ok {
		note(errors.New(`receipt: "time" must be an RFC 3339 string`))
	} else if t, err := time.Parse(time.RFC3339Nano, s); err != nil {
		note(errors.New(`receipt: "time" must be an RFC 3339 string`))
	} else {
		r.Time = t
	}
	// Номер действия — тем же разбором, каким хранилище ставит метку: иначе
	// метка и квитанция назвали бы разные действия.
	if raw := all["action"]; len(raw) > 0 && raw[0] == '"' {
		if a, ok := evidence.SubjectOf(line, "action"); ok {
			r.Action = a
		}
	}
	if r.Action == "" {
		note(fmt.Errorf(`receipt: "action" must be a string of 1 to %d bytes`, evidence.MaxSubjectLen))
	}
	if s, ok := evidence.JSONString(all["step"]); ok && validName(s, MaxStep) {
		r.Step = s
	} else {
		note(fmt.Errorf(`receipt: "step" must be a string of 1 to %d letters, digits and . _ : -`, MaxStep))
	}
	if raw, ok := all["refs"]; ok {
		refs, err := parseRefs(raw)
		if err != nil {
			note(err)
		}
		r.Refs = refs
	}
	if raw, ok := all["approval"]; ok {
		a, err := parseApproval(raw)
		if err != nil {
			note(err)
		}
		r.Approval = a
	}
	if raw, ok := all["body"]; ok {
		r.Body = raw
	}
	return r, problem
}

// Verify проверяет подпись квитанции ключом шлюза.
func (r Receipt) Verify(key ed25519.PublicKey) error {
	if r.Sig == nil {
		return errors.New("the receipt has no signature")
	}
	if len(key) != ed25519.PublicKeySize || !ed25519.Verify(key, r.message(), r.Sig) {
		return errors.New("the receipt signature does not verify with the gateway key")
	}
	return nil
}

func (r Receipt) message() []byte {
	return append([]byte(receiptDomain), r.signed...)
}

// splitSig отрезает хвост с подписью: B (строка без поля sig, с «}» на
// конце) и сама подпись. ok == false — строка кончается не подписью.
func splitSig(line []byte) (b, sig []byte, ok bool) {
	n := len(line)
	if n < sigSuffixLen+2 {
		return nil, nil, false
	}
	tail := line[n-sigSuffixLen:]
	if !bytes.HasPrefix(tail, []byte(sigPrefix)) || !bytes.HasSuffix(tail, []byte(`"}`)) {
		return nil, nil, false
	}
	h := string(tail[len(sigPrefix) : len(tail)-2])
	if !isLowerHex(h) {
		return nil, nil, false
	}
	sig, _ = hex.DecodeString(h)
	b = append(bytes.Clone(line[:n-sigSuffixLen]), '}')
	return b, sig, true
}

// strictObject разбирает объект JSON верхнего уровня: ключ дважды — ошибка
// (и после свёртки регистра: encoding/json не различает «step» и «STEP», а
// Python и jq различают), после «}» — ничего, кроме пробелов.
func strictObject(raw []byte) (map[string]json.RawMessage, error) {
	dec := json.NewDecoder(bytes.NewReader(raw))
	if t, err := dec.Token(); err != nil || t != json.Delim('{') {
		return nil, errors.New("not a JSON object")
	}
	m := map[string]json.RawMessage{}
	seen := map[string]bool{}
	for dec.More() {
		t, err := dec.Token()
		if err != nil {
			return nil, err
		}
		k, _ := t.(string)
		f := foldKey(k)
		if seen[f] {
			return nil, errors.New("a key appears twice")
		}
		seen[f] = true
		var v json.RawMessage
		if err := dec.Decode(&v); err != nil {
			return nil, err
		}
		m[k] = v
	}
	if _, err := dec.Token(); err != nil {
		return nil, err
	}
	if _, err := dec.Token(); err != io.EOF {
		return nil, errors.New("data after the object")
	}
	return m, nil
}

func parseSeq(raw json.RawMessage) (uint64, bool) {
	s := string(raw)
	if s == "" || s[0] < '1' || s[0] > '9' || strings.Trim(s, "0123456789") != "" {
		return 0, false
	}
	n, err := strconv.ParseUint(s, 10, 64)
	return n, err == nil && n <= MaxSeq
}

func parseRefs(raw json.RawMessage) ([]Ref, error) {
	bad := fmt.Errorf(`receipt: "refs" must be an array of at most %d objects {"source": …, "subject": …}`, MaxRefs)
	var items []json.RawMessage
	if len(raw) == 0 || raw[0] != '[' || json.Unmarshal(raw, &items) != nil || len(items) > MaxRefs {
		return nil, bad
	}
	refs := make([]Ref, 0, len(items))
	for _, it := range items {
		m, err := strictObject(it)
		if err != nil || len(m) != 2 {
			return refs, bad
		}
		src, ok1 := evidence.JSONString(m["source"])
		sub, ok2 := evidence.JSONString(m["subject"])
		if !ok1 || !ok2 || src == "" || len(src) > MaxRefSource || strings.ContainsAny(src, "/\x00") ||
			sub == "" || len(sub) > evidence.MaxSubjectLen {
			return refs, fmt.Errorf(`receipt: a ref names a source (1 to %d bytes, no '/') and a subject (1 to %d bytes)`, MaxRefSource, evidence.MaxSubjectLen)
		}
		refs = append(refs, Ref{Source: src, Subject: sub})
	}
	return refs, nil
}

func parseApproval(raw json.RawMessage) (*Approval, error) {
	bad := fmt.Errorf(`receipt: "approval" must be {"format": 1 to %d letters, digits and . _ : -, "credential": a non-empty string}`, MaxApprovalFormat)
	m, err := strictObject(raw)
	if err != nil || len(m) != 2 {
		return nil, bad
	}
	f, ok1 := evidence.JSONString(m["format"])
	c, ok2 := evidence.JSONString(m["credential"])
	if !ok1 || !ok2 || !validName(f, MaxApprovalFormat) || c == "" {
		return nil, bad
	}
	return &Approval{Format: f, Credential: c}, nil
}

// validName — от 1 до max байт из латиницы, цифр и . _ : -.
func validName(s string, max int) bool {
	if s == "" || len(s) > max {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || strings.IndexByte("._:-", c) >= 0) {
			return false
		}
	}
	return true
}

func isLowerHex(s string) bool {
	for i := 0; i < len(s); i++ {
		if !(s[i] >= '0' && s[i] <= '9' || s[i] >= 'a' && s[i] <= 'f') {
			return false
		}
	}
	return true
}

func isHash(s string) bool { return len(s) == 2*sha256.Size && isLowerHex(s) }

// ReceiptTracker следит за цепочками квитанций одного источника: какая
// квитанция каждого шлюза принята последней. Строки подаются в порядке
// приёма.
type ReceiptTracker struct {
	key  ed25519.PublicKey
	last map[string]receiptLink // шлюз → последняя принятая квитанция
}

type receiptLink struct {
	hash string
	seq  uint64
}

// NewReceiptTracker — key nil: подписи не проверяются (SigNoKey). Хранилище
// так не делает: у источника квитанций gateway_key обязателен.
func NewReceiptTracker(key ed25519.PublicKey) *ReceiptTracker {
	return &ReceiptTracker{key: key, last: map[string]receiptLink{}}
}

// Check проверяет очередную квитанцию и двигает состояние её цепочки.
func (t *ReceiptTracker) Check(line []byte) Verdict {
	r, err := ParseReceipt(line)
	v := Verdict{Seq: r.Seq, Writer: r.Gateway, Hash: r.Hash, PrevHash: r.Prev, HashOK: true}
	if err != nil {
		v.Problem = err.Error()
	}
	switch {
	case r.Sig == nil:
		v.Signature = SigInvalid
	case t.key == nil:
		v.Signature = SigNoKey
	case r.Verify(t.key) == nil:
		v.Signature = SigValid
	default:
		v.Signature = SigInvalid
		if v.Problem == "" {
			v.Problem = "the receipt signature does not verify with the pinned gateway key"
		}
	}
	if r.Gateway == "" || r.Seq == 0 || r.Prev == "" {
		// Чья это цепочка, не назвать: состояние не двигается.
		return v
	}
	last, seen := t.last[r.Gateway]
	defer func() {
		// Состояние двигается и после поломки сцепки: одна выпавшая квитанция —
		// одна поломка, а не каскад до конца цепочки. Но не после чужой
		// подписи: такую строку написал не шлюз, в его цепочке её нет, и
		// подделка не должна ломать следующую настоящую квитанцию.
		if v.Signature != SigInvalid {
			t.last[r.Gateway] = receiptLink{hash: r.Hash, seq: r.Seq}
		}
	}()
	switch {
	case !seen && r.Prev == Genesis:
		v.Link = LinkGenesis
		if r.Seq != 1 && v.Problem == "" {
			v.Problem = fmt.Sprintf("a new gateway chain starts at seq %d, not 1", r.Seq)
		}
	case !seen:
		v.Link = LinkFirstSeen
	case r.Prev == last.hash && r.Seq == last.seq+1:
		v.Link = LinkOK
	default:
		v.Link = LinkBroken
		if v.Problem == "" {
			v.Problem = linkProblem(r, last)
		}
	}
	return v
}

func linkProblem(r Receipt, last receiptLink) string {
	switch {
	case r.Prev == Genesis:
		return fmt.Sprintf("the gateway started a new chain at seq %d after seq %d: receipts after seq %d may be lost", r.Seq, last.seq, last.seq)
	case r.Prev == last.hash:
		return fmt.Sprintf("seq %d follows seq %d", r.Seq, last.seq)
	}
	return fmt.Sprintf("prev does not match the previous receipt of this gateway (seq %d): receipts are missing, reordered or replaced", last.seq)
}

// Resume восстанавливает состояние по вердикту, записанному раньше (из цепи
// после рестарта). Условие — то же, при котором Check двигает состояние
// (MovesChain).
func (t *ReceiptTracker) Resume(v Verdict) {
	if MovesChain(v) {
		t.last[v.Writer] = receiptLink{hash: v.Hash, seq: v.Seq}
	}
}

// MovesChain — квитанция с этим вердиктом стала последней в цепочке своего
// шлюза: цепочка названа, и подпись не чужая. Так же считает проверка пакета
// по источнику.
func MovesChain(v Verdict) bool {
	return v.Writer != "" && v.Seq != 0 && v.PrevHash != "" && v.Signature != SigInvalid
}

// Signer ведёт цепочку квитанций одного шлюза и подписывает их.
type Signer struct {
	mu      sync.Mutex
	key     ed25519.PrivateKey
	gateway string
	next    uint64
	prev    string
}

// NewSigner — last: последняя строка цепочки этого шлюза, написанная раньше
// (пусто — цепочка новая). Строка должна быть его и с верной подписью: чужая
// цепочка в том же файле — ошибка настройки, а не повод начать свою.
func NewSigner(key ed25519.PrivateKey, gateway string, last []byte) (*Signer, error) {
	if len(key) != ed25519.PrivateKeySize {
		return nil, errors.New("gateway: not an Ed25519 private key")
	}
	if !validName(gateway, MaxGatewayName) {
		return nil, fmt.Errorf("gateway: the gateway name must be 1 to %d letters, digits and . _ : -", MaxGatewayName)
	}
	s := &Signer{key: key, gateway: gateway, next: 1, prev: Genesis}
	if len(bytes.TrimSpace(last)) == 0 {
		return s, nil
	}
	r, err := ParseReceipt(last)
	switch {
	case err != nil:
		return nil, fmt.Errorf("gateway: the last receipt: %w", err)
	case r.Gateway != gateway:
		return nil, fmt.Errorf("gateway: the last receipt is of gateway %q, not %q", r.Gateway, gateway)
	case r.Seq >= MaxSeq:
		return nil, fmt.Errorf("gateway: the chain has reached seq %d", r.Seq)
	}
	if err := r.Verify(key.Public().(ed25519.PublicKey)); err != nil {
		return nil, fmt.Errorf("gateway: the last receipt: %w", err)
	}
	s.next, s.prev = r.Seq+1, r.Hash
	return s, nil
}

// Draft — шаг действия, как его знает шлюз. Номер, сцепку и подпись ставит
// Signer.
type Draft struct {
	Time     time.Time // ноль — сейчас
	Action   string
	Step     string
	Refs     []Ref
	Approval *Approval
	Body     json.RawMessage
}

// Sign — строка квитанции, без перевода строки. Цепочка двигается, только
// если строка вышла верной: её проверяет тот же ParseReceipt, что и приём.
// Записать строку — дело шлюза: на диск до действия, о котором она.
func (s *Signer) Sign(d Draft) ([]byte, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.next > MaxSeq {
		return nil, fmt.Errorf("gateway: the chain has reached seq %d", uint64(MaxSeq))
	}
	if d.Time.IsZero() {
		d.Time = time.Now()
	}
	out := struct {
		V        int             `json:"v"`
		Gateway  string          `json:"gateway"`
		Seq      uint64          `json:"seq"`
		Prev     string          `json:"prev"`
		Time     string          `json:"time"`
		Action   string          `json:"action"`
		Step     string          `json:"step"`
		Refs     []Ref           `json:"refs,omitempty"`
		Approval *Approval       `json:"approval,omitempty"`
		Body     json.RawMessage `json:"body,omitempty"`
	}{1, s.gateway, s.next, s.prev, d.Time.UTC().Format(time.RFC3339Nano), d.Action, d.Step, d.Refs, d.Approval, d.Body}
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(out); err != nil {
		return nil, fmt.Errorf("gateway: receipt: %w", err)
	}
	b := bytes.TrimRight(buf.Bytes(), "\n")
	sig := ed25519.Sign(s.key, append([]byte(receiptDomain), b...))
	line := append(bytes.Clone(b[:len(b)-1]), sigPrefix...)
	line = append(line, hex.EncodeToString(sig)...)
	line = append(line, `"}`...)
	if len(line) > MaxReceiptLen {
		return nil, fmt.Errorf("gateway: the receipt is %d bytes, longer than a store record (%d): keep a large payload elsewhere and put its SHA-256 into the body", len(line), MaxReceiptLen)
	}
	r, err := ParseReceipt(line)
	if err != nil {
		return nil, fmt.Errorf("gateway: %w", err)
	}
	if err := r.Verify(s.key.Public().(ed25519.PublicKey)); err != nil {
		return nil, fmt.Errorf("gateway: %w", err)
	}
	s.next, s.prev = s.next+1, r.Hash
	return line, nil
}

// Checker — проверка журнала гейтвея при приёме: бортовой журнал Pipelock
// или общая квитанция.
type Checker interface {
	Check(line []byte) Verdict
	Resume(v Verdict)
}

// Verified — записи этого вида проверяются при приёме, и у каждой в цепи
// лежит вердикт хранилища.
func Verified(contentType string) bool {
	return contentType == ContentType || contentType == ReceiptContentType
}

// NewChecker — проверка для вида contentType; nil — вид не проверяется.
func NewChecker(contentType string, key ed25519.PublicKey) Checker {
	switch contentType {
	case ContentType:
		return NewTracker(key)
	case ReceiptContentType:
		return NewReceiptTracker(key)
	}
	return nil
}
