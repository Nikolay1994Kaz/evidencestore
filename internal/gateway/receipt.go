package gateway

// Общая квитанция шлюза — content_type "receipt/v2" (DECISIONS, п. 43 и 47).
//
// Шлюз — то, через что агент действует: MCP-сервер, платформа покупок. На
// каждый шаг действия он пишет строку JSONL и подписывает её своим ключом.
// Строки одного шлюза сцеплены: prev — SHA-256 предыдущей строки, seq растёт
// на единицу. Хранилище при приёме проверяет подпись ключом источника,
// который квитанция называет (gateway_keys), его срок и сцепку и кладёт
// вердикт в цепь рядом с уликой, как у журнала Pipelock. Ничего не
// отвергается.
//
// Подпись — отсоединённый JWS (RFC 7515, приложение F) последним полем
// строки. Шлюз пишет объект без поля jws (байты B, последний — «}»), считает
// обычный JWS с телом B — подписывает ASCII(P) ‖ "." ‖ BASE64URL(B), где P —
// защищённый заголовок в base64url, — и дописывает перед закрывающей скобкой
// заголовок и подпись без тела: B без «}» + `,"jws":"P..S"}`. Проверяющий
// отрезает этот хвост, возвращает «}» и получает компактный JWS P.BASE64URL(B).S,
// который проверит любая библиотека JOSE. Подписаны те самые байты, что в
// строке: каноническая форма JSON не нужна, а значит, и спорить о ней не с
// кем. В заголовке — alg (алгоритм), kid (каким ключом, KeyID) и typ: он
// отделяет подпись квитанции от других подписей тем же ключом.
//
// В открытом вердикте — только шлюз, seq, хэши и исходы. Номер действия и
// шаг остаются в зашифрованном теле, поэтому источник квитанций метится по
// action, и пакет по одному действию не раскрывает остальных.

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
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
const ReceiptContentType = "receipt/v2"

// ReceiptVersion — поле v квитанции.
const ReceiptVersion = 2

// Пределы полей квитанции.
const (
	MaxGatewayName    = 128 // имя шлюза: оно открыто в вердиктах
	MaxStep           = 64
	MaxRefs           = 64
	MaxApprovalFormat = 64
	MaxKeyID          = 128 // kid в заголовке подписи: он открыт в вердиктах
	MaxRefSource      = 255 // как имя источника хранилища
	// MaxSeq — 2^53 − 1: больше число JSON в JavaScript теряет точность, и
	// шлюз на Node и проверяющий на Go видели бы разные номера.
	MaxSeq = 1<<53 - 1
	// MaxReceiptLen — квитанция — одна запись хранилища: длиннее сборщик
	// режет строку на куски, и ни один кусок квитанцией не будет.
	MaxReceiptLen = evidence.MaxBodyLen
)

// ReceiptType — typ защищённого заголовка подписи. Он отделяет подпись
// квитанции от других подписей тем же ключом (явный тип, RFC 8725, 3.11):
// JWS с другим typ квитанцией не станет.
const ReceiptType = "vnd.evidencestore.receipt+jws"

// Алгоритмы подписи квитанции, имена JOSE. Ed25519 — полное имя по RFC 9864;
// EdDSA (RFC 8037) — прежнее имя того же алгоритма, с ключом Ed25519: его ещё
// пишут библиотеки. Подписывает Signer первым, принимаются оба. Другой
// алгоритм — новое имя здесь, а не новый формат.
const (
	AlgEd25519 = "Ed25519"
	AlgEdDSA   = "EdDSA"
)

// jwsPrefix — начало хвоста с подписью: `,"jws":"P..S"}`. MaxJWS — предел
// длины хвоста: дальше от конца строки его начало не ищут. Хватает заголовку
// и подписи любого алгоритма, какой здесь может появиться (у ML-DSA-87
// подпись — 4627 байт).
const (
	jwsPrefix = `,"jws":"`
	MaxJWS    = 16 << 10
)

// receiptFields — поля квитанции v2 верхнего уровня.
var receiptFields = []string{"v", "gateway", "seq", "prev", "time", "action", "step", "refs", "approval", "body", "jws"}

var errNoSignature = errors.New("the receipt has no signature")

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
	// Alg и Kid — алгоритм и имя ключа из заголовка подписи (KeyID). Sig —
	// сама подпись; nil — хвоста с подписью нет или его заголовок не годится.
	Alg string
	Kid string
	Sig []byte
	// Hash — SHA-256 строки (hex): его называет prev следующей квитанции.
	Hash      string
	signed    []byte // B: строка без поля jws
	protected string // защищённый заголовок подписи, base64url, как в строке
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
	if loneSurrogate(line) {
		return r, errors.New(`receipt: a half of a surrogate pair is escaped alone (\ud800 without its pair): parsers read it differently`)
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

	if b, protected, sig, ok := splitJWS(line); !ok {
		note(errors.New(`receipt: the line does not end with its signature, ,"jws":"<protected header>..<signature>"} (a detached JWS, base64url without padding)`))
	} else if fields, err := strictObject(b); err != nil {
		note(fmt.Errorf("receipt without its signature: %w", err))
	} else if raw := all["jws"]; string(raw) != `"`+protected+".."+base64.RawURLEncoding.EncodeToString(sig)+`"` || len(fields) != len(all)-1 {
		// Хвост похож на подпись, но поле jws строки — другое: подписанными
		// считались бы не те байты, что видит разборщик.
		note(errors.New("receipt: the signature at the end of the line is not its jws field"))
	} else if alg, kid, err := parseProtected(protected); err != nil {
		// Имя ключа и алгоритм остаются в Receipt: вердикт называет, чем
		// строка подписана, и когда проверить подпись нельзя.
		r.Alg, r.Kid = alg, kid
		note(err)
	} else if len(sig) != ed25519.SignatureSize {
		r.Alg, r.Kid = alg, kid
		note(fmt.Errorf("receipt: an %s signature is %d bytes, this one is %d", alg, ed25519.SignatureSize, len(sig)))
	} else {
		r.Alg, r.Kid, r.Sig, r.signed, r.protected = alg, kid, sig, b, protected
	}
	delete(all, "jws")

	for k := range all {
		if !slices.Contains(receiptFields, k) {
			// Имени поля в тексте нет: вердикт открыт навсегда.
			note(errors.New("receipt: a top-level field that receipt v2 does not have (it has v, gateway, seq, prev, time, action, step, refs, approval, body and jws)"))
			break
		}
	}
	if string(all["v"]) != strconv.Itoa(ReceiptVersion) {
		note(fmt.Errorf(`receipt: "v" must be the number %d`, ReceiptVersion))
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

// loneSurrogate — в строке JSON половина суррогатной пары экранирована одна
// (\ud800 без пары): Go прочтёт её как U+FFFD, Python — как одиночный
// суррогат, и одно подписанное тело читается двумя способами. Наверху, в refs
// и approval таких строк нет (имена — ASCII), а body свободно (R1-4).
func loneSurrogate(b []byte) bool {
	in := false
	for i := 0; i < len(b); i++ {
		c := b[i]
		if !in {
			in = c == '"'
			continue
		}
		switch c {
		case '"':
			in = false
		case '\\':
			if i+1 >= len(b) {
				return false
			}
			if b[i+1] != 'u' {
				i++
				continue
			}
			v, ok := hex4(b, i+2)
			switch {
			case !ok:
				return false // не JSON: скажет strictObject
			case v >= 0xD800 && v <= 0xDBFF:
				if i+11 >= len(b) || b[i+6] != '\\' || b[i+7] != 'u' {
					return true
				}
				if lo, ok := hex4(b, i+8); !ok || lo < 0xDC00 || lo > 0xDFFF {
					return true
				}
				i += 11
			case v >= 0xDC00 && v <= 0xDFFF:
				return true
			default:
				i += 5
			}
		}
	}
	return false
}

func hex4(b []byte, at int) (uint16, bool) {
	if at+4 > len(b) {
		return 0, false
	}
	var v uint16
	for _, c := range b[at : at+4] {
		switch {
		case c >= '0' && c <= '9':
			v = v<<4 | uint16(c-'0')
		case c >= 'a' && c <= 'f':
			v = v<<4 | uint16(c-'a'+10)
		case c >= 'A' && c <= 'F':
			v = v<<4 | uint16(c-'A'+10)
		default:
			return 0, false
		}
	}
	return v, true
}

// Verify проверяет подпись квитанции ключом key. Квитанция обязана называть
// именно его (kid): подпись, которая сходится с ключом под чужим именем,
// написал тот, кто путает ключи, — или тот, кто хочет, чтобы их спутали.
func (r Receipt) Verify(key ed25519.PublicKey) error {
	if r.Sig == nil {
		return errNoSignature
	}
	if len(key) != ed25519.PublicKeySize {
		return errors.New("the gateway key is not an Ed25519 public key")
	}
	if id := KeyID(key); r.Kid != id {
		return fmt.Errorf("the receipt names key %s, not this gateway key (%s)", r.Kid, id)
	}
	if !ed25519.Verify(key, r.signingInput(), r.Sig) {
		return errors.New("the receipt signature does not verify with the gateway key")
	}
	return nil
}

// signingInput — что подписано (RFC 7515, 5.1): ASCII(P) ‖ "." ‖ BASE64URL(B).
func (r Receipt) signingInput() []byte {
	return signingInput(r.protected, r.signed)
}

func signingInput(protected string, b []byte) []byte {
	out := make([]byte, 0, len(protected)+1+base64.RawURLEncoding.EncodedLen(len(b)))
	out = append(out, protected...)
	out = append(out, '.')
	return base64.RawURLEncoding.AppendEncode(out, b)
}

// Compact — квитанция обычным компактным JWS (RFC 7515, 3.1): заголовок,
// тело — строка без поля jws — и подпись. В таком виде её проверяет любая
// библиотека JOSE с ключом шлюза (JWK). ok == false — подписи у строки нет.
func (r Receipt) Compact() (jws string, ok bool) {
	if r.Sig == nil {
		return "", false
	}
	return string(r.signingInput()) + "." + base64.RawURLEncoding.EncodeToString(r.Sig), true
}

// splitJWS отрезает хвост с подписью: B (строка без поля jws, с «}» на
// конце), защищённый заголовок, как он в строке, и сама подпись. ok == false
// — строка кончается не подписью. Начало хвоста ищется с конца: в нём только
// знаки base64url и две точки, так что поле "jws" внутри body им не станет.
// base64url — строгий: без дополнения и с нулевыми лишними битами, иначе у
// одной подписи было бы несколько записей, а у квитанции — несколько хэшей.
func splitJWS(line []byte) (b []byte, protected string, sig []byte, ok bool) {
	if !bytes.HasSuffix(line, []byte(`"}`)) {
		return nil, "", nil, false
	}
	from := max(len(line)-MaxJWS, 0)
	i := bytes.LastIndex(line[from:], []byte(jwsPrefix))
	if i < 0 {
		return nil, "", nil, false
	}
	i += from
	if i+len(jwsPrefix) > len(line)-2 {
		return nil, "", nil, false // `,"jws":"}`: кавычка хвоста — она же последняя
	}
	protected, s, found := strings.Cut(string(line[i+len(jwsPrefix):len(line)-2]), "..")
	if !found || protected == "" || s == "" {
		return nil, "", nil, false
	}
	if _, err := base64.RawURLEncoding.Strict().DecodeString(protected); err != nil {
		return nil, "", nil, false
	}
	sig, err := base64.RawURLEncoding.Strict().DecodeString(s)
	if err != nil {
		return nil, "", nil, false
	}
	b = append(bytes.Clone(line[:i]), '}')
	return b, protected, sig, true
}

// parseProtected разбирает защищённый заголовок подписи: ровно alg, kid и
// typ. Алгоритм и имя ключа отдаются и при ошибке, если их удалось прочесть.
// Остального в заголовке быть не должно: ключ в самой подписи (jwk, jku,
// x5c) — приглашение проверить её ключом подписавшего, а crit и b64 меняют
// то, что считается подписанным.
func parseProtected(protected string) (alg, kid string, err error) {
	raw, _ := base64.RawURLEncoding.Strict().DecodeString(protected) // проверен splitJWS
	h, err := strictObject(raw)
	if err != nil {
		return "", "", fmt.Errorf("receipt: the protected header of the signature: %w", err)
	}
	alg, okAlg := evidence.JSONString(h["alg"])
	kid, okKid := evidence.JSONString(h["kid"])
	typ, okTyp := evidence.JSONString(h["typ"])
	if !okKid || !validName(kid, MaxKeyID) {
		kid = ""
	}
	switch {
	case len(h) != 3 || !okAlg || !okTyp || kid == "":
		return alg, kid, errors.New(`receipt: the protected header of the signature must be {"alg": …, "kid": …, "typ": …} and nothing else`)
	case typ != ReceiptType:
		return alg, kid, fmt.Errorf("receipt: the signature is not of a receipt: its typ must be %q", ReceiptType)
	case alg != AlgEd25519 && alg != AlgEdDSA:
		return "", kid, fmt.Errorf("receipt: the signature algorithm must be %q (or its older name %q)", AlgEd25519, AlgEdDSA)
	}
	return alg, kid, nil
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
	keys *KeySet
	last map[string]receiptLink // шлюз → последняя принятая квитанция
	// genesis — шлюз → хэш начала его нынешней цепочки: копия этого начала —
	// не новая цепочка, а повтор (LinkStale).
	genesis map[string]string
}

type receiptLink struct {
	hash string
	seq  uint64
}

// NewReceiptTracker — без ключей (nil) подписи не проверяются (SigNoKey).
// Хранилище так не делает: у источника квитанций ключ обязателен.
func NewReceiptTracker(keys *KeySet) *ReceiptTracker {
	return &ReceiptTracker{keys: keys, last: map[string]receiptLink{}, genesis: map[string]string{}}
}

// Check проверяет очередную квитанцию и двигает состояние её цепочки.
// received — когда хранилище её приняло: по этому времени сверяется срок
// ключа (нулевое — срок не сверяется, KeySet.Verify).
func (t *ReceiptTracker) Check(line []byte, received time.Time) Verdict {
	r, err := ParseReceipt(line)
	v := Verdict{Seq: r.Seq, Writer: r.Gateway, Hash: r.Hash, PrevHash: r.Prev, HashOK: true, Kid: r.Kid}
	if err != nil {
		v.Problem = err.Error()
	}
	switch {
	case r.Sig == nil:
		v.Signature = SigInvalid
	case t.keys.Len() == 0:
		v.Signature = SigNoKey
	default:
		// Чужая подпись, ключ не из списка источника и ключ вне своего срока
		// — одно и то же: за шлюз строка не говорит и в его цепочку не входит.
		if err := t.keys.Verify(r, received); err == nil {
			v.Signature = SigValid
		} else {
			v.Signature = SigInvalid
			if v.Problem == "" {
				v.Problem = err.Error()
			}
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
		// подделка не должна ломать следующую настоящую квитанцию. И не после
		// повтора (LinkStale): копию своей же прежней строки дописать может
		// любой, кто пишет в файл, без ключа.
		if MovesChain(v) {
			t.last[r.Gateway] = receiptLink{hash: r.Hash, seq: r.Seq}
			if r.Prev == Genesis {
				t.genesis[r.Gateway] = r.Hash
			}
		}
	}()
	switch {
	case seen && r.Prev != Genesis && r.Seq <= last.seq, seen && r.Prev == Genesis && r.Hash == t.genesis[r.Gateway]:
		v.Link = LinkStale
		if v.Problem == "" {
			switch {
			case r.Hash == last.hash:
				v.Problem = fmt.Sprintf("a copy of the gateway's last receipt (seq %d): the chain goes on from that one", last.seq)
			case r.Prev == Genesis:
				v.Problem = fmt.Sprintf("a copy of the start of the gateway's chain, after its seq %d: the chain goes on from seq %d", last.seq, last.seq)
			default:
				v.Problem = fmt.Sprintf("seq %d after seq %d: a copy of an earlier receipt of this gateway, or a second branch of its chain; the chain goes on from seq %d", r.Seq, last.seq, last.seq)
			}
		}
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
		if v.PrevHash == Genesis {
			t.genesis[v.Writer] = v.Hash
		}
	}
}

// MovesChain — квитанция с этим вердиктом стала последней в цепочке своего
// шлюза: цепочка названа, подпись не чужая, и это не повтор прежней
// (LinkStale). Так же считает проверка пакета по источнику.
func MovesChain(v Verdict) bool {
	return v.Writer != "" && v.Seq != 0 && v.PrevHash != "" && v.Signature != SigInvalid && v.Link != LinkStale
}

// Signer ведёт цепочку квитанций одного шлюза и подписывает их.
type Signer struct {
	mu        sync.Mutex
	key       ed25519.PrivateKey
	protected string // защищённый заголовок подписи, base64url
	gateway   string
	next      uint64
	prev      string
}

// protectedHeader — защищённый заголовок подписи квитанции ключом pub.
func protectedHeader(pub ed25519.PublicKey) string {
	return base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"` + AlgEd25519 + `","kid":"` + KeyID(pub) + `","typ":"` + ReceiptType + `"}`))
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
	s := &Signer{key: key, protected: protectedHeader(key.Public().(ed25519.PublicKey)), gateway: gateway, next: 1, prev: Genesis}
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

// SignLine подписывает готовый объект квитанции b (без поля jws, последний
// байт — «}») ключом key и отдаёт строку с подписью: так подписывает шлюз,
// который собирает JSON сам. Что в b, не проверяется: это дело ParseReceipt.
func SignLine(key ed25519.PrivateKey, b []byte) []byte {
	return signLine(key, protectedHeader(key.Public().(ed25519.PublicKey)), b)
}

func signLine(key ed25519.PrivateKey, protected string, b []byte) []byte {
	sig := ed25519.Sign(key, signingInput(protected, b))
	line := append(bytes.Clone(b[:max(len(b)-1, 0)]), jwsPrefix...)
	line = append(line, protected...)
	line = append(line, ".."...)
	line = base64.RawURLEncoding.AppendEncode(line, sig)
	return append(line, `"}`...)
}

// After ставит цепочку за квитанцией шлюза с номером seq и хэшем hash,
// подписанной его прежним ключом: шлюз сменил ключ, а цепочка — та же
// (AppendHead делает это сам, по голове).
func (s *Signer) After(seq uint64, hash string) error {
	if seq == 0 || seq >= MaxSeq || !isHash(hash) {
		return errors.New("gateway: a chain goes on from a receipt with its seq and its hash (64 hex)")
	}
	s.mu.Lock()
	s.next, s.prev = seq+1, hash
	s.mu.Unlock()
	return nil
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
	}{ReceiptVersion, s.gateway, s.next, s.prev, d.Time.UTC().Format(time.RFC3339Nano), d.Action, d.Step, d.Refs, d.Approval, d.Body}
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(out); err != nil {
		return nil, fmt.Errorf("gateway: receipt: %w", err)
	}
	b := bytes.TrimRight(buf.Bytes(), "\n")
	line := signLine(s.key, s.protected, b)
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
	// received — когда хранилище приняло строку.
	Check(line []byte, received time.Time) Verdict
	Resume(v Verdict)
}

// Verified — записи этого вида проверяются при приёме, и у каждой в цепи
// лежит вердикт хранилища.
func Verified(contentType string) bool {
	return contentType == ContentType || contentType == ReceiptContentType
}

// NewChecker — проверка для вида contentType ключами keys; nil — вид не
// проверяется. У бортового журнала Pipelock ключ один и срока у него нет:
// контрольная точка своего ключа не называет.
func NewChecker(contentType string, keys *KeySet) Checker {
	switch contentType {
	case ContentType:
		var key ed25519.PublicKey
		if k := keys.Keys(); len(k) > 0 {
			key = k[0].Pub
		}
		return recorderChecker{NewTracker(key)}
	case ReceiptContentType:
		return NewReceiptTracker(keys)
	}
	return nil
}

// recorderChecker — Tracker как Checker: время приёма журналу Pipelock не
// нужно, срока у его ключа нет.
type recorderChecker struct{ *Tracker }

func (c recorderChecker) Check(line []byte, _ time.Time) Verdict { return c.Tracker.Check(line) }
