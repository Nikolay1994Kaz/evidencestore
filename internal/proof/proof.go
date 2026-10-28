// Package proof — пакет доказательств по одной улике и его офлайн-проверка.
//
// Хранилище собирает пакет, проверяющий проверяет его сам, без доступа к
// хранилищу и без доверия к нему. Ему нужны только пакет, закреплённый
// открытый ключ хранилища и сертификаты TSA (у НУЦ — корень root_rsa_2020).
//
// Что доказывает пакет и как:
//
//	улика       отпечаток = SHA-256("evidencestore/sealed/v1" ‖ байты улики)
//	лист        тип «улика принята», источник, номер, время приёма, позиция, отпечаток
//	лист        → путь Меркла → корень в звене n
//	звенья      от первого нужного до головы, каждое хэшем ссылается на прежнее
//	T2 (сверху) токен TSA над головой m ≥ n: улика существовала не позже T2
//	T1 (снизу)  токен TSA, лежащий листом в звене k < n: улика вошла в цепь после T1
//	голова      подписана ключом хранилища (Ed25519)
//	тело        если выдан ключ записи (DEK) — вскрывается, тег GCM сходится
//
// Звенья подлинны потому, что голова m заверена TSA, а каждое звено до неё
// входит в хэш следующего: подменить звено n значит сломать хэш головы.
package proof

import (
	"crypto/ed25519"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/Nikolay1994Kaz/evidencestore/internal/auditchain"
	"github.com/Nikolay1994Kaz/evidencestore/internal/evidence"
	"github.com/Nikolay1994Kaz/evidencestore/internal/gateway"
	"github.com/Nikolay1994Kaz/evidencestore/internal/keyring"
	"github.com/Nikolay1994Kaz/evidencestore/internal/tsa"
)

// Version — версия формата пакета одной улики. Версия 2 (27.10) — тот же
// формат, но проверки ему нужны новые (звено токена T1 — tokenLinkTime,
// сверка обещания от головы T1): esverify v0.2.0 и раньше такой пакет не
// разбирает и говорит о версии, а не проверяет его без них. Версия 3
// (28.10) несёт участок — все листья от головы под T1 до звена записи:
// обещание сверяется по меткам на нём, а не по времени звеньев. Пакеты
// версий 1 и 2 читаются по-прежнему, но для -promise не принимаются.
const Version = 3

// HeadDomain — домен хэша головы, который уходит в TSA.
const HeadDomain = "evidencestore/head/v1"

// Допуски времени приёма относительно меток TSA — одни для пакета одной
// улики и для пакета за окно (window.go). Сверху — секунда: время в метке —
// с точностью до секунды. Снизу — минута: улика записывается на диск и
// встаёт в цепь за миллисекунды после приёма, но метка T1 могла лечь в цепь
// между этими моментами.
const (
	ReceiveSlack = time.Second
	ReceiveSkew  = time.Minute
)

// ReceiveLag — на сколько время приёма может отставать от настоящего:
// хранилище зажимает часы хоста окном по якорю TSA не шире ReceiveLag
// (store.recvWindow). Время звеньев при этом доходит до настоящего, и
// честному хранилищу срок обещания нужен не короче ReceiveLag и двух тиков
// цепи (config, chain.promise_mmd).
const ReceiveLag = 55 * time.Second

// Граница окна у пакетов за окно и по источнику (DECISIONS, п. 27, 28).
// Метка заверяет звено, созданное перед запросом к TSA; что легло в цепь,
// пока шёл запрос, — после этого звена, и метка его не заверяет. Такая
// запись получает время приёма позже T2 − WindowEdge: ответа TSA дольше
// StampLatency хранилище не ждёт (токен не ложится в цепь), часы приёма
// отстают от настоящего времени не больше ReceiveLag, остальное — запас на путь
// от приёма до листа в цепи. Поэтому окно, кончившееся раньше
// T2 − WindowEdge, целиком лежит в заверенном.
const (
	StampLatency = 30 * time.Second
	WindowEdge   = 2 * time.Minute
)

// HeadImprint — что заверяет TSA: номер и хэш головы цепи.
func HeadImprint(seq uint64, hash [32]byte) [32]byte {
	var b [8 + 32]byte
	binary.BigEndian.PutUint64(b[:8], seq)
	copy(b[8:], hash[:])
	return tsa.Imprint(HeadDomain, b[:])
}

// EvidenceLeaf — лист цепи для принятой улики. Открытые поля листа повторяют
// заголовок улики: проверяющий сверяет их с самими байтами.
func EvidenceLeaf(h evidence.Header, pos uint64, digest [32]byte) auditchain.Leaf {
	payload := make([]byte, 8+32)
	binary.BigEndian.PutUint64(payload, pos)
	copy(payload[8:], digest[:])
	return auditchain.Leaf{
		UnixNano: h.ReceivedAt,
		Type:     auditchain.EventEvidence,
		Scope:    h.Source,
		Subject:  strconv.FormatUint(h.Seq, 10),
		Payload:  payload,
	}
}

// EvidenceLeafLinked — лист улики со ссылкой на прежний лист улики того же
// источника в порядке цепи (prev — его хэш, нули у первой записи источника):
// цепочка источника внутри общей цепи (DECISIONS, п. 28). Предмет —
// позиция, отпечаток и prev, 72 байта; хранилище пишет такие листья с этого
// изменения, EvidenceLeaf (40 байт) — прежний формат.
func EvidenceLeafLinked(h evidence.Header, pos uint64, digest, prev [32]byte) auditchain.Leaf {
	l := EvidenceLeaf(h, pos, digest)
	l.Payload = append(l.Payload, prev[:]...)
	return l
}

// ParseEvidenceLeaf разбирает предмет листа улики: позиция и отпечаток.
// Читает оба формата: прежний (40 байт) и со ссылкой (72).
func ParseEvidenceLeaf(l auditchain.Leaf) (pos uint64, digest [32]byte, err error) {
	if l.Type != auditchain.EventEvidence || len(l.Payload) != 8+32 && len(l.Payload) != 8+32+32 {
		return 0, digest, errors.New("proof: not an evidence leaf")
	}
	copy(digest[:], l.Payload[8:40])
	return binary.BigEndian.Uint64(l.Payload), digest, nil
}

// EvidencePrev — ссылка листа улики на прежний лист того же источника;
// ok = false — лист прежнего формата, без ссылки.
func EvidencePrev(l auditchain.Leaf) (prev [32]byte, ok bool) {
	if l.Type != auditchain.EventEvidence || len(l.Payload) != 8+32+32 {
		return prev, false
	}
	copy(prev[:], l.Payload[40:])
	return prev, true
}

// Leaf — лист в пакете.
type Leaf struct {
	UnixNano int64  `json:"t"`
	Type     uint8  `json:"type"`
	Scope    string `json:"scope"`
	Subject  string `json:"subject"`
	Payload  []byte `json:"payload"`
}

func FromLeaf(l auditchain.Leaf) Leaf {
	return Leaf{UnixNano: l.UnixNano, Type: uint8(l.Type), Scope: l.Scope, Subject: l.Subject, Payload: l.Payload}
}

// Chain — лист в виде цепи.
func (l Leaf) Chain() auditchain.Leaf { return l.chain() }

func (l Leaf) chain() auditchain.Leaf {
	return auditchain.Leaf{UnixNano: l.UnixNano, Type: auditchain.EventType(l.Type), Scope: l.Scope, Subject: l.Subject, Payload: l.Payload}
}

// Step — шаг пути Меркла.
type Step struct {
	Hash []byte `json:"h"`
	Left bool   `json:"left"`
}

// Link — звено цепи в пакете.
type Link struct {
	Seq      uint64 `json:"seq"`
	PrevHash []byte `json:"prev"`
	UnixNano int64  `json:"t"`
	Type     uint8  `json:"type"`
	Scope    string `json:"scope,omitempty"`
	Subject  string `json:"subject,omitempty"`
	Payload  []byte `json:"payload"`
}

func FromLink(r auditchain.Record) Link {
	return Link{Seq: r.Seq, PrevHash: r.PrevHash[:], UnixNano: r.UnixNano, Type: uint8(r.Type),
		Scope: r.Scope, Subject: r.Subject, Payload: r.Payload}
}

func (l Link) record() (auditchain.Record, error) {
	r := auditchain.Record{Seq: l.Seq, UnixNano: l.UnixNano, Type: auditchain.EventType(l.Type),
		Scope: l.Scope, Subject: l.Subject, Payload: l.Payload}
	if len(l.PrevHash) != 32 {
		return r, fmt.Errorf("link %d: prev hash is %d bytes", l.Seq, len(l.PrevHash))
	}
	copy(r.PrevHash[:], l.PrevHash)
	return r, nil
}

// Inclusion — лист и путь до корня звена.
type Inclusion struct {
	Leaf    Leaf   `json:"leaf"`
	LinkSeq uint64 `json:"link_seq"`
	Path    []Step `json:"path"`
}

// Lower — нижняя граница: токен TSA, лежащий в цепи раньше улики.
type Lower struct {
	Inclusion Inclusion `json:"inclusion"` // лист «метка TSA», в предмете — токен
}

// Upper — верхняя граница: токен TSA над головой m.
type Upper struct {
	HeadSeq uint64 `json:"head_seq"`
	Token   []byte `json:"token"`
}

// Bundle — пакет доказательств по одной улике.
type Bundle struct {
	Version   int                  `json:"v"`
	Evidence  []byte               `json:"evidence"` // байты улики, как на диске
	Inclusion Inclusion            `json:"inclusion"`
	Lower     *Lower               `json:"lower,omitempty"`
	Upper     *Upper               `json:"upper,omitempty"`
	Links     []Link               `json:"links"` // подряд, последнее — голова из Statement
	Statement auditchain.Statement `json:"statement"`
	DEK       []byte               `json:"dek,omitempty"` // ключ этой записи, если выдан
	// Gateway — для улик из журнала гейтвея (content_type pipelock/recorder).
	Gateway *GatewayProof `json:"gateway,omitempty"`
	// Stretch — с версии 3: все листья звеньев от головы, которую заверила
	// T1, до звена улики. По ним сверка обещания находит каждую метку перед
	// уликой (CheckPromise: правило меток).
	Stretch []Leaf `json:"stretch,omitempty"`
}

func Parse(data []byte) (Bundle, error) {
	var b Bundle
	if err := json.Unmarshal(data, &b); err != nil {
		return b, fmt.Errorf("proof: %w", err)
	}
	// Версия у пакетов разных видов своя (пакет за окно — тоже 2): вид
	// сверяется первым.
	if kind, _ := BundleKind(data); kind != "" {
		return b, fmt.Errorf("proof: a bundle of kind %q, not a single-record bundle", kind)
	}
	if b.Version < 1 || b.Version > Version {
		return b, fmt.Errorf("proof: bundle version %d, supported 1 to %d", b.Version, Version)
	}
	return b, nil
}

// Trust — во что верит проверяющий.
type Trust struct {
	// StoreKey — закреплённый открытый ключ хранилища. Ключ из самого
	// пакета не годится: подделавший положит туда свой.
	StoreKey ed25519.PublicKey
	// TSA — корни и промежуточные сертификаты службы меток времени.
	TSA tsa.Trust
	// GatewayKey — закреплённый открытый ключ гейтвея: им проверяется подпись
	// контрольной точки. nil — подпись проверило только хранилище при приёме.
	GatewayKey ed25519.PublicKey
	// AllowNoTSA — принять пакет без метки TSA над цепью после улики. Без неё
	// время и неизменность подтверждает только подпись хранилища, а держатель
	// ключа подписи сочинит улику с любой датой. По умолчанию — провал.
	AllowNoTSA bool
	// Witness — головы, которые проверяющий сам взял у свидетеля (heads.go).
	// nil — сверки со свидетелем нет.
	Witness *Witness
}

// Check — один пункт отчёта.
type Check struct {
	Name   string
	OK     bool
	Detail string
}

// Report — итог проверки.
type Report struct {
	Checks     []Check
	Header     evidence.Header
	Position   uint64
	Digest     [32]byte
	LinkSeq    uint64
	Lower      time.Time // T1, ноль — нет
	Upper      time.Time // T2, ноль — нет
	HeadSeq    uint64
	Body       []byte // тело, если выдан DEK и он подошёл
	BodyOpened bool
	BodyKey    bool // в пакете был ключ записи (подошёл он или нет)

	Gateway           *gateway.Verdict // вердикт хранилища по записи журнала гейтвея
	GatewayCheckpoint *gateway.Verdict // контрольная точка, накрывшая запись (подпись проверена)
	GatewayKeyChecked bool             // подпись точки проверена ключом проверяющего
	// GatewayUnsigned — точка после записи в пакете есть, но её подпись не
	// проверял никто: ключ гейтвея не закреплён ни в хранилище, ни у
	// проверяющего. Такая точка запись не накрывает.
	GatewayUnsigned bool

	// WitnessChecked — пакет сверялся с головами свидетеля (Trust.Witness);
	// WitnessHead — голова свидетеля, которая закрепляет улику: первая не
	// раньше её звена; WitnessNone — такой головы у свидетеля ещё нет.
	// Сверка не прошла — ни того, ни другого.
	WitnessChecked bool
	WitnessHead    uint64
	WitnessNone    bool
	// WitnessFork — первый номер, под которым у свидетеля две версии головы
	// вне участка цепи этой записи: хранилище подписало вторую историю, но
	// запись она не задевает. Ноль — таких нет.
	WitnessFork uint64
}

// Valid — все проверки прошли (замечания вида «нет метки» проверками не
// считаются: они перечислены в Notes).
func (r Report) Valid() bool {
	for _, c := range r.Checks {
		if !c.OK {
			return false
		}
	}
	return len(r.Checks) > 0
}

// Notes — чего пакет не доказывает. Пределы называются в самом отчёте.
func (r Report) Notes() []string {
	var n []string
	if r.Upper.IsZero() {
		n = append(n, "no TSA time-stamp over a head after the record: its time rests on the store's signature alone")
	}
	if r.Lower.IsZero() {
		n = append(n, "no TSA time-stamp before the record: the lower bound of its time is not proven")
	}
	switch {
	case r.BodyOpened:
	case r.BodyKey:
		n = append(n, "body not opened: the record key in the bundle does not fit the body (see the checks)")
	default:
		n = append(n, "body not opened: the bundle carries no record key, or the month key was destroyed (retention)")
	}
	n = append(n, r.gatewayNotes()...)
	if r.WitnessFork != 0 {
		n = append(n, fmt.Sprintf("the witness holds two versions of the chain, both signed with the store key (the first head it holds in two versions is %d): this record's part of the chain is not among them, but the store signed a second history — a rewrite, or a store that lost data without a copy; ask its operator", r.WitnessFork))
	}
	switch {
	case r.WitnessHead != 0:
		n = append(n, fmt.Sprintf("the witness saw head %d, and it fixes the chain up to that head: rewriting this record would contradict the witness, as long as the witness is out of the store administrator's reach", r.WitnessHead))
	case r.WitnessNone:
		n = append(n, "the witness has no head at or after this record yet: until it gets one, only a TSA time-stamp stands against the store's owner rewriting the chain")
	default:
		n = append(n, "the store's signature proves that THIS store signed the head; only a TSA time-stamp stands against its owner rewriting the whole chain")
	}
	n = append(n, "what is proven is that these bytes came from the source and have not changed, not that their content is true")
	return n
}

// Verify проверяет пакет. Возвращает отчёт всегда; ошибка — только если
// пакет даже не разбирается. Итог — Report.Valid().
func Verify(b Bundle, trust Trust) Report {
	var r Report
	add := func(name string, err error, detail string) bool {
		c := Check{Name: name, OK: err == nil, Detail: detail}
		if err != nil {
			c.Detail = err.Error()
		}
		r.Checks = append(r.Checks, c)
		return err == nil
	}

	// 1. Улика и её отпечаток.
	sealed, err := evidence.Unmarshal(b.Evidence)
	if !add("the record parses", err, "") {
		return r
	}
	r.Header = sealed.Header
	r.Digest = evidence.Digest(b.Evidence)

	// 2. Лист улики совпадает с её заголовком и отпечатком.
	leaf := b.Inclusion.Leaf.chain()
	pos, digest, err := ParseEvidenceLeaf(leaf)
	if err == nil {
		r.Position = pos
		switch {
		case digest != r.Digest:
			err = errors.New("the digest in the leaf does not match the record bytes")
		case leaf.Scope != sealed.Source || leaf.Subject != strconv.FormatUint(sealed.Seq, 10):
			err = fmt.Errorf("the leaf is about %s/%s, the record is %s/%d", leaf.Scope, leaf.Subject, sealed.Source, sealed.Seq)
		case leaf.UnixNano != sealed.ReceivedAt:
			err = errors.New("the receive time in the leaf does not match the record")
		}
	}
	add("the chain leaf describes this very record", err, fmt.Sprintf("position %d", pos))

	// 3. Звенья подряд и связаны хэшами.
	links, hashes, err := chainLinks(b.Links)
	if !add("the links are chained by hash with no gaps", err, fmt.Sprintf("%d links", len(links))) {
		return r
	}
	linkAt := func(seq uint64) (auditchain.Record, [32]byte, bool) {
		if len(links) == 0 || seq < links[0].Seq || seq > links[len(links)-1].Seq {
			return auditchain.Record{}, [32]byte{}, false
		}
		i := seq - links[0].Seq
		return links[i], hashes[i], true
	}

	// 4. Голова подписана закреплённым ключом и совпадает с последним звеном.
	err = auditchain.VerifyStatement(b.Statement, trust.StoreKey)
	if err == nil {
		last := len(links) - 1
		if b.Statement.HeadSeq != links[last].Seq || b.Statement.HeadHash != encodeHash(hashes[last]) {
			err = errors.New("the signed head does not match the last link in the bundle")
		}
	}
	r.HeadSeq = b.Statement.HeadSeq
	add("the head is signed with the store key", err, fmt.Sprintf("head %d", b.Statement.HeadSeq))

	// 5. Путь Меркла от листа улики до корня звена n.
	r.LinkSeq = b.Inclusion.LinkSeq
	add("the record is in a chain link (Merkle path)", checkInclusion(b.Inclusion, linkAt), fmt.Sprintf("link %d", b.Inclusion.LinkSeq))

	// 6. Верхняя граница: TSA заверила голову m ≥ n. Без неё пакет — только
	// слово хранилища: держатель ключа подписи сочинит улику с любой датой.
	if b.Upper != nil {
		r.Upper, err = checkUpper(*b.Upper, b.Inclusion.LinkSeq, linkAt, trust.TSA)
		add("a TSA time-stamp over the chain after the record (not later than T2)", err, fmt.Sprintf("T2 = %s, head %d", fmtTime(r.Upper), b.Upper.HeadSeq))
	} else if !trust.AllowNoTSA {
		add("a TSA time-stamp over the chain after the record (not later than T2)",
			errors.New("the bundle has none: only the store's signature vouches for the time and integrity (request the bundle after the next time-stamp, evidencestore stamp; to accept it anyway, esverify -allow-no-tsa)"), "")
	}

	// 7. Нижняя граница: токен TSA лежит в цепи раньше звена улики.
	if b.Lower != nil {
		r.Lower, err = checkLower(*b.Lower, b.Inclusion.LinkSeq, linkAt, trust.TSA)
		add("a TSA time-stamp in the chain before the record (not earlier than T1)", err, fmt.Sprintf("T1 = %s", fmtTime(r.Lower)))
	}

	// 8. Время приёма по нашим часам попадает между метками.
	if !r.Upper.IsZero() || !r.Lower.IsZero() {
		recv := time.Unix(0, sealed.ReceivedAt).UTC()
		err = nil
		if !r.Upper.IsZero() && recv.After(r.Upper.Add(ReceiveSlack)) {
			err = fmt.Errorf("receive time %s is later than time-stamp T2 %s: the store's clock lies", fmtTime(recv), fmtTime(r.Upper))
		}
		if !r.Lower.IsZero() && recv.Before(r.Lower.Add(-ReceiveSkew)) {
			err = fmt.Errorf("receive time %s is earlier than time-stamp T1 %s: the store's clock lies", fmtTime(recv), fmtTime(r.Lower))
		}
		add("the receive time lies between the TSA time-stamps", err, fmtTime(recv))
	}

	// 9. Тело, если выдан ключ записи. Конверт EV2 несёт обязательство на
	// ключ записи под отпечатком улики: другой ключ (и другое тело при
	// том же отпечатке) не пройдёт.
	if len(b.DEK) > 0 {
		r.BodyKey = true
		body, err := keyring.OpenWithDEK(sealed.Envelope, b.DEK)
		if add("the body opens with the record key in the bundle, the key is bound to the digest, the GCM tag matches", err, fmt.Sprintf("%d bytes", len(body))) {
			r.Body, r.BodyOpened = body, true
		}
	}

	// 10. Улика из журнала гейтвея: вердикт при приёме, хэш тела, подпись
	// контрольной точки. Без этой части запись журнала гейтвея не проверить:
	// убрать её из пакета — значит спрятать, что запись не цела.
	switch {
	case b.Gateway != nil:
		verifyGateway(b.Gateway, sealed, &r, trust, linkAt, add)
	case sealed.ContentType == gateway.ContentType:
		add("the gateway verdict describes this record", errors.New("the record comes from a gateway journal, but the bundle has no gateway part"), "")
	}

	// 11. Свидетель голов: цепь пакета сходится с головами, которые
	// проверяющий сам взял у свидетеля.
	if trust.Witness != nil {
		checkWitness(trust.Witness, trust.StoreKey, b.Inclusion.LinkSeq, links, hashes, &r, add)
	}
	return r
}

func chainLinks(in []Link) ([]auditchain.Record, [][32]byte, error) {
	if len(in) == 0 {
		return nil, nil, errors.New("the bundle has no links")
	}
	links := make([]auditchain.Record, len(in))
	hashes := make([][32]byte, len(in))
	for i, l := range in {
		r, err := l.record()
		if err != nil {
			return nil, nil, err
		}
		if i > 0 {
			if r.Seq != links[i-1].Seq+1 {
				return nil, nil, fmt.Errorf("link %d is followed by link %d", links[i-1].Seq, r.Seq)
			}
			if r.PrevHash != hashes[i-1] {
				return nil, nil, fmt.Errorf("link %d does not refer to the hash of link %d: the chain was replaced", r.Seq, links[i-1].Seq)
			}
		}
		links[i], hashes[i] = r, auditchain.Hash(r)
	}
	return links, hashes, nil
}

func checkInclusion(inc Inclusion, linkAt func(uint64) (auditchain.Record, [32]byte, bool)) error {
	link, _, ok := linkAt(inc.LinkSeq)
	if !ok {
		return fmt.Errorf("link %d is not in the bundle", inc.LinkSeq)
	}
	if link.Type != auditchain.EventBatch {
		return fmt.Errorf("link %d does not aggregate leaves", inc.LinkSeq)
	}
	p, err := auditchain.DecodeBatchPayload(link.Payload)
	if err != nil {
		return err
	}
	path := make([]auditchain.ProofStep, len(inc.Path))
	for i, s := range inc.Path {
		if len(s.Hash) != 32 {
			return errors.New("a path step does not parse")
		}
		copy(path[i].Hash[:], s.Hash)
		path[i].SiblingLeft = s.Left
	}
	if !auditchain.VerifyProof(inc.Leaf.chain(), path, p.Root) {
		return fmt.Errorf("the path does not lead to the root of link %d", inc.LinkSeq)
	}
	return nil
}

func checkUpper(u Upper, evidenceLink uint64, linkAt func(uint64) (auditchain.Record, [32]byte, bool), trust tsa.Trust) (time.Time, error) {
	if u.HeadSeq < evidenceLink {
		return time.Time{}, fmt.Errorf("the time-stamp is over head %d, the record is in link %d: the time-stamp does not cover it", u.HeadSeq, evidenceLink)
	}
	_, hash, ok := linkAt(u.HeadSeq)
	if !ok {
		return time.Time{}, fmt.Errorf("link %d is not in the bundle", u.HeadSeq)
	}
	info, err := tsa.Verify(u.Token, HeadImprint(u.HeadSeq, hash), trust)
	if err != nil {
		return time.Time{}, err
	}
	return info.GenTime.UTC(), nil
}

func checkLower(lw Lower, evidenceLink uint64, linkAt func(uint64) (auditchain.Record, [32]byte, bool), trust tsa.Trust) (time.Time, error) {
	inc := lw.Inclusion
	if inc.Leaf.Type != uint8(auditchain.EventTimestamp) {
		return time.Time{}, errors.New("the lower bound is not a TSA time-stamp leaf")
	}
	if inc.LinkSeq >= evidenceLink {
		return time.Time{}, fmt.Errorf("the time-stamp is in link %d, the record in link %d: the time-stamp is not earlier than the record", inc.LinkSeq, evidenceLink)
	}
	if err := checkInclusion(inc, linkAt); err != nil {
		return time.Time{}, err
	}
	stamped, err := strconv.ParseUint(inc.Leaf.Subject, 10, 64)
	if err != nil {
		return time.Time{}, errors.New("the time-stamp leaf has no head number")
	}
	_, hash, ok := linkAt(stamped)
	if !ok {
		return time.Time{}, fmt.Errorf("link %d, certified by the time-stamp, is not in the bundle", stamped)
	}
	info, err := tsa.Verify(inc.Leaf.Payload, HeadImprint(stamped, hash), trust)
	if err != nil {
		return time.Time{}, err
	}
	link, _, _ := linkAt(inc.LinkSeq)
	if err := tokenLinkTime(link, info.GenTime.UTC()); err != nil {
		return time.Time{}, err
	}
	return info.GenTime.UTC(), nil
}

// tokenLinkTime — звено, в котором лежит токен метки, получило время не
// раньше её времени минус ReceiveSkew. Время звена — время его последнего
// листа; лист токена ложится сразу после ответа TSA со временем по якорю
// этой же метки, и звено сворачивается тут же (store.stampOnce): в честной
// цепи время звена с токеном отстаёт от времени метки меньше чем на 55 с.
// Время звеньев пишет само хранилище, и обещание сверяется по нему
// (CheckPromise): звено токена со временем задним числом пропустило бы
// запись, придержанную за метку, «в срок» (Q-33). Проверяется у каждого
// токена, который пакет показывает.
func tokenLinkTime(link auditchain.Record, gen time.Time) error {
	if at := time.Unix(0, link.UnixNano).UTC(); at.Before(gen.Add(-ReceiveSkew)) {
		return fmt.Errorf("link %d holds the token of the time-stamp of %s, yet its time is %s, more than %s earlier: the store backdated the link", link.Seq, fmtTime(gen), fmtTime(at), ReceiveSkew)
	}
	return nil
}

func encodeHash(h [32]byte) string {
	// Тот же вид, что в auditchain.Statement.
	return auditchain.EncodeHash(h)
}

func fmtTime(t time.Time) string {
	if t.IsZero() {
		return "—"
	}
	return t.UTC().Format("2006-01-02 15:04:05 UTC")
}

// Verdict — итог одной строкой.
func (r Report) Verdict() string {
	if r.Valid() {
		return "VERIFIED"
	}
	return "NOT VERIFIED"
}

// Text — отчёт человеческим языком: что доказано, что нет и где пределы.
// Всё, что пришло из пакета (тело, источник, поля журнала гейтвея, тексты
// ошибок), печатается с экранированными управляющими символами: иначе тело
// с ESC-последовательностями рисовало бы на экране проверяющего ложный
// вердикт. Вердикт повторён последней строкой.
func (r Report) Text() string {
	var s string
	verdict := r.Verdict()
	s += verdict + "\n\n"
	if r.Header.Source != "" {
		s += fmt.Sprintf("Record: source %s, number %d, type %q\n", r.Header.Source, r.Header.Seq, r.Header.ContentType)
		s += fmt.Sprintf("Received by the store: %s (by its clock)\n", fmtTime(time.Unix(0, r.Header.ReceivedAt)))
		s += fmt.Sprintf("Digest: %x\n", r.Digest)
	}
	if !r.Lower.IsZero() || !r.Upper.IsZero() {
		s += fmt.Sprintf("Entered the chain between T1 = %s and T2 = %s (TSA time-stamps)\n", fmtTime(r.Lower), fmtTime(r.Upper))
	}
	if g := r.Gateway; g != nil {
		s += fmt.Sprintf("Gateway journal entry: seq %d, session %s, hash %s\n", g.Seq, g.Session, short(g.Hash))
		if c := r.GatewayCheckpoint; c != nil {
			s += fmt.Sprintf("Covered by gateway checkpoint seq %d\n", c.Seq)
		}
	}
	s += "\nChecks:\n"
	for _, c := range r.Checks {
		mark := "✔"
		if !c.OK {
			mark = "✘"
		}
		s += fmt.Sprintf("  %s %s", mark, c.Name)
		if c.Detail != "" {
			s += " — " + c.Detail
		}
		s += "\n"
	}
	if r.BodyOpened {
		if utf8.Valid(r.Body) {
			s += "\nBody:\n" + string(r.Body) + "\n"
		} else {
			s += fmt.Sprintf("\nBody: %d bytes (binary)\n", len(r.Body))
		}
	}
	s += "\nWhat this bundle does not prove:\n"
	for _, n := range r.Notes() {
		s += "  — " + n + "\n"
	}
	return Printable(s) + "\n" + verdict + "\n"
}

// Printable экранирует управляющие символы (C0, C1, DEL) и символы
// управления направлением текста, кроме перевода строки и табуляции: текст
// из пакета не управляет терминалом проверяющего.
func Printable(s string) string {
	var b strings.Builder
	for _, c := range s {
		switch {
		case c == '\n' || c == '\t':
			b.WriteRune(c)
		case unicode.IsControl(c) || unicode.Is(unicode.Bidi_Control, c):
			fmt.Fprintf(&b, "\\u%04x", c)
		default:
			b.WriteRune(c)
		}
	}
	return b.String()
}
