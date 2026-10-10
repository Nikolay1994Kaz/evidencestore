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

	"evidencestore/internal/auditchain"
	"evidencestore/internal/evidence"
	"evidencestore/internal/gateway"
	"evidencestore/internal/keyring"
	"evidencestore/internal/tsa"
)

// Version — версия формата пакета.
const Version = 1

// HeadDomain — домен хэша головы, который уходит в TSA.
const HeadDomain = "evidencestore/head/v1"

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

// ParseEvidenceLeaf разбирает предмет листа улики: позиция и отпечаток.
func ParseEvidenceLeaf(l auditchain.Leaf) (pos uint64, digest [32]byte, err error) {
	if l.Type != auditchain.EventEvidence || len(l.Payload) != 8+32 {
		return 0, digest, errors.New("proof: not an evidence leaf")
	}
	copy(digest[:], l.Payload[8:])
	return binary.BigEndian.Uint64(l.Payload), digest, nil
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
}

func (b Bundle) JSON() ([]byte, error) { return json.MarshalIndent(b, "", " ") }

func Parse(data []byte) (Bundle, error) {
	var b Bundle
	if err := json.Unmarshal(data, &b); err != nil {
		return b, fmt.Errorf("proof: %w", err)
	}
	if b.Version != Version {
		return b, fmt.Errorf("proof: bundle version %d, supported %d", b.Version, Version)
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
	// LegacyEnvelope — конверт старого формата (EV1): ключ записи не связан с
	// отпечатком улики.
	LegacyEnvelope bool
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
		n = append(n, "нет метки TSA над головой после улики: время подтверждено только подписью хранилища")
	}
	if r.Lower.IsZero() {
		n = append(n, "нет метки TSA раньше улики: нижняя граница времени не доказана")
	}
	if r.LegacyEnvelope {
		n = append(n, "конверт старого формата (EV1): выданный ключ записи не связан с отпечатком улики")
	}
	switch {
	case r.BodyOpened:
	case r.BodyKey:
		n = append(n, "тело не вскрыто: выданный ключ записи к телу не подошёл (см. проверки)")
	default:
		n = append(n, "тело не вскрыто: ключ записи не выдан или ключ месяца уничтожен (стирание по сроку)")
	}
	n = append(n, r.gatewayNotes()...)
	n = append(n, "подпись хранилища доказывает, что ЭТОТ экземпляр подписал голову; против переписывания всей цепи её владельцем работает только метка TSA")
	n = append(n, "доказано, что такие байты пришли от источника и не менялись; правдивость их содержимого не доказывается")
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
	if !add("улика разбирается", err, "") {
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
			err = errors.New("отпечаток в листе не совпадает с байтами улики")
		case leaf.Scope != sealed.Source || leaf.Subject != strconv.FormatUint(sealed.Seq, 10):
			err = fmt.Errorf("лист про %s/%s, а улика %s/%d", leaf.Scope, leaf.Subject, sealed.Source, sealed.Seq)
		case leaf.UnixNano != sealed.ReceivedAt:
			err = errors.New("время приёма в листе не совпадает с уликой")
		}
	}
	add("лист цепи описывает именно эту улику", err, fmt.Sprintf("позиция %d", pos))

	// 3. Звенья подряд и связаны хэшами.
	links, hashes, err := chainLinks(b.Links)
	if !add("звенья связаны хэшами без пропусков", err, fmt.Sprintf("%d звеньев", len(links))) {
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
			err = errors.New("подписанная голова не совпадает с последним звеном пакета")
		}
	}
	r.HeadSeq = b.Statement.HeadSeq
	add("голова подписана ключом хранилища", err, fmt.Sprintf("голова %d", b.Statement.HeadSeq))

	// 5. Путь Меркла от листа улики до корня звена n.
	r.LinkSeq = b.Inclusion.LinkSeq
	add("улика входит в звено цепи (путь Меркла)", checkInclusion(b.Inclusion, linkAt), fmt.Sprintf("звено %d", b.Inclusion.LinkSeq))

	// 6. Верхняя граница: TSA заверила голову m ≥ n. Без неё пакет — только
	// слово хранилища: держатель ключа подписи сочинит улику с любой датой.
	if b.Upper != nil {
		r.Upper, err = checkUpper(*b.Upper, b.Inclusion.LinkSeq, linkAt, trust.TSA)
		add("метка TSA над цепью после улики (не позже T2)", err, fmt.Sprintf("T2 = %s, голова %d", fmtTime(r.Upper), b.Upper.HeadSeq))
	} else if !trust.AllowNoTSA {
		add("метка TSA над цепью после улики (не позже T2)",
			errors.New("в пакете её нет: время и неизменность подтверждает только подпись хранилища (запросите пакет после следующей метки — evidencestore stamp; принять без неё — esverify -allow-no-tsa)"), "")
	}

	// 7. Нижняя граница: токен TSA лежит в цепи раньше звена улики.
	if b.Lower != nil {
		r.Lower, err = checkLower(*b.Lower, b.Inclusion.LinkSeq, linkAt, trust.TSA)
		add("метка TSA в цепи раньше улики (не раньше T1)", err, fmt.Sprintf("T1 = %s", fmtTime(r.Lower)))
	}

	// 8. Время приёма по нашим часам попадает между метками.
	if !r.Upper.IsZero() || !r.Lower.IsZero() {
		recv := time.Unix(0, sealed.ReceivedAt).UTC()
		err = nil
		// Улика записывается на диск и встаёт в цепь за миллисекунды после
		// приёма, но метка T1 могла лечь в цепь между этими моментами:
		// допускаем минуту перекоса.
		const skew = time.Minute
		if !r.Upper.IsZero() && recv.After(r.Upper.Add(time.Second)) {
			err = fmt.Errorf("время приёма %s позже метки T2 %s — часы хранилища врут", fmtTime(recv), fmtTime(r.Upper))
		}
		if !r.Lower.IsZero() && recv.Before(r.Lower.Add(-skew)) {
			err = fmt.Errorf("время приёма %s раньше метки T1 %s — часы хранилища врут", fmtTime(recv), fmtTime(r.Lower))
		}
		add("время приёма между метками TSA", err, fmtTime(recv))
	}

	// 9. Тело, если выдан ключ записи. Конверт EV2 несёт обязательство на
	// ключ записи под отпечатком улики: другой ключ (и другое тело при
	// том же отпечатке) не пройдёт.
	if len(b.DEK) > 0 {
		r.BodyKey = true
		r.LegacyEnvelope = keyring.LegacyEnvelope(sealed.Envelope)
		body, err := keyring.OpenWithDEK(sealed.Envelope, b.DEK)
		if add("тело вскрывается выданным ключом записи, ключ связан с отпечатком, тег GCM сходится", err, fmt.Sprintf("%d байт", len(body))) {
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
		add("вердикт гейтвея описывает эту улику", errors.New("улика из журнала гейтвея, а части gateway в пакете нет"), "")
	}
	return r
}

func chainLinks(in []Link) ([]auditchain.Record, [][32]byte, error) {
	if len(in) == 0 {
		return nil, nil, errors.New("в пакете нет звеньев")
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
				return nil, nil, fmt.Errorf("после звена %d идёт %d", links[i-1].Seq, r.Seq)
			}
			if r.PrevHash != hashes[i-1] {
				return nil, nil, fmt.Errorf("звено %d не ссылается на хэш звена %d — цепь подменена", r.Seq, links[i-1].Seq)
			}
		}
		links[i], hashes[i] = r, auditchain.Hash(r)
	}
	return links, hashes, nil
}

func checkInclusion(inc Inclusion, linkAt func(uint64) (auditchain.Record, [32]byte, bool)) error {
	link, _, ok := linkAt(inc.LinkSeq)
	if !ok {
		return fmt.Errorf("звена %d нет в пакете", inc.LinkSeq)
	}
	if link.Type != auditchain.EventBatch {
		return fmt.Errorf("звено %d не агрегат листьев", inc.LinkSeq)
	}
	p, err := auditchain.DecodeBatchPayload(link.Payload)
	if err != nil {
		return err
	}
	path := make([]auditchain.ProofStep, len(inc.Path))
	for i, s := range inc.Path {
		if len(s.Hash) != 32 {
			return errors.New("шаг пути неразбираем")
		}
		copy(path[i].Hash[:], s.Hash)
		path[i].SiblingLeft = s.Left
	}
	if !auditchain.VerifyProof(inc.Leaf.chain(), path, p.Root) {
		return fmt.Errorf("путь не сходится с корнем звена %d", inc.LinkSeq)
	}
	return nil
}

func checkUpper(u Upper, evidenceLink uint64, linkAt func(uint64) (auditchain.Record, [32]byte, bool), trust tsa.Trust) (time.Time, error) {
	if u.HeadSeq < evidenceLink {
		return time.Time{}, fmt.Errorf("метка над головой %d, а улика в звене %d — метка её не покрывает", u.HeadSeq, evidenceLink)
	}
	_, hash, ok := linkAt(u.HeadSeq)
	if !ok {
		return time.Time{}, fmt.Errorf("звена %d нет в пакете", u.HeadSeq)
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
		return time.Time{}, errors.New("нижняя граница — не лист метки TSA")
	}
	if inc.LinkSeq >= evidenceLink {
		return time.Time{}, fmt.Errorf("метка в звене %d, улика в звене %d — метка не раньше улики", inc.LinkSeq, evidenceLink)
	}
	if err := checkInclusion(inc, linkAt); err != nil {
		return time.Time{}, err
	}
	stamped, err := strconv.ParseUint(inc.Leaf.Subject, 10, 64)
	if err != nil {
		return time.Time{}, errors.New("лист метки без номера головы")
	}
	_, hash, ok := linkAt(stamped)
	if !ok {
		return time.Time{}, fmt.Errorf("звена %d, заверенного меткой, нет в пакете", stamped)
	}
	info, err := tsa.Verify(inc.Leaf.Payload, HeadImprint(stamped, hash), trust)
	if err != nil {
		return time.Time{}, err
	}
	return info.GenTime.UTC(), nil
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
		return "ПРОВЕРКА ПРОЙДЕНА"
	}
	return "ПРОВЕРКА НЕ ПРОЙДЕНА"
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
		s += fmt.Sprintf("Улика: источник %s, номер %d, тип %q\n", r.Header.Source, r.Header.Seq, r.Header.ContentType)
		s += fmt.Sprintf("Принята хранилищем: %s (по его часам)\n", fmtTime(time.Unix(0, r.Header.ReceivedAt)))
		s += fmt.Sprintf("Отпечаток: %x\n", r.Digest)
	}
	if !r.Lower.IsZero() || !r.Upper.IsZero() {
		s += fmt.Sprintf("Вошла в цепь между T1 = %s и T2 = %s (по меткам TSA)\n", fmtTime(r.Lower), fmtTime(r.Upper))
	}
	if g := r.Gateway; g != nil {
		s += fmt.Sprintf("Запись журнала гейтвея: seq %d, сессия %s, хэш %s\n", g.Seq, g.Session, short(g.Hash))
		if c := r.GatewayCheckpoint; c != nil {
			s += fmt.Sprintf("Накрыта контрольной точкой гейтвея seq %d\n", c.Seq)
		}
	}
	s += "\nПроверки:\n"
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
			s += "\nТело:\n" + string(r.Body) + "\n"
		} else {
			s += fmt.Sprintf("\nТело: %d байт (двоичное)\n", len(r.Body))
		}
	}
	s += "\nЧего этот пакет не доказывает:\n"
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
