package proof

import (
	"encoding/json"
	"errors"
	"fmt"
	"maps"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/Nikolay1994Kaz/evidencestore/internal/auditchain"
	"github.com/Nikolay1994Kaz/evidencestore/internal/evidence"
	"github.com/Nikolay1994Kaz/evidencestore/internal/gateway"
)

// Пакет по источнику (DECISIONS, п. 28): записи одного источника за окно и
// доказательство, что других нет, без записей чужих систем.
//
//	нижний край    хвосты одни в звене, которое заверила нижняя метка (T1):
//	               хэш последнего листа S к этому месту — начало цепочки
//	записи S       листья с путями Меркла (чужие листья — только хэши);
//	               каждый ссылается на хэш прежнего листа S
//	T2             лист токена первой метки позже окна — закрывающей
//	верхний край   хвосты следующей метки, после токена T2, — конец цепочки
//
// Ссылки сходятся от начала до конца — значит, между краями S не положил в
// цепь ничего, кроме этих записей: выброшенную запись выдала бы ссылка
// следующей. Нижнему краю нужна верхняя граница времени — её даёт метка над
// ним. Верхнему нужна нижняя: всё, что легло в цепь после него, легло после
// окна. Метка над краем её не даёт — метку над старым звеном можно взять
// когда угодно и дописать в цепь, ничего не переписывая. Даёт её только
// токен, лежащий в цепи раньше края: всё, что за ним, легло позже его
// времени. Края заверены метками (и свидетелем): сдвинуть их можно, только
// переписав цепь. На слове хранилища — только то, что хвосты оно записало
// честно, когда ставило метки.
//
// Участок между краями шире окна: края стоят на метках, а окно — где спросили.
// Полноте хватает листьев, поэтому записи вне окна идут листом: номер, время,
// отпечаток. Улики с ключами — только у записей окна (P-46).
//
// Пакет по субъекту (п. 32) — та же цепочка: улика приложена у всех записей
// окна, ключ — только у записей с меткой субъекта. Проверка идёт по заголовкам
// улик: в них видно, чья метка, а тела остальных закрыты.

// SourceKind — вид пакета по источнику; версия та же, что у пакета за окно.
const SourceKind = "source"

// SourceEdge — край пакета: звено Head, в котором одни хвосты источников,
// лист токена метки TSA над ним — с путём Меркла, в звене цепи после края, —
// и раскрытие хвоста своего источника (nil — источника там нет: записей ещё
// не было). Метка над краем заверяет его и даёт верхнюю границу его времени;
// от звена её токена сверяется свидетель.
type SourceEdge struct {
	Head  uint64    `json:"head"`
	Tails *Leaf     `json:"tails,omitempty"`
	Token Inclusion `json:"token"`
	Open  *TailOpen `json:"open,omitempty"`
}

// SubjectClaim — о ком пакет по субъекту: поле записи, его значение и метки,
// которые хранилище за ними считает, по месяцу на метку. Сам проверяющий метку
// не посчитает: ключ меток выведен из ключа месяца и лежит у хранилища. Поле
// закреплено в заголовке каждой записи под меткой. Значение привязывает
// открытое тело: поле в нём обязано назвать этого субъекта. Тела нет — не
// привязывает ничто, и отчёт это говорит.
//
// Метки нет у месяца, чей ключ уничтожен (её не посчитает никто, само хранилище
// тоже) или ждёт уничтожения (хранилище её не считает, а отмена уничтожения
// вернёт): записи такого месяца идут листом, и чьи они — не сказать.
type SubjectClaim struct {
	Field  string         `json:"field"`
	Value  string         `json:"value"`
	Labels []SubjectLabel `json:"labels,omitempty"`
}

// SubjectLabel — метка субъекта в одном месяце источника: Scope —
// «источник/ГГГГ-ММ», тот же скоуп, что у ключа месяца записи.
type SubjectLabel struct {
	Scope string `json:"scope"`
	Tag   []byte `json:"tag"`
}

// names — заявление называет метку для месяца scope.
func (c *SubjectClaim) names(scope string) bool {
	return slices.ContainsFunc(c.Labels, func(l SubjectLabel) bool { return l.Scope == scope })
}

// SourceRecord — запись источника: лист с путём Меркла, лист вердикта
// хранилища для записи журнала гейтвея и, по запросу, улика с ключом записи.
type SourceRecord struct {
	Leaf     Inclusion  `json:"leaf"`
	Verdict  *Inclusion `json:"verdict,omitempty"`
	Evidence []byte     `json:"evidence,omitempty"`
	DEK      []byte     `json:"dek,omitempty"`
}

// SourceBundle — пакет по источнику за окно.
type SourceBundle struct {
	Version int    `json:"v"`
	Kind    string `json:"kind"`
	Source  string `json:"source"`
	// From, To — окно, о котором спросили (время приёма); аудитор сверяет
	// пакет со своим (esverify -from -to).
	From time.Time `json:"from"`
	To   time.Time `json:"to"`
	// Lower — нижний край; Head == 0 — с начала цепи, цепочка источника
	// начинается с нулей. Upper — верхний край.
	Lower SourceEdge `json:"lower"`
	Upper SourceEdge `json:"upper"`
	// Closing — лист токена закрывающей метки (T2: первая позже конца окна
	// больше чем на WindowEdge) с путём Меркла, в звене раньше верхнего края.
	Closing Inclusion `json:"closing"`
	// Links — звенья подряд от нижнего края (или первого звена цепи) до
	// звена токена верхней метки, а с -to-head и дальше; последнее — голова
	// Checkpoint.
	Links []Link `json:"links"`
	// Frontier — граница дерева звеньев перед первым звеном пакета.
	Frontier [][]byte `json:"frontier,omitempty"`
	// Records — все записи источника между краями, в порядке цепи.
	Records []SourceRecord `json:"records,omitempty"`
	// Subject — пакет открывает записи одного субъекта (п. 32); nil — нет.
	Subject *SubjectClaim `json:"subject,omitempty"`
	// WithKeys — пакет просили с ключами (-dek). Месяц с закрытым ключом
	// хранилище отдаёт листом, и пакет, где так все записи окна, без этой
	// пометки не отличить от пакета без -dek. Пометка не подписана и меняет
	// только заметки, не вердикт (P-80).
	WithKeys   bool       `json:"with_keys,omitempty"`
	Checkpoint Checkpoint `json:"checkpoint"`
	// Cosignatures — подписи свидетелей C2SP над головой не раньше звена
	// токена верхнего края (cosigned.go).
	Cosignatures []Cosignature `json:"cosignatures,omitempty"`
	// Archive — метки второй службы над головами не раньше токенов пакета
	// (revoked.go).
	Archive []ArchiveStamp `json:"archive,omitempty"`
}

// ParseSource разбирает пакет по источнику.
func ParseSource(data []byte) (SourceBundle, error) {
	var b SourceBundle
	if err := json.Unmarshal(data, &b); err != nil {
		return b, fmt.Errorf("proof: %w", err)
	}
	if b.Kind != SourceKind || b.Version != WindowVersion {
		return b, fmt.Errorf("proof: bundle kind %q version %d, supported %q version %d%s", b.Kind, b.Version, SourceKind, WindowVersion, olderRelease(b.Version, WindowVersion, unreleasedWindowVersions...))
	}
	return b, nil
}

// SourceReport — итог проверки пакета по источнику.
type SourceReport struct {
	Checks []Check
	Source string
	// From, To — окно, с которым сверялись; FromBundle — окно взято из пакета.
	From, To   time.Time
	FromBundle bool
	// Lower, Upper — время нижней и закрывающей меток (T1, T2); UpperEdge —
	// метки над верхним краем; FromStart — с начала цепи, нижней метки нет.
	Lower, Upper time.Time
	UpperEdge    time.Time
	FromStart    bool
	LowerHead    uint64
	UpperHead    uint64
	HeadSeq      uint64
	// Records — записей источника в пакете; InWindow — из них со временем
	// приёма в окне; FirstSeq, LastSeq — крайние номера; Holes — номера между
	// ними, которых в цепи нет (ссылки там не рвутся).
	Records           int
	InWindow          int
	FirstSeq, LastSeq uint64
	Holes             []SeqRange
	Attached          int
	Bodies            []WindowBody
	// SourceNamed — верхние хвосты называют источник. Нет — под этим именем
	// хранилище записей не называло, и ничем другим имя в пакете не подтверждено.
	SourceNamed bool
	// Subject, SubjectField — о ком пакет по субъекту. SubjectRecords — записей
	// окна под его меткой, SubjectOpened — из них открыто и названо телом: только
	// они привязывают метку к субъекту; SubjectKeyless — без ключа записи,
	// SubjectOthers — закрытых записей окна с чужой меткой, SubjectUnlabeled —
	// без метки. Метку месяца привязывает только открытое тело ЭТОГО месяца:
	// SubjectRecords — записи под метками месяцев, где тело открыто,
	// SubjectUnbound — под метками месяцев без открытого тела (чьи — не
	// доказано), SubjectUnboundMonths — эти месяцы. SubjectNoLabel — записи
	// месяцев, для которых пакет метки не называет, SubjectNoLabelMonths — эти
	// месяцы: хранилище так поступает со стёртым месяцем, но пакет этого не
	// доказывает.
	Subject              string
	SubjectField         string
	SubjectLabel         string // метки из заявления, hex с месяцем: сравнить с пакетом, где тело открыто
	SubjectRecords       int
	SubjectOpened        int
	SubjectKeyless       int
	SubjectOthers        int
	SubjectUnlabeled     int
	SubjectUnbound       int
	SubjectUnboundMonths []string
	SubjectNoLabel       int
	SubjectNoLabelMonths []string
	// SubjectUnconfirmedMonths — месяцы окна (по записям окна), где не открыто
	// ни одно тело субъекта: чьи там записи, пакет не показывает, и пакет,
	// назвавший для такого месяца чужую или выдуманную метку, выглядит так же,
	// как честный пакет без записей субъекта в этом месяце (P-75).
	SubjectUnconfirmedMonths []string
	// GatewayRecords — записей журнала гейтвея (с вердиктом хранилища);
	// GatewayBroken — номера тех, что хранилище при приёме признало
	// поломанными.
	GatewayRecords int
	GatewayBroken  []uint64
	// withheld — тел поломанных записей гейтвея, не вскрытых нарочно: ключ
	// у них есть, и «нет ключа записи» о них неверно.
	withheld int
	// outside — открытых тел вне окна аудитора: в отчёт и в файлы они не идут.
	outside int
	// LeafOnly — записей окна, пришедших листом: в их месяце пакет не несёт ни
	// одной улики (так хранилище отдаёт месяц, чей ключ уничтожен или ждёт
	// уничтожения, P-77, P-80); LeafOnlyMonths — эти месяцы.
	LeafOnly       int
	LeafOnlyMonths []string
	WitnessChecked bool
	WitnessHead    uint64
	WitnessNone    bool
	WitnessFork    uint64
	WitnessRefused int
	// WitnessReceived, WitnessUntimed — как у пакета одной улики (P-21).
	WitnessReceived time.Time
	WitnessUntimed  bool
	// CosignChecked, Cosigned, CosignUnknown, CosignCarried — как у пакета
	// одной улики: закрепляется звено токена верхнего края.
	CosignChecked bool
	Cosigned      []CosignedHead
	CosignUnknown int
	CosignCarried int
	// TSANotes — заметки об отзыве сертификатов служб меток (revoked.go).
	TSANotes []string
}

// Withheld — сколько тел поломанных записей гейтвея не вскрыто нарочно.
func (r SourceReport) Withheld() int { return r.withheld }

// Keyless — улик окна без ключа записи (у пакета не по субъекту): их тела
// не открыты, и -bodies о них говорит (T-03).
func (r SourceReport) Keyless() int { return r.Attached - len(r.Bodies) - r.withheld - r.outside }

// Valid — все проверки прошли.
func (r SourceReport) Valid() bool {
	for _, c := range r.Checks {
		if !c.OK {
			return false
		}
	}
	return len(r.Checks) > 0
}

// Verdict — итог одной строкой.
func (r SourceReport) Verdict() string {
	if r.Valid() {
		return "VERIFIED"
	}
	return "NOT VERIFIED"
}

// VerifySource проверяет пакет по источнику. from, to — окно аудитора; оба
// нуля — сверка с окном из пакета. Итог — Valid().
func VerifySource(b SourceBundle, trust Trust, from, to time.Time) SourceReport {
	r := SourceReport{Source: b.Source, From: from, To: to, LowerHead: b.Lower.Head, UpperHead: b.Upper.Head}
	if from.IsZero() && to.IsZero() {
		r.From, r.To, r.FromBundle = b.From, b.To, true
	}
	if b.Subject != nil {
		r.Subject, r.SubjectField, r.SubjectLabel = b.Subject.Value, b.Subject.Field, labelsText(b.Subject.Labels)
	}
	add := func(name string, err error, detail string) bool {
		c := Check{Name: name, OK: err == nil, Detail: detail}
		if err != nil {
			c.Detail = err.Error()
		}
		r.Checks = append(r.Checks, c)
		return err == nil
	}

	// 1. Звенья подряд и связаны хэшами; корни дерева звеньев на их номерах.
	links, rootAt, err := chainLinks(b.Links, b.Frontier)
	if !add("the links are chained by hash with no gaps", err, fmt.Sprintf("%d links", len(links))) {
		return r
	}
	linkAt := func(seq uint64) (auditchain.Record, [32]byte, bool) {
		root, ok := rootAt(seq)
		if !ok {
			return auditchain.Record{}, [32]byte{}, false
		}
		return links[seq-links[0].Seq], root, true
	}

	// 2. Голова подписана закреплённым ключом и сходится со звеньями пакета.
	r.HeadSeq = b.Checkpoint.Size
	add("the head is signed with the store key", checkHead(b.Checkpoint, trust.StoreKey, links, rootAt), fmt.Sprintf("head %d", b.Checkpoint.Size))
	sc := newStampCheck(trust)

	// 3. Нижний край: хвосты — единственный лист звена, которое заверила
	// нижняя метка; с начала цепи — первое звено и нули.
	var start [32]byte
	if b.Lower.Head == 0 {
		r.FromStart = true
		err = nil
		if links[0].Seq != 1 || links[0].PrevHash != ([32]byte{}) {
			err = fmt.Errorf("the bundle is said to start at the beginning of the chain, but it starts at link %d", links[0].Seq)
		}
		add("the bundle starts at the beginning of the chain", err, "there is no time-stamp before the window")
	} else {
		start, r.Lower, err = sourceEdge(b.Source, b.Lower, linkAt, sc, "the time-stamp of the lower tails")
		add("the lower tails are the only leaf of the link the lower time-stamp certifies (T1)", err,
			fmt.Sprintf("T1 = %s, link %d", fmtTime(r.Lower), b.Lower.Head))
	}

	// 4. Верхний край — хвосты, заверенные своей меткой, после токена
	// закрывающей метки T2: всё, что S положил в цепь до T2, — до этих
	// хвостов. Свежая метка над старым звеном хвостов, дописанная в конец
	// цепи, краем его не делает: токена позже окна перед ним нет.
	end, edgeAt, err := sourceEdge(b.Source, b.Upper, linkAt, sc, "the time-stamp of the upper tails")
	if err == nil {
		r.Upper, err = closingStamp(b, linkAt, sc)
	}
	r.UpperEdge = edgeAt
	r.SourceNamed = b.Upper.Open != nil
	add("the upper tails are the only leaf of a link certified by a time-stamp, and lie after the token of the time-stamp that closes the window (T2)", err,
		fmt.Sprintf("T2 = %s, token in link %d; tails in link %d", fmtTime(r.Upper), b.Closing.LinkSeq, b.Upper.Head))

	// 5. Окно строго между метками — те же допуски, что у пакета за окно.
	add("the time-stamps bracket the window", windowBracket(r.From, r.To, r.Lower, r.Upper), fmt.Sprintf("%s – %s", fmtTime(r.From), fmtTime(r.To)))

	// 6. Записи источника: каждая ссылается на прежнюю, и цепочка идёт от
	// нижних хвостов до верхних.
	add("the records are the whole chain of the source between the tails", sourceChain(b, linkAt, start, end, &r),
		fmt.Sprintf("%d records", len(b.Records)))

	// 7. Время приёма записей — между метками краёв: запись после нижних
	// хвостов принята позже T1 − WindowEdge (запрос к TSA короче
	// StampLatency), запись до верхних — не позже времени их метки + 1 с.
	add("every receive time lies between the time-stamps of the edges", sourceTimes(b, r.Lower, r.UpperEdge), "")

	// 8. Вердикты хранилища по записям журнала гейтвея. Вид источника —
	// из раскрытия верхнего хвоста, под обязательством: у журнала гейтвея
	// вердикт обязан быть у каждой записи, и пакет без улик его не потеряет.
	gw := b.Upper.Open != nil && b.Upper.Open.Kind == gateway.ContentType
	var kindErr error
	if b.Lower.Open != nil && b.Upper.Open != nil && b.Lower.Open.Kind != b.Upper.Open.Kind {
		kindErr = fmt.Errorf("the tails name the kind of %s %q at the lower edge and %q at the upper one", b.Source, b.Lower.Open.Kind, b.Upper.Open.Kind)
	}
	if gw || kindErr != nil || slices.ContainsFunc(b.Records, func(rec SourceRecord) bool { return rec.Verdict != nil }) {
		err := kindErr
		if err == nil {
			err = sourceVerdicts(b, gw, linkAt, &r)
		}
		add("the store's verdicts on gateway journal records are in the chain next to them", err,
			fmt.Sprintf("%d gateway records, %d broken at intake", r.GatewayRecords, len(r.GatewayBroken)))
	}

	// 9. Приложенные улики сверяются со своими листами, тела вскрываются;
	// улика журнала гейтвея — только с вердиктом. Пакет с уликами обязан
	// приложить все записи окна; пакет по субъекту — и без единой улики: иначе
	// снятые улики выглядели бы как «у него записей нет».
	if b.Subject != nil || b.WithKeys || slices.ContainsFunc(b.Records, func(rec SourceRecord) bool { return len(rec.Evidence) > 0 }) {
		add("the records attached match their leaves, and their bodies open with their record keys", sourceAttached(b, &r),
			fmt.Sprintf("%d records, %d bodies opened", r.Attached, len(r.Bodies)))
	}

	// 10. Пакет по субъекту: открыты записи с его меткой и только они, и в
	// открытых телах назван он.
	if b.Subject != nil {
		add("record keys come only with the records under the label, and every open body names the subject", sourceSubject(b, &r),
			r.subjectCounts())
	}

	// 11. Свидетель голов — как у остальных пакетов.
	if trust.Witness != nil {
		var wr Report
		checkWitness(trust.Witness, trust.StoreKey, b.Upper.Token.LinkSeq, links, rootAt, &wr, add)
		r.WitnessChecked, r.WitnessHead, r.WitnessNone, r.WitnessFork, r.WitnessRefused = wr.WitnessChecked, wr.WitnessHead, wr.WitnessNone, wr.WitnessFork, wr.WitnessRefused
		r.WitnessReceived, r.WitnessUntimed = wr.WitnessReceived, wr.WitnessUntimed
	}
	r.CosignCarried = len(b.Cosignatures)
	if len(trust.Cosigners) > 0 {
		r.CosignChecked = true
		var err error
		r.Cosigned, r.CosignUnknown, err = checkCosigned(b.Cosignatures, trust.Cosigners, trust.StoreKey, b.Upper.Token.LinkSeq, links, rootAt)
		add(cosignCheckName, err, cosignDetail(r.Cosigned))
	}
	sc.finish(b.Archive, b.Cosignatures, trust.Cosigners, trust.StoreKey, links[len(links)-1].Seq, rootAt, add)
	r.TSANotes = sc.notes
	return r
}

// sourceEdge — край пакета: в звене e.Head один лист — хвосты, метка, чей
// токен лежит в цепи листом e.Token, заверяет это звено. Возвращает хэш
// последнего листа источника к этому месту (нули — записей ещё не было) и
// время метки.
func sourceEdge(source string, e SourceEdge, linkAt func(uint64) (auditchain.Record, [32]byte, bool), sc *stampCheck, what string) ([32]byte, time.Time, error) {
	link, root, ok := linkAt(e.Head)
	switch {
	case !ok:
		return [32]byte{}, time.Time{}, fmt.Errorf("link %d is not in the bundle", e.Head)
	case e.Tails == nil:
		return [32]byte{}, time.Time{}, fmt.Errorf("the bundle carries no tails for link %d", e.Head)
	}
	p, err := batchOf(link)
	if err != nil {
		return [32]byte{}, time.Time{}, err
	}
	tails := e.Tails.chain()
	if auditchain.MerkleRoot([]auditchain.Leaf{tails}) != p.Root {
		return [32]byte{}, time.Time{}, fmt.Errorf("link %d does not hold just the tails", e.Head)
	}
	last, err := OpenTail(tails, source, e.Open)
	if err != nil {
		return [32]byte{}, time.Time{}, fmt.Errorf("the tails: %w", err)
	}
	if err := checkInclusion(e.Token, linkAt); err != nil {
		return [32]byte{}, time.Time{}, fmt.Errorf("the token of the time-stamp: %w", err)
	}
	if e.Token.LinkSeq <= e.Head {
		return [32]byte{}, time.Time{}, fmt.Errorf("the token of the time-stamp lies in link %d, not after link %d it certifies", e.Token.LinkSeq, e.Head)
	}
	// Тип и номер в листе — сверка для ясного отказа: метка над этим звеном
	// проверяется подписью TSA ниже.
	if tok := e.Token.Leaf.chain(); tok.Type != auditchain.EventTimestamp || tok.Subject != strconv.FormatUint(e.Head, 10) {
		return [32]byte{}, time.Time{}, fmt.Errorf("the leaf in link %d is not a time-stamp token over link %d", e.Token.LinkSeq, e.Head)
	}
	info, err := sc.verify(e.Token.Leaf.chain().Payload, e.Head, root, e.Token.LinkSeq, fmt.Sprintf("%s (token in link %d)", what, e.Token.LinkSeq))
	if err != nil {
		return [32]byte{}, time.Time{}, fmt.Errorf("the time-stamp: %w", err)
	}
	tl, _, _ := linkAt(e.Token.LinkSeq)
	if err := tokenLinkTime(tl, info.GenTime.UTC()); err != nil {
		return [32]byte{}, time.Time{}, err
	}
	return last, info.GenTime.UTC(), nil
}

// closingStamp — закрывающая метка окна: лист её токена с путём Меркла в
// звене раньше верхнего края, метка заверяет голову из пакета. Возвращает её
// время (T2).
func closingStamp(b SourceBundle, linkAt func(uint64) (auditchain.Record, [32]byte, bool), sc *stampCheck) (time.Time, error) {
	c := b.Closing
	if err := checkInclusion(c, linkAt); err != nil {
		return time.Time{}, fmt.Errorf("the token of the time-stamp that closes the window: %w", err)
	}
	if c.LinkSeq >= b.Upper.Head {
		return time.Time{}, fmt.Errorf("the token of the time-stamp that closes the window lies in link %d, not before the upper tails in link %d", c.LinkSeq, b.Upper.Head)
	}
	tok := c.Leaf.chain()
	head, err := strconv.ParseUint(tok.Subject, 10, 64)
	if tok.Type != auditchain.EventTimestamp || err != nil {
		return time.Time{}, fmt.Errorf("the leaf in link %d is not a time-stamp token", c.LinkSeq)
	}
	_, root, ok := linkAt(head)
	if !ok {
		return time.Time{}, fmt.Errorf("link %d, which the time-stamp that closes the window certifies, is not in the bundle", head)
	}
	info, err := sc.verify(tok.Payload, head, root, c.LinkSeq, fmt.Sprintf("time-stamp T2 that closes the window (token in link %d)", c.LinkSeq))
	if err != nil {
		return time.Time{}, fmt.Errorf("the time-stamp that closes the window: %w", err)
	}
	cl, _, _ := linkAt(c.LinkSeq)
	if err := tokenLinkTime(cl, info.GenTime.UTC()); err != nil {
		return time.Time{}, err
	}
	return info.GenTime.UTC(), nil
}

// windowBracket — окно строго между метками с допусками времени приёма:
// запись до нижнего края законно получает время до T1 + 1 с включительно,
// запись после верхнего — позже T2 − WindowEdge, и ни та, ни другая в окно
// не попадёт. lower нулевое — нижней метки нет (с начала цепи).
func windowBracket(from, to, lower, upper time.Time) error {
	switch {
	case from.IsZero() || to.IsZero():
		return errors.New("no window to check against: give one with esverify -from and -to")
	case to.Before(from):
		return fmt.Errorf("the window ends at %s, before it starts at %s", fmtTime(to), fmtTime(from))
	case !lower.IsZero() && !from.After(lower.Add(ReceiveSlack)):
		return fmt.Errorf("the window starts at %s, but the bundle is complete only from a second after time-stamp T1 %s", fmtTime(from), fmtTime(lower))
	case upper.IsZero() || !to.Before(upper.Add(-WindowEdge)):
		return fmt.Errorf("the window ends at %s, but the bundle is complete only up to %s before time-stamp T2 %s", fmtTime(to), WindowEdge, fmtTime(upper))
	}
	return nil
}

// sourceChain проверяет записи источника: каждая — лист улики этого
// источника со ссылкой, и ссылки идут от start до end без разрыва.
//
// Порядок и места записей отдельно не проверяются: ссылка задаёт порядок
// цепи, а до нижних хвостов и в звеньях краёв записи нет (там одни хвосты).
// Запись за верхним краем проверяется — иначе её выдало бы только
// несовпадение конца, с неверным объяснением.
func sourceChain(b SourceBundle, linkAt func(uint64) (auditchain.Record, [32]byte, bool), start, end [32]byte, r *SourceReport) error {
	expect := start
	var seqs []uint64
	for i, rec := range b.Records {
		l := rec.Leaf.Leaf.chain()
		seq, serr := strconv.ParseUint(l.Subject, 10, 64)
		prev, linked := EvidencePrev(l)
		switch {
		case l.Type != auditchain.EventEvidence || l.Scope != b.Source || serr != nil:
			return fmt.Errorf("record %d of the bundle is not a record of %s", i+1, b.Source)
		case !linked:
			return fmt.Errorf("record %s/%d has no link to the previous record of its source: it was written before the store linked them; ask for a window bundle", b.Source, seq)
		}
		if err := checkInclusion(rec.Leaf, linkAt); err != nil {
			return fmt.Errorf("record %s/%d: %w", b.Source, seq, err)
		}
		switch {
		case rec.Leaf.LinkSeq > b.Upper.Head:
			return fmt.Errorf("record %s/%d lies in link %d, after the upper tails in link %d", b.Source, seq, rec.Leaf.LinkSeq, b.Upper.Head)
		case prev != expect:
			return fmt.Errorf("record %s/%d does not refer to the record before it: a record of %s between them is left out", b.Source, seq, b.Source)
		}
		expect = auditchain.LeafHash(l)
		seqs = append(seqs, seq)
		r.Records++
		if recv := time.Unix(0, l.UnixNano).UTC(); !recv.Before(r.From) && !recv.After(r.To) {
			r.InWindow++
		}
	}
	if expect != end {
		return fmt.Errorf("the last record does not match the upper tails: records of %s after it are left out", b.Source)
	}
	// Номер в верхнем раскрытии — номер того же листа: последней записи или,
	// без записей, нижнего раскрытия.
	var last uint64
	if b.Lower.Open != nil {
		last = b.Lower.Open.Seq
	}
	if n := len(seqs); n > 0 {
		last = seqs[n-1]
	}
	if b.Upper.Open != nil && b.Upper.Open.Seq != last {
		return fmt.Errorf("the upper tails name record %d of %s as the last, but the chain of its records ends at %d", b.Upper.Open.Seq, b.Source, last)
	}
	if len(seqs) > 0 {
		slices.Sort(seqs)
		r.FirstSeq, r.LastSeq = seqs[0], seqs[len(seqs)-1]
		r.Holes = unexplained(slices.Compact(seqs), nil)
	}
	return nil
}

// sourceTimes — время приёма каждой записи между метками краёв (нулевая
// метка — края нет: с начала цепи).
func sourceTimes(b SourceBundle, lower, upper time.Time) error {
	for _, rec := range b.Records {
		l := rec.Leaf.Leaf.chain()
		recv := time.Unix(0, l.UnixNano).UTC()
		switch {
		case !upper.IsZero() && recv.After(upper.Add(ReceiveSlack)):
			return fmt.Errorf("record %s/%s: receive time %s is later than %s, the time-stamp of the upper edge", b.Source, l.Subject, fmtTime(recv), fmtTime(upper))
		case !lower.IsZero() && !recv.After(lower.Add(-WindowEdge)):
			return fmt.Errorf("record %s/%s: receive time %s is not later than %s before %s, the time-stamp of the lower edge", b.Source, l.Subject, fmtTime(recv), WindowEdge, fmtTime(lower))
		}
	}
	return nil
}

// sourceVerdicts проверяет листы вердиктов: каждый — в цепи, о той же улике
// того же источника; у журнала гейтвея (gw) вердикт обязан быть у каждой
// записи. Поломанные — в отчёт.
func sourceVerdicts(b SourceBundle, gw bool, linkAt func(uint64) (auditchain.Record, [32]byte, bool), r *SourceReport) error {
	for _, rec := range b.Records {
		l := rec.Leaf.Leaf.chain()
		if rec.Verdict == nil {
			if gw {
				return fmt.Errorf("record %s/%s lacks the store's verdict, and the tails name %s a gateway journal (if the source became one inside the window, ask for a window after the switch)", b.Source, l.Subject, b.Source)
			}
			continue
		}
		pos, _, err := ParseEvidenceLeaf(l)
		if err != nil {
			return fmt.Errorf("record %s/%s: %w", b.Source, l.Subject, err)
		}
		v := rec.Verdict.Leaf.chain()
		vpos, verdict, err := ParseGatewayLeaf(v)
		switch {
		case err != nil:
			return fmt.Errorf("record %s/%s: %w", b.Source, l.Subject, err)
		case vpos != pos || v.Scope != l.Scope || v.Subject != l.Subject:
			return fmt.Errorf("the verdict attached to record %s/%s is about another record", b.Source, l.Subject)
		}
		if err := checkInclusion(*rec.Verdict, linkAt); err != nil {
			return fmt.Errorf("the verdict on record %s/%s: %w", b.Source, l.Subject, err)
		}
		r.GatewayRecords++
		if !verdict.Clean() {
			seq, _ := strconv.ParseUint(l.Subject, 10, 64)
			r.GatewayBroken = append(r.GatewayBroken, seq)
		}
	}
	return nil
}

// sourceAttached сверяет приложенные улики со своими листами и вскрывает
// тела. Улика журнала гейтвея без вердикта не принимается: проверки гейтвея
// у неё в пакете нет, а README обещает, что такой пакет не проходит.
//
// Запись окна без улики — отказ: на такой пакет полагаются как на все записи
// окна, и снятая улика прятала бы тело неудобной записи. Записи вне окна идут
// листом; окно здесь — аудитора: шире окна пакета — и улик не хватит.
func sourceAttached(b SourceBundle, r *SourceReport) error {
	var leaves []auditchain.Leaf
	var attached []WindowRecord
	// Месяцы, в которых пакет несёт улику хоть одной записи: там улика
	// обязательна у каждой записи окна (P-46), и снять одну неудобную нельзя.
	// Месяц без единой улики — листом: так хранилище отдаёт месяц, чей ключ
	// уничтожен или ждёт уничтожения, — заголовки с метками там не нужны, тел
	// всё равно нет (P-77, P-80). Пакет по субъекту несёт улики и в каждом
	// месяце, которому называет метку. Месяц — по времени приёма в листе: оно
	// то же, что в заголовке (windowRecords).
	withEvidence := map[string]bool{}
	for _, rec := range b.Records {
		if len(rec.Evidence) > 0 {
			withEvidence[evidence.ScopeOf(b.Source, rec.Leaf.Leaf.chain().UnixNano)] = true
		}
	}
	leafMonths := map[string]bool{}
	missing := 0
	for _, rec := range b.Records {
		l := rec.Leaf.Leaf.chain()
		leaves = append(leaves, l)
		if len(rec.Evidence) == 0 {
			if InWindow(time.Unix(0, l.UnixNano), r.From, r.To) {
				// Листом — только запись из окна самого пакета: запись окна
				// аудитора вне него хранилище прикладывать и не должно, и месяц,
				// куда заходит окно шире, — не «закрытый месяц», а недостача: нужен
				// пакет за это окно (P-81).
				scope := evidence.ScopeOf(b.Source, l.UnixNano)
				if withEvidence[scope] || b.Subject != nil && b.Subject.names(scope) || !InWindow(time.Unix(0, l.UnixNano), b.From, b.To) {
					missing++
					continue
				}
				r.LeafOnly++
				leafMonths[scope] = true
			}
			continue
		}
		sealed, err := evidence.Unmarshal(rec.Evidence)
		if err != nil {
			return fmt.Errorf("the record attached to %s/%s does not parse: %w", b.Source, l.Subject, err)
		}
		// Улика — только при своём листе: проверка вердикта ниже — по ячейке,
		// и тело записи, переложенное в ячейку другой (с её чистым
		// вердиктом), обходило бы её (E2-01).
		if sealed.Source != l.Scope || strconv.FormatUint(sealed.Seq, 10) != l.Subject {
			return fmt.Errorf("the record attached next to %s/%s is %s/%d: a record goes with its own leaf", b.Source, l.Subject, sealed.Source, sealed.Seq)
		}
		if rec.Verdict == nil && sealed.ContentType == gateway.ContentType {
			return fmt.Errorf("record %s/%d is a gateway journal entry, and the bundle lacks the store's verdict on it", sealed.Source, sealed.Seq)
		}
		attached = append(attached, WindowRecord{Evidence: rec.Evidence, DEK: rec.DEK})
	}
	var wr WindowReport
	err := windowRecords(attached, leaves, &wr)
	r.Attached = wr.Attached
	// Тело записи гейтвея, которую хранилище при приёме признало поломанной,
	// здесь не вскрывается: что с ней не так, показывает пакет одной улики.
	// Тело вне окна аудитора в отчёт и в -bodies не идёт: спросили не о нём.
	for _, body := range wr.Bodies {
		switch {
		case slices.Contains(r.GatewayBroken, body.Seq):
			r.withheld++
		case !InWindow(time.Unix(0, body.ReceivedAt), r.From, r.To):
			r.outside++
		default:
			r.Bodies = append(r.Bodies, body)
		}
	}
	r.LeafOnlyMonths = slices.Sorted(maps.Keys(leafMonths))
	if err == nil && missing > 0 {
		err = fmt.Errorf("%d records received in the window come without their evidence: ask for a bundle over this window", missing)
	}
	return err
}

// LeafOnlyNote — заметка о записях окна, пришедших листом, одна на пакеты по
// источнику, по субъекту и за окно (P-80).
func LeafOnlyNote(n int, months []string) string {
	return fmt.Sprintf("%d records received in the window come without their evidence (%s): the bundle carries the evidence of no record of those months, which is how the store sends a month whose key is destroyed or awaits destruction, so their headers (with any subject labels in them) are not shown, only their number, receive time and digest; anyone can take a month's evidence out of a bundle as well, and the with_keys and keys_for marks are not signed, so this bundle cannot tell which: %s", n, QuotedList(months), ReceiptsPath)
}

// sourceSubject проверяет пакет по субъекту: у записей окна с его меткой тело
// называет его, а записи с другой меткой или без неё идут без ключа. Метка
// своя у каждого месяца источника: запись сверяется с меткой месяца из её
// заголовка. Считает, сколько каких записей в окне. Приложенность и сверку с
// листами делает sourceAttached: сюда приходят те же улики.
func sourceSubject(b SourceBundle, r *SourceReport) error {
	c := b.Subject
	if c.Value == "" || c.Field == "" {
		return errors.New("the bundle does not say whose records it opens")
	}
	// Месяц → метка. Месяц — «источник/ГГГГ-ММ» этого источника: иначе он
	// ничего не помечает, а в отчёте рисовал бы что угодно.
	labels := map[string]evidence.SubjectTag{}
	for _, l := range c.Labels {
		var t evidence.SubjectTag
		switch {
		case !isMonthOf(b.Source, l.Scope):
			return fmt.Errorf("the bundle names a label for %q, which is not a month of %q", l.Scope, b.Source)
		case len(l.Tag) != len(t):
			return fmt.Errorf("the label for %s is %d bytes, not %d", l.Scope, len(l.Tag), len(t))
		}
		copy(t[:], l.Tag)
		if t.IsZero() {
			return errors.New("the bundle names an empty subject label")
		}
		if _, dup := labels[l.Scope]; dup {
			return fmt.Errorf("the bundle names two labels for %s", l.Scope)
		}
		labels[l.Scope] = t
	}
	opened := map[uint64][]byte{}
	for _, body := range r.Bodies {
		opened[body.Seq] = body.Body
	}
	// Счёт по месяцам окна: метку месяца привязывает только открытое тело того
	// же месяца. Тело сентября о метке октября не говорит ничего: иначе пакет
	// заменил бы метку одного месяца чужой и снял ключи этого месяца (P-71 — та
	// же P-49 на уровне месяца). Месяц окна без открытого тела субъекта отчёт
	// называет всегда: выдуманная метка такого месяца не совпадёт ни с одной
	// записью, и пакет выглядит как честный без его записей там (P-75).
	type monthCount struct{ records, opened, keyless int }
	months := map[string]*monthCount{}
	month := func(scope string) *monthCount {
		m := months[scope]
		if m == nil {
			m = &monthCount{}
			months[scope] = m
		}
		return m
	}
	noLabel := map[string]bool{}
	for _, rec := range b.Records {
		if len(rec.Evidence) == 0 {
			// Здесь такой ключ ничего не открывает, а улику этой записи из другого
			// пакета откроет.
			if len(rec.DEK) > 0 {
				return fmt.Errorf("record %s/%s comes with a record key and without its evidence", b.Source, rec.Leaf.Leaf.chain().Subject)
			}
			// Запись месяца без метки, листом (P-77); запись месяца с меткой
			// без улики отвергает sourceAttached.
			l := rec.Leaf.Leaf.chain()
			scope := evidence.ScopeOf(b.Source, l.UnixNano)
			if _, named := labels[scope]; !named && InWindow(time.Unix(0, l.UnixNano), r.From, r.To) {
				month(scope)
				r.SubjectNoLabel++
				noLabel[scope] = true
			}
			continue
		}
		sealed, err := evidence.Unmarshal(rec.Evidence)
		if err != nil {
			return fmt.Errorf("the record attached to %s/%s does not parse: %w", b.Source, rec.Leaf.Leaf.chain().Subject, err)
		}
		// Месяц — из заголовка под отпечатком, а не из заявления.
		want, labelled := labels[sealed.Scope()]
		mine := labelled && sealed.Subject == want
		if !mine && len(rec.DEK) > 0 {
			return fmt.Errorf("record %s/%d does not carry the label of this subject for its month, and it comes with its record key", sealed.Source, sealed.Seq)
		}
		// Поле — из записи, под отпечатком: другое поле того же тела выдало бы
		// чужую метку за этого субъекта, а его записи остались бы закрытыми.
		if mine && sealed.SubjectField != c.Field {
			return fmt.Errorf("record %s/%d was labelled by the field %q, and the bundle names the field %q", sealed.Source, sealed.Seq, sealed.SubjectField, c.Field)
		}
		if !InWindow(time.Unix(0, sealed.ReceivedAt), r.From, r.To) {
			continue
		}
		// Улика в месяце, которому пакет не называет метки: честное хранилище
		// кладёт такой месяц листом (P-77), значит, метку из пакета вынули, а
		// улики оставили — показать месяц «стёртым» так нельзя (P-82).
		if !labelled {
			return fmt.Errorf("record %s/%d comes with its evidence, and the bundle names no label for its month %q: a store sends such a month as leaves, so a label was taken out of this bundle", sealed.Source, sealed.Seq, sealed.Scope())
		}
		m := month(sealed.Scope())
		switch {
		case mine:
			m.records++
			if len(rec.DEK) == 0 {
				m.keyless++
			}
			// Тела нет в отчёте у записи без ключа и у поломанной записи гейтвея.
			if body, ok := opened[sealed.Seq]; ok {
				// Тела без субъекта это тоже касается: значение тогда пустое, а
				// названное не пусто.
				if v, _ := evidence.SubjectOf(body, c.Field); v != c.Value {
					return fmt.Errorf("record %s/%d carries the label of this subject, but its body does not name %q as %q", sealed.Source, sealed.Seq, c.Value, c.Field)
				}
				m.opened++
			}
		case sealed.Subject.IsZero():
			r.SubjectUnlabeled++
		default:
			r.SubjectOthers++
		}
	}
	// По порядку месяцев: итог не зависит от порядка обхода карты.
	unbound := map[string]bool{}
	for _, scope := range slices.Sorted(maps.Keys(months)) {
		m := months[scope]
		r.SubjectOpened += m.opened
		r.SubjectKeyless += m.keyless
		if m.opened > 0 {
			r.SubjectRecords += m.records
			continue
		}
		r.SubjectUnbound += m.records
		if m.records > 0 {
			unbound[scope] = true
		}
		r.SubjectUnconfirmedMonths = append(r.SubjectUnconfirmedMonths, scope)
	}
	r.SubjectUnboundMonths = slices.Sorted(maps.Keys(unbound))
	r.SubjectNoLabelMonths = slices.Sorted(maps.Keys(noLabel))
	return nil
}

// isMonthOf — scope есть месяц источника: «источник/ГГГГ-ММ», как
// evidence.Header.Scope.
func isMonthOf(source, scope string) bool {
	month, ok := strings.CutPrefix(scope, source+"/")
	if !ok {
		return false
	}
	t, err := time.Parse("2006-01", month)
	return err == nil && t.Format("2006-01") == month
}

// labelsText — метки заявления для отчёта: hex и месяц.
func labelsText(ls []SubjectLabel) string {
	if len(ls) == 0 {
		return "none"
	}
	parts := make([]string, len(ls))
	for i, l := range ls {
		parts[i] = fmt.Sprintf("%x in %q", l.Tag, l.Scope)
	}
	return strings.Join(parts, ", ")
}

// QuotedList — имена через запятую, каждое в кавычках: они из заголовков
// записей, перевод строки в имени источника не должен рисовать отчёт.
func QuotedList(names []string) string {
	parts := make([]string, len(names))
	for i, n := range names {
		parts[i] = strconv.Quote(n)
	}
	return strings.Join(parts, ", ")
}

// closedOthers — закрытые записи окна не под меткой субъекта.
func (r SourceReport) closedOthers() int {
	return r.SubjectOthers + r.SubjectUnlabeled + r.SubjectNoLabel
}

// UnderLabels — записи окна под метками, названными в пакете, привязаны они
// телом или нет.
func (r SourceReport) UnderLabels() int { return r.SubjectRecords + r.SubjectUnbound }

// ClosedOthers — закрытые записи окна не под метками субъекта.
func (r SourceReport) ClosedOthers() int { return r.closedOthers() }

// subjectCounts — разбивка записей окна пакета по субъекту, одна на деталь
// проверки, строку Subject и -json: записи субъекта (под меткой месяца, где
// открыто его тело), сколько из них открыто, под меткой в месяцах без
// открытого тела, остальные. Вместе — все записи окна.
func (r SourceReport) subjectCounts() string {
	s := fmt.Sprintf("%d records of the subject, %d of them open", r.SubjectRecords, r.SubjectOpened)
	if r.SubjectUnbound > 0 {
		s += fmt.Sprintf(", %d more under its label in months where none of its bodies opens", r.SubjectUnbound)
	}
	return s + fmt.Sprintf(", %d others closed", r.closedOthers())
}

// KeylessReasons — почему улика пришла без ключа записи. Месяц с уничтоженным
// или ждущим уничтожения ключом хранилище отдаёт листом, а не уликой без
// ключа (P-80), так что причины две (P-83). Один текст на отчёты всех пакетов
// за окно, -bodies и docs/bundles.md.
const KeylessReasons = "the key was removed from this bundle, or the store held it back (a month whose key is destroyed or awaits destruction comes as leaves, not as evidence without keys)"

// KeylessUnderLabel — то же для записи под меткой субъекта.
const KeylessUnderLabel = KeylessReasons

// ReceiptsPath — как отличить месяц, закрытый хранилищем, от вынутого из пакета
// (P-84, P-90). Решает свежий пакет за то же окно: пока ключ жив, в нём улики
// месяца. Ключ уничтожен — остаётся квитанция в цепи: пакет за окно несёт её
// листом, esverify перечисляет со звеном и операцией. Закрывают месяц только
// pending-destruction (до отмены) и destroyed; deactivated есть у любого
// прошлого месяца. Времени выдачи в пакете нет, так что квитанция не говорит,
// был ли месяц закрыт уже при выдаче, а пишется она, когда изменение дошло до
// резерва ключей.
const ReceiptsPath = "to tell a closed month from a stripped one, ask the store for the same bundle again: while the month key lives, a fresh bundle carries the month's evidence. Once the key is destroyed, only the store's key receipt speaks for it: a window bundle over the time the key was closed (evidencestore proof -window -from -to) carries it, and esverify lists it with its link and operation; pending-destruction or destroyed closes the month from that link on (a pending destruction until a later cancel: deactivated, op \"cancel-destroy\"), and deactivated does not close it, every past month gets one a few minutes after it ends. This bundle does not carry the time it was issued, so a receipt does not show that the month was closed already then; a receipt enters the chain once the change has reached the key backup, and it is the store's own statement"

// noLabelWhy — что значит месяц, которому пакет не называет метки (С4, P-72):
// уничтоженный ключ не даст метку никому, ждущий — не даёт, пока ждёт.
const noLabelWhy = "the store names no label for a month whose key is destroyed (then no one can compute it, the store included) or awaits destruction (then the store does not compute it, and a cancelled destruction brings back the same labels and the bodies), and sends its records as leaves; the claim is not signed, so the same is seen when someone takes a month's label and all its evidence out of the bundle, and this bundle cannot tell which: " + ReceiptsPath

// Notes — чего пакет по источнику не доказывает.
func (r SourceReport) Notes() []string {
	n := []string{
		"the tails are the store's own statements, written when it took the time-stamps and certified by them: a store that understated them would have lied at that moment, and a window bundle, or the hidden record's own bundle, shows the lie",
		"of other sources the bundle shows how many there were at each edge (by hashes of their names) and, for every link between the edges, when it was made and how many leaves it holds: the pace of the whole store, not who wrote what",
		"what happened at the source: the bundle holds what the store received; a receive time is the store's clock",
		"a record the store received in the window but held back and put into the chain later is not here: its own bundle shows the later entry, and the collector's signed promise for it shows the missed deadline",
	}
	if len(r.Holes) > 0 {
		var parts []string
		for _, h := range r.Holes {
			parts = append(parts, h.String())
		}
		n = append(n, fmt.Sprintf("numbers %s are not in the chain between the edges: the records around them refer to each other, so nothing under those numbers is left out of this bundle; whether the source skipped them or the store lost them after accepting them, the collector's signed promises show", strings.Join(parts, ", ")))
	}
	if r.FromBundle {
		n = append(n, "the window was taken from the bundle itself: check the bundle against your own window with esverify -from and -to")
	}
	if outside := r.Records - r.Attached - r.LeafOnly; r.Attached > 0 && outside > 0 {
		n = append(n, fmt.Sprintf("%d of the %d records come without their evidence: they were received outside the window, and the bundle shows only their number, receive time and digest", outside, r.Records))
	}
	if r.Subject != "" {
		n = append(n, "which records are this subject's rests on the store's word at intake: it sets a label when it receives a record, from the subject field in its body, and the label cannot change after that; a record whose line named someone else, or no one, is not under this label, and neither is one a dishonest store labelled otherwise: such a record stays closed here, and only its body shows whose it is")
		// Другие записи окна: в месяцах с меткой — улики без ключей, в месяцах
		// без метки — листья, и заголовков там нет (P-85, T-06).
		others := "of the other records received in the window in months the bundle names a label for, it shows the number, receive time, length and subject label, a pseudonym that only the store can compute, and only while the month key lives: each month of a source has its own labels, so a client's records are linked within a month, not across months; their bodies stay closed"
		switch {
		case r.InWindow > 0 && r.SubjectNoLabel == r.InWindow:
			others = "the bundle shows the header of no record received in the window: they all lie in months it names no label for, and come as leaves"
		case r.SubjectNoLabel > 0:
			others += "; records of the months it names no label for come as leaves, without headers or labels"
		}
		n = append(n, others+"; a label handed out before a month key was destroyed stays the client's pseudonym in that month, and no bundle shows the headers of a labelled record of such a month unless asked with -show-label")
		if r.SubjectOpened == 0 {
			if len(r.SubjectUnconfirmedMonths) == len(r.SubjectNoLabelMonths) {
				// Метки нет ни у одного месяца окна: сравнивать нечего, и окно
				// шире закрытый месяц не откроет.
				n = append(n, fmt.Sprintf("the bundle names no label for any month of the window (%s): nothing here ties a label to %q or says whether it has records there", QuotedList(r.SubjectUnconfirmedMonths), r.Subject))
			} else {
				n = append(n, fmt.Sprintf("no body under this label is open in the window (%s), and only an open body of a month ties that month's label to a subject: nothing here says that this label is %q, or that the subject has no records; ask for a window that opens one of its records in those months, or compare the labels %s with a bundle that does", QuotedList(r.SubjectUnconfirmedMonths), r.Subject, r.SubjectLabel))
			}
		}
		if r.SubjectUnlabeled > 0 {
			n = append(n, fmt.Sprintf("%d records received in the window carry no subject label: their lines named no subject, or they came before the source had subject_field, and they could be anyone's", r.SubjectUnlabeled))
		}
		if r.SubjectOpened > 0 && len(r.SubjectUnconfirmedMonths) > 0 {
			k1 := fmt.Sprintf("no body of %q is open in %s, and only an open body of a month ties that month's label to the subject: a bundle can name any label for such a month, so the subject's records there, if it has any, can be among the closed records, and nothing here shows that it has none there", r.Subject, QuotedList(r.SubjectUnconfirmedMonths))
			if r.SubjectUnbound > 0 {
				k1 += fmt.Sprintf("; %d records lie under the labels the bundle names for %s, and nothing here says they are %q's", r.SubjectUnbound, QuotedList(r.SubjectUnboundMonths), r.Subject)
			}
			n = append(n, k1+"; ask for a window that opens one of its records in those months")
		}
		if r.SubjectKeyless > 0 {
			n = append(n, fmt.Sprintf("%d of the %d records under this label come without a record key, so their bodies are not shown: %s; ask its operator", r.SubjectKeyless, r.UnderLabels(), KeylessUnderLabel))
		}
		if r.SubjectNoLabel > 0 {
			// Она же — заметка о листьях для пакета по субъекту: его месяц-лист и
			// есть месяц без метки.
			n = append(n, fmt.Sprintf("%d records received in the window lie in months the bundle names no label for (%s) and come as leaves, with only their number, receive time and digest: whose they are cannot be shown here; %s", r.SubjectNoLabel, QuotedList(r.SubjectNoLabelMonths), noLabelWhy))
		}

	} else if keyless := r.Keyless(); keyless > 0 {
		n = append(n, fmt.Sprintf("%d of the %d records attached carry no record key: %s", keyless, r.Attached, KeylessReasons))
	}
	if r.LeafOnly > 0 && r.Subject == "" {
		n = append(n, LeafOnlyNote(r.LeafOnly, r.LeafOnlyMonths))
	}
	if len(r.GatewayBroken) > 0 {
		var parts []string
		for _, q := range r.GatewayBroken {
			parts = append(parts, strconv.FormatUint(q, 10))
		}
		n = append(n, fmt.Sprintf("gateway journal records %s were found broken by the store at intake (entry hash, chain or checkpoint signature): their bodies are not opened here; single-record bundles show what is wrong", strings.Join(parts, ", ")))
	}
	if r.GatewayRecords > 0 {
		n = append(n, "gateway journal records: the store's verdict at intake is in the bundle; the gateway's checkpoint signature can be checked yourself in single-record bundles (evidencestore proof -source S -seq N, esverify -gateway-key)")
	}
	if r.WitnessRefused != 0 {
		n = append(n, fmt.Sprintf("a collector refused %d heads signed with the store key (in its checkpoints-conflict.jsonl): the store showed it a second history, or lost the end of its chain; ask its operator", r.WitnessRefused))
	}
	if r.WitnessFork != 0 {
		n = append(n, fmt.Sprintf("the witness holds two versions of the chain, both signed with the store key (the first head it holds in two versions is %d): this part of the chain is not among them, but the store signed a second history — a rewrite, or a store that lost data without a copy; ask its operator", r.WitnessFork))
	}
	switch {
	case r.WitnessHead != 0:
		n = append(n, fmt.Sprintf("the witness saw head %d, and it fixes the chain up to that head: rewriting this part would contradict the witness, as long as the witness is out of the store administrator's reach", r.WitnessHead))
		if r.WitnessUntimed {
			n = append(n, WitnessUntimedNote)
		}
	case r.WitnessNone && len(r.Cosigned) > 0:
		n = append(n, "the witness has no head at or after the link that holds the upper time-stamp's token yet")
	case r.WitnessNone:
		n = append(n, "the witness has no head at or after the link that holds the upper time-stamp's token yet: until it gets one, only the TSA time-stamps stand against the store's owner rewriting the chain")
	case len(r.Cosigned) == 0:
		n = append(n, "the store's signature proves that THIS store signed the head; only the TSA time-stamps stand against its owner rewriting the chain: a rewrite after the lower time-stamp needs a fresh upper one, and a T2 more than an hour after the window is a sign of it; a witness (esverify -heads or -witness-key) catches one made sooner")
	}
	n = append(n, CosignNotes(r.CosignChecked, r.Cosigned, r.CosignUnknown, r.CosignCarried, "this part", "T2", r.Upper)...)
	return append(n, r.TSANotes...)
}

// Text — отчёт человеческим языком, как у пакета за окно: всё из пакета —
// с экранированными управляющими символами, вердикт и в конце.
func (r SourceReport) Text() string {
	var b strings.Builder
	verdict := r.Verdict()
	b.WriteString(verdict + "\n\n")
	asked := "asked by the auditor"
	if r.FromBundle {
		asked = "named in the bundle"
	}
	// %q: имя пришло из пакета, и аудитор сверяет его с тем, о ком спрашивал:
	// пробел на конце должен быть виден, перевод строки не должен рисовать отчёт.
	fmt.Fprintf(&b, "Source: %q\nWindow (receive time): %s – %s (%s)\n", r.Source, fmtTime(r.From), fmtTime(r.To), asked)
	records := "no records"
	if r.Records > 0 {
		records = fmt.Sprintf("records %d–%d (%d, %d received in the window)", r.FirstSeq, r.LastSeq, r.Records, r.InWindow)
	}
	if r.Valid() {
		// Края — хвосты, а не время меток: нижние положены перед запросом T1,
		// верхние — первые после токена T2.
		span := fmt.Sprintf("from the beginning of the chain to the first source tails laid after the time-stamp of %s", fmtTime(r.Upper))
		if !r.FromStart {
			span = fmt.Sprintf("from the source tails laid right before the time-stamp of %s to the first source tails laid after the time-stamp of %s", fmtTime(r.Lower), fmtTime(r.Upper))
		}
		if r.SourceNamed {
			fmt.Fprintf(&b, "Every record %q put into the store's chain %s is in this bundle: %s\n", r.Source, span, records)
		} else {
			// Не «записей нет»: имя можно заменить похожим и снять записи, и такой
			// пакет сойдётся, потому что хвосты его не называют (P-59).
			fmt.Fprintf(&b, "The source tails name no source %q up to the first tails laid after the time-stamp of %s, so this bundle holds no records and shows nothing about any other name: compare the name with the source you expect, letter by letter\n", r.Source, fmtTime(r.Upper))
		}
	} else {
		fmt.Fprintf(&b, "Records in the bundle: %s\n", records)
	}
	switch {
	case r.Subject == "":
	case r.SubjectOpened > 0:
		// %q: значение пришло из пакета и из тела, перевод строки в нём нарисовал
		// бы чужие строки отчёта.
		fmt.Fprintf(&b, "Subject: %q (field %q, label %s): %d of the %d records received in the window, %d of them open",
			r.Subject, r.SubjectField, r.SubjectLabel, r.SubjectRecords, r.InWindow, r.SubjectOpened)
		if r.SubjectUnbound > 0 {
			fmt.Fprintf(&b, ", %d more under its label in months where none of its bodies opens", r.SubjectUnbound)
		}
		fmt.Fprintf(&b, ", the other %d stay closed", r.closedOthers())
		if len(r.SubjectUnconfirmedMonths) > 0 {
			// Оговорка в той же строке: её прочтут и без заметок (P-75).
			fmt.Fprintf(&b, "; no body of the subject is open in %s, and its records there are not shown", QuotedList(r.SubjectUnconfirmedMonths))
		}
		b.WriteString("\n")
	default:
		fmt.Fprintf(&b, "Subject: %q (field %q, label %s) is named by the bundle, and no open body ties the label to it: %d records under the label, the other %d of the %d in the window stay closed",
			r.Subject, r.SubjectField, r.SubjectLabel, r.UnderLabels(), r.closedOthers(), r.InWindow)
		if len(r.SubjectUnconfirmedMonths) > 0 {
			// Месяцы окна — и здесь, как в строке с открытыми телами (P-75, E2-02).
			fmt.Fprintf(&b, "; no body of the subject is open in %s, and its records there are not shown", QuotedList(r.SubjectUnconfirmedMonths))
		}
		b.WriteString("\n")
	}
	b.WriteString("\nChecks:\n")
	for _, c := range r.Checks {
		mark := "✔"
		if !c.OK {
			mark = "✘"
		}
		fmt.Fprintf(&b, "  %s %s", mark, c.Name)
		if c.Detail != "" {
			// В тексте отказа есть имя из пакета: Printable оставляет перевод
			// строки, и оно нарисовало бы в отчёте свои строки.
			b.WriteString(" — " + strings.ReplaceAll(c.Detail, "\n", `\n`))
		}
		b.WriteString("\n")
	}
	if len(r.Bodies) > 0 {
		fmt.Fprintf(&b, "\nBodies opened: %d (esverify -bodies DIR writes them out byte for byte)\n", len(r.Bodies))
	}
	b.WriteString("\nWhat this bundle does not prove:\n")
	for _, n := range r.Notes() {
		b.WriteString("  — " + n + "\n")
	}
	return Printable(b.String()) + "\n" + verdict + "\n"
}
