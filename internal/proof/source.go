package proof

import (
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/Nikolay1994Kaz/evidencestore/internal/auditchain"
	"github.com/Nikolay1994Kaz/evidencestore/internal/evidence"
	"github.com/Nikolay1994Kaz/evidencestore/internal/gateway"
	"github.com/Nikolay1994Kaz/evidencestore/internal/tsa"
)

// Пакет по источнику (DECISIONS, п. 28): записи одного источника за окно и
// доказательство, что других нет, без записей чужих систем.
//
//	нижний край    хвосты одни в звене, которое заверила нижняя метка (g1):
//	               хэш последнего листа S к этому месту — начало цепочки
//	записи S       листья с путями Меркла (чужие листья — только хэши);
//	               каждый ссылается на хэш прежнего листа S
//	верхний край   то же у верхней метки (g2) — конец цепочки
//
// Ссылки сходятся от начала до конца — значит, между двумя заверенными
// звеньями S не положил в цепь ничего, кроме этих записей: выброшенную
// запись выдала бы ссылка следующей. Оба края — под метками окна: сдвинуть
// их можно, только переписав цепь и взяв свежую метку, а свежая метка видна
// в отчёте. На слове хранилища — только то, что хвосты оно записало честно,
// когда ставило метки.

// SourceKind — вид пакета по источнику; версия та же, что у пакета за окно.
const SourceKind = "source"

// SourceEdge — край пакета: звено Head, в котором одни хвосты источников,
// лист токена метки TSA над ним — с путём Меркла, в звене цепи после края, —
// и раскрытие хвоста своего источника (nil — источника там нет: записей ещё
// не было). Токен — листом в цепи, а не просто байтами: метку над старым
// звеном можно взять когда угодно, а положить её в цепь задним числом —
// только переписав цепь.
type SourceEdge struct {
	Head  uint64    `json:"head"`
	Tails *Leaf     `json:"tails,omitempty"`
	Token Inclusion `json:"token"`
	Open  *TailOpen `json:"open,omitempty"`
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
	// Links — звенья подряд от нижнего края (или первого звена цепи) до
	// звена токена верхней метки, а с -to-head и дальше; последнее — голова
	// Statement.
	Links []Link `json:"links"`
	// Records — все записи источника между краями, в порядке цепи.
	Records   []SourceRecord       `json:"records,omitempty"`
	Statement auditchain.Statement `json:"statement"`
}

// ParseSource разбирает пакет по источнику.
func ParseSource(data []byte) (SourceBundle, error) {
	var b SourceBundle
	if err := json.Unmarshal(data, &b); err != nil {
		return b, fmt.Errorf("proof: %w", err)
	}
	if b.Kind != SourceKind || b.Version != WindowVersion {
		return b, fmt.Errorf("proof: bundle kind %q version %d, supported %q version %d", b.Kind, b.Version, SourceKind, WindowVersion)
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
	// Lower, Upper — время нижней и верхней меток (g1, g2); FromStart —
	// с начала цепи, нижней метки нет.
	Lower, Upper time.Time
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
	// GatewayRecords — записей журнала гейтвея (с вердиктом хранилища);
	// GatewayBroken — номера тех, что хранилище при приёме признало
	// поломанными.
	GatewayRecords int
	GatewayBroken  []uint64
	WitnessChecked bool
	WitnessHead    uint64
	WitnessNone    bool
	WitnessFork    uint64
}

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
	add := func(name string, err error, detail string) bool {
		c := Check{Name: name, OK: err == nil, Detail: detail}
		if err != nil {
			c.Detail = err.Error()
		}
		r.Checks = append(r.Checks, c)
		return err == nil
	}

	// 1. Звенья подряд и связаны хэшами.
	links, hashes, err := chainLinks(b.Links)
	if !add("the links are chained by hash with no gaps", err, fmt.Sprintf("%d links", len(links))) {
		return r
	}
	linkAt := func(seq uint64) (auditchain.Record, [32]byte, bool) {
		if seq < links[0].Seq || seq > links[len(links)-1].Seq {
			return auditchain.Record{}, [32]byte{}, false
		}
		i := seq - links[0].Seq
		return links[i], hashes[i], true
	}

	// 2. Голова подписана закреплённым ключом и совпадает с последним звеном.
	err = auditchain.VerifyStatement(b.Statement, trust.StoreKey)
	if err == nil {
		last := len(links) - 1
		if b.Statement.HeadSeq != links[last].Seq || b.Statement.HeadHash != encodeHash(hashes[last]) {
			err = errors.New("the signed head does not match the last link in the bundle")
		}
	}
	r.HeadSeq = b.Statement.HeadSeq
	add("the head is signed with the store key", err, fmt.Sprintf("head %d", b.Statement.HeadSeq))

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
		start, r.Lower, err = sourceEdge(b.Source, b.Lower, linkAt, trust.TSA)
		add("the lower tails are the only leaf of the link the lower time-stamp certifies (T1)", err,
			fmt.Sprintf("T1 = %s, link %d", fmtTime(r.Lower), b.Lower.Head))
	}

	// 4. Верхний край — так же, у верхней метки: всё, что S положил в цепь
	// до звена, которое она заверила, — до этих хвостов. Её токен лежит в
	// цепи после края: свежую метку над старым звеном сюда не подставить, не
	// переписав цепь.
	end, upper, err := sourceEdge(b.Source, b.Upper, linkAt, trust.TSA)
	r.Upper = upper
	add("the upper tails are the only leaf of the link the upper time-stamp certifies (T2)", err,
		fmt.Sprintf("T2 = %s, link %d", fmtTime(r.Upper), b.Upper.Head))

	// 5. Окно строго между метками — те же допуски, что у пакета за окно.
	add("the time-stamps bracket the window", windowBracket(r.From, r.To, r.Lower, r.Upper), fmt.Sprintf("%s – %s", fmtTime(r.From), fmtTime(r.To)))

	// 6. Записи источника: каждая ссылается на прежнюю, и цепочка идёт от
	// нижних хвостов до верхних.
	add("the records are the whole chain of the source between the tails", sourceChain(b, linkAt, start, end, &r),
		fmt.Sprintf("%d records", len(b.Records)))

	// 7. Время приёма записей — между метками краёв: запись после нижних
	// хвостов принята позже T1 − WindowEdge (запрос к TSA короче
	// StampLatency), запись до верхних — не позже T2 + 1 с.
	add("every receive time lies between the time-stamps of the edges", sourceTimes(b, r.Lower, r.Upper), "")

	// 8. Вердикты хранилища по записям журнала гейтвея.
	if slices.ContainsFunc(b.Records, func(rec SourceRecord) bool { return rec.Verdict != nil }) {
		add("the store's verdicts on gateway journal records are in the chain next to them", sourceVerdicts(b, linkAt, &r),
			fmt.Sprintf("%d gateway records, %d broken at intake", r.GatewayRecords, len(r.GatewayBroken)))
	}

	// 9. Приложенные улики сверяются со своими листами, тела вскрываются;
	// улика журнала гейтвея — только с вердиктом.
	if slices.ContainsFunc(b.Records, func(rec SourceRecord) bool { return len(rec.Evidence) > 0 }) {
		add("the records attached match their leaves, and their bodies open with their record keys", sourceAttached(b, &r),
			fmt.Sprintf("%d records, %d bodies opened", r.Attached, len(r.Bodies)))
	}

	// 10. Свидетель голов — как у остальных пакетов.
	if trust.Witness != nil {
		var wr Report
		checkWitness(trust.Witness, trust.StoreKey, b.Upper.Token.LinkSeq, links, hashes, &wr, add)
		r.WitnessChecked, r.WitnessHead, r.WitnessNone, r.WitnessFork = wr.WitnessChecked, wr.WitnessHead, wr.WitnessNone, wr.WitnessFork
	}
	return r
}

// sourceEdge — край пакета: в звене e.Head один лист — хвосты, метка, чей
// токен лежит в цепи листом e.Token, заверяет это звено. Возвращает хэш
// последнего листа источника к этому месту (нули — записей ещё не было) и
// время метки.
func sourceEdge(source string, e SourceEdge, linkAt func(uint64) (auditchain.Record, [32]byte, bool), trust tsa.Trust) ([32]byte, time.Time, error) {
	link, hash, ok := linkAt(e.Head)
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
	// Тип и номер в листе — сверка для ясного отказа: метка над этим звеном
	// проверяется подписью TSA ниже.
	if tok := e.Token.Leaf.chain(); tok.Type != auditchain.EventTimestamp || tok.Subject != strconv.FormatUint(e.Head, 10) {
		return [32]byte{}, time.Time{}, fmt.Errorf("the leaf in link %d is not a time-stamp token over link %d", e.Token.LinkSeq, e.Head)
	}
	info, err := tsa.Verify(e.Token.Leaf.chain().Payload, HeadImprint(e.Head, hash), trust)
	if err != nil {
		return [32]byte{}, time.Time{}, fmt.Errorf("the time-stamp: %w", err)
	}
	return last, info.GenTime.UTC(), nil
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

// sourceVerdicts проверяет листы вердиктов: каждый — в цепи, о той же
// улике того же источника. Поломанные — в отчёт.
func sourceVerdicts(b SourceBundle, linkAt func(uint64) (auditchain.Record, [32]byte, bool), r *SourceReport) error {
	for _, rec := range b.Records {
		if rec.Verdict == nil {
			continue
		}
		l := rec.Leaf.Leaf.chain()
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
func sourceAttached(b SourceBundle, r *SourceReport) error {
	var leaves []auditchain.Leaf
	var attached []WindowRecord
	for _, rec := range b.Records {
		leaves = append(leaves, rec.Leaf.Leaf.chain())
		if len(rec.Evidence) == 0 {
			continue
		}
		if rec.Verdict == nil {
			if sealed, err := evidence.Unmarshal(rec.Evidence); err == nil && sealed.ContentType == gateway.ContentType {
				return fmt.Errorf("record %s/%d is a gateway journal entry, and the bundle lacks the store's verdict on it", sealed.Source, sealed.Seq)
			}
		}
		attached = append(attached, WindowRecord{Evidence: rec.Evidence, DEK: rec.DEK})
	}
	var wr WindowReport
	err := windowRecords(attached, leaves, &wr)
	r.Attached = wr.Attached
	// Тело записи гейтвея, которую хранилище при приёме признало поломанной,
	// здесь не вскрывается: что с ней не так, показывает пакет одной улики.
	for _, body := range wr.Bodies {
		if !slices.Contains(r.GatewayBroken, body.Seq) {
			r.Bodies = append(r.Bodies, body)
		}
	}
	return err
}

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
	if r.Attached > len(r.Bodies) {
		n = append(n, fmt.Sprintf("%d of the %d records attached carry no record key: the month key was destroyed (retention) or awaits destruction", r.Attached-len(r.Bodies), r.Attached))
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
	if r.WitnessFork != 0 {
		n = append(n, fmt.Sprintf("the witness holds two versions of the chain, both signed with the store key (the first head it holds in two versions is %d): this part of the chain is not among them, but the store signed a second history — a rewrite, or a store that lost data without a copy; ask its operator", r.WitnessFork))
	}
	switch {
	case r.WitnessHead != 0:
		n = append(n, fmt.Sprintf("the witness saw head %d, and it fixes the chain up to that head: rewriting this part would contradict the witness, as long as the witness is out of the store administrator's reach", r.WitnessHead))
	case r.WitnessNone:
		n = append(n, "the witness has no head at or after the upper tails yet: until it gets one, only the TSA time-stamps stand against the store's owner rewriting the chain")
	default:
		n = append(n, "the store's signature proves that THIS store signed the head; only the TSA time-stamps stand against its owner rewriting the chain: a rewrite after the lower time-stamp needs a fresh upper one, and a T2 more than an hour after the window is a sign of it; a witness (esverify -heads) catches one made sooner")
	}
	return n
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
	fmt.Fprintf(&b, "Source: %s\nWindow (receive time): %s – %s (%s)\n", r.Source, fmtTime(r.From), fmtTime(r.To), asked)
	start := "the beginning of the chain"
	if !r.FromStart {
		start = fmt.Sprintf("the time-stamp of %s", fmtTime(r.Lower))
	}
	records := "no records"
	if r.Records > 0 {
		records = fmt.Sprintf("records %d–%d (%d, %d received in the window)", r.FirstSeq, r.LastSeq, r.Records, r.InWindow)
	}
	if r.Valid() {
		fmt.Fprintf(&b, "Every record %s put into the store's chain from %s to the time-stamp of %s is in this bundle: %s\n", r.Source, start, fmtTime(r.Upper), records)
	} else {
		fmt.Fprintf(&b, "Records in the bundle: %s\n", records)
	}
	b.WriteString("\nChecks:\n")
	for _, c := range r.Checks {
		mark := "✔"
		if !c.OK {
			mark = "✘"
		}
		fmt.Fprintf(&b, "  %s %s", mark, c.Name)
		if c.Detail != "" {
			b.WriteString(" — " + c.Detail)
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
