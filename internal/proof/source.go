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
	"github.com/Nikolay1994Kaz/evidencestore/internal/tsa"
)

// Пакет по источнику (DECISIONS, п. 28): записи одного источника за окно и
// доказательство, что других нет, без метаданных чужих систем.
//
//	нижние хвосты   одни в звене, которое заверила нижняя метка (момент g1):
//	                хэш последнего листа S к этому месту — начало цепочки
//	записи S        листья с путями Меркла (чужие листья — только хэши);
//	                каждый ссылается на хэш прежнего листа S
//	верхняя метка   её лист токена (время g2) и сразу за ним хвосты —
//	                последними в звене: хэш последнего листа S — конец
//
// Ссылки сходятся от начала до конца — значит, между головой под нижней
// меткой и токеном верхней S не положил в цепь ничего, кроме этих записей:
// выброшенную запись выдала бы ссылка следующей. На слове хранилища держатся
// только хвосты — его заявления в цепи под метками.

// SourceKind — вид пакета по источнику; версия та же, что у пакета за окно.
const SourceKind = "source"

// PlacedLeaf — лист с путём Меркла и местом в звене. Место проверяется по
// форме пути (auditchain.ProofShape): соседей проверяющий не видит.
type PlacedLeaf struct {
	Inclusion
	Index int `json:"index"`
}

// SourceRecord — запись источника: лист с местом и, по запросу, улика с
// ключом записи.
type SourceRecord struct {
	Leaf     PlacedLeaf `json:"leaf"`
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
	// LowerHead — звено нижних хвостов: в нём один лист, LowerTails, и его
	// заверила метка LowerToken. Ноль — с начала цепи: цепочка источника
	// начинается с нулей. LowerOpen — раскрытие хвоста источника в нижних
	// хвостах (nil — источника там нет: записей ещё не было).
	LowerHead  uint64    `json:"lower_head"`
	LowerTails *Leaf     `json:"lower_tails,omitempty"`
	LowerToken []byte    `json:"lower_token,omitempty"`
	LowerOpen  *TailOpen `json:"lower_open,omitempty"`
	// UpperToken — лист токена верхней метки; UpperTails — хвосты сразу за
	// ним, последние в том же звене; UpperOpen — раскрытие хвоста источника
	// в них.
	UpperToken PlacedLeaf `json:"upper_token"`
	UpperTails PlacedLeaf `json:"upper_tails"`
	UpperOpen  *TailOpen  `json:"upper_open,omitempty"`
	// Links — звенья подряд от LowerHead (или первого звена цепи); последнее
	// — голова Statement.
	Links []Link `json:"links"`
	// Records — все записи источника между хвостами, в порядке цепи.
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
	UpperLink    uint64 // звено токена верхней метки и верхних хвостов
	HeadSeq      uint64
	// Records — записей источника в пакете; InWindow — из них со временем
	// приёма в окне; FirstSeq, LastSeq — крайние номера; Holes — номера между
	// ними, которых источник хранилищу не дал (ссылки там не рвутся).
	Records           int
	InWindow          int
	FirstSeq, LastSeq uint64
	Holes             []SeqRange
	Attached          int
	Bodies            []WindowBody
	GatewayRecords    int
	WitnessChecked    bool
	WitnessHead       uint64
	WitnessNone       bool
	WitnessFork       uint64
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
	r := SourceReport{Source: b.Source, From: from, To: to, LowerHead: b.LowerHead, UpperLink: b.UpperTails.LinkSeq}
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

	// 3. Нижняя граница: хвосты — единственный лист звена, которое заверила
	// нижняя метка; с начала цепи — первое звено и нули.
	var start [32]byte
	if b.LowerHead == 0 {
		r.FromStart = true
		err = nil
		if links[0].Seq != 1 || links[0].PrevHash != ([32]byte{}) {
			err = fmt.Errorf("the bundle is said to start at the beginning of the chain, but it starts at link %d", links[0].Seq)
		}
		add("the bundle starts at the beginning of the chain", err, "there is no time-stamp before the window")
	} else {
		start, err = lowerTails(b, links[0], hashes[0], trust.TSA, &r)
		add("the lower tails are the only leaf of the link the lower time-stamp certifies (T1)", err,
			fmt.Sprintf("T1 = %s, link %d", fmtTime(r.Lower), b.LowerHead))
	}

	// 4. Верхняя граница: лист токена верхней метки и хвосты сразу за ним —
	// последними в одном звене: в счёт вошло всё, что легло до токена.
	end, err := upperTails(b, linkAt, trust.TSA, &r)
	add("the upper tails lie right after the token of the upper time-stamp, last in their link (T2)", err,
		fmt.Sprintf("T2 = %s, link %d", fmtTime(r.Upper), b.UpperTails.LinkSeq))

	// 5. Окно строго между метками — те же допуски, что у пакета за окно.
	err = nil
	switch {
	case r.From.IsZero() || r.To.IsZero():
		err = errors.New("no window to check against: give one with esverify -from and -to")
	case r.To.Before(r.From):
		err = fmt.Errorf("the window ends at %s, before it starts at %s", fmtTime(r.To), fmtTime(r.From))
	case !r.Lower.IsZero() && !r.From.After(r.Lower.Add(ReceiveSlack)):
		err = fmt.Errorf("the window starts at %s, but the bundle is complete only from a second after time-stamp T1 %s", fmtTime(r.From), fmtTime(r.Lower))
	case r.Upper.IsZero() || !r.To.Before(r.Upper.Add(-ReceiveSkew)):
		err = fmt.Errorf("the window ends at %s, but the bundle is complete only up to a minute before time-stamp T2 %s", fmtTime(r.To), fmtTime(r.Upper))
	}
	add("the time-stamps bracket the window", err, fmt.Sprintf("%s – %s", fmtTime(r.From), fmtTime(r.To)))

	// 6. Записи источника: каждая ссылается на прежнюю, и цепочка идёт от
	// нижних хвостов до верхних.
	add("the records are the whole chain of the source between the tails", sourceChain(b, linkAt, start, end, &r),
		fmt.Sprintf("%d records", len(b.Records)))

	// 7. Приложенные улики сверяются со своими листами, тела вскрываются.
	if slices.ContainsFunc(b.Records, func(rec SourceRecord) bool { return len(rec.Evidence) > 0 }) {
		var leaves []auditchain.Leaf
		var attached []WindowRecord
		for _, rec := range b.Records {
			leaves = append(leaves, rec.Leaf.Leaf.chain())
			if len(rec.Evidence) > 0 {
				attached = append(attached, WindowRecord{Evidence: rec.Evidence, DEK: rec.DEK})
			}
		}
		var wr WindowReport
		err := windowRecords(attached, leaves, &wr)
		r.Attached, r.Bodies, r.GatewayRecords = wr.Attached, wr.Bodies, wr.GatewayRecords
		add("the records attached match their leaves, and their bodies open with their record keys", err,
			fmt.Sprintf("%d records, %d bodies opened", r.Attached, len(r.Bodies)))
	}

	// 8. Свидетель голов — как у остальных пакетов.
	if trust.Witness != nil {
		var wr Report
		checkWitness(trust.Witness, trust.StoreKey, b.UpperTails.LinkSeq, links, hashes, &wr, add)
		r.WitnessChecked, r.WitnessHead, r.WitnessNone, r.WitnessFork = wr.WitnessChecked, wr.WitnessHead, wr.WitnessNone, wr.WitnessFork
	}
	return r
}

// lowerTails — нижние хвосты: единственный лист первого звена пакета, его
// заверила нижняя метка. Возвращает хэш последнего листа источника к этому
// месту (нули — записей ещё не было).
func lowerTails(b SourceBundle, link auditchain.Record, hash [32]byte, trust tsa.Trust, r *SourceReport) ([32]byte, error) {
	switch {
	case link.Seq != b.LowerHead:
		return [32]byte{}, fmt.Errorf("the bundle starts at link %d, the lower tails are said to lie in link %d", link.Seq, b.LowerHead)
	case b.LowerTails == nil:
		return [32]byte{}, errors.New("the bundle carries no lower tails")
	}
	p, err := batchOf(link)
	if err != nil {
		return [32]byte{}, err
	}
	tails := b.LowerTails.chain()
	if auditchain.MerkleRoot([]auditchain.Leaf{tails}) != p.Root {
		return [32]byte{}, fmt.Errorf("link %d does not hold just the lower tails", b.LowerHead)
	}
	start, err := OpenTail(tails, b.Source, b.LowerOpen)
	if err != nil {
		return [32]byte{}, fmt.Errorf("the lower tails: %w", err)
	}
	info, err := tsa.Verify(b.LowerToken, HeadImprint(b.LowerHead, hash), trust)
	if err != nil {
		return [32]byte{}, fmt.Errorf("the lower time-stamp: %w", err)
	}
	r.Lower = info.GenTime.UTC()
	return start, nil
}

// upperTails — верхние хвосты: последний лист своего звена, сразу за листом
// токена верхней метки; токен заверяет голову из пакета. Возвращает хэш
// последнего листа источника к этому месту.
func upperTails(b SourceBundle, linkAt func(uint64) (auditchain.Record, [32]byte, bool), trust tsa.Trust, r *SourceReport) ([32]byte, error) {
	u := b.UpperTails.LinkSeq
	if b.UpperToken.LinkSeq != u {
		return [32]byte{}, fmt.Errorf("the token of the upper time-stamp lies in link %d, the upper tails in link %d", b.UpperToken.LinkSeq, u)
	}
	n, err := placed(b.UpperTails, linkAt)
	if err != nil {
		return [32]byte{}, fmt.Errorf("the upper tails: %w", err)
	}
	if _, err := placed(b.UpperToken, linkAt); err != nil {
		return [32]byte{}, fmt.Errorf("the token of the upper time-stamp: %w", err)
	}
	if b.UpperTails.Index != n-1 || b.UpperToken.Index != n-2 {
		return [32]byte{}, fmt.Errorf("in link %d of %d leaves the token is leaf %d and the tails leaf %d: the tails must come right after the token and close the link",
			u, n, b.UpperToken.Index, b.UpperTails.Index)
	}
	tok := b.UpperToken.Leaf.chain()
	if tok.Type != auditchain.EventTimestamp {
		return [32]byte{}, errors.New("the upper leaf before the tails is not a TSA time-stamp")
	}
	head, err := strconv.ParseUint(tok.Subject, 10, 64)
	if err != nil {
		return [32]byte{}, fmt.Errorf("the token in link %d names head %q", u, tok.Subject)
	}
	_, hash, ok := linkAt(head)
	if !ok {
		return [32]byte{}, fmt.Errorf("the upper time-stamp certifies head %d, which is not in the bundle", head)
	}
	info, err := tsa.Verify(tok.Payload, HeadImprint(head, hash), trust)
	if err != nil {
		return [32]byte{}, fmt.Errorf("the upper time-stamp: %w", err)
	}
	end, err := OpenTail(b.UpperTails.Leaf.chain(), b.Source, b.UpperOpen)
	if err != nil {
		return [32]byte{}, fmt.Errorf("the upper tails: %w", err)
	}
	r.Upper = info.GenTime.UTC()
	return end, nil
}

// placed проверяет лист с местом: путь ведёт к корню звена, и его форма —
// та, что у этого места. Возвращает число листьев звена.
func placed(p PlacedLeaf, linkAt func(uint64) (auditchain.Record, [32]byte, bool)) (int, error) {
	if err := checkInclusion(p.Inclusion, linkAt); err != nil {
		return 0, err
	}
	link, _, _ := linkAt(p.LinkSeq)
	batch, err := auditchain.DecodeBatchPayload(link.Payload)
	if err != nil {
		return 0, err
	}
	shape, err := auditchain.ProofShape(int(batch.Count), p.Index)
	if err != nil {
		return 0, fmt.Errorf("link %d: %w", p.LinkSeq, err)
	}
	if len(shape) != len(p.Path) {
		return 0, fmt.Errorf("the path in link %d is not the path of leaf %d", p.LinkSeq, p.Index)
	}
	for i, left := range shape {
		if p.Path[i].Left != left {
			return 0, fmt.Errorf("the path in link %d is not the path of leaf %d", p.LinkSeq, p.Index)
		}
	}
	return int(batch.Count), nil
}

// sourceChain проверяет записи источника: каждая — лист улики этого
// источника со ссылкой, и ссылки идут от start до end без разрыва.
//
// Порядок и места записей отдельно не проверяются: ссылка задаёт порядок
// цепи, до нижних хвостов и на местах токена и верхних хвостов записи нет
// (это проверено границами). Запись за верхними хвостами проверяется —
// иначе её выдало бы только несовпадение конца, с неверным объяснением.
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
		if _, err := placed(rec.Leaf, linkAt); err != nil {
			return fmt.Errorf("record %s/%d: %w", b.Source, seq, err)
		}
		switch {
		case rec.Leaf.LinkSeq > b.UpperTails.LinkSeq:
			return fmt.Errorf("record %s/%d lies in link %d, after the upper tails in link %d", b.Source, seq, rec.Leaf.LinkSeq, b.UpperTails.LinkSeq)
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
	if b.LowerOpen != nil {
		last = b.LowerOpen.Seq
	}
	if n := len(seqs); n > 0 {
		last = seqs[n-1]
	}
	if b.UpperOpen != nil && b.UpperOpen.Seq != last {
		return fmt.Errorf("the upper tails name record %d of %s as the last, but the chain of its records ends at %d", b.UpperOpen.Seq, b.Source, last)
	}
	if len(seqs) > 0 {
		slices.Sort(seqs)
		r.FirstSeq, r.LastSeq = seqs[0], seqs[len(seqs)-1]
		r.Holes = unexplained(slices.Compact(seqs), nil)
	}
	return nil
}

// Notes — чего пакет по источнику не доказывает.
func (r SourceReport) Notes() []string {
	n := []string{
		"the tails are the store's own statements in its chain, under time-stamps: understating them would hide the latest records of the source, but that lie stays in the chain, and the next window of this source, a window bundle or the collector's signed promises show it",
		"what happened at the source: the bundle holds what the store received; a receive time is the store's clock",
		"a record the store received in the window but held back and put into the chain later is not here: its own bundle shows the later entry, and the collector's signed promise for it shows the missed deadline",
	}
	if len(r.Holes) > 0 {
		var parts []string
		for _, h := range r.Holes {
			parts = append(parts, h.String())
		}
		n = append(n, fmt.Sprintf("numbers %s never reached the store: the records around them refer to each other, so nothing under those numbers is left out", strings.Join(parts, ", ")))
	}
	if r.FromBundle {
		n = append(n, "the window was taken from the bundle itself: check the bundle against your own window with esverify -from and -to")
	}
	if r.Attached > len(r.Bodies) {
		n = append(n, fmt.Sprintf("%d of the %d records attached carry no record key: the month key was destroyed (retention) or awaits destruction", r.Attached-len(r.Bodies), r.Attached))
	}
	if r.GatewayRecords > 0 {
		n = append(n, "gateway journal records: the gateway's own checks (entry hash, checkpoint signature) are in single-record bundles (evidencestore proof -source S -seq N)")
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
		n = append(n, "the store's signature proves that THIS store signed the head; only the TSA time-stamps stand against its owner rewriting the whole chain")
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
