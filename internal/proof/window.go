package proof

import (
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/Nikolay1994Kaz/evidencestore/internal/auditchain"
	"github.com/Nikolay1994Kaz/evidencestore/internal/evidence"
	"github.com/Nikolay1994Kaz/evidencestore/internal/gateway"
	"github.com/Nikolay1994Kaz/evidencestore/internal/keyring"
	"github.com/Nikolay1994Kaz/evidencestore/internal/tsa"
)

// Пакет за окно времени (DECISIONS, п. 27).
//
// Пакет одной улики доказывает её и ничего не говорит о тех, что аудитору не
// дали. Пакет за окно отдаёт ВСЕ листья цепи между двумя метками TSA:
//
//	нижняя метка  заверила голову h1 в момент g1: всё до h1 вошло в цепь раньше g1
//	участок       листья всех звеньев после h1 подряд, до звена с токеном верхней метки
//	верхняя метка её токен (время g2) лежит на участке: всё, что за ним, вошло в цепь позже g2
//
// Проверяющий пересчитывает корень каждого звена из листьев и требует, чтобы
// листья шли подряд от конца звена h1: выбросить или подложить запись нельзя —
// корень не сойдётся. Значит, всё, что вошло в цепь между g1 и g2, — в пакете.
// Время приёма каждой улики сверяется с метками вокруг неё теми же правилами,
// что в пакете одной улики, только «первая метка над её звеном» здесь
// проверяема: между ними видны все листья.

// WindowKind, WindowVersion — вид и версия пакета за окно. Версия своя: старый
// esverify отвечает «bundle version 2», а не разбирает пакет как пакет одной
// улики.
const (
	WindowKind    = "window"
	WindowVersion = 2
)

// BundleKind — вид пакета: WindowKind или "" (пакет одной улики).
func BundleKind(data []byte) (string, error) {
	var head struct {
		Kind string `json:"kind"`
	}
	if err := json.Unmarshal(data, &head); err != nil {
		return "", fmt.Errorf("proof: %w", err)
	}
	return head.Kind, nil
}

// WindowBundle — пакет за окно времени.
type WindowBundle struct {
	Version int    `json:"v"`
	Kind    string `json:"kind"`
	// From, To — окно, о котором спросили (время приёма). Это слова
	// хранилища: аудитор сверяет пакет со своим окном (esverify -from -to).
	From time.Time `json:"from"`
	To   time.Time `json:"to"`
	// LowerHead — голова, которую заверила нижняя метка: участок начинается
	// сразу после неё. Ноль — участок с начала цепи (меток раньше окна нет).
	LowerHead uint64 `json:"lower_head"`
	// StretchEnd — последнее звено участка: в нём токен верхней метки.
	StretchEnd uint64 `json:"stretch_end"`
	// Links — звенья подряд: LowerHead (или первое звено цепи), участок и,
	// по запросу (-to-head), звенья после него; последнее — голова Statement.
	Links []Link `json:"links"`
	// Leaves — все листья звеньев участка по порядку.
	Leaves    []Leaf               `json:"leaves"`
	Statement auditchain.Statement `json:"statement"`
	// Records — улики одного источника с участка и ключи их записей
	// (proof -source S -dek).
	Records []WindowRecord `json:"records,omitempty"`
}

// WindowRecord — улика с участка и ключ её записи. Ключа нет — ключ месяца
// уничтожен или ждёт уничтожения.
type WindowRecord struct {
	Evidence []byte `json:"evidence"`
	DEK      []byte `json:"dek,omitempty"`
}

// ParseWindow разбирает пакет за окно.
func ParseWindow(data []byte) (WindowBundle, error) {
	var b WindowBundle
	if err := json.Unmarshal(data, &b); err != nil {
		return b, fmt.Errorf("proof: %w", err)
	}
	if b.Kind != WindowKind || b.Version != WindowVersion {
		return b, fmt.Errorf("proof: bundle kind %q version %d, supported %q version %d", b.Kind, b.Version, WindowKind, WindowVersion)
	}
	return b, nil
}

// SeqRange — номера у источника от From до To включительно.
type SeqRange struct {
	From uint64 `json:"from"`
	To   uint64 `json:"to"`
}

func (g SeqRange) String() string {
	if g.From == g.To {
		return strconv.FormatUint(g.From, 10)
	}
	return fmt.Sprintf("%d–%d", g.From, g.To)
}

// SourceSummary — что пакет показывает об источнике на участке.
type SourceSummary struct {
	Name     string `json:"name"`
	Records  int    `json:"records"`   // улик на участке
	InWindow int    `json:"in_window"` // из них со временем приёма в окне
	FirstSeq uint64 `json:"first_seq"`
	LastSeq  uint64 `json:"last_seq"`
	// Gaps — пропуски номеров, записанные в цепь на участке.
	Gaps []SeqRange `json:"gaps,omitempty"`
	// Unexplained — номера между первым и последним, которых на участке нет
	// и пропуск о которых на участке не записан.
	Unexplained []SeqRange  `json:"unexplained,omitempty"`
	Silences    []time.Time `json:"silences,omitempty"`     // «источник молчит»
	ContactLost []time.Time `json:"contact_lost,omitempty"` // «сборщик пропал»
	ContactBack []time.Time `json:"contact_back,omitempty"` // «сборщик вернулся»
	Conflicts   int         `json:"conflicts,omitempty"`    // повтор номера с другим телом
	// Gateway — вердиктов по записям журнала гейтвея; GatewayBroken — из них
	// с поломкой.
	Gateway       int `json:"gateway_verdicts,omitempty"`
	GatewayBroken int `json:"gateway_broken,omitempty"`
}

// WindowBody — тело улики, вскрытое ключом записи из пакета.
type WindowBody struct {
	Source     string
	Seq        uint64
	ReceivedAt int64
	Body       []byte
}

// WindowReport — итог проверки пакета за окно.
type WindowReport struct {
	Checks []Check
	// From, To — окно, с которым сверялись; FromBundle — аудитор своего не
	// задал, окно взято из пакета.
	From, To   time.Time
	FromBundle bool
	// Lower, Upper — время нижней и верхней меток (g1, g2). FromStart —
	// участок с начала цепи, нижней метки нет.
	Lower, Upper time.Time
	FromStart    bool
	LowerHead    uint64
	StretchEnd   uint64
	HeadSeq      uint64
	Leaves       int
	Sources      []SourceSummary
	// Attached — приложенных улик; Bodies — вскрытые из них.
	Attached int
	Bodies   []WindowBody
	// GatewayRecords — приложенных улик из журнала гейтвея: их собственные
	// проверки — в пакете одной улики.
	GatewayRecords int
	// Сверка со свидетелем голов — как в Report.
	WitnessChecked bool
	WitnessHead    uint64
	WitnessNone    bool
	WitnessFork    uint64
}

// Valid — все проверки прошли.
func (r WindowReport) Valid() bool {
	for _, c := range r.Checks {
		if !c.OK {
			return false
		}
	}
	return len(r.Checks) > 0
}

// Verdict — итог одной строкой.
func (r WindowReport) Verdict() string {
	if r.Valid() {
		return "VERIFIED"
	}
	return "NOT VERIFIED"
}

// stretchLink — звено участка: номера его листьев [first, first+count) и
// место первого из них в пакете.
type stretchLink struct {
	seq   uint64
	first uint64
	count int
	at    int
}

// windowStamp — метка TSA на участке.
type windowStamp struct {
	link uint64    // звено, где лежит токен
	head uint64    // заверенная голова
	gen  time.Time // время TSA
}

// VerifyWindow проверяет пакет за окно. from, to — окно аудитора; оба нуля —
// сверка с окном из пакета (отчёт об этом говорит). Итог — Valid().
func VerifyWindow(b WindowBundle, trust Trust, from, to time.Time) WindowReport {
	r := WindowReport{From: from, To: to, LowerHead: b.LowerHead, StretchEnd: b.StretchEnd, Leaves: len(b.Leaves)}
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

	// 3. Участок: все листья звеньев после нижней головы, подряд, и они дают
	// корни звеньев. Без этого пункта полноты нет — дальше не идём.
	leaves := make([]auditchain.Leaf, len(b.Leaves))
	for i, l := range b.Leaves {
		leaves[i] = l.chain()
	}
	stretch, err := windowStretch(b, links, leaves)
	detail := fmt.Sprintf("after head %d up to link %d, %d leaves", b.LowerHead, b.StretchEnd, len(leaves))
	if b.LowerHead == 0 {
		detail = fmt.Sprintf("from the first link up to link %d, %d leaves", b.StretchEnd, len(leaves))
	}
	if !add("the bundle holds every leaf of the chain in the stretch, in order (Merkle roots)", err, detail) {
		return r
	}

	// 4. Токены всех меток участка сходятся с заверенными головами.
	stamps, err := windowStamps(leaves, stretch, linkAt, trust.TSA)
	if !add("every TSA time-stamp in the stretch verifies", err, fmt.Sprintf("%d time-stamps", len(stamps))) {
		return r
	}

	// 5. Нижняя метка заверила голову, после которой начинается участок: всё
	// до этой головы вошло в цепь раньше неё.
	lower := -1
	if b.LowerHead == 0 {
		r.FromStart = true
		add("the stretch starts at the beginning of the chain", nil, "there is no time-stamp before the window")
	} else {
		for i, st := range stamps {
			if st.head == b.LowerHead {
				lower = i
				break
			}
		}
		err = nil
		if lower < 0 {
			err = fmt.Errorf("no time-stamp in the stretch certifies head %d, after which the stretch starts", b.LowerHead)
		} else {
			r.Lower = stamps[lower].gen
		}
		add("a TSA time-stamp certifies the head the stretch starts after (T1)", err, fmt.Sprintf("T1 = %s, head %d", fmtTime(r.Lower), b.LowerHead))
	}

	// 6. Верхняя метка — над наибольшей головой участка (в честной цепи —
	// последняя): всё, что легло в цепь после её токена, вошло туда позже её
	// времени, а заверенная часть кончается её головой.
	err = nil
	top := -1
	for i, st := range stamps {
		if top < 0 || st.head > stamps[top].head {
			top = i
		}
	}
	if top < 0 || top == lower {
		err = errors.New("the stretch holds no time-stamp after the window: what entered the chain at its end is not bounded")
	} else {
		r.Upper = stamps[top].gen
	}
	add("a TSA time-stamp in the stretch after the window (T2)", err, fmt.Sprintf("T2 = %s", fmtTime(r.Upper)))

	// 7. Окно лежит строго между метками с допусками времени приёма
	// (windowBracket): ни запись до участка, ни запись после звена, которое
	// заверила верхняя метка, в окно не попадёт.
	add("the time-stamps bracket the window", windowBracket(r.From, r.To, r.Lower, r.Upper), fmt.Sprintf("%s – %s", fmtTime(r.From), fmtTime(r.To)))

	// Звенья после головы, которую заверила верхняя метка (пока шёл запрос
	// к TSA), ничем в пакете не заверены: владелец ключа мог там выдумать
	// запись или выбросить её. Их записи — не в сводке и не к приложению; в
	// окно они не попадают (windowBracket).
	certified := stretch
	if len(stamps) > 0 {
		var up uint64
		for _, st := range stamps {
			up = max(up, st.head)
		}
		for len(certified) > 0 && certified[len(certified)-1].seq > up {
			certified = certified[:len(certified)-1]
		}
	}
	var certLeaves []auditchain.Leaf
	for _, sl := range certified {
		certLeaves = append(certLeaves, leaves[sl.at:sl.at+sl.count]...)
	}

	// 8–9. Листья улик: разбираются, номер у источника — один раз, время
	// приёма — между метками вокруг звена. Заодно — сводка по источникам.
	// Записи после головы верхней метки в сводку не идут, но время их приёма
	// сверяется с ней: иначе запрос к TSA, затянутый ради того, чтобы
	// спрятать запись окна за голову ВЕРХНЕЙ метки, не виден (E1-02).
	r.Sources = summarize(leaves, stretch, len(certified), stamps, &r, add)

	// 10. Приложенные улики — с заверенной части участка, тела вскрываются
	// ключами записей.
	if len(b.Records) > 0 {
		err := windowRecords(b.Records, certLeaves, &r)
		add("the records attached are in the stretch, and their bodies open with their record keys", err,
			fmt.Sprintf("%d records, %d bodies opened", r.Attached, len(r.Bodies)))
	}

	// 11. Свидетель голов: как у пакета одной улики, головы свидетеля внутри
	// пакета обязаны совпасть с его звеньями.
	if trust.Witness != nil {
		var wr Report
		checkWitness(trust.Witness, trust.StoreKey, b.StretchEnd, links, hashes, &wr, add)
		r.WitnessChecked, r.WitnessHead, r.WitnessNone, r.WitnessFork = wr.WitnessChecked, wr.WitnessHead, wr.WitnessNone, wr.WitnessFork
	}
	return r
}

// windowStretch сверяет листья пакета со звеньями участка: звенья идут от
// нижней головы (или с начала цепи) до StretchEnd, листья каждого — подряд,
// без разрыва с предыдущим звеном, и дают его корень.
func windowStretch(b WindowBundle, links []auditchain.Record, leaves []auditchain.Leaf) ([]stretchLink, error) {
	start, next := 0, uint64(0)
	if b.LowerHead == 0 {
		if links[0].Seq != 1 || links[0].PrevHash != ([32]byte{}) {
			return nil, fmt.Errorf("the stretch is said to start at the beginning of the chain, but the bundle starts at link %d", links[0].Seq)
		}
	} else {
		if links[0].Seq != b.LowerHead {
			return nil, fmt.Errorf("the bundle starts at link %d, but the stretch is said to start after head %d", links[0].Seq, b.LowerHead)
		}
		p, err := batchOf(links[0])
		if err != nil {
			return nil, err
		}
		start, next = 1, p.FirstLeaf+uint64(p.Count)
	}
	var out []stretchLink
	at := 0
	for i := start; i < len(links) && links[i].Seq <= b.StretchEnd; i++ {
		p, err := batchOf(links[i])
		if err != nil {
			return nil, err
		}
		if p.FirstLeaf != next {
			return nil, fmt.Errorf("link %d covers leaves from %d, the link before it ends at %d: leaves between them are left out", links[i].Seq, p.FirstLeaf, next)
		}
		n := int(p.Count)
		if n > len(leaves)-at {
			return nil, fmt.Errorf("link %d holds %d leaves, the bundle has %d more: leaves are left out", links[i].Seq, n, len(leaves)-at)
		}
		if auditchain.MerkleRoot(leaves[at:at+n]) != p.Root {
			return nil, fmt.Errorf("the leaves of link %d do not give its Merkle root: a leaf was left out, added, changed or moved", links[i].Seq)
		}
		out = append(out, stretchLink{seq: links[i].Seq, first: next, count: n, at: at})
		at += n
		next += uint64(n)
	}
	switch {
	case len(out) == 0 || out[len(out)-1].seq != b.StretchEnd:
		return nil, fmt.Errorf("the stretch is said to end at link %d, the links in the bundle do not reach it", b.StretchEnd)
	case at != len(leaves):
		return nil, fmt.Errorf("the bundle has %d leaves beyond the stretch", len(leaves)-at)
	}
	return out, nil
}

func batchOf(l auditchain.Record) (auditchain.BatchPayload, error) {
	if l.Type != auditchain.EventBatch {
		return auditchain.BatchPayload{}, fmt.Errorf("link %d does not aggregate leaves", l.Seq)
	}
	p, err := auditchain.DecodeBatchPayload(l.Payload)
	if err != nil {
		return p, fmt.Errorf("link %d: %w", l.Seq, err)
	}
	return p, nil
}

// windowStamps проверяет токены всех меток участка: каждая заверяет голову,
// которая есть в пакете и лежит раньше звена с токеном.
func windowStamps(leaves []auditchain.Leaf, stretch []stretchLink, linkAt func(uint64) (auditchain.Record, [32]byte, bool), trust tsa.Trust) ([]windowStamp, error) {
	var out []windowStamp
	for _, sl := range stretch {
		for _, l := range leaves[sl.at : sl.at+sl.count] {
			if l.Type != auditchain.EventTimestamp {
				continue
			}
			head, err := strconv.ParseUint(l.Subject, 10, 64)
			if err != nil {
				return nil, fmt.Errorf("the time-stamp in link %d has no head number", sl.seq)
			}
			if head >= sl.seq {
				return nil, fmt.Errorf("the time-stamp in link %d certifies head %d, which cannot hold it yet", sl.seq, head)
			}
			_, hash, ok := linkAt(head)
			if !ok {
				return nil, fmt.Errorf("the time-stamp in link %d certifies head %d, which is not in the bundle", sl.seq, head)
			}
			info, err := tsa.Verify(l.Payload, HeadImprint(head, hash), trust)
			if err != nil {
				return nil, fmt.Errorf("the time-stamp in link %d over head %d: %w", sl.seq, head, err)
			}
			link, _, _ := linkAt(sl.seq)
			if err := tokenLinkTime(link, info.GenTime.UTC()); err != nil {
				return nil, err
			}
			out = append(out, windowStamp{link: sl.seq, head: head, gen: info.GenTime.UTC()})
		}
	}
	return out, nil
}

// stampBefore — самая поздняя по времени метка из тех, чью голову звено n
// уже прошло: запись в звене n легла в цепь после того, как эта голова ушла
// в TSA. Не последняя по месту: лист старого токена можно положить в цепь
// ещё раз, за токеном верхней метки, и продлить до него участок — тогда
// «последней» стала бы старая метка, и записи окна за головой верхней
// сверялись бы с ней (Q-48). В честной цепи время меток растёт с их местом,
// и выбор тот же. nil — такой метки на участке нет.
func stampBefore(stamps []windowStamp, n uint64) *windowStamp {
	var t0 *windowStamp
	for i := range stamps {
		if stamps[i].head < n && (t0 == nil || stamps[i].gen.After(t0.gen)) {
			t0 = &stamps[i]
		}
	}
	return t0
}

// stampsAround — метки вокруг звена n, как в пакете одной улики: самая
// поздняя по времени из тех, чей токен лёг в звено раньше n (T1; по той же
// причине, что в stampBefore), и первая над головой не раньше n (T2: копия
// старого токена над поздней головой не бывает). nil — такой метки на
// участке нет.
func stampsAround(stamps []windowStamp, n uint64) (t1, t2 *windowStamp) {
	for i := range stamps {
		if stamps[i].link < n && (t1 == nil || stamps[i].gen.After(t1.gen)) {
			t1 = &stamps[i]
		}
		if t2 == nil && stamps[i].head >= n {
			t2 = &stamps[i]
		}
	}
	return t1, t2
}

// summarize проходит листья участка: улики разбираются, номер у источника
// встречается один раз, время приёма — между метками вокруг звена (пункты
// 8–9). Возвращает сводку по источникам.
func summarize(leaves []auditchain.Leaf, stretch []stretchLink, certified int, stamps []windowStamp, r *WindowReport, add func(string, error, string) bool) []SourceSummary {
	sums := map[string]*SourceSummary{}
	sum := func(name string) *SourceSummary {
		s, ok := sums[name]
		if !ok {
			s = &SourceSummary{Name: name}
			sums[name] = s
		}
		return s
	}
	seqs := map[string][]uint64{}
	seen := map[string]map[uint64]bool{}
	var leafErr, timeErr error
	records := 0
	for k, sl := range stretch {
		t1, t2 := stampsAround(stamps, sl.seq)
		t0 := stampBefore(stamps, sl.seq)
		if k >= certified {
			// Незаверенный хвост участка: только время приёма по метке, чью
			// голову звено прошло.
			for _, l := range leaves[sl.at : sl.at+sl.count] {
				if l.Type != auditchain.EventEvidence || timeErr != nil || t0 == nil {
					continue
				}
				if recv := time.Unix(0, l.UnixNano).UTC(); !recv.After(t0.gen.Add(-WindowEdge)) {
					timeErr = fmt.Errorf("record %s/%s lies in link %d, after head %d the time-stamp of %s certifies, yet its receive time %s is not later than %s before it", l.Scope, l.Subject, sl.seq, t0.head, fmtTime(t0.gen), fmtTime(recv), WindowEdge)
				}
			}
			continue
		}
		for i, l := range leaves[sl.at : sl.at+sl.count] {
			switch l.Type {
			case auditchain.EventEvidence:
				records++
				seq, err := strconv.ParseUint(l.Subject, 10, 64)
				if _, _, perr := ParseEvidenceLeaf(l); err != nil || perr != nil {
					if leafErr == nil {
						leafErr = fmt.Errorf("leaf %d does not parse as a record", sl.first+uint64(i))
					}
					continue
				}
				if seen[l.Scope] == nil {
					seen[l.Scope] = map[uint64]bool{}
				}
				if seen[l.Scope][seq] && leafErr == nil {
					leafErr = fmt.Errorf("record %s/%d is in the chain twice", l.Scope, seq)
				}
				seen[l.Scope][seq] = true
				s := sum(l.Scope)
				s.Records++
				seqs[l.Scope] = append(seqs[l.Scope], seq)
				recv := time.Unix(0, l.UnixNano).UTC()
				if !recv.Before(r.From) && !recv.After(r.To) {
					s.InWindow++
				}
				switch {
				case timeErr != nil:
				case t2 != nil && recv.After(t2.gen.Add(ReceiveSlack)):
					timeErr = fmt.Errorf("record %s/%d: receive time %s is later than %s, the first time-stamp over its link %d", l.Scope, seq, fmtTime(recv), fmtTime(t2.gen), sl.seq)
				case t1 != nil && recv.Before(t1.gen.Add(-ReceiveSkew)):
					timeErr = fmt.Errorf("record %s/%d: receive time %s is earlier than %s, the last time-stamp before its link %d", l.Scope, seq, fmtTime(recv), fmtTime(t1.gen), sl.seq)
				case t0 != nil && !recv.After(t0.gen.Add(-WindowEdge)):
					// Запись легла в цепь после головы, которую метка t0 уже
					// понесла в TSA: честно она принята позже t0 − WindowEdge,
					// а запрос, затянутый ради того, чтобы спрятать её за
					// голову, виден здесь.
					timeErr = fmt.Errorf("record %s/%d lies in link %d, after head %d the time-stamp of %s certifies, yet its receive time %s is not later than %s before it", l.Scope, seq, sl.seq, t0.head, fmtTime(t0.gen), fmtTime(recv), WindowEdge)
				}
			case auditchain.EventGap:
				var g SeqRange
				if json.Unmarshal(l.Payload, &g) == nil && g.From > 0 && g.From <= g.To {
					s := sum(l.Scope)
					s.Gaps = append(s.Gaps, g)
				}
			case auditchain.EventSilence:
				s := sum(l.Scope)
				s.Silences = append(s.Silences, time.Unix(0, l.UnixNano).UTC())
			case auditchain.EventContact:
				s := sum(l.Scope)
				switch l.Subject {
				case "lost":
					s.ContactLost = append(s.ContactLost, time.Unix(0, l.UnixNano).UTC())
				case "back":
					s.ContactBack = append(s.ContactBack, time.Unix(0, l.UnixNano).UTC())
				}
			case auditchain.EventConflict:
				sum(l.Scope).Conflicts++
			case auditchain.EventGateway:
				if _, v, err := ParseGatewayLeaf(l); err == nil {
					s := sum(l.Scope)
					s.Gateway++
					if v.Problem != "" {
						s.GatewayBroken++
					}
				}
			}
		}
	}
	add("every record leaf parses, and every record number appears once", leafErr, fmt.Sprintf("%d records", records))
	add("every receive time lies between the time-stamps around its record", timeErr, "")

	out := make([]SourceSummary, 0, len(sums))
	for name, s := range sums {
		if list := seqs[name]; len(list) > 0 {
			sort.Slice(list, func(i, j int) bool { return list[i] < list[j] })
			s.FirstSeq, s.LastSeq = list[0], list[len(list)-1]
			s.Unexplained = unexplained(list, s.Gaps)
		}
		out = append(out, *s)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out
}

// unexplained — дыры в номерах между первым и последним, не покрытые
// записанными пропусками.
func unexplained(seqs []uint64, gaps []SeqRange) []SeqRange {
	var out []SeqRange
	for i := 1; i < len(seqs); i++ {
		if seqs[i] <= seqs[i-1]+1 {
			continue
		}
		parts := []SeqRange{{From: seqs[i-1] + 1, To: seqs[i] - 1}}
		for _, g := range gaps {
			var rest []SeqRange
			for _, p := range parts {
				if g.To < p.From || g.From > p.To {
					rest = append(rest, p)
					continue
				}
				if g.From > p.From {
					rest = append(rest, SeqRange{From: p.From, To: g.From - 1})
				}
				if g.To < p.To {
					rest = append(rest, SeqRange{From: g.To + 1, To: p.To})
				}
			}
			parts = rest
		}
		out = append(out, parts...)
	}
	return out
}

// windowRecords сверяет приложенные улики с их листьями на участке и
// вскрывает тела ключами записей.
func windowRecords(records []WindowRecord, leaves []auditchain.Leaf, r *WindowReport) error {
	byRecord := map[string]auditchain.Leaf{}
	for _, l := range leaves {
		if l.Type == auditchain.EventEvidence {
			byRecord[l.Scope+"\x00"+l.Subject] = l
		}
	}
	used := map[string]bool{}
	for i, rec := range records {
		r.Attached++
		sealed, err := evidence.Unmarshal(rec.Evidence)
		if err != nil {
			return fmt.Errorf("attached record %d does not parse: %w", i+1, err)
		}
		key := sealed.Source + "\x00" + strconv.FormatUint(sealed.Seq, 10)
		l, ok := byRecord[key]
		switch {
		case !ok:
			return fmt.Errorf("attached record %s/%d is not in the stretch", sealed.Source, sealed.Seq)
		case used[key]:
			return fmt.Errorf("record %s/%d is attached twice", sealed.Source, sealed.Seq)
		}
		used[key] = true
		_, digest, err := ParseEvidenceLeaf(l)
		switch {
		case err != nil:
			return err
		case digest != evidence.Digest(rec.Evidence):
			return fmt.Errorf("attached record %s/%d does not match the digest in its leaf", sealed.Source, sealed.Seq)
		case l.UnixNano != sealed.ReceivedAt:
			return fmt.Errorf("attached record %s/%d: the receive time does not match its leaf", sealed.Source, sealed.Seq)
		}
		if sealed.ContentType == gateway.ContentType {
			r.GatewayRecords++
		}
		if len(rec.DEK) == 0 {
			continue
		}
		body, err := keyring.OpenWithDEK(sealed.Envelope, rec.DEK)
		if err != nil {
			return fmt.Errorf("the body of %s/%d does not open with the record key in the bundle: %w", sealed.Source, sealed.Seq, err)
		}
		r.Bodies = append(r.Bodies, WindowBody{Source: sealed.Source, Seq: sealed.Seq, ReceivedAt: sealed.ReceivedAt, Body: body})
	}
	return nil
}

// Notes — чего пакет за окно не доказывает.
func (r WindowReport) Notes() []string {
	n := []string{
		"what happened at the sources: the bundle holds what the store received; a receive time is the store's clock, checked against the time-stamps around its record",
		"a record the store received in the window but held back and put into the chain later is not here: its own bundle shows the later entry, and the collector's signed promise for it shows the missed deadline",
		"the bundle shows the records of every source in the window as metadata (names, numbers, receive times, digests); bodies only of the records attached",
	}
	if r.FromBundle {
		n = append(n, "the window was taken from the bundle itself: check the bundle against your own window with esverify -from and -to")
	}
	for _, s := range r.Sources {
		for _, u := range s.Unexplained {
			n = append(n, fmt.Sprintf("%s: numbers %s are not in the stretch, and no gap is recorded for them in it: they entered the chain outside the window, or the store lost them — ask for their own bundles", s.Name, u))
		}
	}
	if r.Attached > len(r.Bodies) {
		n = append(n, fmt.Sprintf("%d of the %d records attached carry no record key: the month key was destroyed (retention) or awaits destruction", r.Attached-len(r.Bodies), r.Attached))
	}
	if r.GatewayRecords > 0 {
		n = append(n, "gateway journal records: the gateway's own checks (entry hash, checkpoint signature) are in single-record bundles (evidencestore proof -source S -seq N)")
	}
	if r.WitnessFork != 0 {
		n = append(n, fmt.Sprintf("the witness holds two versions of the chain, both signed with the store key (the first head it holds in two versions is %d): this stretch is not among them, but the store signed a second history — a rewrite, or a store that lost data without a copy; ask its operator", r.WitnessFork))
	}
	switch {
	case r.WitnessHead != 0:
		n = append(n, fmt.Sprintf("the witness saw head %d, and it fixes the chain up to that head: rewriting this stretch would contradict the witness, as long as the witness is out of the store administrator's reach", r.WitnessHead))
	case r.WitnessNone:
		n = append(n, "the witness has no head at or after the end of this stretch yet: until it gets one, only the TSA time-stamps stand against the store's owner rewriting the chain")
	default:
		n = append(n, "the store's signature proves that THIS store signed the head; only the TSA time-stamps stand against its owner rewriting the whole chain")
	}
	return n
}

// Text — отчёт человеческим языком. Как у пакета одной улики, всё, что
// пришло из пакета, печатается с экранированными управляющими символами, и
// вердикт повторён последней строкой. Тела в отчёт не идут: их могут быть
// тысячи (esverify -bodies DIR пишет их в файлы).
func (r WindowReport) Text() string {
	var b strings.Builder
	verdict := r.Verdict()
	b.WriteString(verdict + "\n\n")
	asked := "asked by the auditor"
	if r.FromBundle {
		asked = "named in the bundle"
	}
	fmt.Fprintf(&b, "Window (receive time): %s – %s (%s)\n", fmtTime(r.From), fmtTime(r.To), asked)
	start := "the beginning of the chain"
	if !r.FromStart {
		start = fmt.Sprintf("head %d, time-stamped %s", r.LowerHead, fmtTime(r.Lower))
	}
	if r.Valid() {
		fmt.Fprintf(&b, "Every record the store put into its chain from %s to the time-stamp of %s is in this bundle: links up to %d, %d leaves\n",
			start, fmtTime(r.Upper), r.StretchEnd, r.Leaves)
	} else {
		fmt.Fprintf(&b, "Stretch: from %s up to link %d, %d leaves\n", start, r.StretchEnd, r.Leaves)
	}
	if len(r.Sources) > 0 {
		b.WriteString("\nSources:\n")
		for _, s := range r.Sources {
			b.WriteString("  " + s.line() + "\n")
		}
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

// line — источник одной строкой отчёта.
func (s SourceSummary) line() string {
	var b strings.Builder
	if s.Records == 0 {
		fmt.Fprintf(&b, "%s: no records", s.Name)
	} else {
		fmt.Fprintf(&b, "%s: records %d–%d (%d in the stretch, %d received in the window)", s.Name, s.FirstSeq, s.LastSeq, s.Records, s.InWindow)
	}
	for _, g := range s.Gaps {
		fmt.Fprintf(&b, "; gap %s", g)
	}
	for _, t := range s.Silences {
		fmt.Fprintf(&b, "; silent at %s", fmtTime(t))
	}
	for _, t := range s.ContactLost {
		fmt.Fprintf(&b, "; collector lost contact at %s", fmtTime(t))
	}
	for _, t := range s.ContactBack {
		fmt.Fprintf(&b, "; collector back at %s", fmtTime(t))
	}
	if s.Conflicts > 0 {
		fmt.Fprintf(&b, "; %d seq conflicts", s.Conflicts)
	}
	if s.Gateway > 0 {
		fmt.Fprintf(&b, "; %d gateway entries, %d broken", s.Gateway, s.GatewayBroken)
	}
	return b.String()
}
