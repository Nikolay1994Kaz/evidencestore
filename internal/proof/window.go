package proof

import (
	"encoding/json"
	"errors"
	"fmt"
	"maps"
	"slices"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/Nikolay1994Kaz/evidencestore/internal/auditchain"
	"github.com/Nikolay1994Kaz/evidencestore/internal/evidence"
	"github.com/Nikolay1994Kaz/evidencestore/internal/gateway"
	"github.com/Nikolay1994Kaz/evidencestore/internal/keyring"
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

// WindowKind, WindowVersion — вид и версия пакета за окно (и пакета по
// источнику). Версия своя: старый esverify отвечает «bundle version …», а не
// разбирает пакет как пакет одной улики. Версия 3 (P-23, после v0.3.1) —
// пакет над цепью, где узел листа несёт признак метки. Версия 4 (P-46, после
// v0.4.0) — улики с ключами только у записей окна, в пакете по источнику
// каждая запись окна обязана быть приложена, и есть пакет по субъекту. Версия 5
// (P-70) — метки субъекта по месяцам (SubjectClaim.Labels): пакет версии 4 с
// одной меткой Go прочёл бы как пакет, не называющий ни одной. Прежние версии
// этим выпуском не читаются.
// unreleasedWindowVersions — версии пакетов за окно и по источнику, которые
// писала только сборка между выпусками: версия 4 — сборка 07.11 (edae072).
var unreleasedWindowVersions = []int{4}

const (
	WindowKind    = "window"
	WindowVersion = 5
)

// InWindow — время приёма t в окне [from, to], оба края включены. Одно на
// выдачу и проверку: запись на краю либо открыта, либо нет, у обеих сторон.
func InWindow(t, from, to time.Time) bool { return !t.Before(from) && !t.After(to) }

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
	// по запросу (-to-head), звенья после него; последнее — голова Checkpoint.
	Links []Link `json:"links"`
	// Frontier — граница дерева звеньев перед первым звеном пакета.
	Frontier [][]byte `json:"frontier,omitempty"`
	// Leaves — все листья звеньев участка по порядку.
	Leaves     []Leaf     `json:"leaves"`
	Checkpoint Checkpoint `json:"checkpoint"`
	// Records — улики одного источника с участка и ключи их записей
	// (proof -source S -dek).
	Records []WindowRecord `json:"records,omitempty"`
	// KeysFor — источник, для которого просили ключи (-window -source S -dek).
	// Месяц с закрытым ключом хранилище отдаёт листом, и пакет, где так весь
	// источник, без этой пометки не отличить от пакета без -dek. Пометка не
	// подписана и меняет только заметки, не вердикт (P-80).
	KeysFor string `json:"keys_for,omitempty"`
	// Cosignatures — подписи свидетелей C2SP над головой не раньше конца
	// участка (cosigned.go).
	Cosignatures []Cosignature `json:"cosignatures,omitempty"`
	// Archive — метки второй службы над головами не раньше меток участка
	// (revoked.go).
	Archive []ArchiveStamp `json:"archive,omitempty"`
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
		return b, fmt.Errorf("proof: bundle kind %q version %d, supported %q version %d%s", b.Kind, b.Version, WindowKind, WindowVersion, olderRelease(b.Version, WindowVersion, unreleasedWindowVersions...))
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
	// Attached — приложенных улик; Bodies — вскрытые из них, в окне аудитора;
	// outside — вскрытых вне его окна: в отчёт и в файлы они не идут.
	Attached int
	Bodies   []WindowBody
	outside  int
	// LeafOnly — записей окна у источника с приложенными уликами, пришедших
	// листом: в их месяце пакет не несёт ни одной улики (P-80); LeafOnlyMonths
	// — эти месяцы.
	LeafOnly       int
	LeafOnlyMonths []string
	// KeyReceipts — квитанции ключей месяцев на заверенной части участка
	// (P-84): слова хранилища, но лежат в цепи под метками TSA.
	KeyReceipts []KeyReceipt
	// GatewayRecords — приложенных улик из журнала гейтвея: их собственные
	// проверки — в пакете одной улики.
	GatewayRecords int
	// Сверка со свидетелем голов — как в Report.
	WitnessChecked bool
	WitnessHead    uint64
	WitnessNone    bool
	WitnessFork    uint64
	WitnessRefused int
	// WitnessReceived, WitnessUntimed — как у пакета одной улики (P-21).
	WitnessReceived time.Time
	WitnessUntimed  bool
	// CosignChecked, Cosigned, CosignUnknown, CosignCarried — как у пакета
	// одной улики: закрепляется конец участка.
	CosignChecked bool
	Cosigned      []CosignedHead
	CosignUnknown int
	CosignCarried int
	// TSANotes — заметки об отзыве сертификатов служб меток (revoked.go).
	TSANotes []string
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
	sc := newStampCheck(trust)
	stamps, err := windowStamps(leaves, stretch, linkAt, sc)
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
	// Квитанции ключей на заверенной части участка, со звеном каждой: по ним
	// видно, с какого звена месяц закрыт, по слову хранилища (P-84, P-90).
	r.KeyReceipts = keyReceipts(leaves, certified)

	// 10. Приложенные улики — с заверенной части участка, тела вскрываются
	// ключами записей.
	if len(b.Records) > 0 || b.KeysFor != "" {
		err := windowRecords(b.Records, certLeaves, &r)
		if err == nil {
			err = windowAttached(b.Records, b.KeysFor, certLeaves, b.From, b.To, &r)
		}
		r.Bodies = slices.DeleteFunc(r.Bodies, func(body WindowBody) bool {
			out := !InWindow(time.Unix(0, body.ReceivedAt), r.From, r.To)
			if out {
				r.outside++
			}
			return out
		})
		add("the records attached are in the stretch, and their bodies open with their record keys", err,
			fmt.Sprintf("%d records, %d bodies opened", r.Attached, len(r.Bodies)))
	}

	// 11. Свидетель голов: как у пакета одной улики, головы свидетеля внутри
	// пакета обязаны совпасть с его звеньями.
	if trust.Witness != nil {
		var wr Report
		checkWitness(trust.Witness, trust.StoreKey, b.StretchEnd, links, rootAt, &wr, add)
		r.WitnessChecked, r.WitnessHead, r.WitnessNone, r.WitnessFork, r.WitnessRefused = wr.WitnessChecked, wr.WitnessHead, wr.WitnessNone, wr.WitnessFork, wr.WitnessRefused
		r.WitnessReceived, r.WitnessUntimed = wr.WitnessReceived, wr.WitnessUntimed
	}
	r.CosignCarried = len(b.Cosignatures)
	if len(trust.Cosigners) > 0 {
		r.CosignChecked = true
		var err error
		r.Cosigned, r.CosignUnknown, err = checkCosigned(b.Cosignatures, trust.Cosigners, trust.StoreKey, b.StretchEnd, links, rootAt)
		add(cosignCheckName, err, cosignDetail(r.Cosigned))
	}
	sc.finish(b.Archive, b.Cosignatures, trust.Cosigners, trust.StoreKey, links[len(links)-1].Seq, rootAt, add)
	r.TSANotes = sc.notes
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
func windowStamps(leaves []auditchain.Leaf, stretch []stretchLink, linkAt func(uint64) (auditchain.Record, [32]byte, bool), sc *stampCheck) ([]windowStamp, error) {
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
			_, root, ok := linkAt(head)
			if !ok {
				return nil, fmt.Errorf("the time-stamp in link %d certifies head %d, which is not in the bundle", sl.seq, head)
			}
			info, err := sc.verify(l.Payload, head, root, sl.seq, fmt.Sprintf("the time-stamp in link %d", sl.seq))
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
				if InWindow(recv, r.From, r.To) {
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

// KeyReceipt — квитанция ключа месяца в цепи: скоуп, состояние, операция, время
// листа и звено, где он лежит. Closes — состояние закрывает месяц с этого
// звена: ключ ждёт уничтожения или уничтожен (Final — насовсем). deactivated
// месяц не закрывает: прошлый месяц хранилище деактивирует само через
// несколько минут после его конца, и отмена уничтожения возвращает ключ туда
// же; ключ жив, и месяц идёт уликами (P-90).
type KeyReceipt struct {
	Scope  string    `json:"scope"`
	State  string    `json:"state"`
	Op     string    `json:"op,omitempty"`
	At     time.Time `json:"at"`
	Link   uint64    `json:"link"`
	Closes bool      `json:"closes"`
	Final  bool      `json:"final"`
}

// keyReceipts — квитанции ключей на заверенной части участка, по порядку цепи.
// Операция — из предмета квитанции, слова хранилища: без неё квитанция та же.
func keyReceipts(leaves []auditchain.Leaf, certified []stretchLink) []KeyReceipt {
	var out []KeyReceipt
	for _, sl := range certified {
		for _, l := range leaves[sl.at : sl.at+sl.count] {
			if l.Type != auditchain.EventKeyState {
				continue
			}
			var ev struct {
				Op string `json:"op"`
			}
			_ = json.Unmarshal(l.Payload, &ev)
			final := l.Subject == "destroyed" || l.Subject == "destroyed-effective"
			out = append(out, KeyReceipt{Scope: l.Scope, State: l.Subject, Op: ev.Op, At: time.Unix(0, l.UnixNano).UTC(), Link: sl.seq,
				Closes: final || l.Subject == "pending-destruction", Final: final})
		}
	}
	return out
}

// receiptsNote — квитанции ключей участка: закрывающие — все, остальные — до
// двадцати: закрывающую предел списка не прячет (R2-01).
func receiptsNote(rs []KeyReceipt) string {
	const show = 20
	var closing, other []string
	for _, kr := range rs {
		s := fmt.Sprintf("%q %q", kr.Scope, kr.State)
		if kr.Op != "" {
			s += fmt.Sprintf(" (op %q)", kr.Op)
		}
		s += fmt.Sprintf(" at %s, link %d", fmtTime(kr.At), kr.Link)
		if kr.Closes {
			closing = append(closing, s)
		} else {
			other = append(other, s)
		}
	}
	if len(other) > show {
		other = append(other[:show], fmt.Sprintf("and %d more", len(other)-show))
	}
	text := `the stretch holds the store's key receipts, its own statements, in the chain under the time-stamps; a month is closed from its link on by pending-destruction or destroyed (destroyed for good, a pending destruction until a later cancel: deactivated, op "cancel-destroy"), and deactivated does not close it: the store deactivates every past month a few minutes after it ends, and its key lives`
	if len(closing) > 0 {
		text += "; closing: " + strings.Join(closing, ", ")
	}
	if len(other) > 0 {
		text += "; not closing: " + strings.Join(other, ", ")
	}
	return text
}

// leafMonthsReceipts — что квитанции участка говорят о месяцах, пришедших в
// этом пакете листом (R2-01): по последней квитанции месяца на участке. Нет
// квитанций — пусто: о них говорит ReceiptsPath.
func leafMonthsReceipts(rs []KeyReceipt, months []string) string {
	last := map[string]KeyReceipt{}
	for _, kr := range rs {
		last[kr.Scope] = kr
	}
	var gone, pending, open []string
	for _, m := range months {
		switch kr, ok := last[m]; {
		case !ok:
		case kr.Final:
			gone = append(gone, m)
		case kr.Closes:
			pending = append(pending, m)
		default:
			open = append(open, m)
		}
	}
	var parts []string
	if len(gone) > 0 {
		parts = append(parts, fmt.Sprintf("the last receipt of %s in this stretch is destroyed: by the store's own word its key was gone for good before this bundle was issued", QuotedList(gone)))
	}
	if len(pending) > 0 {
		parts = append(parts, fmt.Sprintf("the last receipt of %s in this stretch is pending-destruction: by the store's own word its key was closed then, and a destruction can be cancelled after this stretch", QuotedList(pending)))
	}
	if len(open) > 0 {
		parts = append(parts, fmt.Sprintf("the last receipt of %s in this stretch does not close it: nothing here shows that the store closed the month, and its evidence may have been taken out of this bundle; if the store closed it later, the closing receipt lies later in the chain", QuotedList(open)))
	}
	return strings.Join(parts, "; ")
}

// Keyless — улик окна без ключа записи: их тела не открыты, и -bodies о них
// говорит (T-03).
func (r WindowReport) Keyless() int { return r.Attached - len(r.Bodies) - r.outside }

// windowAttached: у источника с приложенными уликами приложены все его записи
// окна (P-46), как в пакете по источнику: снятая улика прятала бы тело неудобной
// записи. Окно — аудитора: шире окна пакета — и улик не хватит.
func windowAttached(records []WindowRecord, keysFor string, leaves []auditchain.Leaf, bundleFrom, bundleTo time.Time, r *WindowReport) error {
	attached := map[string]bool{}
	sources := map[string]bool{}
	if keysFor != "" {
		sources[keysFor] = true
	}
	// Месяцы источников, чьи улики пакет несёт: в таком месяце улика обязательна
	// у каждой записи окна (P-46). Месяц источника без единой улики — листом:
	// так хранилище отдаёт месяц, чей ключ уничтожен или ждёт уничтожения
	// (P-80). Лист в пакете за окно и так целиком.
	scopes := map[string]bool{}
	for _, rec := range records {
		sealed, err := evidence.Unmarshal(rec.Evidence)
		if err != nil {
			return err
		}
		sources[sealed.Source] = true
		scopes[sealed.Scope()] = true
		attached[sealed.Source+"\x00"+strconv.FormatUint(sealed.Seq, 10)] = true
	}
	leafMonths := map[string]bool{}
	missing := 0
	for _, l := range leaves {
		if l.Type != auditchain.EventEvidence || !sources[l.Scope] || attached[l.Scope+"\x00"+l.Subject] || !InWindow(time.Unix(0, l.UnixNano), r.From, r.To) {
			continue
		}
		// Листом — только запись из окна самого пакета: окно аудитора шире
		// пакета, зашедшее в другой месяц, — недостача, а не закрытый месяц
		// (P-81).
		if scope := evidence.ScopeOf(l.Scope, l.UnixNano); !scopes[scope] && InWindow(time.Unix(0, l.UnixNano), bundleFrom, bundleTo) {
			r.LeafOnly++
			leafMonths[scope] = true
			continue
		}
		missing++
	}
	r.LeafOnlyMonths = slices.Sorted(maps.Keys(leafMonths))
	if missing > 0 {
		return fmt.Errorf("%d records received in the window come without their evidence: ask for a bundle over this window", missing)
	}
	return nil
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
	if keyless := r.Keyless(); keyless > 0 {
		n = append(n, fmt.Sprintf("%d of the %d records attached carry no record key: %s", keyless, r.Attached, KeylessReasons))
	}
	if r.LeafOnly > 0 {
		n = append(n, LeafOnlyNote(r.LeafOnly, r.LeafOnlyMonths))
	}
	if len(r.KeyReceipts) > 0 {
		n = append(n, receiptsNote(r.KeyReceipts))
		if s := leafMonthsReceipts(r.KeyReceipts, r.LeafOnlyMonths); s != "" {
			n = append(n, s)
		}
	}
	if r.GatewayRecords > 0 {
		n = append(n, "gateway journal records: the gateway's own checks (entry hash, checkpoint signature) are in single-record bundles (evidencestore proof -source S -seq N)")
	}
	if r.WitnessRefused != 0 {
		n = append(n, fmt.Sprintf("a collector refused %d heads signed with the store key (in its checkpoints-conflict.jsonl): the store showed it a second history, or lost the end of its chain; ask its operator", r.WitnessRefused))
	}
	if r.WitnessFork != 0 {
		n = append(n, fmt.Sprintf("the witness holds two versions of the chain, both signed with the store key (the first head it holds in two versions is %d): this stretch is not among them, but the store signed a second history — a rewrite, or a store that lost data without a copy; ask its operator", r.WitnessFork))
	}
	switch {
	case r.WitnessHead != 0:
		n = append(n, fmt.Sprintf("the witness saw head %d, and it fixes the chain up to that head: rewriting this stretch would contradict the witness, as long as the witness is out of the store administrator's reach", r.WitnessHead))
		if r.WitnessUntimed {
			n = append(n, WitnessUntimedNote)
		}
	case r.WitnessNone && len(r.Cosigned) > 0:
		n = append(n, "the witness has no head at or after the end of this stretch yet")
	case r.WitnessNone:
		n = append(n, "the witness has no head at or after the end of this stretch yet: until it gets one, only the TSA time-stamps stand against the store's owner rewriting the chain")
	case len(r.Cosigned) == 0:
		n = append(n, "the store's signature proves that THIS store signed the head; only the TSA time-stamps stand against its owner rewriting the whole chain")
	}
	n = append(n, CosignNotes(r.CosignChecked, r.Cosigned, r.CosignUnknown, r.CosignCarried, "this stretch", "T2", r.Upper)...)
	return append(n, r.TSANotes...)
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
