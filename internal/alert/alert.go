// Package alert — тревоги сборщика: что случилось, файл-очередь и доставка
// человеку.
//
// Тревога — строка alerts.jsonl (Event): всё, что есть сказать об одной
// транзакции агента (несколько поводов разом и сводка: кто, какое действие,
// сколько строк, под какими номерами записей она лежит в хранилище), или одно
// служебное событие сборщика: нет связи с базой, записи потеряны, действие
// агента остановлено пределом строк.
//
// ФАЙЛ — ОЧЕРЕДЬ, А НЕ ВИТРИНА. Человек тревогу в файле не увидит: ему её
// несёт Notifier — в Telegram, в Slack-совместимый веб-хук или на свой адрес в
// JSON. Файл при этом остаётся: тревога сначала ложится в него с fsync, и
// только потом отправляется. Получатель недоступен — она ждёт в файле и уйдёт
// позже; сбор записей от отправки не зависит и её не ждёт. У каждого
// получателя свой курсор (notify-<имя>.json): докуда файл ему уже отправлен.
//
// Доставка — «хотя бы один раз»: упади сборщик между ответом получателя и
// записью курсора, сообщение придёт дважды. Потерять тревогу хуже, чем
// повторить.
//
// Адреса получателей — секреты (в адресе веб-хука Slack и в адресе Telegram
// сидит ключ): в журнал сборщика они не попадают ни сами, ни в тексте ошибок.
package alert

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"slices"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
	"unicode"
	"unicode/utf8"
)

// Поводы тревог.
const (
	KindMassChange = "mass-change" // изменений в транзакции не меньше порога
	KindCanary     = "canary"      // тронута строка-ловушка
	KindTruncate   = "truncate"    // TRUNCATE: строк в записи нет
	KindIdentity   = "identity"    // таблица без REPLICA IDENTITY FULL
	// KindNotViaGateway — транзакция по названным таблицам без намерения
	// шлюза (require_gateway): в базу писали не через шлюз.
	KindNotViaGateway = "not-via-gateway"
	// KindForgedReceipt — строка файла квитанций, подписанная не ключом шлюза:
	// её дописал тот, у кого ключа нет.
	KindForgedReceipt = "forged-receipt"
	KindRefused       = "refused"        // MCP-сервер остановил действие пределом строк
	KindEscaped       = "escaped"        // SQL агента сам закрыл транзакцию MCP-сервера
	KindUnknown       = "commit-unknown" // связь MCP-сервера с базой оборвалась на COMMIT: действие могло зафиксироваться
	KindDBDown        = "db-down"        // нет связи с базой дольше порога
	KindDBUp          = "db-up"          // связь с базой вернулась
	KindGap           = "gap"            // записи потеряны: слот удалён или его журнал стёрт
	KindSlotLag       = "slot-lag"       // база копит журнал для слота: до предела — половина или меньше
	KindSlotOK        = "slot-ok"        // журнал для слота снова в норме
	KindDropped       = "dropped"        // тревога слишком длинная для доставки: вместо неё — эта, с местом в файле
)

// Signal — один повод тревоги.
type Signal struct {
	Kind   string `json:"kind"`
	Detail string `json:"detail"`
}

// Counts — сколько строк транзакция вставила, поправила, удалила в таблице.
type Counts struct {
	I int `json:"I"`
	U int `json:"U"`
	D int `json:"D"`
}

// Event — строка alerts.jsonl. XID == 0 — служебное событие, не транзакция.
type Event struct {
	Time    string   `json:"time"`
	XID     uint32   `json:"xid,omitempty"`
	Signals []Signal `json:"signals"`
	// О транзакции — то же, что в её строке справочника.
	Changes int               `json:"changes,omitempty"`
	Tables  map[string]Counts `json:"tables,omitempty"`
	// Action — действие шлюза, чья это транзакция (по его подписанному
	// намерению); у служебного события — действие, о котором оно (отказ,
	// обрыв на COMMIT). Нет — транзакция не через шлюз.
	Action   *Action `json:"action,omitempty"`
	FirstSeq uint64  `json:"first_seq,omitempty"`
	LastSeq  uint64  `json:"last_seq,omitempty"`
	// Fingerprint — от транзакции в хранилище только отпечаток (намерения
	// шлюза нет): откатить её нельзя.
	Fingerprint bool `json:"fingerprint,omitempty"`
}

// Action — действие шлюза по его квитанции (DECISIONS, п. 42): какой шлюз,
// какая квитанция цепочки (seq и SHA-256 строки — по ним её находят в
// хранилище), номер действия и шаг: StepIntent — действие агента, StepUndo —
// откат.
type Action struct {
	ID      string `json:"id"`
	Gateway string `json:"gateway"`
	Seq     uint64 `json:"seq"`
	Hash    string `json:"hash"`
	Step    string `json:"step"`
	Time    string `json:"time,omitempty"` // часы шлюза: ничего не доказывают
	Agent   string `json:"agent,omitempty"`
	Tool    string `json:"tool,omitempty"`
	Reason  string `json:"reason,omitempty"`
	Undoes  string `json:"undoes,omitempty"` // у отката — какое действие он возвращает
}

// Шаги квитанций шлюза, которые читает сборщик Postgres.
const (
	StepIntent  = "intent"  // перед COMMIT: действие агента в транзакции xid
	StepUndo    = "undo"    // перед COMMIT: откат действия в транзакции xid
	StepOutcome = "outcome" // после: чем кончилось
)

// Add добавляет повод; точный повтор (ловушку тронули дважды одним и тем же
// оператором) не добавляется.
func (e *Event) Add(kind, detail string) {
	for _, s := range e.Signals {
		if s.Kind == kind && s.Detail == detail {
			return
		}
	}
	e.Signals = append(e.Signals, Signal{Kind: kind, Detail: detail})
}

// Kinds — поводы события по порядку.
func (e Event) Kinds() []string {
	out := make([]string, len(e.Signals))
	for i, s := range e.Signals {
		out[i] = s.Kind
	}
	return out
}

// OpenLines открывает файл строк на дозапись. Оборванный хвост без перевода
// строки отрезается (падение посреди записи): иначе следующая строка
// приклеилась бы к обрывку.
func OpenLines(path string) (_ *os.File, err error) {
	f, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return nil, err
	}
	defer func() {
		if err != nil {
			f.Close()
		}
	}()
	fi, err := f.Stat()
	if err != nil {
		return nil, err
	}
	// Конец последней целой строки ищется в хвосте файла, а не чтением всего.
	size := fi.Size()
	good := size
	for step := int64(64 << 10); good > 0; step *= 16 {
		tail := make([]byte, min(size, step))
		if _, err := f.ReadAt(tail, size-int64(len(tail))); err != nil {
			return nil, err
		}
		if i := bytes.LastIndexByte(tail, '\n'); i >= 0 {
			good = size - int64(len(tail)) + int64(i) + 1
			break
		}
		if int64(len(tail)) == size {
			good = 0
		}
	}
	if good != size {
		if err := f.Truncate(good); err != nil {
			return nil, err
		}
	}
	if _, err := f.Seek(good, io.SeekStart); err != nil {
		return nil, err
	}
	return f, nil
}

// Log — alerts.jsonl: тревоги по порядку, каждая — с fsync.
type Log struct {
	mu   sync.Mutex
	f    *os.File
	path string
	wake func()
}

// OpenLog открывает (или заводит) файл тревог.
func OpenLog(path string) (*Log, error) {
	f, err := OpenLines(path)
	if err != nil {
		return nil, err
	}
	return &Log{f: f, path: path}, nil
}

// Path — путь файла.
func (l *Log) Path() string { return l.path }

// OnAppend задаёт, кого будить после каждой записанной тревоги (Notifier.Wake).
func (l *Log) OnAppend(wake func()) {
	l.mu.Lock()
	l.wake = wake
	l.mu.Unlock()
}

// Append дописывает тревогу и возвращается после fsync.
func (l *Log) Append(e Event) error {
	if len(e.Signals) == 0 {
		return errors.New("alert: an event without a signal")
	}
	if e.Time == "" {
		e.Time = time.Now().UTC().Format(time.RFC3339Nano)
	}
	line, err := json.Marshal(e)
	if err != nil {
		return err
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	if _, err := l.f.Write(append(line, '\n')); err != nil {
		return err
	}
	if err := l.f.Sync(); err != nil {
		return err
	}
	if l.wake != nil {
		l.wake()
	}
	return nil
}

// Close закрывает файл.
func (l *Log) Close() error {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.f.Close()
}

// TextOptions — чем дополнить текст тревоги.
type TextOptions struct {
	// Title — о какой базе речь: "database shop".
	Title string
	// UndoHint — команда, которой оператор смотрит откат транзакции; {xid}
	// заменяется её номером. Пусто — без подсказки.
	UndoHint string
}

// maxText — предел текста одного сообщения в знаках: у Telegram — 4096, запас —
// на пометку об обрезке.
const maxText = 3500

// maxTables — столько таблиц называет сообщение; остальные — числом. Так же
// с поводами (maxSignals), а длинная строка режется до maxLine знаков:
// сообщение должно дойти до сводки и команды отката, а не кончиться на
// сотом одинаковом поводе.
const (
	maxTables  = 8
	maxSignals = 8
	maxLine    = 400
)

// short режет строку до maxLine знаков.
func short(s string) string {
	if r := []rune(s); len(r) > maxLine {
		return string(r[:maxLine]) + "…"
	}
	return s
}

// field — значение из отметки (номер действия, имя агента, роль, имя
// приложения) одной строкой и не длиннее строки тревоги: управляющие символы
// (и перевод строки), разделители строк и символы направления текста — кодом
// \uXXXX. Отметки пишет и SQL агента (P-255), а application_name он ставит
// сам: иначе он дописывал в тревогу свои строки («changed: 1 row», «approved by
// the on-call DBA») или длиной выталкивал настоящие (T заход 2).
//
// Сначала экранирование, потом предел: иначе каждый управляющий символ
// становился шестью знаками, и поле росло вшестеро сверх предела (R1, R2
// заход 3). Field — то же для pgtap: поля отметки об отказе.
func field(s string) string {
	var b strings.Builder
	for _, c := range s {
		if unicode.IsControl(c) || unicode.Is(unicode.Bidi_Control, c) || unicode.In(c, unicode.Zl, unicode.Zp) {
			fmt.Fprintf(&b, "\\u%04x", c)
			continue
		}
		b.WriteRune(c)
	}
	return short(b.String())
}

// Field — значение из отметки одной строкой и не длиннее строки тревоги.
func Field(s string) string { return field(s) }

// Text — тревога словами, для человека: что случилось, кто и какое действие,
// сколько строк и чем посмотреть откат.
func Text(e Event, o TextOptions) string {
	var b strings.Builder
	title := o.Title
	if title == "" {
		title = "collector"
	}
	undo := e.Action != nil && e.Action.Step == StepUndo
	switch {
	case e.XID != 0 && undo:
		fmt.Fprintf(&b, "evidencestore, %s: undo transaction %d", title, e.XID)
	case e.XID != 0 && e.Fingerprint:
		fmt.Fprintf(&b, "evidencestore, %s: transaction %d not through the gateway (only its fingerprint is kept)", title, e.XID)
	case e.XID != 0 && e.Action != nil:
		fmt.Fprintf(&b, "evidencestore, %s: agent transaction %d", title, e.XID)
	case e.XID != 0:
		fmt.Fprintf(&b, "evidencestore, %s: transaction %d", title, e.XID)
	default:
		fmt.Fprintf(&b, "evidencestore, %s", title)
	}
	for i, s := range e.Signals {
		if i == maxSignals {
			fmt.Fprintf(&b, "\n• and %d more signals", len(e.Signals)-maxSignals)
			break
		}
		fmt.Fprintf(&b, "\n• %s: %s", s.Kind, short(s.Detail))
	}
	if act := describeAction(e.Action); act != "" {
		fmt.Fprintf(&b, "\naction: %s", act)
	}
	if len(e.Tables) > 0 {
		rows := "rows"
		if e.Changes == 1 {
			rows = "row"
		}
		fmt.Fprintf(&b, "\nchanged: %d %s — %s", e.Changes, rows, describeTables(e.Tables))
	}
	// Конец сообщения — где транзакция лежит и чем посмотреть откат — не
	// режется никогда: режется, если не влезло, то, что перед ним.
	var tail strings.Builder
	if e.FirstSeq != 0 {
		if e.FirstSeq == e.LastSeq {
			fmt.Fprintf(&tail, "\nstore record: %d", e.FirstSeq)
		} else {
			fmt.Fprintf(&tail, "\nstore records: %d–%d", e.FirstSeq, e.LastSeq)
		}
		// Откат TRUNCATE esundo не делает: подсказывать его нечего (T-8, заход 2).
		if o.UndoHint != "" && !undo && !e.Fingerprint && !slices.Contains(e.Kinds(), KindTruncate) {
			fmt.Fprintf(&tail, "\nundo preview: %s", short(strings.ReplaceAll(o.UndoHint, "{xid}", strconv.FormatUint(uint64(e.XID), 10))))
		}
	}
	return clip(b.String(), maxText-utf8.RuneCountInString(tail.String())) + tail.String()
}

// cutNote — пометка в конце обрезанного сообщения.
const cutNote = "\n… (cut: the whole alert is in alerts.jsonl on the collector host)"

// clip обрезает текст до limit знаков вместе с пометкой об обрезке.
func clip(s string, limit int) string {
	if utf8.RuneCountInString(s) <= limit {
		return s
	}
	r := []rune(s)
	return string(r[:max(limit-utf8.RuneCountInString(cutNote), 0)]) + cutNote
}

func describeAction(a *Action) string {
	if a == nil || a.ID == "" {
		return ""
	}
	s := field(a.ID)
	if a.Agent != "" {
		s += ", agent " + field(a.Agent)
	}
	s += fmt.Sprintf(" (receipt %d of gateway %s)", a.Seq, field(a.Gateway))
	if a.Undoes != "" {
		s += ", undoes " + field(a.Undoes)
	}
	if a.Reason != "" {
		s += fmt.Sprintf(" — reason given: %q", short(a.Reason))
	}
	return s
}

func describeTables(tables map[string]Counts) string {
	names := make([]string, 0, len(tables))
	for n := range tables {
		names = append(names, n)
	}
	total := func(n string) int { c := tables[n]; return c.I + c.U + c.D }
	sort.Slice(names, func(i, j int) bool {
		if total(names[i]) != total(names[j]) {
			return total(names[i]) > total(names[j])
		}
		return names[i] < names[j]
	})
	var parts []string
	for i, n := range names {
		if i == maxTables {
			parts = append(parts, fmt.Sprintf("and %d more tables", len(names)-maxTables))
			break
		}
		c := tables[n]
		var ops []string
		for _, op := range []struct {
			name string
			n    int
		}{{"inserted", c.I}, {"updated", c.U}, {"deleted", c.D}} {
			if op.n > 0 {
				ops = append(ops, fmt.Sprintf("%s %d", op.name, op.n))
			}
		}
		parts = append(parts, short(n)+" ("+strings.Join(ops, ", ")+")")
	}
	return strings.Join(parts, "; ")
}

// Digest — одно сообщение вместо многих: получатель был недоступен, и тревог
// накопилось столько, что по одной они завалили бы его.
func Digest(events []Event, o TextOptions) string {
	title := o.Title
	if title == "" {
		title = "collector"
	}
	counts := map[string]int{}
	var kinds []string
	var xids []string
	for _, e := range events {
		for _, s := range e.Signals {
			if counts[s.Kind] == 0 {
				kinds = append(kinds, s.Kind)
			}
			counts[s.Kind]++
		}
		if e.XID != 0 && len(xids) < 30 {
			xids = append(xids, strconv.FormatUint(uint64(e.XID), 10))
		}
	}
	sort.Strings(kinds)
	for i, k := range kinds {
		kinds[i] = fmt.Sprintf("%s ×%d", k, counts[k])
	}
	var b strings.Builder
	fmt.Fprintf(&b, "evidencestore, %s: %d alerts were waiting for this channel, from %s to %s", title, len(events), events[0].Time, events[len(events)-1].Time)
	fmt.Fprintf(&b, "\n%s", strings.Join(kinds, ", "))
	if len(xids) > 0 {
		fmt.Fprintf(&b, "\ntransactions: %s", strings.Join(xids, ", "))
		if len(xids) == 30 {
			b.WriteString(", …")
		}
	}
	b.WriteString("\neach of them is in alerts.jsonl on the collector host; the latest ones follow")
	return clip(b.String(), maxText)
}
