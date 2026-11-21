// Package pgtap превращает поток pgoutput в журнал до-образов для хранилища
// улик: берёт только транзакции наблюдаемых ролей (агентов) и транзакции
// отката, складывает каждую в сжатый поток и режет его на строки-записи, которые
// читает обычный escollect.
//
// ЧЬЯ ТРАНЗАКЦИЯ. В журнале PostgreSQL нет ни роли, ни application_name. Их
// кладёт туда сама база: триггер на оператор зовёт pg_logical_emit_message с
// префиксом "evidence/who" (setup-sql). Сообщение идёт в журнале перед
// изменениями своего оператора, поэтому к первому изменению транзакции уже
// известно, брать её или пропустить, и чужие транзакции в память не копятся.
//
// ФОРМАТ. Запись журнала — строка JSON:
//
//	{"xid":751,"part":1,"last":true,"gz":"<base64>"}
//
// xid наверху — поле субъекта для хранилища ("subject_field": "xid"). Поля gz
// всех частей транзакции, склеенные по порядку, — один поток gzip; в нём строки
// JSON: заголовок H (кто, отметки действия), описания таблиц R, изменения
// I/U/D со значениями колонок текстом (как их отдаёт PostgreSQL), T для
// TRUNCATE, M для отметок после первого изменения и итог C. Часть — не больше
// PartSize сжатых байт, так что строка влезает в запись хранилища (1 МиБ), а
// значение любой длины просто занимает несколько частей.
package pgtap

import (
	"bufio"
	"bytes"
	"compress/gzip"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"slices"
	"time"
	"unicode/utf8"

	"github.com/Nikolay1994Kaz/evidencestore/internal/pgoutput"
	"github.com/Nikolay1994Kaz/evidencestore/internal/pgwire"
)

// Префиксы сообщений журнала, которые понимает сборщик.
const (
	PrefixWho    = "evidence/who"    // ставит триггер: роль сессии
	PrefixAction = "evidence/action" // ставит MCP-сервер через evidence.mark_action
	PrefixUndo   = "evidence/undo"   // ставит транзакция отката
)

// FormatVersion — версия формата потока (поле v заголовка).
const FormatVersion = 1

// MaxPartSize — предел сжатых байт в одной части: в base64 это 1 013 336 байт,
// с обёрткой строка остаётся меньше предела тела записи (evidence.MaxBodyLen).
const MaxPartSize = 760_000

// Canary — строка-ловушка: изменение, в старом или новом образе которого колонка
// Column таблицы Table равна Value, поднимает тревогу.
type Canary struct {
	Table  string `json:"table"` // "schema.table"
	Column string `json:"column"`
	Value  string `json:"value"`
}

// Config — настройки журнала.
type Config struct {
	Dir   string   // каталог журнала: journal.jsonl, index.jsonl, alerts.jsonl
	Roles []string // роли, чьи транзакции брать
	// AlertRows — транзакция с таким числом изменений строк и больше поднимает
	// тревогу «массовое изменение». 0 — не следить.
	AlertRows int
	// RequireAction — транзакция наблюдаемой роли без отметки действия поднимает
	// тревогу: агент пришёл в базу в обход MCP-сервера.
	RequireAction bool
	Canaries      []Canary
	PartSize      int // 0 — 700 000
}

// RelInfo — то, чего нет в сообщении Relation: имена типов и первичный ключ.
type RelInfo struct {
	Types []string // по порядку колонок Relation
	PK    []string
}

// Catalog отвечает на вопросы к каталогу базы.
type Catalog interface {
	Describe(rel pgoutput.Relation) (RelInfo, error)
}

// Counts — сколько строк транзакция вставила, поправила, удалила в таблице.
type Counts struct {
	I int `json:"I"`
	U int `json:"U"`
	D int `json:"D"`
}

// IndexEntry — строка index.jsonl: одна взятая транзакция и где она в журнале.
type IndexEntry struct {
	XID        uint32            `json:"xid"`
	FirstLine  uint64            `json:"first_line"` // номера строк journal.jsonl, с единицы
	LastLine   uint64            `json:"last_line"`
	Changes    int               `json:"changes"`
	Tables     map[string]Counts `json:"tables,omitempty"`
	Truncated  []string          `json:"truncated,omitempty"`
	Who        json.RawMessage   `json:"who,omitempty"`
	Actions    []json.RawMessage `json:"actions,omitempty"`
	Undo       json.RawMessage   `json:"undo,omitempty"`
	CommitTime string            `json:"commit_time"`
	CommitLSN  string            `json:"commit_lsn"`
	EndLSN     string            `json:"end_lsn"`
}

// Alert — строка alerts.jsonl.
type Alert struct {
	Time   string `json:"time"`
	Kind   string `json:"kind"`
	XID    uint32 `json:"xid"`
	Detail string `json:"detail"`
}

// Stats — счётчики с запуска.
type Stats struct {
	Captured, Skipped         uint64 // транзакции
	Changes, SkippedChanges   uint64 // изменения строк
	Parts, Alerts, Duplicates uint64
}

// Tap — журнал до-образов.
type Tap struct {
	cfg   Config
	cat   Catalog
	log   *slog.Logger
	now   func() time.Time
	roles map[string]bool

	journal, index, alerts *os.File
	lines                  uint64 // строк в journal.jsonl
	lastCommit             uint64 // CommitLSN последней транзакции в индексе
	rels                   map[uint32]pgoutput.Relation
	info                   map[uint32]RelInfo
	tx                     *txState
	stats                  Stats
}

type txState struct {
	begin   pgoutput.Begin
	dup     bool // уже в журнале: сервер прислал её повторно после перезапуска
	capture bool
	skipped int // изменения, пропущенные до решения «не наша»
	late    bool

	who, undo json.RawMessage
	actions   []json.RawMessage
	header    bool
	changes   int
	tables    map[string]Counts
	truncated []string
	written   map[uint32]bool
	alerts    []Alert

	buf       bytes.Buffer
	gz        *gzip.Writer
	parts     int
	firstLine uint64
}

// Open открывает (или заводит) журнал в cfg.Dir.
func Open(cfg Config, cat Catalog, log *slog.Logger) (_ *Tap, err error) {
	if cfg.PartSize == 0 {
		cfg.PartSize = 700_000
	}
	if cfg.PartSize < 64 || cfg.PartSize > MaxPartSize {
		return nil, fmt.Errorf("pgtap: part size %d: from 64 to %d bytes", cfg.PartSize, MaxPartSize)
	}
	if len(cfg.Roles) == 0 {
		return nil, errors.New("pgtap: name at least one role to watch")
	}
	if log == nil {
		log = slog.New(slog.DiscardHandler)
	}
	if err := os.MkdirAll(cfg.Dir, 0o700); err != nil {
		return nil, err
	}
	t := &Tap{cfg: cfg, cat: cat, log: log, now: time.Now, roles: map[string]bool{},
		rels: map[uint32]pgoutput.Relation{}, info: map[uint32]RelInfo{}}
	for _, r := range cfg.Roles {
		t.roles[r] = true
	}
	defer func() {
		if err != nil {
			t.Close()
		}
	}()
	if t.journal, t.lines, _, err = openLines(filepath.Join(cfg.Dir, "journal.jsonl")); err != nil {
		return nil, err
	}
	var last []byte
	if t.index, _, last, err = openLines(filepath.Join(cfg.Dir, "index.jsonl")); err != nil {
		return nil, err
	}
	if t.alerts, _, _, err = openLines(filepath.Join(cfg.Dir, "alerts.jsonl")); err != nil {
		return nil, err
	}
	if len(last) > 0 {
		var e IndexEntry
		if err := json.Unmarshal(last, &e); err != nil {
			return nil, fmt.Errorf("pgtap: last line of index.jsonl: %w", err)
		}
		lsn, err := pgwire.ParseLSN(e.CommitLSN)
		if err != nil {
			return nil, fmt.Errorf("pgtap: last line of index.jsonl: %w", err)
		}
		t.lastCommit = uint64(lsn)
	}
	return t, nil
}

// openLines открывает файл строк на дозапись, считает строки и отдаёт последнюю.
// Оборванный хвост без перевода строки отрезается: его транзакция серверу не
// подтверждена и придёт заново, а следующая строка иначе приклеилась бы к обрывку.
func openLines(path string) (_ *os.File, lines uint64, last []byte, err error) {
	f, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return nil, 0, nil, err
	}
	defer func() {
		if err != nil {
			f.Close()
		}
	}()
	r := bufio.NewReaderSize(f, 1<<20)
	var good int64
	for {
		line, err := r.ReadBytes('\n')
		if len(line) > 0 && line[len(line)-1] == '\n' {
			good += int64(len(line))
			lines++
			last = append(last[:0], line[:len(line)-1]...)
		}
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, 0, nil, err
		}
	}
	if err := f.Truncate(good); err != nil {
		return nil, 0, nil, err
	}
	if _, err := f.Seek(good, io.SeekStart); err != nil {
		return nil, 0, nil, err
	}
	return f, lines, last, nil
}

// Close закрывает файлы журнала.
func (t *Tap) Close() error {
	var errs []error
	for _, f := range []*os.File{t.journal, t.index, t.alerts} {
		if f != nil {
			errs = append(errs, f.Close())
		}
	}
	return errors.Join(errs...)
}

// Stats — счётчики с запуска.
func (t *Tap) Stats() Stats { return t.stats }

// InTransaction — между Begin и Commit: подтверждать серверу позицию дальше
// последнего Commit сейчас нельзя.
func (t *Tap) InTransaction() bool { return t.tx != nil }

// Handle принимает очередное сообщение pgoutput. flushed != 0 — транзакция
// закончена и всё, что от неё нужно, лежит на диске: эту позицию можно
// подтвердить серверу.
func (t *Tap) Handle(msg any) (flushed uint64, err error) {
	switch m := msg.(type) {
	case pgoutput.Begin:
		if t.tx != nil {
			return 0, fmt.Errorf("pgtap: begin of %d inside transaction %d", m.XID, t.tx.begin.XID)
		}
		t.tx = &txState{begin: m, dup: m.FinalLSN <= t.lastCommit}
		return 0, nil
	case pgoutput.Relation:
		t.rels[m.ID] = m
		delete(t.info, m.ID)
		return 0, nil
	case pgoutput.Other:
		return 0, nil
	case pgoutput.Message:
		if !m.Transactional || t.tx == nil || t.tx.dup {
			return 0, nil
		}
		return 0, t.mark(m)
	}
	if t.tx == nil {
		return 0, fmt.Errorf("pgtap: %T outside a transaction", msg)
	}
	tx := t.tx
	switch m := msg.(type) {
	case pgoutput.Commit:
		t.tx = nil
		if tx.dup {
			t.stats.Duplicates++
			return m.EndLSN, nil
		}
		if !tx.capture {
			t.stats.Skipped++
			t.stats.SkippedChanges += uint64(tx.skipped)
			return m.EndLSN, nil
		}
		return m.EndLSN, t.finish(tx, m)
	case pgoutput.Insert:
		return 0, t.change(tx, 'I', m.RelID, 'O', nil, m.New)
	case pgoutput.Update:
		return 0, t.change(tx, 'U', m.RelID, m.OldKind, m.Old, m.New)
	case pgoutput.Delete:
		return 0, t.change(tx, 'D', m.RelID, m.OldKind, m.Old, nil)
	case pgoutput.Truncate:
		if tx.dup {
			return 0, nil
		}
		if !tx.capture {
			tx.skipped++
			return 0, nil
		}
		var names []string
		for _, id := range m.RelIDs {
			rel, ok := t.rels[id]
			if !ok {
				return 0, fmt.Errorf("pgtap: truncate of relation %d that was never described", id)
			}
			names = append(names, rel.Namespace+"."+rel.Name)
		}
		if !tx.header {
			if err := t.start(tx); err != nil {
				return 0, err
			}
		}
		tx.truncated = append(tx.truncated, names...)
		t.alert(tx, "truncate", fmt.Sprintf("TRUNCATE %v: the rows are not in the journal and cannot be restored from it", names))
		return 0, t.write(tx, struct {
			T      string   `json:"t"`
			Tables []string `json:"tables"`
		}{"T", names})
	default:
		return 0, fmt.Errorf("pgtap: unexpected message %T", msg)
	}
}

// mark разбирает отметку в журнале: чья транзакция, какое действие, откат ли.
func (t *Tap) mark(m pgoutput.Message) error {
	tx := t.tx
	content := json.RawMessage(m.Content)
	if !json.Valid(content) {
		content, _ = json.Marshal(string(m.Content))
	}
	var who struct {
		Role string `json:"role"`
	}
	json.Unmarshal(content, &who)
	ours := false
	switch m.Prefix {
	case PrefixWho:
		if ours = t.roles[who.Role]; ours && tx.who == nil {
			tx.who = content
		}
	case PrefixAction:
		if ours = t.roles[who.Role]; ours {
			tx.actions = append(tx.actions, content)
		}
	case PrefixUndo:
		ours = true
		if tx.undo == nil {
			tx.undo = content
		}
	default:
		return nil
	}
	if !ours {
		return nil
	}
	if tx.skipped > 0 && !tx.capture && !tx.late {
		// Изменения до отметки уже пропущены: такая транзакция в журнале не вся.
		tx.late = true
		t.alert(tx, "late-marker", fmt.Sprintf("a %s marker came after %d changes of the transaction had been skipped: they are not in the journal", m.Prefix, tx.skipped))
		return t.flushAlerts(tx)
	}
	if tx.late {
		return nil
	}
	tx.capture = true
	if tx.header {
		// Отметка после первого изменения (свой триггер у каждого оператора).
		if m.Prefix == PrefixWho {
			return nil // роль у сессии одна, первая отметка уже в заголовке
		}
		return t.write(tx, struct {
			T       string          `json:"t"`
			Prefix  string          `json:"prefix"`
			Content json.RawMessage `json:"content"`
		}{"M", m.Prefix, content})
	}
	return nil
}

func (t *Tap) alert(tx *txState, kind, detail string) {
	tx.alerts = append(tx.alerts, Alert{Time: t.now().UTC().Format(time.RFC3339Nano), Kind: kind, XID: tx.begin.XID, Detail: detail})
}

func (t *Tap) flushAlerts(tx *txState) error {
	if len(tx.alerts) == 0 {
		return nil
	}
	var buf bytes.Buffer
	for _, a := range tx.alerts {
		line, _ := json.Marshal(a)
		buf.Write(append(line, '\n'))
		t.log.Warn("alert", "kind", a.Kind, "xid", a.XID, "detail", a.Detail)
		t.stats.Alerts++
	}
	tx.alerts = nil
	if _, err := t.alerts.Write(buf.Bytes()); err != nil {
		return err
	}
	return t.alerts.Sync()
}

// start пишет заголовок потока: к первому изменению отметки уже прочитаны.
func (t *Tap) start(tx *txState) error {
	tx.header = true
	tx.gz = gzip.NewWriter(&tx.buf)
	tx.tables = map[string]Counts{}
	tx.written = map[uint32]bool{}
	tx.firstLine = t.lines + 1
	return t.write(tx, struct {
		T          string            `json:"t"`
		V          int               `json:"v"`
		XID        uint32            `json:"xid"`
		CommitTime string            `json:"commit_time"`
		CommitLSN  string            `json:"commit_lsn"`
		Who        json.RawMessage   `json:"who,omitempty"`
		Actions    []json.RawMessage `json:"actions,omitempty"`
		Undo       json.RawMessage   `json:"undo,omitempty"`
	}{"H", FormatVersion, tx.begin.XID, tx.begin.CommitTime.UTC().Format(time.RFC3339Nano), pgwire.LSN(tx.begin.FinalLSN).String(), tx.who, tx.actions, tx.undo})
}

func (t *Tap) write(tx *txState, v any) error {
	line, err := json.Marshal(v)
	if err != nil {
		return err
	}
	if _, err := tx.gz.Write(append(line, '\n')); err != nil {
		return err
	}
	for tx.buf.Len() >= t.cfg.PartSize+1 {
		// Байт сверх части — значит, поток продолжается: эта часть не последняя.
		if err := t.part(tx, tx.buf.Next(t.cfg.PartSize), false); err != nil {
			return err
		}
	}
	return nil
}

func (t *Tap) part(tx *txState, data []byte, last bool) error {
	tx.parts++
	line := make([]byte, 0, base64.StdEncoding.EncodedLen(len(data))+80)
	line = fmt.Appendf(line, `{"xid":%d,"part":%d,"last":%t,"gz":"`, tx.begin.XID, tx.parts, last)
	line = base64.StdEncoding.AppendEncode(line, data)
	line = append(line, '"', '}', '\n')
	if _, err := t.journal.Write(line); err != nil {
		return err
	}
	t.lines++
	t.stats.Parts++
	return nil
}

func (t *Tap) describe(tx *txState, id uint32) (pgoutput.Relation, error) {
	rel, ok := t.rels[id]
	if !ok {
		return rel, fmt.Errorf("pgtap: change of relation %d that was never described", id)
	}
	if tx.written[id] {
		return rel, nil
	}
	info, ok := t.info[id]
	if !ok {
		var err error
		if info, err = t.cat.Describe(rel); err != nil {
			return rel, fmt.Errorf("pgtap: describe %s.%s: %w", rel.Namespace, rel.Name, err)
		}
		if len(info.Types) != len(rel.Columns) {
			return rel, fmt.Errorf("pgtap: describe %s.%s: %d types for %d columns", rel.Namespace, rel.Name, len(info.Types), len(rel.Columns))
		}
		t.info[id] = info
	}
	cols := make([]string, len(rel.Columns))
	for i, c := range rel.Columns {
		cols[i] = c.Name
	}
	if rel.Identity != 'f' {
		t.alert(tx, "identity", fmt.Sprintf("%s.%s is not REPLICA IDENTITY FULL: old rows are not in the journal, its changes cannot be undone", rel.Namespace, rel.Name))
	}
	tx.written[id] = true
	return rel, t.write(tx, struct {
		T        string   `json:"t"`
		ID       uint32   `json:"id"`
		Schema   string   `json:"schema"`
		Table    string   `json:"table"`
		Identity string   `json:"identity"`
		Columns  []string `json:"columns"`
		Types    []string `json:"types"`
		PK       []string `json:"pk"`
	}{"R", id, rel.Namespace, rel.Name, string(rel.Identity), cols, info.Types, info.PK})
}

func (t *Tap) change(tx *txState, op byte, id uint32, oldKind byte, old, fresh []pgoutput.Value) error {
	if tx.dup {
		return nil
	}
	if !tx.capture {
		tx.skipped++
		return nil
	}
	if !tx.header {
		if err := t.start(tx); err != nil {
			return err
		}
	}
	rel, err := t.describe(tx, id)
	if err != nil {
		return err
	}
	line := struct {
		T       string `json:"t"`
		R       uint32 `json:"r"`
		Old     []any  `json:"old,omitempty"`
		New     []any  `json:"new,omitempty"`
		Partial bool   `json:"partial,omitempty"` // старая строка в журнале не вся
	}{T: string(op), R: id}
	full := oldKind == 'O'
	if op != 'I' && !full {
		line.Partial = true
	}
	for name, tuple := range map[string][]pgoutput.Value{"old": old, "new": fresh} {
		if tuple == nil || (name == "old" && !full) {
			continue
		}
		if len(tuple) != len(rel.Columns) {
			return fmt.Errorf("pgtap: %s.%s: a row of %d values for %d columns", rel.Namespace, rel.Name, len(tuple), len(rel.Columns))
		}
		vals := make([]any, len(tuple))
		for i, v := range tuple {
			if v.Kind == pgoutput.Unchanged && name == "new" && full {
				v = old[i] // значение в TOAST не менялось: оно равно старому
			}
			if vals[i], err = value(v); err != nil {
				return fmt.Errorf("pgtap: %s.%s.%s: %w", rel.Namespace, rel.Name, rel.Columns[i].Name, err)
			}
		}
		if name == "old" {
			line.Old = vals
		} else {
			line.New = vals
		}
	}
	key := rel.Namespace + "." + rel.Name
	c := tx.tables[key]
	switch op {
	case 'I':
		c.I++
	case 'U':
		c.U++
	case 'D':
		c.D++
	}
	tx.tables[key] = c
	tx.changes++
	for _, cn := range t.cfg.Canaries {
		if cn.Table != key {
			continue
		}
		i := slices.IndexFunc(rel.Columns, func(col pgoutput.Column) bool { return col.Name == cn.Column })
		if i < 0 {
			continue
		}
		for _, vals := range [][]any{line.Old, line.New} {
			if vals != nil && vals[i] == any(cn.Value) {
				t.alert(tx, "canary", fmt.Sprintf("%s: the canary row %s=%s was touched (%c)", key, cn.Column, cn.Value, op))
				break
			}
		}
	}
	return t.write(tx, line)
}

// value — значение колонки для потока: строка, null или пометка.
func value(v pgoutput.Value) (any, error) {
	switch v.Kind {
	case pgoutput.Null:
		return nil, nil
	case pgoutput.Text:
		if utf8.Valid(v.Data) {
			return string(v.Data), nil
		}
		// Кодировка базы не UTF-8: байты как есть, откат такое значение не берёт.
		return map[string]string{"b64": base64.StdEncoding.EncodeToString(v.Data)}, nil
	case pgoutput.Unchanged:
		return map[string]bool{"unchanged": true}, nil
	default:
		return nil, fmt.Errorf("value of kind %q (the stream must be text)", v.Kind)
	}
}

// finish дописывает транзакцию: итог, остаток потока частями, индекс, тревоги.
// Возвращается после fsync журнала и индекса.
func (t *Tap) finish(tx *txState, c pgoutput.Commit) error {
	if !tx.header {
		// Отметки есть, изменений нет (оператор не тронул ни одной строки).
		if err := t.start(tx); err != nil {
			return err
		}
	}
	if err := t.write(tx, struct {
		T       string `json:"t"`
		Changes int    `json:"changes"`
		EndLSN  string `json:"end_lsn"`
	}{"C", tx.changes, pgwire.LSN(c.EndLSN).String()}); err != nil {
		return err
	}
	if err := tx.gz.Close(); err != nil {
		return err
	}
	for tx.buf.Len() > t.cfg.PartSize {
		if err := t.part(tx, tx.buf.Next(t.cfg.PartSize), false); err != nil {
			return err
		}
	}
	if err := t.part(tx, tx.buf.Bytes(), true); err != nil {
		return err
	}
	if err := t.journal.Sync(); err != nil {
		return err
	}
	entry := IndexEntry{
		XID: tx.begin.XID, FirstLine: tx.firstLine, LastLine: t.lines, Changes: tx.changes, Tables: tx.tables,
		Truncated: tx.truncated, Who: tx.who, Actions: tx.actions, Undo: tx.undo,
		CommitTime: tx.begin.CommitTime.UTC().Format(time.RFC3339Nano),
		CommitLSN:  pgwire.LSN(tx.begin.FinalLSN).String(), EndLSN: pgwire.LSN(c.EndLSN).String(),
	}
	line, err := json.Marshal(entry)
	if err != nil {
		return err
	}
	if _, err := t.index.Write(append(line, '\n')); err != nil {
		return err
	}
	if err := t.index.Sync(); err != nil {
		return err
	}
	t.lastCommit = tx.begin.FinalLSN
	t.stats.Captured++
	t.stats.Changes += uint64(tx.changes)
	if t.cfg.AlertRows > 0 && tx.changes >= t.cfg.AlertRows {
		t.alert(tx, "mass-change", fmt.Sprintf("%d row changes in one transaction (the threshold is %d)", tx.changes, t.cfg.AlertRows))
	}
	if t.cfg.RequireAction && tx.who != nil && len(tx.actions) == 0 && tx.undo == nil {
		t.alert(tx, "no-action", "a transaction of a watched role carries no action marker: it did not come through the MCP server")
	}
	return t.flushAlerts(tx)
}

// Record — строка потока транзакции после распаковки.
type Record map[string]any

// ReadTransaction собирает транзакцию из строк журнала (тел записей хранилища)
// по порядку: берёт последний целый набор частей 1..k с "last": true — после
// перезапуска сборщика транзакция может лежать дважды, первый раз оборванной, —
// и распаковывает поток. Строки другой транзакции — ошибка.
func ReadTransaction(xid uint32, lines [][]byte) ([]Record, error) {
	type part struct {
		XID  uint32 `json:"xid"`
		Part int    `json:"part"`
		Last bool   `json:"last"`
		GZ   []byte `json:"gz"`
	}
	var run, whole []part
	for i, l := range lines {
		var p part
		if err := json.Unmarshal(l, &p); err != nil {
			return nil, fmt.Errorf("pgtap: line %d: %w", i+1, err)
		}
		if p.XID != xid {
			return nil, fmt.Errorf("pgtap: line %d is of transaction %d, not %d", i+1, p.XID, xid)
		}
		if p.Part == 1 {
			run = run[:0]
		}
		if p.Part != len(run)+1 {
			return nil, fmt.Errorf("pgtap: transaction %d: part %d follows part %d: a part is missing", xid, p.Part, len(run))
		}
		run = append(run, p)
		if p.Last {
			whole = slices.Clone(run)
			run = run[:0]
		}
	}
	if whole == nil {
		return nil, fmt.Errorf("pgtap: transaction %d: no last part: the transaction is not all here", xid)
	}
	var stream bytes.Buffer
	for _, p := range whole {
		stream.Write(p.GZ)
	}
	gz, err := gzip.NewReader(&stream)
	if err != nil {
		return nil, fmt.Errorf("pgtap: transaction %d: %w", xid, err)
	}
	var out []Record
	dec := json.NewDecoder(gz)
	for {
		var r Record
		if err := dec.Decode(&r); err == io.EOF {
			break
		} else if err != nil {
			return nil, fmt.Errorf("pgtap: transaction %d: %w", xid, err)
		}
		out = append(out, r)
	}
	if n := len(out); n < 2 || out[0]["t"] != "H" || out[n-1]["t"] != "C" {
		return nil, fmt.Errorf("pgtap: transaction %d: the stream does not run from H to C", xid)
	}
	return out, nil
}
