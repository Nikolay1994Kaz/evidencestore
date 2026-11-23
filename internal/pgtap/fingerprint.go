package pgtap

// ОТПЕЧАТКИ (DECISIONS, п. 41). С Config.All вход берёт все транзакции по
// названным таблицам, а не только наблюдаемых ролей: запись чужой ролью
// (петля dblink, чужая функция SECURITY DEFINER, украденный пароль владельца)
// иначе не попала бы в хранилище вовсе (P-289). Полные строки «до» и «после»
// нужны только для отката — то есть ролям агента, сервера и отката, и
// транзакциям без отметки «кто» (триггер выключен, секция без него: такое
// подозрительно и редко). Транзакция другой роли — людей, приложения — ложится
// отпечатком: кто, xid, время, таблицы, ключи строк, вид изменения и хеши
// старой и новой строки. Самих строк в нём нет, и откатить её из хранилища
// нельзя (pgundo отказывает: Kind = KindFingerprint).
//
// Отпечатки складываются пачкой — одна запись хранилища на много транзакций:
// цена записи хранилища (конверт, звено цепи — около 0,75 КБ, замер 23.11)
// делится на пачку. Пачка уходит в буфер, когда в ней PackTx транзакций или
// PartSize байт, перед первой полной транзакцией после неё и когда ей больше
// PackWait (Tick, по умолчанию минута; у -once — в конце прохода, Flush). До
// этого её транзакции базе не подтверждаются (Pending): упадёт сборщик — база
// пришлёт их заново. Тревоги отпечатка (ловушка, массовое изменение, TRUNCATE)
// поднимаются сразу, на его фиксации.
//
// Формат записи пачки — строка JSON:
//
//	{"xid":"pack","pack":3,"v":1,"gz":"<base64>"}
//
// Поле xid — PackSubject, не номер: хранилище ставит пачкам одну метку
// субъекта, не совпадающую ни с одним xid. Без метки пачка в пакете по окну
// времени была бы «записью без субъекта, может быть чьей угодно», и окно
// перестало бы доказывать, что других записей транзакции агента нет. Пачка
// транзакций агента не держит никогда: транзакция либо целиком, либо
// отпечатком, с первой отметки или первого изменения. В gz — строки JSON, по
// одной на транзакцию (fpEntry).
//
// Хеш строки — первые 16 байт SHA-256 от массива значений колонок в JSON, как
// он стоит в полной записи (значения текстом, как их отдаёт PostgreSQL), в
// base64 без выравнивания. По строке из базы или бэкапа его можно пересчитать
// и сверить. Хеш строки с малым разнообразием значений подбирается перебором:
// тела записей в хранилище зашифрованы, но получатель пакета хеши видит.

import (
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"slices"
	"strconv"
	"time"

	"github.com/Nikolay1994Kaz/evidencestore/internal/pgoutput"
	"github.com/Nikolay1994Kaz/evidencestore/internal/pgwire"
)

// KindFingerprint — IndexEntry.Kind транзакции, от которой в хранилище только
// отпечаток.
const KindFingerprint = "fingerprint"

// PackSubject — значение поля xid записи пачки: её метка субъекта в хранилище.
// Не число — с xid транзакции не совпадёт.
const PackSubject = "pack"

// Пачка отпечатков по умолчанию.
const (
	DefaultPackTx   = 500
	DefaultPackWait = time.Minute
)

// fpRow — изменение строки в отпечатке.
type fpRow struct {
	T       string `json:"t"`            // I, U, D
	R       string `json:"r"`            // schema.table
	K       []any  `json:"k,omitempty"`  // ключ строки (старой, если она есть)
	NK      []any  `json:"nk,omitempty"` // новый ключ, если UPDATE его сменил
	O       string `json:"o,omitempty"`  // хеш старой строки
	N       string `json:"n,omitempty"`  // хеш новой строки
	Partial bool   `json:"partial,omitempty"`
}

// fpEntry — транзакция в пачке.
type fpEntry struct {
	XID        uint32            `json:"xid"`
	CommitTime string            `json:"commit_time"`
	CommitLSN  string            `json:"commit_lsn"`
	EndLSN     string            `json:"end_lsn"`
	Who        json.RawMessage   `json:"who,omitempty"`
	Changes    int               `json:"changes"`
	Tables     map[string]Counts `json:"tables,omitempty"`
	Truncated  []string          `json:"truncated,omitempty"`
	Rows       []json.RawMessage `json:"rows,omitempty"` // fpRow

	end uint64 // EndLSN числом
}

// pack — отпечатки, ещё не ушедшие в буфер.
type pack struct {
	entries []fpEntry
	buf     bytes.Buffer
	gz      *gzip.Writer
	since   time.Time // когда легла первая транзакция пачки
	last    uint64    // FinalLSN последней транзакции пачки
	end     uint64    // EndLSN последней — её подтверждают серверу
	n       uint64    // номер пачки с запуска (поле pack записи)
}

// Pending — в пачке есть отпечатки, которых ещё нет в буфере: позицию дальше
// их транзакций подтверждать серверу нельзя.
func (t *Tap) Pending() bool { return len(t.pack.entries) > 0 }

// Tick — пачка старше PackWait (с её первой транзакции) уходит в буфер.
// flushed != 0 — позиция, которую теперь можно подтвердить серверу.
func (t *Tap) Tick() (flushed uint64, err error) {
	if !t.Pending() || t.now().Sub(t.pack.since) < t.cfg.PackWait {
		return 0, nil
	}
	return t.flushPack()
}

// Flush — пачка уходит в буфер сейчас (проход -once молчит или кончился).
func (t *Tap) Flush() (flushed uint64, err error) {
	if !t.Pending() {
		return 0, nil
	}
	return t.flushPack()
}

// hashRow — хеш строки (см. заголовок файла): по колонкам подряд NULL — «-»,
// значение — «длина в байтах:байты» текста, как его отдал журнал. Значение,
// которого в журнале нет (не менялось и лежит в TOAST, а старой строки
// целиком нет), — хеша нет: ok = false.
func hashRow(tuple []pgoutput.Value) (_ string, ok bool) {
	h := sha256.New()
	var n [20]byte
	for _, v := range tuple {
		switch v.Kind {
		case pgoutput.Null:
			h.Write([]byte{'-'})
		case pgoutput.Text:
			h.Write(strconv.AppendInt(n[:0], int64(len(v.Data)), 10))
			h.Write([]byte{':'})
			h.Write(v.Data)
		default:
			return "", false
		}
	}
	return base64.RawStdEncoding.EncodeToString(h.Sum(nil)[:16]), true
}

// fpInline — сколько байт строк отпечатка транзакция держит в памяти до
// фиксации, чтобы лечь в пачку. Больше — она пишется своими частями, как
// полная, только отпечатком (Kind в справочнике тот же): память сборщика и
// запись хранилища не зависят от размера транзакции (R1-2, R2-2, T-2).
func (t *Tap) fpInline() int { return min(256<<10, t.cfg.PartSize/2) }

// fpChange — изменение строки транзакции-отпечатка.
func (t *Tap) fpChange(tx *txState, op byte, id uint32, oldKind byte, old, fresh []pgoutput.Value) error {
	rel, ok := t.rels[id]
	if !ok {
		return fmt.Errorf("pgtap: change of relation %d that was never described", id)
	}
	info, ok := t.info[id]
	if !ok {
		var err error
		if info, err = t.cat.Describe(rel); err != nil {
			return fmt.Errorf("pgtap: describe %s.%s: %w", rel.Namespace, rel.Name, err)
		}
		t.info[id] = info
	}
	full := oldKind == 'O'
	row := fpRow{T: string(op), R: rel.Namespace + "." + rel.Name, Partial: op != 'I' && !full}
	if rel.Identity != 'f' {
		t.alert(tx, "identity", fmt.Sprintf("%s is not REPLICA IDENTITY FULL: the fingerprint has no hash of the old row, and of the new one only when all its values are in the journal", row.R))
	}
	for _, tuple := range [][]pgoutput.Value{old, fresh} {
		if tuple != nil && len(tuple) != len(rel.Columns) {
			return fmt.Errorf("pgtap: %s: a row of %d values for %d columns", row.R, len(tuple), len(rel.Columns))
		}
	}
	// Значение, которое не менялось и лежит в TOAST, — из старой строки,
	// если она в журнале целиком.
	if fresh != nil && full && old != nil {
		fresh = slices.Clone(fresh)
		for i, v := range fresh {
			if v.Kind == pgoutput.Unchanged {
				fresh[i] = old[i]
			}
		}
	}
	vals := func(tuple []pgoutput.Value) ([]any, error) {
		if tuple == nil {
			return nil, nil
		}
		out := make([]any, len(tuple))
		for i, v := range tuple {
			var err error
			if out[i], err = value(v); err != nil {
				return nil, fmt.Errorf("pgtap: %s.%s: %w", row.R, rel.Columns[i].Name, err)
			}
		}
		return out, nil
	}
	ov, err := vals(old)
	if err != nil {
		return err
	}
	nv, err := vals(fresh)
	if err != nil {
		return err
	}
	if old != nil && full {
		row.O, _ = hashRow(old)
	}
	if fresh != nil {
		var whole bool
		if row.N, whole = hashRow(fresh); !whole {
			row.Partial = true
		}
	}
	key := func(v []any) []any {
		var k []any
		for _, name := range info.PK {
			if i := slices.IndexFunc(rel.Columns, func(c pgoutput.Column) bool { return c.Name == name }); i >= 0 {
				k = append(k, v[i])
			}
		}
		return k
	}
	switch {
	case ov != nil:
		row.K = key(ov)
		if nv != nil {
			if nk := key(nv); !jsonEqual(nk, row.K) {
				row.NK = nk
			}
		}
	case nv != nil:
		row.K = key(nv)
	}
	if tx.tables == nil {
		tx.tables = map[string]Counts{}
	}
	c := tx.tables[row.R]
	switch op {
	case 'I':
		c.I++
	case 'U':
		c.U++
	case 'D':
		c.D++
	}
	tx.tables[row.R] = c
	tx.changes++
	// Старое значение без REPLICA IDENTITY FULL — только ключ: ловушку по
	// другой колонке видно по новому.
	if !full {
		ov = nil
	}
	t.canaries(tx, rel, op, ov, nv)
	if tx.header {
		// Отпечаток пишется своими частями (fpInline): строка — сразу в поток.
		return t.write(tx, row)
	}
	line, err := json.Marshal(row)
	if err != nil {
		return err
	}
	tx.rows = append(tx.rows, line)
	tx.rowBytes += len(line) + 1
	if tx.rowBytes <= t.fpInline() {
		return nil
	}
	// Отпечаток не для пачки: заголовок, накопленные строки — в свой поток.
	if err := t.start(tx); err != nil {
		return err
	}
	for _, l := range tx.rows {
		if err := t.write(tx, l); err != nil {
			return err
		}
	}
	tx.rows, tx.rowBytes = nil, 0
	return nil
}

func jsonEqual(a, b []any) bool {
	x, _ := json.Marshal(a)
	y, _ := json.Marshal(b)
	return bytes.Equal(x, y)
}

// fpCommit — транзакция-отпечаток закончена: в пачку; полная пачка — в буфер.
// Отпечаток, который пишется своими частями (fpInline), заканчивается как
// полная транзакция (finish).
func (t *Tap) fpCommit(tx *txState, c pgoutput.Commit) (flushed uint64, err error) {
	if tx.header {
		if err := t.finish(tx, c); err != nil {
			return 0, err
		}
		return c.EndLSN, nil
	}
	e := fpEntry{
		XID: tx.begin.XID, CommitTime: tx.begin.CommitTime.UTC().Format(time.RFC3339Nano),
		CommitLSN: pgwire.LSN(tx.begin.FinalLSN).String(), EndLSN: pgwire.LSN(c.EndLSN).String(),
		Who: tx.who, Changes: tx.changes, Tables: tx.tables, Truncated: tx.truncated, Rows: tx.rows, end: c.EndLSN,
	}
	line, err := json.Marshal(e)
	if err != nil {
		return 0, err
	}
	e.Rows = nil // в пачке они уже сжаты: в памяти — только для справочника
	p := &t.pack
	// Пачка не перерастает часть: сжатое не длиннее несжатого больше чем на
	// немного, и отпечаток в пачке не длиннее fpInline (R1-2, R2-2, T-2).
	if len(p.entries) > 0 && p.buf.Len()+len(line)+4096 > t.cfg.PartSize {
		if flushed, err = t.flushPack(); err != nil {
			return 0, err
		}
	}
	if len(p.entries) == 0 {
		p.buf.Reset()
		p.gz = gzip.NewWriter(&p.buf)
		p.since = t.now()
	}
	if _, err := p.gz.Write(append(line, '\n')); err != nil {
		return 0, err
	}
	// Сжатое уходит в buf по мере записи: пачка не перерастёт часть — то,
	// что влезает в запись хранилища.
	if err := p.gz.Flush(); err != nil {
		return 0, err
	}
	p.entries = append(p.entries, e)
	p.last, p.end = tx.begin.FinalLSN, c.EndLSN
	t.stats.Fingerprinted++
	t.stats.FingerprintChanges += uint64(tx.changes)
	// Тревоги — как у полной транзакции, кроме no-action: роль не из списков.
	// Номеров записей в тревоге нет (пачка ещё не в буфере), и команды отката
	// тоже: откатить отпечаток нельзя.
	if t.cfg.AlertRows > 0 && tx.changes >= t.cfg.AlertRows {
		t.alert(tx, "mass-change", fmt.Sprintf("%d row changes in one transaction (the threshold is %d) by a role outside the collector's lists: the store keeps only a fingerprint", tx.changes, t.cfg.AlertRows))
	}
	if err := t.flushAlerts(tx, &IndexEntry{Changes: tx.changes, Tables: tx.tables}); err != nil {
		return 0, err
	}
	if len(p.entries) >= t.cfg.PackTx {
		return t.flushPack()
	}
	return flushed, nil
}

// flushPack кладёт пачку в буфер: строки справочника — раньше записи (как у
// последней части полной транзакции), место входа — фиксация последней
// транзакции пачки.
func (t *Tap) flushPack() (flushed uint64, err error) {
	p := &t.pack
	if err := p.gz.Close(); err != nil {
		return 0, err
	}
	seq := t.sink.Next()
	for _, e := range p.entries {
		// Строка справочника отпечатка — только чтобы найти пачку и объяснить
		// отказ отката: кто, когда, таблицы — в самой пачке, в хранилище.
		// Полная строка (~290 Б) была бы дороже отпечатка в пачке (замер 23.11).
		line, err := json.Marshal(IndexEntry{XID: e.XID, Kind: KindFingerprint, FirstSeq: seq, LastSeq: seq, Changes: e.Changes, Who: whoRole(e.Who)})
		if err != nil {
			return 0, err
		}
		if _, err := t.index.Write(append(line, '\n')); err != nil {
			return 0, err
		}
	}
	if err := t.index.Sync(); err != nil {
		return 0, err
	}
	p.n++
	rec := make([]byte, 0, base64.StdEncoding.EncodedLen(p.buf.Len())+48)
	rec = fmt.Appendf(rec, `{"xid":%q,"pack":%d,"v":%d,"gz":"`, PackSubject, p.n, FormatVersion)
	rec = base64.StdEncoding.AppendEncode(rec, p.buf.Bytes())
	rec = append(rec, '"', '}')
	got, err := t.sink.Emit([][]byte{rec}, p.last)
	if err != nil {
		return 0, err
	}
	if got != seq {
		return 0, fmt.Errorf("pgtap: a pack of %d transactions got record number %d, the index says %d", len(p.entries), got, seq)
	}
	t.stats.Packs++
	t.lastCommit = p.last
	end := p.end
	p.entries = p.entries[:0]
	return end, nil
}

// whoRole — из отметки «кто» только роль: {"role":"..."}.
func whoRole(who json.RawMessage) json.RawMessage {
	var w struct {
		Role string `json:"role"`
	}
	if json.Unmarshal(who, &w) != nil || w.Role == "" {
		return nil
	}
	b, _ := json.Marshal(w)
	return b
}

// isPack — тело записи — пачка отпечатков.
func isPack(body []byte) bool {
	var head struct {
		XID any `json:"xid"`
	}
	return json.Unmarshal(body, &head) == nil && head.XID == PackSubject
}

// ReadPack — транзакции пачки отпечатков из тела её записи.
func ReadPack(body []byte) ([]map[string]any, error) {
	var rec struct {
		XID  string `json:"xid"`
		Pack int    `json:"pack"`
		GZ   []byte `json:"gz"`
	}
	if err := json.Unmarshal(body, &rec); err != nil || rec.XID != PackSubject || rec.Pack == 0 {
		return nil, fmt.Errorf("pgtap: not a pack of fingerprints")
	}
	zr, err := gzip.NewReader(bytes.NewReader(rec.GZ))
	if err != nil {
		return nil, err
	}
	var out []map[string]any
	dec := json.NewDecoder(zr)
	for dec.More() {
		var e map[string]any
		if err := dec.Decode(&e); err != nil {
			return nil, err
		}
		out = append(out, e)
	}
	return out, nil
}
