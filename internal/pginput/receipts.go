package pginput

// Намерения шлюза (DECISIONS, п. 42). «Чья транзакция» сборщик берёт не из
// базы, а из файлов квитанций шлюзов (receipt/v1, docs/receipts.md): до
// COMMIT шлюз (esmcp, esundo — у каждого свой файл) пишет туда намерение — номер действия и ссылку
// {"source": <этот источник>, "subject": "<xid>"} — и подписывает его своим
// ключом. Ключ лежит у шлюза, вне базы: ни журнал, ни копия базы, ни её роли
// его не несут. Строка с чужой подписью не в счёт (тревога forged-receipt):
// её дописал тот, у кого ключа нет.
//
// Квитанции об исходе (step "outcome") несут то, что раньше несла отметка
// отказа в журнале базы: действие остановлено пределом, SQL агента вышел из
// транзакции шлюза, связь оборвалась на COMMIT. По ним — тревоги людям.
// Тревоги поднимаются один раз: место каждого файла, до которого они подняты,
// лежит в receipts.json рядом со справочником.

import (
	"bytes"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"syscall"
	"time"

	"github.com/Nikolay1994Kaz/evidencestore/internal/alert"
	"github.com/Nikolay1994Kaz/evidencestore/internal/gateway"
	"github.com/Nikolay1994Kaz/evidencestore/internal/pgtap"
)

// ReceiptsConfig — раздел "receipts" входа: где шлюзы пишут квитанции и чьи
// подписи в них признавать.
type ReceiptsConfig struct {
	// Files — файлы квитанций шлюзов, которые пишут в эту базу, у каждого
	// свой (esmcp "receipts", esundo "receipts"): у шлюза своя цепочка и свой
	// ключ, и в хранилище его файл — свой источник. Путь — от файла настроек.
	Files []string `json:"files"`
	// GatewayKeys — открытые ключи шлюзов (Ed25519, 64 hex): esmcp -pubkey,
	// esreceipt pubkey. Квитанция, которую ни один из них не подписал, не в счёт.
	GatewayKeys []string `json:"gateway_keys"`
	// Source — имя этого источника в хранилище, как его называет ссылка в
	// намерении шлюза (esmcp и esundo "pg_source"). По умолчанию "postgres".
	Source string `json:"source"`
}

// ReceiptsState — файл в Config.Dir: до какого места каждого файла квитанций
// тревоги уже подняты.
const ReceiptsState = "receipts.json"

// intentWindow — намерение старше фиксации своей транзакции больше чем на
// столько — не её: xid 32 бита и через 2^32 транзакций занимается снова.
// Часы шлюза и базы — разные машины, поэтому окно широкое.
const intentWindow = 24 * time.Hour

// maxIntents — сколько последних намерений держать в памяти. Транзакция,
// чьё намерение вытеснено, пойдёт отпечатком: так бывает, только если
// сборщик отстал от шлюза больше чем на столько действий.
var maxIntents = 200_000

// maxReason — сколько знаков причины держать в памяти и класть в справочник:
// esmcp больше 2000 байт не берёт, целиком она в квитанции в хранилище.
const maxReason = 2000

type receiptsState struct {
	Files []fileState `json:"files"`
}

type fileState struct {
	File    string `json:"file"`
	Inode   uint64 `json:"inode"`
	Alerted int64  `json:"alerted"` // тревоги подняты о строках до этого места
}

// receipts — читатель файлов квитанций шлюзов: намерения по xid и тревоги по
// исходам. Читает с начала при запуске и дальше по мере роста файлов.
type receipts struct {
	cfg   ReceiptsConfig
	keys  []ed25519.PublicKey
	state string // путь receiptsState
	raise func(alert.Event) error
	now   func() time.Time

	files []*receiptFile
	byXID map[uint32]pgtap.Intent
	order []uint32
}

// receiptFile — файл квитанций одного шлюза и место в нём.
type receiptFile struct {
	path    string
	f       *os.File
	inode   uint64
	off     int64  // прочитано до сюда
	partial []byte // начало строки без перевода строки
	alerted int64  // тревоги подняты о строках до этого места
}

func (c *ReceiptsConfig) validate() error {
	if len(c.Files) == 0 {
		return errors.New(`receipts.files is required: the receipts files of the gateways that write to this database (esmcp, esundo)`)
	}
	seen := map[string]bool{}
	for _, f := range c.Files {
		if f == "" {
			return errors.New("receipts.files: an empty path")
		}
		if seen[filepath.Clean(f)] {
			return fmt.Errorf("receipts.files: %s is named twice: its alerts would be raised twice", f)
		}
		seen[filepath.Clean(f)] = true
	}
	if len(c.GatewayKeys) == 0 {
		return errors.New("receipts.gateway_keys is required: an intent whose signature nobody checks proves nothing")
	}
	for _, k := range c.GatewayKeys {
		if _, err := gateway.ParseKey(k); err != nil {
			return fmt.Errorf("receipts.gateway_keys: %w", err)
		}
	}
	if c.Source == "" {
		c.Source = "postgres"
	}
	return nil
}

// openReceipts готовит читателя; файлы он читает на первом poll: тревоги
// уходят через raise, а тот готов только после pgtap.Open.
func openReceipts(cfg ReceiptsConfig, dir string, raise func(alert.Event) error) (*receipts, error) {
	r := &receipts{cfg: cfg, state: filepath.Join(dir, ReceiptsState), raise: raise, now: time.Now, byXID: map[uint32]pgtap.Intent{}}
	for _, k := range cfg.GatewayKeys {
		key, _ := gateway.ParseKey(k) // проверен validate
		r.keys = append(r.keys, key)
	}
	var st receiptsState
	if data, err := os.ReadFile(r.state); err == nil {
		if err := json.Unmarshal(data, &st); err != nil {
			return nil, fmt.Errorf("%s: %w", r.state, err)
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}
	for _, path := range cfg.Files {
		rf := &receiptFile{path: path}
		for _, s := range st.Files {
			if s.File == path {
				rf.inode, rf.alerted = s.Inode, s.Alerted
			}
		}
		r.files = append(r.files, rf)
	}
	return r, nil
}

// Intent — pgtap.Intents: намерение шлюза о транзакции xid. Нет в памяти —
// файлы дочитываются: шлюз пишет намерение до COMMIT, а поток отдаёт
// транзакцию после, так что оно уже на диске.
func (r *receipts) Intent(xid uint32, commit time.Time) (pgtap.Intent, bool, error) {
	in, ok := r.byXID[xid]
	if !ok {
		if err := r.poll(); err != nil {
			return in, false, err
		}
		in, ok = r.byXID[xid]
	}
	if !ok {
		return in, false, nil
	}
	if at, err := time.Parse(time.RFC3339Nano, in.Time); err == nil && commit.Sub(at) > intentWindow {
		return in, false, nil // номер занят заново: намерение о давней транзакции
	}
	return in, true, nil
}

// poll дочитывает файлы квитанций.
func (r *receipts) poll() error {
	moved := false
	for _, rf := range r.files {
		m, err := r.pollFile(rf)
		if err != nil {
			return err
		}
		moved = moved || m
	}
	if moved {
		return r.save()
	}
	return nil
}

// pollFile дочитывает один файл. Файла нет — шлюз ещё не писал: намерений нет.
// moved — тревоги подняты дальше, чем было.
func (r *receipts) pollFile(rf *receiptFile) (moved bool, err error) {
	if rf.f == nil {
		f, err := os.Open(rf.path)
		if errors.Is(err, os.ErrNotExist) {
			return false, nil
		}
		if err != nil {
			return false, fmt.Errorf("the gateway's receipts %s: %w", rf.path, err)
		}
		ino := inodeOf(f)
		if ino != rf.inode {
			// Другой файл, чем в прошлый раз: тревоги о нём ещё не поднимались.
			rf.inode, rf.alerted = ino, 0
		}
		rf.f, rf.off, rf.partial = f, 0, nil
	}
	fi, err := rf.f.Stat()
	if err != nil {
		return false, err
	}
	if fi.Size() < rf.off {
		// Файл укоротили: тот же файл переписан заново.
		rf.f.Close()
		rf.f, rf.inode, rf.alerted = nil, 0, 0
		return r.pollFile(rf)
	}
	if fi.Size() == rf.off {
		return false, nil
	}
	buf := make([]byte, fi.Size()-rf.off)
	if _, err := rf.f.ReadAt(buf, rf.off); err != nil && !errors.Is(err, io.EOF) {
		return false, err
	}
	start := rf.off - int64(len(rf.partial))
	data := append(rf.partial, buf...)
	rf.off = fi.Size()
	for {
		i := bytes.IndexByte(data, '\n')
		if i < 0 {
			break
		}
		end := start + int64(i) + 1
		if err := r.line(rf, data[:i], end); err != nil {
			return moved, err
		}
		if end > rf.alerted {
			rf.alerted, moved = end, true
		}
		data, start = data[i+1:], end
	}
	if len(data) > 2*gateway.MaxReceiptLen {
		data = nil // не квитанция: строка длиннее любой подписанной
	}
	rf.partial = bytes.Clone(data)
	return moved, nil
}

func (r *receipts) save() error {
	var st receiptsState
	for _, rf := range r.files {
		st.Files = append(st.Files, fileState{File: rf.path, Inode: rf.inode, Alerted: rf.alerted})
	}
	data, _ := json.Marshal(st)
	return writeFile(r.state, json.RawMessage(data))
}

// line разбирает одну квитанцию файла rf; end — место файла сразу за ней.
func (r *receipts) line(rf *receiptFile, line []byte, end int64) error {
	if len(bytes.TrimSpace(line)) == 0 {
		return nil
	}
	fresh := end > rf.alerted
	rc, perr := gateway.ParseReceipt(line)
	signed := false
	for _, k := range r.keys {
		if rc.Verify(k) == nil {
			signed = true
			break
		}
	}
	if !signed {
		if fresh {
			ev := alert.Event{}
			ev.Add(alert.KindForgedReceipt, fmt.Sprintf("a line of the gateway's receipts %s (ending at byte %d) is signed with no gateway key the collector knows: "+
				"someone without the key wrote it; it decides nothing about any transaction", rf.path, end))
			return r.raise(ev)
		}
		return nil
	}
	if perr != nil {
		return nil // подписано, но не по формату: хранилище назовёт поломку, сборщику в ней нечего взять
	}
	var body struct {
		Agent  string `json:"agent"`
		Tool   string `json:"tool"`
		Reason string `json:"reason"`
		Undoes string `json:"undoes"`
		// Исход (step outcome).
		Outcome    string `json:"outcome"`
		Cause      string `json:"cause"`
		Rows       int    `json:"rows"`
		Limit      int    `json:"limit"`
		WindowRows int    `json:"window_rows"`
		Window     string `json:"window"`
		Actions    int    `json:"actions"`
		Timeout    string `json:"timeout"`
		XID        string `json:"xid"`
		Alerted    bool   `json:"alerted"`
	}
	json.Unmarshal(rc.Body, &body)
	act := pgtap.Intent{ID: rc.Action, Gateway: rc.Gateway, Seq: rc.Seq, Hash: rc.Hash, Step: rc.Step, Time: rc.Time.UTC().Format(time.RFC3339Nano),
		Agent: alert.Field(body.Agent), Tool: alert.Field(body.Tool), Reason: cut(body.Reason, maxReason), Undoes: alert.Field(body.Undoes)}
	switch rc.Step {
	case alert.StepIntent, alert.StepUndo:
		for _, ref := range rc.Refs {
			if ref.Source != r.cfg.Source {
				continue
			}
			xid, err := strconv.ParseUint(ref.Subject, 10, 32)
			if err != nil {
				continue
			}
			r.remember(uint32(xid), act)
		}
	case alert.StepOutcome:
		if fresh {
			return r.outcome(act, body.Outcome, body.Cause, body.Rows, body.Limit, body.WindowRows, body.Window, body.Actions, body.Timeout, body.XID, body.Alerted)
		}
	}
	return nil
}

// cut режет строку до n знаков.
func cut(s string, n int) string {
	if r := []rune(s); len(r) > n {
		return string(r[:n]) + "…"
	}
	return s
}

func (r *receipts) remember(xid uint32, in pgtap.Intent) {
	if _, ok := r.byXID[xid]; !ok {
		r.order = append(r.order, xid)
	}
	r.byXID[xid] = in
	for len(r.order) > maxIntents {
		delete(r.byXID, r.order[0])
		r.order = r.order[1:]
	}
}

// outcome — тревога по исходу действия шлюза. Без тревоги — committed и failed:
// первое видно по транзакции, второе ничего не изменило.
func (r *receipts) outcome(act pgtap.Intent, outcome, cause string, rows, limit, windowRows int, window string, actions int, timeout, xid string, alerted bool) error {
	xid, window, timeout = alert.Field(xid), alert.Field(window), alert.Field(timeout)
	kind, detail := alert.KindRefused, ""
	switch {
	case outcome == "escaped":
		// Не отказ: шлюз ничего не остановил, агент вышел из его транзакции
		// сам. Сказать «ничего не изменилось» нельзя.
		kind = alert.KindEscaped
		where := "the MCP server's transaction"
		if xid != "" {
			where += " " + xid
		}
		if act.Tool == "query" {
			where += " (a read-only one)"
		}
		detail = fmt.Sprintf("the agent's SQL ended %s itself (COMMIT, ROLLBACK or the like in its text): what it changed may be committed "+
			"without the row limits being checked — in that transaction, and in transactions after it, which come without the gateway's intent, as fingerprints", where)
	case outcome == "unknown":
		kind = alert.KindUnknown
		detail = fmt.Sprintf("the connection of the MCP server to the database broke during COMMIT of an action (transaction %s, %d rows): "+
			"it may be committed. The agent was told not to repeat it: check the transaction", xid, rows)
	case cause == "timeout":
		// Отмена по времени — исход failed, но о ней людям сказать надо.
		detail = fmt.Sprintf("the MCP server cancelled an action that ran longer than %s: it was rolled back, nothing changed", timeout)
	case outcome != "refused":
		return nil
	case cause == "row-limit":
		detail = fmt.Sprintf("the MCP server stopped an action that would change %d rows (the limit for one action is %d): it was rolled back, nothing changed", rows, limit)
	case cause == "window-rows":
		detail = fmt.Sprintf("the MCP server stopped an action of %d rows: with it the agent would have changed %d rows in %s (the limit is %d): it was rolled back, nothing changed",
			rows, windowRows+rows, window, limit)
	case cause == "rate":
		if !alerted {
			return nil // о частоте — раз в минуту: остальные отказы только в квитанциях
		}
		detail = fmt.Sprintf("the MCP server refuses the agent's actions: %d in the last minute (the limit is %d). This is reported once a minute at most; every refusal is in the receipts",
			actions, limit)
	default:
		detail = fmt.Sprintf("the MCP server stopped an action (%s): nothing changed", alert.Field(cause))
	}
	ev := alert.Event{Action: &act}
	ev.Add(kind, detail)
	return r.raise(ev)
}

func (r *receipts) close() {
	for _, rf := range r.files {
		if rf.f != nil {
			rf.f.Close()
			rf.f = nil
		}
	}
}

func inodeOf(f *os.File) uint64 {
	fi, err := f.Stat()
	if err != nil {
		return 0
	}
	if st, ok := fi.Sys().(*syscall.Stat_t); ok {
		return st.Ino
	}
	return 0
}
