package pginput

// Намерения шлюза (DECISIONS, п. 42). «Чья транзакция» сборщик берёт не из
// базы, а из файлов квитанций шлюзов (receipt/v1, docs/receipts.md): до
// COMMIT шлюз (esmcp, esundo — у каждого свой файл) пишет туда намерение — номер действия и ссылку
// {"source": <этот источник>, "subject": "<xid>"} — и подписывает его своим
// ключом. Ключ лежит у шлюза, вне базы: ни журнал, ни копия базы, ни её роли
// его не несут. Строка с чужой подписью не в счёт (тревога forged-receipt):
// её дописал тот, у кого ключа нет.
//
// Квитанции об исходе (step "outcome") несут то, что прежде несла отметка
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

// ReceiptsSpent — файл в Config.Dir: какое намерение какую транзакцию уже
// решило (хэш квитанции и место фиксации транзакции). Намерение решает одну
// транзакцию: база, поднятая из копии, выдаёт его номер снова, и чужая
// транзакция с тем же номером шла бы за действие шлюза (R2-1).
const ReceiptsSpent = "receipts-spent.jsonl"

// intentWindow — намерение без номера с эпохой (xid8 в теле — его пишут
// esmcp и esundo, чужой шлюз может и не писать) старше фиксации своей
// транзакции больше чем на столько — не её: xid 32 бита и через 2^32
// транзакций занимается снова. Часы шлюза и базы — разные машины, поэтому
// окно широкое. Намерение с xid8 сверяется по нему (fullXID), без окна.
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
	// Chains — цепочки шлюзов по имени: о чём тревоги уже подняты и какие
	// намерения не в счёт. По seq, а не по месту в файле: ни обрезка, ни
	// замена файла, ни копия прежней строки не поднимают старых тревог и не
	// возвращают снятых намерений (T-6).
	Chains map[string]*chainState `json:"chains,omitempty"`
}

type fileState struct {
	File    string `json:"file"`
	Inode   uint64 `json:"inode"`
	Alerted int64  `json:"alerted"` // тревоги о строках без подписи подняты до этого места
}

// chainState — цепочка квитанций одного шлюза глазами сборщика.
type chainState struct {
	Genesis string `json:"genesis,omitempty"` // хэш её начала: другое начало — новая цепочка
	Alerted uint64 `json:"alerted,omitempty"` // тревоги по исходам подняты до этого seq
	Void    uint64 `json:"void,omitempty"`    // намерения до этого seq не в счёт: база ушла назад (void)
	last    uint64 // последний прочитанный seq
}

// receipts — читатель файлов квитанций шлюзов: намерения по xid и тревоги по
// исходам. Читает с начала при запуске и дальше по мере роста файлов.
type receipts struct {
	cfg   ReceiptsConfig
	keys  []ed25519.PublicKey
	state string // путь receiptsState
	raise func(alert.Event) error
	now   func() time.Time

	files  []*receiptFile
	chains map[string]*chainState
	dirty  bool // chains изменились: сохранить
	byXID  map[uint32]intentAt
	order  []uint32
	// spent — хэш намерения → место фиксации транзакции, которую оно решило
	// (ReceiptsSpent); spentLines — строк в файле.
	spent      map[string]uint64
	spentPath  string
	spentLines int
	// ref8 — недавний номер транзакции базы с эпохой: по нему 32-битный xid
	// из потока получает свою эпоху (fullXID). 0 — не известен: намерения
	// сверяются по окну.
	ref8 uint64
}

// intentAt — намерение и номер его транзакции с эпохой (xid8 из тела
// намерения; 0 — шлюз его не назвал); spent — место фиксации транзакции,
// которую оно уже решило (0 — ещё ни одной).
type intentAt struct {
	in    pgtap.Intent
	xid8  uint64
	spent uint64
}

// receiptFile — файл квитанций одного шлюза и место в нём.
type receiptFile struct {
	path    string
	f       *os.File
	inode   uint64
	off     int64  // прочитано до сюда
	partial []byte // начало строки без перевода строки
	long    bool   // строка длиннее любой квитанции: её байты пропускаются до перевода строки
	alerted int64  // тревоги о строках без подписи подняты до этого места
	tail    []byte // последние байты перед off: другие на их месте — файл переписан
}

// tailLen — сколько байт перед местом чтения сверяется на каждом чтении.
const tailLen = 64

// receiptChunk — сколько файла квитанций читается за раз: память не растёт
// с тем, что дописали в файл (R2-6).
const receiptChunk = 1 << 20

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
	r := &receipts{cfg: cfg, state: filepath.Join(dir, ReceiptsState), raise: raise, now: time.Now, byXID: map[uint32]intentAt{}, chains: map[string]*chainState{},
		spent: map[string]uint64{}, spentPath: filepath.Join(dir, ReceiptsSpent)}
	if err := r.loadSpent(); err != nil {
		return nil, err
	}
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
	for name, c := range st.Chains {
		if c != nil {
			r.chains[name] = c
		}
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

// Intent — pgtap.Intents: намерение шлюза о транзакции xid. Нет в памяти
// или в памяти — о давней транзакции с тем же номером — файлы дочитываются:
// шлюз пишет намерение до COMMIT, а поток отдаёт транзакцию после, так что
// оно уже на диске (R2-9).
//
// final — место фиксации транзакции: намерение, которое уже решило другую
// транзакцию с тем же номером, — не её (spent); повтор той же транзакции
// (сервер шлёт её снова после обрыва) — её. 0 — не сверять.
func (r *receipts) Intent(xid uint32, commit time.Time, final uint64) (pgtap.Intent, bool, error) {
	at, ok := r.byXID[xid]
	if !ok || !r.fits(at, xid, commit, final) {
		if err := r.poll(); err != nil {
			return pgtap.Intent{}, false, err
		}
		if at, ok = r.byXID[xid]; !ok || !r.fits(at, xid, commit, final) {
			return pgtap.Intent{}, false, nil
		}
	}
	r.seen(at)
	if final != 0 && at.spent == 0 {
		at.spent = final
		r.byXID[xid] = at
		if err := r.spend(at.in.Hash, final); err != nil {
			return pgtap.Intent{}, false, err
		}
	}
	return at.in, true, nil
}

// fits — намерение at — о транзакции xid, зафиксированной в commit на месте
// final.
func (r *receipts) fits(at intentAt, xid uint32, commit time.Time, final uint64) bool {
	if final != 0 && at.spent != 0 && at.spent != final {
		return false // уже решило другую транзакцию с этим номером
	}
	if at.xid8 != 0 && r.ref8 != 0 && at.xid8 != fullXID(r.ref8, xid) {
		return false // номер с эпохой: занятый заново после оборота номер — другой
	}
	t, err := time.Parse(time.RFC3339Nano, at.in.Time)
	return err == nil && commit.Sub(t) <= intentWindow
}

// loadSpent читает ReceiptsSpent.
func (r *receipts) loadSpent() error {
	data, err := os.ReadFile(r.spentPath)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	for _, line := range bytes.Split(data, []byte("\n")) {
		var e spentLine
		if json.Unmarshal(line, &e) != nil || e.Hash == "" {
			continue // обрывок последней строки после падения
		}
		r.spent[e.Hash], r.spentLines = e.LSN, r.spentLines+1
	}
	return nil
}

type spentLine struct {
	Hash string `json:"hash"`
	LSN  uint64 `json:"lsn"`
}

// spend — намерение hash решило транзакцию с фиксацией на месте final.
// Дописывается до того, как транзакция ляжет в буфер; без fsync: если
// строка пропадёт вместе с машиной, сервер пришлёт ту же транзакцию снова, и
// намерение решит её же. Файл растёт — переписывается с намерениями в памяти.
func (r *receipts) spend(hash string, final uint64) error {
	r.spent[hash] = final
	if r.spentLines >= 2*maxIntents {
		var b bytes.Buffer
		for _, at := range r.byXID {
			if at.spent != 0 {
				line, _ := json.Marshal(spentLine{at.in.Hash, at.spent})
				b.Write(append(line, '\n'))
			}
		}
		if err := os.WriteFile(r.spentPath+".tmp", b.Bytes(), 0o600); err != nil {
			return err
		}
		if err := os.Rename(r.spentPath+".tmp", r.spentPath); err != nil {
			return err
		}
		r.spentLines = bytes.Count(b.Bytes(), []byte("\n"))
		return nil
	}
	f, err := os.OpenFile(r.spentPath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	defer f.Close()
	line, _ := json.Marshal(spentLine{hash, final})
	if _, err := f.Write(append(line, '\n')); err != nil {
		return err
	}
	r.spentLines++
	return nil
}

// seen — транзакция намерения at пришла из потока: её номер с эпохой —
// опора для следующих.
func (r *receipts) seen(at intentAt) {
	if at.xid8 > r.ref8 {
		r.ref8 = at.xid8
	}
}

// setRef — номер с эпохой, который база выдаст следующим (pginput
// спрашивает его при подключении и с проверкой слота).
func (r *receipts) setRef(next8 uint64) {
	if next8 > r.ref8 {
		r.ref8 = next8
	}
}

// fullXID — 32-битный xid с эпохой: ближайший к ref8. Транзакции потока
// отстоят от любого недавнего номера меньше чем на 2^31: так сама база
// бережёт номера от оборота (autovacuum, wraparound).
func fullXID(ref8 uint64, xid uint32) uint64 {
	return uint64(int64(ref8) + int64(int32(xid-uint32(ref8))))
}

// void — база ушла назад: поднята из копии или её место заняла отставшая
// реплика, и номера транзакций, названные в намерениях до сих пор, она
// выдаст снова другим транзакциям (R2-1). Все намерения, дописанные до
// этого мига, — не в счёт, и после перезапуска тоже (chainState.Void).
func (r *receipts) void() error {
	if err := r.poll(); err != nil {
		return err
	}
	for _, c := range r.chains {
		c.Void = max(c.Void, c.last)
	}
	r.byXID, r.order, r.dirty = map[uint32]intentAt{}, nil, true
	return r.save()
}

// chain — состояние цепочки шлюза name.
func (r *receipts) chain(name string) *chainState {
	c := r.chains[name]
	if c == nil {
		c = &chainState{}
		r.chains[name] = c
	}
	return c
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
	if moved || r.dirty {
		return r.save()
	}
	return nil
}

// pollFile дочитывает один файл. Файла нет — шлюз ещё не писал: намерений нет.
// Путь заменили (logrotate, mv поверх) — прежний файл дочитывается до конца,
// дальше читается новый (R2-3): шлюз пишет по пути, и без этого каждое его
// действие шло бы отпечатком, а исходы — без тревог. moved — тревоги подняты
// дальше, чем было.
func (r *receipts) pollFile(rf *receiptFile) (moved bool, err error) {
	if rf.f == nil {
		if err := r.openFile(rf); err != nil || rf.f == nil {
			return false, err
		}
	}
	moved, err = r.readFile(rf)
	if err != nil || rf.f == nil {
		return moved, err
	}
	if ino, ok := pathInode(rf.path); ok && ino != rf.inode {
		rf.f.Close()
		rf.f, rf.inode, rf.alerted = nil, 0, 0
		m, err := r.pollFile(rf)
		return moved || m || true, err
	}
	return moved, nil
}

// openFile открывает файл по пути. Другой файл, чем в прошлый раз, — тревоги
// о нём ещё не поднимались; если прежний, заменённый, пока сборщик стоял,
// лежит рядом под другим именем, он дочитывается первым: в нём могут быть
// намерения транзакций, которых сборщик ещё не прочёл.
func (r *receipts) openFile(rf *receiptFile) error {
	f, err := os.Open(rf.path)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("the gateway's receipts %s: %w", rf.path, err)
	}
	ino := inodeOf(f)
	switch fi, _ := f.Stat(); {
	case ino != rf.inode:
		if rf.inode != 0 {
			if err := r.drainRotated(rf); err != nil {
				f.Close()
				return err
			}
		}
		rf.inode, rf.alerted = ino, 0
	case fi != nil && fi.Size() < rf.alerted:
		// Тот же файл, но короче места тревог: его переписали заново.
		rf.alerted = 0
	}
	rf.f, rf.off, rf.partial, rf.long, rf.tail = f, 0, nil, false, nil
	return nil
}

// drainRotated — прежний файл квитанций rf (inode rf.inode), если он лежит в
// том же каталоге под другим именем, прочитан до конца: намерения — в
// память, тревоги — о строках после rf.alerted.
func (r *receipts) drainRotated(rf *receiptFile) error {
	dir := filepath.Dir(rf.path)
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil
	}
	for _, e := range entries {
		info, err := e.Info()
		if err != nil || !info.Mode().IsRegular() {
			continue
		}
		if st, ok := info.Sys().(*syscall.Stat_t); !ok || st.Ino != rf.inode {
			continue
		}
		f, err := os.Open(filepath.Join(dir, e.Name()))
		if err != nil {
			return nil
		}
		old := &receiptFile{path: filepath.Join(dir, e.Name()), f: f, inode: rf.inode, alerted: rf.alerted}
		_, err = r.readFile(old)
		f.Close()
		return err
	}
	return nil
}

// readFile читает файл от места rf.off до конца кусками receiptChunk.
// Строка длиннее любой подписанной квитанции пропускается, не копясь в
// памяти. Строки без подписи ключом шлюза — одной тревогой на чтение, а не
// тревогой на строку (R2-6).
func (r *receipts) readFile(rf *receiptFile) (moved bool, err error) {
	fi, err := rf.f.Stat()
	if err != nil {
		return false, err
	}
	if fi.Size() < rf.off || !r.sameTail(rf) {
		// Файл укоротили или переписали на месте: читать с начала. Тревоги
		// по исходам и снятые намерения — по seq (chainState), заново они
		// не поднимаются и не возвращаются; строки без подписи — заново (T-6).
		rf.off, rf.partial, rf.long, rf.tail, rf.alerted = 0, nil, false, nil, 0
		moved = true
	}
	var bad unsigned
	buf := make([]byte, min(int64(receiptChunk), fi.Size()-rf.off))
	for rf.off < fi.Size() {
		got, err := rf.f.ReadAt(buf[:min(int64(len(buf)), fi.Size()-rf.off)], rf.off)
		if err != nil && !errors.Is(err, io.EOF) {
			return moved, err
		}
		if got == 0 {
			break
		}
		rf.off += int64(got)
		data := buf[:got]
		for len(data) > 0 {
			i := bytes.IndexByte(data, '\n')
			if i < 0 {
				if !rf.long {
					rf.partial = append(rf.partial, data...)
					if len(rf.partial) > 2*gateway.MaxReceiptLen {
						rf.partial, rf.long = nil, true // не квитанция: строка длиннее любой подписанной
					}
				}
				break
			}
			end := rf.off - int64(len(data)) + int64(i) + 1
			if rf.long {
				rf.long = false
				if end > rf.alerted {
					bad.add(end, true)
				}
			} else if err := r.line(rf, append(rf.partial, data[:i]...), end, &bad); err != nil {
				return moved, err
			}
			rf.partial = rf.partial[:0]
			if end > rf.alerted {
				rf.alerted, moved = end, true
			}
			data = data[i+1:]
		}
		if chunk := buf[:got]; len(chunk) >= tailLen {
			rf.tail = append(rf.tail[:0], chunk[len(chunk)-tailLen:]...)
		} else if rf.tail = append(rf.tail, chunk...); len(rf.tail) > tailLen {
			rf.tail = append(rf.tail[:0], rf.tail[len(rf.tail)-tailLen:]...)
		}
	}
	return moved, r.unsignedAlert(rf, bad)
}

// sameTail — байты перед местом чтения те же, что были прочитаны.
func (r *receipts) sameTail(rf *receiptFile) bool {
	if len(rf.tail) == 0 {
		return true
	}
	got := make([]byte, len(rf.tail))
	n, _ := rf.f.ReadAt(got, rf.off-int64(len(rf.tail)))
	return n == len(got) && bytes.Equal(got, rf.tail)
}

// unsigned — строки одного чтения файла квитанций, которые не квитанция с
// подписью ключа шлюза: сколько, где первая и последняя кончаются, сколько
// из них длиннее любой квитанции.
type unsigned struct {
	n, long     int
	first, last int64
}

func (u *unsigned) add(end int64, long bool) {
	if u.n == 0 {
		u.first = end
	}
	u.n++
	u.last = end
	if long {
		u.long++
	}
}

// unsignedAlert — одна тревога forged-receipt о строках u файла rf. Такую
// строку мог дописать тот, у кого ключа нет, а мог и сам шлюз, умерший
// посреди строки (Append закрывает обрывок переводом строки): тревога
// называет обе причины (R1-5).
func (r *receipts) unsignedAlert(rf *receiptFile, u unsigned) error {
	if u.n == 0 {
		return nil
	}
	where := fmt.Sprintf("the line ending at byte %d", u.first)
	if u.n > 1 {
		where = fmt.Sprintf("%d lines ending at bytes %d to %d", u.n, u.first, u.last)
	}
	if u.long > 0 {
		where += fmt.Sprintf(" (%d of them longer than any receipt)", u.long)
	}
	ev := alert.Event{}
	ev.Add(alert.KindForgedReceipt, fmt.Sprintf("%s of the gateway's receipts %s: not a receipt signed with a gateway key the collector knows — "+
		"a gateway died in the middle of writing it, or someone without the key wrote it; it decides nothing about any transaction", where, rf.path))
	return r.raise(ev)
}

func (r *receipts) save() error {
	st := receiptsState{Chains: r.chains}
	r.dirty = false
	for _, rf := range r.files {
		st.Files = append(st.Files, fileState{File: rf.path, Inode: rf.inode, Alerted: rf.alerted})
	}
	data, _ := json.Marshal(st)
	return writeFile(r.state, json.RawMessage(data))
}

// line разбирает одну квитанцию файла rf; end — место файла сразу за ней;
// строка без подписи ключом шлюза — в bad.
func (r *receipts) line(rf *receiptFile, line []byte, end int64, bad *unsigned) error {
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
			bad.add(end, false)
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
		XID8       string `json:"xid8"`
		Alerted    bool   `json:"alerted"`
	}
	json.Unmarshal(rc.Body, &body)
	act := pgtap.Intent{ID: rc.Action, Gateway: rc.Gateway, Seq: rc.Seq, Hash: rc.Hash, Step: rc.Step, Time: rc.Time.UTC().Format(time.RFC3339Nano),
		Agent: alert.Field(body.Agent), Tool: alert.Field(body.Tool), Reason: cut(body.Reason, maxReason), Undoes: alert.Field(body.Undoes)}
	c := r.chain(rc.Gateway)
	if rc.Prev == gateway.Genesis && rc.Hash != c.Genesis {
		// Начало цепочки: первое увиденное или новое (шлюз начал цепочку
		// заново). У новой — свой счёт seq.
		if c.Genesis != "" {
			c.Alerted, c.Void, c.last = 0, 0, 0
		}
		c.Genesis, r.dirty = rc.Hash, true
	}
	c.last = max(c.last, rc.Seq)
	switch rc.Step {
	case alert.StepIntent, alert.StepUndo:
		if rc.Seq <= c.Void {
			break // дописано до того, как база ушла назад: номер мог быть выдан снова
		}
		xid8, _ := strconv.ParseUint(body.XID8, 10, 64)
		for _, ref := range rc.Refs {
			if ref.Source != r.cfg.Source {
				continue
			}
			xid, err := strconv.ParseUint(ref.Subject, 10, 32)
			if err != nil {
				continue
			}
			at := intentAt{in: act}
			if xid8 != 0 && uint32(xid8) == uint32(xid) {
				at.xid8 = xid8
			}
			r.remember(uint32(xid), at)
		}
	case alert.StepOutcome:
		// Дважды о том же исходе — нет: ни после обрезки и замены файла, ни
		// по копии прежней строки, дописанной без ключа.
		switch {
		case rc.Seq <= c.Alerted:
		case !fresh:
			c.Alerted, r.dirty = rc.Seq, true // поднята прежде, когда счёт вёлся по месту в файле
		default:
			c.Alerted, r.dirty = rc.Seq, true
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

func (r *receipts) remember(xid uint32, in intentAt) {
	if _, ok := r.byXID[xid]; !ok {
		r.order = append(r.order, xid)
	}
	in.spent = r.spent[in.in.Hash]
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

// pathInode — inode файла по пути сейчас; ok == false — файла нет.
func pathInode(path string) (uint64, bool) {
	fi, err := os.Stat(path)
	if err != nil {
		return 0, false
	}
	if st, ok := fi.Sys().(*syscall.Stat_t); ok {
		return st.Ino, true
	}
	return 0, false
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
