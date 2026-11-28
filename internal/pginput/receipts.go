package pginput

// Намерения шлюза (DECISIONS, п. 42). «Чья транзакция» сборщик берёт не из
// базы, а из файлов квитанций шлюзов (receipt/v2, docs/receipts.md): до
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
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"slices"
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
	// Version — 3: исходы считаются обработанными по хэшу
	// (receipts-alerted.jsonl), а не по месту в файле. Состояние прежней
	// версии — один раз по месту (Files.Alerted), дальше — по хэшу.
	Version int         `json:"version,omitempty"`
	Files   []fileState `json:"files"`
	// HandledBefore — исходы со временем шлюза не позже этого обработаны:
	// их хэши ушли из receipts-alerted.jsonl при сжатии.
	HandledBefore string `json:"handled_before,omitempty"`
	// VoidBefore — намерения любого шлюза без отметки базы со временем шлюза
	// не позже этого не в счёт: база ушла назад, а запустилась в своей новой
	// истории в этот миг (void с границей).
	VoidBefore string `json:"void_before,omitempty"`
	// VoidStartedBefore — намерения с отметкой базы (db_started: когда
	// запущена база, в которой шла транзакция действия, микросекунды) не
	// позже этого не в счёт: их база — прежняя история, до подъёма из копии.
	VoidStartedBefore int64 `json:"void_started_before,omitempty"`
	// VoidTimeline — линия времени, которую сборщик читал, когда база ушла
	// назад: VoidStartedBefore снимает намерения с отметкой линии
	// (db_timeline) только не новее её. Намерение с линии новее — из новой
	// истории, каким бы старым ни был запуск его базы: реплика, ставшая
	// основной, запущена раньше границы.
	VoidTimeline uint32 `json:"void_timeline,omitempty"`
	// Chains — шлюзы по имени: до какого их времени намерения не в счёт.
	Chains map[string]*chainState `json:"chains,omitempty"`
	// Links — последняя квитанция каждой цепочки (путь файла, шлюз, ключ),
	// прочитанная сборщиком: выпавшая из файла квитанция видна и после
	// перезапуска (T-6 второго захода).
	Links map[string]*chainLink `json:"links,omitempty"`
	// Keys — ключи шлюзов по цепочке (путь файла, шлюз): каким подписана его
	// последняя прочитанная квитанция и с каких он ушёл (P-388).
	Keys map[string]*keyState `json:"keys,omitempty"`
}

// keyState — ключи шлюза в одном файле. Смену ключа выводит сам файл: с
// первой квитанцией шлюза под новым ключом прежний для него снят, и строки
// под прежним после неё ничего не решают — их пишет тот, у кого прежний ключ
// остался. Состояние — в receipts.json: файл после рестарта читается с
// начала, его поворачивают и обрезают, а снятый ключ снят навсегда. Цена:
// честное намерение под прежним ключом, прочитанное заново после рестарта,
// тоже ничего не решает (DECISIONS, п. 47).
type keyState struct {
	Current string `json:"current"` // hex
	// Retired — hex ключа → seq первой квитанции шлюза под следующим.
	Retired map[string]uint64 `json:"retired,omitempty"`
}

// chainLink — где сборщик застал цепочку квитанций одного шлюза в одном
// файле. Шлюз ведёт её сам (голова рядом с ключом, gateway.AppendHead): seq
// растёт на единицу, prev — хэш предыдущей, и обрезка файла, ротация и копии
// прежних строк её не сбивают. Пропуск значит, что строки нет в файле: её
// вынул тот, кто пишет в файл без ключа (T-2 второго захода), или файл
// сжали и унесли, пока сборщик стоял (T-6).
type chainLink struct {
	Seq  uint64 `json:"seq"`
	Hash string `json:"hash"`
	// Time — время шлюза в этой квитанции.
	Time string `json:"time,omitempty"`
	// Genesis — начала цепочек этого шлюза, виденные здесь: копия прежнего
	// начала — повтор, а не новая цепочка.
	Genesis []string `json:"genesis,omitempty"`
}

// time — время шлюза в последней квитанции цепочки (ноль — не записано).
func (l *chainLink) time() time.Time {
	t, _ := time.Parse(time.RFC3339Nano, l.Time)
	return t
}

// maxGenesis — сколько начал цепочек одного шлюза помнить.
const maxGenesis = 8

type fileState struct {
	File    string `json:"file"`
	Inode   uint64 `json:"inode"`
	Alerted int64  `json:"alerted"` // тревоги о строках до этого места подняты
}

// chainState — шлюз глазами сборщика. Решает время квитанции, а не seq и
// не место в файле: время подписано шлюзом, и копия прежней строки несёт
// своё прежнее время, а цепочка с тем же именем у другого ключа (второй
// esmcp, смена ключа) или новая цепочка после обрезки файла не сбивает
// счёт другой (R1-1, R1-4, R1-7, R2-2 второго захода).
type chainState struct {
	// VoidTime — намерения шлюза не позже этого времени не в счёт: база ушла
	// назад (void), и названные в них номера она выдаст снова.
	VoidTime string `json:"void_time,omitempty"`
	// SwitchTime — намерения шлюза без отметки линии времени (db_timeline)
	// не позже этого времени не в счёт: кластер переключился на реплику
	// (switched), а такое намерение не говорит, на какой основной писалось.
	SwitchTime string    `json:"switch_time,omitempty"`
	last       time.Time // позднее время намерения, прочитанного у шлюза
}

// ReceiptsAlerted — файл в Config.Dir: хэши квитанций исхода, которые
// сборщик уже обработал (тревога поднята, намерение сверено). Ни обрезка, ни
// замена, ни сдвиг содержимого файла, ни копия прежней строки не поднимают
// тревоги второй раз и не прячут новую: новизну решает хэш квитанции, а не
// место в файле (R1-1 третьего захода: писатель файла без ключа, пока
// сборщик стоял, сдвигал написанное шлюзом перед прежним местом тревог, и
// исходы, вынутое намерение и пропуск в цепочке проходили молча).
const ReceiptsAlerted = "receipts-alerted.jsonl"

// stateVersion — receiptsState.Version этой версии.
const stateVersion = 3

// maxAlerted — сколько хэшей обработанных исходов помнить: сжатие оставляет
// последние, а время самого позднего из ушедших — граница HandledBefore.
const maxAlerted = 50_000

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
	// voidBefore, voidStartedBefore — receiptsState.VoidBefore и
	// VoidStartedBefore.
	voidBefore        time.Time
	voidStartedBefore int64
	voidTimeline      uint32 // receiptsState.VoidTimeline
	// timeline, switches — линия времени сервера и где кончались её
	// предки (setTimelines): по ним у места фиксации транзакции есть линия
	// (timelineOf). 0 — не известна: намерения по линии не сверяются.
	timeline uint32
	switches []timelineSwitch
	dirty    bool // chains изменились: сохранить
	byXID    map[uint32]intentAt
	order    []uint32
	// alerted — хэши обработанных квитанций исхода (ReceiptsAlerted) и их
	// время шлюза; handledBefore — граница сжатия.
	alerted       map[string]bool
	alertedOrder  []handled
	alertedPath   string
	handledBefore time.Time
	// unreadable — почему файл квитанций сейчас не читается (о том же — одна
	// тревога, пока не прочтётся).
	unreadable map[string]string
	links      map[string]*chainLink
	keyStates  map[string]*keyState // (путь файла, шлюз) → его ключи
	// missed — транзакции, у которых на их начале намерения не нашлось
	// (номер → время фиксации): намерение, пришедшее после, — тревога.
	missed      map[uint32]time.Time
	missedOrder []uint32
	// intents — номера действий, чьё намерение прочитано (и снятое void):
	// исход с номером транзакции без намерения — тревога.
	intents      map[string]bool
	intentsOrder []string
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
	// started — отметка базы в намерении (db_started, микросекунды); 0 — нет.
	started int64
	// timeline — линия времени базы в намерении (db_timeline); 0 — нет.
	timeline uint32
}

// timelineSwitch — линия времени — предок нынешней — и место журнала, где
// она кончилась: с него история пошла по следующей линии.
type timelineSwitch struct {
	timeline uint32
	end      uint64
}

// setTimelines — линия времени сервера и её предки (pginput identify, при
// каждом подключении).
func (r *receipts) setTimelines(now uint32, switches []timelineSwitch) {
	r.timeline, r.switches = now, switches
}

// timelineOf — линия времени, на которой записана фиксация на месте final;
// 0 — историю линий сервер не дал.
func (r *receipts) timelineOf(final uint64) uint32 {
	for _, s := range r.switches {
		if final < s.end {
			return s.timeline
		}
	}
	return r.timeline
}

// receiptFile — файл квитанций одного шлюза и место в нём.
type receiptFile struct {
	path string
	// chain — путь из настроек, по которому ведётся цепочка шлюза: у
	// повёрнутого файла, который дочитывается под своим новым именем, — путь,
	// где он лежал (R1-3 третьего захода: иначе первая квитанция нового файла
	// сверялась с местом до остановки, и обычная ротация давала ложный
	// пропуск).
	chain   string
	f       *os.File
	inode   uint64
	off     int64  // прочитано до сюда
	partial []byte // начало строки без перевода строки
	long    bool   // строка длиннее любой квитанции: её байты пропускаются до перевода строки
	alerted int64  // тревоги о строках без подписи подняты до этого места
	// migrate — состояние прежней версии: строки до этого места обработаны
	// ею (по месту), их исходы — в receipts-alerted.jsonl без тревог.
	migrate int64
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
		spent: map[string]uint64{}, spentPath: filepath.Join(dir, ReceiptsSpent),
		alerted: map[string]bool{}, alertedPath: filepath.Join(dir, ReceiptsAlerted), unreadable: map[string]string{},
		links: map[string]*chainLink{}, keyStates: map[string]*keyState{}, intents: map[string]bool{}, missed: map[uint32]time.Time{}}
	if err := r.loadSpent(); err != nil {
		return nil, err
	}
	if err := r.loadAlerted(); err != nil {
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
	if v, err := time.Parse(time.RFC3339Nano, st.VoidBefore); err == nil {
		r.voidBefore = v
	}
	r.voidStartedBefore, r.voidTimeline = st.VoidStartedBefore, st.VoidTimeline
	for k, l := range st.Links {
		if l != nil {
			r.links[k] = l
		}
	}
	for k, ks := range st.Keys {
		if ks != nil {
			r.keyStates[k] = ks
		}
	}
	if v, err := time.Parse(time.RFC3339Nano, st.HandledBefore); err == nil {
		r.handledBefore = v
	}
	for _, path := range cfg.Files {
		rf := &receiptFile{path: path}
		for _, s := range st.Files {
			if s.File == path {
				rf.inode, rf.alerted = s.Inode, s.Alerted
				if st.Version < stateVersion {
					rf.migrate = s.Alerted
				}
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
			r.miss(xid, commit)
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

// maxMissed — сколько транзакций без намерения помнить.
const maxMissed = 100_000

// miss — у транзакции xid (фиксация в commit) намерения не нашлось: она
// легла отпечатком.
func (r *receipts) miss(xid uint32, commit time.Time) {
	if _, ok := r.missed[xid]; !ok {
		r.missedOrder = append(r.missedOrder, xid)
	}
	r.missed[xid] = commit
	if len(r.missedOrder) > 2*maxMissed {
		for _, old := range r.missedOrder[:maxMissed] {
			delete(r.missed, old)
		}
		r.missedOrder = append([]uint32(nil), r.missedOrder[maxMissed:]...)
	}
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
	if tl := r.timelineOf(final); at.timeline != 0 && final != 0 && tl != 0 && tl != at.timeline {
		// Намерение писалось на другой линии времени, чем фиксация этой
		// транзакции: после переключения на реплику новая основная выдаёт
		// заново номера транзакций прежней, не дошедших до неё, — и намерение
		// прежней основной о таком номере решило бы чужую транзакцию.
		return false
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
		// В памяти и в файле — только намерения, которые ещё в памяти
		// (R2-5 второго захода: в памяти spent рос без предела).
		var b bytes.Buffer
		r.spent = map[string]uint64{}
		for _, at := range r.byXID {
			if at.spent != 0 {
				r.spent[at.in.Hash] = at.spent
				line, _ := json.Marshal(spentLine{at.in.Hash, at.spent})
				b.Write(append(line, '\n'))
			}
		}
		if err := replaceFile(r.spentPath, b.Bytes()); err != nil {
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

// voidSpec — что снять, когда база ушла назад.
type voidSpec struct {
	// since — для намерений без отметки базы: время шлюза, до которого они
	// не в счёт (запуск поднятой базы); ноль — не в счёт все прочитанные.
	since time.Time
	// timeline — линия времени, которую сборщик читал до сих пор: намерения
	// с отметкой линии новее её startedBefore не снимает (0 — снимает любые).
	timeline uint32
	// startedBefore — для намерений с отметкой базы: не в счёт, если их база
	// запущена не позже (микросекунды). Это время последней транзакции,
	// прочитанной из прежней истории: база новой истории запущена после неё
	// — и после перезапуска поднятой базы её действия остаются действиями
	// (R2-2 третьего захода). Отметка — в часах базы, а не шлюза: часы шлюза
	// впереди не продлевают жизнь намерению прежней истории (R2-1).
	startedBefore int64
}

// void — база ушла назад: поднята из копии или её место заняла отставшая
// реплика, и номера транзакций, названные в намерениях до сих пор, она
// выдаст снова другим транзакциям (R2-1). Что из прочитанного не в счёт и
// что не в счёт из прочитанного позже — voidSpec. Так и после перезапуска.
func (r *receipts) void(v voidSpec) error {
	if err := r.poll(); err != nil {
		return err
	}
	// Намерения без отметки базы — все прочитанные до сих пор: их время —
	// по часам шлюза, и сравнить его с запуском базы нельзя — часы шлюза
	// впереди продлевали намерению прежней истории жизнь (T-3, R2-1
	// третьего захода). Сравнение — внутри одних часов: с последним
	// прочитанным намерением того же шлюза.
	for _, c := range r.chains {
		if t, err := time.Parse(time.RFC3339Nano, c.VoidTime); err != nil || c.last.After(t) {
			c.VoidTime = c.last.UTC().Format(time.RFC3339Nano)
		}
	}
	if v.since.After(r.voidBefore) {
		r.voidBefore = v.since
	}
	r.voidStartedBefore = max(r.voidStartedBefore, v.startedBefore)
	r.voidTimeline = max(r.voidTimeline, v.timeline)
	var order []uint32
	for _, xid := range r.order {
		at, ok := r.byXID[xid]
		if !ok {
			continue
		}
		// Без отметки базы — все прочитанные (выше); с отметкой — по ней.
		if at.started == 0 || r.startedVoid(at.started, at.timeline) {
			delete(r.byXID, xid)
			continue
		}
		order = append(order, xid)
	}
	r.order = order
	r.dirty = true
	return r.save()
}

// switched — кластер переключился на реплику, у которой есть всё прочитанное
// сборщиком (pginput identify): база назад не уходила, и намерения с
// отметкой линии времени остаются в счёте — каждое решает транзакцию своей
// линии (fits). Намерение без отметки линии (другой шлюз, прежняя версия
// esmcp) не говорит, на какой основной писалось, а новая основная выдаёт
// заново номера транзакций прежней, не дошедших до неё: такие, прочитанные
// до сих пор, — не в счёт, как при уходе базы назад.
func (r *receipts) switched() error {
	if err := r.poll(); err != nil {
		return err
	}
	for _, c := range r.chains {
		if t, err := time.Parse(time.RFC3339Nano, c.SwitchTime); err != nil || c.last.After(t) {
			c.SwitchTime = c.last.UTC().Format(time.RFC3339Nano)
		}
	}
	var order []uint32
	for _, xid := range r.order {
		at, ok := r.byXID[xid]
		if !ok {
			continue
		}
		if at.timeline == 0 {
			delete(r.byXID, xid)
			continue
		}
		order = append(order, xid)
	}
	r.order = order
	r.dirty = true
	return r.save()
}

// isVoid — намерение шлюза c со временем шлюза gw и отметками базы started
// и timeline дописано до того, как база ушла назад или, без отметки линии, до
// переключения кластера.
func (r *receipts) isVoid(c *chainState, gw time.Time, started int64, timeline uint32) bool {
	if t, err := time.Parse(time.RFC3339Nano, c.SwitchTime); timeline == 0 && err == nil && !gw.After(t) {
		return true
	}
	if started != 0 {
		return r.startedVoid(started, timeline)
	}
	return c.voided(gw) || !r.voidBefore.IsZero() && !gw.After(r.voidBefore)
}

// startedVoid — намерение с отметками базы started и timeline — из истории
// до того, как база ушла назад: его база запущена не позже границы, и линия
// времени у него не новее той, что сборщик тогда читал. Без отметки линии
// (timeline 0: шлюз её не пишет) — по одному запуску, как раньше.
func (r *receipts) startedVoid(started int64, timeline uint32) bool {
	if timeline != 0 && r.voidTimeline != 0 && timeline > r.voidTimeline {
		return false
	}
	return started <= r.voidStartedBefore
}

// voided — намерение шлюза c со временем at дописано до того, как база ушла
// назад.
func (c *chainState) voided(at time.Time) bool {
	v, err := time.Parse(time.RFC3339Nano, c.VoidTime)
	return err == nil && !at.After(v)
}

// handled — обработанная квитанция исхода: хэш и время шлюза.
type handled struct {
	Hash string `json:"hash"`
	Time string `json:"time,omitempty"`
}

// loadAlerted читает ReceiptsAlerted.
func (r *receipts) loadAlerted() error {
	data, err := os.ReadFile(r.alertedPath)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	for _, line := range bytes.Split(data, []byte("\n")) {
		var e handled
		if json.Unmarshal(line, &e) == nil && e.Hash != "" && !r.alerted[e.Hash] {
			r.alerted[e.Hash] = true
			r.alertedOrder = append(r.alertedOrder, e)
		}
	}
	return nil
}

// isHandled — квитанция исхода rc уже обработана (по хэшу или до границы
// сжатия).
func (r *receipts) isHandled(rc gateway.Receipt) bool {
	return r.alerted[rc.Hash] || !r.handledBefore.IsZero() && !rc.Time.After(r.handledBefore)
}

// markAlerted — квитанция исхода rc обработана. Пишется после тревоги:
// упасть между ними — тревога второй раз, а не ни разу.
func (r *receipts) markAlerted(rc gateway.Receipt) error {
	e := handled{Hash: rc.Hash, Time: rc.Time.UTC().Format(time.RFC3339Nano)}
	r.alerted[e.Hash] = true
	r.alertedOrder = append(r.alertedOrder, e)
	if len(r.alertedOrder) > 2*maxAlerted {
		drop, keep := r.alertedOrder[:len(r.alertedOrder)-maxAlerted], r.alertedOrder[len(r.alertedOrder)-maxAlerted:]
		for _, d := range drop {
			if t, err := time.Parse(time.RFC3339Nano, d.Time); err == nil && t.After(r.handledBefore) {
				r.handledBefore = t
			}
		}
		var b bytes.Buffer
		r.alerted = map[string]bool{}
		for _, h := range keep {
			r.alerted[h.Hash] = true
			line, _ := json.Marshal(h)
			b.Write(append(line, '\n'))
		}
		r.alertedOrder = append([]handled(nil), keep...)
		r.dirty = true // граница — в receipts.json
		return replaceFile(r.alertedPath, b.Bytes())
	}
	f, err := os.OpenFile(r.alertedPath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	defer f.Close()
	line, _ := json.Marshal(e)
	_, err = f.Write(append(line, '\n'))
	return err
}

// replaceFile заменяет файл целиком: временный файл, fsync, переименование,
// fsync каталога.
func replaceFile(path string, data []byte) error {
	tmp := path + ".tmp"
	f, err := os.OpenFile(tmp, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	if _, err = f.Write(data); err == nil {
		err = f.Sync()
	}
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	if err == nil {
		err = os.Rename(tmp, path)
	}
	if err != nil {
		return err
	}
	return syncDir(filepath.Dir(path))
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
	if err != nil {
		var unread errUnreadable
		if !errors.As(err, &unread) {
			return moved, err // тревогу не записать: свой каталог сборщика
		}
		if rf.f != nil {
			rf.f.Close()
			rf.f = nil
		}
		return moved, r.cannotRead(rf, unread.err)
	}
	if rf.f == nil {
		return moved, nil
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
	// Только сам файл (не ссылка на месте пути, R1-4 третьего захода) и
	// только обычный; O_NONBLOCK: на месте файла может оказаться FIFO, и
	// открытие повисло бы.
	f, err := gateway.OpenReceipts(rf.path, os.O_RDONLY, 0)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return r.cannotRead(rf, err)
	}
	if r.unreadable[rf.path] != "" {
		delete(r.unreadable, rf.path)
		ev := alert.Event{}
		ev.Add(alert.KindReceiptsUnreadable, fmt.Sprintf("the gateway's receipts %s can be read again", rf.path))
		if err := r.raise(ev); err != nil {
			f.Close()
			return err
		}
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

// errUnreadable — файл квитанций шлюза не прочесть (а не свой каталог
// сборщика).
type errUnreadable struct{ err error }

func (e errUnreadable) Error() string { return e.err.Error() }

// cannotRead — файл квитанций rf не открыть или не прочесть: на его месте
// каталог, FIFO, ссылка на чужой файл, нет прав. Вход не встаёт (раньше
// ошибка на каждом начале транзакции держала вход, а при запуске — весь
// сборщик со всеми источниками; R2-6 второго захода): намерений шлюза нет,
// и его транзакции идут отпечатком, а людям — одна тревога, пока файл не
// прочтётся.
func (r *receipts) cannotRead(rf *receiptFile, err error) error {
	why := err.Error()
	if r.unreadable[rf.path] == why {
		return nil
	}
	r.unreadable[rf.path] = why
	ev := alert.Event{}
	ev.Add(alert.KindReceiptsUnreadable, fmt.Sprintf("the gateway's receipts %s cannot be read: %s. Until they can, the gateway's transactions go as fingerprints: whole, with their rows, they are not kept, and they cannot be undone", rf.path, why))
	return r.raise(ev)
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
		old := &receiptFile{path: filepath.Join(dir, e.Name()), chain: rf.path, f: f, inode: rf.inode, alerted: rf.alerted, migrate: rf.migrate}
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
		return false, errUnreadable{err}
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
		// Дыра разреженного файла — нули, продолжение длинной строки: её не
		// читают (R1-5 третьего захода: truncate -s +1T — минуты простоя
		// потока на каждом чтении).
		if data, ok := gateway.NextData(rf.f, rf.off, fi.Size()); !ok || data > rf.off {
			rf.off, rf.partial, rf.long, rf.tail = data, nil, true, nil
			if !ok {
				rf.off = fi.Size()
			}
			continue
		}
		got, err := rf.f.ReadAt(buf[:min(int64(len(buf)), fi.Size()-rf.off)], rf.off)
		if err != nil && !errors.Is(err, io.EOF) {
			return moved, errUnreadable{err}
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
// из них длиннее любой квитанции, сколько подписаны ключом, с которого шлюз
// ушёл (keyState).
type unsigned struct {
	n, long, retired int
	first, last      int64
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
	if u.retired == u.n {
		ev.Add(alert.KindForgedReceipt, fmt.Sprintf("%s of the gateway's receipts %s: signed with a key its gateway moved on from — "+
			"after the gateway's first receipt under its new key, only whoever kept the previous key signs with it; it decides nothing about any transaction", where, rf.path))
		return r.raise(ev)
	}
	also := ""
	if u.retired > 0 {
		also = fmt.Sprintf("; %d of them are signed with a key their gateway moved on from, which only whoever kept that key signs with now", u.retired)
	}
	ev.Add(alert.KindForgedReceipt, fmt.Sprintf("%s of the gateway's receipts %s: not a receipt signed with a gateway key the collector knows — "+
		"a gateway died in the middle of writing it, or someone without the key wrote it%s; it decides nothing about any transaction", where, rf.path, also))
	return r.raise(ev)
}

// retiredKey — квитанция rc файла rf подписана ключом key, с которого её шлюз
// ушёл; иначе ключ становится нынешним ключом шлюза, а прежний, если он
// другой, снимается (keyState).
func (r *receipts) retiredKey(rf *receiptFile, rc gateway.Receipt, key []byte) bool {
	chain := rf.chain
	if chain == "" {
		chain = rf.path
	}
	id, kh := chain+"\x00"+rc.Gateway, hex.EncodeToString(key)
	ks := r.keyStates[id]
	switch {
	case ks == nil:
		r.keyStates[id] = &keyState{Current: kh}
		r.dirty = true
	case ks.Current == kh:
	default:
		if _, gone := ks.Retired[kh]; gone {
			return true
		}
		if ks.Retired == nil {
			ks.Retired = map[string]uint64{}
		}
		ks.Retired[ks.Current] = rc.Seq
		ks.Current = kh
		r.dirty = true
	}
	return false
}

func (r *receipts) save() error {
	st := receiptsState{Version: stateVersion, Chains: r.chains, Links: r.links, Keys: r.keyStates, VoidStartedBefore: r.voidStartedBefore, VoidTimeline: r.voidTimeline}
	if !r.handledBefore.IsZero() {
		st.HandledBefore = r.handledBefore.UTC().Format(time.RFC3339Nano)
	}
	if !r.voidBefore.IsZero() {
		st.VoidBefore = r.voidBefore.UTC().Format(time.RFC3339Nano)
	}
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
	var key []byte
	for _, k := range r.keys {
		if rc.Verify(k) == nil {
			signed, key = true, k
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
	if r.retiredKey(rf, rc, key) {
		if fresh {
			bad.add(end, false)
			bad.retired++
		}
		return nil
	}
	if err := r.link(rf, rc, key); err != nil {
		return err
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
		DBStarted  string `json:"db_started"`
		DBTimeline string `json:"db_timeline"`
		Alerted    bool   `json:"alerted"`
	}
	json.Unmarshal(rc.Body, &body)
	act := pgtap.Intent{ID: rc.Action, Gateway: rc.Gateway, Seq: rc.Seq, Hash: rc.Hash, Step: rc.Step, Time: rc.Time.UTC().Format(time.RFC3339Nano),
		Agent: alert.Field(body.Agent), Tool: alert.Field(body.Tool), Reason: cut(body.Reason, maxReason), Undoes: alert.Field(body.Undoes)}
	c := r.chain(rc.Gateway)
	switch rc.Step {
	case alert.StepIntent, alert.StepUndo:
		r.sawIntent(rc.Action)
		if rc.Time.After(c.last) {
			c.last = rc.Time
		}
		started, _ := strconv.ParseInt(body.DBStarted, 10, 64)
		tl, _ := strconv.ParseUint(body.DBTimeline, 10, 32)
		if r.isVoid(c, rc.Time, started, uint32(tl)) {
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
			at := intentAt{in: act, started: started, timeline: uint32(tl)}
			if xid8 != 0 && uint32(xid8) == uint32(xid) {
				at.xid8 = xid8
			}
			r.remember(uint32(xid), at)
			if commit, ok := r.missed[uint32(xid)]; ok && commit.Sub(rc.Time).Abs() <= intentWindow {
				// Намерения не было, когда сборщик читал транзакцию, а теперь
				// оно есть: его вынули из файла, пока шло действие, и вернули
				// те же байты на то же место (T-2 третьего захода: пропуска в
				// цепочке нет, исход — за намерением, и ни одной тревоги).
				delete(r.missed, uint32(xid))
				ev := alert.Event{Action: &act}
				ev.Add(alert.KindIntentMissing, fmt.Sprintf("the intent of action %q for transaction %d came into %s only after the collector had read the transaction (committed %s): "+
					"someone who writes to the file took the intent out while the action ran and put it back, or the gateway wrote it late; "+
					"transaction %d went as a fingerprint: whole, with its rows, it is not kept, and it cannot be undone",
					rc.Action, xid, rf.path, commit.UTC().Format(time.RFC3339), xid))
				if err := r.raise(ev); err != nil {
					return err
				}
			}
		}
	case alert.StepOutcome:
		// Дважды о том же исходе — нет: ни после обрезки, замены и сдвига
		// файла, ни по копии прежней строки, дописанной без ключа. Новизна —
		// по хэшу, а не по месту в файле (R1-1 третьего захода).
		if r.isHandled(rc) {
			break
		}
		if end <= rf.migrate {
			return r.markAlerted(rc) // обработан прежней версией, по месту
		}
		missing := body.XID != "" && !r.intents[rc.Action] && !r.recorded(rc.Action, body.XID)
		if missing {
			// Сервер пишет намерение до SQL, с номером транзакции, и без него
			// SQL не идёт: исход с номером при непрочитанном намерении — строку
			// намерения вынули из файла, пока шла транзакция, и она легла
			// отпечатком без тревоги (T-2 второго захода).
			ev := alert.Event{Action: &act}
			ev.Add(alert.KindIntentMissing, fmt.Sprintf("the gateway's outcome receipt of action %q (%s, transaction %s) comes without its intent in %s: "+
				"someone who writes to the file removed the intent while the action ran, or it was in a part of the file the collector did not read; "+
				"transaction %s went as a fingerprint: whole, with its rows, it is not kept, and it cannot be undone", rc.Action, alert.Field(body.Outcome), alert.Field(body.XID), rf.path, alert.Field(body.XID)))
			if err := r.raise(ev); err != nil {
				return err
			}
		}
		if _, err := r.outcome(act, body.Outcome, body.Cause, body.Rows, body.Limit, body.WindowRows, body.Window, body.Actions, body.Timeout, body.XID, body.Alerted); err != nil {
			return err
		}
		// Исход обработан: его копии, дописанные без ключа, — ни тревоги снова,
		// ни поиска по справочнику на каждую (R1-2 третьего захода).
		return r.markAlerted(rc)
	}
	return nil
}

// link сверяет квитанцию rc с цепочкой её шлюза в файле rf: пропуск — тревога
// (если о строке тревоги ещё не поднимались). Повтор прежней строки и копия
// прежнего начала цепочку не двигают.
func (r *receipts) link(rf *receiptFile, rc gateway.Receipt, key []byte) error {
	chain := rf.chain
	if chain == "" {
		chain = rf.path
	}
	k := chain + "\x00" + rc.Gateway + "\x00" + hex.EncodeToString(key)
	l := r.links[k]
	if rc.Prev == gateway.Genesis {
		if l != nil && slices.Contains(l.Genesis, rc.Hash) {
			return nil // копия прежнего начала
		}
		g := []string{rc.Hash}
		if l != nil {
			g = append(l.Genesis, rc.Hash)
			if len(g) > maxGenesis {
				g = g[len(g)-maxGenesis:]
			}
		}
		r.links[k] = &chainLink{Seq: rc.Seq, Hash: rc.Hash, Time: rc.Time.UTC().Format(time.RFC3339Nano), Genesis: g}
		return nil
	}
	if l == nil {
		r.links[k] = &chainLink{Seq: rc.Seq, Hash: rc.Hash, Time: rc.Time.UTC().Format(time.RFC3339Nano)} // первая увиденная: что до неё, сборщик не читал
		return nil
	}
	if rc.Seq <= l.Seq {
		return nil // повтор прежней строки или её копия
	}
	gap := rc.Seq != l.Seq+1 || rc.Prev != l.Hash
	if gap && rc.Time.Before(l.time()) {
		// Квитанция старше последней прочитанной, а seq выше: копия из другой
		// ветви цепочки (прежней, до потери головы шлюзом), не продолжение.
		// Место цепочки она не двигает: иначе пропуски до её seq не были бы
		// видны (R1 третьего захода).
		return nil
	}
	from := l.Seq
	l.Seq, l.Hash, l.Time = rc.Seq, rc.Hash, rc.Time.UTC().Format(time.RFC3339Nano)
	if !gap {
		return nil
	}
	what := fmt.Sprintf("%d receipts between them are", rc.Seq-from-1)
	if rc.Seq == from+1 {
		what = "it names another one before it:"
	}
	ev := alert.Event{}
	ev.Add(alert.KindReceiptsGap, fmt.Sprintf("in %s the receipt of gateway %s with seq %d follows its seq %d, and %s not in the file. "+
		"Someone who writes to the file removed them (an intent removed while its action ran turns the action's transaction into a fingerprint, an outcome removed hides its alert), "+
		"or a part of the file the collector did not read was rotated away while it was stopped, or the gateway's chain went another way (a second branch); the store keeps whatever it read of them",
		rf.path, alert.Field(rc.Gateway), rc.Seq, from, what))
	return r.raise(ev)
}

// recorded — транзакция xid уже лежит в справочнике действием id: намерение
// прочитано прежде (до перезапуска, в файле, который с тех пор повернули и
// сжали), и тревога intent-missing о нём была бы ложной.
func (r *receipts) recorded(id, xid string) bool {
	n, err := strconv.ParseUint(xid, 10, 32)
	if err != nil {
		return false
	}
	e, found, err := pgtap.LookupTail(filepath.Join(filepath.Dir(r.state), pgtap.IndexFile), uint32(n), recordedSpan)
	return err == nil && found && e.Action != nil && e.Action.ID == id
}

// recordedSpan — сколько последних байт справочника смотрит recorded: там
// транзакции последних часов, а действие, чей исход пришёл сейчас, — среди
// них.
const recordedSpan = 16 << 20

// sawIntent — намерение действия id прочитано.
func (r *receipts) sawIntent(id string) {
	if r.intents[id] {
		return
	}
	r.intents[id] = true
	r.intentsOrder = append(r.intentsOrder, id)
	if len(r.intentsOrder) > 2*maxIntents {
		for _, old := range r.intentsOrder[:maxIntents] {
			delete(r.intents, old)
		}
		r.intentsOrder = append([]string(nil), r.intentsOrder[maxIntents:]...)
	}
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
func (r *receipts) outcome(act pgtap.Intent, outcome, cause string, rows, limit, windowRows int, window string, actions int, timeout, xid string, alerted bool) (bool, error) {
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
		return false, nil
	case cause == "row-limit":
		detail = fmt.Sprintf("the MCP server stopped an action that would change %d rows (the limit for one action is %d): it was rolled back, nothing changed", rows, limit)
	case cause == "window-rows":
		detail = fmt.Sprintf("the MCP server stopped an action of %d rows: with it the agent would have changed %d rows in %s (the limit is %d): it was rolled back, nothing changed",
			rows, windowRows+rows, window, limit)
	case cause == "rate":
		if !alerted {
			return false, nil // о частоте — раз в минуту: остальные отказы только в квитанциях
		}
		detail = fmt.Sprintf("the MCP server refuses the agent's actions: %d in the last minute (the limit is %d). This is reported once a minute at most; every refusal is in the receipts",
			actions, limit)
	default:
		detail = fmt.Sprintf("the MCP server stopped an action (%s): nothing changed", alert.Field(cause))
	}
	ev := alert.Event{Action: &act}
	ev.Add(kind, detail)
	return true, r.raise(ev)
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
