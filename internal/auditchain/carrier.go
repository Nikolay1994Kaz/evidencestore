package auditchain

import (
	"encoding/binary"
	"errors"
	"fmt"
	"hash/crc32"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"

	"golang.org/x/sys/unix"
)

// Носитель цепи на диске: три файла и жёсткий порядок записи между ними.
//
//	leaves_<первый>.log  события — ротируются по размеру, не удаляются и не сжимаются никогда
//	chain.log            звенья-агрегаты — append-only, не трогается никогда
//	chain.head           48 Б × 2 слота — голова, пишется на месте с fdatasync
//
// ⭐ЦЕНЫ ЗДЕСЬ НЕ УГАДАНЫ, А ИЗМЕРЕНЫ ДО КОДА (carrier_bench_test.go, ext4):
// событие синхронно — 1.49 мс, это ВОСЕМЬ бюджетов вставки (188 мкс), темп упал
// бы 5324→670/с. Батчем на тике — 5.9…7.3 мкс, 3.1–3.9% бюджета. Поэтому
// Append только копит, а на диск ходит Flush. Голова — два слота с CRC и
// fdatasync (0.42 мс) вместо tmp→rename→fsync каталога (2.16 мс): rename нужен
// файлам переменного размера, голова — 48 фиксированных байт.
//
// ⭐ПОРЯДОК ВНУТРИ ТИКА ФИКСИРОВАН И ЕСТЬ ГЛАВНОЕ СВОЙСТВО НОСИТЕЛЯ:
//
//	листья → fsync → звено → fsync → голова
//
// Тот же приём, что при уничтожении ключа (сначала новый файл, потом старый
// корень): отказ обязан
// оставлять МЕНЕЕ ДОКАЗАННОЕ, а не менее доказуемое. Листья без корня
// доигрываются — Open поднимает их и включает в следующее звено. Корень без
// листьев не чинится ничем: остаётся «что-то было, а что — неизвестно»,
// навсегда. Перестановка стоит 1.2 мс на секунду (0.12%) и меняет один класс
// отказа на другой, необратимый.
type Carrier struct {
	mu  sync.Mutex
	dir string

	leaves *os.File
	chain  *os.File
	head   *os.File

	headState Head
	nextLeaf  uint64 // сквозной номер следующего листа
	segFirst  uint64 // номер первого листа в текущем файле листьев

	pending []Leaf
	onDisk  int // сколько первых pending уже durable в файле листьев

	segmentBytes int64 // порог ротации; поле, а не константа, чтобы тест мог его опустить
	recovery     Recovery

	// failed — первая ошибка записи тика. Дальше носитель не пишет ничего:
	// после неудачной фазы неизвестно, что на диске, а повтор дописал бы
	// листья и звено второй раз. Что на диске, разберёт Open после рестарта.
	failed error

	// beforeWrite — крючок отказа: зовётся перед каждой записью тика с именем
	// фазы ("leaves"/"link"/"head"). В проде nil.
	//
	// ⭐ЗАЧЕМ СШИВКА В ПРОДОВОМ КОДЕ. Порядок фаз — главное свойство носителя,
	// и проверить его иначе нечем: при штатной работе перестановка фаз
	// НЕЗАМЕТНА, файлы получаются те же. Разница видна ровно в момент отказа
	// между ними, а отказ надо уметь устроить. Без этого крючка тест на
	// порядок был бы зелёным при любой перестановке — то есть проверял бы
	// собственное существование.
	beforeWrite func(phase string) error
}

const (
	chainFileName = "chain.log"
	headFileName  = "chain.head"
	leafPrefix    = "leaves_"
	leafSuffix    = ".log"

	// headSlotSize — голова: seq + хеш + CRC + выравнивание. Две копии в одном
	// файле, пишутся попеременно: перезапись на месте не атомарна при отказе
	// питания, а два слота с CRC дают правило «взять валидный с большим seq».
	headSlotSize = 48

	// defaultSegmentBytes — порог ротации файла листьев.
	//
	// ⚠Ротация возможна ТОЛЬКО на границе тика, когда буфер пуст. Иначе
	// непокрытые листья могли бы оказаться в двух файлах сразу, и
	// восстановление пришлось бы учить склейке ради случая, которого можно
	// просто не допустить.
	defaultSegmentBytes = 64 << 20
)

// Recovery — что носитель обнаружил при открытии.
//
// Возвращается наружу, а не пишется в лог внутри: «голова отставала» и «хвост
// обрезан» — события разного веса, и решать, как громко о них говорить,
// должен вызывающий. Молчать нельзя ни о том, ни о другом.
type Recovery struct {
	Links             int    // звеньев в цепи
	HeadAdvanced      uint64 // на сколько звеньев голова отставала от журнала
	LeavesWithoutRoot int    // листья, не покрытые звеном: уйдут в следующее
	TornTailBytes     int64  // байт оборванного хвоста отброшено
	TornTailFile      string // куда отложен последний отрезанный хвост
	// HeadSlotDamaged — один из слотов головы записан и не сходится с CRC.
	// Так бывает при отказе посреди записи головы, но так же выглядит и
	// подмена: звено, отрезанное вместе с порчей слота, не видно ничем.
	HeadSlotDamaged bool
}

// ErrTruncatedChain — журнал короче, чем помнит голова.
//
// ⚠Это не поломка носителя, а ровно тот сигнал, ради которого цепь построена:
// кто-то отрезал хвост. Отдельная ошибка нужна, чтобы вызывающий мог отличить
// её от «файл побился» и не чинил её автоматически.
var ErrTruncatedChain = errors.New("auditchain: журнал короче сохранённой головы — хвост обрезан")

// Open поднимает носитель, восстанавливая состояние после любого отказа.
func Open(dir string) (*Carrier, error) {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, fmt.Errorf("auditchain: каталог %s: %w", dir, err)
	}
	c := &Carrier{dir: dir, segmentBytes: defaultSegmentBytes}

	// На пути ошибки файлы закрываются без флаша: недоразобранный носитель
	// не пишет ничего, иначе поднятые листья легли бы под звено, которое не
	// сходится с ними.
	var err error
	if c.head, err = os.OpenFile(filepath.Join(dir, headFileName), os.O_CREATE|os.O_RDWR, 0o600); err != nil {
		return nil, err
	}
	if err = c.head.Truncate(2 * headSlotSize); err != nil {
		c.closeFiles()
		return nil, err
	}
	if c.chain, err = os.OpenFile(filepath.Join(dir, chainFileName), os.O_CREATE|os.O_RDWR|os.O_APPEND, 0o600); err != nil {
		c.closeFiles()
		return nil, err
	}
	// Каталог с только что созданными файлами: без этого fsync отказ питания
	// может оставить записи без имён.
	if err = syncDir(dir); err != nil {
		c.closeFiles()
		return nil, err
	}
	if err = c.recover(); err != nil {
		c.closeFiles()
		return nil, err
	}
	return c, nil
}

// recover сводит три файла в одно состояние. Порядок разбора обратный порядку
// записи: голова, журнал, листья.
func (c *Carrier) recover() error {
	saved, err := c.readHead()
	if err != nil {
		return err
	}

	bodies, torn, aside, err := readFrames(c.chain)
	if err != nil {
		return err
	}
	c.recovery.TornTailBytes += torn
	if aside != "" {
		c.recovery.TornTailFile = aside
	}

	links := make([]Record, 0, len(bodies))
	for i, body := range bodies {
		r, err := decodeRecord(body)
		if err != nil {
			return fmt.Errorf("auditchain: звено %d: %w", i, err)
		}
		links = append(links, r)
	}

	head, err := Verify(links, nil)
	if err != nil {
		return err
	}
	switch {
	case saved.Seq > head.Seq:
		return fmt.Errorf("%w: в журнале %d звеньев, голова помнит %d", ErrTruncatedChain, head.Seq, saved.Seq)
	case saved.Seq < head.Seq:
		// Отказ между fsync звена и записью головы. Журнал длиннее — данные
		// целы, голова просто не успела; догоняем и говорим об этом вслух.
		//
		// ⚠Но догоняем НЕ вслепую: сохранённая голова обязана совпасть со
		// звеном на своей позиции. Без этой сверки журнал ЧУЖОЙ цепи принялся
		// бы молча — «голова отстала» стало бы универсальным оправданием
		// любого расхождения, то есть дырой ровно там, где строится защита.
		if saved.Seq > 0 && Hash(links[saved.Seq-1]) != saved.Hash {
			return fmt.Errorf("auditchain: сохранённая голова (seq %d) не совпадает со звеном журнала на той же позиции — цепь подменена",
				saved.Seq)
		}
		c.recovery.HeadAdvanced = head.Seq - saved.Seq
	case saved.Hash != head.Hash:
		return fmt.Errorf("auditchain: голова журнала не совпадает с сохранённой при равной длине — цепь подменена")
	}
	c.headState = head
	c.recovery.Links = len(links)

	// Голова догоняет журнал на диске: иначе следующий отказ застал бы носитель
	// в том же несогласованном состоянии, а восстановление, которое не
	// доводится до конца, — это не восстановление.
	if c.recovery.HeadAdvanced > 0 {
		if err := c.writeHead(head); err != nil {
			return err
		}
	}

	covered := uint64(0)
	if n := len(links); n > 0 {
		p, err := DecodeBatchPayload(links[n-1].Payload)
		if err != nil {
			return fmt.Errorf("auditchain: последнее звено: %w", err)
		}
		covered = p.FirstLeaf + uint64(p.Count)
	}
	return c.openLeafSegment(covered)
}

// openLeafSegment открывает последний файл листьев и поднимает из него
// листья, которые не покрыты ни одним звеном.
func (c *Carrier) openLeafSegment(covered uint64) error {
	segs, err := leafSegments(c.dir)
	if err != nil {
		return err
	}
	if len(segs) == 0 {
		if covered > 0 {
			return fmt.Errorf("%w: звенья покрывают %d листьев, а файлов листьев нет", ErrLeavesMissing, covered)
		}
		c.segFirst = covered
		c.nextLeaf = covered
		return c.createLeafSegment(covered)
	}
	c.segFirst = segs[len(segs)-1]
	f, err := os.OpenFile(leafPath(c.dir, c.segFirst), os.O_RDWR|os.O_APPEND, 0o600)
	if err != nil {
		return err
	}
	c.leaves = f

	bodies, torn, aside, err := readFrames(f)
	if err != nil {
		return err
	}
	c.recovery.TornTailBytes += torn
	if aside != "" {
		c.recovery.TornTailFile = aside
	}
	c.nextLeaf = c.segFirst + uint64(len(bodies))

	if c.nextLeaf < covered {
		return fmt.Errorf("%w: звено покрывает лист %d, а в файлах листьев их %d — листья потеряны",
			ErrLeavesMissing, covered-1, c.nextLeaf)
	}
	// ⭐Листья без корня: отказ случился между их fsync и записью звена.
	// Они не потеряны — поднимаем в буфер, следующее звено их накроет.
	for i := covered - c.segFirst; i < uint64(len(bodies)); i++ {
		l, err := decodeLeaf(bodies[i])
		if err != nil {
			return fmt.Errorf("auditchain: лист %d: %w", c.segFirst+i, err)
		}
		c.pending = append(c.pending, l)
	}
	c.onDisk = len(c.pending)
	c.recovery.LeavesWithoutRoot = len(c.pending)
	return nil
}

func (c *Carrier) createLeafSegment(first uint64) error {
	f, err := os.OpenFile(leafPath(c.dir, first), os.O_CREATE|os.O_RDWR|os.O_APPEND, 0o600)
	if err != nil {
		return err
	}
	c.leaves = f
	c.segFirst = first
	return syncDir(c.dir)
}

// Recovery — что обнаружилось при открытии.
func (c *Carrier) Recovery() Recovery {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.recovery
}

// Append кладёт событие в буфер. На диск не ходит: цена похода измерена и
// составляет восемь бюджетов вставки (см. шапку файла).
func (c *Carrier) Append(l Leaf) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.appendLocked(l)
}

// appendLocked держит инвариант, на котором стоит нумерация:
// первый лист батча = nextLeaf − len(pending). Номер выдаётся ЗДЕСЬ, а не при
// флаше, потому что он должен быть сквозным и не зависеть от того, сколько
// событий попало в конкретный тик.
func (c *Carrier) appendLocked(l Leaf) {
	c.pending = append(c.pending, l)
	c.nextLeaf++
}

// Pending — сколько событий ждёт ближайшего тика. Это и есть окно
// недоказуемости в штуках.
func (c *Carrier) Pending() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return len(c.pending)
}

// Head — текущая голова цепи.
func (c *Carrier) Head() Head {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.headState
}

// Flush закрывает батч: пишет листья, звено над ними и голову — в этом
// порядке, с fsync между фазами.
//
// Пустой батч не пишет НИЧЕГО и не двигает голову. Иначе простаивающий
// инстанс писал бы 31.5 млн пустых звеньев в год: 3.5 ГБ сообщений «ничего
// не произошло» при бюджете 10 ГБ.
func (c *Carrier) Flush() (Head, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.flushLocked()
}

func (c *Carrier) flushLocked() (Head, error) {
	if c.failed != nil {
		return c.headState, c.failed
	}
	if len(c.pending) == 0 {
		return c.headState, nil
	}
	head, err := c.writeTick()
	if err != nil {
		c.failed = fmt.Errorf("auditchain: запись тика: %w", err)
		return c.headState, c.failed
	}
	return head, nil
}

// Failed — защёлкнутая ошибка записи: не nil — носитель больше не пишет, и
// принимать улики, которые не лягут в цепь, нельзя.
func (c *Carrier) Failed() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.failed
}

// writeTick — листья, звено, голова. Любая ошибка защёлкивает носитель
// (flushLocked).
func (c *Carrier) writeTick() (Head, error) {
	if err := c.rotateIfNeeded(); err != nil {
		return c.headState, err
	}

	// Фаза 1: листья. Пишем только те, что ещё не на диске — остальные подняты
	// восстановлением и уже durable.
	fresh := c.pending[c.onDisk:]
	if len(fresh) > 0 {
		buf := make([]byte, 0, 160*len(fresh))
		for _, l := range fresh {
			buf = append(buf, frameLeaf(l)...)
		}
		if err := c.fail("leaves"); err != nil {
			return c.headState, err
		}
		if _, err := c.leaves.Write(buf); err != nil {
			return c.headState, err
		}
		if err := c.leaves.Sync(); err != nil {
			return c.headState, err
		}
	}

	// Фаза 2: звено над батчем.
	first := c.nextLeaf - uint64(len(c.pending))
	link, err := LinkBatch(c.headState, c.pending[len(c.pending)-1].UnixNano, first, c.pending)
	if err != nil {
		return c.headState, err
	}
	if err := c.fail("link"); err != nil {
		return c.headState, err
	}
	if _, err := c.chain.Write(frameRecord(link)); err != nil {
		return c.headState, err
	}
	if err := c.chain.Sync(); err != nil {
		return c.headState, err
	}

	// Фаза 3: голова.
	next := Head{Seq: link.Seq, Hash: Hash(link)}
	if err := c.fail("head"); err != nil {
		return c.headState, err
	}
	if err := c.writeHead(next); err != nil {
		return c.headState, err
	}

	c.headState = next
	c.pending = c.pending[:0]
	c.onDisk = 0
	return next, nil
}

// AppendSync — событие, которое обязано быть доказуемым немедленно.
//
// ⭐ЗАЧЕМ ОТДЕЛЬНЫЙ ПУТЬ. Батч у WAL стоит ДАННЫХ (осознанный RPO), у цепи он
// стоит ГАРАНТИИ: голова, отставшая на k записей, после аварии неотличима от
// обрезанного хвоста — то есть владелец получает правдоподобное отрицание в
// пределах окна. Для SHRED и QUARANTINE это неприемлемо: их квитанция и есть
// продукт. Флаш до себя закрывает окно ПОЛНОСТЬЮ — квитанция всегда покрывает
// всё, что было раньше, — и стоит ноль, потому что эти команды и так платят
// синхронную запись кейринга того же порядка (2.78 мс против 0.42+0.65).
//
// ⚠FORGET сюда НЕ относится, и это тоже измерено: в mix-прогоне их ~118/с, при
// 2.78 мс это треть всего времени, потраченная на одну команду.
func (c *Carrier) AppendSync(l Leaf) (Head, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.appendLocked(l)
	return c.flushLocked()
}

// rotateIfNeeded режет файл листьев ПЕРЕД записью батча.
//
// ⚠Условие onDisk == 0 — не оптимизация, а то самое требование «непокрытые
// листья лежат в ОДНОМ файле». После восстановления часть буфера уже на диске
// в старом файле; отрезав его сейчас, мы развели бы один батч по двум файлам,
// и ReadLeaves для будущего доказательства читал бы половину. Один пропущенный
// тик дешевле, чем склейка в разборе.
func (c *Carrier) rotateIfNeeded() error {
	if c.onDisk != 0 {
		return nil
	}
	st, err := c.leaves.Stat()
	if err != nil || st.Size() < c.segmentBytes {
		return err
	}
	if err := c.leaves.Close(); err != nil {
		return err
	}
	return c.createLeafSegment(c.nextLeaf - uint64(len(c.pending)))
}

// SetBeforeWrite ставит крючок отказа (см. beforeWrite): им тест движка
// устраивает отказ записи цепи. В проде не зовётся.
func (c *Carrier) SetBeforeWrite(fn func(phase string) error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.beforeWrite = fn
}

func (c *Carrier) fail(phase string) error {
	if c.beforeWrite == nil {
		return nil
	}
	return c.beforeWrite(phase)
}

// writeHead пишет голову в слот, чередуя их по чётности seq.
func (c *Carrier) writeHead(h Head) error {
	off := int64(h.Seq%2) * headSlotSize
	if _, err := c.head.WriteAt(encodeHead(h), off); err != nil {
		return err
	}
	// fdatasync, а не fsync: файл постоянного размера, метаданные не менялись.
	// Измерено — вдвое дешевле (0.42 против 0.82 мс). На растущем журнале выше
	// такой замены нет и быть не может: там меняется размер файла.
	return unix.Fdatasync(int(c.head.Fd()))
}

// readHead берёт валидный слот с большим seq — правило, ради которого слотов
// два. Оба невалидны (свежий файл из нулей) — голова нулевая. Слот, в
// который писали (не нули), но с несходящимся CRC, отмечается в Recovery.
func (c *Carrier) readHead() (Head, error) {
	buf := make([]byte, 2*headSlotSize)
	if _, err := c.head.ReadAt(buf, 0); err != nil && !errors.Is(err, io.EOF) {
		return Head{}, err
	}
	var best Head
	for i := 0; i < 2; i++ {
		slot := buf[i*headSlotSize : (i+1)*headSlotSize]
		h, ok := decodeHead(slot)
		if !ok && !allZero(slot) {
			c.recovery.HeadSlotDamaged = true
		}
		if ok && h.Seq >= best.Seq {
			best = h
		}
	}
	return best, nil
}

func allZero(b []byte) bool {
	for _, x := range b {
		if x != 0 {
			return false
		}
	}
	return true
}

// Close сбрасывает буфер и закрывает файлы.
//
// ⚠Флаш на закрытии — не вежливость: без него штатная остановка теряла бы
// доказуемость последних событий ровно так же, как авария, и «выключили
// аккуратно» ничем не отличалось бы от «выдернули шнур».
func (c *Carrier) Close() error {
	c.mu.Lock()
	defer c.mu.Unlock()

	var firstErr error
	if c.chain != nil && c.leaves != nil {
		if _, err := c.flushLocked(); err != nil {
			firstErr = err
		}
	}
	if err := c.closeFiles(); err != nil && firstErr == nil {
		firstErr = err
	}
	return firstErr
}

// closeFiles закрывает файлы без флаша.
func (c *Carrier) closeFiles() error {
	var firstErr error
	for _, f := range []*os.File{c.leaves, c.chain, c.head} {
		if f == nil {
			continue
		}
		if err := f.Close(); err != nil && firstErr == nil {
			firstErr = err
		}
	}
	c.leaves, c.chain, c.head = nil, nil, nil
	return firstErr
}

// ReadChain читает звенья с диска — для VERIFY и для экспорта.
func ReadChain(dir string) ([]Record, error) {
	f, err := os.Open(filepath.Join(dir, chainFileName))
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, nil
		}
		return nil, err
	}
	defer f.Close()

	bodies, err := readFramesRO(f)
	if err != nil {
		return nil, err
	}
	links := make([]Record, 0, len(bodies))
	for i, body := range bodies {
		r, err := decodeRecord(body)
		if err != nil {
			return nil, fmt.Errorf("auditchain: звено %d: %w", i, err)
		}
		links = append(links, r)
	}
	return links, nil
}

// ErrLeavesMissing — нужных листьев на диске нет. Листья не удаляются
// никогда, поэтому это потеря или порча каталога цепи, а не срок хранения:
// звено доказывает, что N событий было, но какие — уже не доказать.
var ErrLeavesMissing = errors.New("auditchain: leaves missing")

// ReadLeaves читает count листьев начиная с номера first — то, из чего
// строится путь Меркла для доказательства включения. Нет файла с этими
// листьями или в нём нет нужных записей — ErrLeavesMissing.
func ReadLeaves(dir string, first uint64, count int) ([]Leaf, error) {
	segs, err := leafSegments(dir)
	if err != nil {
		return nil, err
	}
	idx := sort.Search(len(segs), func(i int) bool { return segs[i] > first }) - 1
	if idx < 0 {
		return nil, fmt.Errorf("%w: листья с номера %d не найдены", ErrLeavesMissing, first)
	}
	f, err := os.Open(leafPath(dir, segs[idx]))
	if errors.Is(err, os.ErrNotExist) {
		return nil, fmt.Errorf("%w: %w", ErrLeavesMissing, err)
	}
	if err != nil {
		return nil, err
	}
	defer f.Close()

	bodies, err := readFramesRO(f)
	if err != nil {
		return nil, err
	}
	from := int(first - segs[idx])
	if from+count > len(bodies) {
		return nil, fmt.Errorf("%w: в файле листьев %d записей, запрошены %d..%d",
			ErrLeavesMissing, len(bodies), from, from+count)
	}
	out := make([]Leaf, 0, count)
	for i := from; i < from+count; i++ {
		l, err := decodeLeaf(bodies[i])
		if err != nil {
			return nil, err
		}
		out = append(out, l)
	}
	return out, nil
}

// ---------------------------------------------------------------------------
// Кадрирование и разбор
// ---------------------------------------------------------------------------

// frame — кадр в файле: длина, тело, CRC.
//
// Хеш цепи защищает от подмены, но не от ОБОРВАННОЙ записи в хвосте — её надо
// уметь отличить от подмены, иначе каждая авария будет выглядеть как атака.
func frame(body []byte) []byte {
	out := make([]byte, 0, 8+len(body))
	var n [4]byte
	binary.BigEndian.PutUint32(n[:], uint32(len(body)))
	out = append(out, n[:]...)
	out = append(out, body...)
	binary.BigEndian.PutUint32(n[:], crc32.ChecksumIEEE(body))
	return append(out, n[:]...)
}

func frameRecord(r Record) []byte { return frame(encodeForHash(r)) }
func frameLeaf(l Leaf) []byte     { return frame(encodeLeafForHash(l)) }

// readFrames читает файл кадр за кадром и ОБРЕЗАЕТ оборванный хвост,
// возвращая число отброшенных байт и файл, куда хвост отложен.
//
// ⚠Обрыв допускается только в конце файла: если за плохим кадром есть хоть
// один целый, это порча середины или правка, и молчать о ней нельзя —
// ошибка. Отрезанное не уничтожается: оно ложится рядом, в
// <файл>.torn-<смещение>.
func readFrames(f *os.File) ([][]byte, int64, string, error) {
	return scanFrames(f, true)
}

// readFramesRO — то же для читателей (ReadChain, ReadLeaves, ScanLeaves):
// оборванный хвост пропускается, но файл не трогается. Обрезать хвост вправе
// только носитель при открытии: читатель, запущенный во время записи,
// увидел бы недописанный кадр и отрезал бы его у пишущего.
func readFramesRO(f *os.File) ([][]byte, error) {
	bodies, _, _, err := scanFrames(f, false)
	return bodies, err
}

// maxFrame — предел тела кадра при поиске целого кадра за плохим: события
// цепи — сотни байт, токен TSA — единицы килобайт.
const maxFrame = 1 << 20

func scanFrames(f *os.File, truncate bool) ([][]byte, int64, string, error) {
	if _, err := f.Seek(0, io.SeekStart); err != nil {
		return nil, 0, "", err
	}
	data, err := io.ReadAll(f)
	if err != nil {
		return nil, 0, "", err
	}

	var bodies [][]byte
	off := 0
	for off < len(data) {
		if off+8 > len(data) {
			break // хвост короче заголовка и CRC
		}
		n := int(binary.BigEndian.Uint32(data[off : off+4]))
		if n == 0 || off+8+n > len(data) {
			break // пустых кадров не бывает (нули после сбоя питания), или длина за концом файла
		}
		body := data[off+4 : off+4+n]
		if crc32.ChecksumIEEE(body) != binary.BigEndian.Uint32(data[off+4+n:off+8+n]) {
			break
		}
		bodies = append(bodies, body)
		off += 8 + n
	}
	if off == len(data) {
		return bodies, 0, "", nil
	}
	// Плохой кадр. Обрыв записи бывает только в конце: целый кадр дальше
	// значит порчу середины.
	if at, ok := frameAfter(data, off+1); ok {
		return nil, 0, "", fmt.Errorf("auditchain: %s: кадр по смещению %d испорчен, а по смещению %d — целый кадр: файл повреждён, это не оборванный хвост",
			f.Name(), off, at)
	}
	torn := int64(len(data) - off)
	var aside string
	if truncate {
		// Хвост отрезаем физически: иначе следующая запись пристроится за
		// мусором и разъедется навсегда. Но сначала откладываем его рядом.
		aside = fmt.Sprintf("%s.torn-%d", f.Name(), off)
		if err := writeSynced(aside, data[off:]); err != nil {
			return nil, 0, "", fmt.Errorf("auditchain: отложить хвост: %w", err)
		}
		if err := syncDir(filepath.Dir(f.Name())); err != nil {
			return nil, 0, "", err
		}
		if err := f.Truncate(int64(off)); err != nil {
			return nil, 0, "", err
		}
		if _, err := f.Seek(0, io.SeekEnd); err != nil {
			return nil, 0, "", err
		}
	}
	return bodies, torn, aside, nil
}

// frameAfter ищет целый кадр (длина в пределах maxFrame, CRC сходится),
// начинающийся в [from, from+8+maxFrame): если кадр испорчен, следующий
// настоящий начинается не дальше. Объём проверки ограничен: исчерпав его,
// frameAfter отвечает «нашёлся» — отказ безопаснее, чем срезать целое.
func frameAfter(data []byte, from int) (int, bool) {
	budget := 1 << 30
	for i := from; i+8 <= len(data) && i < from+8+maxFrame; i++ {
		n := int(binary.BigEndian.Uint32(data[i:]))
		if n == 0 || n > maxFrame || i+8+n > len(data) {
			continue
		}
		if budget -= n; budget < 0 {
			return i, true
		}
		if crc32.ChecksumIEEE(data[i+4:i+4+n]) == binary.BigEndian.Uint32(data[i+4+n:]) {
			return i, true
		}
	}
	return 0, false
}

// writeSynced создаёт файл с содержимым и сбрасывает его на диск.
func writeSynced(path string, data []byte) error {
	f, err := os.OpenFile(path, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	_, werr := f.Write(data)
	return errors.Join(werr, f.Sync(), f.Close())
}

func encodeHead(h Head) []byte {
	buf := make([]byte, headSlotSize)
	binary.BigEndian.PutUint64(buf[0:8], h.Seq)
	copy(buf[8:40], h.Hash[:])
	binary.BigEndian.PutUint32(buf[40:44], crc32.ChecksumIEEE(buf[0:40]))
	return buf
}

func decodeHead(buf []byte) (Head, bool) {
	if len(buf) < headSlotSize {
		return Head{}, false
	}
	if crc32.ChecksumIEEE(buf[0:40]) != binary.BigEndian.Uint32(buf[40:44]) {
		return Head{}, false
	}
	var h Head
	h.Seq = binary.BigEndian.Uint64(buf[0:8])
	copy(h.Hash[:], buf[8:40])
	return h, true
}

// decodeRecord — обратная encodeForHash. Разбор однозначен, потому что поля
// записаны с префиксом длины (дыра 1 из шапки пакета).
func decodeRecord(b []byte) (Record, error) {
	var r Record
	if len(b) < 8+hashSize+8+1 {
		return r, fmt.Errorf("звено короче заголовка: %d Б", len(b))
	}
	r.Seq = binary.BigEndian.Uint64(b[0:8])
	copy(r.PrevHash[:], b[8:8+hashSize])
	off := 8 + hashSize
	r.UnixNano = int64(binary.BigEndian.Uint64(b[off : off+8]))
	off += 8
	r.Type = EventType(b[off])
	off++

	fields, err := readFields(b[off:], 3)
	if err != nil {
		return r, err
	}
	r.Scope, r.Subject, r.Payload = string(fields[0]), string(fields[1]), fields[2]
	return r, nil
}

// decodeLeaf — обратная encodeLeafForHash.
func decodeLeaf(b []byte) (Leaf, error) {
	var l Leaf
	if len(b) < 1+8+1 {
		return l, fmt.Errorf("лист короче заголовка: %d Б", len(b))
	}
	if b[0] != domainLeaf {
		return l, fmt.Errorf("лист начинается с байта 0x%02x, ожидался домен листа 0x%02x", b[0], domainLeaf)
	}
	l.UnixNano = int64(binary.BigEndian.Uint64(b[1:9]))
	l.Type = EventType(b[9])

	fields, err := readFields(b[10:], 3)
	if err != nil {
		return l, err
	}
	l.Scope, l.Subject, l.Payload = string(fields[0]), string(fields[1]), fields[2]
	return l, nil
}

func readFields(b []byte, n int) ([][]byte, error) {
	out := make([][]byte, 0, n)
	off := 0
	for i := 0; i < n; i++ {
		if off+4 > len(b) {
			return nil, fmt.Errorf("поле %d: нет длины", i)
		}
		size := int(binary.BigEndian.Uint32(b[off : off+4]))
		off += 4
		if size < 0 || off+size > len(b) {
			return nil, fmt.Errorf("поле %d: длина %d выходит за пределы записи", i, size)
		}
		out = append(out, b[off:off+size])
		off += size
	}
	if off != len(b) {
		return nil, fmt.Errorf("после разбора осталось %d лишних байт", len(b)-off)
	}
	return out, nil
}

// ---------------------------------------------------------------------------
// Файлы листьев
// ---------------------------------------------------------------------------

func leafPath(dir string, first uint64) string {
	return filepath.Join(dir, fmt.Sprintf("%s%020d%s", leafPrefix, first, leafSuffix))
}

// leafSegments — стартовые номеры файлов листьев по возрастанию.
func leafSegments(dir string) ([]uint64, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, err
	}
	var out []uint64
	for _, e := range entries {
		name := e.Name()
		if !strings.HasPrefix(name, leafPrefix) || !strings.HasSuffix(name, leafSuffix) {
			continue
		}
		num := name[len(leafPrefix) : len(name)-len(leafSuffix)]
		first, err := strconv.ParseUint(num, 10, 64)
		if err != nil {
			continue
		}
		out = append(out, first)
	}
	sort.Slice(out, func(i, j int) bool { return out[i] < out[j] })
	return out, nil
}

// syncDir сбрасывает каталог: без этого созданный файл может не пережить
// отказ питания, даже если его содержимое сброшено.
func syncDir(dir string) error {
	d, err := os.Open(dir)
	if err != nil {
		return err
	}
	defer d.Close()
	return d.Sync()
}

// ScanLeaves проходит все листья по порядку, читая каждый файл один раз, и
// отдаёт сквозной номер листа. Сюда входят и листья, ещё не накрытые
// звеном. Листья не удаляются никогда, поэтому дыра в нумерации файлов —
// порча, а не срок хранения.
func ScanLeaves(dir string, fn func(num uint64, l Leaf) error) error {
	segs, err := leafSegments(dir)
	if err != nil {
		return err
	}
	var next uint64
	for _, first := range segs {
		if first != next {
			return fmt.Errorf("%w: нет листьев %d…%d — файл листьев утрачен", ErrLeavesMissing, next, first-1)
		}
		f, err := os.Open(leafPath(dir, first))
		if err != nil {
			return err
		}
		bodies, err := readFramesRO(f)
		f.Close()
		if err != nil {
			return err
		}
		for _, b := range bodies {
			l, err := decodeLeaf(b)
			if err != nil {
				return fmt.Errorf("auditchain: лист %d: %w", next, err)
			}
			if err := fn(next, l); err != nil {
				return err
			}
			next++
		}
	}
	return nil
}
