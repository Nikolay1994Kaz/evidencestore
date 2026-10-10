// Package evlog — журнал улик. Каждая принятая улика ложится сюда, и только
// после fsync приём отвечает «принято».
//
// УСТРОЙСТВО. Файлы seg_<первая позиция>.log только дописываются. После
// ротации сегмент не меняется никогда: он же и есть неизменяемый сегмент
// хранения, копия которого уходит в S3. Компакции нет и не будет: файлы с
// уликами не переписываются.
//
//	сегмент: "EVLOG01\n" | u64 первая позиция | { запись }…
//	запись:  u32 длина | u32 CRC-32C(данные) | данные
//
// Позиция — сквозной номер записи с единицы, по всем сегментам. Данные —
// байты улики (evidence.Sealed.Marshal); журнал их не разбирает.
//
// ГРУППОВОЙ КОММИТ. Писатели кладут записи в очередь и ждут. Один поток
// забирает всё, что накопилось, пишет одной операцией, делает fsync и только
// потом будит всех писателей этой пачки. Пока идёт fsync, следующая пачка
// копится сама: чем медленнее диск, тем крупнее пачки. Отсюда главное
// свойство: Append вернулся без ошибки — запись на диске.
//
// FAIL-STOP. Первая ошибка записи или fsync защёлкивается: дальше журнал
// отказывает всем (Failed). После неудачного fsync нельзя знать, что на
// диске, а отвечать «принято» про то, что, может быть, не записано, нельзя.
//
// ОСВОБОЖДЕНИЕ. Хранилище из журнала улик не удаляет ничего. Release нужен
// буферу сборщика: там запись больше не нужна, когда её приняло хранилище.
// Удаляются только целые закрытые сегменты. Сначала на диск ложится нижняя
// граница (файл floor), потом удаляются файлы. Прерванное удаление Open
// доводит до конца, а сегмент ниже границы не считается пропавшим. Всё это —
// только у журнала, открытого с AllowRelease. Журнал улик обязан начинаться
// с позиции 1, а файл floor в нём — порча: иначе подложенный floor удалял бы
// улики при старте.
//
// ОБОРВАННЫЙ ХВОСТ — только в конце последнего сегмента и только если за
// плохой записью нет ни одной целой: целая запись дальше значит порчу
// середины, а за ней подтверждённые улики. Отрезанные байты не
// уничтожаются, а откладываются в файл рядом (seg_….log.torn-<смещение>).
package evlog

import (
	"bufio"
	"encoding/binary"
	"errors"
	"fmt"
	"hash/crc32"
	"io"
	"os"
	"path/filepath"
	"slices"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

const (
	segMagic  = "EVLOG01\n"
	segHeader = len(segMagic) + 8
	frameHead = 8 // u32 длина + u32 CRC

	// MaxRecord — предел одной записи: улика с телом до 1 МиБ плюс заголовок
	// и конверт с запасом. Длина сверх предела при чтении — порча.
	MaxRecord = 4 << 20
	// DefaultSegmentBytes — порог ротации сегмента.
	DefaultSegmentBytes = 64 << 20

	queueLen = 1024

	// floorFile — первая позиция, оставшаяся после Release.
	floorFile = "floor"
)

var (
	ErrClosed = errors.New("evlog: closed")
	// ErrNoRelease — Release у журнала, открытого без AllowRelease.
	ErrNoRelease = errors.New("evlog: this log never releases records")
	ErrCorrupt   = errors.New("evlog: corrupt")
	ErrTooBig    = errors.New("evlog: record too big")
	ErrNoPos     = errors.New("evlog: no such position")
)

var castagnoli = crc32.MakeTable(crc32.Castagnoli)

// Options — настройки журнала.
type Options struct {
	// SegmentBytes — порог ротации; 0 — DefaultSegmentBytes.
	SegmentBytes int64
	// OnCommit зовётся потоком записи после fsync каждой пачки, по порядку
	// позиций и до того, как писатели получат ответ. Сюда движок вешает
	// листья цепи: порядок листьев совпадает с порядком журнала.
	OnCommit func(first uint64, records [][]byte)
	// AllowRelease — журнал может удалять доставленные сегменты (Release) и
	// начинаться не с 1 (файл floor). Только для буфера сборщика.
	AllowRelease bool
}

// Recovery — что журнал нашёл при открытии.
type Recovery struct {
	Records       uint64 // записей в журнале
	Segments      int
	TornTailBytes int64  // отброшенный оборванный хвост последнего сегмента
	TornTailFile  string // куда отложен отрезанный хвост
}

type segment struct {
	first   uint64
	path    string
	offsets []uint32 // смещение каждой записи в файле
	size    int64
}

func (s *segment) end() uint64 { return s.first + uint64(len(s.offsets)) }

type request struct {
	records [][]byte
	done    chan result
}

type result struct {
	first uint64
	err   error
}

// Log — журнал улик.
type Log struct {
	dir      string
	segBytes int64
	onCommit func(uint64, [][]byte)
	release  bool
	recovery Recovery

	mu       sync.RWMutex // segs и failed; запись — только поток журнала
	segs     []*segment
	failed   error
	active   *os.File
	reqs     chan *request
	closing  sync.Once
	stopped  chan struct{}
	sendMu   sync.RWMutex // Append держит RLock, Close — Lock: после Close в канал не пишут
	isClosed bool

	// syncFile — fsync активного сегмента. Поле, а не прямой вызов, чтобы
	// тест мог устроить отказ fsync: иначе правило «ответ только после
	// успешного fsync» нечем проверить.
	syncFile func(*os.File) error

	// Для показателей: пачки, записанные с fsync, и время записи с fsync.
	commits     atomic.Uint64
	commitNanos atomic.Uint64
}

// Stats — сколько пачек записано с fsync и сколько это заняло всего.
type Stats struct {
	Commits     uint64
	CommitNanos uint64
}

// Stats — показатели журнала с открытия.
func (l *Log) Stats() Stats {
	return Stats{Commits: l.commits.Load(), CommitNanos: l.commitNanos.Load()}
}

// Open открывает журнал в каталоге, создавая его при первом запуске. visit,
// если задан, получает каждую запись по порядку: так движок за один проход
// поднимает индекс принятых и досчитывает цепь.
//
// Оборванный хвост последнего сегмента (отказ посреди записи пачки)
// отрезается и откладывается рядом: эти байты никогда не подтверждались.
// Порча в любом другом месте — ErrCorrupt: молча терять подтверждённые улики
// нельзя.
func Open(dir string, opt Options, visit func(pos uint64, data []byte) error) (*Log, error) {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, fmt.Errorf("evlog: %w", err)
	}
	l := &Log{
		dir:      dir,
		segBytes: opt.SegmentBytes,
		onCommit: opt.OnCommit,
		release:  opt.AllowRelease,
		reqs:     make(chan *request, queueLen),
		stopped:  make(chan struct{}),
		syncFile: (*os.File).Sync,
	}
	if l.segBytes <= 0 {
		l.segBytes = DefaultSegmentBytes
	}
	if err := l.recover(visit); err != nil {
		return nil, err
	}
	go l.run()
	return l, nil
}

func (l *Log) recover(visit func(uint64, []byte) error) error {
	firsts, err := listSegments(l.dir)
	if err != nil {
		return err
	}
	floor, err := l.readFloor()
	if err != nil {
		return err
	}
	// Сегменты ниже границы — остаток прерванного Release. Граница обязана
	// быть началом сегмента, который есть, — иначе файл floor не наш, и по
	// нему ничего не удаляется.
	if floor > 1 && len(firsts) > 0 {
		if !slices.Contains(firsts, floor) {
			return fmt.Errorf("%w: %s says the log starts at %d, no segment starts there", ErrCorrupt, floorFile, floor)
		}
		for firsts[0] < floor {
			if err := os.Remove(segPath(l.dir, firsts[0])); err != nil {
				return fmt.Errorf("evlog: %w", err)
			}
			firsts = firsts[1:]
		}
	}
	// Последний сегмент без заголовка — сбой посреди создания сегмента
	// прежней версией (без переименования): записей в нём нет.
	if n := len(firsts); n > 0 {
		p := segPath(l.dir, firsts[n-1])
		if fi, err := os.Stat(p); err == nil && fi.Size() < int64(segHeader) {
			if err := os.Remove(p); err != nil {
				return fmt.Errorf("evlog: %w", err)
			}
			firsts = firsts[:n-1]
		}
	}
	next := floor
	for i, first := range firsts {
		if first != next {
			return fmt.Errorf("%w: segment starts at %d, expected %d", ErrCorrupt, first, next)
		}
		last := i == len(firsts)-1
		seg, torn, aside, err := scanSegment(l.dir, first, last, visit)
		if err != nil {
			return err
		}
		l.recovery.TornTailBytes += torn
		if aside != "" {
			l.recovery.TornTailFile = aside
		}
		l.segs = append(l.segs, seg)
		next = seg.end()
	}
	if len(l.segs) == 0 {
		if err := l.newSegment(floor); err != nil {
			return err
		}
	} else {
		seg := l.segs[len(l.segs)-1]
		f, err := os.OpenFile(seg.path, os.O_WRONLY, 0)
		if err != nil {
			return fmt.Errorf("evlog: %w", err)
		}
		if _, err := f.Seek(seg.size, io.SeekStart); err != nil {
			f.Close()
			return fmt.Errorf("evlog: %w", err)
		}
		l.active = f
	}
	l.recovery.Segments = len(l.segs)
	l.recovery.Records = l.segs[len(l.segs)-1].end() - floor
	return nil
}

// readFloor — первая позиция журнала: из файла floor, без него — 1. Журнал
// без AllowRelease начинается с 1 всегда, а floor в нём — порча.
func (l *Log) readFloor() (uint64, error) {
	data, err := os.ReadFile(filepath.Join(l.dir, floorFile))
	switch {
	case errors.Is(err, os.ErrNotExist):
		return 1, nil
	case err != nil:
		return 0, fmt.Errorf("evlog: %w", err)
	case !l.release:
		return 0, fmt.Errorf("%w: %s file in a log that never releases records", ErrCorrupt, floorFile)
	}
	floor, err := strconv.ParseUint(strings.TrimSpace(string(data)), 10, 64)
	if err != nil || floor == 0 {
		return 0, fmt.Errorf("%w: bad %s file", ErrCorrupt, floorFile)
	}
	return floor, nil
}

// scanSegment читает сегмент целиком. У последнего сегмента оборванный хвост
// отрезается (и откладывается в файл aside), у остальных любая
// неисправность — порча.
func scanSegment(dir string, first uint64, last bool, visit func(uint64, []byte) error) (_ *segment, torn int64, aside string, _ error) {
	path := segPath(dir, first)
	f, err := os.OpenFile(path, os.O_RDWR, 0)
	if err != nil {
		return nil, 0, "", fmt.Errorf("evlog: %w", err)
	}
	defer f.Close()
	st, err := f.Stat()
	if err != nil {
		return nil, 0, "", fmt.Errorf("evlog: %w", err)
	}
	r := bufio.NewReaderSize(f, 1<<20)
	var hdr [segHeader]byte
	if _, err := io.ReadFull(r, hdr[:]); err != nil || string(hdr[:len(segMagic)]) != segMagic ||
		binary.BigEndian.Uint64(hdr[len(segMagic):]) != first {
		return nil, 0, "", fmt.Errorf("%w: %s: bad header", ErrCorrupt, path)
	}
	seg := &segment{first: first, path: path, size: int64(segHeader)}
	for {
		data, n, err := readFrame(r)
		if err == io.EOF {
			break
		}
		if err != nil {
			if !last {
				return nil, 0, "", fmt.Errorf("%w: %s at offset %d: %v", ErrCorrupt, path, seg.size, err)
			}
			// Обрыв пачки бывает только в самом конце: целая запись дальше —
			// порча середины, за которой подтверждённые улики.
			at, found, ferr := findFrame(f, seg.size+1, st.Size())
			if ferr != nil {
				return nil, 0, "", fmt.Errorf("evlog: %w", ferr)
			}
			if found {
				return nil, 0, "", fmt.Errorf("%w: %s at offset %d: %v, and a whole record follows at offset %d: not a torn tail", ErrCorrupt, path, seg.size, err, at)
			}
			if aside, err = setAside(f, path, seg.size, st.Size()); err != nil {
				return nil, 0, "", err
			}
			if err := f.Truncate(seg.size); err != nil {
				return nil, 0, "", fmt.Errorf("evlog: truncate torn tail: %w", err)
			}
			if err := f.Sync(); err != nil {
				return nil, 0, "", fmt.Errorf("evlog: %w", err)
			}
			return seg, st.Size() - seg.size, aside, nil
		}
		pos := seg.end()
		seg.offsets = append(seg.offsets, uint32(seg.size))
		seg.size += int64(n)
		if visit != nil {
			if err := visit(pos, data); err != nil {
				return nil, 0, "", err
			}
		}
	}
	return seg, 0, "", nil
}

// findFrame ищет целую запись (длина в пределах, CRC сходится), которая
// начинается в [from, from+frameHead+MaxRecord): если середина испорчена,
// следующая настоящая запись начинается не дальше. На случай мусора,
// похожего на длины, проверка ограничена объёмом: исчерпав его, findFrame
// отвечает «нашлась» — отказ стартовать безопаснее, чем срезать
// подтверждённое.
func findFrame(f *os.File, from, size int64) (int64, bool, error) {
	end := min(size, from+2*(frameHead+MaxRecord))
	if end-from < frameHead {
		return 0, false, nil
	}
	buf := make([]byte, end-from)
	if _, err := f.ReadAt(buf, from); err != nil && !errors.Is(err, io.EOF) {
		return 0, false, err
	}
	budget := 1 << 30
	for i := 0; i+frameHead <= len(buf) && i < frameHead+MaxRecord; i++ {
		n := int(binary.BigEndian.Uint32(buf[i:]))
		if n == 0 || n > MaxRecord || i+frameHead+n > len(buf) {
			continue
		}
		if budget -= n; budget < 0 {
			return from + int64(i), true, nil
		}
		if crc32.Checksum(buf[i+frameHead:i+frameHead+n], castagnoli) == binary.BigEndian.Uint32(buf[i+4:]) {
			return from + int64(i), true, nil
		}
	}
	return 0, false, nil
}

// setAside откладывает отрезаемый хвост [from, size) в файл рядом с
// сегментом: отрезанное не уничтожается, его можно разобрать.
func setAside(f *os.File, path string, from, size int64) (string, error) {
	buf := make([]byte, size-from)
	if _, err := f.ReadAt(buf, from); err != nil && !errors.Is(err, io.EOF) {
		return "", fmt.Errorf("evlog: read torn tail: %w", err)
	}
	aside := fmt.Sprintf("%s.torn-%d", path, from)
	if err := writeSynced(aside, buf); err != nil {
		return "", fmt.Errorf("evlog: set torn tail aside: %w", err)
	}
	return aside, syncDir(filepath.Dir(path))
}

// readFrame читает одну запись. io.EOF — ровно на границе записи.
func readFrame(r io.Reader) ([]byte, int, error) {
	var h [frameHead]byte
	n, err := io.ReadFull(r, h[:])
	if err == io.EOF && n == 0 {
		return nil, 0, io.EOF
	}
	if err != nil {
		return nil, 0, errors.New("torn frame header")
	}
	size := binary.BigEndian.Uint32(h[:4])
	if size == 0 || size > MaxRecord {
		return nil, 0, fmt.Errorf("bad record length %d", size)
	}
	data := make([]byte, size)
	if _, err := io.ReadFull(r, data); err != nil {
		return nil, 0, errors.New("torn record")
	}
	if crc32.Checksum(data, castagnoli) != binary.BigEndian.Uint32(h[4:]) {
		return nil, 0, errors.New("crc mismatch")
	}
	return data, frameHead + int(size), nil
}

// Recovery — что нашлось при открытии.
func (l *Log) Recovery() Recovery { return l.recovery }

// Append записывает пачку записей и ждёт fsync. Отдаёт позицию первой:
// записи пачки лежат подряд. Вернулся без ошибки — записи на диске.
func (l *Log) Append(records [][]byte) (first uint64, err error) {
	if len(records) == 0 {
		return 0, errors.New("evlog: empty append")
	}
	for _, rec := range records {
		if len(rec) == 0 || len(rec) > MaxRecord {
			return 0, fmt.Errorf("%w: %d bytes", ErrTooBig, len(rec))
		}
	}
	if err := l.Failed(); err != nil {
		return 0, err
	}
	req := &request{records: records, done: make(chan result, 1)}
	l.sendMu.RLock()
	if l.isClosed {
		l.sendMu.RUnlock()
		return 0, ErrClosed
	}
	l.reqs <- req
	l.sendMu.RUnlock()
	res := <-req.done
	return res.first, res.err
}

// run — поток журнала: забирает всё накопившееся и коммитит одной пачкой.
func (l *Log) run() {
	defer close(l.stopped)
	for req := range l.reqs {
		batch := []*request{req}
	drain:
		for {
			select {
			case r, ok := <-l.reqs:
				if !ok {
					break drain
				}
				batch = append(batch, r)
			default:
				break drain
			}
		}
		l.commit(batch)
	}
}

func (l *Log) commit(batch []*request) {
	reply := func(first uint64, err error) {
		for _, r := range batch {
			r.done <- result{first: first, err: err}
			first += uint64(len(r.records))
		}
	}
	if err := l.Failed(); err != nil {
		reply(0, err)
		return
	}
	l.mu.RLock()
	seg := l.segs[len(l.segs)-1]
	l.mu.RUnlock()
	if seg.size >= l.segBytes {
		if err := l.rotate(seg.end()); err != nil {
			l.fail(err)
			reply(0, err)
			return
		}
		l.mu.RLock()
		seg = l.segs[len(l.segs)-1]
		l.mu.RUnlock()
	}

	var all [][]byte
	size := 0
	for _, r := range batch {
		for _, rec := range r.records {
			all = append(all, rec)
			size += frameHead + len(rec)
		}
	}
	buf := make([]byte, 0, size)
	offsets := make([]uint32, 0, len(all))
	off := seg.size
	for _, rec := range all {
		offsets = append(offsets, uint32(off))
		buf = binary.BigEndian.AppendUint32(buf, uint32(len(rec)))
		buf = binary.BigEndian.AppendUint32(buf, crc32.Checksum(rec, castagnoli))
		buf = append(buf, rec...)
		off += int64(frameHead + len(rec))
	}
	start := time.Now()
	if _, err := l.active.Write(buf); err != nil {
		l.fail(fmt.Errorf("evlog: write: %w", err))
		reply(0, l.Failed())
		return
	}
	if err := l.syncFile(l.active); err != nil {
		l.fail(fmt.Errorf("evlog: fsync: %w", err))
		reply(0, l.Failed())
		return
	}
	l.commitNanos.Add(uint64(time.Since(start)))
	l.commits.Add(1)
	first := seg.end()
	l.mu.Lock()
	seg.offsets = append(seg.offsets, offsets...)
	seg.size = off
	l.mu.Unlock()
	if l.onCommit != nil {
		l.onCommit(first, all)
	}
	reply(first, nil)
}

// rotate закрывает текущий сегмент и открывает следующий. Текущий уже
// синхронизирован: ротация бывает только между пачками.
func (l *Log) rotate(first uint64) error {
	if err := l.active.Close(); err != nil {
		return fmt.Errorf("evlog: close segment: %w", err)
	}
	l.active = nil
	return l.newSegment(first)
}

// newSegment заводит сегмент: заголовок пишется во временный файл и только
// потом получает имя сегмента — сбой посреди создания не оставляет сегмента
// без заголовка.
func (l *Log) newSegment(first uint64) error {
	path := segPath(l.dir, first)
	if _, err := os.Stat(path); !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("evlog: new segment %s: exists or unreadable: %v", path, err)
	}
	hdr := append([]byte(segMagic), make([]byte, 8)...)
	binary.BigEndian.PutUint64(hdr[len(segMagic):], first)
	tmp := path + ".tmp"
	if err := writeSynced(tmp, hdr); err != nil {
		os.Remove(tmp)
		return fmt.Errorf("evlog: new segment: %w", err)
	}
	if err := os.Rename(tmp, path); err != nil {
		os.Remove(tmp)
		return fmt.Errorf("evlog: new segment: %w", err)
	}
	if err := syncDir(l.dir); err != nil {
		return err
	}
	f, err := os.OpenFile(path, os.O_WRONLY, 0)
	if err != nil {
		return fmt.Errorf("evlog: new segment: %w", err)
	}
	if _, err := f.Seek(0, io.SeekEnd); err != nil {
		f.Close()
		return fmt.Errorf("evlog: new segment: %w", err)
	}
	l.mu.Lock()
	l.segs = append(l.segs, &segment{first: first, path: path, size: int64(segHeader)})
	l.mu.Unlock()
	l.active = f
	return nil
}

func (l *Log) fail(err error) {
	l.mu.Lock()
	if l.failed == nil {
		l.failed = err
	}
	l.mu.Unlock()
}

// Failed — защёлкнутая ошибка записи. Не nil — журнал больше не пишет, и
// приём обязан отвечать отказом.
func (l *Log) Failed() error {
	l.mu.RLock()
	defer l.mu.RUnlock()
	return l.failed
}

// First — первая позиция, которая ещё есть в журнале (после Release — выше 1).
func (l *Log) First() uint64 {
	l.mu.RLock()
	defer l.mu.RUnlock()
	return l.segs[0].first
}

// Next — позиция, которую получит следующая запись.
func (l *Log) Next() uint64 {
	l.mu.RLock()
	defer l.mu.RUnlock()
	return l.segs[len(l.segs)-1].end()
}

// Read читает запись по позиции и сверяет её CRC.
func (l *Log) Read(pos uint64) ([]byte, error) {
	l.mu.RLock()
	i := sort.Search(len(l.segs), func(i int) bool { return l.segs[i].end() > pos })
	if pos == 0 || i == len(l.segs) || pos < l.segs[i].first {
		l.mu.RUnlock()
		return nil, fmt.Errorf("%w: %d", ErrNoPos, pos)
	}
	seg := l.segs[i]
	off := int64(seg.offsets[pos-seg.first])
	l.mu.RUnlock()

	f, err := os.Open(seg.path)
	if err != nil {
		return nil, fmt.Errorf("evlog: %w", err)
	}
	defer f.Close()
	if _, err := f.Seek(off, io.SeekStart); err != nil {
		return nil, fmt.Errorf("evlog: %w", err)
	}
	data, _, err := readFrame(bufio.NewReader(f))
	if err != nil {
		return nil, fmt.Errorf("%w: position %d: %v", ErrCorrupt, pos, err)
	}
	return data, nil
}

// SegmentInfo — сегмент для копирования наружу.
type SegmentInfo struct {
	Path   string
	First  uint64
	Count  uint64
	Size   int64
	Sealed bool // ротирован и больше не меняется
}

// Segments — все сегменты по порядку; последний ещё дописывается.
func (l *Log) Segments() []SegmentInfo {
	l.mu.RLock()
	defer l.mu.RUnlock()
	out := make([]SegmentInfo, len(l.segs))
	for i, s := range l.segs {
		out[i] = SegmentInfo{
			Path: s.path, First: s.first, Count: uint64(len(s.offsets)),
			Size: s.size, Sealed: i < len(l.segs)-1,
		}
	}
	return out
}

// Release удаляет закрытые сегменты, все записи которых лежат на позициях не
// дальше upTo. Сегмент с последней записью остаётся всегда: по ней буфер
// продолжает после рестарта. Журнал на время записи границы заперт: на
// буфере сборщика это ничего не стоит, а хранилище Release не зовёт.
func (l *Log) Release(upTo uint64) error {
	if !l.release {
		return ErrNoRelease
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	last := l.segs[len(l.segs)-1].end() - 1
	n := 0
	for n < len(l.segs)-1 && l.segs[n].end()-1 <= upTo && l.segs[n].end()-1 < last {
		n++
	}
	if n == 0 {
		return nil
	}
	if err := writeFloor(l.dir, l.segs[n].first); err != nil {
		return err
	}
	// Граница на диске: сегменты ниже неё освобождены, даже если удаление
	// файла сорвётся (его доудалит Open).
	gone := l.segs[:n]
	l.segs = append([]*segment(nil), l.segs[n:]...)
	var errs []error
	for _, s := range gone {
		if err := os.Remove(s.path); err != nil {
			errs = append(errs, fmt.Errorf("evlog: %w", err))
		}
	}
	return errors.Join(errs...)
}

// writeFloor записывает нижнюю границу: временный файл, fsync, переименование,
// fsync каталога.
func writeFloor(dir string, floor uint64) error {
	tmp := filepath.Join(dir, floorFile+".tmp")
	err := writeSynced(tmp, []byte(strconv.FormatUint(floor, 10)+"\n"))
	if err == nil {
		err = os.Rename(tmp, filepath.Join(dir, floorFile))
	}
	if err != nil {
		return fmt.Errorf("evlog: floor: %w", err)
	}
	return syncDir(dir)
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

// Close дожидается записи всех принятых в очередь пачек и закрывает файл.
func (l *Log) Close() error {
	l.closing.Do(func() {
		l.sendMu.Lock()
		l.isClosed = true
		close(l.reqs)
		l.sendMu.Unlock()
	})
	<-l.stopped
	if l.active != nil {
		err := l.active.Close()
		l.active = nil
		return err
	}
	return nil
}

func segPath(dir string, first uint64) string {
	return filepath.Join(dir, fmt.Sprintf("seg_%020d.log", first))
}

func listSegments(dir string) ([]uint64, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, fmt.Errorf("evlog: %w", err)
	}
	var out []uint64
	for _, e := range entries {
		name := e.Name()
		if !strings.HasPrefix(name, "seg_") || !strings.HasSuffix(name, ".log") {
			continue
		}
		n, err := strconv.ParseUint(strings.TrimSuffix(strings.TrimPrefix(name, "seg_"), ".log"), 10, 64)
		if err != nil {
			return nil, fmt.Errorf("%w: unexpected file %s", ErrCorrupt, name)
		}
		out = append(out, n)
	}
	sort.Slice(out, func(i, j int) bool { return out[i] < out[j] })
	return out, nil
}

func syncDir(dir string) error {
	d, err := os.Open(dir)
	if err != nil {
		return fmt.Errorf("evlog: %w", err)
	}
	defer d.Close()
	if err := d.Sync(); err != nil {
		return fmt.Errorf("evlog: dir fsync: %w", err)
	}
	return nil
}
