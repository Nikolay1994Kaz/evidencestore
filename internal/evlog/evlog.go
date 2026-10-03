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
	"sort"
	"strconv"
	"strings"
	"sync"
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
)

var (
	ErrClosed  = errors.New("evlog: closed")
	ErrCorrupt = errors.New("evlog: corrupt")
	ErrTooBig  = errors.New("evlog: record too big")
	ErrNoPos   = errors.New("evlog: no such position")
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
}

// Recovery — что журнал нашёл при открытии.
type Recovery struct {
	Records       uint64 // записей в журнале
	Segments      int
	TornTailBytes int64 // отброшенный оборванный хвост последнего сегмента
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
}

// Open открывает журнал в каталоге, создавая его при первом запуске. visit,
// если задан, получает каждую запись по порядку: так движок за один проход
// поднимает индекс принятых и досчитывает цепь.
//
// Оборванный хвост последнего сегмента (отказ посреди записи пачки)
// отрезается: эти байты никогда не подтверждались. Порча в любом другом месте —
// ErrCorrupt: молча терять подтверждённые улики нельзя.
func Open(dir string, opt Options, visit func(pos uint64, data []byte) error) (*Log, error) {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, fmt.Errorf("evlog: %w", err)
	}
	l := &Log{
		dir:      dir,
		segBytes: opt.SegmentBytes,
		onCommit: opt.OnCommit,
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
	next := uint64(1)
	for i, first := range firsts {
		if first != next {
			return fmt.Errorf("%w: segment starts at %d, expected %d", ErrCorrupt, first, next)
		}
		last := i == len(firsts)-1
		seg, torn, err := scanSegment(l.dir, first, last, visit)
		if err != nil {
			return err
		}
		l.recovery.TornTailBytes += torn
		l.segs = append(l.segs, seg)
		next = seg.end()
	}
	if len(l.segs) == 0 {
		if err := l.newSegment(1); err != nil {
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
	l.recovery.Records = l.segs[len(l.segs)-1].end() - 1
	return nil
}

// scanSegment читает сегмент целиком. У последнего сегмента оборванный хвост
// отрезается, у остальных любая неисправность — порча.
func scanSegment(dir string, first uint64, last bool, visit func(uint64, []byte) error) (*segment, int64, error) {
	path := segPath(dir, first)
	f, err := os.OpenFile(path, os.O_RDWR, 0)
	if err != nil {
		return nil, 0, fmt.Errorf("evlog: %w", err)
	}
	defer f.Close()
	st, err := f.Stat()
	if err != nil {
		return nil, 0, fmt.Errorf("evlog: %w", err)
	}
	r := bufio.NewReaderSize(f, 1<<20)
	var hdr [segHeader]byte
	if _, err := io.ReadFull(r, hdr[:]); err != nil || string(hdr[:len(segMagic)]) != segMagic ||
		binary.BigEndian.Uint64(hdr[len(segMagic):]) != first {
		return nil, 0, fmt.Errorf("%w: %s: bad header", ErrCorrupt, path)
	}
	seg := &segment{first: first, path: path, size: int64(segHeader)}
	for {
		data, n, err := readFrame(r)
		if err == io.EOF {
			break
		}
		if err != nil {
			if !last {
				return nil, 0, fmt.Errorf("%w: %s at offset %d: %v", ErrCorrupt, path, seg.size, err)
			}
			torn := st.Size() - seg.size
			if err := f.Truncate(seg.size); err != nil {
				return nil, 0, fmt.Errorf("evlog: truncate torn tail: %w", err)
			}
			if err := f.Sync(); err != nil {
				return nil, 0, fmt.Errorf("evlog: %w", err)
			}
			return seg, torn, nil
		}
		pos := seg.end()
		seg.offsets = append(seg.offsets, uint32(seg.size))
		seg.size += int64(n)
		if visit != nil {
			if err := visit(pos, data); err != nil {
				return nil, 0, err
			}
		}
	}
	return seg, 0, nil
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

func (l *Log) newSegment(first uint64) error {
	path := segPath(l.dir, first)
	f, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		return fmt.Errorf("evlog: new segment: %w", err)
	}
	hdr := append([]byte(segMagic), make([]byte, 8)...)
	binary.BigEndian.PutUint64(hdr[len(segMagic):], first)
	if _, err := f.Write(hdr); err != nil {
		f.Close()
		return fmt.Errorf("evlog: new segment: %w", err)
	}
	if err := f.Sync(); err != nil {
		f.Close()
		return fmt.Errorf("evlog: new segment: %w", err)
	}
	if err := syncDir(l.dir); err != nil {
		f.Close()
		return err
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
