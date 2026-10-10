package evlog

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"testing"
)

func rec(i int) []byte { return []byte(fmt.Sprintf("record-%05d", i)) }

func openLog(t *testing.T, dir string, opt Options, visit func(uint64, []byte) error) *Log {
	t.Helper()
	l, err := Open(dir, opt, visit)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { l.Close() })
	return l
}

func TestAppendReadReopen(t *testing.T) {
	dir := t.TempDir()
	l := openLog(t, dir, Options{}, nil)
	first, err := l.Append([][]byte{rec(1), rec(2)})
	if err != nil || first != 1 {
		t.Fatalf("append: %d, %v", first, err)
	}
	if first, err = l.Append([][]byte{rec(3)}); err != nil || first != 3 {
		t.Fatalf("append: %d, %v", first, err)
	}
	for pos := uint64(1); pos <= 3; pos++ {
		got, err := l.Read(pos)
		if err != nil || !bytes.Equal(got, rec(int(pos))) {
			t.Fatalf("read %d: %q, %v", pos, got, err)
		}
	}
	for _, pos := range []uint64{0, 4} {
		if _, err := l.Read(pos); !errors.Is(err, ErrNoPos) {
			t.Fatalf("read %d: %v", pos, err)
		}
	}
	if err := l.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := l.Append([][]byte{rec(9)}); !errors.Is(err, ErrClosed) {
		t.Fatalf("append после Close: %v", err)
	}

	var seen []uint64
	l2 := openLog(t, dir, Options{}, func(pos uint64, data []byte) error {
		if !bytes.Equal(data, rec(int(pos))) {
			return fmt.Errorf("pos %d: %q", pos, data)
		}
		seen = append(seen, pos)
		return nil
	})
	if len(seen) != 3 || l2.Next() != 4 || l2.Recovery().Records != 3 {
		t.Fatalf("после переоткрытия: seen=%v next=%d", seen, l2.Next())
	}
	if first, err := l2.Append([][]byte{rec(4)}); err != nil || first != 4 {
		t.Fatalf("append после переоткрытия: %d, %v", first, err)
	}
}

// Конкурентные писатели получают непересекающиеся позиции, OnCommit видит
// записи строго по порядку, и каждая запись лежит на своей позиции.
func TestConcurrentAppendsGroupCommit(t *testing.T) {
	var mu sync.Mutex
	var commits int
	next := uint64(1)
	var orderErr error
	opt := Options{OnCommit: func(first uint64, records [][]byte) {
		mu.Lock()
		defer mu.Unlock()
		commits++
		if first != next && orderErr == nil {
			orderErr = fmt.Errorf("пачка с %d, ожидали %d", first, next)
		}
		next = first + uint64(len(records))
	}}
	l := openLog(t, t.TempDir(), opt, nil)
	const writers, each = 16, 50
	got := make([][]uint64, writers)
	var wg sync.WaitGroup
	for w := range writers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := range each {
				pos, err := l.Append([][]byte{[]byte(fmt.Sprintf("w%d-%d", w, i))})
				if err != nil {
					t.Error(err)
					return
				}
				got[w] = append(got[w], pos)
			}
		}()
	}
	wg.Wait()
	if orderErr != nil {
		t.Fatal(orderErr)
	}
	seen := map[uint64]bool{}
	for w, ps := range got {
		for i, pos := range ps {
			if seen[pos] {
				t.Fatalf("позиция %d выдана дважды", pos)
			}
			seen[pos] = true
			data, err := l.Read(pos)
			if err != nil || string(data) != fmt.Sprintf("w%d-%d", w, i) {
				t.Fatalf("pos %d: %q, %v", pos, data, err)
			}
		}
	}
	if l.Next() != writers*each+1 {
		t.Fatalf("next = %d", l.Next())
	}
	t.Logf("%d записей, %d fsync", writers*each, commits)
}

// Ротация: сегменты идут подряд, закрытые помечены, всё читается после
// переоткрытия.
func TestRotation(t *testing.T) {
	dir := t.TempDir()
	l := openLog(t, dir, Options{SegmentBytes: 64}, nil)
	for i := 1; i <= 10; i++ {
		if _, err := l.Append([][]byte{rec(i)}); err != nil {
			t.Fatal(err)
		}
	}
	segs := l.Segments()
	if len(segs) < 3 {
		t.Fatalf("сегментов %d", len(segs))
	}
	var total uint64
	for i, s := range segs {
		if s.First != total+1 || s.Sealed != (i < len(segs)-1) {
			t.Fatalf("сегмент %d: %+v", i, s)
		}
		total += s.Count
	}
	if total != 10 {
		t.Fatalf("записей в сегментах %d", total)
	}
	l.Close()
	l2 := openLog(t, dir, Options{SegmentBytes: 64}, nil)
	for i := 1; i <= 10; i++ {
		if got, err := l2.Read(uint64(i)); err != nil || !bytes.Equal(got, rec(i)) {
			t.Fatalf("read %d: %q, %v", i, got, err)
		}
	}
}

// Оборванный хвост последнего сегмента отрезается при открытии: эти байты
// никогда не подтверждались.
func TestTornTailIsCut(t *testing.T) {
	dir := t.TempDir()
	l := openLog(t, dir, Options{}, nil)
	if _, err := l.Append([][]byte{rec(1), rec(2)}); err != nil {
		t.Fatal(err)
	}
	l.Close()
	path := segPath(dir, 1)
	good, _ := os.ReadFile(path)
	for _, tail := range [][]byte{
		{0, 0},                         // обрывок заголовка записи
		{0, 0, 0, 20, 1, 2, 3, 4, 'x'}, // заголовок есть, тела не хватает
	} {
		if err := os.WriteFile(path, append(bytes.Clone(good), tail...), 0o600); err != nil {
			t.Fatal(err)
		}
		l2, err := Open(dir, Options{}, nil)
		if err != nil {
			t.Fatal(err)
		}
		if r := l2.Recovery(); r.Records != 2 || r.TornTailBytes != int64(len(tail)) {
			t.Fatalf("recovery: %+v", r)
		}
		if st, _ := os.Stat(path); st.Size() != int64(len(good)) {
			t.Fatalf("хвост не отрезан: %d байт вместо %d", st.Size(), len(good))
		}
		if aside, err := os.ReadFile(l2.Recovery().TornTailFile); err != nil || !bytes.Equal(aside, tail) {
			t.Fatalf("отрезанный хвост не отложен: %q, %v", aside, err)
		}
		if first, err := l2.Append([][]byte{rec(3)}); err != nil || first != 3 {
			t.Fatalf("append после обрезки: %d, %v", first, err)
		}
		if got, err := l2.Read(3); err != nil || !bytes.Equal(got, rec(3)) {
			t.Fatalf("read: %q, %v", got, err)
		}
		l2.Close()
		os.WriteFile(path, good, 0o600)
	}
}

// Порча закрытого сегмента — громкая ошибка, а не тихая потеря.
func TestCorruptSealedSegmentIsLoud(t *testing.T) {
	dir := t.TempDir()
	l := openLog(t, dir, Options{SegmentBytes: 64}, nil)
	for i := 1; i <= 6; i++ {
		if _, err := l.Append([][]byte{rec(i)}); err != nil {
			t.Fatal(err)
		}
	}
	l.Close()
	path := segPath(dir, 1)
	data, _ := os.ReadFile(path)
	data[len(data)-1] ^= 1
	os.WriteFile(path, data, 0o600)
	if _, err := Open(dir, Options{SegmentBytes: 64}, nil); !errors.Is(err, ErrCorrupt) {
		t.Fatalf("порча закрытого сегмента: %v", err)
	}
	// Отказ открытия ничего не трогает: испорченный сегмент — тоже улика.
	if after, _ := os.ReadFile(path); !bytes.Equal(after, data) {
		t.Fatal("испорченный закрытый сегмент изменён при открытии")
	}
}

// Пропавший сегмент в середине — тоже порча.
func TestMissingSegmentIsLoud(t *testing.T) {
	dir := t.TempDir()
	l := openLog(t, dir, Options{SegmentBytes: 64}, nil)
	for i := 1; i <= 10; i++ {
		l.Append([][]byte{rec(i)})
	}
	segs := l.Segments()
	l.Close()
	os.Remove(segs[1].Path)
	if _, err := Open(dir, Options{SegmentBytes: 64}, nil); !errors.Is(err, ErrCorrupt) {
		t.Fatalf("пропал сегмент: %v", err)
	}
}

// Первая ошибка записи защёлкивается: ни одному писателю больше не ответят
// «записано».
func TestFailStop(t *testing.T) {
	l := openLog(t, t.TempDir(), Options{}, nil)
	if _, err := l.Append([][]byte{rec(1)}); err != nil {
		t.Fatal(err)
	}
	l.active.Close() // диск «отказал»
	if _, err := l.Append([][]byte{rec(2)}); err == nil {
		t.Fatal("запись прошла на отказавшем диске")
	}
	if l.Failed() == nil {
		t.Fatal("ошибка не защёлкнулась")
	}
	if _, err := l.Append([][]byte{rec(3)}); err == nil {
		t.Fatal("после отказа журнал снова пишет")
	}
	if got, err := l.Read(1); err != nil || !bytes.Equal(got, rec(1)) {
		t.Fatalf("записанное до отказа читается: %q, %v", got, err)
	}
}

// Отказ fsync: писатель получает ошибку, а не «записано», и журнал
// защёлкивается — после неудачного fsync неизвестно, что на диске.
func TestFsyncFailureIsNotAcknowledged(t *testing.T) {
	var calls int
	l := openLog(t, t.TempDir(), Options{OnCommit: func(uint64, [][]byte) { calls++ }}, nil)
	l.syncFile = func(*os.File) error { return errors.New("EIO") }
	if _, err := l.Append([][]byte{rec(1)}); err == nil {
		t.Fatal("запись подтверждена без fsync")
	}
	if calls != 0 {
		t.Fatal("OnCommit позван до успешного fsync")
	}
	l.syncFile = (*os.File).Sync
	if _, err := l.Append([][]byte{rec(2)}); err == nil || l.Failed() == nil {
		t.Fatal("после отказа fsync журнал снова пишет")
	}
	if l.Next() != 1 {
		t.Fatalf("неподтверждённые записи видны: next = %d", l.Next())
	}
}

func TestRecordLimits(t *testing.T) {
	l := openLog(t, t.TempDir(), Options{}, nil)
	for _, bad := range [][][]byte{nil, {{}}, {make([]byte, MaxRecord+1)}} {
		if _, err := l.Append(bad); err == nil {
			t.Fatalf("принята негодная пачка из %d", len(bad))
		}
	}
	if _, err := l.Append([][]byte{make([]byte, MaxRecord)}); err != nil {
		t.Fatalf("запись на пределе: %v", err)
	}
}

// fill пишет записи 1..n по одной: при пороге 64 байта сегменты по 2–3
// записи.
func fill(t *testing.T, l *Log, n int) {
	t.Helper()
	for i := 1; i <= n; i++ {
		if _, err := l.Append([][]byte{rec(i)}); err != nil {
			t.Fatal(err)
		}
	}
}

// Release удаляет сегменты целиком и только те, где всё не дальше upTo;
// после переоткрытия журнал начинается с границы, позиции прежние.
func TestReleaseDropsWholeSegments(t *testing.T) {
	dir := t.TempDir()
	l := openLog(t, dir, Options{SegmentBytes: 64, AllowRelease: true}, nil)
	fill(t, l, 10)
	segs := l.Segments()
	if len(segs) < 4 {
		t.Fatalf("сегментов %d", len(segs))
	}
	// Конец второго сегмента плюс одна запись третьего: третий не весь
	// подтверждён и остаётся.
	upTo := segs[1].First + segs[1].Count
	if err := l.Release(upTo); err != nil {
		t.Fatal(err)
	}
	keep := segs[2].First
	for i, s := range segs {
		_, err := os.Stat(s.Path)
		if gone := errors.Is(err, os.ErrNotExist); gone != (i < 2) {
			t.Fatalf("сегмент %d (с %d): удалён = %v", i, s.First, gone)
		}
	}
	if _, err := l.Read(keep - 1); !errors.Is(err, ErrNoPos) {
		t.Fatalf("освобождённая позиция читается: %v", err)
	}
	if got, err := l.Read(keep); err != nil || !bytes.Equal(got, rec(int(keep))) {
		t.Fatalf("read %d: %q, %v", keep, got, err)
	}
	l.Close()

	var seen []uint64
	l2 := openLog(t, dir, Options{SegmentBytes: 64, AllowRelease: true}, func(pos uint64, data []byte) error {
		if !bytes.Equal(data, rec(int(pos))) {
			return fmt.Errorf("pos %d: %q", pos, data)
		}
		seen = append(seen, pos)
		return nil
	})
	if len(seen) == 0 || seen[0] != keep || seen[len(seen)-1] != 10 || l2.Next() != 11 {
		t.Fatalf("после переоткрытия: seen=%v next=%d", seen, l2.Next())
	}
	if first, err := l2.Append([][]byte{rec(11)}); err != nil || first != 11 {
		t.Fatalf("append: %d, %v", first, err)
	}
}

// Сегмент с последней записью не удаляется, даже когда всё подтверждено и
// за ним уже открыт пустой сегмент (ротация, затем падение до записи).
func TestReleaseKeepsLastRecord(t *testing.T) {
	dir := t.TempDir()
	l := openLog(t, dir, Options{SegmentBytes: 64, AllowRelease: true}, nil)
	fill(t, l, 10)
	l.Close()
	hdr := append([]byte(segMagic), 0, 0, 0, 0, 0, 0, 0, 11)
	if err := os.WriteFile(segPath(dir, 11), hdr, 0o600); err != nil {
		t.Fatal(err)
	}
	l2 := openLog(t, dir, Options{SegmentBytes: 64, AllowRelease: true}, nil)
	if err := l2.Release(10); err != nil {
		t.Fatal(err)
	}
	if got, err := l2.Read(10); err != nil || !bytes.Equal(got, rec(10)) {
		t.Fatalf("последняя запись: %q, %v", got, err)
	}
	if _, err := l2.Read(1); !errors.Is(err, ErrNoPos) {
		t.Fatalf("подтверждённое не освобождено: %v", err)
	}
}

// Прерванный Release: граница на диске, файл сегмента ниже неё ещё лежит.
// Open доводит удаление до конца, записи ниже границы не видны.
func TestInterruptedReleaseFinishedOnOpen(t *testing.T) {
	dir := t.TempDir()
	l := openLog(t, dir, Options{SegmentBytes: 64, AllowRelease: true}, nil)
	fill(t, l, 10)
	first := l.Segments()[0]
	saved, err := os.ReadFile(first.Path)
	if err != nil {
		t.Fatal(err)
	}
	if err := l.Release(first.Count); err != nil {
		t.Fatal(err)
	}
	l.Close()
	if err := os.WriteFile(first.Path, saved, 0o600); err != nil { // удаление «не дошло до диска»
		t.Fatal(err)
	}
	var low []uint64
	openLog(t, dir, Options{SegmentBytes: 64, AllowRelease: true}, func(pos uint64, _ []byte) error {
		if pos <= first.Count {
			low = append(low, pos)
		}
		return nil
	})
	if len(low) != 0 {
		t.Fatalf("видны освобождённые позиции %v", low)
	}
	if _, err := os.Stat(first.Path); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("сегмент ниже границы не удалён: %v", err)
	}
}

// Без файла границы журнал начинается с 1: пропавший первый сегмент журнала
// улик — порча, а не освобождение.
func TestMissingFirstSegmentIsLoud(t *testing.T) {
	dir := t.TempDir()
	l := openLog(t, dir, Options{SegmentBytes: 64}, nil)
	fill(t, l, 10)
	segs := l.Segments()
	l.Close()
	os.Remove(segs[0].Path)
	if _, err := Open(dir, Options{SegmentBytes: 64}, nil); !errors.Is(err, ErrCorrupt) {
		t.Fatalf("пропал первый сегмент: %v", err)
	}
}

// ⭐ Файл floor в журнале улик — порча, а не граница: подложенный floor не
// удаляет улики при старте (журнал улик Release не зовёт никогда).
func TestFloorRefusedWithoutAllowRelease(t *testing.T) {
	dir := t.TempDir()
	l := openLog(t, dir, Options{SegmentBytes: 64}, nil)
	fill(t, l, 10)
	if err := l.Release(5); !errors.Is(err, ErrNoRelease) {
		t.Fatalf("Release у журнала улик: %v", err)
	}
	segs := l.Segments()
	l.Close()
	if err := os.WriteFile(filepath.Join(dir, floorFile), []byte("4\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Open(dir, Options{SegmentBytes: 64}, nil); !errors.Is(err, ErrCorrupt) {
		t.Fatalf("floor в журнале улик: %v", err)
	}
	for _, s := range segs {
		if _, err := os.Stat(s.Path); err != nil {
			t.Fatalf("сегмент с %d удалён: %v", s.First, err)
		}
	}
}

// Граница, которая не совпадает с началом ни одного сегмента, — порча, и по
// ней ничего не удаляется.
func TestFloorMustStartASegment(t *testing.T) {
	dir := t.TempDir()
	l := openLog(t, dir, Options{SegmentBytes: 64, AllowRelease: true}, nil)
	fill(t, l, 10)
	segs := l.Segments()
	l.Close()
	if err := os.WriteFile(filepath.Join(dir, floorFile), []byte("5\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Open(dir, Options{SegmentBytes: 64, AllowRelease: true}, nil); !errors.Is(err, ErrCorrupt) {
		t.Fatalf("граница посреди сегмента: %v", err)
	}
	for _, s := range segs {
		if _, err := os.Stat(s.Path); err != nil {
			t.Fatalf("сегмент с %d удалён: %v", s.First, err)
		}
	}
}

// ⭐ Испорчена запись в середине последнего сегмента, за ней целые: это не
// оборванный хвост. Открытие отказывает и ничего не режет (раньше один бит
// стирал все подтверждённые записи после него).
func TestCorruptionInLastSegmentIsNotCut(t *testing.T) {
	dir := t.TempDir()
	l := openLog(t, dir, Options{}, nil)
	fill(t, l, 10)
	l.Close()
	path := segPath(dir, 1)
	data, _ := os.ReadFile(path)
	bad := bytes.Clone(data)
	bad[segHeader+3*(frameHead+len(rec(1)))+frameHead+2] ^= 1 // тело четвёртой записи
	if err := os.WriteFile(path, bad, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Open(dir, Options{}, nil); !errors.Is(err, ErrCorrupt) {
		t.Fatalf("порча середины последнего сегмента: %v", err)
	}
	if after, _ := os.ReadFile(path); !bytes.Equal(after, bad) {
		t.Fatalf("сегмент изменён: %d байт, было %d", len(after), len(bad))
	}
}

// Сбой посреди создания сегмента старой версией: последний сегмент без
// заголовка. Записей в нём нет — он убирается, журнал открывается (раньше —
// отказ «bad header» и ручная правка). Так и с самым первым сегментом.
func TestHeaderlessLastSegmentRecovered(t *testing.T) {
	dir := t.TempDir()
	l := openLog(t, dir, Options{SegmentBytes: 64}, nil)
	fill(t, l, 10)
	next := l.Next()
	l.Close()
	if err := os.WriteFile(segPath(dir, next), []byte("EVLO"), 0o600); err != nil {
		t.Fatal(err)
	}
	l2 := openLog(t, dir, Options{SegmentBytes: 64}, nil)
	if l2.Next() != next {
		t.Fatalf("next %d, ожидали %d", l2.Next(), next)
	}
	if first, err := l2.Append([][]byte{rec(int(next))}); err != nil || first != next {
		t.Fatalf("append: %d, %v", first, err)
	}

	fresh := t.TempDir()
	if err := os.WriteFile(segPath(fresh, 1), nil, 0o600); err != nil {
		t.Fatal(err)
	}
	l3 := openLog(t, fresh, Options{}, nil)
	if first, err := l3.Append([][]byte{rec(1)}); err != nil || first != 1 {
		t.Fatalf("append в пустой журнал: %d, %v", first, err)
	}
}
