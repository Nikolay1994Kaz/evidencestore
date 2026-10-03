package evlog

import (
	"bytes"
	"errors"
	"fmt"
	"os"
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
