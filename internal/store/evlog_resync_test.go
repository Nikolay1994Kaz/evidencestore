package store

import (
	"errors"
	"os"
	"sync/atomic"
	"testing"
	"time"
)

// Q-81 (заход 2 нового цикла, 28.10). Исправление Q-75 опирается на то,
// что перезапуск после отказа fsync поднимает пачку из журнала улик и кладёт
// её в цепь («a batch whose fsync failed may still be on disk, and the
// restart puts it into the chain»). Но «читается после перезапуска» не
// значит «на диске»: в Linux (ext4, xfs) после ошибки обратной записи
// страницы помечаются чистыми и остаются в кэше страниц — новый процесс
// читает их оттуда, а ни один следующий fsync их уже не пишет (fsyncgate,
// PostgreSQL 2018). Хранилище на подъёме этих байтов не переписывает и не
// синхронизирует: кладёт запись в цепь и на повтор сборщика отвечает
// «duplicate» с подписанным обещанием. После перезагрузки хоста на месте
// записи — то, что было на диске (здесь — нули), за ней — записи, принятые
// после перезапуска, и хранилище не стартует; запись, на которую выдано
// обещание и чей лист в цепи, потеряна.
//
// Ядро здесь моделируется: байты пачки лежат в файле, пока «хост» жив, и
// обнуляются при «перезагрузке», если с отказа fsync их никто не записал
// заново и не синхронизировал: после отказа mtime сегмента ставится в
// прошлое, и fsync засчитывается, только если перед ним в файл писали
// (одного fsync без записи на чистых страницах мало — судья).
func TestEvlogFsyncFailureRestartRewrites(t *testing.T) {
	c := newClock()
	cfg := testConfig(t)
	var fail atomic.Bool
	s, err := Open(cfg, Options{Logger: quiet, Now: c.now, NoBackground: true, evlogSync: func(f *os.File) error {
		if fail.Load() {
			return errors.New("EIO (модель: обратная запись не прошла, страницы помечены чистыми)")
		}
		return f.Sync()
	}})
	if err != nil {
		t.Fatal(err)
	}
	s.tsaLocal.Now = c.now
	mustStamp(t, s)
	ingest(t, s, "abs-core", 1, 1)
	mustStamp(t, s)

	segs := s.evlog.Segments()
	segPath := segs[len(segs)-1].Path
	size := func() int64 {
		fi, err := os.Stat(segPath)
		if err != nil {
			t.Fatal(err)
		}
		return fi.Size()
	}
	before := size()
	c.add(time.Second)
	fail.Store(true)
	if _, err := s.Ingest("abs-core", []Incoming{{Seq: 2, Body: []byte("abs-core event 2")}}); err == nil {
		t.Fatal("fsync отказал, а запись принята")
	}
	after := size()
	if after <= before {
		t.Fatalf("байты пачки не легли в файл: %d → %d", before, after)
	}
	s.Close()
	old := time.Date(2000, 1, 1, 0, 0, 0, 0, time.UTC)
	if err := os.Chtimes(segPath, old, old); err != nil {
		t.Fatal(err)
	}

	// Перезапуск процесса (не хоста): кэш страниц цел, пачка читается.
	c.add(time.Minute)
	var syncs atomic.Int64
	s2, err := Open(cfg, Options{Logger: quiet, Now: c.now, NoBackground: true, evlogSync: func(f *os.File) error {
		if fi, err := f.Stat(); err == nil && f.Name() == segPath && !fi.ModTime().Equal(old) {
			syncs.Add(1)
		}
		return f.Sync()
	}})
	if err != nil {
		t.Fatal(err)
	}
	s2.tsaLocal.Now = c.now
	mustStamp(t, s2)
	dup := ingest(t, s2, "abs-core", 2, 2)
	t.Logf("после перезапуска: запись 2 — %s, обещание выдано: %v; fsync переписанного сегмента с подъёма до обещания: %d", dup[0].Status, dup[0].Promise != nil, syncs.Load())
	if dup[0].Status != StatusDuplicate || dup[0].Promise == nil {
		t.Fatalf("повтор записи 2: %+v", dup[0])
	}
	rewritten := syncs.Load() > 0
	// Записи после перезапуска ложатся за ней и синхронизируются — на
	// чистые страницы записи 2 их fsync в Linux не действует.
	c.add(time.Second)
	ingest(t, s2, "abs-core", 3, 3)
	mustStampNow(t, s2)
	s2.Close()

	// Перезагрузка хоста: байтов записи 2 на диске нет, если с отказа fsync
	// их никто не записал заново.
	if !rewritten {
		f, err := os.OpenFile(segPath, os.O_WRONLY, 0)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := f.WriteAt(make([]byte, after-before), before); err != nil {
			t.Fatal(err)
		}
		f.Close()
	}
	s3, err := Open(cfg, Options{Logger: quiet, Now: c.now, NoBackground: true})
	if err == nil {
		s3.Close()
		return
	}
	t.Errorf("Q-81: после перезагрузки хоста хранилище не стартует, запись 2 (обещание выдано после перезапуска, лист в цепи) потеряна: %v", err)
}
