package evlog

import (
	"bytes"
	"encoding/binary"
	"os"
	"sync/atomic"
	"testing"
)

// Resync (Q-81): записи хвоста последнего сегмента переписываются теми же
// байтами и синхронизируются; байты файла не меняются. Последний сегмент
// пуст (падение сразу после ротации), а хвост начинается в прежнем — Resync
// не падает и ничего не пишет: прежний сегмент закрыт после успешного fsync.
func TestResync(t *testing.T) {
	dir := t.TempDir()
	l, err := Open(dir, Options{SegmentBytes: 64}, nil)
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 3; i++ {
		if _, err := l.Append([][]byte{bytes.Repeat([]byte{byte('a' + i)}, 40)}); err != nil {
			t.Fatal(err)
		}
	}
	if err := l.Close(); err != nil {
		t.Fatal(err)
	}
	firsts, err := listSegments(dir)
	if err != nil || len(firsts) < 2 {
		t.Fatalf("сегменты: %v, %v", firsts, err)
	}
	last := segPath(dir, firsts[len(firsts)-1])
	before, err := os.ReadFile(last)
	if err != nil {
		t.Fatal(err)
	}

	var syncs atomic.Int64
	sync := func(f *os.File) error { syncs.Add(1); return f.Sync() }
	l, err = Open(dir, Options{SegmentBytes: 64, SyncFile: sync}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := l.Resync(1); err != nil {
		t.Fatal(err)
	}
	after, err := os.ReadFile(last)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(before, after) || syncs.Load() != 1 {
		t.Fatalf("Resync: байты изменились: %v, fsync: %d", !bytes.Equal(before, after), syncs.Load())
	}
	next := l.Next()
	if err := l.Close(); err != nil {
		t.Fatal(err)
	}

	// Падение сразу после ротации: последний сегмент — только заголовок.
	hdr := append([]byte(segMagic), make([]byte, 8)...)
	binary.BigEndian.PutUint64(hdr[len(segMagic):], next)
	if err := os.WriteFile(segPath(dir, next), hdr, 0o600); err != nil {
		t.Fatal(err)
	}
	syncs.Store(0)
	l, err = Open(dir, Options{SegmentBytes: 64, SyncFile: sync}, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	if err := l.Resync(1); err != nil || syncs.Load() != 0 {
		t.Fatalf("Resync при пустом последнем сегменте: %v, fsync: %d", err, syncs.Load())
	}
}
