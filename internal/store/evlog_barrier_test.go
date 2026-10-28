package store

import (
	"context"
	"errors"
	"os"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// E2 (заход 2 нового цикла, 28.10). TestEvlogFsyncFailureStopsStamps ловит только отказ,
// случившийся до метки: проверка s.evlog.Failed(), перенесённая до барьера
// (до landed), его тоже проходит. Здесь fsync пачки висит, пока метка ждёт
// запись в барьере, и отказывает уже после снимка: запись снимается с учёта
// «в пути» отказом посреди ожидания, и токен обязан не лечь. Убивает
// мутацию «проверка отказа журнала до барьера».
func TestEvlogFailsWhileStampWaits(t *testing.T) {
	c := newClock()
	cfg := testConfig(t)
	block := make(chan error)
	entered := make(chan struct{}, 1)
	var armed atomic.Bool
	s, err := Open(cfg, Options{Logger: quiet, Now: c.now, NoBackground: true, evlogSync: func(f *os.File) error {
		if armed.Load() {
			entered <- struct{}{}
			return <-block
		}
		return f.Sync()
	}})
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	s.tsaLocal.Now = c.now
	mustStamp(t, s)
	ingest(t, s, "abs-core", 1, 1)
	mustStamp(t, s)

	c.add(time.Second)
	armed.Store(true)
	ingestErr := make(chan error, 1)
	go func() {
		_, err := s.Ingest("abs-core", []Incoming{{Seq: 2, Body: []byte("abs-core event 2")}})
		ingestErr <- err
	}()
	<-entered // байты записи 2 в файле, fsync висит: запись в пути
	armed.Store(false)
	s.chainMu.Lock()
	before := len(s.tokens)
	s.chainMu.Unlock()
	stampErr := make(chan error, 1)
	go func() {
		_, err := s.stampNow(context.Background())
		stampErr <- err
	}()
	// Метка сняла записи в пути и ждёт их (барьер).
	for deadline := time.Now().Add(5 * time.Second); ; {
		s.mu.Lock()
		paused := s.stampPause != nil
		s.mu.Unlock()
		if paused {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("метка не дошла до барьера")
		}
		time.Sleep(time.Millisecond)
	}
	block <- errors.New("EIO (отказ fsync посреди барьера)")
	if err := <-ingestErr; err == nil {
		t.Fatal("fsync отказал, а запись принята")
	}
	err = <-stampErr
	s.chainMu.Lock()
	after := len(s.tokens)
	s.chainMu.Unlock()
	t.Logf("метка: %v; токенов было %d, стало %d", err, before, after)
	if err == nil || !strings.Contains(err.Error(), "evidence log failed") || after != before {
		t.Errorf("отказ журнала улик посреди барьера: токен лёг (метка: %v)", err)
	}
}
