package store

import (
	"context"
	"errors"
	"os"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Nikolay1994Kaz/evidencestore/internal/proof"
)

// Q-75 (заход 1 нового цикла, 28.10), сквозной путь на
// настоящем коде, без снимков диска. fsync журнала улик отказывает после
// того, как байты записи легли в файл: Ingest отвечает ошибкой и снимает
// запись с учёта «в пути» (release), журнал защёлкнут. Метка после этого
// (keepAnchor раз в час, метка под уничтожение ключа, `evidencestore stamp`)
// ложится в цепь: барьеру ждать больше некого. Перезапуск после починки
// диска поднимает запись из журнала как принятую и догоняет её в цепь — уже
// за токеном этой метки. Сборщик ответа не получил и повторяет запись:
// «duplicate» с обещанием по прежнему времени приёма. Пакет записи не
// проходит («receive time … earlier than T1»), -promise обвиняет честное
// хранилище.
func TestEvlogFsyncFailureStopsStamps(t *testing.T) {
	c := newClock()
	cfg := testConfig(t)
	var fail atomic.Bool
	syncFile := func(f *os.File) error {
		if fail.Load() {
			return errors.New("EIO (судья: отказ fsync)")
		}
		return f.Sync()
	}
	s, err := Open(cfg, Options{Logger: quiet, Now: c.now, NoBackground: true, evlogSync: syncFile})
	if err != nil {
		t.Fatal(err)
	}
	s.tsaLocal.Now = c.now
	mustStamp(t, s)
	ingest(t, s, "abs-core", 1, 1)
	mustStamp(t, s)

	c.add(time.Second)
	fail.Store(true)
	if _, err := s.Ingest("abs-core", []Incoming{{Seq: 2, Body: []byte("abs-core event 2")}}); err == nil {
		t.Fatal("fsync отказал, а запись принята")
	}
	if s.Healthy() == nil {
		t.Fatal("отказ журнала улик не защёлкнут")
	}
	s.chainMu.Lock()
	before, head := len(s.tokens), s.chain.Head().Seq
	s.chainMu.Unlock()
	c.add(10 * time.Minute)
	_, stampErr := s.stampNow(context.Background())
	s.chainMu.Lock()
	after, headAfter := len(s.tokens), s.chain.Head().Seq
	s.chainMu.Unlock()
	t.Logf("после отказа fsync: метка — %v; токенов было %d, стало %d; голова %d → %d", stampErr, before, after, head, headAfter)
	// Ни токена, ни звена хвостов, ни запроса к TSA (судья захода 2).
	if !errors.Is(stampErr, ErrLogFailed) || after != before || headAfter != head {
		t.Errorf("журнал улик отказал, а метка: %v; токенов %d → %d, голова %d → %d", stampErr, before, after, head, headAfter)
	}
	s.Close()

	// Перезапуск после починки диска.
	c.add(time.Minute)
	s2, err := Open(cfg, Options{Logger: quiet, Now: c.now, NoBackground: true})
	if err != nil {
		t.Fatal(err)
	}
	defer s2.Close()
	s2.tsaLocal.Now = c.now
	mustStamp(t, s2)
	dup := ingest(t, s2, "abs-core", 2, 2)
	t.Logf("повтор записи 2: %s", dup[0].Status)
	if dup[0].Promise == nil {
		t.Fatalf("повтор записи 2 без обещания: %+v", dup[0])
	}
	mustStampNow(t, s2)
	b, err := s2.Proof("abs-core", 2, false)
	if err != nil {
		t.Fatal(err)
	}
	r := proof.Verify(b, trustOf(t, s2))
	perr := proof.CheckPromise(*dup[0].Promise, r, b, false)
	for _, ch := range r.Checks {
		if !ch.OK {
			t.Logf("✘ %s — %s", ch.Name, ch.Detail)
		}
	}
	if !r.Valid() || perr != nil {
		t.Fatalf("Q-75: честное хранилище после отказа fsync: пакет записи 2 %s; -promise: %v", r.Verdict(), perr)
	}
}
