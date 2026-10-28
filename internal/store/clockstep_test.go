package store

import (
	"sync/atomic"
	"testing"
	"time"

	"github.com/Nikolay1994Kaz/evidencestore/internal/auditchain"
	"github.com/Nikolay1994Kaz/evidencestore/internal/proof"
)

// Q-71 (заход 28.10, третий): шкала помнит прежнее высокое время. Часы хоста
// верны — лист события ложится у нижнего края оценки TSA (lo), шкала там.
// Часы хоста шагают назад (на минуту и больше): время приёма новой записи —
// у нижнего края окна (floor = hi − 55 с), шкала не трогается (оно ниже
// неё). Пока запись в пути, часы хоста шагают обратно вперёд (NTP), и лист
// события получает lo сразу: предел шкалы — прежнее время шкалы плюс ход
// монотонных часов от него, а не от времени приёма записи в пути. Скачок —
// до 54 с; запись в пути 8 с — и -promise обвиняет честное хранилище.
func TestHostClockStepBackForwardKeepsPromise(t *testing.T) {
	truth := newClock()
	var mono atomic.Int64
	mono.Store(int64(1000 * time.Hour))
	advance := func(d time.Duration) {
		truth.add(d)
		mono.Add(int64(d))
	}
	var lag atomic.Int64 // часы хоста = истина − lag
	host := func() time.Time { return truth.now().Add(-time.Duration(lag.Load())) }
	s, err := Open(testConfig(t), Options{Logger: quiet, Now: host, NoBackground: true, Mono: func() time.Duration { return time.Duration(mono.Load()) }})
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	s.tsaLocal.Now = truth.now
	ingest(t, s, "abs-core", 1, 1)
	mustStamp(t, s)
	s.needAnchor = true
	advance(time.Minute)
	// Часы хоста верны: событие (молчание, связь, пропуск другого
	// источника…) — у lo, шкала там.
	s.appendJSONEvent(auditchain.EventSilence, "pipelock", "", map[string]any{"since": truth.now().UTC(), "expect_every": "10s"})
	// Часы хоста шагнули назад на 2 минуты.
	lag.Store(int64(2 * time.Minute))
	advance(time.Second)

	s.scopeMu.Lock() // запись 2 взяла время приёма (у нижнего края окна) и стоит
	done := make(chan []Result, 1)
	go func() {
		res, err := s.Ingest("abs-core", []Incoming{{Seq: 2, Body: []byte("abs-core event 2")}})
		if err != nil {
			t.Error(err)
		}
		done <- res
	}()
	for {
		s.mu.Lock()
		taken := s.sources["abs-core"].inflight[2]
		s.mu.Unlock()
		if taken {
			break
		}
		time.Sleep(time.Millisecond)
	}
	advance(8 * time.Second)
	lag.Store(0) // NTP шагнул часы хоста обратно к настоящему
	s.appendJSONEvent(auditchain.EventSilence, "pipelock", "", map[string]any{"since": truth.now().UTC(), "expect_every": "10s"})
	if err := s.flush(); err != nil {
		t.Fatal(err)
	}
	s.scopeMu.Unlock()
	res := <-done
	if err := s.flush(); err != nil {
		t.Fatal(err)
	}
	advance(time.Minute)
	ingest(t, s, "abs-core", 3, 3)
	mustStamp(t, s)
	b, err := s.Proof("abs-core", 2, false)
	if err != nil {
		t.Fatal(err)
	}
	r := proof.Verify(b, trustOf(t, s))
	p := *res[0].Promise
	t.Logf("время приёма записи 2: %s (истина при приёме %s)", time.Unix(0, p.ReceivedAt).UTC().Format("15:04:05.000"), truth.now().Add(-8*time.Second-time.Minute).UTC().Format("15:04:05.000"))
	if err := checkBoth(t, s, p, r, b); err != nil || !r.Valid() {
		t.Fatalf("запись 2: пакет %s; обещание: %v", r.Verdict(), err)
	}
}
