package store

import (
	"context"
	"errors"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Nikolay1994Kaz/evidencestore/internal/auditchain"
	"github.com/Nikolay1994Kaz/evidencestore/internal/proof"
)

// Q-70 (заход 28.10, третий): отложенная перестановка якоря (pending) не
// снимается, когда якорь уже переставила обычная метка. Запись A в пути
// дольше reanchorWait при метке №1 (пауза ВМ 5 с, ответ TSA 29 с с подписью в
// конце) — перестановка отложена по ответу gen1. Метка №2 (ответ 2 с, подпись
// в начале) потери хода уже не видит (разрыв у границы clockLost), A ложится
// на её барьере, токен и якорь — по gen2, приём открыт. Ответ gen1 остаётся в
// s.pending, и следующий шаг keepAnchor (finishReanchor) ставит якорь по нему
// — без паузы приёма и барьера. Нижний край окна у gen1 выше на весь ответ
// (29 с): при часах хоста позади шкала скачет вперёд, пока запись R в пути, и
// честное обещание R «нарушается».
func TestStalePendingAnchorKeepsPromise(t *testing.T) {
	saved := reanchorWait
	reanchorWait = 300 * time.Millisecond
	defer func() { reanchorWait = saved }()
	truth := newClock()
	var mono atomic.Int64
	mono.Store(int64(1000 * time.Hour))
	advance := func(real, monoD time.Duration) {
		truth.add(real)
		mono.Add(int64(monoD))
	}
	host := func() time.Time { return truth.now().Add(-2 * time.Minute) } // часы хоста позади
	s, err := Open(testConfig(t), Options{Logger: quiet, Now: host, NoBackground: true, Mono: func() time.Duration { return time.Duration(mono.Load()) }})
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	s.tsaLocal.Now = truth.now
	ingest(t, s, "abs-core", 1, 1)
	mustStamp(t, s) // якорь, ответ мгновенный
	s.needAnchor = true
	advance(time.Minute, time.Minute)
	advance(5*time.Second, 0) // пауза ВМ 5 с: монотонные часы стояли

	inflight := func(seq uint64) bool {
		s.mu.Lock()
		defer s.mu.Unlock()
		return s.sources["abs-core"].inflight[seq]
	}
	hold := func(seq uint64) chan []Result {
		done := make(chan []Result, 1)
		s.scopeMu.Lock()
		go func() {
			res, err := s.Ingest("abs-core", []Incoming{{Seq: seq, Body: []byte("abs-core event")}})
			if err != nil {
				t.Error(err)
			}
			done <- res
		}()
		for !inflight(seq) {
			time.Sleep(time.Millisecond)
		}
		return done
	}

	// Метка №1: A в пути всю метку; ответ 29 с, подпись в конце.
	doneA := hold(2)
	s.tsaLocal.Now = func() time.Time {
		advance(29*time.Second, 29*time.Second)
		return truth.now()
	}
	if _, err := s.StampNow(context.Background()); !errors.Is(err, errReanchorPending) {
		t.Fatalf("метка №1: %v", err)
	}
	advance(10*time.Second, 10*time.Second) // шаг keepAnchor

	// Метка №2: ответ 2 с, подпись в начале; A ложится, пока метка её ждёт.
	s.tsaLocal.Now = func() time.Time {
		g := truth.now()
		advance(2*time.Second, 2*time.Second)
		go func() {
			time.Sleep(20 * time.Millisecond)
			s.scopeMu.Unlock()
		}()
		return g
	}
	if _, err := s.StampNow(context.Background()); err != nil {
		t.Fatalf("метка №2: %v", err)
	}
	s.tsaLocal.Now = truth.now
	<-doneA
	stale := s.pending != nil
	t.Logf("после метки №2: pending=%v reanchoring=%v", stale, s.reanchoring)

	// Запись R берёт время приёма по якорю gen2 и стоит в пути 35 с (обещано 60).
	doneR := hold(3)
	advance(5*time.Second, 5*time.Second)
	s.stampMu.Lock() // шаг keepAnchor
	finished := s.finishReanchor()
	s.stampMu.Unlock()
	t.Logf("finishReanchor на шаге keepAnchor: %v", finished)
	advance(30*time.Second, 30*time.Second)
	s.appendJSONEvent(auditchain.EventSilence, "pipelock", "", map[string]any{"since": truth.now().UTC(), "expect_every": "10s"})
	if err := s.flush(); err != nil {
		t.Fatal(err)
	}
	s.scopeMu.Unlock()
	res := <-doneR
	if err := s.flush(); err != nil {
		t.Fatal(err)
	}
	advance(time.Minute, time.Minute)
	ingest(t, s, "abs-core", 4, 4)
	mustStamp(t, s)
	b, err := s.Proof("abs-core", 3, false)
	if err != nil {
		t.Fatal(err)
	}
	r := proof.Verify(b, trustOf(t, s))
	p := *res[0].Promise
	if err := checkBoth(t, s, p, r, b); err != nil || !r.Valid() {
		t.Fatalf("запись 3 в пути 35 с (обещано 60): пакет %s; обещание: %v", r.Verdict(), err)
	}
}

// Q-71 (заход 28.10, третий): предел шкалы (scaleLocked) отсчитывается от её
// прежнего наибольшего значения, а не от времени приёма записи в пути. Часы
// хоста позади на 2 минуты (время приёма — у нижнего края окна). Метка A
// отвечала 29 с с подписью в конце — нижний край её окна выше на весь ответ;
// хвосты метки B (мгновенный ответ) подняли шкалу по окну A, а нижний край
// окна B ниже на 29 с. Запись R приходит сразу после B, источник молчал
// дольше 29 с — её время приёма на 29 с ниже шкалы. Пока она в пути (32 с,
// обещано 60), NTP шагает часы хоста к истине: шкала идёт от своего
// прежнего наибольшего значения, и событие ложится на 29 + 32 с позже
// времени приёма R — обещание «нарушено». Класс Q-66 не закрыт.
func TestScaleBelowRecordStepKeepsPromise(t *testing.T) {
	saved := reanchorWait
	reanchorWait = 300 * time.Millisecond
	defer func() { reanchorWait = saved }()
	truth := newClock()
	var mono atomic.Int64
	mono.Store(int64(1000 * time.Hour))
	advance := func(d time.Duration) {
		truth.add(d)
		mono.Add(int64(d))
	}
	var off atomic.Int64
	off.Store(int64(-2 * time.Minute))
	host := func() time.Time { return truth.now().Add(time.Duration(off.Load())) }
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

	// Метка A: ответ 29 с, подпись в конце.
	ingest(t, s, "abs-core", 2, 2)
	s.tsaLocal.Now = func() time.Time {
		advance(29 * time.Second)
		return truth.now()
	}
	mustStampNow(t, s)
	s.tsaLocal.Now = truth.now
	ingest(t, s, "abs-core", 3, 3)
	if err := s.flush(); err != nil {
		t.Fatal(err)
	}
	advance(40 * time.Second) // источник молчит

	// Метка B: ответ мгновенный; её хвосты — по окну A.
	mustStampNow(t, s)

	// Запись R — сразу после B, в пути 32 с.
	s.scopeMu.Lock()
	done := make(chan []Result, 1)
	go func() {
		res, err := s.Ingest("abs-core", []Incoming{{Seq: 4, Body: []byte("abs-core event 4")}})
		if err != nil {
			t.Error(err)
		}
		done <- res
	}()
	for {
		s.mu.Lock()
		taken := s.sources["abs-core"].inflight[4]
		s.mu.Unlock()
		if taken {
			break
		}
		time.Sleep(time.Millisecond)
	}
	advance(2 * time.Second)
	off.Store(0) // NTP шагнул часы хоста к истине
	advance(30 * time.Second)
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
	ingest(t, s, "abs-core", 5, 5)
	mustStamp(t, s)
	b, err := s.Proof("abs-core", 4, false)
	if err != nil {
		t.Fatal(err)
	}
	r := proof.Verify(b, trustOf(t, s))
	if err := checkBoth(t, s, *res[0].Promise, r, b); err != nil || !r.Valid() {
		t.Fatalf("запись 4 в пути 32 с (обещано 60): пакет %s; обещание: %v", r.Verdict(), err)
	}
}
