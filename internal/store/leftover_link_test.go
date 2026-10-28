package store

import (
	"errors"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Nikolay1994Kaz/evidencestore/internal/proof"
)

// Q-73 (заход 28.10, третий): мутация X41 — остатки с диска не своим
// звеном, а вместе с первым звеном догона. Падение между fsync листьев и
// звена (лист записи 2 на диске без звена), а запись 3 уже в журнале улик,
// но не в цепи (её лист ждал chainMu, пока звено не записалось), и взяла
// время приёма на 70 с позже записи 2 (звено стояло: fsync цепи висел).
// Остатки своим звеном — время звена записи 2 её собственное; вместе с
// догоном — время записи 3, позже срока записи 2.
func TestLeftoverOwnLinkBeforeCatchUp(t *testing.T) {
	truth := newClock()
	var mono atomic.Int64
	mono.Store(int64(1000 * time.Hour))
	advance := func(d time.Duration) {
		truth.add(d)
		mono.Add(int64(d))
	}
	monoF := func() time.Duration { return time.Duration(mono.Load()) }
	cfg := testConfig(t)
	s, err := Open(cfg, Options{Logger: quiet, Now: truth.now, NoBackground: true, Mono: monoF})
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	s.tsaLocal.Now = truth.now
	mustStamp(t, s) // T1
	ingest(t, s, "abs-core", 1, 1)
	if err := s.flush(); err != nil {
		t.Fatal(err)
	}
	res := ingest(t, s, "abs-core", 2, 2) // лист в памяти
	s.chainMu.Lock()
	advance(70 * time.Second)
	done := make(chan error, 1)
	go func() {
		_, err := s.Ingest("abs-core", []Incoming{{Seq: 3, Body: []byte("abs-core event 3")}})
		done <- err
	}()
	time.Sleep(300 * time.Millisecond) // запись 3 — в журнале улик, лист ждёт chainMu
	s.chain.SetBeforeWrite(func(phase string) error {
		if phase == "link" {
			return errors.New("crash (test)")
		}
		return nil
	})
	if err := s.flushLocked(); err == nil {
		t.Fatal("звено записалось")
	}
	crashed := copyDirs(t, cfg)
	s.chain.SetBeforeWrite(nil)
	s.chainMu.Unlock()
	<-done

	advance(time.Minute)
	s2, err := Open(crashed, Options{Logger: quiet, Now: truth.now, NoBackground: true, Mono: monoF})
	if err != nil {
		t.Fatal(err)
	}
	defer s2.Close()
	s2.tsaLocal.Now = truth.now
	catchUpLinks(t, s2, "abs-core", 2, 3)
	mustStamp(t, s2)
	if _, err := s2.Proof("abs-core", 3, false); err != nil {
		t.Fatalf("запись 3 не догнана: %v", err)
	}
	b, err := s2.Proof("abs-core", 2, false)
	if err != nil {
		t.Fatal(err)
	}
	r := proof.Verify(b, trustOf(t, s2))
	for _, l := range b.Links {
		t.Logf("link %d at %s", l.Seq, time.Unix(0, l.UnixNano).UTC().Format("15:04:05.000"))
	}
	if err := checkBoth(t, s2, *res[0].Promise, r, b); err != nil || !r.Valid() {
		t.Fatalf("запись 2: пакет %s; обещание: %v", r.Verdict(), err)
	}
}
