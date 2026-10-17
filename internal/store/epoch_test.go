package store

import (
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"sync"
	"testing"

	"github.com/Nikolay1994Kaz/evidencestore/internal/auditchain"
)

var (
	epochA = strings.Repeat("a", EpochLen)
	epochB = strings.Repeat("b", EpochLen)
)

func sourceEpoch(t *testing.T, s *Store, name string) string {
	t.Helper()
	for _, src := range s.Status().Sources {
		if src.Name == name {
			return src.Epoch
		}
	}
	t.Fatalf("источника %s нет в статусе", name)
	return ""
}

// B-03: первая эпоха источника закрепляется, чужая получает отказ, сборщик
// без эпохи (прежней версии) проходит, только пока ничего не закреплено.
// Закрепление и отказы — в цепи (отказ одной эпохе — одно событие) и
// переживают рестарт; оператор закрепляет другую эпоху.
func TestEpochBindsSource(t *testing.T) {
	c := newClock()
	cfg := testConfig(t)
	s := openStore(t, cfg, c)
	if err := s.Admit("abs-core", ""); err != nil {
		t.Fatalf("без эпохи, пока не закреплено: %v", err)
	}
	if got := sourceEpoch(t, s, "abs-core"); got != "" {
		t.Fatalf("сборщик без эпохи закрепил %q", got)
	}
	for i := 0; i < 2; i++ {
		if err := s.Admit("abs-core", epochA); err != nil {
			t.Fatalf("первая эпоха, запрос %d: %v", i+1, err)
		}
	}
	for _, e := range []string{epochB, epochB, ""} {
		err := s.Admit("abs-core", e)
		if !errors.Is(err, ErrEpochMismatch) {
			t.Fatalf("эпоха %q при закреплённой: %v", e, err)
		}
		if e != "" && !strings.Contains(err.Error(), "evidencestore sources bind -source abs-core -epoch "+e) {
			t.Fatalf("в отказе нет команды оператору: %v", err)
		}
		// Закреплённая эпоха в отказе работала бы паролем: самозванец
		// повторил бы запрос с ней.
		if strings.Contains(err.Error(), epochA) {
			t.Fatalf("отказ называет закреплённую эпоху: %v", err)
		}
	}
	if err := s.Admit("abs-core", "ABC"); !errors.Is(err, ErrBadRecord) {
		t.Fatalf("кривая эпоха: %v", err)
	}
	if err := s.Admit("nope", epochA); !errors.Is(err, ErrUnknownSource) {
		t.Fatalf("неизвестный источник: %v", err)
	}
	if got := sourceEpoch(t, s, "abs-core"); got != epochA {
		t.Fatalf("в статусе эпоха %q", got)
	}
	if n := s.sources["abs-core"].epochRefused.Load(); n != 3 {
		t.Fatalf("отказов насчитано %d, было 3", n)
	}
	s.Close()

	var reasons []string
	for _, l := range leavesOf(t, cfg, auditchain.EventEpoch) {
		var ev epochEvent
		if err := json.Unmarshal(l.Payload, &ev); err != nil || l.Scope != "abs-core" {
			t.Fatalf("событие эпохи: %s %v", l.Payload, err)
		}
		reasons = append(reasons, ev.Reason+":"+ev.Epoch[:min(1, len(ev.Epoch))])
	}
	if got := strings.Join(reasons, ","); got != "first contact:a,refused:b,refused:" {
		t.Fatalf("события эпохи в цепи: %s", got)
	}

	s2 := openStore(t, cfg, c)
	if err := s2.Admit("abs-core", epochB); !errors.Is(err, ErrEpochMismatch) {
		t.Fatalf("после рестарта чужая эпоха: %v", err)
	}
	if err := s2.Admit("abs-core", epochA); err != nil {
		t.Fatalf("после рестарта своя эпоха: %v", err)
	}
	if err := s2.BindEpoch("abs-core", epochB); err != nil {
		t.Fatal(err)
	}
	if err := s2.Admit("abs-core", epochA); !errors.Is(err, ErrEpochMismatch) {
		t.Fatalf("прежняя эпоха после смены оператором: %v", err)
	}
	if err := s2.Admit("abs-core", epochB); err != nil {
		t.Fatalf("эпоха, закреплённая оператором: %v", err)
	}
	if err := s2.BindEpoch("abs-core", "zz"); !errors.Is(err, ErrBadRecord) {
		t.Fatalf("кривая эпоха оператора: %v", err)
	}
	if err := s2.BindEpoch("nope", epochA); !errors.Is(err, ErrUnknownSource) {
		t.Fatalf("оператор, неизвестный источник: %v", err)
	}
}

// Закрепление ложится в цепь звеном сразу: падение сразу после первого
// контакта не отдаёт источник следующей установке.
func TestEpochBindingSurvivesCrash(t *testing.T) {
	c := newClock()
	cfg := testConfig(t)
	s := openStore(t, cfg, c)
	if err := s.Admit("abs-core", epochA); err != nil {
		t.Fatal(err)
	}
	crashed := copyDirs(t, cfg)
	s2 := openStore(t, crashed, c)
	if err := s2.Admit("abs-core", epochB); !errors.Is(err, ErrEpochMismatch) {
		t.Fatalf("после падения чужая эпоха: %v", err)
	}
}

// Несколько установок выходят на связь одновременно, когда источник ещё
// ничей: закрепляется ровно одна, остальные получают отказ.
func TestEpochFirstContactRace(t *testing.T) {
	c := newClock()
	cfg := testConfig(t)
	s := openStore(t, cfg, c)
	const n = 8
	var wg sync.WaitGroup
	errs := make([]error, n)
	for i := range n {
		wg.Add(1)
		go func() {
			defer wg.Done()
			errs[i] = s.Admit("abs-core", fmt.Sprintf("%0*x", EpochLen, i+1))
		}()
	}
	wg.Wait()
	bound := 0
	for _, err := range errs {
		switch {
		case err == nil:
			bound++
		case !errors.Is(err, ErrEpochMismatch):
			t.Fatalf("отказ: %v", err)
		}
	}
	if bound != 1 {
		t.Fatalf("закрепилось %d установок из %d", bound, n)
	}
	s.Close()
	if got := len(leavesOf(t, cfg, auditchain.EventEpoch)); got != n {
		t.Fatalf("событий эпохи %d, ожидали закрепление и %d отказов", got, n-1)
	}
}

// Запросы с выдуманными эпохами не раздувают цепь: отказы разным эпохам
// ложатся в неё до предела, дальше — только счётчик.
func TestEpochRefusalsBounded(t *testing.T) {
	c := newClock()
	cfg := testConfig(t)
	s := openStore(t, cfg, c)
	if err := s.Admit("abs-core", epochA); err != nil {
		t.Fatal(err)
	}
	const n = maxRefusedEpochs + 10
	for i := range n {
		if err := s.Admit("abs-core", fmt.Sprintf("%0*x", EpochLen, i+1)); !errors.Is(err, ErrEpochMismatch) {
			t.Fatalf("эпоха %d: %v", i+1, err)
		}
	}
	if got := s.sources["abs-core"].epochRefused.Load(); got != n {
		t.Fatalf("отказов насчитано %d из %d", got, n)
	}
	s.Close()
	if got := len(leavesOf(t, cfg, auditchain.EventEpoch)); got != 1+maxRefusedEpochs {
		t.Fatalf("событий эпохи в цепи %d, ожидали закрепление и %d отказов", got, maxRefusedEpochs)
	}
}
