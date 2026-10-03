package store

import (
	"context"
	"errors"
	"fmt"
	"strconv"
	"time"

	"evidencestore/internal/auditchain"
	"evidencestore/internal/proof"
	"evidencestore/internal/tsa"
)

// startBackground запускает фоновые циклы: звено раз в тик, метку TSA раз
// в tsa.every, обслуживание ключей и контроль молчания.
func (s *Store) startBackground() {
	s.loop(s.cfg.Chain.Tick.D(), func() {
		if err := s.flush(); err != nil {
			s.log.Error("chain flush", "err", err)
		}
	})
	if s.tsaURL != "" || s.tsaLocal != nil {
		s.loop(s.cfg.TSA.Every.D(), func() {
			ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
			defer cancel()
			if _, err := s.Stamp(ctx); err != nil {
				s.log.Error("tsa stamp", "err", err)
			}
		})
	}
	if s.replicaRemote != nil {
		s.loop(s.cfg.Replica.Every.D(), func() {
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
			defer cancel()
			if _, err := s.ShipOnce(ctx, s.replicaRemote); err != nil {
				s.log.Error("replica", "err", err)
			}
		})
	}
	s.loop(time.Minute, func() { s.Maintain(s.nowTime()) })
	s.loop(10*time.Second, func() { s.CheckSilence(s.nowTime()) })
}

func (s *Store) loop(every time.Duration, fn func()) {
	s.wg.Add(1)
	go func() {
		defer s.wg.Done()
		t := time.NewTicker(every)
		defer t.Stop()
		for {
			select {
			case <-s.stop:
				return
			case <-t.C:
				fn()
			}
		}
	}()
}

// Maintain — обслуживание ключей: завести месяцы, закрыть прошлые,
// уничтожить те, у которых истёк срок ожидания.
func (s *Store) Maintain(now time.Time) {
	if err := s.ensureMonthScopes(now); err != nil {
		s.log.Error("ensure month keys", "err", err)
	}
	if err := s.deactivatePastMonths(now); err != nil {
		s.log.Error("deactivate past months", "err", err)
	}
	if _, err := s.CompleteDue(); err != nil {
		s.log.Error("complete key destruction", "err", err)
	}
}

// CheckSilence пишет в цепь «источник молчит», если записей нет дольше его
// ритма. Так замечается отключение журналов, которое ПП № 832 п. 38
// запрещает администраторам. Событие одно на эпизод молчания.
func (s *Store) CheckSilence(now time.Time) {
	type silent struct {
		name  string
		since time.Time
		every time.Duration
	}
	var found []silent
	s.mu.Lock()
	for name, st := range s.sources {
		every := st.cfg.ExpectEvery.D()
		if !st.known || st.cfg.Disabled || every == 0 || st.silent {
			continue
		}
		last := st.lastAt
		if last.IsZero() || last.Before(s.opened) && st.count == 0 {
			last = s.opened
		}
		if now.Sub(last) > every {
			st.silent = true
			found = append(found, silent{name, last, every})
		}
	}
	s.mu.Unlock()
	for _, f := range found {
		s.appendJSONEvent(auditchain.EventSilence, f.name, "", map[string]any{
			"since": f.since.UTC(), "expect_every": f.every.String(),
		})
		s.log.Warn("source is silent", "source", f.name, "since", f.since)
	}
}

// Stamp заверяет текущую голову цепи у TSA и кладёт токен в цепь листом.
// Отдаёт заверенную голову; ноль — заверять нечего (голова не менялась).
func (s *Store) Stamp(ctx context.Context) (uint64, error) {
	if s.tsaURL == "" && s.tsaLocal == nil {
		return 0, errors.New("store: no TSA configured")
	}
	s.stampMu.Lock()
	defer s.stampMu.Unlock()
	if err := s.flush(); err != nil {
		return 0, err
	}
	s.chainMu.Lock()
	head := s.chain.Head()
	already := head.Seq == 0 || head.Seq <= s.lastStamped
	s.chainMu.Unlock()
	if already {
		return 0, nil
	}
	imprint := proof.HeadImprint(head.Seq, head.Hash)
	var token []byte
	var err error
	if s.tsaLocal != nil {
		token, err = s.tsaLocal.Sign(imprint[:], nil)
	} else {
		token, err = tsa.Request(ctx, s.tsaHTTP, s.tsaURL, imprint)
	}
	if err != nil {
		return 0, err
	}
	// Токен проверяется до того, как лечь в цепь: в цепь не попадает то,
	// что проверяющий потом не примет.
	info, err := tsa.Verify(token, imprint, s.tsaTrust)
	if err != nil {
		return 0, fmt.Errorf("store: TSA token rejected: %w", err)
	}
	s.chainMu.Lock()
	num := s.appendLeafLocked(auditchain.Leaf{
		UnixNano: s.nowTime().UnixNano(),
		Type:     auditchain.EventTimestamp,
		Subject:  strconv.FormatUint(head.Seq, 10),
		Payload:  token,
	})
	s.tokens = append(s.tokens, tokenRef{head: head.Seq, leaf: num, gen: info.GenTime})
	s.lastStamped = head.Seq
	err = s.flushLocked()
	s.chainMu.Unlock()
	s.log.Info("tsa stamp", "head", head.Seq, "gen_time", info.GenTime)
	return head.Seq, err
}
