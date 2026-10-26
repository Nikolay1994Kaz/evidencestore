package store

import (
	"context"
	"errors"
	"fmt"
	"strconv"
	"time"

	"github.com/Nikolay1994Kaz/evidencestore/internal/auditchain"
	"github.com/Nikolay1994Kaz/evidencestore/internal/keyring"
	"github.com/Nikolay1994Kaz/evidencestore/internal/proof"
	"github.com/Nikolay1994Kaz/evidencestore/internal/tsa"
)

// startBackground запускает фоновые циклы: звено раз в тик, метку TSA раз
// в tsa.every, обслуживание ключей, контроль молчания и связи со сборщиками.
func (s *Store) startBackground() {
	s.loop(s.cfg.Chain.Tick.D(), func() {
		if err := s.flush(); err != nil {
			s.log.Error("chain flush", "err", err)
		}
	})
	if s.tsaURL != "" || s.tsaLocal != nil {
		// Первая метка — сразу после старта: она же якорь часов приёма, и
		// до неё приём закрыт (W-13). Якорь держится свежим (keepAnchor).
		s.loopNow(s.cfg.TSA.Every.D(), s.stampLogged)
		s.wg.Add(1)
		go s.keepAnchor()
	} else {
		s.log.Warn("no TSA configured (tsa.url): proofs carry no external time-stamp, and esverify rejects them unless told -allow-no-tsa")
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
	if s.witnessRemote != nil {
		s.loop(s.cfg.Witness.Every.D(), func() {
			ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
			defer cancel()
			if err := s.WitnessOnce(ctx); err != nil {
				s.log.Error("witness", "err", err)
			}
		})
	}
	s.loop(time.Minute, func() { s.Maintain(s.nowTime()) })
	s.loop(10*time.Second, func() {
		now := s.nowTime()
		s.CheckSilence(now)
		s.CheckContact(now)
	})
}

// anchorRetry — как часто проверять, свеж ли якорь, и повторять метку,
// пока он не свеж. Переменная — чтобы тесты не ждали.
var anchorRetry = 10 * time.Second

// stampLogged — метка по расписанию; ошибка — в журнал.
func (s *Store) stampLogged() {
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	if _, err := s.Stamp(ctx); err != nil {
		s.log.Error("tsa stamp", "err", err)
	}
}

// keepAnchor держит якорь часов приёма свежим: якоря нет, он старше
// anchorRefresh или окно по нему разошлось — метка ставится сейчас, даже
// если в цепь ничего не легло (простой). Не вышла — повтор через
// anchorRetry, а не через tsa.every: без свежего якоря приём закрыт.
// Зовётся с s.wg.Add(1).
func (s *Store) keepAnchor() {
	defer s.wg.Done()
	t := time.NewTicker(anchorRetry)
	defer t.Stop()
	for {
		select {
		case <-s.stop:
			return
		case <-t.C:
		}
		if !s.anchorStale() {
			continue
		}
		if s.anchored() != nil {
			s.log.Warn("intake waits for a fresh TSA time-stamp")
		}
		ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
		if _, err := s.stampNow(ctx); err != nil {
			s.log.Error("tsa stamp", "err", err)
		}
		cancel()
	}
}

func (s *Store) loop(every time.Duration, fn func()) { s.runLoop(every, false, fn) }

// loopNow — loop, первый раз сразу.
func (s *Store) loopNow(every time.Duration, fn func()) { s.runLoop(every, true, fn) }

func (s *Store) runLoop(every time.Duration, now bool, fn func()) {
	s.wg.Add(1)
	go func() {
		defer s.wg.Done()
		if now {
			fn()
		}
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
	s.confirmKeys()
	if err := s.ensureMonthScopes(now); err != nil {
		s.log.Error("ensure month keys", "err", err)
	}
	if err := s.deactivatePastMonths(now); err != nil {
		s.log.Error("deactivate past months", "err", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	if _, err := s.CompleteDue(ctx); err != nil {
		// Сироты держат окончательность, пока не решит оператор: про них —
		// один раз на новый набор, а не каждую минуту.
		if !errors.Is(err, keyring.ErrOrphanRoots) || err.Error() != s.orphanWarned {
			s.log.Error("complete key destruction", "err", err)
		}
		if errors.Is(err, keyring.ErrOrphanRoots) {
			s.orphanWarned = err.Error()
		}
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
		if last.IsZero() {
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
// Отдаёт заверенную голову; ноль — заверять нечего: после прошлой метки в
// цепь не легло ничего, кроме неё самой (иначе метка ставилась бы каждые
// tsa.every вечно — сам токен двигает голову).
func (s *Store) Stamp(ctx context.Context) (uint64, error) {
	head, _, err := s.stamp(ctx, false)
	return head, err
}

// stampNow ставит метку над текущей головой и отдаёт её время: так берётся
// доверенное время для уничтожения ключей. Ставится всегда: голова после
// прошлой метки новее заверенной — в ней лежит сам прошлый токен.
func (s *Store) stampNow(ctx context.Context) (time.Time, error) {
	_, gen, err := s.stamp(ctx, true)
	return gen, err
}

func (s *Store) stamp(ctx context.Context, force bool) (_ uint64, gen time.Time, err error) {
	defer func() {
		if err != nil {
			s.stampErrors.Add(1)
		}
	}()
	if s.tsaURL == "" && s.tsaLocal == nil {
		return 0, gen, errors.New("store: no TSA configured")
	}
	s.stampMu.Lock()
	defer s.stampMu.Unlock()
	s.chainMu.Lock()
	if err := s.flushLocked(); err != nil {
		s.chainMu.Unlock()
		return 0, gen, err
	}
	head := s.chain.Head()
	already := head.Seq == 0 || head.Seq <= s.lastStamped || (!force && s.nextLeaf <= s.stampedLeaves)
	if !already && head.Seq != s.preTailsHead {
		// Хвосты перед запросом — одни в своём звене, его метка и заверяет:
		// состояние источников к моменту метки (п. 28). Метка, повторённая
		// без новых листьев, заверяет то же звено.
		s.appendLeafLocked(s.tailsLocked())
		if err := s.flushLocked(); err != nil {
			s.chainMu.Unlock()
			return 0, gen, err
		}
		head = s.chain.Head()
		s.preTailsHead = head.Seq
	}
	s.chainMu.Unlock()
	if already {
		return 0, gen, nil
	}
	imprint := proof.HeadImprint(head.Seq, head.Hash)
	asked := s.mono()
	var token []byte
	if s.tsaLocal != nil {
		token, err = s.tsaLocal.Sign(imprint[:], nil)
	} else {
		token, err = tsa.Request(ctx, s.tsaHTTP, s.tsaURL, imprint)
	}
	if err != nil {
		return 0, gen, err
	}
	// Токен проверяется до того, как лечь в цепь: в цепь не попадает то,
	// что проверяющий потом не примет.
	info, err := tsa.Verify(token, imprint, s.tsaTrust)
	if err != nil {
		return 0, gen, fmt.Errorf("store: TSA token rejected: %w", err)
	}
	s.chainMu.Lock()
	num := s.appendLeafLocked(auditchain.Leaf{
		UnixNano: s.nowTime().UnixNano(),
		Type:     auditchain.EventTimestamp,
		Subject:  strconv.FormatUint(head.Seq, 10),
		Payload:  token,
	})
	// Хвосты сразу после токена — последним листом его звена: в счёт входит
	// всё, что легло, пока шёл запрос (верхняя граница пакета по источнику).
	s.appendLeafLocked(s.tailsLocked())
	s.tokens = append(s.tokens, tokenRef{head: head.Seq, leaf: num, gen: info.GenTime})
	s.queueWitnessLocked(head, true) // ею кончаются пакеты: свидетель видит её саму
	s.lastStamped = max(s.lastStamped, head.Seq)
	s.stampedLeaves = num + 2
	err = s.flushLocked()
	s.chainMu.Unlock()
	s.anchorClock(info.GenTime, s.mono()-asked)
	s.log.Info("tsa stamp", "head", head.Seq, "gen_time", info.GenTime)
	return head.Seq, info.GenTime, err
}
