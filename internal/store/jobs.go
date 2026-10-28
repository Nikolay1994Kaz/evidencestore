package store

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"sort"
	"strconv"
	"strings"
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

// anchorBackoff — во сколько раз реже anchorRetry, самое большее, идут
// повторы метки после отказов подряд: при лежащей TSA каждая попытка с
// новыми листьями кладёт звено хвостов (Q-43), а приём после её
// возвращения ждёт не дольше двух минут.
const anchorBackoff = 12

// stampTimeout — сколько ждать ответа TSA: ответ дольше proof.StampLatency
// всё равно не берётся.
const stampTimeout = proof.StampLatency + 5*time.Second

// stampLogged — метка по расписанию; ошибка — в журнал.
func (s *Store) stampLogged() {
	ctx, cancel := context.WithTimeout(context.Background(), stampTimeout)
	defer cancel()
	if _, err := s.Stamp(ctx); err != nil {
		s.log.Error("tsa stamp", "err", err)
	}
}

// keepAnchor держит якорь часов приёма свежим: якоря нет, он старше
// anchorRefresh или окно по нему разошлось — метка ставится сейчас, даже
// если в цепь ничего не легло (простой). Не вышла — повтор через
// anchorRetry, а не через tsa.every: без свежего якоря приём закрыт; после
// отказов подряд — реже, до anchorBackoff раз. Зовётся с s.wg.Add(1).
func (s *Store) keepAnchor() {
	defer s.wg.Done()
	t := time.NewTicker(anchorRetry)
	defer t.Stop()
	var fails, skip int
	for {
		select {
		case <-s.stop:
			return
		case <-t.C:
		}
		s.stampMu.Lock()
		finished := s.finishReanchor()
		s.stampMu.Unlock()
		if finished {
			fails, skip = 0, 0
		}
		if skip > 0 {
			skip--
			continue
		}
		if !s.anchorStale() {
			fails = 0
			continue
		}
		if s.anchored() != nil {
			s.log.Warn("intake waits for a fresh TSA time-stamp")
		}
		ctx, cancel := context.WithTimeout(context.Background(), stampTimeout)
		if _, err := s.stampNow(ctx); err != nil {
			s.log.Error("tsa stamp", "err", err)
			// Отсрочка из-за записей в пути — не отказ TSA: повтор на
			// следующем шаге, без растущей паузы.
			if !errors.Is(err, ErrStampDeferred) {
				skip = min(1<<min(fails, 4), anchorBackoff) - 1
				fails++
			}
		} else {
			fails = 0
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

// StampNow — метка по просьбе оператора (evidencestore stamp): ставится и
// без новых листьев, с новыми хвостами после прошлого токена — в простое
// так закрывается окно и появляется верхний край пакета по источнику.
func (s *Store) StampNow(ctx context.Context) (uint64, error) {
	head, _, err := s.stamp(ctx, true)
	return head, err
}

// lockGateways берёт замки пачек всех источников журнала гейтвея — по
// одному, в порядке имён (Ingest держит не больше одного) — и возвращает,
// чем их отпустить.
func (s *Store) lockGateways() func() {
	s.mu.Lock()
	var names []string
	for name, st := range s.sources {
		if st.gw != nil {
			names = append(names, name)
		}
	}
	sort.Strings(names)
	locked := make([]*sourceState, 0, len(names))
	for _, name := range names {
		locked = append(locked, s.sources[name])
	}
	s.mu.Unlock()
	for _, st := range locked {
		st.gwMu.Lock()
	}
	return func() {
		for _, st := range locked {
			st.gwMu.Unlock()
		}
	}
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
	s.finishReanchor()
	head, gen, err := s.stampOnce(ctx, force)
	if errors.Is(err, errClockLost) {
		// Якорь уже взят по этой метке (reanchor). Повтор кладёт новые
		// хвосты — после того, что легло в цепь, пока шёл запрос, — и метка
		// их заверяет. Срок у повтора свой: первая попытка могла съесть почти
		// весь, а несвежим якорь уже не считается, и keepAnchor её не повторит.
		s.log.Warn("the TSA time is ahead of the receive-time window: the monotonic clock lost time (host suspended or VM paused?); stamping again", "err", err)
		rctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), stampTimeout)
		head, gen, err = s.stampOnce(rctx, true)
		cancel()
	}
	s.mu.Lock()
	closed := err == nil && s.needAnchor && !s.intakeOpen && !s.anchorTSA.IsZero()
	s.mu.Unlock()
	if closed {
		// Якорь есть, а приём закрыт: хвосты последней метки легли без якоря
		// (первая метка процесса). Приём открывает метка с хвостами при
		// якоре — сразу, и без новых листьев; не вышла — keepAnchor
		// повторит (anchorStale).
		rctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), stampTimeout)
		head, gen, err = s.stampOnce(rctx, true)
		cancel()
	}
	return head, gen, err
}

// errClockLost — время TSA позже окна по якорю: монотонные часы потеряли
// время (сон хоста, пауза ВМ), и время приёма отставало от времени TSA
// больше, чем допускает граница окна пакетов (proof.WindowEdge).
var errClockLost = errors.New("store: the TSA time is ahead of the receive-time window")

// stampOnce — одна метка под stampMu.
func (s *Store) stampOnce(ctx context.Context, force bool) (_ uint64, gen time.Time, err error) {
	// Журнал улик отказал — токен всё равно не ляжет (ниже, после барьера):
	// без запроса к TSA и без звена хвостов.
	if err := s.evlog.Failed(); err != nil {
		return 0, gen, fmt.Errorf("%w: %w", ErrLogFailed, err)
	}
	// Пачка журнала гейтвея кладёт в цепь улики и вердикты к ним не разом:
	// хвосты перед запросом не встают между уликой и её вердиктом — пакет по
	// источнику берёт вердикт своей записи до края.
	unlockGW := s.lockGateways()
	before := s.leafTime()
	s.mu.Lock()
	first := s.anchorTSA.IsZero()
	s.mu.Unlock()
	s.chainMu.Lock()
	if err := s.flushLocked(); err != nil {
		s.chainMu.Unlock()
		unlockGW()
		return 0, gen, err
	}
	head := s.chain.Head()
	already := head.Seq == 0 || head.Seq <= s.lastStamped || (!force && s.nextLeaf <= s.stampedLeaves)
	if !already && head.Seq != s.preTailsHead {
		// Хвосты перед запросом — одни в своём звене, его метка и заверяет:
		// состояние источников к моменту метки (п. 28). Метка, повторённая
		// без новых листьев, заверяет то же звено.
		s.appendLeafLocked(s.tailsLocked(before))
		if err := s.flushLocked(); err != nil {
			s.chainMu.Unlock()
			unlockGW()
			return 0, gen, err
		}
		head = s.chain.Head()
		s.preTailsHead = head.Seq
		// К свидетелю — сразу, головой под меткой: ею кончаются пакеты. Пока
		// идёт запрос к TSA, обход свидетеля может поставить в очередь и
		// отправить голову новее, и эта, встав в очередь после неё, туда бы
		// уже не попала. Метка не выйдет — свидетель получит лишнюю голову.
		s.queueWitnessLocked(head, true)
	}
	s.chainMu.Unlock()
	unlockGW()
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
	// Ответ дольше StampLatency в цепь не ложится: что легло в цепь, пока шёл
	// запрос, — после заверенного звена, и граница окна пакетов
	// (proof.WindowEdge) держится на том, что запрос был коротким.
	answered := s.mono()
	took := answered - asked
	if took > proof.StampLatency {
		return 0, gen, fmt.Errorf("store: the TSA answered after %s, longer than %s: the time-stamp is not used", took.Round(time.Millisecond), proof.StampLatency)
	}
	// Токен проверяется до того, как лечь в цепь: в цепь не попадает то,
	// что проверяющий потом не примет.
	info, err := tsa.Verify(token, imprint, s.tsaTrust)
	if err != nil {
		return 0, gen, fmt.Errorf("store: TSA token rejected: %w", err)
	}
	// Время TSA позже окна по якорю: монотонные часы стояли (сон хоста,
	// пауза ВМ), и время приёма отставало на всю паузу. Запись, принятая,
	// пока шёл запрос, легла после заверенного звена со временем внутри окна,
	// которое эта метка закрыла бы, и пакеты за такое окно её бы не
	// показали. Токен не ложится; якорь — по нему, и метка повторяется.
	s.mu.Lock()
	_, hi, _ := s.anchorWindowAt(answered)
	s.mu.Unlock()
	if hi != 0 && info.GenTime.UnixNano() > hi+int64(clockLost) {
		if !s.reanchor(info.GenTime, answered, took) {
			return 0, gen, errReanchorPending
		}
		return 0, gen, fmt.Errorf("%w by %s", errClockLost, time.Duration(info.GenTime.UnixNano()-hi).Round(time.Second))
	}
	// Записи, взявшие время приёма по прежнему якорю, ложатся раньше
	// токена и листьев нового: за ними время приёма записи, чей fsync шёл
	// дольше ответа, было бы раньше времени метки больше чем на ReceiveSkew
	// (отставание до ReceiveLag и весь запрос), и её пакет не прошёл бы
	// (Q-61), а токен метки, чьё время позже её времени приёма больше чем
	// на минуту, лёг бы перед ней, и esverify -promise обвинил бы честное
	// хранилище (proof.checkStamps; Q-64). Снимок записей в пути и пауза
	// приёма — под одним замком: такая запись либо в снимке и ляжет до
	// токена, либо возьмёт время уже по новому якорю. Пауза — до якоря
	// (defer); приём на ней ждёт, а не получает отказ.
	pause := make(chan struct{})
	s.mu.Lock()
	s.stampPause = pause
	wait := s.inFlightLocked()
	s.mu.Unlock()
	defer func() {
		s.mu.Lock()
		s.stampPause = nil
		s.mu.Unlock()
		close(pause)
	}()
	if rest := s.landed(wait); len(rest) > 0 {
		return 0, gen, fmt.Errorf("%w (%s)", errRecordsInFlight, describeInFlight(rest))
	}
	// Журнал улик отказал: запись, которой Append вернул ошибку, снята с
	// учёта в пути (release), но её байты могли лечь на диск (Write прошёл,
	// fsync — нет), и после перезапуска она догонится в цепь — после этого
	// токена, со временем приёма до его ответа: её пакет не пройдёт, а
	// обещание на повтор будет нарушено при подписи (Q-75). Отказ
	// защёлкивается в журнале до ответа писателю, так что запись из снимка,
	// снятая отказом, видна здесь. Токен не ложится до перезапуска.
	if err := s.evlog.Failed(); err != nil {
		return 0, gen, fmt.Errorf("%w: %w", ErrLogFailed, err)
	}
	// Время листа токена — по окну этой же метки: после старта якоря ещё
	// нет, и лист получил бы часы хоста как есть. Сам якорь — после того,
	// как лист лёг в цепь: с якорем открывается приём, и запись, принятая
	// раньше листа токена, легла бы до него — у первой метки без T1 (Q-50).
	lo, hi := anchorWindow(info.GenTime, took, s.mono()-answered)
	after := clampToWindow(s.nowTime().UnixNano(), lo, hi)
	s.chainMu.Lock()
	// Записи, взявшие время приёма по прежнему якорю (и дождавшиеся барьера
	// выше), — своим звеном до листа токена: время их звена — по прежнему
	// якорю, как и время их приёма. В звене токена оно стало бы временем
	// листа токена — по окну этой метки, чей нижний край выше прежнего на
	// весь ответ TSA (пока обещание сверялось по времени звеньев, срок
	// записи, бывшей в пути весь запрос, так «нарушался», Q-64). Лист токена
	// — всегда один в своём звене (README; тест tokenLinksAlone, Q-84).
	if err := s.flushLocked(); err != nil {
		s.chainMu.Unlock()
		return 0, gen, err
	}
	num := s.appendLeafLocked(auditchain.Leaf{
		UnixNano: after,
		Type:     auditchain.EventTimestamp,
		Subject:  strconv.FormatUint(head.Seq, 10),
		Payload:  token,
	})
	s.tokens = append(s.tokens, tokenRef{head: head.Seq, leaf: num, gen: info.GenTime})
	s.lastStamped = max(s.lastStamped, head.Seq)
	s.stampedLeaves = num + 1
	if err = s.flushLocked(); err == nil {
		// Звеном токена кончаются пакеты за окно и по источнику: и оно к
		// свидетелю головой под меткой, не ждать обхода.
		s.queueWitnessLocked(s.chain.Head(), true)
	}
	s.chainMu.Unlock()
	s.anchorClock(info.GenTime, answered, took)
	// Отложенная перестановка (reanchor) теперь лишняя: якорь — по этой
	// метке, свежее. Доведённая по прежнему ответу, она переставила бы якорь
	// без паузы приёма и барьера (Q-70).
	s.pending = nil
	s.mu.Lock()
	if !first || !s.needAnchor {
		s.intakeOpen = true
	}
	// Пауза перестановки якоря, отложенной из-за записи в пути (reanchor),
	// кончается и тогда, когда повтор уже не видит потери хода часов: якорь
	// свежий, время приёма снова по нему.
	s.reanchoring = false
	s.mu.Unlock()
	s.log.Info("tsa stamp", "head", head.Seq, "gen_time", info.GenTime)
	return head.Seq, info.GenTime, err
}

// reanchor ставит якорь по метке, время которой позже окна по якорю:
// монотонные часы стояли, и время приёма отставало на всю паузу. Запись,
// уже взявшая время по прежнему якорю, но ещё не легшая в цепь (fsync
// журнала улик), обязана лечь в звено раньше листьев нового якоря: иначе
// хвосты повторной метки лягут раньше неё, а время её звена — по новому
// якорю, на всю паузу позже её срока (Q-49; пока обещание сверялось по
// времени звеньев, esverify -promise так обвинял честную запись). Поэтому
// приём на это время на паузе (новая запись получает 503, сборщик
// повторит), записи в пути дожидаются, их листья сворачиваются в звено, и
// только потом — якорь.
//
// Записи в пути, не легшие за reanchorWait (медленный диск после паузы ВМ,
// копия ключа месяца), якорь не двигают: приём остаётся на паузе, якорь —
// прежним, и keepAnchor повторяет метку (anchorStale), пока они не лягут.
// Иначе такая запись легла бы после листьев нового якоря, и её пакет и
// обещание не сошлись бы (Q-59). false — якорь не переставлен.
func (s *Store) reanchor(gen time.Time, answered, took time.Duration) bool {
	// Флаг и снимок — под одним замком: запись, взявшая время по прежнему
	// якорю, либо в снимке, либо уже получила отказ.
	s.mu.Lock()
	s.reanchoring = true
	wait := s.inFlightLocked()
	s.mu.Unlock()
	if rest := s.landed(wait); len(rest) > 0 {
		s.log.Error("records taken in before the monotonic clock was found stopped are still not in the chain: the intake stays paused until they are", "records", describeInFlight(rest))
		if err := s.flush(); err != nil {
			s.log.Error("chain flush", "err", err)
		}
		s.pending = &pendingAnchor{gen: gen, answered: answered, took: took, wait: rest}
		return false
	}
	if err := s.flush(); err != nil {
		s.log.Error("chain flush", "err", err)
	}
	s.anchorClock(gen, answered, took)
	s.mu.Lock()
	s.reanchoring = false
	s.mu.Unlock()
	s.pending = nil
	return true
}

// pendingAnchor — ответ TSA, по которому якорь не переставлен, пока не легли
// записи wait, взявшие время приёма по прежнему якорю (reanchor).
type pendingAnchor struct {
	gen            time.Time
	answered, took time.Duration
	wait           []inFlight
}

// finishReanchor доводит отложенную перестановку якоря, когда записи, которых
// она ждала, легли в цепь: якорь — по тому же ответу TSA, без нового запроса,
// и приём открывается, даже если TSA тем временем пропала (Q-67). Зовётся
// под stampMu: в начале каждой метки и на каждом шаге keepAnchor.
func (s *Store) finishReanchor() bool {
	p := s.pending
	if p == nil {
		return false
	}
	s.mu.Lock()
	p.wait = slices.DeleteFunc(p.wait, func(r inFlight) bool { return !r.st.inflight[r.seq] })
	rest := len(p.wait)
	s.mu.Unlock()
	if rest > 0 {
		return false
	}
	if err := s.flush(); err != nil {
		s.log.Error("chain flush", "err", err)
		return false
	}
	s.anchorClock(p.gen, p.answered, p.took)
	s.mu.Lock()
	s.reanchoring = false
	s.mu.Unlock()
	s.pending = nil
	s.log.Info("the records in flight reached the chain: receive times follow the TSA time stamped while they were", "gen_time", p.gen)
	return true
}

// ErrStampDeferred — метка не вышла, пока не легли в цепь записи, взявшие
// время приёма раньше (errRecordsInFlight, errReanchorPending): это не
// отказ TSA, хранилище повторит метку само.
var ErrStampDeferred = errors.New("store: time-stamp deferred")

// ErrLogFailed — журнал улик отказал (запись или fsync): метки не ложатся
// до перезапуска, а перезапуск кладёт в цепь записи хвоста раньше любой
// новой метки (Q-75).
var ErrLogFailed = errors.New("store: the evidence log failed, no time-stamp until restart")

// errReanchorPending — время TSA позже окна по якорю, а записи, взявшие
// время приёма по прежнему якорю, ещё не в цепи: якорь не переставлен,
// приём на паузе, пока они не лягут (reanchor, finishReanchor).
var errReanchorPending = fmt.Errorf("%w: the TSA time is ahead of the receive-time window, and records taken in before are not in the chain yet; the intake stays paused until they are, then receive times follow that TSA time", ErrStampDeferred)

// errRecordsInFlight — записи, взявшие время приёма до ответа TSA, ещё не в
// журнале улик: токен не ложится, следующая метка — по расписанию.
var errRecordsInFlight = fmt.Errorf("%w: records taken in before the TSA answered are not in the chain yet, so the answer is not used; the next time-stamp is taken on schedule", ErrStampDeferred)

// reanchorWait — сколько метка ждёт записи в пути (stampOnce, reanchor):
// fsync журнала улик — миллисекунды; не легли — метка повторится. Переменная
// — чтобы тесты не ждали.
var reanchorWait = 5 * time.Second

// inFlight — запись, взявшая время приёма, но ещё не легшая в журнал улик.
type inFlight struct {
	st  *sourceState
	seq uint64
}

// inFlightLocked — записи в пути сейчас (под s.mu).
func (s *Store) inFlightLocked() []inFlight {
	var wait []inFlight
	for _, st := range s.sources {
		for q := range st.inflight {
			wait = append(wait, inFlight{st, q})
		}
	}
	return wait
}

// landed ждёт, пока записи wait лягут в журнал улик (их листья — уже в
// цепи), не дольше reanchorWait; возвращает те, что не легли.
func (s *Store) landed(wait []inFlight) []inFlight {
	for deadline := time.Now().Add(reanchorWait); len(wait) > 0; {
		if time.Now().After(deadline) {
			return wait
		}
		time.Sleep(time.Millisecond)
		s.mu.Lock()
		wait = slices.DeleteFunc(wait, func(r inFlight) bool { return !r.st.inflight[r.seq] })
		s.mu.Unlock()
	}
	return nil
}

// describeInFlight — записи в пути для журнала и ответа оператору: что
// именно не легло (зависший keys.backup_dir держит запись нового месяца).
func describeInFlight(wait []inFlight) string {
	var names []string
	for _, r := range wait[:min(len(wait), 3)] {
		names = append(names, r.st.cfg.Name+"/"+strconv.FormatUint(r.seq, 10))
	}
	if len(wait) > 3 {
		names = append(names, fmt.Sprintf("%d more", len(wait)-3))
	}
	return "in flight: " + strings.Join(names, ", ")
}
