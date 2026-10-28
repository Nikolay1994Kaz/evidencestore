package store

import (
	"context"
	"errors"
	"fmt"
	mrand "math/rand/v2"
	"os"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/Nikolay1994Kaz/evidencestore/internal/auditchain"
	"github.com/Nikolay1994Kaz/evidencestore/internal/proof"
)

// Симуляция часов приёма: истинное время задаёт TSA (метка округлена до
// секунды), часы хоста смещены, прыгают и уходят, монотонные часы уходят
// (без NTP — тем же ходом, что часы хоста), ответ TSA идёт до 25 с, TSA
// пропадает, хранилище простаивает сутками и перезапускается, машина
// засыпает (монотонные часы стоят, часы хоста догоняет NTP или стоят тоже),
// записи приходят и в окно между ответом TSA и новым якорем, а запись бывает
// в пути (до журнала улик) всю метку — дольше, чем её ждёт перестановка
// якоря (Q-59). После
// последней метки каждая принятая запись должна пройти проверку
// (время приёма между T1 − 1 мин и T2 + 1 с) и сверку с обещанием, данным
// при приёме (esverify -promise); приём не закрыт, пока TSA отвечает;
// верные часы хоста — не тревога.
//
// CLOCKSIM_SEEDS — сценариев, CLOCKSIM_SEED — один сценарий.

func TestClockSim(t *testing.T) {
	saved := reanchorWait
	reanchorWait = 200 * time.Millisecond // запись в пути ложится за миллисекунды — или держит замок всю метку
	defer func() { reanchorWait = saved }()
	seeds := 12 // в гейте; длинный прогон — CLOCKSIM_SEEDS=2000
	if raceBuild {
		seeds = 3
	}
	if v, err := strconv.Atoi(os.Getenv("CLOCKSIM_SEEDS")); err == nil && v > 0 {
		seeds = v
	}
	only, single := os.LookupEnv("CLOCKSIM_SEED")
	failed, kinds := 0, map[string]int{}
	for i := range seeds {
		seed := uint64(i) + 1
		if single {
			if i > 0 {
				break
			}
			seed, _ = strconv.ParseUint(only, 10, 64)
		}
		if msg := runClockSim(t, seed); msg != "" {
			failed++
			kind, _, _ := strings.Cut(msg, ":")
			kind = strings.Join(strings.FieldsFunc(kind, func(r rune) bool { return r >= '0' && r <= '9' }), "N")
			kinds[kind]++
			if kinds[kind] <= 2 {
				t.Errorf("CLOCKSIM_SEED=%d:\n%s", seed, msg)
			}
		}
	}
	if failed > 0 {
		t.Errorf("провалено %d из %d сценариев; виды: %v", failed, seeds, kinds)
	}
}

type clockSim struct {
	t   *testing.T
	rng *mrand.Rand
	s   *Store

	t0, now  time.Time     // истинное время (оно же время TSA)
	hostOff  time.Duration // часы хоста = истина + hostOff + уход
	hostPPM  float64       // уход часов хоста
	monoPPM  float64       // уход монотонных часов
	monoBase time.Duration // монотонные часы процесса начинаются не с нуля
	tsaDown  bool
	lag      time.Duration // задержка ответа TSA на следующей метке

	seq       uint64
	accepted  []uint64
	promises  map[uint64]proof.Promise
	pending   []uint64 // отвергнутые до якоря: сборщик повторит
	lastOK    time.Time
	armed     bool      // принять запись в окне между ответом TSA и новым якорем
	slow      bool      // следующая метка — с записью в пути, пока она идёт
	onAnswer  func()    // крючок TSA после ответа: отпустить запись в пути
	paused    bool      // монотонные часы стояли: до метки тревога о часах законна
	pauseAt   time.Time // приём на паузе перестановки якоря с этого момента
	signing   bool      // идёт метка
	signed    bool      // TSA уже ответила на эту метку
	excursion bool      // часы хоста шагнули назад на секунды: NTP вернёт их, пока запись в пути (Q-71)
	trace     []string
	fails     []string
	alarms    uint64
}

func (c *clockSim) host() time.Time {
	el := c.now.Sub(c.t0)
	return c.now.Add(c.hostOff + time.Duration(float64(el)*c.hostPPM/1e6))
}

func (c *clockSim) mono() time.Duration {
	el := c.now.Sub(c.t0)
	return c.monoBase + el + time.Duration(float64(el)*c.monoPPM/1e6)
}

func (c *clockSim) note(format string, args ...any) {
	c.trace = append(c.trace, c.now.Format("01-02 15:04:05.0")+" "+fmt.Sprintf(format, args...))
}

func (c *clockSim) fail(format string, args ...any) {
	c.fails = append(c.fails, fmt.Sprintf(format, args...))
}

func runClockSim(t *testing.T, seed uint64) string {
	c := &clockSim{t: t, rng: mrand.New(mrand.NewPCG(seed, seed^0x9e3779b9)), promises: map[uint64]proof.Promise{}}
	c.t0 = time.Date(2026, 10, 11, 10, 0, 0, 0, time.UTC).Add(time.Duration(c.rng.Int64N(int64(time.Second))))
	c.now = c.t0
	c.monoBase = time.Duration(c.rng.Int64N(int64(1000 * time.Hour)))
	// Часы хоста: верные, чуть впереди или позади, сильно впереди или позади.
	offs := []time.Duration{0, 300 * time.Millisecond, -300 * time.Millisecond, 5 * time.Second, -5 * time.Second, 40 * time.Second, -40 * time.Second, 3 * time.Minute, -3 * time.Minute}
	c.hostOff = offs[c.rng.IntN(len(offs))]
	c.monoPPM = float64(c.rng.IntN(201) - 100)
	if c.rng.IntN(2) == 0 {
		c.hostPPM = c.monoPPM // без NTP: один кварц
	}
	c.note("часы хоста %+v, уход хоста %+.0f ppm, монотонных %+.0f ppm", c.hostOff, c.hostPPM, c.monoPPM)

	cfg := testConfig(t)
	open := func() {
		s, err := Open(cfg, Options{Logger: quiet, NoBackground: true, Now: c.host, Mono: c.monoHook})
		if err != nil {
			c.fail("открытие: %v", err)
			return
		}
		s.tsaLocal.Now = c.tsaHook
		s.needAnchor = true // так в serve с TSA
		c.s = s
	}
	open()
	defer func() {
		if c.s != nil {
			c.s.Close()
		}
	}()
	for step := 0; step < 220 && len(c.fails) == 0 && c.s != nil; step++ {
		switch r := c.rng.IntN(100); {
		case r < 35:
			c.ingest()
		case r < 42:
			c.armed = true // запись в окне следующей метки
			c.note("следующая метка — с записью между ответом TSA и якорем")
		case r < 47:
			c.tsaDown = !c.tsaDown
			c.note("TSA down=%v", c.tsaDown)
		case r < 50:
			jump := []time.Duration{2 * time.Second, 20 * time.Second, 5 * time.Minute, 2 * time.Hour}[c.rng.IntN(4)]
			if c.rng.IntN(2) == 0 {
				jump = -jump
			}
			c.hostOff += jump
			c.note("часы хоста прыгнули на %v", jump)
		case r < 53:
			c.s.Close()
			c.s = nil
			c.note("хранилище перезапущено")
			open()
		case r < 56:
			// Сон хоста или пауза ВМ: монотонные часы стоят, истина идёт;
			// часы хоста догоняет NTP или они стоят тоже. Запись, бывшая в
			// пути, может застрять до первой метки.
			d := []time.Duration{10 * time.Second, 9 * time.Minute, 2 * time.Hour}[c.rng.IntN(3)]
			c.monoBase -= d + time.Duration(float64(d)*c.monoPPM/1e6) // за паузу — ни шага, и назад тоже
			host := "догнаны"
			if c.rng.IntN(2) == 0 {
				c.hostOff -= d
				host = "стояли"
			}
			c.now = c.now.Add(d)
			c.paused = true
			c.slow = c.slow || c.rng.IntN(2) == 0
			c.note("пауза %v, часы хоста %s; запись в пути на метке: %v", d, host, c.slow)
		case r < 58:
			c.slow = true
			c.note("следующая метка — с записью в пути")
		case r < 60:
			// Часы хоста шагнули назад на 2 минуты, и сразу — метка с
			// записью в пути (NTP может шагнуть их обратно, пока она в
			// пути): синхронизация гипервизора против NTP (Q-71).
			c.advance(time.Minute) // метка по расписанию — шкала по часам хоста
			c.hostOff -= 2 * time.Minute
			c.slow, c.excursion = true, true
			c.note("часы хоста шагнули назад на 2 мин; следующая метка — с записью в пути")
			c.advance(time.Second)
		default:
			ds := []time.Duration{time.Second, 10 * time.Second, time.Minute, 10 * time.Minute, time.Hour, 6 * time.Hour, 26 * time.Hour, 3 * 24 * time.Hour}
			w := []int{20, 20, 15, 15, 10, 8, 6, 6}
			c.advance(ds[pick(c.rng, w)])
		}
	}
	if len(c.fails) == 0 && c.s != nil {
		c.finish()
	}
	if len(c.fails) == 0 {
		return ""
	}
	from := 0
	if _, single := os.LookupEnv("CLOCKSIM_SEED"); !single {
		from = max(0, len(c.trace)-40)
	}
	return strings.Join(c.fails[:min(len(c.fails), 4)], "\n") + "\nход:\n  " + strings.Join(c.trace[from:], "\n  ")
}

func pick(rng *mrand.Rand, w []int) int {
	sum := 0
	for _, x := range w {
		sum += x
	}
	n := rng.IntN(sum)
	for i, x := range w {
		if n < x {
			return i
		}
		n -= x
	}
	return len(w) - 1
}

// tsaHook — часы локальной TSA, их зовёт подпись: запрос идёт до подписи,
// ответ — после; недоступная TSA отвечает меткой, которую хранилище не
// примет (после конца срока её сертификата).
func (c *clockSim) tsaHook() time.Time {
	before := c.lag * time.Duration(c.rng.IntN(101)) / 100
	c.now = c.now.Add(before)
	gen := c.now
	c.now = c.now.Add(c.lag - before)
	c.signed = c.signing
	if f := c.onAnswer; f != nil {
		c.onAnswer = nil
		f()
	}
	if c.tsaDown {
		return time.Date(2100, 1, 1, 0, 0, 0, 0, time.UTC)
	}
	return gen
}

// monoHook — монотонные часы; armed — первый их вызов после ответа TSA
// (якорь ещё прежний, токена в цепи нет) принимает запись: она ложится в
// звено токена, время звена — уже по новому якорю.
func (c *clockSim) monoHook() time.Duration {
	m := c.mono()
	if c.armed && c.signing && c.signed {
		c.armed, c.signing = false, false
		c.note("запись в окне между ответом TSA и якорем")
		c.ingest()
	}
	return m
}

// ingest — сборщик шлёт запись (и повторяет отвергнутые до якоря).
func (c *clockSim) ingest() {
	if len(c.pending) == 0 {
		c.seq++
		c.pending = append(c.pending, c.seq)
	}
	for len(c.pending) > 0 {
		q := c.pending[0]
		res, err := c.s.Ingest("abs-core", []Incoming{{Seq: q, Body: []byte(fmt.Sprintf("record %d", q))}})
		if errors.Is(err, ErrNoAnchor) {
			paused := c.reanchoring()
			if paused && c.pauseAt.IsZero() {
				c.pauseAt = c.now
			}
			switch {
			case paused && !c.tsaDown && c.now.Sub(c.pauseAt) > 2*time.Minute:
				c.fail("приём на паузе перестановки якоря %v, TSA отвечает", c.now.Sub(c.pauseAt))
			case !paused && !c.lastOK.IsZero() && c.now.Sub(c.lastOK) < time.Hour && !c.tsaDown && !c.restartedSince():
				c.fail("приём закрыт без причины: последняя метка %v назад, TSA отвечает", c.now.Sub(c.lastOK))
			}
			return
		}
		c.pauseAt = time.Time{}
		if err != nil {
			c.fail("приём записи %d: %v", q, err)
			return
		}
		c.accepted = append(c.accepted, q)
		c.promises[q] = *res[0].Promise
		c.pending = c.pending[1:]
	}
	// Тик цепи (фоновых циклов в симуляции нет): звено — за секунду после
	// приёма, а не на следующей метке, иначе в звено записи ложились бы
	// листья на минуты позже и обещание «нарушала» бы сама симуляция.
	// Запись посреди метки звено не сворачивает: оно — звено токена.
	if !c.signing {
		if err := c.s.flush(); err != nil {
			c.fail("сброс цепи: %v", err)
		}
	}
	c.checkAlarms()
}

// checkAlarms — тревога о часах после приёма: при верных часах хоста и
// идущих монотонных она ложная.
func (c *clockSim) checkAlarms() {
	if n := c.s.clockCapped.Load(); n > c.alarms {
		c.alarms = n
		if d := c.host().Sub(c.now); d < 5*time.Second && d > -5*time.Second && c.hostPPM == 0 && !c.paused {
			c.fail("ложная тревога: часы хоста отличаются от истины на %v", d)
		}
	}
}

// reanchoring — приём на паузе перестановки якоря (Q-59): законный отказ.
func (c *clockSim) reanchoring() bool {
	c.s.mu.Lock()
	defer c.s.mu.Unlock()
	return c.s.reanchoring
}

// withSlow — метка (stamp) с записью в пути: запись взяла время приёма, а до
// журнала улик не дойдёт (scopeMu), пока метка не кончится, — или ляжет в
// момент ответа TSA, пока метка её ждёт (барьер stampOnce). Пока запись
// держит замок, часов она не читает; отпускает её горутина, запущенная
// после того, как метка подвинула часы (tsaHook), а метка видит, что она
// легла, под s.mu — порядок есть в обе стороны. Пока она в пути, часы хоста,
// отстающие от истины, могут шагнуть к ней (NTP).
//
// С записью между ответом TSA и якорем (armed) — не на одной метке: та идёт
// из этой же горутины и ждала бы scopeMu, который держит сама симуляция.
func (c *clockSim) withSlow(stamp func() error) error {
	if !c.slow || c.armed {
		return stamp()
	}
	c.slow = false
	c.seq++
	q := c.seq
	type result struct {
		res []Result
		err error
	}
	done := make(chan result, 1)
	c.s.scopeMu.Lock()
	go func() {
		res, err := c.s.Ingest("abs-core", []Incoming{{Seq: q, Body: []byte(fmt.Sprintf("record %d", q))}})
		done <- result{res, err}
	}()
	var r result
	inFlight := false
	for !inFlight {
		c.s.mu.Lock()
		inFlight = c.s.sources["abs-core"].inflight[q]
		c.s.mu.Unlock()
		select {
		case r = <-done: // приём закрыт: запись не в пути, сборщик повторит
			c.s.scopeMu.Unlock()
			c.pending = append(c.pending, q)
			c.note("запись %d не принята: %v", q, r.err)
			return stamp()
		default:
		}
		time.Sleep(10 * time.Microsecond)
	}
	c.checkAlarms() // время приёма взято: тревога — по часам этого момента
	early := c.rng.IntN(2) == 0
	if early {
		c.onAnswer = func() { go c.s.scopeMu.Unlock() }
		c.note("запись %d в пути до ответа TSA", q)
	} else {
		c.note("запись %d в пути всю метку", q)
	}
	excursion := c.excursion
	c.excursion = false
	if c.hostOff < -5*time.Second && (excursion || c.rng.IntN(2) == 0) {
		c.hostOff = 0
		c.note("NTP шагнул часы хоста к истине, пока запись в пути")
	}
	if excursion || c.rng.IntN(2) == 0 {
		// Пока запись в пути, проходят секунды и в цепь ложится событие
		// (молчание, связь, ключ): его время — по шкале (Q-71).
		d := time.Duration(1+c.rng.IntN(12)) * time.Second
		if excursion {
			d = time.Duration(7+c.rng.IntN(6)) * time.Second
		}
		c.now = c.now.Add(d)
		c.s.appendJSONEvent(auditchain.EventSilence, "pipelock", "", map[string]any{"since": c.now.UTC(), "expect_every": "10s"})
		c.note("через %v, пока запись в пути, — событие в цепи", d)
	}
	err := stamp()
	if !early || c.onAnswer != nil {
		c.onAnswer = nil
		c.s.scopeMu.Unlock()
	}
	r = <-done
	switch {
	case r.err != nil:
		c.fail("приём записи %d, бывшей в пути: %v", q, r.err)
	default:
		c.accepted = append(c.accepted, q)
		c.promises[q] = *r.res[0].Promise
		if ferr := c.s.flush(); ferr != nil {
			c.fail("сброс цепи: %v", ferr)
		}
	}
	return err
}

func (c *clockSim) restartedSince() bool {
	for i := len(c.trace) - 1; i >= 0; i-- {
		if strings.Contains(c.trace[i], "хранилище перезапущено") {
			return true
		}
		if strings.Contains(c.trace[i], "метка поставлена") {
			return false
		}
	}
	return false
}

// advance — проходит время; фоновые циклы хранилища (метки по расписанию,
// поддержание якоря) — шагом в минуту (у хранилища повтор чаще — на
// проверяемое это не влияет, а симуляция идёт быстрее).
func (c *clockSim) advance(d time.Duration) {
	end := c.now.Add(d)
	nextStamp := c.now
	for c.now.Before(end) && len(c.fails) == 0 {
		c.now = minT(end, c.now.Add(time.Minute))
		if !c.now.Before(nextStamp) {
			c.stamp()
			nextStamp = c.now.Add(10 * time.Minute)
		}
		clockSimBackground(c)
	}
}

func minT(a, b time.Time) time.Time {
	if a.Before(b) {
		return a
	}
	return b
}

// stamp — метка по расписанию (tsa.every). При лежащей TSA попытка
// кончается отказом; вместо неё — сброс цепи, как в начале попытки
// (подписи P-256 на каждую неудачу сделали бы симуляцию долгой).
func (c *clockSim) stamp() {
	if c.tsaDown {
		if err := c.s.flush(); err != nil {
			c.fail("сброс цепи: %v", err)
		}
		return
	}
	c.lag = []time.Duration{0, 200 * time.Millisecond, 2 * time.Second, 12 * time.Second, 25 * time.Second, 29 * time.Second}[c.rng.IntN(6)]
	var head uint64
	err := c.withSlow(func() error {
		c.signing, c.signed = true, false
		var err error
		head, err = c.s.Stamp(context.Background())
		c.signing, c.signed = false, false
		return err
	})
	switch {
	case errors.Is(err, errReanchorPending) || errors.Is(err, errRecordsInFlight):
		c.note("метка не вышла — запись в пути: %v", err)
	case err != nil && !c.tsaDown:
		c.fail("метка при живой TSA: %v", err)
	case err == nil && head > 0:
		c.lastOK, c.paused = c.now, false
		c.note("метка поставлена (ответ %v)", c.lag)
	}
}

// finish — TSA жива, последняя метка: всё принятое должно пройти проверку.
func (c *clockSim) finish() {
	c.tsaDown = false
	c.advance(time.Minute)
	c.ingest()
	c.now = c.now.Add(2 * time.Second)
	c.lag = 0
	if _, err := c.s.stampNow(context.Background()); err != nil {
		c.fail("последняя метка: %v", err)
		return
	}
	trust := trustOf(c.t, c.s)
	bad := 0
	for _, q := range c.accepted {
		b, err := c.s.Proof("abs-core", q, false)
		if err != nil {
			c.fail("пакет %d: %v", q, err)
			return
		}
		r := proof.Verify(b, trust)
		if r.Valid() {
			if err := proof.CheckPromise(c.promises[q], r, b, false); err != nil {
				bad++
				if bad <= 2 {
					c.fail("обещание по законной улике %d не выполнено: %v", q, err)
				}
			}
			continue
		}
		bad++
		if bad <= 2 {
			var why []string
			for _, ch := range r.Checks {
				if !ch.OK {
					why = append(why, ch.Name+": "+ch.Detail)
				}
			}
			c.fail("законная улика %d не прошла: %s", q, strings.Join(why, "; "))
		}
	}
	if bad > 2 {
		c.fail("и ещё %d", bad-2)
	}
	// Вся цепь одним пакетом за окно: при любых часах хоста время приёма
	// каждой улики сходится с метками вокруг неё, и принятое — в пакете.
	r, seqs, err := wholeChainWindow(c.s, trust)
	switch {
	case err != nil:
		c.fail("пакет за окно: %v", err)
	case !r.Valid():
		c.fail("пакет за окно не проходит: %s", failedChecks(r))
	case len(seqs["abs-core"]) != len(c.accepted):
		c.fail("в пакете за окно %d улик, принято %d", len(seqs["abs-core"]), len(c.accepted))
	}
	// И пакетом по источнику: цепочка abs-core сходится, принятое — в ней.
	// Окно закрывает предпоследняя метка, и её время должно быть позже всех
	// прежних: после перезапуска метка якоря и метка, что открывает приём,
	// ложатся в одну секунду, и закрывающей стала бы первая из них — запись,
	// принятая после второй, честно лежала бы за краем (Q-45).
	c.now = c.now.Add(2 * time.Second)
	if _, err := c.s.stampNow(context.Background()); err != nil {
		c.fail("метка перед пакетом по источнику: %v", err)
		return
	}
	sr, err := wholeChainSource(c.s, "abs-core", trust)
	switch {
	case err != nil:
		c.fail("пакет по источнику: %v", err)
	case !sr.Valid():
		c.fail("пакет по источнику не проходит: %s", sourceFailedChecks(sr))
	case sr.Records != len(c.accepted):
		c.fail("в пакете по источнику %d улик, принято %d", sr.Records, len(c.accepted))
	}
	switch mr, ok, err := midChainSource(c.s, "abs-core", trust); {
	case err != nil:
		c.fail("пакет по источнику от середины цепи: %v", err)
	case ok && (!mr.Valid() || mr.FromStart):
		c.fail("пакет по источнику от середины цепи не проходит: %s", sourceFailedChecks(mr))
	}
}

// clockSimBackground — шаг keepAnchor: якорь несвеж — метка сейчас, даже в
// простой (при лежащей TSA попытка кончится отказом — её нет, см. stamp).
func clockSimBackground(c *clockSim) {
	if !c.s.anchorStale() || c.tsaDown {
		return
	}
	c.lag = []time.Duration{0, 200 * time.Millisecond, 2 * time.Second}[c.rng.IntN(3)]
	err := c.withSlow(func() error {
		c.signing, c.signed = true, false
		_, err := c.s.stampNow(context.Background())
		c.signing, c.signed = false, false
		return err
	})
	switch {
	case errors.Is(err, errReanchorPending) || errors.Is(err, errRecordsInFlight):
		c.note("метка якоря не вышла — запись в пути: %v", err)
		return
	case err != nil:
		c.fail("метка якоря при живой TSA: %v", err)
		return
	}
	c.lastOK, c.paused = c.now, false
	c.note("метка якоря (ответ %v)", c.lag)
}
