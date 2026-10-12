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

	"evidencestore/internal/proof"
)

// Симуляция часов приёма: истинное время задаёт TSA (метка округлена до
// секунды), часы хоста смещены, прыгают и уходят, монотонные часы уходят
// (без NTP — тем же ходом, что часы хоста), ответ TSA идёт до 25 с, TSA
// пропадает, хранилище простаивает сутками и перезапускается, записи
// приходят и в окно между токеном новой метки в цепи и новым якорем. После
// последней метки каждая принятая запись должна пройти проверку
// (время приёма между T1 − 1 мин и T2 + 1 с); приём не закрыт, пока TSA
// отвечает; верные часы хоста — не тревога.
//
// CLOCKSIM_SEEDS — сценариев, CLOCKSIM_SEED — один сценарий.

func TestClockSim(t *testing.T) {
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

	seq      uint64
	accepted []uint64
	pending  []uint64 // отвергнутые до якоря: сборщик повторит
	lastOK   time.Time
	armed    bool // принять запись в окне между токеном и якорем
	signing  bool // идёт метка
	trace    []string
	fails    []string
	alarms   uint64
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
	c := &clockSim{t: t, rng: mrand.New(mrand.NewPCG(seed, seed^0x9e3779b9))}
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
			c.note("следующая метка — с записью в окне")
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
	if c.tsaDown {
		return time.Date(2100, 1, 1, 0, 0, 0, 0, time.UTC)
	}
	return gen
}

// monoHook — монотонные часы; armed — первый их вызов после подписи метки
// (токен уже в цепи, якорь ещё прежний) принимает запись.
func (c *clockSim) monoHook() time.Duration {
	m := c.mono()
	if c.armed && c.signing {
		c.armed, c.signing = false, false
		c.note("запись в окне между токеном и якорем")
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
		_, err := c.s.Ingest("abs-core", []Incoming{{Seq: q, Body: []byte(fmt.Sprintf("record %d", q))}})
		if errors.Is(err, ErrNoAnchor) {
			if !c.lastOK.IsZero() && c.now.Sub(c.lastOK) < time.Hour && !c.tsaDown && !c.restartedSince() {
				c.fail("приём закрыт без причины: последняя метка %v назад, TSA отвечает", c.now.Sub(c.lastOK))
			}
			return
		}
		if err != nil {
			c.fail("приём записи %d: %v", q, err)
			return
		}
		c.accepted = append(c.accepted, q)
		c.pending = c.pending[1:]
	}
	if n := c.s.clockCapped.Load(); n > c.alarms {
		c.alarms = n
		if d := c.host().Sub(c.now); d < 5*time.Second && d > -5*time.Second && c.hostPPM == 0 {
			c.fail("ложная тревога: часы хоста отличаются от истины на %v", d)
		}
	}
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
	c.lag = []time.Duration{0, 200 * time.Millisecond, 2 * time.Second, 12 * time.Second, 25 * time.Second}[c.rng.IntN(5)]
	c.signing = true
	head, err := c.s.Stamp(context.Background())
	c.signing = false
	switch {
	case err != nil && !c.tsaDown:
		c.fail("метка при живой TSA: %v", err)
	case err == nil && head > 0:
		c.lastOK = c.now
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
}

// clockSimBackground — шаг keepAnchor: якорь несвеж — метка сейчас, даже в
// простой (при лежащей TSA попытка кончится отказом — её нет, см. stamp).
func clockSimBackground(c *clockSim) {
	if !c.s.anchorStale() || c.tsaDown {
		return
	}
	c.lag = []time.Duration{0, 200 * time.Millisecond, 2 * time.Second}[c.rng.IntN(3)]
	c.signing = true
	_, err := c.s.stampNow(context.Background())
	c.signing = false
	if err != nil {
		c.fail("метка якоря при живой TSA: %v", err)
		return
	}
	c.lastOK = c.now
	c.note("метка якоря (ответ %v)", c.lag)
}
