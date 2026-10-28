package store

import (
	"context"
	"errors"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Nikolay1994Kaz/evidencestore/internal/config"
	"github.com/Nikolay1994Kaz/evidencestore/internal/proof"
)

// Q-72 (заход 28.10, третий): зависшая копия keyring.dat в keys.backup_dir (README, Known
// limitations: «A stalled keys.backup_dir stalls the intake and the
// time-stamps … nothing is lost, the collectors keep the lines»). Пока копия
// висит, ensureScope держит scopeMu, и запись, уже взявшая время приёма,
// стоит в пути. Если копия висит дольше срока обещания и за это время в цепь
// ложится что-то со временем шкалы (хвосты метки, отложенной барьером, —
// stall=metka; запись другого источника, тоже ждавшая scopeMu, — stall=source),
// честное хранилище подписывает обещание, которое уже нельзя выполнить:
// esverify -promise его обвиняет. Часы хоста верны, TSA мгновенна.
func TestStalledKeyBackupKeepsPromise(t *testing.T) {
	for _, mode := range []string{"stamp", "source"} {
		t.Run(mode, func(t *testing.T) {
			saved := reanchorWait
			reanchorWait = 20 * time.Millisecond
			defer func() { reanchorWait = saved }()
			truth := newClock()
			var mono atomic.Int64
			mono.Store(int64(1000 * time.Hour))
			advance := func(d time.Duration) {
				truth.add(d)
				mono.Add(int64(d))
			}
			cfg := testConfig(t, func(c *config.Config) {
				c.Sources = append(c.Sources, config.Source{Name: "web", ContentType: "syslog", RetentionMonths: 1})
			})
			s, err := Open(cfg, Options{Logger: quiet, Now: truth.now, NoBackground: true, Mono: func() time.Duration { return time.Duration(mono.Load()) }})
			if err != nil {
				t.Fatal(err)
			}
			defer s.Close()
			s.tsaLocal.Now = truth.now
			ingest(t, s, "abs-core", 1, 1)
			ingest(t, s, "web", 1, 1)
			mustStamp(t, s) // якорь
			s.needAnchor = true
			advance(time.Minute)

			s.scopeMu.Lock() // копия keyring.dat в keys.backup_dir висит
			type out struct {
				res []Result
				err error
			}
			run := func(src string, seq uint64) chan out {
				ch := make(chan out, 1)
				go func() {
					res, err := s.Ingest(src, []Incoming{{Seq: seq, Body: []byte(src + " event")}})
					ch <- out{res, err}
				}()
				for {
					s.mu.Lock()
					taken := s.sources[src].inflight[seq]
					s.mu.Unlock()
					if taken {
						return ch
					}
					time.Sleep(time.Millisecond)
				}
			}
			a := run("abs-core", 2) // взяла время приёма и ждёт копию
			advance(65 * time.Second)
			var w chan out
			switch mode {
			case "stamp":
				// Метка в это время (оператор, расписание): хвосты — в цепь,
				// барьер не дождался записи — отсрочка, как обещает README.
				if _, err := s.StampNow(context.Background()); !errors.Is(err, ErrStampDeferred) {
					t.Fatalf("метка при зависшей копии: %v", err)
				}
			case "source":
				w = run("web", 2) // запись другого источника тоже ждёт копию
			}
			advance(5 * time.Second)
			s.scopeMu.Unlock() // копия доехала: записи ложатся
			ra := <-a
			if w != nil {
				<-w
			}
			if ra.err != nil {
				// Не принята, обещания нет: сборщик повторит с новым временем
				// приёма. Так можно — лишь бы записи не было в цепи.
				if _, err := s.Proof("abs-core", 2, false); err == nil {
					t.Fatalf("запись в цепи, а приём ответил ошибкой: %v", ra.err)
				}
				t.Logf("запись не принята (повторит сборщик): %v", ra.err)
				return
			}
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
			p := *ra.res[0].Promise
			t.Logf("abs-core/2: receive time %s, deadline %s", time.Unix(0, p.ReceivedAt).UTC().Format(time.TimeOnly), time.Unix(0, p.Deadline).UTC().Format(time.TimeOnly))
			from := uint64(0)
			if b.Lower != nil {
				t.Logf("lower subject %s", b.Lower.Inclusion.Leaf.Subject)
			}
			for _, l := range b.Links {
				t.Logf("link %d at %s (record link %d, from %d)", l.Seq, time.Unix(0, l.UnixNano).UTC().Format("15:04:05.000"), r.LinkSeq, from)
			}
			if err := checkBoth(t, s, p, r, b); err != nil || !r.Valid() {
				t.Fatalf("честное хранилище: пакет %s; обещание: %v", r.Verdict(), err)
			}
		})
	}
}
