package collector

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/Nikolay1994Kaz/evidencestore/internal/config"
	"github.com/Nikolay1994Kaz/evidencestore/internal/evidence"
	"github.com/Nikolay1994Kaz/evidencestore/internal/evlog"
	"github.com/Nikolay1994Kaz/evidencestore/internal/input"
	"github.com/Nikolay1994Kaz/evidencestore/internal/metrics"
	"github.com/Nikolay1994Kaz/evidencestore/internal/pginput"
	"github.com/Nikolay1994Kaz/evidencestore/internal/store"
)

// fakeSource — источник не из файлов: пачки записей по порядку, у каждой
// место (cursor) — её номер. Как база со слотом репликации, он отдаёт заново
// всё, что новее места, с которым вход открыли. Переживает «перезапуски»
// сборщика: каждый сборщик получает свой fakeInput над тем же источником.
type fakeSource struct {
	mu      sync.Mutex
	batches [][]string // пачка i (с единицы) — место i
	gapAt   map[int]string
	wake    chan struct{}
}

func newSource() *fakeSource {
	return &fakeSource{gapAt: map[int]string{}, wake: make(chan struct{}, 16)}
}

func (s *fakeSource) add(bodies ...string) {
	s.mu.Lock()
	s.batches = append(s.batches, bodies)
	s.mu.Unlock()
	select {
	case s.wake <- struct{}{}:
	default:
	}
}

// fakeInput — input.Input над fakeSource.
type fakeInput struct {
	src    *fakeSource
	sink   input.Sink
	opened uint64 // место, с которым открыли
	pos    int    // место после последней отданной пачки
	closed bool
}

func (f *fakeInput) Open(cursor uint64, sink input.Sink) error {
	f.opened, f.pos, f.sink = cursor, int(cursor), sink
	return nil
}

func (f *fakeInput) Read() (int, error) {
	f.src.mu.Lock()
	defer f.src.mu.Unlock()
	n := 0
	for f.pos < len(f.src.batches) {
		next := f.pos + 1
		if why, ok := f.src.gapAt[next]; ok {
			delete(f.src.gapAt, next)
			if err := f.sink.Gap(why); err != nil {
				return n, err
			}
		}
		var bodies [][]byte
		for _, b := range f.src.batches[f.pos] {
			bodies = append(bodies, []byte(b))
		}
		if _, err := f.sink.Emit(bodies, uint64(next)); err != nil {
			return n, err
		}
		f.pos = next
		n += len(bodies)
	}
	return n, nil
}

func (f *fakeInput) ReadAll(context.Context) (int, error) { return f.Read() }

func (f *fakeInput) Wait(ctx context.Context, d time.Duration) {
	select {
	case <-ctx.Done():
	case <-f.src.wake:
	case <-time.After(d):
	}
}

func (f *fakeInput) Close() error { f.closed = true; return nil }

// Metrics — показатели входа: свой и с меткой, как у очереди тревог.
func (f *fakeInput) Metrics() []metrics.Family {
	return []metrics.Family{
		metrics.One("escollect_fake_position", "where the fake input stands", metrics.Gauge, float64(f.pos)),
		{Name: "escollect_alerts_waiting", Help: "alerts not yet delivered to a notify target", Type: metrics.Gauge,
			Samples: []metrics.Sample{{Labels: [][2]string{{"target", "telegram"}}, Value: 2}}},
	}
}

// inputRig — стенд, где сборщик читает не файл, а вход.
func inputRig(t *testing.T) (*rig, *fakeSource) {
	t.Helper()
	r := newRig(t)
	r.cfg.File, r.cfg.FromStart = "", false
	src := newSource()
	r.cfg.in = &fakeInput{src: src}
	if err := r.cfg.validate(); err != nil {
		t.Fatal(err)
	}
	return r, src
}

// again — сборщик после «перезапуска»: новый вход над тем же источником.
func (r *rig) again(t *testing.T, src *fakeSource) (*Collector, *fakeInput) {
	t.Helper()
	in := &fakeInput{src: src}
	r.cfg.in = in
	return r.collector(t), in
}

// Записи входа доходят до хранилища под номерами подряд, место входа
// переживает перезапуск, и вход продолжает ровно с него.
func TestInputDeliversAndResumesFromItsCursor(t *testing.T) {
	r, src := inputRig(t)
	c, in := r.again(t, src)
	src.add("a")
	src.add("b1", "b2")
	cycle(t, c)
	if got := strings.Join(r.bodies(t), ","); got != "a,b1,b2" {
		t.Fatalf("принято %q", got)
	}
	if c.Pending() != 0 || c.Acked() != 3 {
		t.Fatalf("pending %d, acked %d", c.Pending(), c.Acked())
	}
	c.Close()
	if !in.closed {
		t.Fatal("вход не закрыт вместе со сборщиком")
	}
	if _, err := os.Stat(filepath.Join(r.cfg.SpoolDir, "files.json")); err == nil {
		t.Fatal("у входа не из файлов появился files.json")
	}

	c, in = r.again(t, src)
	if in.opened != 2 {
		t.Fatalf("вход открыт с места %d, ожидали 2", in.opened)
	}
	src.add("c")
	cycle(t, c)
	if got := strings.Join(r.bodies(t), ","); got != "a,b1,b2,c" {
		t.Fatalf("после перезапуска принято %q", got)
	}
}

// Место входа лежит в записи буфера. Когда доставленное из буфера ушло, оно
// остаётся в снимке input.json — как места файлов в files.json.
func TestInputCursorOutlivesReleasedSpool(t *testing.T) {
	saved := spoolSegmentBytes
	spoolSegmentBytes = 256
	t.Cleanup(func() { spoolSegmentBytes = saved })
	r, src := inputRig(t)
	c, _ := r.again(t, src)
	for i := 0; i < 20; i++ {
		src.add(fmt.Sprintf("record %02d %s", i, strings.Repeat("x", 100)))
		cycle(t, c)
	}
	if c.spool.First() < 10 {
		t.Fatalf("буфер не освобождался: первая позиция %d", c.spool.First())
	}
	c.Close()
	var snap inputState
	if found, err := readJSON(filepath.Join(r.cfg.SpoolDir, "input.json"), &snap); err != nil || !found || snap.Cursor != 20 || !snap.Started {
		t.Fatalf("input.json: %+v, найден %v, %v", snap, found, err)
	}
	c, in := r.again(t, src)
	if in.opened != 20 {
		t.Fatalf("вход открыт с места %d, ожидали 20", in.opened)
	}
	src.add("last")
	cycle(t, c)
	if got := r.bodies(t); len(got) != 21 || got[20] != "last" {
		t.Fatalf("принято %d записей, последняя %q", len(got), got[len(got)-1])
	}
}

// Место сдвигает только последняя запись пачки: у остальных в буфере лежит
// прежнее. Если пачка легла на диск не вся, вход получит её заново.
func TestInputBatchMovesCursorWithItsLastRecord(t *testing.T) {
	r, src := inputRig(t)
	c, _ := r.again(t, src)
	src.add("a")
	src.add("b1", "b2", "b3")
	if _, err := c.ReadOnce(); err != nil {
		t.Fatal(err)
	}
	c.Close()
	var cursors []string
	l, err := evlog.Open(filepath.Join(r.cfg.SpoolDir, "spool"), evlog.Options{AllowRelease: true}, func(_ uint64, data []byte) error {
		rec, err := parseRecord(data)
		if err == nil && rec.kind == kindLine {
			cursors = append(cursors, fmt.Sprintf("%s@%d", rec.body, rec.pos.Offset))
		}
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
	l.Close()
	if got := strings.Join(cursors, " "); got != "a@1 b1@1 b2@1 b3@2" {
		t.Fatalf("места в буфере: %s", got)
	}
}

// Вход знает, что потерял данные: номер пропущен, и хранилище видит пропуск —
// и посреди нумерации, и в её конце (по пульсу).
func TestInputGapIsVisibleToTheStore(t *testing.T) {
	r, src := inputRig(t)
	r.cfg.HeartbeatEvery = config.Duration(time.Millisecond)
	c, _ := r.again(t, src)
	src.add("before")
	cycle(t, c)
	src.gapAt[2] = "the source dropped what the collector had not read"
	src.add("after")
	cycle(t, c)
	if last, _ := r.st.LastSeq("abs-core"); last != 3 {
		t.Fatalf("последний номер %d, ожидали 3 (номер 2 пропущен)", last)
	}
	if _, err := r.st.Proof("abs-core", 2, false); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("номер 2: %v", err)
	}
	// Пропуск в конце: записей после него нет, о нём говорит пульс.
	if err := (sink{c}).Gap("lost at the end"); err != nil {
		t.Fatal(err)
	}
	c.Close()
	c, in := r.again(t, src)
	if in.opened != 2 || c.nextSeq != 5 {
		t.Fatalf("после перезапуска: место %d, следующий номер %d", in.opened, c.nextSeq)
	}
	time.Sleep(5 * time.Millisecond)
	if err := c.SendOnce(context.Background()); err != nil {
		t.Fatal(err)
	}
	src.add("later")
	cycle(t, c)
	got := r.bodies(t)
	if len(got) != 5 || got[0] != "before" || !strings.HasPrefix(got[1], "<нет 2") || got[2] != "after" || !strings.HasPrefix(got[3], "<нет 4") || got[4] != "later" {
		t.Fatalf("принято %q", got)
	}
}

// Падение в любой точке записи на диск — буфер, input.json, state.json, до
// записи и сразу после неё, на первом запуске и потом: после перезапуска вход
// получает ровно то место, до которого его записи легли в буфер, и в хранилище
// каждая запись оказывается один раз, по порядку и без пропусков.
func TestInputSurvivesCrashAtEveryPersistPoint(t *testing.T) {
	batches := [][]string{{"1"}, {"2a", "2b"}, {"3"}, {"4a", "4b", "4c"}}
	want := "1,2a,2b,3,4a,4b,4c"
	crash := errors.New("падение")
	ctx := context.Background()
	for crashAt := 1; ; crashAt++ {
		r, src := inputRig(t)
		// run ведёт сценарий с места, где остановились; crashAt == 0 — без падений.
		fed := 0
		run := func(crashAt int) (crashed bool, points int) {
			in := &fakeInput{src: src}
			r.cfg.in = in
			c, err := New(r.cfg, quiet)
			if err != nil {
				t.Fatalf("точка %d: %v", crashAt, err)
			}
			defer c.Close()
			c.persistHook = func(string) error {
				if points++; points == crashAt {
					return crash
				}
				return nil
			}
			step := func(err error) bool {
				if err != nil && !errors.Is(err, crash) {
					t.Fatalf("точка %d: %v", crashAt, err)
				}
				return err != nil
			}
			if step(c.Bootstrap(ctx)) {
				return true, points
			}
			for {
				_, err := c.ReadOnce()
				if step(err) || step(c.SendOnce(ctx)) {
					return true, points
				}
				if fed == len(batches) {
					return false, points
				}
				src.add(batches[fed]...)
				fed++
			}
		}
		crashed, points := run(crashAt)
		if crashed {
			if again, _ := run(0); again {
				t.Fatalf("точка %d: падение без точки падения", crashAt)
			}
		}
		if got := strings.Join(r.bodies(t), ","); got != want {
			t.Fatalf("падение в точке %d: принято %q, ожидали %q", crashAt, got, want)
		}
		// Точка не достигнута — сценарий пройден целиком, точки кончились.
		// (Достигнута, а сборщик не остановился — запись, чью ошибку он
		// переживает: голова цепи.)
		if points < crashAt {
			if points < 20 {
				t.Fatalf("сценарий прошёл всего %d точек записи: он ничего не проверяет", points)
			}
			return
		}
	}
}

// Цикл Run не спит свою паузу, когда у входа появились данные: вход будит его.
func TestRunWakesWhenTheInputHasData(t *testing.T) {
	r, src := inputRig(t)
	r.cfg.FlushEvery = config.Duration(time.Minute)
	in := &fakeInput{src: src}
	r.cfg.in = in
	c, err := New(r.cfg, quiet)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- c.Run(ctx) }()
	deadline := time.Now().Add(10 * time.Second)
	for i, body := range []string{"first", "second"} {
		time.Sleep(50 * time.Millisecond) // цикл уже ждёт вход
		src.add(body)
		for {
			if last, _ := r.st.LastSeq("abs-core"); last == uint64(i+1) {
				break
			}
			if time.Now().After(deadline) {
				t.Fatalf("запись %q не дошла: цикл спит свою минуту", body)
			}
			time.Sleep(5 * time.Millisecond)
		}
	}
	cancel()
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	c.Close()
}

// Буфер помнит места своего входа: spool_dir, начатый с файлами, с другим
// входом не открывается, и наоборот — иначе вход начал бы с нуля и выдал бы
// всё заново под новыми номерами.
func TestSpoolDirBelongsToItsInput(t *testing.T) {
	r := newRig(t)
	c := r.collector(t)
	appendLines(t, r.cfg.File, "line\n")
	cycle(t, c)
	c.Close()
	file := r.cfg.File
	r.cfg.File, r.cfg.FromStart, r.cfg.in = "", false, &fakeInput{src: newSource()}
	if c, err := New(r.cfg, quiet); err == nil {
		c.Close()
		t.Fatal("буфер файлов открыт с другим входом")
	} else if !strings.Contains(err.Error(), "reading files") {
		t.Fatal(err)
	}

	r2, src := inputRig(t)
	c, _ = r2.again(t, src)
	src.add("x")
	cycle(t, c)
	c.Close()
	r2.cfg.in, r2.cfg.File = nil, file
	if c, err := New(r2.cfg, quiet); err == nil {
		c.Close()
		t.Fatal("буфер входа открыт для чтения файлов")
	} else if !strings.Contains(err.Error(), "another input") {
		t.Fatal(err)
	}
}

// Пустой буфер при input.json со словом «старт» — буфер потерян, а не первый
// запуск: молча начать заново значило бы выдать всё под новыми номерами.
func TestInputLostSpoolIsNotAFirstStart(t *testing.T) {
	r, src := inputRig(t)
	c, _ := r.again(t, src)
	src.add("x")
	cycle(t, c)
	c.Close()
	if err := os.RemoveAll(filepath.Join(r.cfg.SpoolDir, "spool")); err != nil {
		t.Fatal(err)
	}
	r.cfg.in = &fakeInput{src: src}
	if c, err := New(r.cfg, quiet); err == nil {
		c.Close()
		t.Fatal("потерянный буфер принят за первый запуск")
	} else if !strings.Contains(err.Error(), "the spool was lost") {
		t.Fatal(err)
	}
}

// Запись длиннее предела хранилища вход резать должен сам: сборщик не знает
// его формата и молча делить не станет.
func TestInputRecordOverTheStoreLimitIsRefused(t *testing.T) {
	r, src := inputRig(t)
	c, _ := r.again(t, src)
	if _, err := (sink{c}).Emit([][]byte{make([]byte, evidence.MaxBodyLen+1)}, 1); err == nil {
		t.Fatal("запись длиннее предела принята")
	}
	if _, err := (sink{c}).Emit(nil, 1); err == nil {
		t.Fatal("пустая пачка принята")
	}
	if _, err := (sink{c}).Emit([][]byte{make([]byte, evidence.MaxBodyLen)}, 1); err != nil {
		t.Fatal(err)
	}
	if c.Pending() != 1 || c.cursor != 1 {
		t.Fatalf("pending %d, cursor %d", c.Pending(), c.cursor)
	}
}

func TestInputConfig(t *testing.T) {
	pg := func() *pginput.Config {
		return &pginput.Config{DSN: "host=db user=tap dbname=shop", Roles: []string{"agent"}, Tables: []string{"public.accounts"}}
	}
	base := Config{Server: "https://x", CA: "ca", Cert: "c", Key: "k", SpoolDir: "/s", StoreKey: anyKey}
	good := base
	good.Postgres = pg()
	if err := good.validate(); err != nil {
		t.Fatal(err)
	}
	if good.Postgres.Dir != "/s" || good.Postgres.Slot != "evidence_tap" || good.Postgres.Publication != "evidence_pub" || good.Postgres.StatusEvery.D() != 5*time.Second {
		t.Fatalf("умолчания: %+v", good.Postgres)
	}
	both, start, noRoles, badTable := base, base, base, base
	both.Postgres, both.File = pg(), "/a.log"
	start.Postgres, start.FromStart = pg(), true
	noRoles.Postgres = pg()
	noRoles.Postgres.Roles = nil
	badTable.Postgres = pg()
	badTable.Postgres.Tables = []string{"accounts"}
	for name, c := range map[string]Config{"postgres и file": both, "from_start без файлов": start, "без ролей": noRoles, "таблица без схемы": badTable} {
		if err := c.validate(); err == nil {
			t.Errorf("%s: принято", name)
		}
	}
}

// Несколько источников в одном файле настроек: общее — наверху, своё — у
// каждого, и своё перекрывает общее.
func TestLoadConfigsWithSeveralSources(t *testing.T) {
	dir := t.TempDir()
	write := func(body string) string {
		p := filepath.Join(dir, "collector.json")
		if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
		return p
	}
	cfgs, err := LoadConfigs(write(`{"server": "https://store:8443", "ca": "ca.crt", "store_key": "` + anyKey + `", "batch": 64,
		"sources": [
			{"cert": "app.crt", "key": "app.key", "spool_dir": "spool-app", "file": "/var/log/app.log", "batch": 8},
			{"cert": "pg.crt", "key": "pg.key", "spool_dir": "spool-pg",
			 "postgres": {"dsn": "host=db user=tap dbname=shop", "roles": ["agent"], "tables": ["public.accounts"], "dir": "pg"}}]}`))
	if err != nil {
		t.Fatal(err)
	}
	if len(cfgs) != 2 {
		t.Fatalf("%d источников", len(cfgs))
	}
	app, pg := cfgs[0], cfgs[1]
	if app.Server != "https://store:8443" || app.CA != filepath.Join(dir, "ca.crt") || app.Batch != 8 || app.File != "/var/log/app.log" || app.Postgres != nil {
		t.Fatalf("первый источник: %+v", app)
	}
	if pg.Batch != 64 || pg.File != "" || pg.Postgres == nil || pg.Postgres.Dir != filepath.Join(dir, "pg") || pg.SpoolDir != filepath.Join(dir, "spool-pg") {
		t.Fatalf("второй источник: %+v %+v", pg, pg.Postgres)
	}
	// Один источник, по-старому, — тоже список из одного.
	one, err := LoadConfigs(write(`{"server": "https://store:8443", "ca": "ca.crt", "store_key": "` + anyKey + `",
		"cert": "app.crt", "key": "app.key", "spool_dir": "spool", "file": "app.log"}`))
	if err != nil || len(one) != 1 || one[0].File != filepath.Join(dir, "app.log") {
		t.Fatalf("%v %+v", err, one)
	}
	for name, body := range map[string]string{
		"общий spool_dir": `{"server": "https://s", "ca": "ca", "store_key": "` + anyKey + `", "cert": "c", "key": "k", "spool_dir": "one",
			"sources": [{"file": "/a.log"}, {"file": "/b.log"}]}`,
		"пустой список":      `{"server": "https://s", "sources": []}`,
		"незнакомое поле":    `{"server": "https://s", "ca": "ca", "store_key": "` + anyKey + `", "sources": [{"cert": "c", "key": "k", "spool_dir": "s", "file": "/a.log", "fiel": 1}]}`,
		"источник без входа": `{"server": "https://s", "ca": "ca", "store_key": "` + anyKey + `", "sources": [{"cert": "c", "key": "k", "spool_dir": "s"}]}`,
	} {
		if _, err := LoadConfigs(write(body)); err == nil {
			t.Errorf("%s: принято", name)
		}
	}
}

// Страница /metrics: показатели сборщика и его входа с меткой источника; у
// процесса с несколькими источниками одноимённые показатели — один показатель
// с разными метками. Страница отдаёт снимок последнего прохода цикла, а не
// читает поля сборщика из чужого потока.
func TestMetricsPage(t *testing.T) {
	r, src := inputRig(t)
	c, _ := r.again(t, src)
	get := func(cs ...*Collector) string {
		t.Helper()
		srv := httptest.NewServer(MetricsHandler(cs...))
		defer srv.Close()
		resp, err := http.Get(srv.URL + "/metrics")
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		body, _ := io.ReadAll(resp.Body)
		if resp.StatusCode != 200 || !strings.HasPrefix(resp.Header.Get("Content-Type"), "text/plain; version=0.0.4") {
			t.Fatalf("%s %s", resp.Status, resp.Header.Get("Content-Type"))
		}
		return string(body)
	}
	if page := get(c); page != "" {
		t.Fatalf("a page before the first pass of the loop:\n%s", page)
	}
	src.add("a")
	src.add("b1", "b2")
	if _, err := c.ReadOnce(); err != nil {
		t.Fatal(err)
	}
	c.publish()
	page := get(c)
	for _, want := range []string{
		"# TYPE escollect_spool_pending_records gauge\n",
		`escollect_up{source="abs-core"} 1` + "\n",
		`escollect_spool_pending_records{source="abs-core"} 3` + "\n",
		`escollect_issued_seq{source="abs-core"} 3` + "\n",
		`escollect_acked_seq{source="abs-core"} 0` + "\n",
		`escollect_fake_position{source="abs-core"} 2` + "\n",
		`escollect_alerts_waiting{source="abs-core",target="telegram"} 2` + "\n",
		`escollect_loop_timestamp_seconds{source="abs-core"} `,
	} {
		if !strings.Contains(page, want) {
			t.Fatalf("the page lacks %q:\n%s", want, page)
		}
	}
	if strings.Contains(page, `escollect_store_last_contact_timestamp_seconds{source="abs-core"} 0`+"\n") {
		t.Fatal("the store answered at bootstrap, but the page says it never did")
	}
	// Доставили — снимок прежний, пока цикл не сложит новый.
	if err := c.SendOnce(context.Background()); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(get(c), `escollect_spool_pending_records{source="abs-core"} 3`) {
		t.Fatal("the page read the collector's fields past the snapshot")
	}
	c.publish()
	if page := get(c); !strings.Contains(page, `escollect_spool_pending_records{source="abs-core"} 0`) || !strings.Contains(page, `escollect_acked_seq{source="abs-core"} 3`) {
		t.Fatalf("after delivery:\n%s", page)
	}
	// Второй источник того же процесса.
	r2, src2 := inputRig(t)
	c2, _ := r2.again(t, src2)
	c2.source = "pg-agent"
	c2.publish()
	page = get(c, c2)
	if strings.Count(page, "# TYPE escollect_up gauge") != 1 || !strings.Contains(page, `escollect_up{source="abs-core"} 1`) || !strings.Contains(page, `escollect_up{source="pg-agent"} 1`) {
		t.Fatalf("two sources on one page:\n%s", page)
	}
	// Снимок первого источника вторым не испорчен.
	if page := get(c); strings.Contains(page, "pg-agent") {
		t.Fatalf("the first collector's snapshot was changed by the merge:\n%s", page)
	}
	bad := *r.cfg
	bad.MetricsListen = "9465"
	if err := bad.validate(); err == nil {
		t.Fatal("metrics_listen without a host:port form was accepted")
	}
}
