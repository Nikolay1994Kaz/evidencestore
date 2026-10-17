package collector

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"log/slog"
	"maps"
	mrand "math/rand/v2"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"slices"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Nikolay1994Kaz/evidencestore/internal/auditchain"
	"github.com/Nikolay1994Kaz/evidencestore/internal/config"
	"github.com/Nikolay1994Kaz/evidencestore/internal/evidence"
	"github.com/Nikolay1994Kaz/evidencestore/internal/keyring"
	"github.com/Nikolay1994Kaz/evidencestore/internal/pki"
	"github.com/Nikolay1994Kaz/evidencestore/internal/proof"
	"github.com/Nikolay1994Kaz/evidencestore/internal/server"
	"github.com/Nikolay1994Kaz/evidencestore/internal/store"
	"github.com/Nikolay1994Kaz/evidencestore/internal/tsa"
)

// Симуляция сборщика: случайные записи, ротации, переименования, перезапуски
// и падения сборщика в точке записи на диск, отказы хранилища — против
// эталона «что записано». Время виртуальное: сборщик берёт его из c.now.
//
// Мир без разрушений: файлы только переименовываются в своём каталоге,
// приложение переоткрывает журнал быстрее rotateQuiet, а пока сборщик
// стоит, файл, родившийся без него, не уходит с пути или из-под маски
// (иначе сборщику его не увидеть — предел из README). Здесь каждая
// записанная строка доставлена ровно один раз, пропусков в нумерации нет,
// внутри файла — порядок записи.
//
// Мир с разрушениями: ещё удаление, сжатие и copytruncate, в любой момент.
// Повторов и чужих строк нет, теряются только строки разрушенных файлов, и
// всякая потеря видна пропуском в нумерации.
//
// Сверх этого у каждого сценария свой набор помех (simProfile; включена
// случайная часть — так глубокие сочетания встречаются чаще): длинные
// строки (куски), падение сразу после записи на диск и посреди записи
// буфера, потерянные ответы хранилища (принято, а сборщик не узнал), права —
// новый журнал, который сборщику не прочитать, отнятые на время права на
// файл, нечитаемый каталог журнала, spool_dir без записи, — имена logrotate
// dateext. Права администратор возвращает — рано или в конце; эталон тот же.
//
// Хранилище — поддельное в памяти или настоящее (store и сервер приёма по
// mTLS; метки TSA по ходу сценария и в конце). У настоящего каждый принятый
// номер ещё и проходит офлайн-проверку пакета доказательств, как в esverify:
// с обеими границами времени по меткам; каждый пропущенный лежит в цепи
// событием пропуска.
//
// SIM_SEEDS — сценариев на мир с поддельным хранилищем, SIM_REAL_SEEDS — с
// настоящим, SIM_SEED — один сценарий (воспроизвести), SIM_STEPS — шагов в
// сценарии, SIM_KIND — показывать провалы одного вида, SIM_FAULTS — помехи
// вместо случайных: all, none или имена через запятую (simFaultNames).

const (
	simQuiet = 10 * time.Second // rotateQuiet в виртуальном времени
	simFlush = time.Second      // шаг проходов сборщика
	simPiece = 100              // pieceLen: длинная строка — несколько кусков
)

var (
	errSimCrash = errors.New("симуляция: процесс упал здесь")
	errSimLost  = errors.New("симуляция: ответ хранилища потерян")
)

func TestCollectorSim(t *testing.T) {
	def := 60
	if raceBuild {
		def = 10
	}
	seeds, steps := envInt("SIM_SEEDS", def), envInt("SIM_STEPS", 160)
	realSeeds := envInt("SIM_REAL_SEEDS", max(def/20, 1))
	only, single := os.LookupEnv("SIM_SEED")
	certs := simCerts(t)
	// Маленькие сегменты буфера: доставленное освобождается часто, и снимок
	// реестра (files.json) перед освобождением — тоже под проверкой. Мелкие
	// порции чтения и куски строк: несколько записей буфера за проход и
	// длинные строки без мегабайтов.
	savedSeg, savedChunk, savedPiece := spoolSegmentBytes, readChunk, pieceLen
	spoolSegmentBytes, readChunk, pieceLen = 2<<10, 512, simPiece
	t.Cleanup(func() { spoolSegmentBytes, readChunk, pieceLen = savedSeg, savedChunk, savedPiece })
	var worlds []simWorld
	for _, real := range []bool{false, true} {
		worlds = append(worlds,
			simWorld{name: "file", real: real},
			simWorld{name: "glob", glob: true, real: real},
			simWorld{name: "file-destructive", destructive: true, real: real},
			simWorld{name: "glob-destructive", glob: true, destructive: true, real: real},
		)
	}
	for _, w := range worlds {
		name, n := w.name, seeds
		if w.real {
			name, n = w.name+"-real", realSeeds
		}
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			failed, kinds := 0, map[string]int{}
			for i := range n {
				seed := uint64(i) + 1
				if single {
					if i > 0 {
						break
					}
					seed, _ = strconv.ParseUint(only, 10, 64)
				}
				if msg := runSim(t, w, seed, steps, certs); msg != "" {
					failed++
					kind, _, _ := strings.Cut(msg, " ")
					kind, _, _ = strings.Cut(kind, ":")
					kinds[kind]++
					if want := os.Getenv("SIM_KIND"); (want == "" || want == kind) && kinds[kind] <= 3 && (want != "" || failed <= 3) {
						t.Errorf("мир %s, SIM_SEED=%d:\n%s", name, seed, msg)
					}
				}
			}
			if failed > 0 {
				t.Errorf("мир %s: провалено %d из %d сценариев; виды: %v", name, failed, n, kinds)
			}
		})
	}
}

func envInt(name string, def int) int {
	if v, err := strconv.Atoi(os.Getenv(name)); err == nil && v > 0 {
		return v
	}
	return def
}

type simWorld struct {
	name        string
	glob        bool
	destructive bool
	real        bool // настоящее хранилище
}

// simProfile — помехи сценария.
type simProfile struct {
	long      bool // длинные строки — несколько кусков
	after     bool // падение сразу после записи на диск
	torn      bool // падение посреди записи буфера: на диске начало пачки
	flaky     bool // ответы хранилища теряются: принято, а сборщик не узнал
	permNew   bool // logrotate create с правами, которых сборщику не хватает
	permFile  bool // права на файл журнала отняты на время
	permDir   bool // каталог журнала не читается на время
	permSpool bool // spool_dir не пишется на время (права, место)
	dateext   bool // имена logrotate dateext
}

var simFaultNames = []string{"long", "after", "torn", "flaky", "perm-new", "perm-file", "perm-dir", "perm-spool", "dateext"}

func (p *simProfile) flags() []*bool {
	return []*bool{&p.long, &p.after, &p.torn, &p.flaky, &p.permNew, &p.permFile, &p.permDir, &p.permSpool, &p.dateext}
}

// newProfile — помехи сценария: каждая включена с вероятностью 3/5 (или
// как велит SIM_FAULTS).
func newProfile(rng *mrand.Rand) simProfile {
	var p simProfile
	want, set := os.LookupEnv("SIM_FAULTS")
	for i, f := range p.flags() {
		*f = rng.IntN(5) < 3
		if set {
			*f = want == "all" || slices.Contains(strings.Split(want, ","), simFaultNames[i])
		}
	}
	return p
}

func (p simProfile) String() string {
	var on []string
	for i, f := range p.flags() {
		if *f {
			on = append(on, simFaultNames[i])
		}
	}
	if len(on) == 0 {
		return "нет"
	}
	return strings.Join(on, ",")
}

// simCertsDir — сертификаты УЦ, сборщика и сервера приёма и ключ
// поддельного хранилища (одни на все сценарии).
type simCertsDir struct {
	dir     string
	storeSK ed25519.PrivateKey
}

func simCerts(t *testing.T) simCertsDir {
	dir := t.TempDir()
	ca, _ := pki.NewCA("ca")
	pki.WriteCert(filepath.Join(dir, "ca.crt"), ca.Cert)
	cl, _ := ca.Client("abs-core")
	cl.Write(dir, "abs-core")
	srv, _ := ca.Server("127.0.0.1")
	srv.Write(dir, "server")
	_, sk, _ := ed25519.GenerateKey(rand.Reader)
	return simCertsDir{dir: dir, storeSK: sk}
}

// simStore — хранилище симуляции.
type simStore interface {
	attach(c *Collector) // подключить сборщик
	setDown(v bool)      // недоступно
	setFlaky(v bool)     // ответы на приём теряются
	isDown() bool
	isFlaky() bool
	tick() // прошла секунда: настоящее хранилище иногда ставит метку TSA
	// contents — что принято: тела по номерам и последний номер; bad —
	// нарушения (протокола со стороны сборщика, проверки доказательств).
	contents() (bodies map[uint64]string, last uint64, bad []string)
	close()
}

// simLose — теряется ли ответ на n-й приём: детерминированно, 3 из 8.
func simLose(n uint64) bool { return (n*0x9E3779B97F4A7C15)>>61 < 3 }

// --- поддельное хранилище: протокол /v1/state и /v1/ingest в памяти ---

type fakeStore struct {
	mu       sync.Mutex
	sk       ed25519.PrivateKey
	pub      string
	down     bool
	flaky    bool
	reqs     uint64
	bodies   map[uint64]string
	promises map[uint64]proof.Promise
	last     uint64
	position uint64
	bad      []string // нарушения протокола со стороны сборщика
}

func newFakeStore(sk ed25519.PrivateKey) *fakeStore {
	return &fakeStore{
		sk: sk, pub: base64.RawStdEncoding.EncodeToString(sk.Public().(ed25519.PublicKey)),
		bodies: map[uint64]string{}, promises: map[uint64]proof.Promise{},
	}
}

func (s *fakeStore) RoundTrip(req *http.Request) (*http.Response, error) {
	if req.Body != nil {
		defer req.Body.Close()
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	rec := httptest.NewRecorder()
	switch {
	case s.down:
		http.Error(rec, "down", http.StatusServiceUnavailable)
	case req.Method == http.MethodGet && req.URL.Path == "/v1/state":
		json.NewEncoder(rec).Encode(stateResponse{LastSeq: s.last, PublicKey: s.pub})
	case req.Method == http.MethodPost && req.URL.Path == "/v1/ingest":
		s.ingest(rec, req)
		if s.reqs++; s.flaky && simLose(s.reqs) {
			return nil, errSimLost // принято, а ответ не дошёл
		}
	default:
		http.NotFound(rec, req)
	}
	resp := rec.Result()
	resp.Request = req
	return resp, nil
}

func (s *fakeStore) ingest(w http.ResponseWriter, req *http.Request) {
	var in struct {
		Records []struct {
			Seq  uint64 `json:"seq"`
			Body []byte `json:"body"`
		} `json:"records"`
	}
	if err := json.NewDecoder(req.Body).Decode(&in); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	prev := uint64(0)
	for _, r := range in.Records {
		if r.Seq <= prev {
			s.bad = append(s.bad, fmt.Sprintf("протокол: пачка не по возрастанию: %d после %d", r.Seq, prev))
		}
		prev = r.Seq
		if b, ok := s.bodies[r.Seq]; ok && b != string(r.Body) {
			s.bad = append(s.bad, fmt.Sprintf("протокол: номер %d: тело %q, а принято %q", r.Seq, r.Body, b))
			w.WriteHeader(http.StatusConflict)
			json.NewEncoder(w).Encode(errorResponse{Error: "another body", Code: codeSeqConflict})
			return
		} else if !ok && r.Seq <= s.last {
			s.bad = append(s.bad, fmt.Sprintf("протокол: номер %d ниже принятого %d и раньше не приходил", r.Seq, s.last))
		}
	}
	type result struct {
		Seq      uint64         `json:"seq"`
		Status   string         `json:"status"`
		Position uint64         `json:"position"`
		Promise  *proof.Promise `json:"promise"`
	}
	var out struct {
		Results []result `json:"results"`
	}
	for _, r := range in.Records {
		p, ok := s.promises[r.Seq]
		status := statusDuplicate
		if !ok {
			s.position++
			d := sha256.Sum256(r.Body)
			p = proof.Promise{Source: "abs-core", Seq: r.Seq, Position: s.position, Digest: d[:], ReceivedAt: 1, Deadline: 2, PublicKey: s.pub}
			p.Signature = ed25519.Sign(s.sk, proof.PromiseBytes(p))
			s.promises[r.Seq], s.bodies[r.Seq] = p, string(r.Body)
			s.last = max(s.last, r.Seq)
			status = statusAccepted
		}
		out.Results = append(out.Results, result{r.Seq, status, p.Position, &p})
	}
	json.NewEncoder(w).Encode(out)
}

func (s *fakeStore) attach(c *Collector) { c.http = &http.Client{Transport: s} }

func (s *fakeStore) setDown(v bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.down = v
}

func (s *fakeStore) setFlaky(v bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.flaky = v
}

func (s *fakeStore) isDown() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.down
}

func (s *fakeStore) isFlaky() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.flaky
}

func (s *fakeStore) contents() (map[uint64]string, uint64, []string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return maps.Clone(s.bodies), s.last, slices.Clone(s.bad)
}

func (s *fakeStore) tick()  {}
func (s *fakeStore) close() {}

// --- настоящее хранилище: store и сервер приёма по mTLS на сценарий ---

type realStore struct {
	st     *store.Store
	hs     *httptest.Server
	cfg    *config.Config
	down   atomic.Bool
	flaky  atomic.Bool
	reqs   atomic.Uint64
	ticks  int
	closed bool
}

func newRealStore(t *testing.T, certs simCertsDir) (*realStore, error) {
	dir := t.TempDir()
	cfg := &config.Config{
		DataDir: filepath.Join(dir, "data"), RootsDir: filepath.Join(dir, "roots"),
		TLS: config.TLS{Cert: filepath.Join(certs.dir, "server.crt"), Key: filepath.Join(certs.dir, "server.key"),
			ClientCA: filepath.Join(certs.dir, "ca.crt")},
		TSA:     config.TSA{URL: "local"},
		Sources: []config.Source{{Name: "abs-core", ContentType: "syslog"}},
	}
	cfg.Defaults()
	if _, err := store.Init(cfg); err != nil {
		return nil, err
	}
	st, err := store.Open(cfg, store.Options{Logger: quiet, NoBackground: true})
	if err != nil {
		return nil, err
	}
	tlsCfg, err := server.TLSConfig(cfg)
	if err != nil {
		st.Close()
		return nil, err
	}
	r := &realStore{st: st, cfg: cfg}
	h := server.New(cfg, st, quiet).IntakeHandler()
	r.hs = httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		switch {
		case r.down.Load():
			http.Error(w, "down", http.StatusServiceUnavailable)
		case req.URL.Path == "/v1/ingest" && r.flaky.Load() && simLose(r.reqs.Add(1)):
			h.ServeHTTP(httptest.NewRecorder(), req) // принято…
			panic(http.ErrAbortHandler)              // …а ответ не дошёл: соединение оборвано
		default:
			h.ServeHTTP(w, req)
		}
	}))
	r.hs.TLS = tlsCfg
	r.hs.Config.ErrorLog = log.New(io.Discard, "", 0)
	r.hs.StartTLS()
	return r, nil
}

func (r *realStore) attach(*Collector) {} // свой клиент TLS сборщика
func (r *realStore) setDown(v bool)    { r.down.Store(v) }
func (r *realStore) setFlaky(v bool)   { r.flaky.Store(v) }
func (r *realStore) isDown() bool      { return r.down.Load() }
func (r *realStore) isFlaky() bool     { return r.flaky.Load() }

// tick — метка TSA раз в 15 с виртуального времени (если в цепь что-то
// легло): у улик есть нижняя граница T1, и проверка пакета смотрит время.
func (r *realStore) tick() {
	if r.ticks++; r.ticks%15 == 0 {
		r.st.Stamp(context.Background())
	}
}

// contents — тела по номерам из пакетов доказательств; каждый пакет
// проходит офлайн-проверку с обеими границами времени (последняя метка —
// над всеми уликами), каждый пропущенный номер — событие пропуска в цепи.
// После него хранилище закрыто.
func (r *realStore) contents() (map[uint64]string, uint64, []string) {
	bodies := map[uint64]string{}
	var bad []string
	if _, err := r.st.Stamp(context.Background()); err != nil {
		bad = append(bad, "хранилище: метка TSA: "+err.Error())
	}
	last, err := r.st.LastSeq("abs-core")
	if err != nil {
		return bodies, 0, []string{"хранилище: LastSeq: " + err.Error()}
	}
	pub, _ := base64.RawStdEncoding.DecodeString(r.st.PublicKey())
	trust := proof.Trust{StoreKey: ed25519.PublicKey(pub)}
	if a, err := tsa.LoadAuthority(filepath.Join(r.cfg.DataDir, "tsa-local")); err != nil {
		bad = append(bad, "хранилище: TSA: "+err.Error())
	} else {
		trust.TSA = a.Trust()
	}
	var missing []uint64
	for q := uint64(1); q <= last; q++ {
		b, err := r.st.Proof("abs-core", q, true)
		if errors.Is(err, store.ErrNotFound) {
			missing = append(missing, q)
			continue
		}
		if err != nil {
			bad = append(bad, fmt.Sprintf("доказательство: номер %d: %v", q, err))
			continue
		}
		if rep := proof.Verify(b, trust); !rep.Valid() {
			bad = append(bad, fmt.Sprintf("доказательство: номер %d не проходит проверку: %s", q, failedCheck(rep)))
		}
		sealed, err := evidence.Unmarshal(b.Evidence)
		if err == nil {
			var body []byte
			if body, err = keyring.OpenWithDEK(sealed.Envelope, b.DEK); err == nil {
				bodies[q] = string(body)
			}
		}
		if err != nil {
			bad = append(bad, fmt.Sprintf("доказательство: номер %d: тело не вскрыть: %v", q, err))
		}
	}
	r.close() // цепь дописана на диск
	var gaps [][2]uint64
	err = auditchain.ScanLeaves(filepath.Join(r.cfg.DataDir, "chain"), func(_ uint64, l auditchain.Leaf) error {
		if l.Type == auditchain.EventGap && l.Scope == "abs-core" {
			var g struct{ From, To uint64 }
			if err := json.Unmarshal(l.Payload, &g); err != nil {
				return err
			}
			gaps = append(gaps, [2]uint64{g.From, g.To})
		}
		return nil
	})
	if err != nil {
		bad = append(bad, "цепь: "+err.Error())
	}
	for _, q := range missing {
		if !slices.ContainsFunc(gaps, func(g [2]uint64) bool { return g[0] <= q && q <= g[1] }) {
			bad = append(bad, fmt.Sprintf("цепь: номер %d пропущен, а события пропуска нет (пропуски в цепи: %v)", q, gaps))
		}
	}
	return bodies, last, bad
}

func failedCheck(r proof.Report) string {
	for _, c := range r.Checks {
		if !c.OK {
			return c.Name + ": " + c.Detail
		}
	}
	return r.Verdict()
}

func (r *realStore) close() {
	if r.closed {
		return
	}
	r.closed = true
	r.hs.Close()
	r.st.Close()
}

// simLog — журнал сборщика с виртуальным временем симуляции.
type simLog struct {
	slog.Handler
	s *sim
}

func (h simLog) Handle(ctx context.Context, r slog.Record) error {
	r.AddAttrs(slog.String("vt", h.s.now.Format("15:04:05.0")))
	return h.Handler.Handle(ctx, r)
}

func (h simLog) WithAttrs(as []slog.Attr) slog.Handler { return simLog{h.Handler.WithAttrs(as), h.s} }
func (h simLog) WithGroup(g string) slog.Handler       { return simLog{h.Handler.WithGroup(g), h.s} }

// --- мир ---

// Как приложение ротирует свой журнал.
const (
	styleRotate = iota // logrotate create: name.log → name.log.1 → name.log.2… (dateext: name.log-ГГГГММДД-с)
	styleInMask        // name.log → name-K.log (под маской), позже уходит из-под неё
	styleShard         // каждый шард — новый файл name-K.log, старый закрыт
	styleDated         // dateext с extension .log: name.log → name-ГГГГММДД-с.log (под маской)
)

type simWriter struct {
	name  string
	style int
	path  string   // путь журнала (его открывает приложение при HUP)
	f     *os.File // куда пишет приложение сейчас
	ino   uint64
	hupAt time.Time // ротирован: до этого момента пишет в прежний файл
	n     int
	gen   int
}

type simLine struct {
	file    *simFile
	idx     int  // порядковый номер записи (строки или куска) в своём файле
	mayLose bool // файл разрушен: потеря допустима, но должна быть видна
	unseen  bool // разрушена раньше, чем сборщик мог её увидеть: потеря может быть и тихой
	wseq    int  // порядок записи (по всему миру)
}

// simFile — файл мира. inode — лишь адрес: удалённого файла ядро отдаёт
// новому, поэтому учёт — по файлу, а не по inode.
type simFile struct {
	ino    uint64
	lines  int
	broken bool // разрушен
	locked bool // права отняты: сборщику его не открыть
}

// simFix — что и когда вернёт администратор (права).
type simFix struct {
	at   time.Time
	what string
	do   func()
}

type sim struct {
	t        *testing.T
	w        simWorld
	prof     simProfile
	rng      *mrand.Rand
	dir      string
	cfg      *Config
	store    simStore
	logBuf   *bytes.Buffer
	logger   *slog.Logger
	c        *Collector
	now      time.Time
	seen     map[*simFile]bool // файл был на пути (под маской) при проходе сборщика
	started  bool              // первый запуск позади
	quieting bool              // тишина: вышедший сборщик поднимается сразу
	wseq     int               // строк записано всего
	// readAt — сколько строк было записано к последнему проходу, когда файл
	// был известен сборщику и открывался: строки позже ему прочитать было
	// нечем.
	readAt   map[*simFile]int
	writers  []*simWriter
	lines    map[string]*simLine // ожидаемые записи: строки и куски длинных строк
	byIno    map[uint64]*simFile // inode → файл, у которого он сейчас
	trace    []string
	failures []string
	crashAt  int // >= 0 — упасть на этой точке записи следующего прохода
	// Права: что вернёт администратор и что заперто сейчас.
	fixes       []simFix
	dirLocked   bool
	spoolLocked bool
	// Падение посреди записи буфера: размеры сегментов перед записью и обрыв,
	// который ляжет на диск, когда процесс остановится.
	segPre map[string]int64
	tear   func()
}

func runSim(t *testing.T, w simWorld, seed uint64, steps int, certs simCertsDir) (msg string) {
	rng := mrand.New(mrand.NewPCG(seed, seed*7919))
	s := &sim{
		t: t, w: w, rng: rng, prof: newProfile(rng), dir: t.TempDir(), logBuf: &bytes.Buffer{},
		now: time.Date(2026, 10, 11, 10, 0, 0, 0, time.UTC), lines: map[string]*simLine{},
		byIno: map[uint64]*simFile{}, crashAt: -1, seen: map[*simFile]bool{}, readAt: map[*simFile]int{},
	}
	s.logger = slog.New(simLog{slog.NewTextHandler(s.logBuf, &slog.HandlerOptions{
		Level: slog.LevelInfo,
		ReplaceAttr: func(_ []string, a slog.Attr) slog.Attr {
			if a.Key == slog.TimeKey {
				return slog.Attr{} // время — виртуальное, в vt
			}
			return a
		},
	}), s})
	s.cfg = &Config{
		CA: filepath.Join(certs.dir, "ca.crt"), Cert: filepath.Join(certs.dir, "abs-core.crt"), Key: filepath.Join(certs.dir, "abs-core.key"),
		SpoolDir: filepath.Join(t.TempDir(), "spool"), FromStart: true,
	}
	kind := "поддельное"
	if w.real {
		rs, err := newRealStore(t, certs)
		if err != nil {
			return "хранилище не поднялось: " + err.Error()
		}
		s.store, kind = rs, "настоящее"
		s.cfg.Server, s.cfg.StoreKey = rs.hs.URL, rs.st.PublicKey()
	} else {
		fs := newFakeStore(certs.storeSK)
		s.store = fs
		s.cfg.Server, s.cfg.StoreKey = "https://store.invalid", fs.pub
	}
	if w.glob {
		s.cfg.Glob = filepath.Join(s.dir, "*.log")
		s.writers = []*simWriter{
			{name: "app", style: styleRotate}, {name: "web", style: styleInMask}, {name: "pl", style: styleShard},
		}
		if s.prof.dateext {
			s.writers = append(s.writers, &simWriter{name: "dx", style: styleDated})
		}
	} else {
		s.cfg.File = filepath.Join(s.dir, "audit.log")
		s.writers = []*simWriter{{name: "audit", style: styleRotate}}
	}
	if err := s.cfg.validate(); err != nil {
		t.Fatal(err)
	}
	defer func() {
		if r := recover(); r != nil {
			msg = fmt.Sprintf("паника: %v\n%s", r, s.tail())
		}
		if s.c != nil {
			s.c.Close()
		}
		s.applyFixes(true) // права на место: иначе каталоги теста не удалить
		for _, wr := range s.writers {
			if wr.f != nil {
				wr.f.Close()
			}
		}
		s.store.close()
	}()
	s.note("помехи: %s; хранилище %s", s.prof, kind)
	for _, wr := range s.writers {
		s.open(wr)
	}
	s.start()
	for range steps {
		if len(s.failures) > 0 {
			break
		}
		s.step()
	}
	if len(s.failures) == 0 {
		s.quiesce()
	}
	if len(s.failures) == 0 {
		s.check()
	}
	if len(s.failures) == 0 {
		return ""
	}
	return strings.Join(s.failures[:min(len(s.failures), 6)], "\n") + "\nпомехи: " + s.prof.String() + "\n" + s.tail()
}

func (s *sim) tail() string {
	from := max(0, len(s.trace)-60)
	if _, single := os.LookupEnv("SIM_SEED"); single {
		from = 0 // один сценарий — ход целиком
	}
	log := s.logBuf.String()
	if len(log) > 6000 {
		log = "…" + log[len(log)-6000:]
	}
	return "ход (последние шаги):\n  " + strings.Join(s.trace[from:], "\n  ") + "\nжурнал сборщика:\n" + log
}

func (s *sim) note(format string, args ...any) {
	s.trace = append(s.trace, fmt.Sprintf("%s ", s.now.Format("15:04:05.0"))+fmt.Sprintf(format, args...))
}

func (s *sim) fail(format string, args ...any) {
	s.failures = append(s.failures, fmt.Sprintf(format, args...))
}

// open — приложение открывает (создаёт) свой журнал.
func (s *sim) open(wr *simWriter) {
	if wr.f != nil {
		wr.f.Close()
	}
	wr.path = filepath.Join(s.dir, wr.name+".log")
	if wr.style == styleShard {
		wr.path = filepath.Join(s.dir, fmt.Sprintf("%s-%d.log", wr.name, wr.gen))
	}
	_, statErr := os.Stat(wr.path)
	f, err := os.OpenFile(wr.path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		s.t.Fatal(err)
	}
	wr.f, wr.ino, wr.hupAt = f, s.inodeOf(f), time.Time{}
	if statErr != nil || s.byIno[wr.ino] == nil {
		s.born(wr.ino)
	}
}

// born — на этом inode родился новый файл.
func (s *sim) born(ino uint64) *simFile {
	f := &simFile{ino: ino}
	s.byIno[ino] = f
	return f
}

func (s *sim) inodeOf(f *os.File) uint64 {
	fi, err := f.Stat()
	if err != nil {
		s.t.Fatal(err)
	}
	return inode(fi)
}

func (s *sim) write(wr *simWriter, text string) {
	if _, err := wr.f.WriteString(text); err != nil {
		s.t.Fatal(err)
	}
}

// line — приложение пишет строку целиком (или двумя кусками с проходом
// сборщика между ними). Длинная строка длиннее pieceLen: сборщик режет её на
// куски, и каждый кусок — отдельная запись; у каждого куска своя метка в
// начале, чтобы эталон знал его в лицо.
func (s *sim) line(wr *simWriter, split bool) {
	wr.n++
	var pieces []string
	if s.prof.long && s.rng.IntN(6) == 0 {
		k := 2 + s.rng.IntN(3)
		for i := range k {
			mark := fmt.Sprintf("%s-%d#%d-", wr.name, wr.n, i)
			n := simPiece
			if i == k-1 {
				n = len(mark) + 1 + s.rng.IntN(simPiece-len(mark))
			}
			pieces = append(pieces, mark+strings.Repeat("y", n-len(mark)))
		}
	} else {
		pieces = []string{fmt.Sprintf("%s-%d-%s", wr.name, wr.n, strings.Repeat("x", s.rng.IntN(40)))}
	}
	text := strings.Join(pieces, "")
	fl := s.byIno[wr.ino]
	written := func() {
		s.wseq++
		for _, p := range pieces {
			s.lines[p] = &simLine{file: fl, idx: fl.lines, wseq: s.wseq}
			fl.lines++
		}
	}
	if split {
		half := len(text) / 2
		s.write(wr, text[:half])
		s.pass()
		written() // целой строка стала после прохода: тот видел половину
		s.write(wr, text[half:]+"\n")
		s.note("%s: строка %d двумя кусками (inode %d)", wr.name, wr.n, wr.ino)
		return
	}
	written()
	s.write(wr, text+"\n")
	if len(pieces) > 1 {
		s.note("%s: длинная строка %d, кусков %d (inode %d)", wr.name, wr.n, len(pieces), wr.ino)
	}
}

// mayLeave — файл может уйти с пути или из-под маски, только если
// сборщик хоть раз видел его на месте: файл, пришедший и ушедший, пока
// сборщик не смотрел, ему не увидеть (предел из README). Разрушения
// (удаление, сжатие, copytruncate) — без этого условия.
func (s *sim) mayLeave(ino uint64) bool {
	return s.seen[s.byIno[ino]]
}

// look — сборщик посмотрел на путь (маску): файлы там он видел.
func (s *sim) look() {
	var paths []string
	if s.w.glob {
		paths, _ = filepath.Glob(s.cfg.Glob)
	} else {
		paths = []string{s.cfg.File}
	}
	for _, p := range paths {
		if fi, err := os.Stat(p); err == nil {
			if f := s.byIno[inode(fi)]; f != nil {
				s.seen[f] = true
			}
		}
	}
}

func (s *sim) step() {
	wr := s.writers[s.rng.IntN(len(s.writers))]
	switch r := s.rng.IntN(100); {
	case r < 40:
		from := wr.n + 1
		for range 1 + s.rng.IntN(3) {
			s.line(wr, s.rng.IntN(8) == 0)
		}
		s.note("%s: строки %d–%d в inode %d", wr.name, from, wr.n, wr.ino)
	case r < 52:
		s.rotate(wr)
	case r < 57 && s.w.glob:
		s.moveOut()
	case r < 62 && os.Getenv("SIM_NORESTART") == "":
		s.restart(false)
	case r < 67 && os.Getenv("SIM_NORESTART") == "":
		s.restart(true)
	case r < 71:
		s.store.setDown(!s.store.isDown())
		s.note("хранилище down=%v", s.store.isDown())
	case r < 78 && s.w.destructive:
		s.destroy()
	case r < 81 && s.prof.flaky:
		s.store.setFlaky(!s.store.isFlaky())
		s.note("хранилище: ответы теряются=%v", s.store.isFlaky())
	case r < 84 && s.prof.permFile:
		s.lockFile()
	case r < 86 && s.prof.permDir:
		s.lockDir()
	case r < 88 && s.prof.permSpool:
		s.lockSpool()
	default:
		dts := []time.Duration{200 * time.Millisecond, time.Second, 2 * time.Second, 4 * time.Second, 7 * time.Second, 11 * time.Second, 25 * time.Second}
		s.tick(dts[s.rng.IntN(len(dts))])
	}
}

// rotate — ротация по стилю приложения.
func (s *sim) rotate(wr *simWriter) {
	if !wr.hupAt.IsZero() {
		return // прежняя ротация ещё не переоткрыта
	}
	dated := func(format string) string {
		return fmt.Sprintf(format, s.now.Format("20060102"), s.now.Unix())
	}
	switch wr.style {
	case styleShard:
		wr.gen++
		s.open(wr)
		s.note("%s: новый шард %s (inode %d)", wr.name, filepath.Base(wr.path), wr.ino)
		return
	case styleRotate:
		if !s.mayLeave(wr.ino) {
			return
		}
		if s.prof.dateext {
			// dateext, dateformat -%Y%m%d-%s: имя занято — logrotate ротацию
			// пропускает.
			to := wr.path + dated("-%s-%d")
			if _, err := os.Stat(to); err == nil {
				return
			}
			os.Rename(wr.path, to)
			break
		}
		// Сдвиг цепочки: name.log.K → name.log.K+1, name.log → name.log.1.
		for k := 30; k >= 1; k-- {
			from := fmt.Sprintf("%s.%d", wr.path, k)
			if _, err := os.Stat(from); err == nil {
				os.Rename(from, fmt.Sprintf("%s.%d", wr.path, k+1))
			}
		}
		os.Rename(wr.path, wr.path+".1")
	case styleInMask:
		wr.gen++
		os.Rename(wr.path, filepath.Join(s.dir, fmt.Sprintf("%s-%d.log", wr.name, wr.gen)))
	case styleDated:
		to := filepath.Join(s.dir, wr.name+dated("-%s-%d.log"))
		if _, err := os.Stat(to); err == nil {
			return
		}
		os.Rename(wr.path, to)
	}
	old := wr.ino
	// logrotate create: новый пустой журнал сразу; приложение переоткроет
	// его по HUP, до тех пор пишет в прежний. Права create могут быть такими,
	// что приложению писать можно, а сборщику не прочитать, — пока
	// администратор не исправит.
	if s.rng.IntN(4) > 0 {
		mode, locked := os.FileMode(0o600), s.prof.permNew && s.rng.IntN(2) == 0
		if locked {
			mode = 0o200
		}
		f, err := os.OpenFile(wr.path, os.O_CREATE|os.O_WRONLY, mode)
		if err != nil {
			s.t.Fatal(err)
		}
		nf := s.born(s.inodeOf(f))
		if locked {
			fixes := []time.Duration{5 * time.Second, 30 * time.Second, 2 * time.Minute, 1000 * time.Hour}
			d := fixes[s.rng.IntN(len(fixes))]
			nf.locked = true
			s.note("%s: новый журнал (inode %d) создан с правами 0200, исправят через %s", wr.name, s.inodeOf(f), d)
			s.fixLater(d, wr.name+": права нового журнала исправлены", func() { f.Chmod(0o600); f.Close(); nf.locked = false })
		} else {
			f.Close()
		}
	}
	wr.hupAt = s.now.Add(time.Duration(s.rng.Int64N(int64(simQuiet * 8 / 10))))
	s.note("%s: ротация (inode %d), HUP в %s", wr.name, old, wr.hupAt.Format("15:04:05.0"))
}

// moveOut — файл, ротированный внутри маски, уходит из-под неё.
func (s *sim) moveOut() {
	var names []string
	for _, pat := range []string{"web-*.log", "dx-*.log"} {
		m, _ := filepath.Glob(filepath.Join(s.dir, pat))
		names = append(names, m...)
	}
	if len(names) == 0 {
		return
	}
	p := names[s.rng.IntN(len(names))]
	fi, err := os.Stat(p)
	if err != nil {
		return
	}
	ino := inode(fi)
	for _, wr := range s.writers {
		if wr.ino == ino && wr.hupAt.IsZero() {
			return // в него ещё пишут как в текущий
		}
	}
	if !s.mayLeave(ino) {
		return
	}
	os.Rename(p, p+".old")
	s.note("из-под маски: %s (inode %d)", filepath.Base(p), ino)
}

// destroy — удаление, сжатие или copytruncate (мир с разрушениями).
func (s *sim) destroy() {
	var victims []string
	for _, pat := range []string{"*.log.*", "*-*.log", "*.log-*"} {
		m, _ := filepath.Glob(filepath.Join(s.dir, pat))
		victims = append(victims, m...)
	}
	victims = slices.DeleteFunc(victims, func(p string) bool { return strings.HasSuffix(p, ".gz") })
	switch k := s.rng.IntN(3); {
	case k == 2 && !s.w.glob:
		// copytruncate текущего журнала: копия под новым inode, оригинал обнулён.
		wr := s.writers[0]
		if !wr.hupAt.IsZero() {
			return
		}
		data, err := os.ReadFile(wr.path)
		if err != nil {
			return
		}
		s.breakFile(wr.ino)
		s.create(wr.path+".copy", data)
		os.Truncate(wr.path, 0)
		s.note("copytruncate %s (inode %d)", filepath.Base(wr.path), wr.ino)
	case len(victims) > 0:
		p := victims[s.rng.IntN(len(victims))]
		fi, err := os.Stat(p)
		if err != nil {
			return
		}
		ino := inode(fi)
		for _, wr := range s.writers {
			if wr.ino == ino {
				return // в него ещё пишут
			}
		}
		s.breakFile(ino)
		if k == 0 {
			os.Remove(p)
			s.note("удалён %s (inode %d)", filepath.Base(p), ino)
		} else {
			s.create(p+".gz", []byte("\x1f\x8b сжато"))
			os.Remove(p)
			s.note("сжат %s (inode %d)", filepath.Base(p), ino)
		}
	}
}

func (s *sim) breakFile(ino uint64) {
	f := s.byIno[ino]
	if f == nil {
		return
	}
	f.broken = true
	for _, l := range s.lines {
		if l.file == f && !l.mayLose {
			// Сборщик не знал файла или не прочитать ему было строку: не
			// смотрел после её записи или файл не открывался (права) —
			// узнать о ней ему нечем.
			l.mayLose, l.unseen = true, !s.seen[f] || l.wseq > s.readAt[f]
		}
	}
}

// create — новый файл с содержимым (копия, «сжатый»).
func (s *sim) create(path string, data []byte) {
	if err := os.WriteFile(path, data, 0o600); err != nil {
		s.t.Fatal(err)
	}
	fi, err := os.Stat(path)
	if err != nil {
		s.t.Fatal(err)
	}
	s.born(inode(fi))
}

// --- права ---

// fixLater — администратор вернёт права через d.
func (s *sim) fixLater(d time.Duration, what string, do func()) {
	s.fixes = append(s.fixes, simFix{at: s.now.Add(d), what: what, do: do})
}

// applyFixes — администратор возвращает права, срок которых подошёл (all —
// все).
func (s *sim) applyFixes(all bool) {
	keep := s.fixes[:0]
	for _, f := range s.fixes {
		if all || !s.now.Before(f.at) {
			f.do()
			s.note("%s", f.what)
			continue
		}
		keep = append(keep, f)
	}
	s.fixes = keep
}

// faultFor — на сколько отнимаются права.
func (s *sim) faultFor() time.Duration {
	ds := []time.Duration{2 * time.Second, 5 * time.Second, 15 * time.Second, 40 * time.Second, 90 * time.Second}
	return ds[s.rng.IntN(len(ds))]
}

// lockFile — права на файл журнала отняты на время: открыть его сборщику
// нельзя (открытый дескриптор читает и дальше). Права возвращаются через
// дескриптор — где бы файл к тому времени ни лежал.
func (s *sim) lockFile() {
	entries, err := os.ReadDir(s.dir)
	if err != nil {
		return
	}
	var names []string
	for _, e := range entries {
		if e.Type().IsRegular() && !strings.HasSuffix(e.Name(), ".gz") {
			names = append(names, e.Name())
		}
	}
	if len(names) == 0 {
		return
	}
	p := filepath.Join(s.dir, names[s.rng.IntN(len(names))])
	f, err := os.OpenFile(p, os.O_WRONLY, 0)
	if err != nil {
		return
	}
	if err := f.Chmod(0o200); err != nil {
		f.Close()
		return
	}
	d, sf := s.faultFor(), s.byIno[s.inodeOf(f)]
	if sf != nil {
		sf.locked = true
	}
	s.note("права на %s (inode %d) отняты на %s", filepath.Base(p), s.inodeOf(f), d)
	s.fixLater(d, "права на "+filepath.Base(p)+" возвращены", func() {
		f.Chmod(0o600)
		f.Close()
		if sf != nil {
			sf.locked = false
		}
	})
}

// lockDir — каталог журнала не читается (листинг), хотя файлы в нём
// открываются и переименовываются.
func (s *sim) lockDir() {
	if s.dirLocked {
		return
	}
	if err := os.Chmod(s.dir, 0o300); err != nil {
		s.t.Fatal(err)
	}
	s.dirLocked = true
	d := s.faultFor()
	s.note("каталог журнала не читается %s", d)
	s.fixLater(d, "каталог журнала читается снова", func() {
		os.Chmod(s.dir, 0o700)
		s.dirLocked = false
	})
}

// lockSpool — в spool_dir не создать и не удалить файл (права, место):
// буфер не открывает новый сегмент, files.json и state.json не пишутся.
func (s *sim) lockSpool() {
	if s.spoolLocked {
		return
	}
	dirs := []string{s.cfg.SpoolDir, filepath.Join(s.cfg.SpoolDir, "spool")}
	for _, d := range dirs {
		os.Chmod(d, 0o500)
	}
	s.spoolLocked = true
	d := s.faultFor()
	s.note("spool_dir не пишется %s", d)
	s.fixLater(d, "spool_dir пишется снова", func() {
		for _, d := range dirs {
			os.Chmod(d, 0o700)
		}
		s.spoolLocked = false
	})
}

// --- время и сборщик ---

// tick — проходит виртуальное время: права возвращаются, приложения
// переоткрывают журналы по HUP, сборщик делает проходы.
func (s *sim) tick(d time.Duration) {
	end := s.now.Add(d)
	for s.now.Before(end) {
		s.now = minTime(end, s.now.Add(simFlush))
		s.applyFixes(false)
		for _, wr := range s.writers {
			if !wr.hupAt.IsZero() && !s.now.Before(wr.hupAt) {
				s.open(wr)
				s.note("%s: HUP, пишет в %s (inode %d)", wr.name, filepath.Base(wr.path), wr.ino)
			}
		}
		s.pass()
		s.store.tick()
	}
}

func minTime(a, b time.Time) time.Time {
	if a.Before(b) {
		return a
	}
	return b
}

// start поднимает сборщик (первый запуск — при живом хранилище). Первый
// запуск может упасть в точке записи — тогда он повторяется, как после
// перезапуска службой.
func (s *sim) start() {
	c, err := New(s.cfg, s.logger)
	if err != nil {
		if s.spoolLocked {
			s.note("сборщик не поднялся: %v", err) // служба поднимет позже
			return
		}
		s.fail("New: %v", err)
		return
	}
	s.store.attach(c)
	c.now = func() time.Time { return s.now }
	c.quietFor = simQuiet
	crashed := false
	if !s.started && s.prof.after && s.rng.IntN(3) == 0 {
		at, n := s.rng.IntN(8), 0
		c.persistHook = func(what string) error {
			if n == at {
				s.note("падение при первом запуске: %s", what)
				crashed = true
				return errSimCrash
			}
			n++
			return nil
		}
	}
	err = c.Bootstrap(context.Background())
	c.persistHook = nil
	if crashed {
		c.Close()
		s.start()
		return
	}
	if err != nil {
		first := c.nextSeq == 0 && s.store.isDown()
		s.store.setDown(false)
		if !first {
			c.Close()
			s.fail("Bootstrap: %v", err)
			return
		}
		if err := c.Bootstrap(context.Background()); err != nil {
			c.Close()
			s.fail("Bootstrap: %v", err)
			return
		}
	}
	s.c = c
	if !s.started {
		s.look() // первый запуск вносит файлы на месте в реестр
		s.started = true
	}
	s.note("сборщик поднят")
}

// restart — остановка сборщика (crash — падение в случайной точке записи
// следующего прохода: перед записью, сразу после неё или посреди записи
// буфера) и, не всегда сразу, запуск.
func (s *sim) restart(crash bool) {
	if s.c == nil {
		s.start()
		return
	}
	if !crash {
		s.stop("остановлен")
		return
	}
	points := 6
	if s.prof.after {
		points = 12
	}
	s.crashAt = s.rng.IntN(points)
	n := 0
	s.c.persistHook = func(what string) error {
		after := strings.HasSuffix(what, "+")
		if after && !s.prof.after {
			return nil
		}
		if what == "spool" && s.prof.torn {
			s.segPre = s.segSizes()
		}
		if n != s.crashAt {
			n++
			return nil
		}
		switch {
		case what == "spool+" && s.prof.torn && s.rng.IntN(2) == 0:
			s.tear = s.tearLast()
			s.note("падение посреди записи буфера")
		case after:
			s.note("падение сразу после записи %s", strings.TrimSuffix(what, "+"))
		default:
			s.note("падение перед записью %s", what)
		}
		return errSimCrash
	}
	s.pass()
	if s.c != nil {
		s.c.persistHook, s.crashAt = nil, -1
	}
}

// segSizes — размеры сегментов буфера.
func (s *sim) segSizes() map[string]int64 {
	out := map[string]int64{}
	paths, _ := filepath.Glob(filepath.Join(s.cfg.SpoolDir, "spool", "seg_*.log"))
	for _, p := range paths {
		if fi, err := os.Stat(p); err == nil {
			out[p] = fi.Size()
		}
	}
	return out
}

// tearLast — обрыв последней пачки буфера: на диске остаётся её начало
// (от нуля байт до всей без последнего), как при падении посреди записи.
// Пачка целиком лежит в одном сегменте (evlog переходит к новому только
// между пачками); новый сегмент начинается с заголовка, записанного раньше.
func (s *sim) tearLast() func() {
	paths, _ := filepath.Glob(filepath.Join(s.cfg.SpoolDir, "spool", "seg_*.log"))
	if len(paths) == 0 {
		return nil
	}
	last := paths[len(paths)-1]
	from, ok := s.segPre[last]
	if !ok {
		from = 16 // заголовок сегмента evlog
	}
	fi, err := os.Stat(last)
	if err != nil || fi.Size() <= from {
		return nil
	}
	cut := from + s.rng.Int64N(fi.Size()-from)
	return func() { os.Truncate(last, cut) }
}

func (s *sim) stop(why string) {
	s.c.Close()
	s.c, s.crashAt = nil, -1
	if s.tear != nil {
		s.tear() // обрыв ложится на диск, когда процесса уже нет
		s.tear = nil
	}
	s.note("сборщик %s", why)
	if s.quieting || s.rng.IntN(2) == 0 {
		s.start()
	}
}

// pass — один проход сборщика, как в Run: прочитать и отправить. Ошибка
// чтения при отказавшем буфере — выход процесса (служба поднимет позже);
// иначе ошибка чтения допустима, только пока заперт каталог журнала или
// spool_dir. Ошибка отправки — повтор в следующий раз.
func (s *sim) pass() {
	if s.c == nil {
		return
	}
	_, err := s.c.ReadOnce()
	switch {
	case errors.Is(err, errSimCrash):
		s.stop("упал")
		return
	case err != nil && s.c.spool.Failed() != nil:
		s.stop(fmt.Sprintf("вышел: буфер отказал (%v)", err))
		return
	case err != nil && !s.dirLocked && !s.spoolLocked:
		s.fail("ReadOnce: %v", err)
		return
	case err != nil:
		s.note("ReadOnce: %v", err)
	default:
		s.look()
		for f := range s.seen {
			if !f.locked {
				s.readAt[f] = s.wseq
			}
		}
	}
	err = s.c.SendOnce(context.Background())
	switch {
	case err == nil:
	case errors.Is(err, errSimCrash):
		s.stop("упал")
	case s.c.spool.Failed() != nil:
		s.stop(fmt.Sprintf("вышел: буфер отказал (%v)", err))
	case errors.Is(err, ErrConflict), errors.Is(err, ErrEpoch), errors.Is(err, ErrBadPromise):
		s.fail("SendOnce: %v", err)
	case s.store.isDown():
	case s.store.isFlaky() || s.spoolLocked:
		s.note("SendOnce: %v", err)
	default:
		s.fail("SendOnce: %v", err)
	}
}

// quiesce — права возвращены, приложения переоткрыли журналы и замолчали,
// хранилище живо, сборщик работает: всё, что можно прочитать, должно дойти.
func (s *sim) quiesce() {
	for _, wr := range s.writers {
		if !wr.hupAt.IsZero() {
			wr.hupAt = s.now
		}
	}
	s.applyFixes(true)
	s.store.setDown(false)
	s.store.setFlaky(false)
	s.quieting = true
	if s.c == nil {
		s.start()
	}
	s.note("тишина")
	s.tick(3 * simQuiet)
	for range 20 {
		if len(s.failures) > 0 || s.c == nil {
			return
		}
		n, err := s.c.ReadOnce()
		if err != nil {
			s.fail("ReadOnce в тишине: %v", err)
			return
		}
		if err := s.c.SendOnce(context.Background()); err != nil {
			s.fail("SendOnce в тишине: %v", err)
			return
		}
		if n == 0 && s.c.Pending() == 0 {
			return
		}
		s.now = s.now.Add(simFlush)
	}
	s.fail("сборщик не успокоился: ещё читает или шлёт")
}

// check сверяет доставленное с записанным.
func (s *sim) check() {
	bodies, last, bad := s.store.contents()
	for _, b := range bad[:min(len(bad), 3)] {
		s.fail("%s", b)
	}
	var gaps []uint64
	seen := map[string][]uint64{}
	for q := uint64(1); q <= last; q++ {
		b, ok := bodies[q]
		if !ok {
			gaps = append(gaps, q)
			continue
		}
		seen[b] = append(seen[b], q)
	}
	var unknown, dups, lost, lostOK []string
	for b, qs := range seen {
		if _, ok := s.lines[b]; !ok {
			// Соседи по номерам — видно, с какого места сборщик читал.
			var near []string
			for q := qs[0] - min(qs[0]-1, 2); q <= qs[0]+2 && q <= last; q++ {
				near = append(near, fmt.Sprintf("%d:%.14q", q, bodies[q]))
			}
			unknown = append(unknown, fmt.Sprintf("%q (номер %d; рядом %s)", b, qs[0], strings.Join(near, " ")))
		}
		if len(qs) > 1 {
			dups = append(dups, fmt.Sprintf("%q номера %v", b, qs))
		}
	}
	for text, l := range s.lines {
		if _, ok := seen[text]; ok {
			continue
		}
		if l.mayLose && l.unseen {
			continue // разрушена раньше, чем сборщик мог её увидеть
		}
		if l.mayLose {
			lostOK = append(lostOK, fmt.Sprintf("%q (inode %d)", text, l.file.ino))
		} else {
			lost = append(lost, fmt.Sprintf("%q (inode %d)", text, l.file.ino))
		}
	}
	sort.Strings(unknown)
	sort.Strings(dups)
	sort.Strings(lost)
	if len(unknown) > 0 {
		s.fail("чужие строки (%d): %v", len(unknown), unknown[:min(len(unknown), 4)])
	}
	if len(dups) > 0 {
		s.fail("повторы (%d): %v", len(dups), dups[:min(len(dups), 4)])
	}
	if len(lost) > 0 {
		s.fail("потеряны (%d из %d), пропусков в нумерации %d: %v", len(lost), len(s.lines), len(gaps), lost[:min(len(lost), 4)])
	}
	if len(lostOK) > 0 && len(gaps) == 0 {
		sort.Strings(lostOK)
		s.fail("потеряно %d строк разрушенных файлов, а пропуска в нумерации нет: потеря тихая: %v", len(lostOK), lostOK[:min(len(lostOK), 4)])
	}
	if !s.w.destructive && len(gaps) > 0 {
		s.fail("пропуски в нумерации без потерь: %v", gaps[:min(len(gaps), 6)])
	}
	// Внутри файла — порядок записи.
	type at struct{ idx, seq int }
	byFile := map[*simFile][]at{}
	for text, l := range s.lines {
		if qs := seen[text]; len(qs) > 0 {
			byFile[l.file] = append(byFile[l.file], at{l.idx, int(qs[0])})
		}
	}
	for f, xs := range byFile {
		ino := f.ino
		sort.Slice(xs, func(i, j int) bool { return xs[i].idx < xs[j].idx })
		for i := 1; i < len(xs); i++ {
			if xs[i].seq < xs[i-1].seq {
				s.fail("inode %d: строка %d записана позже строки %d, а номер у неё меньше (%d < %d)", ino, xs[i].idx, xs[i-1].idx, xs[i].seq, xs[i-1].seq)
				break
			}
		}
	}
}
