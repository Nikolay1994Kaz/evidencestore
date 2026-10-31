// Package collector — лёгкий сборщик рядом с источником.
//
// Читает файл журнала построчно, нумерует строки (Seq по порядку), кладёт в
// дисковый буфер и отправляет пачками в хранилище по HTTPS с клиентским
// сертификатом. Запись доставлена, только когда хранилище ответило «принято»
// и подписало обещание, которое сходится с закреплённым ключом. Доставка
// «хотя бы один раз»: повтор хранилище узнаёт по (источник, номер) и сверяет
// тело.
//
// БУФЕР — свой экземпляр журнала evlog, того же, что у журнала улик
// хранилища: запись только после fsync, после первой ошибки записи журнал
// больше не пишет (fail-stop), оборванный хвост отрезается при открытии.
// Доставленные сегменты удаляются целиком (Release). Тела ждут отправки на
// диске, в памяти — только счётчики.
//
// ПОЧЕМУ ПОЗИЦИЯ В ФАЙЛЕ ЛЕЖИТ В КАЖДОЙ ЗАПИСИ БУФЕРА. Если хранить
// «докуда прочитан файл» отдельно, падение между записью в буфер и
// сохранением позиции перечитает строки и выдаст им НОВЫЕ номера — у
// хранилища окажется две улики об одном событии. Позиция внутри записи
// буфера пишется одним fsync с самой строкой, и после падения чтение
// продолжается ровно с того места. Первый запуск тоже кладёт в буфер
// запись — «старт»: с какого номера и с какого места читать.
//
// Тело не трогается: строка уходит байт в байт (без перевода строки).
// Строка длиннее предела режется на куски, каждый — отдельная запись.
//
// Вместо одного файла можно читать файлы по маске (glob) — для источников,
// которые пишут новые файлы, а не ротируют один: бортовой журнал Pipelock
// кладёт каждый шард в новый файл evidence-<сессия>-<seq>.jsonl. Сборщик
// помнит про каждый файл под маской, докуда его прочитал (files.json), и
// читает любой файл с непрочитанным, где бы тот ни встал по времени
// изменения: часы, ушедшие назад, шард не прячут. Непрочитанные файлы идут
// по времени изменения, при равенстве — по имени, где числа сравниваются как
// числа. Текущий файл дочитывается до конца, когда появился другой
// непрочитанный: значит, писатель его закрыл. В каталоге — один писатель.
package collector

import (
	"bufio"
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/Nikolay1994Kaz/evidencestore/internal/config"
	"github.com/Nikolay1994Kaz/evidencestore/internal/evidence"
	"github.com/Nikolay1994Kaz/evidencestore/internal/evlog"
	"github.com/Nikolay1994Kaz/evidencestore/internal/proof"

	"golang.org/x/sys/unix"
)

// Config — настройки сборщика.
type Config struct {
	Server string `json:"server"` // https://host:port хранилища
	CA     string `json:"ca"`     // сертификат УЦ, выпустившего сертификат сервера
	Cert   string `json:"cert"`   // сертификат сборщика (CommonName = источник)
	Key    string `json:"key"`    // его ключ
	// StoreKey — закреплённый открытый ключ хранилища (base64, его печатает
	// evidencestore init). Обязателен: без него подмену хранилища не видно,
	// а его обещания нечем проверить.
	StoreKey string `json:"store_key"`
	SpoolDir string `json:"spool_dir"`
	File     string `json:"file"` // читаемый файл журнала
	// Glob — маска файлов (filepath.Match) вместо file, когда источник
	// пишет новые файлы: "/var/lib/pipelock/recorder/evidence-*.jsonl".
	Glob string `json:"glob"`
	// FromStart — читать файл с начала (иначе — только новые строки).
	FromStart  bool            `json:"from_start"`
	Batch      int             `json:"batch"`       // записей в пачке, 1–512; 0 — 256
	FlushEvery config.Duration `json:"flush_every"` // пауза между проходами; 0 — 1 с
	// HeartbeatEvery — пульс: отправлять нечего, а хранилище не отвечало
	// сборщику дольше этого — GET /v1/state, и хранилище отличает тихий
	// журнал от остановленного сборщика (expect_contact источника, по
	// умолчанию 2 мин). 0 — 30 с.
	HeartbeatEvery config.Duration `json:"heartbeat_every"`
}

const (
	// maxBatch — больше записей в одной пачке хранилище не принимает
	// (store.MaxBatch; равенство стережёт тест).
	maxBatch     = 512
	defaultBatch = 256
)

// LoadConfig читает настройки; относительные пути — от файла настроек.
func LoadConfig(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var c Config
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&c); err != nil {
		return nil, fmt.Errorf("collector config %s: %w", path, err)
	}
	base := filepath.Dir(path)
	for _, p := range []*string{&c.CA, &c.Cert, &c.Key, &c.SpoolDir, &c.File, &c.Glob} {
		if *p != "" && !filepath.IsAbs(*p) {
			*p = filepath.Join(base, *p)
		}
	}
	return &c, c.validate()
}

// validate проверяет настройки и ставит умолчания. Опасное значение —
// ошибка, а не тихая замена: http:// уводит тела улик открытым текстом,
// отрицательная пауза крутит цикл без сна, пачку больше 512 хранилище
// отвергнет навсегда.
func (c *Config) validate() error {
	if c.Batch == 0 {
		c.Batch = defaultBatch
	}
	if c.FlushEvery == 0 {
		c.FlushEvery = config.Duration(time.Second)
	}
	if c.HeartbeatEvery == 0 {
		c.HeartbeatEvery = config.Duration(30 * time.Second)
	}
	c.Server = strings.TrimRight(c.Server, "/")
	var errs []error
	for name, v := range map[string]string{"server": c.Server, "ca": c.CA, "cert": c.Cert, "key": c.Key, "store_key": c.StoreKey, "spool_dir": c.SpoolDir} {
		if v == "" {
			errs = append(errs, fmt.Errorf("%s is required", name))
		}
	}
	if c.Server != "" {
		if u, err := url.Parse(c.Server); err != nil {
			errs = append(errs, fmt.Errorf("server: %w", err))
		} else if u.Scheme != "https" || u.Host == "" {
			errs = append(errs, fmt.Errorf("server %q: must be an https:// address", c.Server))
		}
	}
	if c.StoreKey != "" {
		if _, err := parseStoreKey(c.StoreKey); err != nil {
			errs = append(errs, err)
		}
	}
	if c.Batch < 1 || c.Batch > maxBatch {
		errs = append(errs, fmt.Errorf("batch %d: must be between 1 and %d", c.Batch, maxBatch))
	}
	if c.FlushEvery < 0 {
		errs = append(errs, fmt.Errorf("flush_every %v: must not be negative", c.FlushEvery.D()))
	}
	if c.HeartbeatEvery < 0 {
		errs = append(errs, fmt.Errorf("heartbeat_every %v: must not be negative", c.HeartbeatEvery.D()))
	}
	if (c.File == "") == (c.Glob == "") {
		errs = append(errs, errors.New("exactly one of file and glob is required"))
	}
	if c.Glob != "" {
		// Каталог маски — один и без подстановок: его сборщик читает целиком
		// и в нём же ищет ротированный файл по inode.
		if _, err := filepath.Match(c.Glob, ""); err != nil {
			errs = append(errs, fmt.Errorf("glob %q: %w", c.Glob, err))
		} else if strings.ContainsAny(filepath.Dir(c.Glob), `*?[\`) {
			errs = append(errs, fmt.Errorf("glob %q: wildcards are allowed in the file name only", c.Glob))
		}
	}
	return errors.Join(errs...)
}

func parseStoreKey(s string) (ed25519.PublicKey, error) {
	raw, err := base64.RawStdEncoding.DecodeString(strings.TrimRight(s, "="))
	if err != nil || len(raw) != ed25519.PublicKeySize {
		return nil, errors.New("store_key must be the store's base64 Ed25519 public key (evidencestore init prints it)")
	}
	return raw, nil
}

// Collector — один источник: файл или файлы по маске.
type Collector struct {
	cfg      *Config
	log      *slog.Logger
	http     *http.Client
	storeKey ed25519.PublicKey
	source   string // CommonName своего сертификата: о нём обещания хранилища
	// epoch — эпоха этой установки сборщика (spool_dir/epoch.json): с
	// каждым запросом; хранилище закрепляет за источником первую установку
	// и отказывает остальным.
	epoch string

	nextSeq uint64 // номер следующей строки
	acked   uint64 // всё до этого номера включительно принято хранилищем
	// files — реестр: каждый файл, который сборщик читает или прочитал и
	// ещё видит, по inode (ReadOnce).
	files     map[uint64]*tracked
	firstPass bool // первый проход после запуска: новые файлы — не «из прошлого»

	spool    *evlog.Log
	sentPos  uint64 // позиция в буфере: всё до неё включительно доставлено
	pending  int    // строк в буфере после sentPos
	promises promiseFile
	// contactAt — когда хранилище последний раз ответило сборщику (приём или
	// state): старше heartbeat_every — пульс (SendOnce). Ноль — ещё не
	// отвечало; отсчёт тогда с первого прохода.
	contactAt time.Time

	warned map[string]time.Time // когда последний раз сказали «читать нечего (нельзя)» — по пути

	// now, quietFor — часы и rotateQuiet этого сборщика: симуляция ведёт
	// виртуальное время. persistHook (только тесты) зовётся перед каждой
	// записью на диск — буфер, files.json, state.json, start-files.json — и
	// сразу после неё (имя с «+»); ошибка — падение процесса ровно в этой
	// точке.
	now         func() time.Time
	quietFor    time.Duration
	persistHook func(what string) error
	// wall — часы, с которыми сверяется время приёма в обещании
	// (keepPromise): настоящие, и в симуляции тоже — хранилище в ней живёт
	// по настоящим часам.
	wall func() time.Time
}

// promiseFile — файл обещаний (*os.File; тест подставляет обрыв записи).
type promiseFile interface {
	io.Writer
	Sync() error
	Stat() (os.FileInfo, error)
	Truncate(size int64) error
	Close() error
}

// tracked — файл в реестре.
type tracked struct {
	ino   uint64
	path  string // где видели последний раз
	off   int64  // прочитано до: за последней целой строкой (или куском)
	head  string // первая строка, до 64 байт; "" — не знаем
	mtime int64  // время изменения при последнем взгляде, unix-нс (порядок чтения)
	// birth — время рождения файла (statx btime), unix-нс; 0 — файловая
	// система не знает. inode удалённого файла ядро отдаёт новому: по
	// рождению видно, что это другой файл, даже с той же первой строкой.
	birth int64
	// idle — дочитан и закрыт за простоем (под маской есть новее): дорастёт —
	// откроется снова; пропадёт — без пропуска номера.
	idle bool

	f      *os.File  // открыт: ушедший с пути файл дочитывается через него
	size   int64     // размер при последнем взгляде через f; -1 — ещё не смотрели
	growth time.Time // когда рос последний раз (для rotateQuiet)
	left   time.Time // когда сборщик заметил, что файл ушёл с пути (из-под маски)
	listed bool      // на пути журнала или под маской в этом проходе
	lsize  int64     // размер по листингу этого прохода
}

type filePos struct {
	Inode  uint64
	Offset int64
}

// fileState — файл в files.json (снимок реестра).
type fileState struct {
	Inode  uint64 `json:"inode"`
	Offset int64  `json:"offset"`          // прочитано до
	MTime  int64  `json:"mtime,omitempty"` // unix-нс
	Head   string `json:"head,omitempty"`  // первая строка, до 64 байт
	Path   string `json:"path,omitempty"`  // где видели последний раз
	Birth  int64  `json:"birth,omitempty"` // время рождения, unix-нс
	Idle   bool   `json:"idle,omitempty"`  // дочитан и закрыт за простоем
}

// state — state.json.
type state struct {
	Acked uint64 `json:"acked"`
}

// New поднимает сборщик: буфер, состояние, клиент TLS.
func New(cfg *Config, log *slog.Logger) (_ *Collector, err error) {
	if log == nil {
		log = slog.New(slog.NewTextHandler(os.Stderr, nil))
	}
	c := &Collector{cfg: cfg, log: log, files: map[uint64]*tracked{}, now: time.Now, wall: time.Now, quietFor: rotateQuiet, firstPass: true}
	if c.storeKey, err = parseStoreKey(cfg.StoreKey); err != nil {
		return nil, fmt.Errorf("collector: %w", err)
	}
	cert, err := tls.LoadX509KeyPair(cfg.Cert, cfg.Key)
	if err != nil {
		return nil, fmt.Errorf("collector certificate: %w", err)
	}
	leaf, err := x509.ParseCertificate(cert.Certificate[0])
	if err != nil {
		return nil, fmt.Errorf("collector certificate: %w", err)
	}
	c.source = leaf.Subject.CommonName
	caPEM, err := os.ReadFile(cfg.CA)
	if err != nil {
		return nil, err
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(caPEM) {
		return nil, errors.New("collector: no certificates in ca")
	}
	c.http = &http.Client{
		// Пачка — не больше maxBatchBytes тел, ≈1,4 МиБ на проводе: за две
		// минуты (столько же её ждёт сервер) она проходит и по 128 кбит/с.
		Timeout: 2 * time.Minute,
		Transport: &http.Transport{
			// Прокси из окружения (HTTPS_PROXY) не берётся намеренно: улики
			// идут прямо в хранилище (docs/dev/DECISIONS.md).
			DialContext:         (&net.Dialer{Timeout: 10 * time.Second, KeepAlive: 30 * time.Second}).DialContext,
			TLSHandshakeTimeout: 10 * time.Second,
			TLSClientConfig:     &tls.Config{MinVersion: tls.VersionTLS13, RootCAs: roots, Certificates: []tls.Certificate{cert}},
		},
	}
	if err := os.MkdirAll(cfg.SpoolDir, 0o700); err != nil {
		return nil, err
	}
	defer func() {
		if err != nil {
			c.Close() // открытое до сбоя не течёт
		}
	}()
	if err := c.load(); err != nil {
		return nil, err
	}
	return c, nil
}

func (c *Collector) spoolDir() string     { return filepath.Join(c.cfg.SpoolDir, "spool") }
func (c *Collector) statePath() string    { return filepath.Join(c.cfg.SpoolDir, "state.json") }
func (c *Collector) filesPath() string    { return filepath.Join(c.cfg.SpoolDir, "files.json") }
func (c *Collector) startPath() string    { return filepath.Join(c.cfg.SpoolDir, "start-files.json") }
func (c *Collector) promisesPath() string { return filepath.Join(c.cfg.SpoolDir, "promises.jsonl") }
func (c *Collector) epochPath() string    { return filepath.Join(c.cfg.SpoolDir, "epoch.json") }

// rejectedFile — обещания, которые не сошлись: улика против хранилища.
const rejectedFile = "promises-rejected.jsonl"

// aheadFile — обещания со временем приёма позже ответа хранилища: улика
// против хранилища (keepPromise).
const aheadFile = "promises-ahead.jsonl"

// deadlineFile — обещания со сроком дальше proof.MaxPromiseMMD от времени
// приёма: улика против хранилища (keepPromise).
const deadlineFile = "promises-deadline.jsonl"

// receiveAhead — насколько время приёма в обещании может быть позже ответа
// хранилища по часам сборщика: расхождение часов сборщика и TSA. Честное
// хранилище берёт время приёма не позже времени TSA (окно по якорю).
const receiveAhead = time.Minute

// spoolSegmentBytes — порог ротации сегмента буфера: доставленное уходит с
// диска сегментами такого размера. Переменная — чтобы тест увидел удаление.
var spoolSegmentBytes int64 = 16 << 20

// load поднимает буфер и состояние после рестарта.
func (c *Collector) load() error {
	if _, err := os.Stat(filepath.Join(c.cfg.SpoolDir, "spool.log")); err == nil {
		return errors.New("collector: spool_dir holds spool.log of an older escollect: deliver it with that version, or empty spool_dir")
	}
	var st state
	stateFound, err := readJSON(c.statePath(), &st)
	if err != nil {
		return err
	}
	// Реестр — снимок files.json (до первого files.json — снимок первого
	// запуска, start-files.json), поверх — записи буфера по порядку: снимок
	// пишется раньше, чем освобождается доставленное, поэтому записи после
	// него новее, а до него — не новее.
	var files []fileState
	filesFound, err := readJSON(c.filesPath(), &files)
	if err != nil {
		return err
	}
	startFound := false
	if !filesFound {
		if startFound, err = readJSON(c.startPath(), &files); err != nil {
			return err
		}
	}
	c.acked = st.Acked
	for _, f := range files {
		c.files[f.Inode] = &tracked{ino: f.Inode, off: f.Offset, mtime: f.MTime, head: f.Head, path: f.Path, birth: f.Birth, idle: f.Idle, size: -1}
	}

	var last spoolRecord
	n, started := 0, false
	visit := func(p uint64, data []byte) error {
		r, err := parseRecord(data)
		if err != nil {
			return fmt.Errorf("collector spool position %d: %w", p, err)
		}
		switch {
		case n == 0:
			c.sentPos = p - 1
		case r.seq < last.seq || r.kind == kindLine && r.seq == last.seq:
			// Номера строк в буфере только растут (метки повторяют
			// последний выданный); иначе буфер испорчен, и слать из него
			// нельзя.
			return fmt.Errorf("collector spool position %d: seq %d after %d", p, r.seq, last.seq)
		}
		switch r.kind {
		case kindStart:
			started = true
			c.acked = max(c.acked, r.seq)
		case kindPos:
			if r.pos.Inode != 0 {
				t := c.track(r.pos.Inode)
				parts := strings.SplitN(string(r.body), "\n", 3)
				t.off, t.head, t.idle = r.pos.Offset, parts[0], false
				if len(parts) > 1 && parts[1] != "" {
					t.path = parts[1]
				}
				if len(parts) > 2 {
					t.birth, _ = strconv.ParseInt(parts[2], 10, 64)
				}
			}
		case kindLine:
			t := c.track(r.pos.Inode)
			t.off, t.idle = r.pos.Offset, false
		case kindDone:
			delete(c.files, r.pos.Inode)
		}
		if r.seq <= c.acked {
			c.sentPos = p
		} else if r.kind == kindLine {
			c.pending++
		}
		last, n = r, n+1
		return nil
	}
	if c.spool, err = evlog.Open(c.spoolDir(), evlog.Options{SegmentBytes: spoolSegmentBytes, AllowRelease: true}, visit); err != nil {
		return fmt.Errorf("collector spool: %w", err)
	}
	switch {
	case n == 0 && (stateFound || filesFound):
		return errors.New("collector: the spool is empty, but state.json or files.json is there: the spool was lost, and the read positions with it. " +
			"Restore spool_dir from a backup if there is one. Emptying spool_dir starts over: numbering continues from the store, " +
			"lines not yet delivered are skipped — or, with from_start, the whole log is delivered again under new numbers (duplicates). " +
			"An emptied spool_dir is a new collector installation: the store refuses it until the operator binds it (the command is in the refusal)")
	case n == 0:
		c.sentPos = c.spool.Next() - 1 // первый запуск
		clear(c.files)
	case !filesFound && !started:
		return errors.New("collector: files.json is missing and the spool no longer holds the start record: read positions are unknown")
	case !filesFound && !startFound:
		return errors.New("collector: files.json and start-files.json are both missing: read positions are unknown")
	case c.acked > last.seq:
		return fmt.Errorf("collector: state.json says seq %d is delivered, but the spool ends at %d", c.acked, last.seq)
	default:
		c.nextSeq = last.seq + 1
	}
	if err := c.loadEpoch(); err != nil {
		return err
	}
	if err := c.repairPromises(); err != nil {
		return err
	}
	c.promises, err = os.OpenFile(c.promisesPath(), os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600)
	return err
}

// epochFile — epoch.json.
type epochFile struct {
	Epoch string `json:"epoch"`
}

// loadEpoch читает эпоху этой установки или заводит новую: первый запуск,
// буфер прежней версии без эпохи или spool_dir, начатый заново. Новая
// эпоха у источника, за которым хранилище уже закрепило другую, — отказ,
// пока оператор её не примет (evidencestore sources bind).
func (c *Collector) loadEpoch() error {
	var e epochFile
	found, err := readJSON(c.epochPath(), &e)
	switch {
	case err != nil:
		return err
	case found && !validEpoch(e.Epoch):
		return fmt.Errorf("collector: %s: %q is not an epoch", c.epochPath(), e.Epoch)
	case found:
		c.epoch = e.Epoch
		return nil
	}
	var raw [16]byte
	if _, err := rand.Read(raw[:]); err != nil {
		return err
	}
	e.Epoch = hex.EncodeToString(raw[:])
	if err := writeJSON(c.epochPath(), e); err != nil {
		return err
	}
	c.epoch = e.Epoch
	c.log.Info("collector epoch created: the store binds the source to the first installation it hears from", "epoch", c.epoch)
	return nil
}

// validEpoch — эпоха: 16 байт в строчном hex (store.ValidEpoch).
func validEpoch(e string) bool {
	b, err := hex.DecodeString(e)
	return err == nil && len(b) == 16 && e == strings.ToLower(e)
}

// repairPromises отрезает недописанную последнюю строку promises.jsonl
// (падение посреди записи): иначе к обрывку приклеится следующее обещание.
func (c *Collector) repairPromises() error {
	f, err := os.OpenFile(c.promisesPath(), os.O_RDWR, 0)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	defer f.Close()
	fi, err := f.Stat()
	if err != nil || fi.Size() == 0 {
		return err
	}
	// Обещание — сотни байт: конец последней целой строки — в хвосте файла.
	size := fi.Size()
	tail := make([]byte, min(size, 64<<10))
	if _, err := f.ReadAt(tail, size-int64(len(tail))); err != nil {
		return err
	}
	if tail[len(tail)-1] == '\n' {
		return nil
	}
	keep := size - int64(len(tail)) + int64(bytes.LastIndexByte(tail, '\n')+1)
	c.log.Warn("promises.jsonl: torn last line cut", "bytes", size-keep)
	return errors.Join(f.Truncate(keep), f.Sync())
}

// Close закрывает буфер и файлы.
func (c *Collector) Close() error {
	for _, t := range c.files {
		if t.f != nil {
			t.f.Close()
			t.f = nil
		}
	}
	var errs []error
	if c.spool != nil {
		errs = append(errs, c.spool.Close())
		c.spool = nil
	}
	if c.promises != nil {
		errs = append(errs, c.promises.Close())
		c.promises = nil
	}
	return errors.Join(errs...)
}

var (
	// ErrStoreKey — хранилище предъявило не тот ключ, что закреплён.
	ErrStoreKey = errors.New("collector: store presents another public key than the pinned one")
	// ErrStoreAhead — хранилище помнит номера, которых этот сборщик не
	// выдавал: spool_dir подняли из старой копии (снимок ВМ, бэкап) или
	// второй сборщик работает с тем же сертификатом.
	ErrStoreAhead = errors.New("collector: the store holds seqs this collector never issued")
	// ErrConflict — хранилище не приняло повтор занятого номера: под ним
	// другое тело (причины те же, что у ErrStoreAhead) или принятое тело
	// нечем сверить (ключ месяца ждёт уничтожения или уничтожен). Причину
	// называет хранилище; сборщик останавливается.
	ErrConflict = errors.New("collector: the store refused a resend under a taken seq")
	// ErrEpoch — хранилище закрепило источник за другой установкой
	// сборщика: эта останавливается. Если она — законная замена прежней
	// (переустановка, потерян spool_dir), её принимает оператор; команда — в
	// тексте ошибки.
	ErrEpoch = errors.New("collector: the store binds the source to another collector installation")
	// ErrBadPromise — ответ без обещания хранилища или с обещанием, которое
	// не сходится. Записи остаются в буфере.
	ErrBadPromise = errors.New("collector: store answer without a valid signed promise")
)

// stateResponse — ответ GET /v1/state (server.StateResponse: связь по
// именам JSON, её стерегут тесты на настоящем сервере).
type stateResponse struct {
	LastSeq   uint64 `json:"last_seq"`
	PublicKey string `json:"public_key"`
}

// fetchState — GET /v1/state. issued — последний выданный номер, когда всё
// выданное доставлено (пульс): по нему хранилище записывает пропуск в конце
// нумерации; ноль — не сообщать (запуск).
func (c *Collector) fetchState(ctx context.Context, issued uint64) (stateResponse, error) {
	var st stateResponse
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.cfg.Server+"/v1/state", nil)
	if err != nil {
		return st, err
	}
	req.Header.Set(epochHeader, c.epoch)
	if issued > 0 {
		req.Header.Set(issuedHeader, strconv.FormatUint(issued, 10))
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return st, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 64<<10))
		if err := epochRefused(resp, body); err != nil {
			return st, err
		}
		return st, fmt.Errorf("collector: state: %s: %s", resp.Status, strings.TrimSpace(string(body)))
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 64<<10)).Decode(&st); err != nil {
		return st, err
	}
	if base64.RawStdEncoding.EncodeToString(c.storeKey) != st.PublicKey {
		return st, ErrStoreKey
	}
	c.contactAt = c.now()
	return st, nil
}

// Bootstrap сверяется с хранилищем при запуске.
//
// Первый запуск: номер продолжается с последнего принятого хранилищем
// (после переустановки сборщика нумерация не начнётся заново), место
// чтения — конец файла (или начало с from_start); то и другое ложится в
// буфер записью «старт». Без хранилища первый запуск невозможен.
//
// Повторный: нумерация идёт из буфера, и хранилище может быть недоступно —
// записи подождут. Хранилище, которое помнит больше выданных номеров, —
// стоп: дальше сборщик выдавал бы занятые номера. Хранилище, которое
// помнит меньше, чем подтвердило (восстановлено из старой копии, потеряло
// диск), — тревога: в буфере лежат его подписанные обещания —
// доказательство потери.
func (c *Collector) Bootstrap(ctx context.Context) error {
	st, err := c.fetchState(ctx, 0)
	if errors.Is(err, ErrStoreKey) || errors.Is(err, ErrEpoch) {
		return err
	}
	if c.nextSeq != 0 {
		switch {
		case err != nil:
			c.log.Warn("store unreachable at start; records wait in the spool", "err", err)
		case st.LastSeq >= c.nextSeq:
			return fmt.Errorf("%w: it holds up to %d, this collector issued up to %d: spool_dir was restored from an old copy, or another collector uses this certificate",
				ErrStoreAhead, st.LastSeq, c.nextSeq-1)
		case st.LastSeq < c.acked:
			c.log.Error("store remembers fewer records than it acknowledged; its signed promises in the spool prove the loss",
				"store_last_seq", st.LastSeq, "acked", c.acked)
		}
		return nil
	}
	if err != nil {
		return err
	}
	c.nextSeq, c.acked = st.LastSeq+1, st.LastSeq
	if c.cfg.FromStart && st.LastSeq > 0 {
		c.log.Warn("from_start, but the store already holds records of this source: lines it has will come again under new numbers",
			"store_last_seq", st.LastSeq)
	}
	if err := c.registerExisting(); err != nil {
		return err
	}
	// Реестр первого запуска — в отдельный файл до записи «старт»: он нужен,
	// если упасть после «старт», до files.json, а в запись буфера тысячи
	// файлов под маской не уместились бы.
	if err := c.persist("start", func() error { return writeJSON(c.startPath(), c.fileList()) }); err != nil {
		return err
	}
	// Старт — первая запись буфера: с ним запуск уже не первый.
	if err := c.appendSpool([]spoolRecord{{kind: kindStart, seq: st.LastSeq}}); err != nil {
		return err
	}
	c.sentPos = c.spool.Next() - 1
	c.log.Info("collector bootstrap", "next_seq", c.nextSeq)
	return c.saveFiles()
}

// registerExisting — первый запуск: файлы на пути (под маской) — в реестр,
// чтобы ротированный до первого прохода нашёлся по inode. С from_start —
// с начала; без него то, что уже записано, не читается: место — конец
// последней целой строки (недописанная строка новая, и первая улика — не
// её обрывок).
func (c *Collector) registerExisting() error {
	seen, err := c.list()
	if err != nil {
		return err
	}
	for _, f := range seen {
		t := &tracked{ino: f.ino, path: f.path, head: fileHead(f.path), mtime: f.mtime, birth: birthAt(f.path, f.ino), size: -1}
		if !c.cfg.FromStart {
			t.off = lastLineEnd(f.path, f.size)
		}
		c.files[f.ino] = t
	}
	return nil
}

// Run читает файл и отправляет пачки до отмены ctx.
func (c *Collector) Run(ctx context.Context) error {
	if err := c.Bootstrap(ctx); err != nil {
		return err
	}
	backoff := time.Duration(0)
	var sendAt time.Time // раньше не слать: хранилище отказало
	for {
		if _, err := c.ReadOnce(); err != nil {
			// Буфер отказал (запись или fsync): что на диске, покажет только
			// чтение заново. Выход, рестарт.
			if ferr := c.spool.Failed(); ferr != nil {
				return fmt.Errorf("collector: spool failed: %w", ferr)
			}
			c.log.Error("read", "err", err)
		}
		if !time.Now().Before(sendAt) {
			if err := c.SendOnce(ctx); err != nil {
				if errors.Is(err, ErrConflict) || errors.Is(err, ErrEpoch) {
					return err
				}
				// Хранилище недоступно или отказало: записи ждут в буфере,
				// повтор с растущей паузой. Чтение идёт прежним шагом: пауза
				// доходит до минуты, и две ротации за неё теряли бы средний
				// файл (W-03).
				backoff = min(max(backoff*2, time.Second), time.Minute)
				sendAt = time.Now().Add(backoff)
				level := slog.LevelWarn
				if errors.Is(err, ErrBadPromise) || errors.Is(err, ErrStoreKey) {
					level = slog.LevelError
				}
				c.log.Log(ctx, level, "send", "err", err, "pending", c.pending, "retry_in", backoff)
			} else {
				backoff = 0
			}
		}
		select {
		case <-ctx.Done():
			return nil
		case <-time.After(c.cfg.FlushEvery.D()):
		}
	}
}

// ReadOnce — один проход: найти файлы, дочитать каждый, закрыть дочитанные.
//
// Реестр (c.files) знает каждый файл по inode: докуда прочитан, первую
// строку, где видели последний раз, открыт ли он и когда рос. Файл на пути
// журнала (под маской) читается, пока растёт. Ушедший оттуда —
// ротированный, ушедший из-под маски, удалённый — дочитывается через свой
// дескриптор, пока не замолчит на rotateQuiet: приложение пишет в него,
// пока не переоткроет журнал (logrotate create, затем HUP); только тогда
// берётся и последняя строка без перевода строки. Каждый файл — сам по
// себе: вторая ротация, пока первый ротированный ждёт тишины, ничего не
// теряет, и два писателя под одной маской друг другу не мешают. Раньше
// сборщик читал один «текущий» файл, а следующие ждали в очереди в памяти:
// каждое ожидание тишины открывало окно для потери (W-03, X-02, Y-02, Y-03,
// Y-04).
//
// Новый файл попадает в реестр записью 'P' в буфере — до своей первой
// строки: после падения сборщик знает о нём и найдёт по inode в каталоге,
// даже переименованный (Y-03, Y-05). Дочитанный и ушедший — записью 'D'.
//
// Найти нечем (сборщик стоял, а файл сжали, удалили или унесли из
// каталога) или файл обрезан (подменён) на месте — непрочитанное потеряно:
// сборщик пропускает номер, и хранилище запишет в цепь пропуск — потеря
// видна, а не тиха.
//
// Файл, который не открыть (права), — тоже в реестре: откроется, когда
// права исправят, где бы в каталоге ни лежал (Z-01, Z-02). Каталог, который
// не прочитать (права, нехватка дескрипторов, сбой ФС), — не «файлов нет»:
// по такому листингу ничего не решается, открытые файлы читаются дальше, а
// проход возвращает ошибку (Z-03).
func (c *Collector) ReadOnce() (int, error) {
	seen, listErr := c.list()
	if listErr == nil {
		if err := c.reconcile(seen); err != nil {
			return 0, err
		}
		c.firstPass = false
	}
	total := 0
	for _, t := range c.byAge() {
		n, err := c.readFile(t)
		total += n
		if err != nil {
			return total, err
		}
	}
	if err := c.retire(); err != nil {
		return total, err
	}
	return total, listErr
}

// rotateQuiet — сколько ушедший с пути файл должен молчать, чтобы считать
// его закрытым приложением. Переменная — чтобы тесты не ждали.
var rotateQuiet = 10 * time.Second

// idleQuiets — сколько rotateQuiet файл под маской молчит, прежде чем его
// дескриптор закрывается (если под маской есть файл новее): тысячи
// дописанных шардов не держат тысячи дескрипторов.
const idleQuiets = 6

// list — файлы на пути журнала или под маской.
func (c *Collector) list() ([]globFile, error) {
	if c.cfg.Glob != "" {
		files, err := c.globFiles()
		if err == nil && len(files) == 0 {
			c.warnMissing("no log files match the glob (yet)", c.cfg.Glob)
		}
		return files, err
	}
	fi, err := os.Stat(c.cfg.File)
	switch {
	case errors.Is(err, os.ErrNotExist):
		c.warnMissing("log file does not exist (yet)", c.cfg.File)
		return nil, nil
	case err != nil:
		return nil, err
	case !fi.Mode().IsRegular():
		return nil, fmt.Errorf("collector: %s is not a regular file", c.cfg.File)
	}
	return []globFile{{path: c.cfg.File, ino: inode(fi), size: fi.Size(), mtime: fi.ModTime().UnixNano()}}, nil
}

// track — запись реестра для inode (новая — пустая).
func (c *Collector) track(ino uint64) *tracked {
	t := c.files[ino]
	if t == nil {
		t = &tracked{ino: ino, size: -1}
		c.files[ino] = t
	}
	return t
}

// reconcile сверяет реестр с листингом: новые файлы — в реестр, ушедшие без
// дескриптора — искать по inode рядом, пропавшие — забыть.
func (c *Collector) reconcile(seen []globFile) error {
	for _, t := range c.files {
		t.listed = false
	}
	newest := int64(0)
	for _, t := range c.files {
		newest = max(newest, t.mtime)
	}
	for _, f := range seen {
		t := c.files[f.ino]
		// Закрытый файл, у которого не изменились размер и время, не
		// открывается: тысячи дописанных шардов — не тысячи вызовов за проход.
		if t != nil && t.f == nil && (f.size != t.off || f.mtime != t.mtime) && !c.same(t, f.path) {
			// inode удалённого файла ядро отдало новому: прежний дочитан, если
			// закрыт за простоем; иначе не узнать.
			if err := c.forget(t, !t.idle, "log file replaced under the same inode"); err != nil {
				return err
			}
			t = nil
		}
		if t == nil {
			var err error
			if t, err = c.adopt(f, newest); err != nil {
				return err
			}
			if t == nil {
				continue // не открыть: в следующий раз
			}
		}
		t.path, t.mtime, t.listed, t.lsize = f.path, f.mtime, true, f.size
	}
	for _, t := range c.files {
		switch {
		case t.listed:
			t.left = time.Time{}
		case t.left.IsZero():
			t.left = c.now() // ушёл: приложение пишет в него до HUP
		}
	}
	for _, t := range c.byAge() {
		if t.listed || t.f != nil {
			continue
		}
		// Ушёл с пути (из-под маски), а дескриптора нет: сборщик стоял или
		// закрыл его за простоем. Ротированный лежит рядом под другим именем.
		path, err := c.findInode(t)
		if err != nil {
			// Каталог не прочитать: файл не пропал, его не видно (Z-03).
			c.warnMissing("log directory cannot be read: "+err.Error(), filepath.Dir(t.path))
			continue
		}
		if path != "" {
			f, err := openInode(path, t.ino)
			if err != nil {
				// Не открыть (права) — ждёт в реестре, остальные файлы
				// читаются (Z-01); на inode другой файл — пропал.
				if b := birthAt(path, t.ino); t.birth == 0 || b == 0 || b == t.birth {
					t.path = path
					c.warnMissing("log file cannot be opened: "+err.Error(), path)
					continue
				}
			}
			if f != nil && sameFile(t, f) {
				t.f, t.path, t.size = f, path, -1
				continue
			}
			if f != nil {
				f.Close()
			}
		}
		// Нигде нет: закрытый за простоем был дочитан — без пропуска;
		// иначе дочитан ли он, не узнать — пропуск номера.
		if err := c.forget(t, !t.idle, "log file is gone"); err != nil {
			return err
		}
	}
	return nil
}

// adopt — новый файл: в реестр с начала и в буфер записью 'P' — до первой
// строки. Открывается сразу: ротированный дочитывается через этот
// дескриптор, даже если его тут же сожмут или удалят. Не открыть (права
// после logrotate create) — всё равно в реестр: откроется, когда права
// исправят, где бы ни лежал, а пропадёт раньше — пропуск номера, не тихая
// потеря (Z-02); остальные файлы читаются (X-03).
func (c *Collector) adopt(f globFile, newest int64) (*tracked, error) {
	fd, err := openInode(f.path, f.ino)
	if err == nil && fd == nil {
		return nil, nil // сменился между листингом и открытием
	}
	t := &tracked{ino: f.ino, path: f.path, mtime: f.mtime, size: -1}
	if err != nil {
		c.warnMissing("log file cannot be opened: "+err.Error(), f.path)
		t.birth = birthAt(f.path, f.ino)
	} else {
		t.f, t.birth = fd, birthOf(fd)
	}
	if err := c.mark(t); err != nil {
		if t.f != nil {
			t.f.Close()
		}
		return nil, err
	}
	c.files[f.ino] = t
	if !c.firstPass && f.mtime < newest-int64(c.quietFor) {
		c.log.Warn("a new log file is older than the ones already read by modification time; is the clock going back?", "file", f.path)
	}
	if t.f != nil {
		c.log.Info("reading log file", "file", f.path, "inode", f.ino)
	}
	return t, nil
}

// mark кладёт в буфер запись 'P': файл в реестре с этого места; номер —
// последний выданный (в том числе пропущенный), тело — первая строка, путь
// и время рождения через перевод строки.
func (c *Collector) mark(t *tracked) error {
	body := t.head + "\n" + t.path + "\n" + strconv.FormatInt(t.birth, 10)
	return c.appendSpool([]spoolRecord{{kind: kindPos, seq: c.nextSeq - 1, pos: filePos{t.ino, t.off}, body: []byte(body)}})
}

// same — файл по path с inode записи — тот же файл, что в реестре: то же
// рождение (если файловая система его знает; statx по пути — и у файла,
// который не открыть), иначе та же первая строка.
func (c *Collector) same(t *tracked, path string) bool {
	if b := birthAt(path, t.ino); t.birth != 0 && b != 0 {
		return b == t.birth
	}
	f, err := openInode(path, t.ino)
	if err != nil || f == nil {
		return true // не знаем — не значит «другой»
	}
	defer f.Close()
	return sameFile(t, f)
}

// sameFile — открытый файл с inode записи — тот же файл, что в реестре.
func sameFile(t *tracked, f *os.File) bool {
	if b := birthOf(f); t.birth != 0 && b != 0 {
		return b == t.birth
	}
	return t.off == 0 || headMatches(f, t.head)
}

// birthOf — время рождения открытого файла (statx btime), unix-нс; 0 —
// файловая система не знает.
func birthOf(f *os.File) int64 {
	var st unix.Statx_t
	if err := unix.Statx(int(f.Fd()), "", unix.AT_EMPTY_PATH, unix.STATX_BTIME, &st); err != nil || st.Mask&unix.STATX_BTIME == 0 {
		return 0
	}
	return st.Btime.Sec*1e9 + int64(st.Btime.Nsec)
}

// birthAt — время рождения файла по пути, если там файл с этим inode; 0 —
// не знаем. Файл не открывается: прав на чтение не нужно.
func birthAt(path string, ino uint64) int64 {
	var st unix.Statx_t
	if err := unix.Statx(unix.AT_FDCWD, path, 0, unix.STATX_BTIME|unix.STATX_INO, &st); err != nil ||
		st.Ino != ino || st.Mask&unix.STATX_BTIME == 0 {
		return 0
	}
	return st.Btime.Sec*1e9 + int64(st.Btime.Nsec)
}

// forget убирает файл из реестра записью 'D'; gap — непрочитанное могло
// пропасть: номер пропускается (в той же записи), хранилище запишет пропуск.
func (c *Collector) forget(t *tracked, gap bool, why string) error {
	if gap {
		c.log.Error(why+"; its unread tail may be lost: leaving a gap in numbering", "file", t.path, "inode", t.ino)
		c.nextSeq++
	}
	if err := c.appendSpool([]spoolRecord{{kind: kindDone, seq: c.nextSeq - 1, pos: filePos{t.ino, t.off}}}); err != nil {
		if gap {
			c.nextSeq--
		}
		return err
	}
	if t.f != nil {
		t.f.Close()
	}
	delete(c.files, t.ino)
	return nil
}

// byAge — реестр в порядке записи: по времени изменения, при равенстве — по
// имени с числами как числами.
func (c *Collector) byAge() []*tracked {
	out := make([]*tracked, 0, len(c.files))
	for _, t := range c.files {
		out = append(out, t)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].mtime != out[j].mtime {
			return out[i].mtime < out[j].mtime
		}
		if bi, bj := filepath.Base(out[i].path), filepath.Base(out[j].path); bi != bj {
			return naturalLess(bi, bj)
		}
		return out[i].ino < out[j].ino
	})
	return out
}

// readFile дочитывает файл: новые полные строки — в буфер с номерами.
func (c *Collector) readFile(t *tracked) (int, error) {
	if t.f == nil {
		// Закрыт (за простоем или до перезапуска) и на месте: открыть, если
		// изменился; путь журнала в режиме file — всегда.
		if !t.listed || (c.cfg.Glob != "" && t.lsize == t.off) {
			return 0, nil
		}
		f, err := openInode(t.path, t.ino)
		if err != nil {
			c.warnMissing("log file cannot be opened: "+err.Error(), t.path)
			return 0, nil
		}
		if f == nil {
			return 0, nil // переименован после листинга: найдётся в следующий раз
		}
		t.f, t.size, t.idle = f, -1, false
	}
	fi, err := t.f.Stat()
	if err != nil {
		return 0, err
	}
	if fi.Size() < t.off || c.replaced(t) {
		c.log.Error("log file truncated or replaced in place, unread lines are lost; leaving a gap in numbering", "file", t.path, "inode", t.ino)
		off, head := t.off, t.head
		c.nextSeq++
		t.off, t.head = 0, ""
		if err := c.mark(t); err != nil { // пропуск — в той же записи
			// Записи нет — нет и пропуска: номер и место назад, как в forget,
			// иначе пульс сообщил бы хранилищу номер, которого нет в буфере.
			c.nextSeq--
			t.off, t.head = off, head
			return 0, err
		}
	}
	if fi.Size() != t.size {
		t.size, t.growth = fi.Size(), c.now()
	}
	// Последняя строка без перевода строки берётся, когда файл замолчал и
	// ушёл с пути (под маской — когда есть файл новее): писатель его
	// закрыл.
	final := c.quiet(t) && (!t.listed || (c.cfg.Glob != "" && c.newerListed(t)))
	return c.readLines(t, final)
}

// quiet — файл не рос дольше rotateQuiet, а ушедший с пути — ещё и
// rotateQuiet с того, как сборщик заметил уход: приложение пишет в
// ротированный файл, пока не переоткроет журнал, и файл, молчавший до
// ротации, — не закрытый (Y-02).
func (c *Collector) quiet(t *tracked) bool {
	now := c.now()
	return !t.growth.IsZero() && now.Sub(t.growth) >= c.quietFor && (t.listed || now.Sub(t.left) >= c.quietFor)
}

// newerListed — под маской есть файл новее: писатель перешёл к нему.
func (c *Collector) newerListed(t *tracked) bool {
	for _, o := range c.files {
		if o != t && o.listed && o.mtime > t.mtime {
			return true
		}
	}
	return false
}

// replaced — на месте файла (тот же inode, тот же дескриптор) другое
// содержимое: первая строка не та (copytruncate, файл успел дорасти до
// прежнего места). Первую строку не прочитать — «не знаю», а не «подменён».
func (c *Collector) replaced(t *tracked) bool {
	if t.off == 0 || t.head == "" {
		return false
	}
	return !headMatches(t.f, t.head)
}

// retire закрывает дочитанное: ушедший с пути и замолчавший файл — из
// реестра (запись 'D'); файл под маской, долго молчащий, когда есть новее, —
// дескриптор закрыт (idle), место помнится.
func (c *Collector) retire() error {
	changed := false
	for _, t := range c.byAge() {
		if t.f == nil || !c.quiet(t) || t.off < t.size {
			continue
		}
		switch {
		case !t.listed:
			c.log.Info("log file done", "file", t.path, "inode", t.ino)
			if err := c.forget(t, false, ""); err != nil {
				return err
			}
		case c.cfg.Glob != "" && c.now().Sub(t.growth) >= idleQuiets*c.quietFor && c.newerListed(t):
			t.f.Close()
			t.f, t.idle, changed = nil, true, true
		}
	}
	if changed {
		return c.saveFiles()
	}
	return nil
}

// openInode открывает path, если это файл с этим inode; иначе nil.
func openInode(path string, ino uint64) (*os.File, error) {
	f, err := os.Open(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	fi, err := f.Stat()
	if err != nil || inode(fi) != ino {
		f.Close()
		return nil, err
	}
	return f, nil
}

// warnMissing говорит в журнал, что читать нечего или нельзя (опечатка в
// пути, пустая маска, права): раз в минуту на путь, а не молча.
func (c *Collector) warnMissing(msg, what string) {
	if c.warned == nil {
		c.warned = map[string]time.Time{}
	}
	if c.now().Sub(c.warned[what]) >= time.Minute {
		c.log.Warn(msg, "path", what)
		c.warned[what] = c.now()
	}
}

// globFile — файл под маской (или на пути журнала).
type globFile struct {
	path  string
	ino   uint64
	size  int64
	mtime int64 // unix-нс
}

// globFiles — файлы под маской (порядок чтения задаёт byAge). Каталог
// читается целиком, и ошибка чтения — ошибка: filepath.Glob её глотает, и
// нечитаемый каталог выглядел пустым — все файлы разом «уходили» (Z-03).
func (c *Collector) globFiles() ([]globFile, error) {
	dir, pattern := filepath.Dir(c.cfg.Glob), filepath.Base(c.cfg.Glob)
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, err
	}
	var out []globFile
	for _, e := range entries {
		if ok, _ := filepath.Match(pattern, e.Name()); !ok {
			continue
		}
		p := filepath.Join(dir, e.Name())
		fi, err := os.Stat(p)
		switch {
		case errors.Is(err, os.ErrNotExist):
			continue // удалён между листингом и взглядом
		case err != nil:
			return nil, err
		case !fi.Mode().IsRegular():
			continue
		}
		out = append(out, globFile{path: p, ino: inode(fi), size: fi.Size(), mtime: fi.ModTime().UnixNano()})
	}
	return out, nil
}

// headMatches — первая строка файла та же, что head; head "" — не знаем, и
// прочитать не вышло — тоже. Недописанная первая строка у файла, чья первая
// строка была дописана, — другой файл (inode удалённого достался новому).
func headMatches(f *os.File, head string) bool {
	if head == "" {
		return true
	}
	h, err := headOf(f)
	return err != nil || h == head
}

// fileList — реестр в порядке inode (для files.json).
func (c *Collector) fileList() []fileState {
	out := make([]fileState, 0, len(c.files))
	for _, t := range c.files {
		out = append(out, fileState{Inode: t.ino, Offset: t.off, MTime: t.mtime, Head: t.head, Path: t.path, Birth: t.birth, Idle: t.idle})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Inode < out[j].Inode })
	return out
}

// headOf — первая строка файла, не длиннее 64 байт; "" — первая строка
// короче 64 байт и ещё не дописана.
func headOf(f *os.File) (string, error) {
	buf := make([]byte, 64)
	n, err := f.ReadAt(buf, 0)
	if err != nil && !errors.Is(err, io.EOF) {
		return "", err
	}
	head, _, found := bytes.Cut(buf[:n], []byte("\n"))
	if !found && n < len(buf) {
		return "", nil
	}
	return string(head), nil
}

// fileHead — headOf по пути; "" — не прочитать или не дописана.
func fileHead(path string) string {
	f, err := os.Open(path)
	if err != nil {
		return ""
	}
	defer f.Close()
	h, _ := headOf(f)
	return h
}

// lastLineEnd — где кончается последняя целая строка файла: первый запуск
// без from_start встаёт туда, а не в середину недописанной строки.
func lastLineEnd(path string, size int64) int64 {
	f, err := os.Open(path)
	if err != nil {
		return size
	}
	defer f.Close()
	window := min(size, int64(evidence.MaxBodyLen)+1)
	buf := make([]byte, window)
	if _, err := f.ReadAt(buf, size-window); err != nil && !errors.Is(err, io.EOF) {
		return size
	}
	if i := bytes.LastIndexByte(buf, '\n'); i >= 0 {
		return size - window + int64(i) + 1
	}
	if window == size {
		return 0 // одна недописанная строка: она новая
	}
	return size
}

// naturalLess сравнивает имена так, что подряд идущие цифры — числа.
func naturalLess(a, b string) bool {
	for a != "" && b != "" {
		ca, cb := chunk(a), chunk(b)
		a, b = a[len(ca):], b[len(cb):]
		if ca == cb {
			continue
		}
		na, nb := strings.TrimLeft(ca, "0"), strings.TrimLeft(cb, "0")
		if isDigit(ca[0]) && isDigit(cb[0]) && na != nb {
			if len(na) != len(nb) {
				return len(na) < len(nb)
			}
			return na < nb
		}
		return ca < cb
	}
	return len(a) < len(b)
}

// chunk — первые подряд идущие цифры или не-цифры строки.
func chunk(s string) string {
	d := isDigit(s[0])
	i := 1
	for i < len(s) && isDigit(s[i]) == d {
		i++
	}
	return s[:i]
}

func isDigit(b byte) bool { return '0' <= b && b <= '9' }

// findInode ищет файл реестра по inode в каталоге, где его видели
// последний раз (или в каталоге журнала): так находится ротированный файл
// под новым именем после перезапуска или закрытия за простоем. "" — файла
// там нет; ошибка — каталог не прочитать, и про файл ничего не известно
// (Z-03).
func (c *Collector) findInode(t *tracked) (string, error) {
	dir := filepath.Dir(t.path)
	if t.path == "" {
		dir = filepath.Dir(c.cfg.File)
		if c.cfg.Glob != "" {
			dir = filepath.Dir(c.cfg.Glob)
		}
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		return "", err
	}
	for _, e := range entries {
		if fi, err := e.Info(); err == nil && fi.Mode().IsRegular() && inode(fi) == t.ino {
			return filepath.Join(dir, e.Name()), nil
		}
	}
	return "", nil
}

// readChunk — сколько байт тел копится в памяти до записи в буфер: файл
// любого размера читается без роста памяти. pieceLen — длина куска, на
// которые режется длинная строка. Переменные — чтобы симуляция писала в
// буфер часто и резала строки дёшево.
var (
	readChunk = 4 << 20
	pieceLen  = evidence.MaxBodyLen
)

// readLines читает открытый файл от места в реестре до его размера сейчас.
// final — файл больше не растёт: строка без перевода строки в конце тоже
// берётся.
func (c *Collector) readLines(t *tracked, final bool) (int, error) {
	fi, err := t.f.Stat()
	if err != nil {
		return 0, err
	}
	if fi.Size() <= t.off {
		return 0, nil
	}
	// Первая строка нового файла ложится в буфер записью 'P' в одной пачке с
	// его первыми строками и раньше них: есть в буфере строка файла — есть и
	// его первая строка (оборванный хвост буфера отрезается только с конца).
	// Отдельной записью после строк она оставляла окно: упал между ними —
	// первая строка неизвестна, и copytruncate с дорастанием за прежнее
	// место не виден (длинная симуляция: обрывки строк вместо потерянных).
	head := ""
	if t.off == 0 && t.head == "" {
		head, _ = headOf(t.f)
	}
	r := bufio.NewReaderSize(io.NewSectionReader(t.f, t.off, fi.Size()-t.off), 1<<20)
	var recs []spoolRecord
	size, total := 0, 0
	flush := func() error {
		if len(recs) == 0 {
			return nil
		}
		batch := recs
		if head != "" {
			hr := spoolRecord{kind: kindPos, seq: recs[0].seq - 1, pos: filePos{t.ino, 0}, body: []byte(head + "\n" + t.path + "\n" + strconv.FormatInt(t.birth, 10))}
			batch = append([]spoolRecord{hr}, recs...)
		}
		if err := c.appendSpool(batch); err != nil {
			c.nextSeq -= uint64(len(recs))
			return err
		}
		if head != "" {
			t.head, head = head, ""
		}
		t.off = recs[len(recs)-1].pos.Offset
		c.pending += len(recs)
		total += len(recs)
		recs, size = nil, 0
		return nil
	}
	off := t.off
	for {
		line, err := r.ReadBytes('\n')
		if err != nil && err != io.EOF {
			// Номера строк, не легших в буфер, возвращаются: иначе следующий
			// проход выдаст тем же строкам новые номера, а хранилище запишет
			// ложный пропуск.
			c.nextSeq -= uint64(len(recs))
			return total, err
		}
		if err == io.EOF && (!final || len(line) == 0) {
			break // недописанная строка ждёт перевода строки
		}
		start := off
		off += int64(len(line))
		body := bytes.TrimSuffix(line, []byte("\n"))
		for cut := 0; ; {
			n := min(len(body)-cut, pieceLen)
			end := off // после последнего куска — за переводом строки
			if cut+n < len(body) {
				end = start + int64(cut+n) // кусок длинной строки: сразу за ним
			}
			recs = append(recs, spoolRecord{kind: kindLine, seq: c.nextSeq, pos: filePos{t.ino, end}, body: body[cut : cut+n]})
			c.nextSeq++
			size += n
			if cut += n; cut == len(body) {
				break
			}
		}
		if size >= readChunk {
			if err := flush(); err != nil {
				return total, err
			}
		}
		if err == io.EOF {
			break
		}
	}
	return total, flush()
}

// maxBatchBytes — предел тел в одной пачке: с base64 и JSON ≈1,4 МиБ на
// проводе, пачка успевает за время ожидания и на медленном канале. Одна
// запись (кусок не длиннее MaxBodyLen) в предел помещается всегда.
const maxBatchBytes = 1 << 20

// SendOnce отправляет накопленное пачками, пока есть что и пока хранилище
// принимает. Доставленные сегменты буфера удаляются.
//
// Отправлять нечего, а хранилище не отвечало дольше heartbeat_every, —
// пульс: GET /v1/state, тот же запрос, что при старте. Без него хранилище
// не отличает тихий журнал от остановленного сборщика (P-05). Пульс идёт из
// того же цикла, что читает журнал: зависший цикл замолчит, как убитый
// процесс. Отказ эпохе в ответе на пульс — стоп, как при отправке: прежняя
// установка после sources bind останавливается и тогда, когда ей нечего
// слать.
func (c *Collector) SendOnce(ctx context.Context) error {
	for c.pending > 0 {
		batch, last, err := c.nextBatch()
		if err != nil {
			return err
		}
		if len(batch) == 0 {
			return fmt.Errorf("collector: %d records pending, none in the spool after position %d", c.pending, c.sentPos)
		}
		if err := c.send(ctx, batch); err != nil {
			return err
		}
		c.sentPos, c.pending = last, c.pending-len(batch)
		// Снимок реестра — раньше, чем доставленное уйдёт из буфера: места
		// файлов из освобождённых записей остаются в files.json.
		if err := c.saveFiles(); err != nil {
			return err
		}
		if err := c.spool.Release(c.sentPos); err != nil {
			return err
		}
	}
	now := c.now()
	if c.contactAt.IsZero() {
		c.contactAt = now
	}
	if now.Sub(c.contactAt) < c.cfg.HeartbeatEvery.D() {
		return nil
	}
	// Буфер пуст: всё выданное доставлено, и номер после последней
	// доставленной строки, пропущенный сборщиком, хранилище запишет
	// пропуском сейчас (Q-44).
	_, err := c.fetchState(ctx, c.nextSeq-min(c.nextSeq, 1))
	return err
}

// nextBatch — следующая пачка из буфера: строки после sentPos, не больше
// cfg.Batch записей и maxBatchBytes тел. last — позиция последней.
func (c *Collector) nextBatch() (batch []spoolRecord, last uint64, err error) {
	size := 0
	for p := c.sentPos + 1; p < c.spool.Next() && len(batch) < c.cfg.Batch; p++ {
		data, err := c.spool.Read(p)
		if err != nil {
			return nil, 0, err
		}
		r, err := parseRecord(data)
		if err != nil {
			return nil, 0, fmt.Errorf("collector spool position %d: %w", p, err)
		}
		if r.kind != kindLine {
			continue
		}
		if len(batch) > 0 && size+len(r.body) > maxBatchBytes {
			break
		}
		batch, last, size = append(batch, r), p, size+len(r.body)
	}
	return batch, last, nil
}

const (
	statusAccepted  = "accepted"
	statusDuplicate = "duplicate"
	// codeSeqConflict — ответ 409 с этим кодом: номер занят другим телом
	// (server.CodeSeqConflict).
	codeSeqConflict = "seq_conflict"
	// codeEpochMismatch — ответ 409 с этим кодом: источник закреплён за
	// другой установкой сборщика (server.CodeEpochMismatch).
	codeEpochMismatch = "epoch_mismatch"
	// epochHeader — заголовок с эпохой установки (server.EpochHeader).
	epochHeader = "Collector-Epoch"
	// issuedHeader — заголовок пульса с последним выданным номером
	// (server.IssuedHeader).
	issuedHeader = "Collector-Issued"
)

// errorResponse — тело ответа хранилища с ошибкой (server.ErrorResponse).
type errorResponse struct {
	Error string `json:"error"`
	Code  string `json:"code"`
}

// epochRefused — ErrEpoch, если хранилище отказало этой установке: в
// тексте хранилища — эпоха этой установки и команда оператору.
// Закреплённую эпоху хранилище не называет.
func epochRefused(resp *http.Response, body []byte) error {
	var e errorResponse
	if resp.StatusCode == http.StatusConflict && json.Unmarshal(body, &e) == nil && e.Code == codeEpochMismatch {
		return fmt.Errorf("%w: %s", ErrEpoch, e.Error)
	}
	return nil
}

// ingestResponse — ответ POST /v1/ingest (server.IngestResponse).
type ingestResponse struct {
	Results []struct {
		Seq      uint64         `json:"seq"`
		Status   string         `json:"status"`
		Position uint64         `json:"position"`
		Promise  *proof.Promise `json:"promise"`
	} `json:"results"`
}

// send отправляет пачку. Подтверждённой она становится, только если на
// каждую запись хранилище ответило «принято» или «повтор» и подписало
// обещание, которое сходится.
func (c *Collector) send(ctx context.Context, batch []spoolRecord) error {
	type rec struct {
		Seq  uint64 `json:"seq"`
		Body []byte `json:"body"`
	}
	req := struct {
		Records []rec `json:"records"`
	}{}
	for _, r := range batch {
		req.Records = append(req.Records, rec{r.seq, r.body})
	}
	data, err := json.Marshal(req)
	if err != nil {
		return err
	}
	hreq, err := http.NewRequestWithContext(ctx, http.MethodPost, c.cfg.Server+"/v1/ingest", bytes.NewReader(data))
	if err != nil {
		return err
	}
	hreq.Header.Set("Content-Type", "application/json")
	hreq.Header.Set(epochHeader, c.epoch)
	resp, err := c.http.Do(hreq)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 64<<20))
	if err != nil {
		return err
	}
	if resp.StatusCode != http.StatusOK {
		if err := epochRefused(resp, body); err != nil {
			return err
		}
		var e errorResponse
		if json.Unmarshal(body, &e) == nil && resp.StatusCode == http.StatusConflict && e.Code == codeSeqConflict {
			return fmt.Errorf("%w: %s", ErrConflict, e.Error)
		}
		return fmt.Errorf("store answered %s: %s", resp.Status, strings.TrimSpace(string(body)))
	}
	c.contactAt = c.now()
	answered := c.wall()
	var out ingestResponse
	if err := json.Unmarshal(body, &out); err != nil {
		return fmt.Errorf("store answered garbage: %w", err)
	}
	if len(out.Results) != len(batch) {
		return fmt.Errorf("store answered %d results for %d records", len(out.Results), len(batch))
	}
	var bad []error
	for i, r := range out.Results {
		switch {
		case r.Seq != batch[i].seq:
			return fmt.Errorf("store result %d: seq %d, sent %d", i, r.Seq, batch[i].seq)
		case r.Status != statusAccepted && r.Status != statusDuplicate:
			return fmt.Errorf("store result %d: seq %d status %q", i, r.Seq, r.Status)
		}
		if err := c.keepPromise(r.Promise, r.Position, batch[i], answered); err != nil {
			bad = append(bad, err)
		}
	}
	if err := c.promises.Sync(); err != nil {
		return err
	}
	if len(bad) > 0 {
		return errors.Join(append([]error{ErrBadPromise}, bad...)...)
	}
	c.acked = batch[len(batch)-1].seq
	return c.saveState()
}

// keepPromise проверяет обещание хранилища и сохраняет его. Проверяется
// подпись закреплённым ключом и то, что обещание — об этой записи
// (источник, номер, позиция). Отпечаток сборщик сверить не может: это
// отпечаток зашифрованной улики. Обещание, которое не сходится, кладётся
// отдельно (promises-rejected.jsonl) — это улика против хранилища, — а
// запись остаётся в буфере.
//
// Время приёма в обещании — слово хранилища, и сверить его может только
// сборщик: хранилище, сдвинувшее его вперёд и придержавшее запись, вывело
// бы её из окна, в которое она пришла, со сроком обещания, который она
// уложит (Q-56). Время приёма позже ответа (answered, часы сборщика) больше
// чем на receiveAhead — ошибка в журнал и обещание в promises-ahead.jsonl;
// запись доставлена: у хранилища она есть, повтор вернёт то же обещание.
// Так же и срок: дальше proof.MaxPromiseMMD от времени приёма он пропускает
// запись, придержанную за метку, что закрывает окно (Q-57), — ошибка в
// журнал и обещание в promises-deadline.jsonl. esverify -promise такой срок
// сам сужает до MaxPromiseMMD.
func (c *Collector) keepPromise(p *proof.Promise, position uint64, r spoolRecord, answered time.Time) error {
	if p == nil {
		c.log.Error("store answered without a promise; the record stays in the spool", "seq", r.seq)
		return fmt.Errorf("seq %d: no promise", r.seq)
	}
	var bad error
	if p.Source != c.source || p.Seq != r.seq || p.Position != position {
		bad = fmt.Errorf("seq %d at %d: promise is about %s/%d at %d", r.seq, position, p.Source, p.Seq, p.Position)
	} else if err := proof.VerifyPromise(*p, c.storeKey); err != nil {
		bad = fmt.Errorf("seq %d: %w", r.seq, err)
	}
	line, err := json.Marshal(p)
	if err != nil {
		return err
	}
	line = append(line, '\n')
	if bad != nil {
		c.log.Error("store promise rejected; the record stays in the spool", "err", bad)
		return errors.Join(bad, appendLine(filepath.Join(c.cfg.SpoolDir, rejectedFile), line))
	}
	// Запись оборвалась посреди строки (место кончилось) — обрывок
	// отрезается: иначе к нему приклеится следующее обещание. Запись
	// останется недоставленной, повтор получит обещание снова.
	fi, err := c.promises.Stat()
	if err != nil {
		return err
	}
	if _, err := c.promises.Write(line); err != nil {
		return errors.Join(err, c.promises.Truncate(fi.Size()))
	}
	var keep error
	if recv := time.Unix(0, p.ReceivedAt); recv.After(answered.Add(receiveAhead)) {
		c.log.Error("the store's promise gives a receive time later than its answer: the store may shift receive times to keep a record out of the window it arrived in; the promise is kept as evidence",
			"seq", r.seq, "receive_time", recv.UTC(), "answered", answered.UTC(), "file", aheadFile)
		keep = appendLine(filepath.Join(c.cfg.SpoolDir, aheadFile), line)
	}
	if mmd := time.Duration(p.Deadline - p.ReceivedAt); mmd > proof.MaxPromiseMMD {
		c.log.Error("the store's promise gives a deadline further from the receive time than allowed: a record held back past the time-stamp that closes its window would still meet it; the promise is kept as evidence",
			"seq", r.seq, "deadline_after", mmd, "allowed", proof.MaxPromiseMMD, "file", deadlineFile)
		keep = errors.Join(keep, appendLine(filepath.Join(c.cfg.SpoolDir, deadlineFile), line))
	}
	return keep
}

func appendLine(path string, line []byte) error {
	f, err := os.OpenFile(path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	_, err = f.Write(line)
	return errors.Join(err, f.Sync(), f.Close())
}

// Pending — сколько записей ждёт подтверждения.
func (c *Collector) Pending() int { return c.pending }

// Acked — последний подтверждённый номер.
func (c *Collector) Acked() uint64 { return c.acked }

func (c *Collector) saveState() error {
	return c.persist("state", func() error { return writeJSON(c.statePath(), state{Acked: c.acked}) })
}

func (c *Collector) saveFiles() error {
	return c.persist("files", func() error { return writeJSON(c.filesPath(), c.fileList()) })
}

// persist — запись на диск: тест роняет здесь процесс — до записи или
// сразу после неё.
func (c *Collector) persist(what string, write func() error) error {
	if c.persistHook != nil {
		if err := c.persistHook(what); err != nil {
			return err
		}
	}
	if err := write(); err != nil {
		return err
	}
	if c.persistHook != nil {
		return c.persistHook(what + "+")
	}
	return nil
}

// readJSON читает файл состояния; false — файла нет.
func readJSON(path string, v any) (bool, error) {
	data, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	if err := json.Unmarshal(data, v); err != nil {
		return false, fmt.Errorf("collector: %s: %w", filepath.Base(path), err)
	}
	return true, nil
}

// writeJSON заменяет файл состояния целиком: временный файл, fsync,
// переименование и fsync каталога — без него замена может откатиться при
// отключении питания.
func writeJSON(path string, v any) error {
	data, err := json.Marshal(v)
	if err != nil {
		return err
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, data, 0o600); err != nil {
		return err
	}
	f, err := os.Open(tmp)
	if err == nil {
		err = errors.Join(f.Sync(), f.Close())
	}
	if err == nil {
		err = os.Rename(tmp, path)
	}
	if err == nil {
		err = syncDir(filepath.Dir(path))
	}
	return err
}

func syncDir(dir string) error {
	d, err := os.Open(dir)
	if err != nil {
		return err
	}
	return errors.Join(d.Sync(), d.Close())
}

// --- буфер ---
//
// Запись буфера — данные записи evlog:
//
//	u8 вид | u64 номер | u64 inode | u64 смещение | тело
//
// Вид 'L' — строка (или кусок длинной строки); смещение — откуда читать
// этот файл после неё. Вид 'S' — старт, первая запись первого запуска: всё
// до этого номера включительно уже у хранилища (места файлов —
// start-files.json). Вид 'P' — файл в реестре с этого места: новый (с
// нуля) или после пропуска (обрезан, подменён); номер — последний выданный
// (в том числе пропущенный); тело — первая строка ("" — не знаем), перевод
// строки и путь. Вид 'D' — файл ушёл из реестра (дочитан или пропал);
// номер — последний выданный, с пропуском, если непрочитанное могло
// пропасть.
const (
	kindLine  byte = 'L'
	kindStart byte = 'S'
	kindPos   byte = 'P'
	kindDone  byte = 'D'
	recHead        = 1 + 8 + 8 + 8
)

type spoolRecord struct {
	kind byte
	seq  uint64
	pos  filePos // откуда читать файл после этой записи
	body []byte
}

func (r spoolRecord) marshal() []byte {
	b := make([]byte, 0, recHead+len(r.body))
	b = append(b, r.kind)
	b = binary.BigEndian.AppendUint64(b, r.seq)
	b = binary.BigEndian.AppendUint64(b, r.pos.Inode)
	b = binary.BigEndian.AppendUint64(b, uint64(r.pos.Offset))
	return append(b, r.body...)
}

func parseRecord(b []byte) (spoolRecord, error) {
	if len(b) < recHead || (b[0] != kindLine && b[0] != kindStart && b[0] != kindPos && b[0] != kindDone) {
		return spoolRecord{}, errors.New("not a spool record")
	}
	return spoolRecord{
		kind: b[0],
		seq:  binary.BigEndian.Uint64(b[1:]),
		pos:  filePos{Inode: binary.BigEndian.Uint64(b[9:]), Offset: int64(binary.BigEndian.Uint64(b[17:]))},
		body: b[recHead:],
	}, nil
}

func (c *Collector) appendSpool(recs []spoolRecord) error {
	data := make([][]byte, len(recs))
	for i, r := range recs {
		data[i] = r.marshal()
	}
	return c.persist("spool", func() error {
		_, err := c.spool.Append(data)
		return err
	})
}

func inode(fi os.FileInfo) uint64 {
	if st, ok := fi.Sys().(*syscall.Stat_t); ok {
		return st.Ino
	}
	return 0
}

// Promises читает сохранённые обещания (для проверки и отчётов). bad —
// сколько строк не разобралось: они пропускаются, целые обещания отдаются.
func Promises(spoolDir string) (_ map[uint64]proof.Promise, bad int, _ error) {
	f, err := os.Open(filepath.Join(spoolDir, "promises.jsonl"))
	if err != nil {
		return nil, 0, err
	}
	defer f.Close()
	out := map[uint64]proof.Promise{}
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 64<<10), 1<<20)
	for sc.Scan() {
		var p proof.Promise
		if err := json.Unmarshal(sc.Bytes(), &p); err != nil {
			bad++
			continue
		}
		out[p.Seq] = p
	}
	return out, bad, sc.Err()
}

// SortedSeqs — номера в порядке возрастания (для вывода).
func SortedSeqs(m map[uint64]proof.Promise) []string {
	var seqs []uint64
	for s := range m {
		seqs = append(seqs, s)
	}
	sort.Slice(seqs, func(i, j int) bool { return seqs[i] < seqs[j] })
	out := make([]string, len(seqs))
	for i, s := range seqs {
		out[i] = strconv.FormatUint(s, 10)
	}
	return out
}
