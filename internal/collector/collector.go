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
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/binary"
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
	"slices"
	"sort"
	"strconv"
	"strings"
	"syscall"
	"time"

	"evidencestore/internal/config"
	"evidencestore/internal/evidence"
	"evidencestore/internal/evlog"
	"evidencestore/internal/proof"
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
	if (c.File == "") == (c.Glob == "") {
		errs = append(errs, errors.New("exactly one of file and glob is required"))
	}
	if c.Glob != "" {
		if _, err := filepath.Match(c.Glob, ""); err != nil {
			errs = append(errs, fmt.Errorf("glob %q: %w", c.Glob, err))
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

	nextSeq uint64  // номер следующей строки
	acked   uint64  // всё до этого номера включительно принято хранилищем
	pos     filePos // текущий файл и откуда читать его дальше
	// files — что сборщик знает о файлах (по inode): докуда прочитан — у
	// всех, кроме текущего (его место — pos), первая строка, время
	// изменения. В режиме glob — файлы под маской, уже прочитанные или
	// пропущенные первым запуском; в режиме file — только текущий.
	files map[uint64]fileState

	spool    *evlog.Log
	sentPos  uint64 // позиция в буфере: всё до неё включительно доставлено
	pending  int    // строк в буфере после sentPos
	promises *os.File
}

type filePos struct {
	Inode  uint64
	Offset int64
}

// fileState — файл в files.json.
type fileState struct {
	Inode  uint64 `json:"inode"`
	Offset int64  `json:"offset"`          // прочитано до
	MTime  int64  `json:"mtime,omitempty"` // unix-нс, время изменения при этом Offset
	Head   string `json:"head,omitempty"`  // первая строка, до 64 байт
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
	c := &Collector{cfg: cfg, log: log, files: map[uint64]fileState{}}
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
			// идут прямо в хранилище (docs/DECISIONS.md).
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
func (c *Collector) promisesPath() string { return filepath.Join(c.cfg.SpoolDir, "promises.jsonl") }

// rejectedFile — обещания, которые не сошлись: улика против хранилища.
const rejectedFile = "promises-rejected.jsonl"

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
	var files []fileState
	filesFound, err := readJSON(c.filesPath(), &files)
	if err != nil {
		return err
	}
	c.acked = st.Acked

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
		case r.seq <= last.seq:
			// Номера в буфере только растут; иначе буфер испорчен, и слать
			// из него нельзя.
			return fmt.Errorf("collector spool position %d: seq %d after %d", p, r.seq, last.seq)
		}
		if r.kind == kindStart {
			started = true
			c.acked = max(c.acked, r.seq)
			if !filesFound {
				if err := json.Unmarshal(r.body, &files); err != nil {
					return fmt.Errorf("collector spool start: %w", err)
				}
			}
		}
		if r.seq <= c.acked {
			c.sentPos = p
		} else if r.kind == kindLine {
			c.pending++
		}
		last, n = r, n+1
		return nil
	}
	if c.spool, err = evlog.Open(c.spoolDir(), evlog.Options{SegmentBytes: spoolSegmentBytes}, visit); err != nil {
		return fmt.Errorf("collector spool: %w", err)
	}
	switch {
	case n == 0 && (stateFound || filesFound):
		return errors.New("collector: the spool is empty, but state.json or files.json is there: the spool was lost, and the read position with it; " +
			"to start over, empty spool_dir (numbering continues from the store; lines not delivered are read again only with from_start)")
	case n == 0:
		c.sentPos = c.spool.Next() - 1 // первый запуск
	case !filesFound && !started:
		return errors.New("collector: files.json is missing and the spool no longer holds the start record: read positions are unknown")
	case c.acked > last.seq:
		return fmt.Errorf("collector: state.json says seq %d is delivered, but the spool ends at %d", c.acked, last.seq)
	default:
		c.nextSeq, c.pos = last.seq+1, last.pos
	}
	for _, f := range files {
		c.files[f.Inode] = f
	}
	if err := c.repairPromises(); err != nil {
		return err
	}
	c.promises, err = os.OpenFile(c.promisesPath(), os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600)
	return err
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
	// ErrConflict — хранилище держит под номером этого сборщика другое тело.
	// Причины те же, что у ErrStoreAhead; сборщик останавливается.
	ErrConflict = errors.New("collector: the store holds another body under a seq of this collector")
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

func (c *Collector) fetchState(ctx context.Context) (stateResponse, error) {
	var st stateResponse
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.cfg.Server+"/v1/state", nil)
	if err != nil {
		return st, err
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return st, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 64<<10))
		return st, fmt.Errorf("collector: state: %s: %s", resp.Status, strings.TrimSpace(string(body)))
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 64<<10)).Decode(&st); err != nil {
		return st, err
	}
	if base64.RawStdEncoding.EncodeToString(c.storeKey) != st.PublicKey {
		return st, ErrStoreKey
	}
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
	st, err := c.fetchState(ctx)
	if errors.Is(err, ErrStoreKey) {
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
	if !c.cfg.FromStart {
		if err := c.skipExisting(); err != nil {
			return err
		}
	}
	files, err := json.Marshal(c.fileList())
	if err != nil {
		return err
	}
	// Старт — первая запись буфера: с ним запуск уже не первый. В нём же
	// files.json — на случай падения до записи files.json.
	if err := c.appendSpool([]spoolRecord{{kind: kindStart, seq: st.LastSeq, pos: c.pos, body: files}}); err != nil {
		return err
	}
	c.sentPos = c.spool.Next() - 1
	c.log.Info("collector bootstrap", "next_seq", c.nextSeq)
	return c.saveFiles()
}

// skipExisting — первый запуск без from_start: то, что уже записано, не
// читается.
func (c *Collector) skipExisting() error {
	if c.cfg.Glob == "" {
		fi, err := os.Stat(c.cfg.File)
		if errors.Is(err, os.ErrNotExist) {
			return nil
		}
		if err != nil {
			return err
		}
		c.pos = filePos{Inode: inode(fi), Offset: fi.Size()}
		c.files[c.pos.Inode] = fileState{Inode: c.pos.Inode, Head: fileHead(c.cfg.File)}
		return nil
	}
	files, err := c.globFiles()
	if err != nil {
		return err
	}
	for _, f := range files {
		c.files[f.ino] = fileState{Inode: f.ino, Offset: f.size, MTime: f.mtime, Head: fileHead(f.path)}
	}
	return nil
}

// Run читает файл и отправляет пачки до отмены ctx.
func (c *Collector) Run(ctx context.Context) error {
	if err := c.Bootstrap(ctx); err != nil {
		return err
	}
	backoff := time.Duration(0)
	for {
		if _, err := c.ReadOnce(); err != nil {
			// Буфер отказал (запись или fsync): что на диске, покажет только
			// чтение заново. Выход, рестарт.
			if ferr := c.spool.Failed(); ferr != nil {
				return fmt.Errorf("collector: spool failed: %w", ferr)
			}
			c.log.Error("read", "err", err)
		}
		wait := c.cfg.FlushEvery.D()
		if err := c.SendOnce(ctx); err != nil {
			if errors.Is(err, ErrConflict) {
				return err
			}
			// Хранилище недоступно или отказало: записи ждут в буфере,
			// повтор с растущей паузой.
			backoff = min(max(backoff*2, time.Second), time.Minute)
			wait = max(wait, backoff)
			level := slog.LevelWarn
			if errors.Is(err, ErrBadPromise) {
				level = slog.LevelError
			}
			c.log.Log(ctx, level, "send", "err", err, "pending", c.pending, "retry_in", wait)
		} else {
			backoff = 0
		}
		select {
		case <-ctx.Done():
			return nil
		case <-time.After(wait):
		}
	}
}

// ReadOnce дочитывает файл: новые полные строки — в буфер с номерами.
//
// Ротация: прежде чем читать новый файл, дочитывается старый — его находят
// рядом по inode (audit.log → audit.log.1), и последняя строка без перевода
// строки там тоже берётся: файл больше не растёт. Если старого файла уже
// нет, или файл обрезан (подменён) на месте, его непрочитанный хвост
// потерян. Тогда сборщик пропускает один номер, и хранилище запишет в цепь
// пропуск: потеря видна, а не тиха.
func (c *Collector) ReadOnce() (int, error) {
	if c.cfg.Glob != "" {
		return c.readGlob()
	}
	fi, err := os.Stat(c.cfg.File)
	if errors.Is(err, os.ErrNotExist) {
		return 0, nil
	}
	if err != nil {
		return 0, err
	}
	total := 0
	switch cur := inode(fi); {
	case c.pos.Inode == 0:
		if err := c.follow(cur); err != nil {
			return 0, err
		}
	case cur != c.pos.Inode:
		if old := c.findByInode(c.pos.Inode); old != "" && !c.replaced(old) {
			n, err := c.readLines(old, true)
			total += n
			if err != nil {
				return total, err
			}
		} else {
			c.log.Error("rotated log file is gone, its unread tail is lost; leaving a gap in numbering", "file", c.cfg.File)
			c.nextSeq++
		}
		c.log.Info("log file rotated", "file", c.cfg.File)
		if err := c.follow(cur); err != nil {
			return total, err
		}
	case fi.Size() < c.pos.Offset || c.replaced(c.cfg.File):
		c.log.Error("log file truncated or replaced in place, unread lines are lost; leaving a gap in numbering", "file", c.cfg.File)
		c.nextSeq++
		if err := c.follow(cur); err != nil {
			return total, err
		}
	}
	n, err := c.readLines(c.cfg.File, false)
	total += n
	if err == nil && n > 0 {
		err = c.learnHead(c.cfg.File)
	}
	return total, err
}

// follow (режим file) делает текущим файл с этим inode, с начала. Прежний
// забывается.
func (c *Collector) follow(ino uint64) error {
	c.pos = filePos{Inode: ino}
	c.files = map[uint64]fileState{ino: {Inode: ino}}
	return c.saveFiles()
}

// replaced — на месте текущего файла (тот же inode) уже другой: первая
// строка не та. inode удалённого файла ядро отдаёт новому, а файл,
// обрезанный на месте (copytruncate), успевает дорасти до прежнего места.
func (c *Collector) replaced(path string) bool {
	head := c.files[c.pos.Inode].Head
	return c.pos.Offset > 0 && head != "" && fileHead(path) != head
}

// learnHead запоминает первую строку текущего файла, когда она дописана.
func (c *Collector) learnHead(path string) error {
	e := c.files[c.pos.Inode]
	if e.Head != "" {
		return nil
	}
	if e.Head = fileHead(path); e.Head == "" {
		return nil
	}
	e.Inode = c.pos.Inode
	c.files[c.pos.Inode] = e
	return c.saveFiles()
}

// globFile — файл под маской.
type globFile struct {
	path  string
	ino   uint64
	size  int64
	mtime int64 // unix-нс
}

// globFiles — файлы под маской в порядке записи: по времени изменения, при
// равенстве — по имени с числами как числами («-8» раньше «-16»).
func (c *Collector) globFiles() ([]globFile, error) {
	paths, err := filepath.Glob(c.cfg.Glob)
	if err != nil {
		return nil, err
	}
	var out []globFile
	for _, p := range paths {
		fi, err := os.Stat(p)
		if err != nil || !fi.Mode().IsRegular() {
			continue
		}
		out = append(out, globFile{path: p, ino: inode(fi), size: fi.Size(), mtime: fi.ModTime().UnixNano()})
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].mtime != out[j].mtime {
			return out[i].mtime < out[j].mtime
		}
		return naturalLess(filepath.Base(out[i].path), filepath.Base(out[j].path))
	})
	return out, nil
}

// readGlob — ReadOnce для маски: дочитать текущий файл и, если есть другой
// файл с непрочитанным, перейти к нему.
func (c *Collector) readGlob() (int, error) {
	files, err := c.globFiles()
	if err != nil {
		return 0, err
	}
	c.forgetGone(files)
	total := 0
	// Переходов за проход — не больше, чем файлов (с запасом): если вопреки
	// условию в каталоге пишут двое, проход всё равно кончается.
	for range 2*len(files) + 1 {
		cur := -1
		if c.pos.Inode != 0 {
			cur = slices.IndexFunc(files, func(f globFile) bool { return f.ino == c.pos.Inode })
			if cur < 0 || files[cur].size < c.pos.Offset || c.replaced(files[cur].path) {
				// Текущий файл удалён, обрезан или подменён: непрочитанный
				// хвост потерян. Пропуск номера в цепи хранилища, чтение — со
				// следующего файла.
				c.log.Error("current log file is gone, its unread tail is lost; leaving a gap in numbering", "glob", c.cfg.Glob)
				c.nextSeq++
				delete(c.files, c.pos.Inode)
				c.pos, cur = filePos{}, -1
			}
		}
		next := c.firstUnread(files)
		if cur < 0 {
			if next < 0 {
				return total, nil
			}
			if err := c.switchTo(files[next]); err != nil {
				return total, err
			}
			continue
		}
		if next >= 0 && next < cur {
			if _, known := c.files[files[next].ino]; !known {
				c.log.Warn("a new log file is older than the current one by modification time; is the clock going back?", "file", files[next].path)
			}
		}
		final := next >= 0
		n, err := c.readLines(files[cur].path, final)
		total += n
		if err == nil && n > 0 {
			err = c.learnHead(files[cur].path)
		}
		if err != nil || !final {
			return total, err
		}
		// Текущий дочитан: запомнить, докуда, и перейти к следующему.
		e := c.files[c.pos.Inode]
		e.Inode, e.Offset, e.MTime = c.pos.Inode, c.pos.Offset, files[cur].mtime
		c.files[c.pos.Inode] = e
		if err := c.switchTo(files[next]); err != nil {
			return total, err
		}
	}
	return total, nil
}

// switchTo делает файл текущим — с того места, докуда он прочитан раньше (0 —
// новый файл). files.json пишется до первой строки из нового файла: после
// падения прежний текущий уже числится прочитанным.
func (c *Collector) switchTo(f globFile) error {
	c.pos = filePos{Inode: f.ino, Offset: c.files[f.ino].Offset}
	c.log.Info("reading log file", "file", f.path, "offset", c.pos.Offset)
	return c.saveFiles()
}

// forgetGone забывает файлы, которых больше нет, и файлы, чей inode
// достался другому файлу (первая строка не та). Файл, у которого не
// изменились размер и время, не открывается.
func (c *Collector) forgetGone(files []globFile) {
	byIno := make(map[uint64]globFile, len(files))
	for _, f := range files {
		byIno[f.ino] = f
	}
	for ino, e := range c.files {
		if ino == c.pos.Inode {
			continue // текущий сверяется в readGlob
		}
		f, ok := byIno[ino]
		switch {
		case !ok:
			delete(c.files, ino)
		case f.size == e.Offset && f.mtime == e.MTime:
		case fileHead(f.path) != e.Head:
			delete(c.files, ino) // другой файл с тем же inode: читается с начала
		default:
			e.MTime = f.mtime
			c.files[ino] = e
		}
	}
}

// firstUnread — первый по порядку файл, кроме текущего, где есть
// непрочитанное: новый файл или известный, который дорос.
func (c *Collector) firstUnread(files []globFile) int {
	for i, f := range files {
		if f.ino != c.pos.Inode && f.size > c.files[f.ino].Offset {
			return i
		}
	}
	return -1
}

// fileList — files в порядке inode (для files.json).
func (c *Collector) fileList() []fileState {
	out := make([]fileState, 0, len(c.files))
	for _, f := range c.files {
		out = append(out, f)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Inode < out[j].Inode })
	return out
}

// fileHead — первая строка файла, не длиннее 64 байт; "" — первая строка
// короче 64 байт и ещё не дописана, или файла нет.
func fileHead(path string) string {
	f, err := os.Open(path)
	if err != nil {
		return ""
	}
	defer f.Close()
	buf := make([]byte, 64)
	n, _ := io.ReadFull(f, buf)
	head, _, found := bytes.Cut(buf[:n], []byte("\n"))
	if !found && n < len(buf) {
		return ""
	}
	return string(head)
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

// findByInode ищет в каталоге журнала файл с этим inode: так находится
// ротированный файл под новым именем.
func (c *Collector) findByInode(ino uint64) string {
	dir := filepath.Dir(c.cfg.File)
	entries, err := os.ReadDir(dir)
	if err != nil {
		return ""
	}
	for _, e := range entries {
		if fi, err := e.Info(); err == nil && fi.Mode().IsRegular() && inode(fi) == ino {
			return filepath.Join(dir, e.Name())
		}
	}
	return ""
}

// readChunk — сколько байт тел копится в памяти до записи в буфер: файл
// любого размера читается без роста памяти.
const readChunk = 4 << 20

// readLines читает path от текущей позиции до конца. final — файл больше не
// растёт: строка без перевода строки в конце тоже берётся.
func (c *Collector) readLines(path string, final bool) (int, error) {
	f, err := os.Open(path)
	if err != nil {
		return 0, err
	}
	defer f.Close()
	fi, err := f.Stat()
	if err != nil {
		return 0, err
	}
	if inode(fi) != c.pos.Inode || fi.Size() <= c.pos.Offset {
		return 0, nil // файл сменился между stat и open — прочтём в следующий раз
	}
	if _, err := f.Seek(c.pos.Offset, io.SeekStart); err != nil {
		return 0, err
	}
	r := bufio.NewReaderSize(f, 1<<20)
	var recs []spoolRecord
	size, total := 0, 0
	flush := func() error {
		if len(recs) == 0 {
			return nil
		}
		if err := c.appendSpool(recs); err != nil {
			c.nextSeq -= uint64(len(recs))
			return err
		}
		c.pos = recs[len(recs)-1].pos
		c.pending += len(recs)
		total += len(recs)
		recs, size = nil, 0
		return nil
	}
	off := c.pos.Offset
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
			n := min(len(body)-cut, evidence.MaxBodyLen)
			end := off // после последнего куска — за переводом строки
			if cut+n < len(body) {
				end = start + int64(cut+n) // кусок длинной строки: сразу за ним
			}
			recs = append(recs, spoolRecord{kind: kindLine, seq: c.nextSeq, pos: filePos{c.pos.Inode, end}, body: body[cut : cut+n]})
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
		if err := c.spool.Release(c.sentPos); err != nil {
			return err
		}
	}
	return nil
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
)

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
		var e struct {
			Error string `json:"error"`
			Code  string `json:"code"`
		}
		if json.Unmarshal(body, &e) == nil && resp.StatusCode == http.StatusConflict && e.Code == codeSeqConflict {
			return fmt.Errorf("%w: %s: spool_dir was restored from an old copy, or another collector uses this certificate", ErrConflict, e.Error)
		}
		return fmt.Errorf("store answered %s: %s", resp.Status, strings.TrimSpace(string(body)))
	}
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
		if err := c.keepPromise(r.Promise, r.Position, batch[i]); err != nil {
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
func (c *Collector) keepPromise(p *proof.Promise, position uint64, r spoolRecord) error {
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
	_, err = c.promises.Write(line)
	return err
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

func (c *Collector) saveState() error { return writeJSON(c.statePath(), state{Acked: c.acked}) }
func (c *Collector) saveFiles() error { return writeJSON(c.filesPath(), c.fileList()) }

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
// файл после неё. Вид 'S' — старт, первая запись первого запуска: всё до
// этого номера включительно уже у хранилища, читать — с этого места; тело —
// files.json на момент старта.
const (
	kindLine  byte = 'L'
	kindStart byte = 'S'
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
	if len(b) < recHead || (b[0] != kindLine && b[0] != kindStart) {
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
	_, err := c.spool.Append(data)
	return err
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
