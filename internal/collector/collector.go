// Package collector — лёгкий сборщик рядом с источником.
//
// Читает файл журнала построчно, нумерует строки (Seq по порядку с 1),
// кладёт в дисковый буфер (spool) и отправляет пачками в хранилище по
// HTTPS с клиентским сертификатом. Запись уходит из буфера только после
// ответа «принято»: доставка «хотя бы один раз», повторы хранилище
// отбрасывает по (источник, номер).
//
// ПОЧЕМУ ПОЗИЦИЯ В ФАЙЛЕ ЛЕЖИТ В КАЖДОЙ ЗАПИСИ БУФЕРА. Если хранить
// «докуда прочитан файл» отдельно, падение между записью в буфер и
// сохранением позиции перечитает строки и выдаст им НОВЫЕ номера — у
// хранилища окажется две улики об одном событии. Позиция внутри записи
// буфера пишется одним fsync с самой строкой, и после падения чтение
// продолжается ровно с того места.
//
// Тело не трогается: строка уходит байт в байт (без перевода строки).
// Строка длиннее предела режется на куски, каждый — отдельная запись.
//
// Вместо одного файла можно читать файлы по маске (glob) — для источников,
// которые пишут новые файлы, а не ротируют один: бортовой журнал Pipelock
// кладёт каждый шард в новый файл evidence-<сессия>-<seq>.jsonl. Файлы идут
// по времени изменения, при равенстве — по имени, где числа сравниваются как
// числа. Текущий файл дочитывается до конца, когда за ним появился
// следующий: значит, писатель его закрыл. В каталоге — один писатель.
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
	"hash/crc32"
	"io"
	"log/slog"
	"net/http"
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
	"evidencestore/internal/proof"
)

// Config — настройки сборщика.
type Config struct {
	Server   string `json:"server"`    // https://host:port хранилища
	CA       string `json:"ca"`        // сертификат УЦ, выпустившего сертификат сервера
	Cert     string `json:"cert"`      // сертификат сборщика (CommonName = источник)
	Key      string `json:"key"`       // его ключ
	StoreKey string `json:"store_key"` // закреплённый открытый ключ хранилища (base64): проверка обещаний
	SpoolDir string `json:"spool_dir"`
	File     string `json:"file"` // читаемый файл журнала
	// Glob — маска файлов (filepath.Match) вместо file, когда источник
	// пишет новые файлы: "/var/lib/pipelock/recorder/evidence-*.jsonl".
	Glob string `json:"glob"`
	// FromStart — читать файл с начала (иначе — только новые строки).
	FromStart  bool            `json:"from_start"`
	Batch      int             `json:"batch"`
	FlushEvery config.Duration `json:"flush_every"`
}

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

func (c *Config) validate() error {
	if c.Batch <= 0 {
		c.Batch = 256
	}
	if c.FlushEvery == 0 {
		c.FlushEvery = config.Duration(time.Second)
	}
	var errs []error
	for name, v := range map[string]string{"server": c.Server, "ca": c.CA, "cert": c.Cert, "key": c.Key, "spool_dir": c.SpoolDir} {
		if v == "" {
			errs = append(errs, fmt.Errorf("%s is required", name))
		}
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

// Collector — один источник, один файл.
type Collector struct {
	cfg      *Config
	log      *slog.Logger
	http     *http.Client
	storeKey ed25519.PublicKey

	nextSeq uint64 // номер следующей строки
	acked   uint64 // всё до этого номера включительно принято хранилищем
	pos     filePos
	// globMTime — время изменения файла, на который сборщик перешёл последним
	// (режим glob): если текущий файл удалят, чтение продолжится с файлов не
	// старше его.
	globMTime int64
	// globHead — первая строка текущего файла (до 64 байт): номер inode
	// удалённого файла ядро отдаёт новому, и только содержимое отличает
	// новый файл от прежнего.
	globHead string

	spool    *os.File
	spoolLen int64
	pending  []spoolRecord // в буфере и ещё не приняты
	promises *os.File
}

type filePos struct {
	Inode  uint64 `json:"inode"`
	Offset int64  `json:"offset"`
}

type spoolRecord struct {
	seq  uint64
	pos  filePos // позиция в файле после этой строки
	body []byte
}

type state struct {
	Acked     uint64 `json:"acked"`
	GlobMTime int64  `json:"glob_mtime,omitempty"` // unix-нс, режим glob
	GlobHead  string `json:"glob_head,omitempty"`
}

// New поднимает сборщик: буфер, состояние, клиент TLS.
func New(cfg *Config, log *slog.Logger) (*Collector, error) {
	if log == nil {
		log = slog.New(slog.NewTextHandler(os.Stderr, nil))
	}
	c := &Collector{cfg: cfg, log: log}
	if cfg.StoreKey != "" {
		raw, err := base64.RawStdEncoding.DecodeString(strings.TrimRight(cfg.StoreKey, "="))
		if err != nil || len(raw) != ed25519.PublicKeySize {
			return nil, errors.New("collector: store_key must be a base64 Ed25519 public key")
		}
		c.storeKey = raw
	}
	cert, err := tls.LoadX509KeyPair(cfg.Cert, cfg.Key)
	if err != nil {
		return nil, fmt.Errorf("collector certificate: %w", err)
	}
	caPEM, err := os.ReadFile(cfg.CA)
	if err != nil {
		return nil, err
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(caPEM) {
		return nil, errors.New("collector: no certificates in ca")
	}
	c.http = &http.Client{Timeout: time.Minute, Transport: &http.Transport{
		TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS13, RootCAs: roots, Certificates: []tls.Certificate{cert}},
	}}
	if err := os.MkdirAll(cfg.SpoolDir, 0o700); err != nil {
		return nil, err
	}
	if err := c.load(); err != nil {
		return nil, err
	}
	return c, nil
}

func (c *Collector) spoolPath() string    { return filepath.Join(c.cfg.SpoolDir, "spool.log") }
func (c *Collector) statePath() string    { return filepath.Join(c.cfg.SpoolDir, "state.json") }
func (c *Collector) promisesPath() string { return filepath.Join(c.cfg.SpoolDir, "promises.jsonl") }

// load поднимает буфер и состояние после рестарта.
func (c *Collector) load() error {
	if data, err := os.ReadFile(c.statePath()); err == nil {
		var st state
		if err := json.Unmarshal(data, &st); err != nil {
			return fmt.Errorf("collector state: %w", err)
		}
		c.acked, c.globMTime, c.globHead = st.Acked, st.GlobMTime, st.GlobHead
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	f, err := os.OpenFile(c.spoolPath(), os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return err
	}
	c.spool = f
	recs, good, err := readSpool(f)
	if err != nil {
		return err
	}
	if err := f.Truncate(good); err != nil { // оборванный хвост: строки перечитаются из файла
		return err
	}
	if _, err := f.Seek(good, io.SeekStart); err != nil {
		return err
	}
	c.spoolLen = good
	for _, r := range recs {
		c.nextSeq = r.seq + 1
		c.pos = r.pos
		if r.seq > c.acked {
			c.pending = append(c.pending, r)
		}
	}
	if c.nextSeq == 0 && c.acked > 0 {
		c.nextSeq = c.acked + 1
	}
	if c.promises, err = os.OpenFile(c.promisesPath(), os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600); err != nil {
		return err
	}
	return nil
}

// Close закрывает файлы.
func (c *Collector) Close() error {
	return errors.Join(c.spool.Close(), c.promises.Close())
}

// ErrStoreKey — хранилище предъявило не тот ключ, что закреплён.
var ErrStoreKey = errors.New("collector: store presents another public key than the pinned one")

type storeState struct {
	LastSeq   uint64 `json:"last_seq"`
	PublicKey string `json:"public_key"`
}

func (c *Collector) storeState(ctx context.Context) (storeState, error) {
	var st storeState
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, c.cfg.Server+"/v1/state", nil)
	resp, err := c.http.Do(req)
	if err != nil {
		return st, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return st, fmt.Errorf("collector: state: %s: %s", resp.Status, body)
	}
	if err := json.NewDecoder(resp.Body).Decode(&st); err != nil {
		return st, err
	}
	if c.storeKey != nil && base64.RawStdEncoding.EncodeToString(c.storeKey) != st.PublicKey {
		return st, ErrStoreKey
	}
	return st, nil
}

// Bootstrap сверяется с хранилищем при запуске.
//
// Первый запуск: номер продолжается с последнего принятого хранилищем
// (после переустановки сборщика нумерация не начнётся заново); без
// хранилища первый запуск невозможен.
//
// Повторный: нумерация идёт из буфера, и хранилище может быть недоступно —
// записи подождут. Если же хранилище помнит меньше, чем подтвердило
// (восстановлено из старой копии, потеряло диск), это тревога: в буфере
// лежат его подписанные обещания — доказательство потери.
func (c *Collector) Bootstrap(ctx context.Context) error {
	st, err := c.storeState(ctx)
	if errors.Is(err, ErrStoreKey) {
		return err
	}
	if c.nextSeq != 0 {
		switch {
		case err != nil:
			c.log.Warn("store unreachable at start; records wait in the spool", "err", err)
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
	switch {
	case c.cfg.FromStart:
	case c.cfg.Glob != "":
		files, err := c.globFiles()
		if err != nil {
			return err
		}
		if len(files) > 0 {
			last := files[len(files)-1]
			c.pos, c.globMTime = filePos{Inode: last.ino, Offset: last.size}, last.mtime
		}
	default:
		if fi, err := os.Stat(c.cfg.File); err == nil {
			c.pos = filePos{Inode: inode(fi), Offset: fi.Size()}
		}
	}
	c.log.Info("collector bootstrap", "next_seq", c.nextSeq)
	return c.saveState()
}

// Run читает файл и отправляет пачки до отмены ctx.
func (c *Collector) Run(ctx context.Context) error {
	if err := c.Bootstrap(ctx); err != nil {
		return err
	}
	backoff := time.Duration(0)
	for {
		if _, err := c.ReadOnce(); err != nil {
			c.log.Error("read", "err", err)
		}
		wait := c.cfg.FlushEvery.D()
		if err := c.SendOnce(ctx); err != nil {
			// Хранилище недоступно или отказало: записи ждут в буфере,
			// повтор с растущей паузой.
			backoff = min(max(backoff*2, time.Second), time.Minute)
			wait = max(wait, backoff)
			c.log.Warn("send", "err", err, "pending", len(c.pending), "retry_in", wait)
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
// нет или файл обрезан на месте, его непрочитанный хвост потерян. Тогда
// сборщик пропускает один номер, и хранилище запишет в цепь пропуск: потеря
// видна, а не тиха.
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
		c.pos = filePos{Inode: cur}
	case cur != c.pos.Inode:
		if old := c.findByInode(c.pos.Inode); old != "" {
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
		c.pos = filePos{Inode: cur}
	case fi.Size() < c.pos.Offset:
		c.log.Error("log file truncated in place, unread lines are lost; leaving a gap in numbering", "file", c.cfg.File)
		c.nextSeq++
		c.pos.Offset = 0
	}
	n, err := c.readLines(c.cfg.File, false)
	return total + n, err
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

// readGlob — ReadOnce для маски: дочитать текущий файл и, если за ним уже
// есть следующий, перейти к нему.
func (c *Collector) readGlob() (int, error) {
	files, err := c.globFiles()
	if err != nil || len(files) == 0 {
		return 0, err
	}
	if c.pos.Inode == 0 {
		if err := c.switchTo(files[0]); err != nil {
			return 0, err
		}
	}
	total := 0
	for {
		i := slices.IndexFunc(files, func(f globFile) bool { return f.ino == c.pos.Inode })
		if i >= 0 && c.pos.Offset > 0 && c.globHead != "" && fileHead(files[i].path) != c.globHead {
			i = -1 // тот же inode, другой файл: прежний удалён
		}
		if i < 0 {
			// Текущий файл удалён, его непрочитанный хвост потерян: пропуск
			// номера в цепи хранилища, чтение — с файлов не старше его.
			j := slices.IndexFunc(files, func(f globFile) bool { return f.mtime >= c.globMTime })
			if c.globMTime == 0 {
				j = len(files) - 1 // время неизвестно: не перечитывать старое
			}
			if j < 0 {
				return total, nil // новых файлов ещё нет
			}
			c.log.Error("current log file is gone, its unread tail is lost; leaving a gap in numbering", "glob", c.cfg.Glob)
			c.nextSeq++
			if err := c.switchTo(files[j]); err != nil {
				return total, err
			}
			continue
		}
		final := i < len(files)-1
		n, err := c.readLines(files[i].path, final)
		total += n
		if n > 0 && c.globHead == "" {
			c.globHead = fileHead(files[i].path)
		}
		if err != nil || !final {
			return total, err
		}
		if err := c.switchTo(files[i+1]); err != nil {
			return total, err
		}
	}
}

// switchTo делает файл текущим и запоминает его время изменения.
func (c *Collector) switchTo(f globFile) error {
	c.pos, c.globMTime, c.globHead = filePos{Inode: f.ino}, f.mtime, ""
	c.log.Info("reading log file", "file", f.path)
	return c.saveState()
}

// fileHead — первая строка файла, не длиннее 64 байт.
func fileHead(path string) string {
	f, err := os.Open(path)
	if err != nil {
		return ""
	}
	defer f.Close()
	buf := make([]byte, 64)
	n, _ := io.ReadFull(f, buf)
	head, _, _ := bytes.Cut(buf[:n], []byte("\n"))
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
	off := c.pos.Offset
	for {
		line, err := r.ReadBytes('\n')
		if err != nil && err != io.EOF {
			return 0, err
		}
		if err == io.EOF && (!final || len(line) == 0) {
			break // недописанная строка ждёт перевода строки
		}
		start := off
		off += int64(len(line))
		body := bytes.TrimSuffix(line, []byte("\n"))
		for len(body) > evidence.MaxBodyLen {
			recs = append(recs, spoolRecord{seq: c.nextSeq, pos: filePos{c.pos.Inode, start}, body: body[:evidence.MaxBodyLen]})
			c.nextSeq++
			body = body[evidence.MaxBodyLen:]
		}
		recs = append(recs, spoolRecord{seq: c.nextSeq, pos: filePos{c.pos.Inode, off}, body: body})
		c.nextSeq++
		if err == io.EOF {
			break
		}
	}
	if len(recs) == 0 {
		return 0, nil
	}
	if err := c.appendSpool(recs); err != nil {
		c.nextSeq -= uint64(len(recs))
		return 0, err
	}
	c.pos = recs[len(recs)-1].pos
	c.pending = append(c.pending, recs...)
	return len(recs), nil
}

// maxBatchBytes — предел тел в одной пачке: с base64 и JSON пачка остаётся
// под пределом запроса хранилища (16 МиБ). Строка больше предела уходит
// одна.
const maxBatchBytes = 8 << 20

// SendOnce отправляет накопленное пачками, пока есть что и пока хранилище
// принимает.
func (c *Collector) SendOnce(ctx context.Context) error {
	for len(c.pending) > 0 {
		n, size := 0, 0
		for n < len(c.pending) && n < c.cfg.Batch && (n == 0 || size+len(c.pending[n].body) <= maxBatchBytes) {
			size += len(c.pending[n].body)
			n++
		}
		if err := c.send(ctx, c.pending[:n]); err != nil {
			return err
		}
		c.pending = c.pending[n:]
	}
	return c.compactSpool()
}

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
	data, _ := json.Marshal(req)
	hreq, _ := http.NewRequestWithContext(ctx, http.MethodPost, c.cfg.Server+"/v1/ingest", bytes.NewReader(data))
	hreq.Header.Set("Content-Type", "application/json")
	resp, err := c.http.Do(hreq)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 64<<20))
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("store answered %s: %s", resp.Status, strings.TrimSpace(string(body)))
	}
	var out struct {
		Results []struct {
			Seq     uint64         `json:"seq"`
			Status  string         `json:"status"`
			Promise *proof.Promise `json:"promise"`
		} `json:"results"`
	}
	if err := json.Unmarshal(body, &out); err != nil || len(out.Results) != len(batch) {
		return fmt.Errorf("store answered garbage: %v", err)
	}
	for i, r := range out.Results {
		if r.Seq != batch[i].seq || (r.Status != "accepted" && r.Status != "duplicate") {
			return fmt.Errorf("store result %d: seq %d status %q", i, r.Seq, r.Status)
		}
		if r.Promise != nil {
			if err := c.keepPromise(*r.Promise, batch[i]); err != nil {
				return err
			}
		}
	}
	if err := c.promises.Sync(); err != nil {
		return err
	}
	c.acked = batch[len(batch)-1].seq
	return c.saveState()
}

// keepPromise проверяет и сохраняет обещание хранилища. Обещание с чужим
// ключом или про другие байты — повод для тревоги: хранилище ведёт себя не
// так, как обязалось. Оно всё равно сохраняется: это улика против хранилища.
func (c *Collector) keepPromise(p proof.Promise, r spoolRecord) error {
	if c.storeKey != nil {
		if err := proof.VerifyPromise(p, c.storeKey); err != nil {
			c.log.Error("store promise does not verify", "seq", r.seq, "err", err)
		}
	}
	if p.Seq != r.seq || p.Source == "" {
		c.log.Error("store promise is about another record", "seq", r.seq, "promise_seq", p.Seq)
	}
	line, _ := json.Marshal(p)
	_, err := c.promises.Write(append(line, '\n'))
	return err
}

// Pending — сколько записей ждёт подтверждения.
func (c *Collector) Pending() int { return len(c.pending) }

// Acked — последний подтверждённый номер.
func (c *Collector) Acked() uint64 { return c.acked }

func (c *Collector) saveState() error {
	data, _ := json.Marshal(state{Acked: c.acked, GlobMTime: c.globMTime, GlobHead: c.globHead})
	tmp := c.statePath() + ".tmp"
	if err := os.WriteFile(tmp, data, 0o600); err != nil {
		return err
	}
	f, err := os.Open(tmp)
	if err == nil {
		err = errors.Join(f.Sync(), f.Close())
	}
	if err != nil {
		return err
	}
	return os.Rename(tmp, c.statePath())
}

// --- буфер ---
//
//	запись: u32 длина | u32 CRC-32C | u64 seq | u64 inode | u64 смещение | тело

var castagnoli = crc32.MakeTable(crc32.Castagnoli)

func (c *Collector) appendSpool(recs []spoolRecord) error {
	var buf []byte
	for _, r := range recs {
		payload := binary.BigEndian.AppendUint64(nil, r.seq)
		payload = binary.BigEndian.AppendUint64(payload, r.pos.Inode)
		payload = binary.BigEndian.AppendUint64(payload, uint64(r.pos.Offset))
		payload = append(payload, r.body...)
		buf = binary.BigEndian.AppendUint32(buf, uint32(len(payload)))
		buf = binary.BigEndian.AppendUint32(buf, crc32.Checksum(payload, castagnoli))
		buf = append(buf, payload...)
	}
	if _, err := c.spool.Write(buf); err != nil {
		return err
	}
	if err := c.spool.Sync(); err != nil {
		return err
	}
	c.spoolLen += int64(len(buf))
	return nil
}

func readSpool(f *os.File) ([]spoolRecord, int64, error) {
	data, err := io.ReadAll(f)
	if err != nil {
		return nil, 0, err
	}
	var out []spoolRecord
	off := 0
	for off+8 <= len(data) {
		n := int(binary.BigEndian.Uint32(data[off:]))
		if n < 24 || off+8+n > len(data) {
			break
		}
		payload := data[off+8 : off+8+n]
		if crc32.Checksum(payload, castagnoli) != binary.BigEndian.Uint32(data[off+4:]) {
			break
		}
		out = append(out, spoolRecord{
			seq:  binary.BigEndian.Uint64(payload),
			pos:  filePos{Inode: binary.BigEndian.Uint64(payload[8:]), Offset: int64(binary.BigEndian.Uint64(payload[16:]))},
			body: append([]byte(nil), payload[24:]...),
		})
		off += 8 + n
	}
	return out, int64(off), nil
}

// compactSpool переписывает буфер, когда в нём всё принято: последняя
// запись остаётся — в ней позиция в файле и номер.
func (c *Collector) compactSpool() error {
	if len(c.pending) > 0 || c.spoolLen < 1<<20 {
		return nil
	}
	f, err := os.Open(c.spoolPath())
	if err != nil {
		return err
	}
	recs, _, err := readSpool(f)
	f.Close()
	if err != nil || len(recs) == 0 {
		return err
	}
	last := recs[len(recs)-1]
	last.body = nil
	tmp := c.spoolPath() + ".tmp"
	nf, err := os.OpenFile(tmp, os.O_CREATE|os.O_TRUNC|os.O_RDWR, 0o600)
	if err != nil {
		return err
	}
	old := c.spool
	c.spool, c.spoolLen = nf, 0
	if err := c.appendSpool([]spoolRecord{last}); err != nil {
		c.spool = old
		nf.Close()
		return err
	}
	if err := os.Rename(tmp, c.spoolPath()); err != nil {
		return err
	}
	old.Close()
	d, err := os.Open(c.cfg.SpoolDir)
	if err != nil {
		return err
	}
	defer d.Close()
	return d.Sync()
}

func inode(fi os.FileInfo) uint64 {
	if st, ok := fi.Sys().(*syscall.Stat_t); ok {
		return st.Ino
	}
	return 0
}

// Promises читает сохранённые обещания (для проверки и отчётов).
func Promises(spoolDir string) (map[uint64]proof.Promise, error) {
	f, err := os.Open(filepath.Join(spoolDir, "promises.jsonl"))
	if err != nil {
		return nil, err
	}
	defer f.Close()
	out := map[uint64]proof.Promise{}
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 1<<20), 1<<20)
	for sc.Scan() {
		var p proof.Promise
		if err := json.Unmarshal(sc.Bytes(), &p); err != nil {
			return nil, err
		}
		out[p.Seq] = p
	}
	return out, sc.Err()
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
