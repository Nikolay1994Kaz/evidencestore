// Package store — движок хранилища улик: связывает кейринг, журнал улик,
// цепь и свидетеля времени.
//
// Путь улики (синхронно, до ответа «принято»):
//
//	Ingest: источник известен? (Source, Seq) уже был? → время приёма по
//	нашим монотонным часам → печать (keyring) → журнал улик, fsync →
//	лист в цепь (в порядке журнала) → подписанное обещание.
//
// В фоне: звено раз в тик, метка TSA над головой раз в N минут (токен
// ложится в цепь листом), ключи месяцев (завести, закрыть прошлый, добить
// уничтожение), контроль молчания источников.
//
// На диске (DataDir):
//
//	keyring.dat   ключи месяцев, заперты корнем из RootsDir
//	evidence/     журнал улик (evlog): сегменты только дописываются
//	chain/        цепь (auditchain) и ключ подписи хранилища sign.key
//	tsa-local/    ключи встроенной демо-службы меток, если она включена
//
// Всё, что меняет кейринг и цепь, идёт через этот процесс: у них один
// писатель. Администрирование — через unix-сокет (пакет server).
package store

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"evidencestore/internal/auditchain"
	"evidencestore/internal/config"
	"evidencestore/internal/evidence"
	"evidencestore/internal/evlog"
	"evidencestore/internal/gateway"
	"evidencestore/internal/keyring"
	"evidencestore/internal/ship"
	"evidencestore/internal/tsa"

	"golang.org/x/sys/unix"
)

var (
	ErrUnknownSource  = errors.New("store: unknown source")
	ErrSourceDisabled = errors.New("store: source disabled")
	ErrInFlight       = errors.New("store: record with this seq is being written right now")
	ErrNotFound       = errors.New("store: no such record")
	ErrBadRecord      = errors.New("store: bad record")
	// ErrSeqConflict — повтор занятого номера не принят: пришло другое тело
	// (сборщик откатили к старой копии, или второй сборщик работает с тем же
	// сертификатом) или принятое тело нечем сверить (ключ месяца ждёт
	// уничтожения или уничтожен). Причина — в тексте ошибки по каждому
	// номеру. Пачка не принята целиком, событие — в цепи.
	ErrSeqConflict = errors.New("store: resend under a taken seq refused")
	ErrClosed      = errors.New("store: closed")
	// ErrEvidenceLost — цепь знает улики, которых нет в журнале: журнал
	// потерял подтверждённые записи. Запускаться в таком состоянии нельзя.
	ErrEvidenceLost = errors.New("store: chain covers evidence missing from the log")
	// ErrKeyringMismatch — кейринг не сходится с квитанциями в цепи (откат
	// или подмена keyring.dat). Нужен разбор человеком.
	ErrKeyringMismatch = errors.New("store: keyring does not match key events in the chain")
	// ErrLocked — data_dir уже открыт другим процессом: два писателя одной
	// цепи сдвинули бы друг другу номера листов.
	ErrLocked = errors.New("store: data_dir is used by another evidencestore process")
)

// Options — то, что не входит в файл конфигурации.
type Options struct {
	Logger *slog.Logger
	// Now — часы; nil — time.Now. Тесты двигают их через месяцы.
	Now func() time.Time
	// HTTP — клиент для TSA; nil — с таймаутом 30 с.
	HTTP *http.Client
	// NoBackground — не запускать фоновые циклы (тесты зовут шаги сами).
	NoBackground bool
	// Mono — сколько прошло с открытия по монотонным часам: скачки настенных
	// часов на них не видны. nil — настоящие; при заданном Now — по нему.
	Mono func() time.Duration
}

// Store — работающий экземпляр хранилища.
type Store struct {
	cfg    *config.Config
	log    *slog.Logger
	now    func() time.Time
	mono   func() time.Duration
	opened time.Time

	keys     *keyring.Keyring
	evlog    *evlog.Log
	chain    *auditchain.Carrier
	signer   *auditchain.Signer
	chainDir string

	tsaURL   string
	tsaTrust tsa.Trust
	tsaLocal *tsa.Authority
	tsaHTTP  *http.Client

	// Якорь часов (под mu): время последней метки TSA этого процесса и
	// монотонные часы в тот момент. Время приёма не обгоняет «время TSA +
	// сколько прошло по монотонным часам» больше чем на clockSlack.
	anchorTSA  time.Time
	anchorMono time.Duration
	clockAhead bool // часы хоста сейчас впереди якоря (о начале — в журнал один раз)

	// mu — источники, индекс принятых, часы приёма.
	mu       sync.Mutex
	sources  map[string]*sourceState
	lastRecv int64

	// scopeMu — известные скоупы ключей и последние записанные в цепь
	// состояния. Порядок захвата: scopeMu раньше chainMu.
	scopeMu   sync.Mutex
	scopes    map[string]bool
	keyLabels map[string]string

	// chainMu — всё, что пишет в цепь или читает её файлы. Порядок
	// захвата: mu раньше chainMu, никогда наоборот.
	chainMu       sync.Mutex
	nextLeaf      uint64              // сквозной номер следующего листа
	linked        uint64              // сколько листьев накрыто звеньями
	links         []linkRef           // звенья по порядку
	evLeaf        []uint64            // evLeaf[pos-1] = номер листа улики + 1
	tokens        []tokenRef          // метки TSA, лёгшие в цепь листьями
	lastStamped   uint64              // голова, заверенная последней
	stampedLeaves uint64              // листьев в цепи сразу после последнего токена
	gwLeaf        map[uint64]uint64   // позиция улики гейтвея → лист её вердикта
	gwMarks       map[string][]gwMark // источник → контрольные точки и поломки по порядку

	// Копия наружу (replica.go).
	replicaMu     sync.Mutex
	replica       *replicaState
	replicaRemote ship.Remote

	stampMu sync.Mutex // метки по одной: фон и оператор не заверяют одну голову дважды

	// epochMu — эпоха сборщика закрепляется по одной (epoch.go). Порядок
	// захвата: epochMu раньше mu и chainMu.
	epochMu sync.Mutex

	orphanWarned string // о каких сиротах уже предупредили (Maintain)

	// Счётчики для /metrics с запуска (metrics.go).
	ingestErrors  atomic.Uint64
	clockCapped   atomic.Uint64 // время приёма срезано якорем TSA
	stampErrors   atomic.Uint64
	replicaErrors atomic.Uint64
	replicaOK     atomic.Int64 // unix-нс конца последней удачной копии

	stop      chan struct{}
	wg        sync.WaitGroup
	closeOnce sync.Once
	closed    bool

	lock *os.File // замок на data_dir (lockDataDir), держится до Close
}

type linkRef struct {
	seq, first, count uint64
}

type tokenRef struct {
	head uint64 // заверенная голова
	leaf uint64 // номер листа с токеном
	gen  time.Time
}

type sourceState struct {
	cfg      config.Source
	known    bool // есть в реестре; иначе улики остались от выведенного источника
	seqs     seqIndex
	maxSeq   uint64
	count    uint64
	lastAt   time.Time
	inflight map[uint64]bool
	silent   bool

	pendingGaps []gap // найденные пропуски, ещё не записанные в цепь

	// Журнал гейтвея (gateway.go); gw == nil — источник не гейтвей.
	gw         *gateway.Tracker
	gwMu       sync.Mutex    // пачки такого источника — по одной
	gwVerified uint64        // последняя позиция с вердиктом в цепи
	gwProblems atomic.Uint64 // записи с поломкой с момента запуска
	dups       atomic.Uint64 // повторно присланные записи с момента запуска
	conflicts  atomic.Uint64 // номер занят другим телом, с момента запуска

	// Эпоха сборщика (epoch.go): закреплённая за источником, "" — не
	// закреплена; эпохи, отказ которым уже лёг в цепь; отказы с запуска.
	epoch         string
	refusedEpochs map[string]bool
	epochRefused  atomic.Uint64
}

func (s *Store) nowTime() time.Time {
	if s.now != nil {
		return s.now()
	}
	return time.Now()
}

func dirs(cfg *config.Config) (evidenceDir, chainDir, tsaDir string) {
	return filepath.Join(cfg.DataDir, "evidence"), filepath.Join(cfg.DataDir, "chain"), filepath.Join(cfg.DataDir, "tsa-local")
}

func rootStore(cfg *config.Config) keyring.FileRoots {
	return keyring.FileRoots{Dir: cfg.RootsDir, Mirror: cfg.Keys.RootsMirrorDir}
}

func keyringOptions(cfg *config.Config, now func() time.Time) keyring.Options {
	opt := keyring.Options{MinWait: cfg.Keys.MinWait.D(), Now: now}
	if dir := cfg.Keys.BackupDir; dir != "" {
		opt.Backup = func(path string, gen uint64) error { return backupFile(path, dir, gen) }
	}
	return opt
}

// backupFile кладёт копию атомарно: tmp → fsync → rename, неудачная попытка
// прежнюю копию не портит (этого требует keyring.Options.Backup).
//
// gen > 0 — поколение keyring.dat. Оно записывается рядом (keyring.dat.gen),
// и копия младшего поколения поверх старшего не ложится: так
// keyring.dat, откатившийся вместе с диском, не затирает свежий резерв.
func backupFile(src, dir string, gen uint64) error {
	data, err := os.ReadFile(src)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	dst := filepath.Join(dir, filepath.Base(src))
	genPath := dst + ".gen"
	if gen > 0 {
		if b, err := os.ReadFile(genPath); err == nil {
			if have, err := strconv.ParseUint(strings.TrimSpace(string(b)), 10, 64); err == nil && have > gen {
				return fmt.Errorf("store: %s holds generation %d, newer than this keyring.dat (%d): refusing to overwrite the backup with an older file", dst, have, gen)
			}
		}
	}
	if err := writeAtomic(dst, data); err != nil {
		return err
	}
	if gen > 0 {
		return writeAtomic(genPath, []byte(strconv.FormatUint(gen, 10)+"\n"))
	}
	return nil
}

// writeAtomic: tmp → fsync → rename → fsync каталога.
func writeAtomic(dst string, data []byte) error {
	dir := filepath.Dir(dst)
	tmp := dst + ".tmp"
	f, err := os.OpenFile(tmp, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	_, werr := f.Write(data)
	serr := f.Sync()
	cerr := f.Close()
	if err := errors.Join(werr, serr, cerr); err != nil {
		os.Remove(tmp)
		return err
	}
	if err := os.Rename(tmp, dst); err != nil {
		return err
	}
	d, err := os.Open(dir)
	if err != nil {
		return err
	}
	defer d.Close()
	return d.Sync()
}

// lockDataDir берёт исключительный замок на data_dir (flock на файле LOCK).
// Замок держится до Close; упавший процесс снимает его вместе с собой.
func lockDataDir(dir string) (*os.File, error) {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, err
	}
	f, err := os.OpenFile(filepath.Join(dir, "LOCK"), os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return nil, err
	}
	if err := unix.Flock(int(f.Fd()), unix.LOCK_EX|unix.LOCK_NB); err != nil {
		f.Close()
		if errors.Is(err, unix.EWOULDBLOCK) {
			return nil, fmt.Errorf("%w: %s", ErrLocked, dir)
		}
		return nil, fmt.Errorf("lock %s: %w", dir, err)
	}
	return f, nil
}

// ErrBackupExists — в keys.backup_dir уже лежат ключи другого запуска init.
var ErrBackupExists = errors.New("store: keys.backup_dir already holds keyring.dat or sign.key")

// Init заводит хранилище: каталоги, кейринг под новым корнем, ключ подписи.
// Повторный Init на живом хранилище — ошибка (keyring.ErrExists). Init при
// ключах в резерве — тоже ошибка: так выглядит хранилище, потерявшее
// data_dir, и новый пустой кейринг затёр бы в резерве ключи всех месяцев.
func Init(cfg *config.Config) (publicKey string, err error) {
	for _, d := range []string{cfg.DataDir, cfg.RootsDir, cfg.Keys.RootsMirrorDir} {
		if d == "" {
			continue
		}
		if err := os.MkdirAll(d, 0o700); err != nil {
			return "", err
		}
	}
	lock, err := lockDataDir(cfg.DataDir)
	if err != nil {
		return "", err
	}
	defer lock.Close()
	if dir := cfg.Keys.BackupDir; dir != "" {
		for _, name := range []string{keyring.FileName, auditchain.SignKeyFileName} {
			if _, err := os.Stat(filepath.Join(dir, name)); err == nil {
				return "", fmt.Errorf("%w: %s — this store lost data_dir? restore keyring.dat and sign.key from there instead of init",
					ErrBackupExists, filepath.Join(dir, name))
			}
		}
	}
	k, err := keyring.Create(cfg.DataDir, rootStore(cfg), keyringOptions(cfg, nil))
	if err != nil {
		return "", err
	}
	k.Close()
	_, chainDir, tsaDir := dirs(cfg)
	if err := os.MkdirAll(chainDir, 0o700); err != nil {
		return "", err
	}
	signer, err := auditchain.LoadOrCreateSigner(chainDir)
	if err != nil {
		return "", err
	}
	if err := backupSigner(cfg, chainDir); err != nil {
		return "", err
	}
	if cfg.TSA.URL == "local" {
		if _, err := os.Stat(filepath.Join(tsaDir, "root.crt")); errors.Is(err, os.ErrNotExist) {
			a, err := tsa.NewAuthority(false)
			if err != nil {
				return "", err
			}
			if err := a.Save(tsaDir); err != nil {
				return "", err
			}
		}
	}
	return signer.PublicKeyString(), nil
}

// Open поднимает хранилище и восстанавливает всё, что не успело
// дописаться: листья цепи по журналу, квитанции ключей по кейрингу.
func Open(cfg *config.Config, opt Options) (*Store, error) {
	s := &Store{
		cfg:       cfg,
		log:       opt.Logger,
		now:       opt.Now,
		sources:   make(map[string]*sourceState),
		gwLeaf:    make(map[uint64]uint64),
		gwMarks:   make(map[string][]gwMark),
		scopes:    make(map[string]bool),
		keyLabels: make(map[string]string),
		stop:      make(chan struct{}),
		tsaHTTP:   opt.HTTP,
	}
	if s.log == nil {
		s.log = slog.New(slog.NewTextHandler(os.Stderr, nil))
	}
	if s.tsaHTTP == nil {
		s.tsaHTTP = &http.Client{Timeout: 30 * time.Second}
	}
	s.opened = s.nowTime()
	s.mono = opt.Mono
	if s.mono == nil {
		if opt.Now != nil {
			s.mono = func() time.Duration { return s.nowTime().Sub(s.opened) } // часы теста — без монотонной части
		} else {
			start := time.Now()
			s.mono = func() time.Duration { return time.Since(start) }
		}
	}
	for _, src := range cfg.Sources {
		s.sources[src.Name] = &sourceState{cfg: src, known: true, inflight: map[uint64]bool{}, gw: newTracker(src)}
	}
	lock, err := lockDataDir(cfg.DataDir)
	if err != nil {
		return nil, err
	}
	s.lock = lock
	if err := s.open(); err != nil {
		s.closeFiles()
		return nil, err
	}
	if !opt.NoBackground {
		s.startBackground()
	}
	return s, nil
}

func (s *Store) open() error {
	cfg := s.cfg
	evDir, chainDir, tsaDir := dirs(cfg)
	s.chainDir = chainDir

	var err error
	if s.keys, err = keyring.Open(cfg.DataDir, rootStore(cfg), keyringOptions(cfg, s.now)); err != nil {
		if errors.Is(err, keyring.ErrNotFound) {
			return fmt.Errorf("%w (first run: `evidencestore init`; after losing data_dir: put keyring.dat and sign.key back from keys.backup_dir)", err)
		}
		return err
	}
	if cfg.Keys.BackupDir == "" {
		s.log.Warn("keys.backup_dir is not set: keyring.dat has no copy, and losing data_dir loses the keys of every month")
	}
	if err := s.keys.RepairRoots(); err != nil {
		s.log.Warn("keyring root copies", "err", err)
	}
	// Зеркало корней на упавшей машине не мешает стартовать: корни читаются
	// из roots_dir. Окончательность уничтожения ждёт, пока зеркало не
	// откликнется (keyring.finishLocked).
	if orphans, err := s.keys.OrphanRoots(); err != nil {
		s.log.Warn("keyring roots cannot be listed (is keys.roots_mirror_dir reachable?): key destruction stays non-final meanwhile", "err", err)
	} else if len(orphans) > 0 {
		s.log.Warn("keyring roots unknown to keyring.dat: destruction stays non-final until `evidencestore keys destroy-orphan-roots`", "roots", orphans)
	}
	if err := s.openTSA(tsaDir); err != nil {
		return err
	}
	if cfg.Replica.URL != "" {
		if s.replicaRemote, err = ship.OpenRemote(cfg.Replica.URL); err != nil {
			return err
		}
	}
	if s.chain, err = auditchain.Open(chainDir); err != nil {
		return fmt.Errorf("chain: %w", err)
	}
	s.logChainRecovery(s.chain.Recovery())
	// Ключ подписи заводит init. Цепь есть, а ключа нет — ключ потерян: новый
	// ключ молча сменил бы подпись, и сборщики с проверяющими, закрепившие
	// старый, перестали бы принимать хранилище.
	if _, err := os.Stat(filepath.Join(chainDir, auditchain.SignKeyFileName)); errors.Is(err, os.ErrNotExist) && s.chain.Head().Seq > 0 {
		return fmt.Errorf("store: %s is missing while the chain holds %d links: put sign.key back from keys.backup_dir",
			filepath.Join(chainDir, auditchain.SignKeyFileName), s.chain.Head().Seq)
	}
	if s.signer, err = auditchain.LoadOrCreateSigner(chainDir); err != nil {
		return err
	}
	if err := backupSigner(cfg, chainDir); err != nil {
		s.log.Warn("signing key backup", "err", err)
	}
	cs, err := s.scanChain()
	if err != nil {
		return err
	}
	maxChained := cs.maxPos

	var maxRecv int64
	var tail []pending              // улики, которых ещё нет в цепи
	var gwTail []pending            // улики гейтвея без вердикта в цепи
	keyUse := map[[16]byte]uint64{} // ключ → первая улика под ним
	tailSources := map[string]bool{}
	visit := func(pos uint64, data []byte) error {
		sealed, err := evidence.Unmarshal(data)
		if err != nil {
			return fmt.Errorf("evidence log position %d: %w", pos, err)
		}
		if id, ok := keyring.KEKIDOf(sealed.Envelope); ok {
			if _, seen := keyUse[id]; !seen {
				keyUse[id] = pos
			}
		}
		s.indexRecord(sealed.Header, pos)
		maxRecv = max(maxRecv, sealed.ReceivedAt)
		if pos > maxChained {
			tail = append(tail, pending{pos: pos, header: sealed.Header, digest: evidence.Digest(data)})
			tailSources[sealed.Source] = true
		}
		if st := s.sources[sealed.Source]; st != nil && st.gw != nil && pos > st.gwVerified {
			gwTail = append(gwTail, pending{pos: pos, header: sealed.Header, envelope: sealed.Envelope})
		}
		return nil
	}
	if s.evlog, err = evlog.Open(evDir, evlog.Options{OnCommit: s.onCommit}, visit); err != nil {
		return fmt.Errorf("evidence log: %w", err)
	}
	if r := s.evlog.Recovery(); r.TornTailBytes > 0 {
		s.log.Warn("evidence log: torn tail cut and set aside", "bytes", r.TornTailBytes, "file", r.TornTailFile)
	}
	if maxChained >= s.evlog.Next() {
		return fmt.Errorf("%w: chain covers position %d, log ends at %d", ErrEvidenceLost, maxChained, s.evlog.Next()-1)
	}
	if err := s.checkKeyUse(keyUse); err != nil {
		return err
	}
	s.lastRecv = maxRecv
	if ahead := time.Duration(maxRecv - s.nowTime().UnixNano()); ahead > clockSlack {
		s.log.Error("the evidence log holds receive times ahead of the host clock (an earlier clock jump): new records keep receive times monotonic, so they are ahead too until the clock catches up",
			"ahead", ahead)
	}
	if len(tail) > 0 {
		s.log.Info("chain catch-up", "records", len(tail))
		s.chainMu.Lock()
		for _, p := range tail {
			s.appendEvidenceLocked(p.header, p.pos, p.digest)
		}
		s.chainMu.Unlock()
		s.announceTailGaps(cs.maxSeq, tailSources)
	}
	// «Источник молчит» записан в цепь и с тех пор от него ничего нет: эпизод
	// молчания продолжается, второе событие о нём не нужно.
	s.mu.Lock()
	for name := range cs.silent {
		if st := s.sources[name]; st != nil && !tailSources[name] {
			st.silent = true
		}
	}
	s.mu.Unlock()
	// Вердикты гейтвея, не успевшие лечь в цепь до падения: тела вскрываются
	// ключами месяца и проверяются заново, в порядке журнала.
	for _, p := range gwTail {
		st := s.sources[p.header.Source]
		var v gateway.Verdict
		if body, err := s.keys.Unseal(p.envelope); err != nil {
			v = gateway.Verdict{Problem: "catch-up after restart: body unavailable: " + err.Error()}
		} else {
			v = st.gw.Check(body)
		}
		s.appendGatewayVerdict(st, p.header, p.pos, v)
	}
	if err := s.reconcileKeys(cs.keyEvents); err != nil {
		return err
	}
	s.appendEvent(auditchain.EventStart, "", "", []byte(s.signer.PublicKeyString()))
	if err := s.ensureMonthScopes(s.nowTime()); err != nil {
		return err
	}
	return s.flush()
}

// checkKeyUse: каждый ключ, под которым запечатаны улики журнала, известен
// кейрингу — живым или надгробием. Иначе keyring.dat не тот (чужой или
// поднят из резерва старше этих улик): тела под незнакомым ключом не
// открыть, а сироты, которых он не знает, нельзя уничтожать. Сверка с цепью
// этого не видит, если квитанция ключа не успела лечь в цепь до падения.
func (s *Store) checkKeyUse(use map[[16]byte]uint64) error {
	known := map[[16]byte]bool{}
	for _, ki := range s.keys.List() {
		known[ki.KEKID] = true
	}
	var errs []error
	for id, pos := range use {
		if !known[id] {
			errs = append(errs, fmt.Errorf("%w: evidence at position %d is sealed with key %x, unknown to keyring.dat (wrong file, or restored from a backup older than this evidence)", ErrKeyringMismatch, pos, id))
		}
	}
	return errors.Join(errs...)
}

type pending struct {
	pos      uint64
	header   evidence.Header
	digest   [32]byte
	envelope []byte // только у улик гейтвея
}

func (s *Store) openTSA(dir string) error {
	switch s.cfg.TSA.URL {
	case "":
		return nil
	case "local":
		a, err := tsa.LoadAuthority(dir)
		if err != nil {
			return fmt.Errorf("local demo TSA keys are missing in %s (`evidencestore init` creates them only for a new store; restore that directory or set tsa.url to a real TSA): %w", dir, err)
		}
		// Встроенная служба живёт в этом процессе и по его часам (тесты
		// двигают их); настоящая TSA, разумеется, по своим.
		a.Now = s.now
		s.tsaLocal = a
		s.tsaTrust = a.Trust()
		return nil
	}
	s.tsaURL = s.cfg.TSA.URL
	trust, err := tsa.LoadTrust(joinPaths(s.cfg.TSA.Trust))
	if err != nil {
		return err
	}
	s.tsaTrust = trust
	return nil
}

func joinPaths(ps []string) string {
	out := ""
	for i, p := range ps {
		if i > 0 {
			out += ","
		}
		out += p
	}
	return out
}

// TSATrust — доверие к службе меток, которым пользуется хранилище. Для
// встроенной демо-службы — её корень.
func (s *Store) TSATrust() tsa.Trust { return s.tsaTrust }

// TSARoot — корень встроенной демо-службы (nil для внешней).
func (s *Store) TSARoot() []byte {
	if s.tsaLocal == nil {
		return nil
	}
	return s.tsaLocal.Root().Raw
}

// PublicKey — открытый ключ хранилища: его закрепляют проверяющий и сборщики.
func (s *Store) PublicKey() string { return s.signer.PublicKeyString() }

// Close останавливает фон, сворачивает хвост цепи в звено и закрывает файлы.
func (s *Store) Close() error {
	var err error
	s.closeOnce.Do(func() {
		close(s.stop)
		s.wg.Wait()
		s.mu.Lock()
		s.closed = true
		s.mu.Unlock()
		if s.evlog != nil {
			// Журнал закрывается первым и дожидается начатых пачек: их листья
			// успеют лечь в цепь до последнего звена. Повторный Close журнала
			// в closeFiles безвреден.
			err = errors.Join(err, s.evlog.Close())
		}
		err = errors.Join(err, s.flush())
		err = errors.Join(err, s.closeFiles())
	})
	return err
}

func (s *Store) closeFiles() error {
	var err error
	if s.evlog != nil {
		err = errors.Join(err, s.evlog.Close())
	}
	if s.chain != nil {
		err = errors.Join(err, s.chain.Close())
	}
	if s.keys != nil {
		err = errors.Join(err, s.keys.Close())
	}
	if s.lock != nil {
		err = errors.Join(err, s.lock.Close())
		s.lock = nil
	}
	return err
}

// Healthy — можно ли принимать: ни журнал улик, ни цепь не защёлкнуты
// ошибкой. Улика, которая не ляжет в цепь, — обещание, которое не будет
// выполнено.
func (s *Store) Healthy() error {
	s.mu.Lock()
	closed := s.closed
	s.mu.Unlock()
	if closed {
		return ErrClosed
	}
	if err := s.evlog.Failed(); err != nil {
		return err
	}
	return s.chain.Failed()
}

// logChainRecovery говорит вслух о том, что носитель цепи нашёл при
// открытии.
func (s *Store) logChainRecovery(r auditchain.Recovery) {
	if r.TornTailBytes > 0 {
		s.log.Warn("chain: torn tail cut and set aside", "bytes", r.TornTailBytes, "file", r.TornTailFile)
	}
	if r.HeadAdvanced > 0 {
		s.log.Warn("chain: head lagged behind the log and was advanced", "links", r.HeadAdvanced)
	}
	if r.HeadSlotDamaged {
		s.log.Warn("chain: a head slot is damaged (a failure while writing the head, or tampering): links after the valid slot are not checked against a saved head")
	}
	if r.LeavesWithoutRoot > 0 {
		s.log.Info("chain: leaves without a link are linked now", "leaves", r.LeavesWithoutRoot)
	}
}

// backupSigner кладёт ключ подписи в keys.backup_dir, если там его нет или
// он другой: в копию наружу он не уезжает, а без него восстановленное
// хранилище подписывало бы головы новым ключом, и проверяющие с закреплённым
// старым ключом их не приняли бы.
func backupSigner(cfg *config.Config, chainDir string) error {
	dir := cfg.Keys.BackupDir
	if dir == "" {
		return nil
	}
	src := filepath.Join(chainDir, auditchain.SignKeyFileName)
	have, err := os.ReadFile(filepath.Join(dir, auditchain.SignKeyFileName))
	if err == nil {
		want, err := os.ReadFile(src)
		if err != nil {
			return err
		}
		if bytes.Equal(have, want) {
			return nil
		}
		return fmt.Errorf("store: %s differs from the signing key in data_dir: not overwritten, check which one is right",
			filepath.Join(dir, auditchain.SignKeyFileName))
	}
	if err := backupFile(src, dir, 0); err != nil {
		return fmt.Errorf("backup signing key: %w", err)
	}
	return nil
}

// clockSlack — насколько время приёма может обогнать «время последней метки
// TSA + сколько прошло по монотонным часам»: секундная точность меток, сеть,
// уход хода.
const clockSlack = 10 * time.Second

// clockLocked — время приёма: наши часы, но строго больше прошлого. Часы,
// прыгнувшие назад, не уводят запись в прошлый (возможно, уже стёртый) месяц.
// Прыжок вперёд ограничен якорем — последней меткой TSA этого процесса: иначе
// один прыжок часов на сутки делал все следующие улики «из будущего» (так
// требует монотонность), и это переживало рестарт.
func (s *Store) clockLocked() int64 {
	t := s.nowTime().UnixNano()
	if !s.anchorTSA.IsZero() {
		// Оценка по якорю — время TSA плюс ход монотонных часов. Часы хоста
		// впереди неё больше допуска (точность метки, сеть, уход хода 0,1 %)
		// — им не верим и берём оценку.
		elapsed := s.mono() - s.anchorMono
		est := s.anchorTSA.Add(elapsed).UnixNano()
		if t > est+int64(clockSlack+elapsed/1000) {
			if !s.clockAhead {
				s.log.Error("host clock is ahead of TSA time: receive times follow the last time-stamp and the monotonic clock",
					"ahead", time.Duration(t-est))
			}
			s.clockAhead = true
			s.clockCapped.Add(1)
			t = est
		} else {
			s.clockAhead = false
		}
	}
	if t <= s.lastRecv {
		t = s.lastRecv + 1
	}
	s.lastRecv = t
	return t
}

// anchorClock ставит якорь часов по свежей метке TSA.
func (s *Store) anchorClock(gen time.Time) {
	s.mu.Lock()
	s.anchorTSA, s.anchorMono = gen, s.mono()
	s.mu.Unlock()
}

func b64(b []byte) string { return base64.StdEncoding.EncodeToString(b) }

func sum(b []byte) [32]byte { return sha256.Sum256(b) }
