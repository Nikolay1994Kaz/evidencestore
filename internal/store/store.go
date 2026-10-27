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
	"cmp"
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

	"github.com/Nikolay1994Kaz/evidencestore/internal/auditchain"
	"github.com/Nikolay1994Kaz/evidencestore/internal/config"
	"github.com/Nikolay1994Kaz/evidencestore/internal/evidence"
	"github.com/Nikolay1994Kaz/evidencestore/internal/evlog"
	"github.com/Nikolay1994Kaz/evidencestore/internal/gateway"
	"github.com/Nikolay1994Kaz/evidencestore/internal/keyring"
	"github.com/Nikolay1994Kaz/evidencestore/internal/proof"
	"github.com/Nikolay1994Kaz/evidencestore/internal/ship"
	"github.com/Nikolay1994Kaz/evidencestore/internal/tsa"

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
	// ErrNoAnchor — с TSA приём ждёт свежей метки: без неё время приёма не
	// удержать между метками (W-13, Y-01). Сборщик держит строки в буфере и
	// повторит.
	ErrNoAnchor = errors.New("store: waiting for a fresh TSA time-stamp before accepting records: without it receive times cannot be kept between the time-stamps; is the TSA reachable?")
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
	// writeHook (только тесты) зовётся перед копией keyring.dat в резерв:
	// симуляция снимает здесь диск — так выглядит падение между записью
	// кейринга и его копией.
	writeHook func(point string)
	// evlogSegment, chainSegment (только тесты) — пороги ротации сегментов
	// журнала улик и файлов листьев цепи: симуляция гоняет ротацию под
	// падениями. 0 — как в проде.
	evlogSegment, chainSegment int64
	// replicaChunk (только тесты) — предел куска копии наружу.
	replicaChunk int64
	// wrapRoots (только тесты) оборачивает хранилище корней: симуляция
	// роняет процесс посреди поворота корня.
	wrapRoots func(keyring.RootStore) keyring.RootStore
}

// Store — работающий экземпляр хранилища.
type Store struct {
	cfg    *config.Config
	log    *slog.Logger
	now    func() time.Time
	mono   func() time.Duration
	opened time.Time

	writeHook    func(point string) // Options.writeHook
	evlogSegment int64              // Options.evlogSegment
	chainSegment int64              // Options.chainSegment
	replicaChunk int64              // Options.replicaChunk, без него — replicaChunk
	wrapRoots    func(keyring.RootStore) keyring.RootStore

	keys     *keyring.Keyring
	evlog    *evlog.Log
	chain    *auditchain.Carrier
	signer   *auditchain.Signer
	chainDir string

	tsaURL   string
	tsaTrust tsa.Trust
	tsaLocal *tsa.Authority
	tsaHTTP  *http.Client

	// Якорь часов (под mu): время последней метки TSA этого процесса,
	// монотонные часы в момент ответа и сколько шёл ответ. По нему — окно
	// времени TSA сейчас (anchorWindowLocked).
	anchorTSA  time.Time
	anchorMono time.Duration
	anchorLag  time.Duration // от запроса к TSA до якоря: подпись — где-то в этом окне
	anchorHost time.Duration // часы хоста минус время TSA в момент якоря
	clockOff   bool          // часы хоста сейчас вне окна (о начале — в журнал один раз)
	// needAnchor — приём ждёт свежего якоря: TSA настроена, фоновые циклы
	// работают (serve). Без якоря время приёма не с чем сверить: часы хоста,
	// убежавшие вперёд до первой метки, давали одной записи время «из
	// будущего», а монотонность — и всем следующим на всю длину скачка
	// (W-13).
	needAnchor bool
	// reanchoring — якорь переставляется после потери хода монотонных часов
	// (reanchor): приём на паузе.
	reanchoring bool
	// intakeOpen — легла в цепь метка, чьи хвосты легли уже при якоре этого
	// процесса (вторая после старта): до неё приём закрыт и при свежем
	// якоре. Пока шёл запрос первой метки, якоря не было, и события в цепи
	// получали часы хоста как есть; сверка обещания считает звенья от головы
	// под T1 (proof.CheckPromise), и с T1 — первой меткой часы хоста впереди
	// обвинили бы честное хранилище (Q-47).
	intakeOpen bool
	// anchorGen — сколько раз ставился якорь: событие, ждавшее цепь, пока он
	// менялся, берёт время заново (lockChainAt).
	anchorGen atomic.Uint64

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
	// srcTail — последний лист улики каждого источника в порядке цепи: на него
	// ссылается следующий лист источника, он же уходит в хвосты (п. 28).
	srcTail map[string]srcTailRef
	// gwSources — источники журнала гейтвея: заданы при старте и не
	// меняются, читаются без замка. Их вид — в хвостах (tailKind).
	gwSources map[string]bool
	// preTailsHead — звено хвостов перед запросом, ещё не заверенное: метка,
	// повторённая без новых листьев (TSA не ответила), берёт его же.
	preTailsHead uint64

	// Копия наружу (replica.go).
	replicaMu     sync.Mutex
	replica       *replicaState
	replicaRemote ship.Remote
	// replicaShipped — голова, до которой копия держит цепь после удачного
	// прохода этого процесса; до первого удачного прохода — ноль.
	replicaShipped atomic.Uint64

	// Канал свидетеля голов (witness.go). Очередь — под chainMu.
	witnessRemote ship.Remote
	witnessQueue  []witnessHead
	witnessQueued uint64 // наибольшая голова, поставленная в очередь

	stampMu sync.Mutex // метки по одной: фон и оператор не заверяют одну голову дважды

	// epochMu — эпоха сборщика закрепляется по одной (epoch.go). Порядок
	// захвата: epochMu раньше mu и chainMu.
	epochMu sync.Mutex

	orphanWarned string // о каких сиротах уже предупредили (Maintain)
	// signerBackupPending — sign.key не подтверждён в keys.backup_dir
	// (confirmSigner): копия не прошла или там другой ключ.
	signerBackupPending atomic.Bool

	// Счётчики для /metrics с запуска (metrics.go).
	ingestErrors  atomic.Uint64
	clockCapped   atomic.Uint64 // время приёма срезано якорем TSA
	stampErrors   atomic.Uint64
	replicaErrors atomic.Uint64
	replicaOK     atomic.Int64 // unix-нс конца последней удачной копии
	witnessErrors atomic.Uint64
	witnessOK     atomic.Int64 // unix-нс последней головы, ушедшей свидетелю

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

// srcTailRef — последний лист улики источника в цепи: номер записи и хэш
// листа.
type srcTailRef struct {
	seq  uint64
	hash [32]byte
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

	// Связь со сборщиком (contact.go): последнее обращение, пропущенное
	// Admit; последний контакт перед эпизодом «сборщик пропал» (ноль —
	// эпизода нет) и первый после него (ноль — ещё не вернулся).
	contactAt time.Time
	lostSince time.Time
	backAt    time.Time

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

func keyringOptions(cfg *config.Config, now func() time.Time, hook func(point string)) keyring.Options {
	opt := keyring.Options{MinWait: cfg.Keys.MinWait.D(), Now: now}
	if dir := cfg.Keys.BackupDir; dir != "" {
		opt.Backup = func(path string, gen uint64) error {
			if hook != nil {
				hook("keyring backup")
			}
			return backupFile(path, dir, gen)
		}
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
	if err := needDir(dir, "keys.backup_dir"); err != nil {
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

// needDir — каталог на месте. Пропавший не создаётся: так выглядит и не
// смонтированный диск, и созданный каталог лёг бы на системный, а копии в
// нём — незаметно (P-12). Каталог заводит оператор.
func needDir(dir, name string) error {
	fi, err := os.Stat(dir)
	switch {
	case err != nil:
		return fmt.Errorf("store: %s: %w (is the disk mounted? the store does not create this directory)", name, err)
	case !fi.IsDir():
		return fmt.Errorf("store: %s: %s is not a directory", name, dir)
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
	// Резерв ключей и зеркало корней лежат на других дисках, и каталоги на
	// них заводит оператор (needDir) — проверка до того, как init что-то
	// запишет.
	for _, d := range [][2]string{{cfg.Keys.BackupDir, "keys.backup_dir"}, {cfg.Keys.RootsMirrorDir, "keys.roots_mirror_dir"}} {
		if d[0] == "" {
			continue
		}
		if err := needDir(d[0], d[1]); err != nil {
			return "", err
		}
	}
	for _, d := range []string{cfg.DataDir, cfg.RootsDir} {
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
	k, err := keyring.Create(cfg.DataDir, rootStore(cfg), keyringOptions(cfg, nil, nil))
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
		srcTail:   make(map[string]srcTailRef),
		scopes:    make(map[string]bool),
		keyLabels: make(map[string]string),
		stop:      make(chan struct{}),
		tsaHTTP:   opt.HTTP,
		writeHook: opt.writeHook,

		evlogSegment: opt.evlogSegment,
		chainSegment: opt.chainSegment,
		replicaChunk: cmp.Or(opt.replicaChunk, replicaChunk),
		wrapRoots:    opt.wrapRoots,
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
	s.gwSources = map[string]bool{}
	for _, src := range cfg.Sources {
		st := &sourceState{cfg: src, known: true, inflight: map[uint64]bool{}, gw: newTracker(src)}
		s.sources[src.Name] = st
		s.gwSources[src.Name] = st.gw != nil
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
		s.needAnchor = s.tsaURL != "" || s.tsaLocal != nil
		s.startBackground()
	}
	return s, nil
}

func (s *Store) open() error {
	cfg := s.cfg
	evDir, chainDir, tsaDir := dirs(cfg)
	s.chainDir = chainDir

	var err error
	var roots keyring.RootStore = rootStore(cfg)
	if s.wrapRoots != nil {
		roots = s.wrapRoots(roots)
	}
	if s.keys, err = keyring.Open(cfg.DataDir, roots, keyringOptions(cfg, s.now, s.writeHook)); err != nil {
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
	if cfg.Witness.URL != "" {
		// Свидетель — чужое хранилище: ключи у него свои (ES_WITNESS_*).
		if s.witnessRemote, err = ship.OpenRemoteEnv(cfg.Witness.URL, "ES_WITNESS"); err != nil {
			return fmt.Errorf("witness: %w", err)
		}
	}
	if s.chain, err = auditchain.Open(chainDir); err != nil {
		return fmt.Errorf("chain: %w", err)
	}
	if s.chainSegment > 0 {
		s.chain.SetSegmentBytes(s.chainSegment)
	}
	s.logChainRecovery(s.chain.Recovery())
	if err := checkLostSigner(cfg, chainDir, s.chain.Head().Seq); err != nil {
		return err
	}
	if s.signer, err = auditchain.LoadOrCreateSigner(chainDir); err != nil {
		return err
	}
	if err := s.confirmSigner(); err != nil {
		// Цепь пуста: этим ключом хранилище ещё ничего не подписало, и
		// остановка ничего не стоит — какой из двух ключей верный, решает
		// человек (P-13). С цепью хранилище стартует, а расхождение
		// показывает тревога.
		if errors.Is(err, errSignerDiffers) && s.chain.Head().Seq == 0 {
			return err
		}
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
	if s.evlog, err = evlog.Open(evDir, evlog.Options{OnCommit: s.onCommit, SegmentBytes: s.evlogSegment}, visit); err != nil {
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
	// Наибольший номер — и по пропускам в цепи: пропуск, объявленный
	// пульсом, кончается номером, которого в журнале улик нет.
	s.mu.Lock()
	for name, m := range cs.maxSeq {
		if st := s.sources[name]; st != nil {
			st.maxSeq = max(st.maxSeq, m)
		}
	}
	s.mu.Unlock()
	if len(tail) > 0 {
		s.log.Info("chain catch-up", "records", len(tail))
		s.chainMu.Lock()
		for _, p := range tail {
			s.appendEvidenceLocked(p.header, p.pos, p.digest)
		}
		// Звено догона — сразу, до событий подъёма (пропуски, вердикты,
		// запуск): их время — часы хоста без якоря, и в одном звене с ними
		// время звена догнанных записей стало бы часами хоста; сверка
		// обещания обвинила бы запись, которую подъём догнал быстро (Q-53).
		err := s.flushLocked()
		s.chainMu.Unlock()
		if err != nil {
			return err
		}
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
		// Копия в резерв не прошла: ключ заведён, но не выдаётся, пока
		// обслуживание не повторит копию. Старту это не мешает — как и
		// недоступное зеркало корней (Z-06).
		if !errors.Is(err, keyring.ErrBackupPending) {
			return err
		}
		s.log.Warn("keyring backup pending at start: new month keys are not used until the copy succeeds", "err", err)
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

// checkLostSigner — можно ли завести ключ подписи, если его нет в
// data_dir/chain/. Ключ заводит init, и новый молча сменил бы подпись:
// сборщики и проверяющие, закрепившие старый, перестали бы принимать
// хранилище. Поэтому новый заводится, только пока цепь пуста и ключа нет и
// в keys.backup_dir: иначе ключ потерян или положен не туда (S-08, P-13).
func checkLostSigner(cfg *config.Config, chainDir string, links uint64) error {
	path := filepath.Join(chainDir, auditchain.SignKeyFileName)
	if _, err := os.Stat(path); !errors.Is(err, os.ErrNotExist) {
		return nil
	}
	// unchecked — резерв не прочесть (диск не смонтирован): он не
	// подтверждает, что ключа в нём нет.
	var unchecked error
	if dir := cfg.Keys.BackupDir; dir != "" {
		backup := filepath.Join(dir, auditchain.SignKeyFileName)
		_, err := os.Stat(backup)
		if err == nil {
			return fmt.Errorf("store: %s is missing, while keys.backup_dir holds the signing key: copy %s there", path, backup)
		}
		if errors.Is(err, os.ErrNotExist) {
			err = needDir(dir, "keys.backup_dir")
		}
		unchecked = err
	}
	switch {
	case links > 0:
		return fmt.Errorf("store: %s is missing while the chain holds %d links: put sign.key back from keys.backup_dir", path, links)
	case unchecked != nil:
		return fmt.Errorf("store: %s is missing, and the backup cannot be checked for it: %w", path, unchecked)
	}
	return nil
}

// errSignerDiffers — в keys.backup_dir лежит другой ключ подписи.
var errSignerDiffers = errors.New("store: keys.backup_dir holds another signing key")

// backupSigner кладёт ключ подписи в keys.backup_dir, если там его нет: в
// копию наружу он не уезжает, а без него восстановленное хранилище
// подписывало бы головы новым ключом, и проверяющие с закреплённым старым
// ключом их не приняли бы. Другой ключ в резерве не затирается.
func backupSigner(cfg *config.Config, chainDir string) error {
	dir := cfg.Keys.BackupDir
	if dir == "" {
		return nil
	}
	src := filepath.Join(chainDir, auditchain.SignKeyFileName)
	backup := filepath.Join(dir, auditchain.SignKeyFileName)
	have, err := os.ReadFile(backup)
	switch {
	case err == nil:
		want, err := os.ReadFile(src)
		if err != nil {
			return err
		}
		if bytes.Equal(have, want) {
			return nil
		}
		return fmt.Errorf("%w: %s differs from %s: not overwritten, check which one is right", errSignerDiffers, backup, src)
	case !errors.Is(err, os.ErrNotExist):
		return err
	}
	if err := backupFile(src, dir, 0); err != nil {
		return fmt.Errorf("backup signing key: %w", err)
	}
	return nil
}

// confirmSigner — backupSigner с тревогой: пока ключ подписи не подтверждён
// в резерве, sign_key_backup_pending, и обслуживание повторяет раз в минуту.
func (s *Store) confirmSigner() error {
	err := backupSigner(s.cfg, s.chainDir)
	s.signerBackupPending.Store(err != nil)
	return err
}

// Время приёма и якорь TSA.
//
// esverify принимает время приёма между T1 − 1 мин и T2 + 1 с, где T1 —
// метка в цепи перед уликой, T2 — первая после неё, а метки округлены до
// секунды. Время TSA сейчас хранилище знает с точностью до окна по якорю —
// последней метке этого процесса и монотонным часам после неё:
//
//	lo = метка + ход − 100 ppm                        (не позже времени TSA)
//	hi = метка + 1 с + задержка ответа + ход + 100 ppm (не раньше его)
//
// Время приёма — часы хоста, зажатые в [hi − recvWindow, lo]: не позже
// времени TSA, значит, не позже T2 + 1 с; не раньше времени TSA минус
// recvWindow, значит, не раньше T1 − 1 мин (запас — время от взятия
// времени приёма до листа в цепи, fsync журнала). Окно шире recvWindow
// (якорь старше ≈трёх суток, ответ TSA шёл слишком долго) удержать нельзя — приём
// закрыт, пока свежая метка его не сузит; при простое метка ставится раз в
// anchorRefresh, и якорь не стареет.
//
// Раньше якорь старел без предела (метка — только при новых листьях), и
// каждая постоянная вычета ухода хода рвала одну из границ (W-01, X-01,
// Y-01); часы хоста, отставшие больше чем на минуту, рвали нижнюю.
const (
	recvWindow    = proof.ReceiveLag
	anchorRefresh = time.Hour
	// clockSlack — на сколько часы хоста могут выйти за окно по якорю,
	// прежде чем это тревога, а не обычное отставание оценки.
	clockSlack = 10 * time.Second
	// clockLost — на сколько время TSA может быть позже окна по якорю, прежде
	// чем это потеря хода монотонных часов (сон хоста, пауза ВМ): их уход за
	// час якоря — меньше 2 с даже при подстройке NTP до 500 ppm.
	clockLost = 3 * time.Second
	driftPPM  = 10000 // 1/driftPPM — уход монотонных часов, 100 ppm
)

// anchorWindowLocked — lo и hi по якорю сейчас (unix-нс); ok — якорь есть и
// окно не шире recvWindow.
func (s *Store) anchorWindowLocked() (lo, hi int64, ok bool) {
	return s.anchorWindowAt(s.mono())
}

// anchorWindowAt — то же при монотонных часах mono (под s.mu).
func (s *Store) anchorWindowAt(mono time.Duration) (lo, hi int64, ok bool) {
	if s.anchorTSA.IsZero() {
		return 0, 0, false
	}
	lo, hi = anchorWindow(s.anchorTSA, s.anchorLag, mono-s.anchorMono)
	return lo, hi, hi-lo <= int64(recvWindow)
}

// anchorWindow — lo и hi (unix-нс) по метке со временем gen, ответ на
// которую шёл lag, через el монотонных часов после ответа.
func anchorWindow(gen time.Time, lag, el time.Duration) (lo, hi int64) {
	lo = gen.Add(el - el/driftPPM).UnixNano()
	run := el + lag
	hi = gen.Add(time.Second + run + run/driftPPM).UnixNano()
	return lo, hi
}

// clampToWindow — часы хоста t, зажатые в [hi − recvWindow, lo].
func clampToWindow(t, lo, hi int64) int64 {
	return min(max(t, hi-int64(recvWindow)), lo)
}

// clockLocked — время приёма: часы хоста в окне по якорю и строго больше
// прошлого. Часы, прыгнувшие назад, не уводят запись в прошлый (возможно,
// уже стёртый) месяц; прыгнувшие вперёд не делают улики «из будущего».
// Без якоря (TSA не настроена; в serve с TSA приём до якоря закрыт) —
// часы хоста как есть.
func (s *Store) clockLocked() int64 {
	t := s.nowTime().UnixNano()
	if lo, hi, _ := s.anchorWindowLocked(); hi != 0 {
		floor := hi - int64(recvWindow)
		switch {
		case t > hi+int64(clockSlack):
			s.clockAlarm("host clock is ahead of TSA time, or the monotonic clock stopped (host suspended, VM paused): receive times follow the last time-stamp and the monotonic clock", time.Duration(t-hi))
		case t < floor-int64(clockSlack):
			s.clockAlarm("host clock is behind TSA time: receive times follow the last time-stamp and the monotonic clock", time.Duration(floor-t))
		default:
			s.clockOff = false
		}
		// Окно уже recvWindow — floor ≤ lo; шире (только без фоновых
		// циклов: в serve приём тогда закрыт) — верхняя граница важнее.
		t = min(max(t, floor), lo)
	}
	if t <= s.lastRecv {
		t = s.lastRecv + 1
	}
	s.lastRecv = t
	return t
}

// leafTime — время листа события (пропуск, молчание, связь, эпоха, ключи,
// хвосты, токен): часы хоста в том же окне по якорю, что время приёма, без
// строгого роста. Время звена — время его последнего листа, и обещание
// сверяется по нему (proof.CheckPromise): событие по часам хоста, убежавшим
// вперёд TSA, делало звено «позже срока» обещания, данного по зажатому
// времени приёма. Зовётся без s.mu и до chainMu.
func (s *Store) leafTime() int64 {
	t := s.nowTime().UnixNano()
	mono := s.mono() // вне s.mu: часы теста бывают с крючком
	s.mu.Lock()
	lo, hi, _ := s.anchorWindowAt(mono)
	s.mu.Unlock()
	if hi != 0 {
		t = clampToWindow(t, lo, hi)
	}
	return t
}

// clockAlarm — часы хоста вне окна по якорю: в журнал один раз на эпизод,
// счётчик — на каждую запись.
func (s *Store) clockAlarm(msg string, by time.Duration) {
	if !s.clockOff {
		s.log.Error(msg, "by", by)
	}
	s.clockOff = true
	s.clockCapped.Add(1)
}

// anchored — ErrNoAnchor, пока приём ждёт якоря: в serve с TSA время
// приёма без свежего якоря не удержать в границах проверки.
func (s *Store) anchored() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.needAnchor {
		return nil
	}
	if _, _, ok := s.anchorWindowLocked(); !ok || !s.intakeOpen {
		return ErrNoAnchor
	}
	return nil
}

// anchorStale — якорь пора освежить: его нет, приём по нему ещё не открыт
// (intakeOpen), он старше anchorRefresh, окно по нему разошлось больше чем
// на половину recvWindow или часы хоста
// ушли вперёд оценки по якорю больше чем на clockSlack сверх того, где были
// при якоре: монотонные часы стояли (сон хоста, пауза ВМ), и время приёма
// отстаёт на всю паузу. Часы хоста, просто идущие впереди, метку не зовут:
// их сдвиг при якоре тот же.
func (s *Store) anchorStale() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	lo, hi, ok := s.anchorWindowLocked()
	if !ok || s.mono()-s.anchorMono > anchorRefresh || hi-lo > int64(recvWindow/2) || s.needAnchor && !s.intakeOpen {
		return true
	}
	return time.Duration(s.nowTime().UnixNano()-lo)-s.anchorHost > clockSlack
}

// anchorClock ставит якорь часов по свежей метке TSA: её время, монотонные
// часы в момент ответа и сколько шёл ответ. Якорь — на момент ответа, а не
// на момент вызова: иначе нижняя оценка отставала бы ещё на проверку
// токена и запись звена с ним.
func (s *Store) anchorClock(gen time.Time, answered, took time.Duration) {
	lo, _ := anchorWindow(gen, took, s.mono()-answered) // вне s.mu: часы теста бывают с крючком
	s.mu.Lock()
	s.anchorTSA, s.anchorMono, s.anchorLag = gen, answered, took
	s.anchorHost = time.Duration(s.nowTime().UnixNano() - lo)
	s.mu.Unlock()
	s.anchorGen.Add(1)
}
