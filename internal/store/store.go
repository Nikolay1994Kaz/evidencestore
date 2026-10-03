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
	"context"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
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
)

var (
	ErrUnknownSource  = errors.New("store: unknown source")
	ErrSourceDisabled = errors.New("store: source disabled")
	ErrInFlight       = errors.New("store: record with this seq is being written right now")
	ErrNotFound       = errors.New("store: no such record")
	ErrBadRecord      = errors.New("store: bad record")
	ErrClosed         = errors.New("store: closed")
	// ErrEvidenceLost — цепь знает улики, которых нет в журнале: журнал
	// потерял подтверждённые записи. Запускаться в таком состоянии нельзя.
	ErrEvidenceLost = errors.New("store: chain covers evidence missing from the log")
	// ErrKeyringMismatch — кейринг не сходится с квитанциями в цепи (откат
	// или подмена keyring.dat). Нужен разбор человеком.
	ErrKeyringMismatch = errors.New("store: keyring does not match key events in the chain")
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
}

// Store — работающий экземпляр хранилища.
type Store struct {
	cfg    *config.Config
	log    *slog.Logger
	now    func() time.Time
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
	chainMu     sync.Mutex
	nextLeaf    uint64              // сквозной номер следующего листа
	linked      uint64              // сколько листьев накрыто звеньями
	links       []linkRef           // звенья по порядку
	evLeaf      []uint64            // evLeaf[pos-1] = номер листа улики + 1
	tokens      []tokenRef          // метки TSA, лёгшие в цепь листьями
	lastStamped uint64              // голова, заверенная последней
	gwLeaf      map[uint64]uint64   // позиция улики гейтвея → лист её вердикта
	gwMarks     map[string][]gwMark // источник → контрольные точки и поломки по порядку

	// Копия наружу (replica.go).
	replicaMu     sync.Mutex
	replica       *replicaState
	replicaRemote ship.Remote

	stampMu sync.Mutex // метки по одной: фон и оператор не заверяют одну голову дважды

	orphanWarned string // о каких сиротах уже предупредили (Maintain)

	// Счётчики для /metrics с запуска (metrics.go).
	ingestErrors  atomic.Uint64
	stampErrors   atomic.Uint64
	replicaErrors atomic.Uint64
	replicaOK     atomic.Int64 // unix-нс конца последней удачной копии

	stop      chan struct{}
	wg        sync.WaitGroup
	closeOnce sync.Once
	closed    bool
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
func backupFile(src, dir string, gen uint64) error {
	data, err := os.ReadFile(src)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	dst := filepath.Join(dir, filepath.Base(src))
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

// Init заводит хранилище: каталоги, кейринг под новым корнем, ключ подписи.
// Повторный Init на живом хранилище — ошибка (keyring.ErrExists).
func Init(cfg *config.Config) (publicKey string, err error) {
	for _, d := range []string{cfg.DataDir, cfg.RootsDir, cfg.Keys.RootsMirrorDir} {
		if d == "" {
			continue
		}
		if err := os.MkdirAll(d, 0o700); err != nil {
			return "", err
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
	// Ключ подписи — в резерв рядом с keyring.dat: в копию наружу он не
	// уезжает, а без него восстановленное хранилище подписывало бы головы
	// новым ключом, и проверяющие с закреплённым старым ключом их не приняли бы.
	if dir := cfg.Keys.BackupDir; dir != "" {
		if err := backupFile(filepath.Join(chainDir, auditchain.SignKeyFileName), dir, 0); err != nil {
			return "", fmt.Errorf("backup signing key: %w", err)
		}
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
	for _, src := range cfg.Sources {
		s.sources[src.Name] = &sourceState{cfg: src, known: true, inflight: map[uint64]bool{}, gw: newTracker(src)}
	}
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
			return fmt.Errorf("%w (run `evidencestore init` first)", err)
		}
		return err
	}
	// Файл после рестарта не знает, что из него уже в резерве: копия
	// подтверждает это, и квитанции, ждавшие её, лягут в цепь при сверке.
	if err := s.keys.Confirm(); err != nil {
		s.log.Warn("keyring backup pending", "err", err)
	}
	if orphans, err := s.keys.OrphanRoots(); err != nil {
		return err
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
	if s.signer, err = auditchain.LoadOrCreateSigner(chainDir); err != nil {
		return err
	}
	keyEvents, maxChained, err := s.scanChain()
	if err != nil {
		return err
	}

	var maxRecv int64
	var tail []pending              // улики, которых ещё нет в цепи
	var gwTail []pending            // улики гейтвея без вердикта в цепи
	keyUse := map[[16]byte]uint64{} // ключ → первая улика под ним
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
		s.log.Warn("evidence log: torn tail cut", "bytes", r.TornTailBytes)
	}
	if maxChained >= s.evlog.Next() {
		return fmt.Errorf("%w: chain covers position %d, log ends at %d", ErrEvidenceLost, maxChained, s.evlog.Next()-1)
	}
	if err := s.checkKeyUse(keyUse); err != nil {
		return err
	}
	s.lastRecv = maxRecv
	if len(tail) > 0 {
		s.log.Info("chain catch-up", "records", len(tail))
		s.chainMu.Lock()
		for _, p := range tail {
			s.appendEvidenceLocked(p.header, p.pos, p.digest)
		}
		s.chainMu.Unlock()
	}
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
	if err := s.reconcileKeys(keyEvents); err != nil {
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
			return fmt.Errorf("local TSA (run `evidencestore init`): %w", err)
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
	return err
}

// Healthy — можно ли принимать: журнал улик не защёлкнут ошибкой.
func (s *Store) Healthy() error {
	s.mu.Lock()
	closed := s.closed
	s.mu.Unlock()
	if closed {
		return ErrClosed
	}
	return s.evlog.Failed()
}

// clockLocked — время приёма: наши часы, но строго больше прошлого. Часы,
// прыгнувшие назад, не уводят запись в прошлый (возможно, уже стёртый) месяц.
func (s *Store) clockLocked() int64 {
	t := s.nowTime().UnixNano()
	if t <= s.lastRecv {
		t = s.lastRecv + 1
	}
	s.lastRecv = t
	return t
}

func b64(b []byte) string { return base64.StdEncoding.EncodeToString(b) }

func sum(b []byte) [32]byte { return sha256.Sum256(b) }

var _ = context.Background
