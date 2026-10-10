// Package keyring — ключи для криптостирания улик.
//
// Ключи в три уровня:
//
//	корень      — живёт в RootStore (файл в пилоте, потом HSM), заворачивает ключ,
//	              которым заперт keyring.dat целиком;
//	ключ скоупа — KEK на «источник/месяц», обёртывает ключи записей;
//	ключ записи — DEK, шифрует тело; обёрнутый DEK лежит в конверте рядом с ним.
//
// Стереть тела скоупа — уничтожить его KEK. Но копии keyring.dat живут
// дольше: в резерве, в бэкапах диска, в старых блоках SSD. Поэтому
// уничтожение поворачивает корень: файл без ключа запирается новым корнем,
// старый корень уничтожается, и все старые копии разом становятся
// нечитаемыми. По той же причине файл можно копировать в резерв свободно: без
// корня он бесполезен.
//
// Жизнь ключа (по мотивам NIST SP 800-57):
//
//	Active ──Deactivate──▶ Deactivated ──ScheduleDestroy──▶ Pending ──CompleteDue──▶ Destroyed
//	                            ▲                               │
//	                            └────────CancelDestroy──────────┘
//
// Active шифрует и расшифровывает, Deactivated (прошлый месяц) только
// расшифровывает, Pending не делает ничего, но уничтожение ещё можно
// отменить, от Destroyed остаётся надгробие. Срок ожидания — не меньше
// Options.MinWait, заявку подтверждают два человека (Policy).
//
// Порча файла — громкая ошибка: корень проверяет файл целиком, и один битый
// байт даёт ErrCorrupt, а не тихую потерю части ключей.
package keyring

import (
	"crypto/cipher"
	"crypto/rand"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"sync"
	"time"
)

const (
	// FileName — файл кейринга в каталоге данных.
	FileName = "keyring.dat"
	// MaxScopeLen — предел имени скоупа. Пределы проверяются и при записи, и
	// при чтении: иначе можно записать файл, который потом не откроется.
	MaxScopeLen = 1024
	// MaxApprovals и MaxApproverLen — пределы подтверждений одной заявки.
	MaxApprovals   = 8
	MaxApproverLen = 255

	fileMagic     = "KRNG3\n"
	legacyMagic   = "KRNG2\n" // прежний формат: весь файл запирал сам корень
	maxRootIDLen  = 255
	fileKeySize   = 32  // ключ файла, его заворачивает корень
	maxWrappedLen = 512 // предел завёрнутого ключа: у HSM и KMS обёртка длиннее ключа
	kekSize       = 32  // AES-256
	kekIDSize     = 16
	dekSize       = 32
	envelopeTag   = "EV2"
	legacyTag     = "EV1" // прежний конверт: без обязательства на ключ записи
	commitSize    = 32
)

// State — состояние ключа скоупа. Значения записываются в файл.
type State uint8

const (
	Active      State = 1
	Deactivated State = 2
	Pending     State = 3
	Destroyed   State = 4
)

var stateNames = [...]string{"", "active", "deactivated", "pending-destruction", "destroyed"}

func (s State) String() string {
	if s >= Active && s <= Destroyed {
		return stateNames[s]
	}
	return fmt.Sprintf("State(%d)", uint8(s))
}

var (
	ErrNotFound       = errors.New("keyring: file not found")
	ErrExists         = errors.New("keyring: file already exists")
	ErrCorrupt        = errors.New("keyring: corrupt file")
	ErrClosed         = errors.New("keyring: closed")
	ErrScopeName      = errors.New("keyring: bad scope name")
	ErrUnknownScope   = errors.New("keyring: unknown scope")
	ErrScopeClosed    = errors.New("keyring: scope is not writable")
	ErrScopeDestroyed = errors.New("keyring: scope destroyed")
	ErrBadState       = errors.New("keyring: invalid state for operation")
	ErrApproval       = errors.New("keyring: approvals rejected")
	ErrNotBackedUp    = errors.New("keyring: key not in backup yet")
	// ErrBackupPending — изменение записано в keyring.dat, а копия в резерв
	// не прошла. Изменение действует; Confirm повторит копию.
	ErrBackupPending = errors.New("keyring: change saved, backup copy pending")
	// ErrOrphanRoots — в хранилище корней есть корни, которых не знает
	// keyring.dat (см. OrphanRoots). Пока они есть, уничтожение не становится
	// окончательным.
	ErrOrphanRoots = errors.New("keyring: orphan roots present")

	// Исходы Unseal. Реплей обязан их различать: «стёрто» — пропустить
	// запись, «ждёт уничтожения» — не грузить, но и не считать стёртым,
	// остальное — остановиться.
	ErrKeyDestroyed = errors.New("keyring: key destroyed")
	ErrKeyPending   = errors.New("keyring: key pending destruction")
	ErrUnknownKey   = errors.New("keyring: unknown key")
	ErrMalformed    = errors.New("keyring: malformed envelope")
)

// RootStore хранит корни. Корень не покидает хранилище: кейринг передаёт ему
// ключ файла (32 байта), чтобы завернуть или развернуть. Сейчас это
// FileRoots, для банка — HSM (C_WrapKey) или KMS за этим же интерфейсом.
type RootStore interface {
	NewRoot() (id string, err error)
	// Wrap заворачивает ключ файла корнем id; aad связывает обёртку с
	// заголовком файла.
	Wrap(id string, key, aad []byte) ([]byte, error)
	// Unwrap разворачивает ключ файла.
	Unwrap(id string, wrapped, aad []byte) ([]byte, error)
	// DestroyRoot уничтожает корень насовсем. Неизвестный id — не ошибка:
	// после сбоя уничтожение повторяют.
	DestroyRoot(id string) error
	// Roots перечисляет корни, которые есть в хранилище: по ним находятся
	// сироты (OrphanRoots).
	Roots() ([]string, error)
}

// Options — необязательные настройки.
type Options struct {
	// Backup копирует keyring.dat в резерв; зовётся после каждой записи
	// файла. Пока копия не прошла, новый ключ не выдаётся (EnsureScope
	// отвечает ошибкой) и старые корни не уничтожаются: иначе после потери
	// диска в резерве не окажется нужного ключа или копия будет заперта уже
	// уничтоженным корнем. Копия должна быть атомарной: неудачная попытка не
	// портит прежнюю. Зовётся без общего замка: Seal под уже скопированными
	// ключами в это время работает, другие изменения кейринга ждут очереди.
	Backup func(path string, gen uint64) error
	// MinWait — наименьший срок между заявкой на уничтожение и самим
	// уничтожением. Задаётся настройкой, а не тем, кто подаёт заявку: иначе
	// окно отмены было бы доброй волей заявителя.
	MinWait time.Duration
	// Policy решает, хватает ли подтверждений. nil — TwoPeople.
	Policy Policy
	// Now — часы для сроков ожидания; nil — time.Now. Нужны тестам.
	Now func() time.Time
}

// KeyInfo — состояние ключа скоупа для оператора и квитанций в цепи.
// Самого ключа в нём нет.
type KeyInfo struct {
	Scope         string
	KEKID         [kekIDSize]byte
	State         State
	DeactivatedAt time.Time
	DestroyAfter  time.Time // срок ожидания у Pending
	DestroyedAt   time.Time // ключа нет в текущем файле
	EffectiveAt   time.Time // старые корни уничтожены; ноль у Destroyed — CompleteDue надо повторить
	Approvals     []string  // кто подтвердил уничтожение
	// Confirmed — это состояние уже в резерве. Квитанцию в цепь пишут только
	// по таким: тогда keyring.dat, восстановленный из резерва, не окажется
	// позади цепи.
	Confirmed bool
}

type entry struct {
	scope string
	id    [kekIDSize]byte
	state State
	key   []byte      // nil у уничтоженного и после Close
	aead  cipher.AEAD // кэш: NewGCM на каждый вызов стоит 336 нс и 1280 Б
	gen   uint64      // поколение файла, в котором ключ появился
	// changed — поколение записи, в которой состояние менялось последним.
	// Только в памяти: после Open считается последним поколением файла.
	changed uint64

	deactivated, destroyAfter, destroyed, effective time.Time
	approvals                                       []string
}

// live — ключ ещё лежит в файле.
func (e *entry) live() bool { return e.state != Destroyed }

// info — состояние ключа; safe — последнее поколение, дошедшее до резерва.
func (e *entry) info(safe uint64) KeyInfo {
	return KeyInfo{
		Scope:         e.scope,
		KEKID:         e.id,
		State:         e.state,
		DeactivatedAt: e.deactivated,
		DestroyAfter:  e.destroyAfter,
		DestroyedAt:   e.destroyed,
		EffectiveAt:   e.effective,
		Approvals:     append([]string(nil), e.approvals...),
		Confirmed:     e.changed <= safe,
	}
}

// Keyring — ключи скоупов под корнем, durable в одном файле.
type Keyring struct {
	// wmu ставит изменения в очередь. Он держится всю операцию, в том числе
	// пока persistLocked копирует файл в резерв с отпущенным mu: в этом окне
	// читатели работают, а состояние не меняет никто.
	wmu     sync.Mutex
	mu      sync.RWMutex
	path    string
	roots   RootStore
	opt     Options
	rootID  string   // корень текущего файла
	retired []string // старые корни, ещё не уничтоженные
	gen     uint64   // поколение текущего файла, +1 на каждую запись
	safe    uint64   // последнее поколение, записанное и скопированное в резерв
	byName  map[string]*entry
	byID    map[[kekIDSize]byte]*entry
	closed  bool
}

func newKeyring(dir string, roots RootStore, opt Options) *Keyring {
	return &Keyring{
		path:   filepath.Join(dir, FileName),
		roots:  roots,
		opt:    opt,
		byName: make(map[string]*entry),
		byID:   make(map[[kekIDSize]byte]*entry),
	}
}

// Create заводит пустой кейринг под новым корнем. Файл уже есть — ErrExists:
// начинать с чистого листа поверх живых ключей нельзя.
func Create(dir string, roots RootStore, opt Options) (*Keyring, error) {
	k := newKeyring(dir, roots, opt)
	if _, err := os.Stat(k.path); err == nil {
		return nil, fmt.Errorf("%w: %s", ErrExists, k.path)
	} else if !errors.Is(err, os.ErrNotExist) {
		return nil, fmt.Errorf("keyring create: %w", err)
	}
	id, err := k.newRoot()
	if err != nil {
		return nil, err
	}
	k.wmu.Lock()
	defer k.wmu.Unlock()
	k.mu.Lock()
	defer k.mu.Unlock()
	k.rootID = id
	if _, err := k.persistLocked(); err != nil {
		return nil, err
	}
	return k, nil
}

// Open открывает существующий кейринг. Файла нет — ErrNotFound, а не пустой
// кейринг: иначе потерянный файл выглядел бы как «все ключи уничтожены».
func Open(dir string, roots RootStore, opt Options) (*Keyring, error) {
	k := newKeyring(dir, roots, opt)
	data, err := os.ReadFile(k.path)
	if errors.Is(err, os.ErrNotExist) {
		return nil, fmt.Errorf("%w: %s", ErrNotFound, k.path)
	}
	if err != nil {
		return nil, fmt.Errorf("keyring open: %w", err)
	}
	if err := k.load(data); err != nil {
		k.Close() // обнулить ключи, которые успели загрузиться
		return nil, err
	}
	return k, nil
}

// EnsureScopes заводит ключи для скоупов, которых ещё нет, одной записью
// файла. Скоупы следующего месяца лучше завести заранее одним вызовом: иначе
// в полночь каждый источник придёт сюда за эксклюзивным замком отдельно.
//
// Закрытый скоуп не открывается снова (ErrScopeClosed), уничтоженный не
// воскрешается (ErrScopeDestroyed): новый ключ под старым именем снова
// открыл бы прошлый месяц для записи.
//
// nil означает, что все ключи активны, записаны и скопированы в резерв.
// Только тогда под ними можно запечатывать: ключ без данных безвреден,
// данные без ключа потеряны.
func (k *Keyring) EnsureScopes(scopes ...string) error {
	k.wmu.Lock()
	defer k.wmu.Unlock()
	k.mu.Lock()
	defer k.mu.Unlock()
	if k.closed {
		return ErrClosed
	}
	for _, s := range scopes {
		if s == "" || len(s) > MaxScopeLen {
			return fmt.Errorf("%w: length %d", ErrScopeName, len(s))
		}
		if e, ok := k.byName[s]; ok {
			switch e.state {
			case Destroyed:
				return fmt.Errorf("%w: %q", ErrScopeDestroyed, s)
			case Deactivated, Pending:
				return fmt.Errorf("%w: %q is %v", ErrScopeClosed, s, e.state)
			}
		}
	}
	var fresh []*entry
	for _, s := range scopes {
		if _, ok := k.byName[s]; ok {
			continue
		}
		// Ключ появится в следующей записи, отсюда gen+1.
		e := &entry{scope: s, state: Active, key: make([]byte, kekSize), gen: k.gen + 1, changed: k.gen + 1}
		rand.Read(e.id[:]) // с Go 1.24 rand.Read не возвращает ошибок
		rand.Read(e.key)
		if err := k.add(e); err != nil {
			zeroize(e.key)
			k.dropLocked(fresh)
			return err
		}
		fresh = append(fresh, e)
	}
	if k.savedLocked(scopes) {
		return nil
	}
	committed, err := k.persistLocked()
	if !committed {
		k.dropLocked(fresh)
	}
	return err
}

// EnsureScope — EnsureScopes для одного скоупа; отдаёт ID его ключа. Если
// ключ уже есть и сохранён, хватает общего замка, и Seal не ждёт.
func (k *Keyring) EnsureScope(scope string) ([kekIDSize]byte, error) {
	k.mu.RLock()
	e := k.byName[scope]
	ready := !k.closed && k.savedLocked([]string{scope})
	k.mu.RUnlock()
	if ready {
		return e.id, nil
	}
	if err := k.EnsureScopes(scope); err != nil {
		return [kekIDSize]byte{}, err
	}
	k.mu.RLock()
	defer k.mu.RUnlock()
	return k.byName[scope].id, nil
}

// savedLocked: все скоупы есть, активны и уже побывали в резерве.
func (k *Keyring) savedLocked(scopes []string) bool {
	for _, s := range scopes {
		e, ok := k.byName[s]
		if !ok || e.state != Active || e.gen > k.safe {
			return false
		}
	}
	return true
}

// add кладёт ключ в индексы. Повтор имени или ID — порча файла.
func (k *Keyring) add(e *entry) error {
	if _, dup := k.byName[e.scope]; dup {
		return fmt.Errorf("%w: duplicate scope %q", ErrCorrupt, e.scope)
	}
	if _, dup := k.byID[e.id]; dup {
		return fmt.Errorf("%w: duplicate key id", ErrCorrupt)
	}
	if e.live() {
		aead, err := newAEAD(e.key)
		if err != nil {
			return fmt.Errorf("%w: %v", ErrCorrupt, err)
		}
		e.aead = aead
	}
	k.byName[e.scope] = e
	k.byID[e.id] = e
	return nil
}

func (k *Keyring) dropLocked(es []*entry) {
	for _, e := range es {
		delete(k.byName, e.scope)
		delete(k.byID, e.id)
		zeroize(e.key)
	}
}

// newRoot заводит корень. Длину имени проверяем сразу: слишком длинное имя
// записалось бы в заголовок файла, который потом не откроется.
func (k *Keyring) newRoot() (string, error) {
	id, err := k.roots.NewRoot()
	if err != nil {
		return "", fmt.Errorf("keyring new root: %w", err)
	}
	if id == "" || len(id) > maxRootIDLen {
		return "", fmt.Errorf("keyring new root: bad id length %d", len(id))
	}
	return id, nil
}

// Scopes возвращает скоупы, ключи которых ещё не уничтожены, в порядке имён.
func (k *Keyring) Scopes() []string {
	k.mu.RLock()
	defer k.mu.RUnlock()
	var out []string
	for name, e := range k.byName {
		if e.live() {
			out = append(out, name)
		}
	}
	sort.Strings(out)
	return out
}

// List возвращает состояние всех ключей, включая надгробия, в порядке имён.
// По нему движок после рестарта сверяет кейринг с квитанциями в цепи.
func (k *Keyring) List() []KeyInfo {
	k.mu.RLock()
	defer k.mu.RUnlock()
	out := make([]KeyInfo, 0, len(k.byName))
	for _, e := range k.byName {
		out = append(out, e.info(k.safe))
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Scope < out[j].Scope })
	return out
}

// BackupPending — последняя запись keyring.dat ещё не в резерве.
func (k *Keyring) BackupPending() bool {
	k.mu.RLock()
	defer k.mu.RUnlock()
	return k.safe < k.gen
}

// Confirm повторяет копию в резерв, если последняя запись туда не дошла.
// Звать по расписанию: иначе изменение, записанное при лежащем резерве,
// ждало бы следующего изменения кейринга, а его квитанция — вместе с ним.
// nil — всё записанное уже в резерве.
func (k *Keyring) Confirm() error {
	k.wmu.Lock()
	defer k.wmu.Unlock()
	k.mu.Lock()
	defer k.mu.Unlock()
	if k.closed {
		return ErrClosed
	}
	if k.safe >= k.gen {
		return nil
	}
	return k.backupLocked()
}

// OrphanRoots — корни в хранилище корней, которых не знает keyring.dat: ни
// корень файла, ни ждущие уничтожения. Сирота остаётся после сбоя между
// созданием корня и записью файла (им ничего не заперто) и после
// восстановления keyring.dat из резерва, отставшего от поворота корня. Во
// втором случае сиротой заперт файл умершей машины, и копия того файла из её
// бэкапов открывает ключи, уничтоженные позже. Поэтому, пока сироты есть,
// уничтожение не становится окончательным (EffectiveAt не ставится).
//
// Перечисление корней (ввод-вывод, зеркало бывает медленным) идёт без
// замка: Seal его не ждёт.
func (k *Keyring) OrphanRoots() ([]string, error) {
	k.mu.RLock()
	if k.closed {
		k.mu.RUnlock()
		return nil, ErrClosed
	}
	known := k.knownRootsLocked()
	k.mu.RUnlock()
	all, err := k.roots.Roots()
	if err != nil {
		return nil, fmt.Errorf("keyring list roots: %w", err)
	}
	return orphansOf(all, known), nil
}

// knownRootsLocked — корни, которые знает keyring.dat: корень файла и ждущие
// уничтожения.
func (k *Keyring) knownRootsLocked() map[string]bool {
	known := map[string]bool{k.rootID: true}
	for _, r := range k.retired {
		known[r] = true
	}
	return known
}

func orphansOf(all []string, known map[string]bool) []string {
	var out []string
	for _, id := range all {
		if !known[id] {
			out = append(out, id)
		}
	}
	sort.Strings(out)
	return out
}

// RootRepairer — хранилище корней, которое умеет доложить недостающие копии
// корня (FileRoots: Dir и Mirror).
type RootRepairer interface {
	RepairRoots(ids []string) error
}

// RepairRoots докладывает недостающие копии корня файла, если хранилище
// корней это умеет. Звать при запуске и по расписанию.
func (k *Keyring) RepairRoots() error {
	r, ok := k.roots.(RootRepairer)
	if !ok {
		return nil
	}
	k.mu.RLock()
	if k.closed {
		k.mu.RUnlock()
		return ErrClosed
	}
	id := k.rootID
	k.mu.RUnlock()
	return r.RepairRoots([]string{id})
}

// DestroyOrphanRoots уничтожает корни-сироты и отдаёт уничтоженные. Только по
// решению оператора: если каталог корней по ошибке общий с другим
// хранилищем, его корни здесь тоже выглядят сиротами.
func (k *Keyring) DestroyOrphanRoots() ([]string, error) {
	// wmu: корень файла и ждущие уничтожения не меняются, пока идёт
	// уничтожение, и новый корень поворота не примется за сироту. Читателям
	// корни не нужны, общий замок не держим.
	k.wmu.Lock()
	defer k.wmu.Unlock()
	k.mu.RLock()
	if k.closed {
		k.mu.RUnlock()
		return nil, ErrClosed
	}
	known := k.knownRootsLocked()
	k.mu.RUnlock()
	all, err := k.roots.Roots()
	if err != nil {
		return nil, fmt.Errorf("keyring list roots: %w", err)
	}
	orphans := orphansOf(all, known)
	var done []string
	var errs []error
	for _, id := range orphans {
		if err := k.roots.DestroyRoot(id); err != nil {
			errs = append(errs, fmt.Errorf("keyring destroy root %s: %w", id, err))
			continue
		}
		done = append(done, id)
	}
	return done, errors.Join(errs...)
}

// Close обнуляет ключи в памяти. Обнуление неполное: копии остаются внутри
// cipher.AEAD (расписание раундов AES), до них из Go не добраться. После
// Close методы отвечают ErrClosed, а не «стёрто». Идущую копию в резерв
// Close дожидается.
func (k *Keyring) Close() error {
	k.wmu.Lock()
	defer k.wmu.Unlock()
	k.mu.Lock()
	defer k.mu.Unlock()
	for _, e := range k.byName {
		zeroize(e.key)
		e.key, e.aead = nil, nil
	}
	k.closed = true
	return nil
}

func (k *Keyring) now() time.Time {
	if k.opt.Now != nil {
		return k.opt.Now()
	}
	return time.Now()
}
