package mcpserver

// Пределы для агента, которые не зависят от прав его роли в базе: сколько
// может идти один запрос, сколько действий в минуту и сколько строк за окно.
//
// ПОЧЕМУ ТАЙМЕР ЗДЕСЬ, А НЕ ТОЛЬКО В БАЗЕ. statement_timeout и lock_timeout
// роли — значения по умолчанию: сессия их меняет, и SQL агента тоже может —
// SET ему не дают (PREPARE), но SELECT set_config(…) — обычный SELECT. Таймер
// сервера агенту недоступен: время вышло — запрос отменяется на сервере базы
// (CancelRequest), соединение закрывается, транзакция откатывается.
//
// ПОЧЕМУ СЧЁТ — ПО ФАЙЛУ КВИТАНЦИЙ. Сервер живёт один сеанс агента. Счёт в
// памяти обнулялся бы с каждым новым сеансом, а файл квитанций у всех сеансов
// агента общий: в нём каждое действие, его время и число строк. Два сеанса
// одновременно могут оба пройти проверку и вместе превысить предел на одно
// действие: предел мягкий, не замок.

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"syscall"
	"time"

	"golang.org/x/sys/unix"

	"github.com/Nikolay1994Kaz/evidencestore/internal/alert"
	"github.com/Nikolay1994Kaz/evidencestore/internal/gateway"
	"github.com/Nikolay1994Kaz/evidencestore/internal/pgrole"
	"github.com/Nikolay1994Kaz/evidencestore/internal/pgwire"
)

// Причины отказа и срыва действия (Receipt.Cause, в квитанции исхода).
const (
	CauseRowLimit   = "row-limit"   // действие меняет больше строк, чем можно одному
	CauseWindowRows = "window-rows" // с ним агент превысил бы предел строк за окно
	CauseRate       = "rate"        // слишком много действий за минуту
	CauseTimeout    = "timeout"     // запрос шёл дольше предела и отменён
	CauseEscaped    = "escaped"     // SQL агента закрыл транзакцию сервера (COMMIT, ROLLBACK в тексте)
	CauseUnknown    = "unknown"     // связь с базой оборвалась на COMMIT: действие могло зафиксироваться
)

// canceler — соединение, запрос по которому можно прервать с другого потока
// (*pgwire.Conn).
type canceler interface{ Cancel() error }

// errTimeout — запрос агента шёл дольше предела.
var errTimeout = errors.New("the statement timed out")

// connect открывает соединение с базой, если его нет.
func (s *Server) connect() error {
	if s.db != nil {
		return nil
	}
	db, err := s.cfg.Dial(s.sessionParams())
	if err != nil {
		return fmt.Errorf("the database is unreachable: %w", err)
	}
	// Роль проверяется на каждом новом соединении, а не только при запуске:
	// база могла быть недоступна на старте (её занял или рвал агент — R1-4,
	// R2-5, T-2), а права выдают и после (DECISIONS, п. 39).
	if err := checkRole(db); err != nil {
		if c, ok := db.(io.Closer); ok {
			c.Close()
		}
		var pg *pgwire.PgError
		if errors.Is(err, ErrSharedRole) || errors.As(err, &pg) {
			return err
		}
		return fmt.Errorf("the database is unreachable: %w", err)
	}
	s.db = db
	return nil
}

// Close закрывает соединение с базой. Следующий вызов откроет новое — и
// снова проверит роль.
func (s *Server) Close() { s.drop() }

// ErrSharedRole — роль сервера не только его: суперпользователь, состоит в
// другой роли, ею может стать другая роль со входом, или ей дано то, чем SQL
// агента достал бы до чужих сеансов, журнала базы и файлов сервера.
var ErrSharedRole = errors.New("the role of the MCP server is not its own")

// RoleCheck — запрос проверки роли (checkRole); метка в начале — чтобы
// поддельная база в тестах узнала его.
const RoleCheck = "/* evidencestore: the role of the MCP server */ "

// CheckRole подключается и проверяет роль сервера (checkRole). esmcp зовёт
// её при запуске, чтобы не начинать работу с чужой ролью; та же проверка
// идёт на каждом новом соединении.
func (s *Server) CheckRole() error { return s.connect() }

// checkRole проверяет, что роль, которой сервер вошёл, — только его. SQL
// агента идёт этой ролью, поэтому:
//   - не суперпользователь;
//   - никакая другая роль со входом, кроме суперпользователей, не может ею
//     стать: иначе её умолчания и сеансы — в руках той роли, и таблицы она
//     пишет в обход шлюза;
//   - может только выданное ей самой — то же, что проверяет
//     escollect -setup-sql (pgrole.Rights, pgrole.Params): ни членств, ни
//     pg_terminate_backend, ни чужих SECURITY DEFINER, ни того, что initdb или
//     расширение оставили суперпользователям, ни сторонних серверов, ни
//     параметров уровня суперпользователя (P-276, P-277, P-280; заход 2).
//
// Права выдают и после настройки (DECISIONS, пп. 39, 40). Чего здесь нет —
// владения и CREATE: SQL агента в PREPARE не исполняет DDL; их проверяет
// -setup-sql.
func checkRole(db DB) error {
	res, err := db.Query("BEGIN; SET LOCAL search_path = pg_catalog, pg_temp; " + RoleCheck +
		"SELECT current_user::text, r.rolsuper::text, " +
		"(SELECT string_agg(x.rolname::text, ', ' ORDER BY x.rolname) FROM pg_roles x " +
		"WHERE x.oid <> r.oid AND x.rolcanlogin AND NOT x.rolsuper AND pg_has_role(x.oid, r.oid, 'MEMBER')), " +
		"(SELECT string_agg(DISTINCT w.x, ', ') FROM (" + pgrole.Rights("current_user") + ") AS w), " +
		"current_setting('server_version_num') " +
		"FROM pg_roles r WHERE r.rolname = current_user; COMMIT")
	if err != nil {
		rollback(db)
		return err
	}
	row := roleRow(res, 5)
	switch {
	case row == nil:
		return fmt.Errorf("%w: the check of the role gave no answer", ErrSharedRole)
	case row[1] != nil && *row[1] == "true":
		return fmt.Errorf("%w: %s is a superuser. Give the MCP server a role of its own (mcp_roles in the collector config; escollect -setup-sql creates it)", ErrSharedRole, *row[0])
	case row[2] != nil:
		return fmt.Errorf("%w: %s can become %s. Revoke the membership: whoever can become the role of the server sets its defaults, ends its sessions and writes the tables past the gateway", ErrSharedRole, *row[2], *row[0])
	case row[3] != nil:
		return fmt.Errorf("%w: %s. %s", ErrSharedRole, *row[3], pgrole.Hint)
	}
	if v, _ := strconv.Atoi(deref(row[4])); v < 150000 {
		return nil
	}
	res, err = db.Query("BEGIN; SET LOCAL search_path = pg_catalog, pg_temp; " + RoleCheck +
		"SELECT string_agg(DISTINCT w.x, ', ') FROM (" + pgrole.Params("current_user") + ") AS w; COMMIT")
	if err != nil {
		rollback(db)
		return err
	}
	if row := roleRow(res, 1); row == nil {
		return fmt.Errorf("%w: the check of the parameters gave no answer", ErrSharedRole)
	} else if row[0] != nil {
		return fmt.Errorf("%w: %s. %s", ErrSharedRole, *row[0], pgrole.Hint)
	}
	return nil
}

// roleRow — единственная строка ответа с n колонками; nil — её нет.
func roleRow(res []pgwire.Result, n int) []*string {
	for _, r := range res {
		if len(r.Rows) == 1 && len(r.Rows[0]) == n {
			return r.Rows[0]
		}
	}
	return nil
}

func rollback(db DB) {
	if db.TxStatus() != pgwire.TxIdle {
		db.Query("ROLLBACK")
	}
}

func deref(v *string) string {
	if v == nil {
		return ""
	}
	return *v
}

// sessionParams — параметры входа соединения сервера. Умолчания своей роли
// агент ставит себе сам (ALTER ROLE … SET в своей сессии мимо сервера), и
// DISCARD ALL возвращает сеанс к ним; параметры входа сильнее их, и
// DISCARD ALL возвращает к параметрам. Вне транзакции действия — отказ по
// частоте, по таймауту, отказы отката, обрыв на COMMIT — сервер шёл с
// умолчаниями агента: statement_timeout = 1 мс (и jit_above_cost = 0, чтобы
// не успеть) или role = чужая группа — и тревоги не было ни одной (отказ
// был тогда отметкой в журнале базы). Откат же шёл без таймаутов вовсе (агент снимает их у своей роли) и
// висел на замке строки под замком агента (R2 заход 2). Роль — та, которой
// сервер вошёл; таймауты — те же, что ставит guards.
//
// Через пулер (Config.Pooler) параметров входа нет: пулер их не пропускает.
// Те же значения транзакция ставит себе сама (ownSettings).
func (s *Server) sessionParams() map[string]string {
	if s.cfg.Pooler {
		return nil
	}
	return s.loginParams()
}

// loginParams — значения, с которыми идут свои запросы сервера: параметрами
// входа прямого соединения или, через пулер, в начале каждой транзакции.
func (s *Server) loginParams() map[string]string {
	ms := func(d time.Duration) string { return strconv.FormatInt(d.Milliseconds(), 10) }
	p := map[string]string{"role": "none", "statement_timeout": "0", "lock_timeout": "0", "idle_in_transaction_session_timeout": "300000"}
	if s.cfg.StatementTimeout > 0 {
		p["statement_timeout"] = ms(s.cfg.StatementTimeout + dbBackstop)
	}
	if s.cfg.LockTimeout > 0 {
		p["lock_timeout"] = ms(s.cfg.LockTimeout)
	}
	return p
}

// drop закрывает соединение: открытая в нём транзакция на сервере откатится.
func (s *Server) drop() {
	if c, ok := s.db.(io.Closer); ok {
		c.Close()
	}
	s.db = nil
}

// timed выполняет SQL агента (run) не дольше StatementTimeout. Время вышло —
// запрос отменяется на сервере базы, а соединение закрывается: просьба об
// отмене не должна догнать следующий запрос, и транзакция должна откатиться,
// что бы агент в ней ни выставил.
func (s *Server) timed(run func() ([]pgwire.Result, error)) ([]pgwire.Result, error) {
	limit := s.cfg.StatementTimeout
	if limit <= 0 {
		return run()
	}
	if err := s.connect(); err != nil {
		return nil, err
	}
	db := s.db
	fired := make(chan struct{})
	t := time.AfterFunc(limit, func() {
		defer close(fired)
		c, ok := db.(canceler)
		if ok && c.Cancel() == nil {
			return
		}
		// Отменить нечем или отмена не дошла: закрыть соединение, чтобы хотя
		// бы сервер агента не ждал ответа.
		if cl, ok := db.(io.Closer); ok {
			cl.Close()
		}
	})
	res, err := run()
	if t.Stop() {
		return res, err
	}
	<-fired
	s.drop()
	return nil, fmt.Errorf("%w: it ran longer than %s and was cancelled", errTimeout, limit)
}

// dbBackstop — на столько таймаут в самой базе длиннее таймера сервера: первым
// срабатывает таймер, а база подстраховывает, если просьба об отмене до неё не
// дошла.
const dbBackstop = 5 * time.Second

// guards — таймауты базы на одну транзакцию агента (SET LOCAL): страховка под
// таймером сервера и срок ожидания чужой блокировки. Это значения по
// умолчанию — SQL агента может их сменить (set_config); таймер сервера
// (timed) ему недоступен, а после команд агента сервер ставит их снова.
func (s *Server) guards() []string {
	var out []string
	if s.cfg.StatementTimeout > 0 {
		out = append(out, fmt.Sprintf("SET LOCAL statement_timeout = %d", (s.cfg.StatementTimeout+dbBackstop).Milliseconds()))
	}
	if s.cfg.LockTimeout > 0 {
		out = append(out, fmt.Sprintf("SET LOCAL lock_timeout = %d", s.cfg.LockTimeout.Milliseconds()))
	}
	return out
}

// spent — одно действие из файла квитанций: когда, сколько строк изменило
// (если зафиксировано).
type spent struct {
	at   time.Time
	rows int
	// action и pending — намерение без исхода: действие было, а чем
	// кончилось, квитанции нет (сервер убит между COMMIT и исходом, T-8).
	// Оно в счёте с худшим случаем строк, пока исход его не заменит.
	action  string
	pending bool
	// hash — квитанции, по которой оно в счёте, intent — его намерения:
	// копия той же строки, дописанная без ключа, второй раз не считается.
	hash, intent string
}

// ledger — расход агента за последнее время по файлу квитанций. Файл читается
// с того места, где остановились в прошлый раз: в него пишут и другие сеансы.
type ledger struct {
	path, agent string
	// own — квитанция этого шлюза с его подписью (Server.own): в счёт идут
	// только квитанции исхода — по одной на действие.
	own     func(line []byte) (Receipt, string, bool)
	keep    time.Duration // сколько помнить: самое длинное окно
	worst   int           // строк у намерения без исхода: предел действия, без него — предел окна
	primed  bool
	off     int64
	ino     uint64 // inode файла, который читался: другой по пути — ротация
	tail    []byte // байты перед off: другие — файл переписан (copytruncate и дорос)
	items   []spent
	alerted time.Time // последний отказ за частоту, о котором людям ушла тревога
}

// refresh дочитывает файл и забывает то, что старше keep.
func (l *ledger) refresh(now time.Time) error {
	f, err := gateway.OpenReceipts(l.path, os.O_RDONLY, 0)
	if errors.Is(err, os.ErrNotExist) {
		if !l.primed {
			// Файла по пути ещё нет — только что повернули: счёт окна — по
			// повёрнутым рядом (R2-4 третьего захода).
			l.primeSiblings(now)
			l.primed = true
		}
		return nil
	}
	if err != nil {
		return err
	}
	defer f.Close()
	fi, err := f.Stat()
	if err != nil {
		return err
	}
	ino := inodeOf(fi)
	if !l.primed {
		_, covered, _, err := l.prime(f, fi.Size(), now)
		if err != nil {
			return err
		}
		if !covered {
			// Окно начинается раньше этого файла: его начало может лежать в
			// повёрнутом файле рядом. Новый сеанс (процесс esmcp) после
			// ротации иначе не видел действий, сделанных до неё (R2-4
			// третьего захода). Сначала они, потом этот файл — копии строк
			// между ними (copytruncate) в счёт один раз, по хэшу.
			l.primeSiblings(now)
		}
		items, _, end, err := l.prime(f, fi.Size(), now)
		if err != nil {
			return err
		}
		l.items, l.off, l.primed, l.ino = append(l.items, items...), end, true, ino
	} else {
		// Ротация (logrotate, mv; copytruncate) — не повод забыть счёт: в
		// окне остаются действия, сделанные до неё (R2-9, T-4 второго
		// захода). Прежний файл, если он лежит рядом под другим именем,
		// дочитывается до конца; новый — весь новый.
		switch {
		case ino != l.ino:
			if old := l.rotated(ino); old != nil {
				if ofi, err := old.Stat(); err == nil {
					items, _, _, err := l.read(old, l.off, ofi.Size(), now, false)
					if err == nil {
						l.items = append(l.items, items...)
					}
				}
				old.Close()
			}
			l.off, l.ino = 0, ino
		case fi.Size() < l.off || !l.sameTail(f):
			// Тот же файл обрезан (copytruncate) — и, может быть, уже дорос за
			// прежнее место (R2-4 третьего захода): читать с начала; что уже в
			// счёте, второй раз не считается (по хэшу).
			l.off = 0
		}
		fromStart := l.off == 0
		items, covered, end, err := l.read(f, l.off, fi.Size(), now, false)
		if err != nil {
			return err
		}
		l.items, l.off = append(l.items, items...), end
		if fromStart && !covered {
			// Файл с начала, и он не покрывает окна: начало окна — в
			// повёрнутых рядом (их копия при copytruncate), в том числе то,
			// что сеанс не успел прочесть до ротации.
			l.primeSiblings(now)
		}
	}
	l.keepTail(f)
	fresh := l.items[:0]
	for _, it := range l.items {
		if now.Sub(it.at) <= l.keep {
			fresh = append(fresh, it)
		}
	}
	l.items = fresh
	return nil
}

// prime читает хвост файла f (size байт), покрывающий окно: хвост берётся с
// запасом и растёт, пока не покроет окно или весь файл.
func (l *ledger) prime(f *os.File, size int64, now time.Time) (items []spent, covered bool, end int64, err error) {
	for tail := int64(256 << 10); ; tail *= 16 {
		start := max(size-tail, 0)
		items, covered, end, err = l.read(f, start, size, now, start > 0)
		if err != nil || covered || start == 0 {
			return items, covered, end, err
		}
	}
}

// primeSiblings — в счёт окна то, что лежит в повёрнутых файлах рядом.
func (l *ledger) primeSiblings(now time.Time) {
	for _, old := range l.siblings(now) {
		if ofi, err := old.Stat(); err == nil {
			if items, _, _, err := l.prime(old, ofi.Size(), now); err == nil {
				l.items = append(l.items, items...)
			}
		}
		old.Close()
	}
}

// siblings — повёрнутые файлы квитанций рядом (имя файла с точкой или дефисом
// после, не сжатые), менявшиеся в пределах окна, — от старых к новым.
func (l *ledger) siblings(now time.Time) []*os.File {
	dir, base := filepath.Dir(l.path), filepath.Base(l.path)
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil
	}
	type file struct {
		f   *os.File
		mod time.Time
	}
	var out []file
	for _, e := range entries {
		name := e.Name()
		if name == base || !strings.HasPrefix(name, base+".") && !strings.HasPrefix(name, base+"-") {
			continue
		}
		switch filepath.Ext(name) {
		case ".gz", ".bz2", ".xz", ".zst", ".lz4", ".lock", ".head", ".tmp":
			continue
		}
		f, err := gateway.OpenReceipts(filepath.Join(dir, name), os.O_RDONLY, 0)
		if err != nil {
			continue
		}
		fi, err := f.Stat()
		if err != nil || now.Sub(fi.ModTime()) > l.keep {
			f.Close()
			continue
		}
		out = append(out, file{f, fi.ModTime()})
	}
	slices.SortFunc(out, func(a, b file) int { return a.mod.Compare(b.mod) })
	files := make([]*os.File, len(out))
	for i, x := range out {
		files[i] = x.f
	}
	return files
}

// keepTail запоминает байты файла перед местом чтения.
func (l *ledger) keepTail(f *os.File) {
	n := min(l.off, 64)
	l.tail = make([]byte, n)
	if got, _ := f.ReadAt(l.tail, l.off-n); int64(got) != n {
		l.tail = nil
	}
}

// sameTail — байты перед местом чтения те же, что были.
func (l *ledger) sameTail(f *os.File) bool {
	if len(l.tail) == 0 {
		return true
	}
	got := make([]byte, len(l.tail))
	n, _ := f.ReadAt(got, l.off-int64(len(l.tail)))
	return n == len(got) && bytes.Equal(got, l.tail)
}

// rotated — прежний файл (inode l.ino), если он лежит в каталоге файла
// квитанций под другим именем; ino — файл, что теперь по пути.
func (l *ledger) rotated(ino uint64) *os.File {
	if l.ino == 0 {
		return nil
	}
	entries, err := os.ReadDir(filepath.Dir(l.path))
	if err != nil {
		return nil
	}
	for _, e := range entries {
		if !e.Type().IsRegular() {
			continue
		}
		fi, err := e.Info()
		if err != nil || inodeOf(fi) != l.ino {
			continue
		}
		f, err := os.Open(filepath.Join(filepath.Dir(l.path), e.Name()))
		if err != nil {
			return nil
		}
		if ofi, err := f.Stat(); err != nil || inodeOf(ofi) != l.ino {
			f.Close()
			return nil
		}
		return f
	}
	return nil
}

// inodeOf — номер inode файла (0 — не узнать).
func inodeOf(fi os.FileInfo) uint64 {
	if st, ok := fi.Sys().(*syscall.Stat_t); ok {
		return st.Ino
	}
	return 0
}

// read разбирает квитанции файла от start до end. midline — start взят
// наугад (хвост файла) и может стоять посреди строки. covered — среди
// прочитанных есть квитанция старше keep: хвост покрыл окно. done — докуда
// прочитаны целые строки: обрывок в конце ещё дописывается другим сеансом, и
// следующее чтение начнётся с его начала. Раньше чтение продолжалось с конца
// файла, и квитанция, застигнутая недописанной, пропадала из счёта насовсем
// (P-244).
func (l *ledger) read(f *os.File, start, end int64, now time.Time, midline bool) (items []spent, covered bool, done int64, err error) {
	// Строки — кусками, строка длиннее любой квитанции пропускается: файл
	// квитанций дописывает и тот, у кого ключа нет, и продлённый нулями файл
	// иначе ронял сервер на нехватке памяти (P-351 у сервера).
	first := midline
	done, err = gateway.ReadLines(f, start, end, func(line []byte, _ int64, long bool) {
		if first {
			first = false // остаток строки, посреди которой началось чтение, — не квитанция
			return
		}
		if long {
			return
		}
		var old bool
		items, old = l.take(line, now, items)
		covered = covered || old
	})
	if err != nil {
		return nil, false, start, err
	}
	return items, covered, done, nil
}

// take — квитанция line в счёт (в items); old — она старше окна.
func (l *ledger) take(line []byte, now time.Time, items []spent) (_ []spent, old bool) {
	rc, step, ok := l.own(line)
	if !ok || (step != alert.StepOutcome && step != alert.StepIntent && step != alert.StepUndo) {
		return items, false
	}
	sum := sha256.Sum256(bytes.TrimRight(line, "\r\n"))
	hash := hex.EncodeToString(sum[:])
	if l.known(items, hash) {
		return items, false // копия прежней строки: писатель файла копиями держал бы агента под отказом
	}
	at, perr := time.Parse(time.RFC3339Nano, rc.Time)
	if perr != nil {
		return items, false
	}
	if now.Sub(at) > l.keep {
		return items, true
	}
	if step != alert.StepOutcome {
		// Намерение: действие пошло в базу. Исхода может не быть никогда —
		// тогда оно в счёте с худшим случаем (T-8, R2-4).
		if rc.Agent == l.agent && (rc.Tool == "execute" || rc.Tool == "undo_apply") {
			items = append(items, spent{at: at, rows: l.worst, action: rc.ActionID, pending: true, hash: hash})
		}
		return items, false
	}
	l.note(rc, at)
	if it, ok := l.count(rc, at); ok {
		it.action, it.hash = rc.ActionID, hash
		if !l.settle(items, it) && !l.settle(l.items, it) {
			items = append(items, it)
		}
	} else {
		// Не в счёт (отказ за частоту и подобное): и намерение его — нет.
		l.settle(items, spent{at: at, action: rc.ActionID})
		l.settle(l.items, spent{at: at, action: rc.ActionID})
	}
	return items, false
}

// add — своя квитанция сеанса, только что записанная, — в счёт сразу, а не
// когда её прочтут из файла: файл могли повернуть раньше (copytruncate со
// сжатием, olddir), и своё действие сеанс не увидел бы никогда (R2-4
// третьего захода). Из файла она второй раз не считается — по хэшу.
func (l *ledger) add(line []byte, now time.Time) {
	if len(line) > 0 {
		l.items, _ = l.take(line, now, l.items)
	}
}

// known — квитанция hash уже в счёте (в items или в l.items).
func (l *ledger) known(items []spent, hash string) bool {
	has := func(list []spent) bool {
		return slices.ContainsFunc(list, func(it spent) bool { return it.hash == hash || it.intent == hash })
	}
	return has(items) || has(l.items)
}

// settle — исход it заменяет намерение того же действия в items, если оно
// там есть.
func (l *ledger) settle(items []spent, it spent) bool {
	for i := len(items) - 1; i >= 0; i-- {
		if items[i].pending && items[i].action == it.action {
			it.intent = items[i].hash
			items[i] = it
			return true
		}
	}
	return false
}

// count — идёт ли квитанция в счёт. Считаются действия этого агента — execute
// и откаты undo_apply (откат меняет те же строки обратно, P-249), — кроме
// отказанных за частоту: те в базу не ходили, и считать их — значит держать
// агента под отказом, пока он пробует. Строки — у зафиксированных и у тех,
// чей COMMIT оборвался (unknown): они могли зафиксироваться, и раньше так
// обходилось окно — агент своей ролью обрывал сеанс сервера, пока COMMIT ждёт
// синхронную реплику, а база уже зафиксировала у себя (P-258).
func (l *ledger) count(rc Receipt, at time.Time) (spent, bool) {
	if rc.Agent != l.agent || (rc.Tool != "execute" && rc.Tool != "undo_apply") || rc.Cause == CauseRate {
		return spent{}, false
	}
	it := spent{at: at}
	if rc.Outcome == "committed" || rc.Outcome == "unknown" {
		it.rows = rc.Rows
	}
	return it, true
}

// note запоминает, когда об отказе за частоту последний раз ушла тревога.
func (l *ledger) note(rc Receipt, at time.Time) {
	if rc.Agent == l.agent && rc.Cause == CauseRate && rc.Alerted && at.After(l.alerted) {
		l.alerted = at
	}
}

// usage — сколько действий агент сделал за последнюю минуту, сколько строк
// изменил за окно и когда об отказе за частоту последний раз ушла тревога.
//
// self — действие, которое сейчас идёт: его намерение уже в файле, а строки
// считает тот, кто спрашивает; пусто — действие ещё не начато.
func (s *Server) usage(now time.Time, self string) (actions, rows int, alerted time.Time, err error) {
	var items []spent
	if s.cfg.ReceiptsPath != "" {
		if s.ledger == nil {
			worst := s.cfg.RowLimit
			if worst == 0 {
				worst = s.cfg.WindowRows
			}
			s.ledger = &ledger{path: s.cfg.ReceiptsPath, agent: s.cfg.Agent, own: s.own, keep: max(time.Minute, s.cfg.Window), worst: worst}
		}
		if err := s.ledger.refresh(now); err != nil {
			return 0, 0, alerted, err
		}
		items, alerted = s.ledger.items, s.ledger.alerted
	} else {
		// Файла на чтение нет (тесты): счёт по памяти этого сеанса.
		l := ledger{agent: s.cfg.Agent}
		for _, rc := range s.recent {
			if at, err := time.Parse(time.RFC3339Nano, rc.Time); err == nil {
				l.note(rc, at)
				if it, ok := l.count(rc, at); ok {
					items = append(items, it)
				}
			}
		}
		alerted = l.alerted
	}
	for _, it := range items {
		if it.pending && self != "" && it.action == self {
			continue
		}
		age := now.Sub(it.at)
		if age <= time.Minute {
			actions++
		}
		if age <= s.cfg.Window {
			rows += it.rows
		}
	}
	return actions, rows, alerted, nil
}

// markRefused кладёт подробности отказа в квитанцию исхода: по ней сборщик
// поднимает тревогу для людей (pginput, receipts.go). В журнал базы ничего не
// пишется: «что случилось» говорит подписанная квитанция шлюза, а не база
// (DECISIONS, п. 42). true — тревога будет.
func (s *Server) markRefused(rc *Receipt, info map[string]any) bool {
	if rc.Info == nil {
		rc.Info = map[string]any{}
	}
	for k, v := range info {
		rc.Info[k] = v
	}
	return s.cfg.ReceiptsPath != ""
}

// actionLock — замок на действие агента для всех его сеансов: flock на файле
// рядом с квитанциями, свой у каждого агента. Проверка частоты и окна,
// действие и квитанция идут под ним: без замка одновременные сеансы проходили
// проверку разом, и при пределе 4 действия в минуту из 30 одновременных
// проходило до 30 (P-252). Ждёт не дольше, чем может идти одно действие: дольше
// — другое действие агента зависло, и агенту честнее так и сказать. Без файла
// квитанций на чтение (тесты) замка нет.
func (s *Server) actionLock() (func(), error) {
	if s.cfg.ReceiptsPath == "" {
		return func() {}, nil
	}
	sum := sha256.Sum256([]byte(s.cfg.Agent))
	path := s.cfg.ReceiptsPath + "." + hex.EncodeToString(sum[:8]) + ".lock"
	wait := lockWait
	if s.cfg.StatementTimeout > 0 {
		wait = s.cfg.StatementTimeout + dbBackstop + lockWait
	}
	deadline := time.Now().Add(wait)
	for {
		// Файл замка лежит в каталоге квитанций, а его пишет и тот, у кого
		// ключа нет: подмени он файл другим (или ссылкой), сеансы держали бы
		// замки разных файлов и шли бы разом — мимо счёта пределов (P-252).
		// Замок взят — путь обязан вести к тому же файлу, иначе — заново.
		f, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR|unix.O_NOFOLLOW, 0o600)
		if err != nil {
			return nil, fmt.Errorf("the lock of the agent's actions could not be opened, so the limits cannot be checked: %w", err)
		}
		for {
			err = unix.Flock(int(f.Fd()), unix.LOCK_EX|unix.LOCK_NB)
			if err == nil || !errors.Is(err, unix.EWOULDBLOCK) || time.Now().After(deadline) {
				break
			}
			time.Sleep(20 * time.Millisecond)
		}
		if err != nil {
			f.Close()
			if errors.Is(err, unix.EWOULDBLOCK) {
				return nil, fmt.Errorf("another action of this agent has been running for more than %s: wait for it and do not retry in a loop", wait)
			}
			return nil, fmt.Errorf("the lock of the agent's actions failed, so the limits cannot be checked: %w", err)
		}
		held, herr := f.Stat()
		now, nerr := os.Lstat(path)
		if herr == nil && nerr == nil && held.Mode().IsRegular() && os.SameFile(held, now) {
			return func() { unix.Flock(int(f.Fd()), unix.LOCK_UN); f.Close() }, nil
		}
		f.Close()
		if time.Now().After(deadline) {
			return nil, fmt.Errorf("the lock file of the agent's actions %s keeps being replaced, so the limits cannot be checked", path)
		}
	}
}

// lockWait — сколько ждать замок сверх времени одного действия (в тестах — меньше).
var lockWait = 10 * time.Second
