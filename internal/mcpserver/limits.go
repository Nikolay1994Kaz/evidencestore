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
	"bufio"
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"strconv"
	"time"

	"golang.org/x/sys/unix"

	"github.com/Nikolay1994Kaz/evidencestore/internal/alert"
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
func (s *Server) sessionParams() map[string]string {
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
	items   []spent
	alerted time.Time // последний отказ за частоту, о котором людям ушла тревога
}

// refresh дочитывает файл и забывает то, что старше keep.
func (l *ledger) refresh(now time.Time) error {
	f, err := os.Open(l.path)
	if errors.Is(err, os.ErrNotExist) {
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
	if !l.primed {
		// Первый раз: нужен только хвост файла, покрывающий окно. Хвост
		// берётся с запасом и растёт, пока не покроет окно или весь файл.
		for tail := int64(256 << 10); ; tail *= 16 {
			start := max(fi.Size()-tail, 0)
			items, covered, end, err := l.read(f, start, fi.Size(), now, start > 0)
			if err != nil {
				return err
			}
			if covered || start == 0 {
				l.items, l.off, l.primed = items, end, true
				break
			}
		}
	} else {
		if fi.Size() < l.off {
			l.off, l.items = 0, nil // файл заменили (ротация): в нём всё новое
		}
		items, _, end, err := l.read(f, l.off, fi.Size(), now, false)
		if err != nil {
			return err
		}
		l.items, l.off = append(l.items, items...), end
	}
	fresh := l.items[:0]
	for _, it := range l.items {
		if now.Sub(it.at) <= l.keep {
			fresh = append(fresh, it)
		}
	}
	l.items = fresh
	return nil
}

// read разбирает квитанции файла от start до end. midline — start взят
// наугад (хвост файла) и может стоять посреди строки. covered — среди
// прочитанных есть квитанция старше keep: хвост покрыл окно. done — докуда
// прочитаны целые строки: обрывок в конце ещё дописывается другим сеансом, и
// следующее чтение начнётся с его начала. Раньше чтение продолжалось с конца
// файла, и квитанция, застигнутая недописанной, пропадала из счёта насовсем
// (P-244).
func (l *ledger) read(f *os.File, start, end int64, now time.Time, midline bool) (items []spent, covered bool, done int64, err error) {
	r := bufio.NewReaderSize(io.NewSectionReader(f, start, end-start), 1<<16)
	done = start
	if midline {
		// Остаток строки, посреди которой началось чтение, — не квитанция.
		skip, err := r.ReadBytes('\n')
		if err == io.EOF {
			return nil, false, start, nil
		} else if err != nil {
			return nil, false, start, err
		}
		done += int64(len(skip))
	}
	for {
		line, err := r.ReadBytes('\n')
		if err == io.EOF {
			return items, covered, done, nil // обрывок без перевода строки ещё дописывается
		}
		if err != nil {
			return nil, false, start, err
		}
		done += int64(len(line))
		rc, step, ok := l.own(bytes.TrimRight(line, "\n"))
		if !ok || (step != alert.StepOutcome && step != alert.StepIntent && step != alert.StepUndo) {
			continue
		}
		at, perr := time.Parse(time.RFC3339Nano, rc.Time)
		if perr != nil {
			continue
		}
		if now.Sub(at) > l.keep {
			covered = true
			continue
		}
		if step != alert.StepOutcome {
			// Намерение: действие пошло в базу. Исхода может не быть никогда —
			// тогда оно в счёте с худшим случаем (T-8, R2-4).
			if rc.Agent == l.agent && (rc.Tool == "execute" || rc.Tool == "undo_apply") {
				items = append(items, spent{at: at, rows: l.worst, action: rc.ActionID, pending: true})
			}
			continue
		}
		l.note(rc, at)
		if it, ok := l.count(rc, at); ok {
			it.action = rc.ActionID
			if !l.settle(items, it) && !l.settle(l.items, it) {
				items = append(items, it)
			}
		} else {
			// Не в счёт (отказ за частоту и подобное): и намерение его — нет.
			l.settle(items, spent{at: at, action: rc.ActionID})
			l.settle(l.items, spent{at: at, action: rc.ActionID})
		}
	}
}

// settle — исход it заменяет намерение того же действия в items, если оно
// там есть.
func (l *ledger) settle(items []spent, it spent) bool {
	for i := len(items) - 1; i >= 0; i-- {
		if items[i].pending && items[i].action == it.action {
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
	f, err := os.OpenFile(s.cfg.ReceiptsPath+"."+hex.EncodeToString(sum[:8])+".lock", os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return nil, fmt.Errorf("the lock of the agent's actions could not be opened, so the limits cannot be checked: %w", err)
	}
	wait := lockWait
	if s.cfg.StatementTimeout > 0 {
		wait = s.cfg.StatementTimeout + dbBackstop + lockWait
	}
	for deadline := time.Now().Add(wait); ; {
		err := unix.Flock(int(f.Fd()), unix.LOCK_EX|unix.LOCK_NB)
		if err == nil {
			return func() { unix.Flock(int(f.Fd()), unix.LOCK_UN); f.Close() }, nil
		}
		if !errors.Is(err, unix.EWOULDBLOCK) || time.Now().After(deadline) {
			f.Close()
			if errors.Is(err, unix.EWOULDBLOCK) {
				return nil, fmt.Errorf("another action of this agent has been running for more than %s: wait for it and do not retry in a loop", wait)
			}
			return nil, fmt.Errorf("the lock of the agent's actions failed, so the limits cannot be checked: %w", err)
		}
		time.Sleep(20 * time.Millisecond)
	}
}

// lockWait — сколько ждать замок сверх времени одного действия (в тестах — меньше).
var lockWait = 10 * time.Second
