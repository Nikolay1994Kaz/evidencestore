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
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"time"

	"golang.org/x/sys/unix"

	"github.com/Nikolay1994Kaz/evidencestore/internal/pgwire"
)

// Причины отказа и срыва действия (Receipt.Cause, отметка evidence.mark_refused).
const (
	CauseRowLimit   = "row-limit"   // действие меняет больше строк, чем можно одному
	CauseWindowRows = "window-rows" // с ним агент превысил бы предел строк за окно
	CauseRate       = "rate"        // слишком много действий за минуту
	CauseTimeout    = "timeout"     // запрос шёл дольше предела и отменён
	CauseEscaped    = "escaped"     // SQL агента закрыл транзакцию сервера (COMMIT, ROLLBACK в тексте)
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
	db, err := s.cfg.Dial()
	if err != nil {
		return fmt.Errorf("the database is unreachable: %w", err)
	}
	s.db = db
	return nil
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
}

// ledger — расход агента за последнее время по файлу квитанций. Файл читается
// с того места, где остановились в прошлый раз: в него пишут и другие сеансы.
type ledger struct {
	path, agent string
	keep        time.Duration // сколько помнить: самое длинное окно
	primed      bool
	off         int64
	items       []spent
	alerted     time.Time // последний отказ за частоту, о котором людям ушла тревога
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
		var rc Receipt
		if json.Unmarshal(line, &rc) != nil {
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
		l.note(rc, at)
		if it, ok := l.count(rc, at); ok {
			items = append(items, it)
		}
	}
}

// count — идёт ли квитанция в счёт. Считаются действия этого агента — execute
// и откаты undo_apply (откат меняет те же строки обратно, P-249), — кроме
// отказанных за частоту: те в базу не ходили, и считать их — значит держать
// агента под отказом, пока он пробует. Строки — только у зафиксированных.
func (l *ledger) count(rc Receipt, at time.Time) (spent, bool) {
	if rc.Agent != l.agent || (rc.Tool != "execute" && rc.Tool != "undo_apply") || rc.Cause == CauseRate {
		return spent{}, false
	}
	it := spent{at: at}
	if rc.Outcome == "committed" {
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
func (s *Server) usage(now time.Time) (actions, rows int, alerted time.Time, err error) {
	var items []spent
	if s.cfg.ReceiptsPath != "" {
		if s.ledger == nil {
			s.ledger = &ledger{path: s.cfg.ReceiptsPath, agent: s.cfg.Agent, keep: max(time.Minute, s.cfg.Window)}
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

// markRefused оставляет в журнале базы отметку об отказе: по ней сборщик
// поднимает тревогу для людей. Сообщение не транзакционное, поэтому годится и
// внутри транзакции, которая сейчас откатится, и вне транзакции. Внутри —
// после своих настроек (own), вне — с чистого сеанса (fresh): SQL агента не
// меняет, как база прочтёт отметку с его причиной (P-243, P-256). false —
// отметки нет, и тревоги не будет.
func (s *Server) markRefused(rc *Receipt, info map[string]any) bool {
	info["action_id"], info["agent"], info["reason"], info["cause"] = rc.ActionID, rc.Agent, rc.Reason, rc.Cause
	mark, _ := json.Marshal(info)
	if _, err := s.run("SELECT evidence.mark_refused(" + pgwire.Literal(string(mark)) + "::pg_catalog.json)"); err != nil {
		s.log.Error("the refusal is not marked in the database log, so no alert is raised for it (is the database prepared with the current escollect -setup-sql?)",
			"action", rc.ActionID, "cause", rc.Cause, "err", err)
		return false
	}
	return true
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
