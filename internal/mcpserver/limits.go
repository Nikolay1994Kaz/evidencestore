package mcpserver

// Пределы для агента, которые не зависят от прав его роли в базе: сколько
// может идти один запрос, сколько действий в минуту и сколько строк за окно.
//
// ПОЧЕМУ ТАЙМЕР ЗДЕСЬ, А НЕ ТОЛЬКО В БАЗЕ. statement_timeout и lock_timeout
// роли — значения по умолчанию: сессия меняет их командой SET, а SQL агента
// идёт в базу как есть. Таймер сервера агенту недоступен: время вышло —
// запрос отменяется на сервере базы (CancelRequest), соединение закрывается,
// транзакция откатывается.
//
// ПОЧЕМУ СЧЁТ — ПО ФАЙЛУ КВИТАНЦИЙ. Сервер живёт один сеанс агента. Счёт в
// памяти обнулялся бы с каждым новым сеансом, а файл квитанций у всех сеансов
// агента общий: в нём каждое действие, его время и число строк. Два сеанса
// одновременно могут оба пройти проверку и вместе превысить предел на одно
// действие: предел мягкий, не замок.

import (
	"bufio"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"time"

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

// timed выполняет SQL агента не дольше StatementTimeout. Время вышло —
// запрос отменяется на сервере базы, а соединение закрывается: просьба об
// отмене не должна догнать следующий запрос, и транзакция должна откатиться,
// что бы агент в ней ни выставил.
func (s *Server) timed(sql string) ([]pgwire.Result, error) {
	limit := s.cfg.StatementTimeout
	if limit <= 0 {
		return s.run(sql)
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
	res, err := s.run(sql)
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
// умолчанию — SQL агента может их сменить; таймер сервера (timed) ему
// недоступен. "" — задавать нечего.
func (s *Server) guards() string {
	var sql string
	if s.cfg.StatementTimeout > 0 {
		sql = fmt.Sprintf("SET LOCAL statement_timeout = %d", (s.cfg.StatementTimeout + dbBackstop).Milliseconds())
	}
	if s.cfg.LockTimeout > 0 {
		if sql != "" {
			sql += "; "
		}
		sql += fmt.Sprintf("SET LOCAL lock_timeout = %d", s.cfg.LockTimeout.Milliseconds())
	}
	return sql
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
			items, covered, err := l.read(f, start, fi.Size(), now, start > 0)
			if err != nil {
				return err
			}
			if covered || start == 0 {
				l.items, l.off, l.primed = items, fi.Size(), true
				break
			}
		}
	} else {
		if fi.Size() < l.off {
			l.off, l.items = 0, nil // файл заменили (ротация): в нём всё новое
		}
		items, _, err := l.read(f, l.off, fi.Size(), now, false)
		if err != nil {
			return err
		}
		l.items, l.off = append(l.items, items...), fi.Size()
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
// прочитанных есть квитанция старше keep: хвост покрыл окно.
func (l *ledger) read(f *os.File, start, end int64, now time.Time, midline bool) (items []spent, covered bool, err error) {
	r := bufio.NewReaderSize(io.NewSectionReader(f, start, end-start), 1<<16)
	if midline {
		// Остаток строки, посреди которой началось чтение, — не квитанция.
		if _, err := r.ReadBytes('\n'); err == io.EOF {
			return nil, false, nil
		} else if err != nil {
			return nil, false, err
		}
	}
	for {
		line, err := r.ReadBytes('\n')
		if err == io.EOF {
			return items, covered, nil // обрывок без перевода строки ещё дописывается
		}
		if err != nil {
			return nil, false, err
		}
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

// count — идёт ли квитанция в счёт. Считаются действия execute этого агента,
// кроме отказанных за частоту: те в базу не ходили, и считать их — значит
// держать агента под отказом, пока он пробует. Строки — только у
// зафиксированных.
func (l *ledger) count(rc Receipt, at time.Time) (spent, bool) {
	if rc.Agent != l.agent || rc.Tool != "execute" || rc.Cause == CauseRate {
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
// внутри транзакции, которая сейчас откатится, и вне транзакции.
func (s *Server) markRefused(rc *Receipt, info map[string]any) {
	info["action_id"], info["agent"], info["reason"], info["cause"] = rc.ActionID, rc.Agent, rc.Reason, rc.Cause
	mark, _ := json.Marshal(info)
	if _, err := s.run("SELECT evidence.mark_refused(" + pgwire.Literal(string(mark)) + "::json)"); err != nil {
		s.log.Error("the refusal is not marked in the database log, so no alert is raised for it (is the database prepared with the current escollect -setup-sql?)",
			"action", rc.ActionID, "cause", rc.Cause, "err", err)
	}
}
