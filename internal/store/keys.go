package store

import (
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"

	"evidencestore/internal/auditchain"
	"evidencestore/internal/keyring"
)

// Каждая смена состояния ключа ложится в цепь событием EventKeyState:
// Scope — скоуп, Subject — метка состояния (keyLabel), в предмете — номер
// ключа, срок ожидания и кто подтвердил. Так уничтожение ключа становится
// квитанцией, которую закроет следующая метка TSA.
//
// Цепь же служит якорем для самого кейринга: при запуске его состояние
// сверяется с последним событием каждого ключа (reconcileKeys). Откат
// keyring.dat к старой копии (вернуть отменённую заявку, снова открыть
// закрытый месяц) виден как расхождение с цепью.

// keyLabel — метка состояния для цепи. «Уничтожен окончательно» —
// отдельная метка: старые корни уничтожены, старые копии кейринга не
// открываются.
func keyLabel(ki keyring.KeyInfo) string {
	if ki.State == keyring.Destroyed && !ki.EffectiveAt.IsZero() {
		return "destroyed-effective"
	}
	return ki.State.String()
}

var labelRank = map[string]int{
	"active": 1, "deactivated": 2, "pending-destruction": 3, "destroyed": 4, "destroyed-effective": 5,
}

type keyEvent struct {
	KEKID        string     `json:"kek_id"`
	State        string     `json:"state"`
	Op           string     `json:"op,omitempty"`
	DestroyAfter *time.Time `json:"destroy_after,omitempty"`
	DestroyedAt  *time.Time `json:"destroyed_at,omitempty"`
	EffectiveAt  *time.Time `json:"effective_at,omitempty"`
	Approvals    []string   `json:"approvals,omitempty"`
	Recovered    bool       `json:"recovered,omitempty"` // квитанция восстановлена при запуске после сбоя
}

func optTime(t time.Time) *time.Time {
	if t.IsZero() {
		return nil
	}
	u := t.UTC()
	return &u
}

// logKeyLocked пишет событие, если состояние ключа сменилось с последнего
// записанного. Зовётся под scopeMu.
//
// Только по состоянию, дошедшему до резерва (Confirmed): keyring.dat,
// поднятый из резерва после потери диска, тогда не окажется позади цепи, и
// хранилище стартует. Неподтверждённое состояние ляжет в цепь позже — его
// допишет syncKeys после Confirm в обслуживании.
func (s *Store) logKeyLocked(ki keyring.KeyInfo, op string, approvals []keyring.Approval, recovered bool) {
	if !ki.Confirmed {
		return
	}
	label := keyLabel(ki)
	if s.keyLabels[ki.Scope] == label {
		return
	}
	ev := keyEvent{
		KEKID: hex.EncodeToString(ki.KEKID[:]), State: label, Op: op,
		DestroyAfter: optTime(ki.DestroyAfter), DestroyedAt: optTime(ki.DestroyedAt), EffectiveAt: optTime(ki.EffectiveAt),
		Recovered: recovered,
	}
	if ki.State == keyring.Pending || ki.State == keyring.Destroyed {
		ev.Approvals = ki.Approvals
	}
	for _, a := range approvals {
		if op == string(keyring.OpCancelDestroy) {
			ev.Approvals = append(ev.Approvals, a.Who)
		}
	}
	s.appendJSONEvent(auditchain.EventKeyState, ki.Scope, label, ev)
	s.keyLabels[ki.Scope] = label
	s.log.Info("key state", "scope", ki.Scope, "state", label, "op", op)
}

func (s *Store) keyInfo(scope string) (keyring.KeyInfo, bool) {
	for _, ki := range s.keys.List() {
		if ki.Scope == scope {
			return ki, true
		}
	}
	return keyring.KeyInfo{}, false
}

// syncKeys пишет события для всех ключей, чьё состояние в кейринге ушло
// вперёд записанного в цепь. Зовётся после любой операции над ключами:
// так квитанция появляется и тогда, когда операция вернула ошибку, но
// успела записать кейринг (сбой резерва).
func (s *Store) syncKeys(op string, approvals []keyring.Approval) {
	s.scopeMu.Lock()
	defer s.scopeMu.Unlock()
	for _, ki := range s.keys.List() {
		s.scopes[ki.Scope] = true
		s.logKeyLocked(ki, op, approvals, false)
	}
}

// reconcileKeys сверяет кейринг с последними событиями ключей в цепи.
// Кейринг может быть впереди цепи на одну операцию (упали между записью
// кейринга и квитанцией) — тогда квитанция дописывается. Позади цепи он
// быть не может: это откат или подмена keyring.dat.
//
// Копия keyring.dat в резерв — только после сверки: файл после рестарта не
// знает, что из него уже в резерве, и копия это подтверждает (квитанции
// ждут подтверждения). Раньше копия шла до сверки, и keyring.dat, старший
// цепи, затирал свежий резерв, а сверка отказывала уже потом.
func (s *Store) reconcileKeys(chainLast map[string]string) error {
	s.scopeMu.Lock()
	defer s.scopeMu.Unlock()
	s.keyLabels = map[string]string{}
	for scope, label := range chainLast {
		s.keyLabels[scope] = label
	}
	var errs []error
	var ahead []string
	for _, ki := range s.keys.List() {
		s.scopes[ki.Scope] = true
		cur := keyLabel(ki)
		last, inChain := chainLast[ki.Scope]
		delete(chainLast, ki.Scope)
		switch {
		case cur == last:
		case !inChain, labelRank[cur] > labelRank[last],
			last == "pending-destruction" && cur == "deactivated": // отмена, квитанция не успела
			ahead = append(ahead, ki.Scope)
		default:
			errs = append(errs, fmt.Errorf("%w: %s is %q in keyring, chain says %q", ErrKeyringMismatch, ki.Scope, cur, last))
		}
	}
	for scope, last := range chainLast {
		errs = append(errs, fmt.Errorf("%w: %s is %q in chain but missing from keyring", ErrKeyringMismatch, scope, last))
	}
	if len(errs) > 0 {
		return errors.Join(errs...)
	}
	if err := s.keys.Confirm(); err != nil {
		s.log.Warn("keyring backup pending", "err", err)
	}
	for _, scope := range ahead {
		if ki, ok := s.keyInfo(scope); ok {
			s.logKeyLocked(ki, "", nil, true)
		}
	}
	return nil
}

// ensureScope заводит ключ скоупа с квитанцией в цепи. Быстрый путь — без
// обращения к кейрингу.
func (s *Store) ensureScope(scope string) error {
	s.scopeMu.Lock()
	defer s.scopeMu.Unlock()
	if s.scopes[scope] {
		return nil
	}
	return s.ensureScopesLocked([]string{scope})
}

func (s *Store) ensureScopesLocked(scopes []string) error {
	var fresh []string
	for _, sc := range scopes {
		if !s.scopes[sc] {
			fresh = append(fresh, sc)
		}
	}
	if len(fresh) == 0 {
		return nil
	}
	err := s.keys.EnsureScopes(fresh...)
	// Квитанции — только у ключей, дошедших до резерва (logKeyLocked). Ключ,
	// записанный без копии, Seal не выдаст, и в цепь он ляжет после Confirm.
	for _, sc := range fresh {
		if ki, ok := s.keyInfo(sc); ok {
			s.logKeyLocked(ki, "create", nil, false)
			if err == nil {
				s.scopes[sc] = true
			}
		}
	}
	return err
}

// scopeOf разбирает скоуп "источник/ГГГГ-ММ".
func scopeOf(scope string) (source string, month time.Time, ok bool) {
	i := strings.LastIndexByte(scope, '/')
	if i <= 0 {
		return "", time.Time{}, false
	}
	m, err := time.Parse("2006-01", scope[i+1:])
	if err != nil {
		return "", time.Time{}, false
	}
	return scope[:i], m, true
}

func monthScope(source string, t time.Time) string {
	t = t.UTC()
	return fmt.Sprintf("%s/%04d-%02d", source, t.Year(), int(t.Month()))
}

func monthStart(t time.Time) time.Time {
	t = t.UTC()
	return time.Date(t.Year(), t.Month(), 1, 0, 0, 0, 0, time.UTC)
}

// ensureMonthScopes заводит ключи текущего месяца, а за неделю до конца
// месяца — и следующего: в полночь первого числа никто не ждёт записи
// keyring.dat под эксклюзивным замком.
func (s *Store) ensureMonthScopes(now time.Time) error {
	next := monthStart(now).AddDate(0, 1, 0)
	var want []string
	for _, src := range s.cfg.Sources {
		if src.Disabled {
			continue
		}
		want = append(want, monthScope(src.Name, now))
		if next.Sub(now) < 7*24*time.Hour {
			want = append(want, monthScope(src.Name, next))
		}
	}
	s.scopeMu.Lock()
	defer s.scopeMu.Unlock()
	return s.ensureScopesLocked(want)
}

// deactivationGrace — сколько ждать после начала месяца, прежде чем закрыть
// прошлый: запись, принятая в 23:59:59, могла ещё запечатываться.
const deactivationGrace = 5 * time.Minute

// deactivatePastMonths закрывает для записи ключи прошлых месяцев.
func (s *Store) deactivatePastMonths(now time.Time) error {
	cur := monthStart(now)
	if now.Before(cur.Add(deactivationGrace)) {
		cur = cur.AddDate(0, -1, 0)
	}
	var past []string
	for _, ki := range s.keys.List() {
		if ki.State != keyring.Active {
			continue
		}
		if _, m, ok := scopeOf(ki.Scope); ok && m.Before(cur) {
			past = append(past, ki.Scope)
		}
	}
	if len(past) == 0 {
		return nil
	}
	err := s.keys.Deactivate(past...)
	s.syncKeys("deactivate", nil)
	return err
}

// Keys — состояние всех ключей.
func (s *Store) Keys() []keyring.KeyInfo { return s.keys.List() }

// DestroyOrphanRoots уничтожает корни-сироты по решению оператора и пишет
// это событием в цепь. Безопасно для улик: при запуске хранилище проверило,
// что каждая улика журнала запечатана ключом из keyring.dat, а им заперт его
// собственный корень, не сирота.
func (s *Store) DestroyOrphanRoots() ([]string, error) {
	done, err := s.keys.DestroyOrphanRoots()
	if len(done) > 0 {
		s.appendJSONEvent(auditchain.EventRoots, "", "orphan-roots-destroyed", map[string]any{"roots": done})
		s.log.Warn("orphan keyring roots destroyed", "roots", done)
	}
	return done, err
}

// confirmKeys повторяет копию keyring.dat в резерв, если она не прошла, и
// дописывает в цепь квитанции, ждавшие копии.
func (s *Store) confirmKeys() {
	if err := s.keys.Confirm(); err != nil {
		s.log.Warn("keyring backup pending", "err", err)
	}
	s.syncKeys("", nil)
	if err := s.keys.RepairRoots(); err != nil {
		s.log.Warn("keyring root copies", "err", err)
	}
}

// ErrCurrentMonth — попытка закрыть текущий или будущий месяц без force:
// приём от источника встал бы до конца месяца.
var ErrCurrentMonth = errors.New("store: closing the current month stops intake from the source until the month ends; use force")

// Deactivate закрывает скоупы для записи вручную. Текущий и будущий месяц —
// только с force: новые записи источника ложатся именно в них, и закрытие
// остановит приём от источника до конца месяца.
func (s *Store) Deactivate(force bool, scopes ...string) error {
	if !force {
		cur := monthStart(s.nowTime())
		for _, sc := range scopes {
			if _, m, ok := scopeOf(sc); ok && !m.Before(cur) {
				return fmt.Errorf("%w: %s", ErrCurrentMonth, sc)
			}
		}
	}
	err := s.keys.Deactivate(scopes...)
	s.syncKeys("deactivate", nil)
	return err
}

// ScheduleDestroy — заявка на уничтожение ключа скоупа (два подтверждения,
// срок ожидания не короче keys.min_wait).
//
// Срок отмеряется от доверенного времени: от свежей метки TSA, если она
// позже наших часов (и не раньше последнего времени приёма). Уничтожение
// сверяется с TSA (CompleteDue), и часы, отставшие в момент заявки, иначе
// сжимали окно отмены: срок = отставшие часы + ожидание давно прошёл по TSA.
// Метки не получить — заявка не принимается.
func (s *Store) ScheduleDestroy(ctx context.Context, scope string, wait time.Duration, approvals []keyring.Approval) (keyring.KeyInfo, error) {
	from := s.nowTime()
	if s.tsaURL != "" || s.tsaLocal != nil {
		t, err := s.stampNow(ctx)
		if err != nil {
			return keyring.KeyInfo{}, fmt.Errorf("store: a destruction request needs TSA time: %w", err)
		}
		if t.After(from) {
			from = t
		}
	}
	s.mu.Lock()
	if lr := time.Unix(0, s.lastRecv); lr.After(from) {
		from = lr
	}
	s.mu.Unlock()
	ki, err := s.keys.ScheduleDestroyFrom(scope, from, wait, approvals)
	s.syncKeys(string(keyring.OpScheduleDestroy), approvals)
	return ki, err
}

// CancelDestroy отменяет заявку в период ожидания.
func (s *Store) CancelDestroy(scope string, approvals []keyring.Approval) (keyring.KeyInfo, error) {
	ki, err := s.keys.CancelDestroy(scope, approvals)
	s.syncKeys(string(keyring.OpCancelDestroy), approvals)
	return ki, err
}

// CompleteDue уничтожает ключи, чей срок ожидания истёк. Срок отмеряется
// по меньшему из двух времён — наших часов и метки TSA, взятой тут же над
// текущей головой: перевод часов хоста вперёд не сокращает окно отмены.
// Метка ложится в цепь раньше квитанции об уничтожении, и проверяющий видит,
// что срок истёк по времени TSA. Без TSA — по нашим часам. Метки не
// получить — уничтожение ждёт (старые корни при этом добиваются).
func (s *Store) CompleteDue(ctx context.Context) ([]keyring.KeyInfo, error) {
	var at time.Time // ноль — ничего не уничтожать, только добить корни
	var stampErr error
	if now := s.nowTime(); s.dueBy(now) {
		at = now
		if s.tsaURL != "" || s.tsaLocal != nil {
			t, err := s.stampNow(ctx)
			switch {
			case err != nil:
				at, stampErr = time.Time{}, fmt.Errorf("store: key destruction waits for TSA time: %w", err)
			case t.Before(at):
				at = t
			}
		}
	}
	changed, err := s.keys.CompleteDueAt(at)
	s.syncKeys("complete", nil)
	return changed, errors.Join(stampErr, err)
}

// dueBy — есть ли ключ, ждущий уничтожения, чей срок истёк к now.
func (s *Store) dueBy(now time.Time) bool {
	for _, ki := range s.keys.List() {
		if ki.State == keyring.Pending && !now.Before(ki.DestroyAfter) {
			return true
		}
	}
	return false
}

// DueScope — месяц источника, вышедший за срок хранения.
type DueScope struct {
	Scope string
	State keyring.State
	Since time.Time // когда месяц вышел за срок
}

// RetentionDue — месяцы, которые пора уничтожать по сроку хранения
// источника. Заявку подают люди (два подтверждения): автоматом ключи не
// уничтожаются.
func (s *Store) RetentionDue(now time.Time) []DueScope {
	var out []DueScope
	for _, ki := range s.keys.List() {
		if ki.State == keyring.Destroyed || ki.State == keyring.Pending {
			continue
		}
		source, m, ok := scopeOf(ki.Scope)
		if !ok {
			continue
		}
		src, ok := s.cfg.Source(source)
		if !ok || src.RetentionMonths == 0 {
			continue
		}
		// Месяц хранится RetentionMonths полных месяцев после своего конца.
		expires := m.AddDate(0, 1+src.RetentionMonths, 0)
		if !now.Before(expires) {
			out = append(out, DueScope{Scope: ki.Scope, State: ki.State, Since: expires})
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Scope < out[j].Scope })
	return out
}
