package keyring

import (
	"fmt"
	"slices"
	"sort"
	"time"
)

// Op — операция, которой нужны подтверждения.
type Op string

const (
	OpScheduleDestroy Op = "schedule-destroy"
	OpCancelDestroy   Op = "cancel-destroy"
)

// Approval — подтверждение одного человека: имя, которое ложится в
// keyring.dat и в цепь. Подписи у подтверждения нет.
type Approval struct {
	Who string
}

// TwoPeople — правило подтверждений: заявка на уничтожение — два разных
// человека, отмена — один (отмена — безопасное направление).
//
// Это учёт «кто подтвердил», а не запрет: имена приходят через админку, и
// администратор хоста впишет любые. Настоящий двойной контроль — только если
// проверка исполняется там, куда администратор хоста не дотягивается (кворум
// HSM, хранитель у другой команды).
type TwoPeople struct{}

func (TwoPeople) Check(op Op, approvals []Approval) error {
	need := 2
	if op == OpCancelDestroy {
		need = 1
	}
	seen := make(map[string]bool)
	for _, a := range approvals {
		if a.Who != "" {
			seen[a.Who] = true
		}
	}
	if len(seen) < need {
		return fmt.Errorf("%w: %s needs %d distinct approvers", ErrApproval, op, need)
	}
	return nil
}

// Deactivate закрывает скоупы для записи: расшифровывать можно,
// запечатывать нельзя. Зовётся, когда месяц закончился: после этого
// подвинутые назад часы уже не помогут дописать прошлый месяц.
func (k *Keyring) Deactivate(scopes ...string) error {
	k.wmu.Lock()
	defer k.wmu.Unlock()
	k.mu.Lock()
	defer k.mu.Unlock()
	if k.closed {
		return ErrClosed
	}
	var changed []*entry
	for _, s := range scopes {
		e, ok := k.byName[s]
		if !ok {
			return fmt.Errorf("%w: %q", ErrUnknownScope, s)
		}
		switch e.state {
		case Active:
			if !slices.Contains(changed, e) {
				changed = append(changed, e)
			}
		case Deactivated:
		default:
			return fmt.Errorf("%w: %q is %v", ErrBadState, s, e.state)
		}
	}
	if len(changed) == 0 {
		return nil
	}
	now := k.now()
	prev := make([]entry, len(changed))
	for i, e := range changed {
		prev[i] = *e
		e.state, e.deactivated, e.changed = Deactivated, now, k.gen+1
	}
	committed, err := k.persistLocked()
	if !committed {
		for i, e := range changed {
			*e = prev[i]
		}
	}
	return err
}

// MaxWait — предел срока ожидания: дальше время в файле не поместится в
// unix-нс, а срок «через 240 лет» после рестарта читался бы как 1681 год, и
// ключ уничтожался бы сразу.
const MaxWait = 10 * 365 * 24 * time.Hour

// ScheduleDestroyFrom — первый шаг уничтожения: Deactivated → Pending. Ключ
// сразу перестаёт работать, но до срока from + wait уничтожение можно
// отменить. from — время, которому верят (движок берёт его от метки TSA).
// Срок не короче Options.MinWait и не длиннее MaxWait.
func (k *Keyring) ScheduleDestroyFrom(scope string, from time.Time, wait time.Duration, approvals []Approval) (KeyInfo, error) {
	k.wmu.Lock()
	defer k.wmu.Unlock()
	k.mu.Lock()
	defer k.mu.Unlock()
	if k.closed {
		return KeyInfo{}, ErrClosed
	}
	e, ok := k.byName[scope]
	if !ok {
		return KeyInfo{}, fmt.Errorf("%w: %q", ErrUnknownScope, scope)
	}
	if e.state != Deactivated {
		return e.info(k.safe), fmt.Errorf("%w: %q is %v, schedule needs %v", ErrBadState, scope, e.state, Deactivated)
	}
	if wait < k.opt.MinWait {
		return e.info(k.safe), fmt.Errorf("%w: wait %v is shorter than minimum %v", ErrBadState, wait, k.opt.MinWait)
	}
	if wait > MaxWait {
		return e.info(k.safe), fmt.Errorf("%w: wait %v is longer than maximum %v", ErrBadState, wait, MaxWait)
	}
	who, err := approve(OpScheduleDestroy, approvals)
	if err != nil {
		return e.info(k.safe), err
	}
	prev := *e
	e.state, e.destroyAfter, e.approvals, e.changed = Pending, from.Add(wait), who, k.gen+1
	committed, err := k.persistLocked()
	if !committed {
		*e = prev
	}
	return e.info(k.safe), err
}

// CancelDestroy отменяет заявку в период ожидания: Pending → Deactivated.
func (k *Keyring) CancelDestroy(scope string, approvals []Approval) (KeyInfo, error) {
	k.wmu.Lock()
	defer k.wmu.Unlock()
	k.mu.Lock()
	defer k.mu.Unlock()
	if k.closed {
		return KeyInfo{}, ErrClosed
	}
	e, ok := k.byName[scope]
	if !ok {
		return KeyInfo{}, fmt.Errorf("%w: %q", ErrUnknownScope, scope)
	}
	if e.state != Pending {
		return e.info(k.safe), fmt.Errorf("%w: %q is %v, cancel needs %v", ErrBadState, scope, e.state, Pending)
	}
	if _, err := approve(OpCancelDestroy, approvals); err != nil {
		return e.info(k.safe), err
	}
	prev := *e
	e.state, e.destroyAfter, e.approvals, e.changed = Deactivated, time.Time{}, nil, k.gen+1
	committed, err := k.persistLocked()
	if !committed {
		*e = prev
	}
	return e.info(k.safe), err
}

// approve проверяет пределы и правило TwoPeople; отдаёт имена подтвердивших.
// Пределы — до правила: имя или их число сверх предела записалось бы в файл,
// который потом не откроется.
func approve(op Op, approvals []Approval) ([]string, error) {
	if len(approvals) > MaxApprovals {
		return nil, fmt.Errorf("%w: %d approvals, at most %d", ErrApproval, len(approvals), MaxApprovals)
	}
	for _, a := range approvals {
		if len(a.Who) > MaxApproverLen {
			return nil, fmt.Errorf("%w: approver name longer than %d", ErrApproval, MaxApproverLen)
		}
	}
	if err := (TwoPeople{}).Check(op, approvals); err != nil {
		return nil, err
	}
	who := make([]string, 0, len(approvals))
	for _, a := range approvals {
		who = append(who, a.Who)
	}
	return who, nil
}

// CompleteDueAt — второй шаг: уничтожает ключи, чей срок ожидания истёк к
// моменту at, и добивает старые корни. at — время, которому верят: движок
// берёт меньшее из своих часов и метки TSA, ноль — ничего не уничтожать,
// только добить корни. Звать по расписанию. Отдаёт ключи, у которых
// что-то изменилось (уничтожен, стал окончательным): по каждому движок пишет
// квитанцию в цепь. При ошибке тоже отдаёт то, что успело измениться.
func (k *Keyring) CompleteDueAt(at time.Time) ([]KeyInfo, error) {
	k.wmu.Lock()
	defer k.wmu.Unlock()
	k.mu.Lock()
	defer k.mu.Unlock()
	if k.closed {
		return nil, ErrClosed
	}
	var due []*entry
	for _, e := range k.byName {
		if e.state == Pending && !at.IsZero() && !at.Before(e.destroyAfter) {
			due = append(due, e)
		}
	}
	sort.Slice(due, func(i, j int) bool { return due[i].scope < due[j].scope })

	var changed []*entry
	if len(due) > 0 {
		committed, err := k.rotateLocked(due, at)
		if committed {
			changed = append(changed, due...)
		}
		if err != nil {
			return k.infos(changed), err
		}
	}
	eff, err := k.finishLocked()
	return k.infos(append(changed, eff...)), err
}

// infos — KeyInfo по списку без повторов, в порядке первого появления.
func (k *Keyring) infos(es []*entry) []KeyInfo {
	seen := make(map[*entry]bool, len(es))
	var out []KeyInfo
	for _, e := range es {
		if !seen[e] {
			seen[e] = true
			out = append(out, e.info(k.safe))
		}
	}
	return out
}
