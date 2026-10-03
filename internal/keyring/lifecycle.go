package keyring

import (
	"fmt"
	"sort"
	"time"
)

// Op — операция, которой нужны подтверждения.
type Op string

const (
	OpScheduleDestroy Op = "schedule-destroy"
	OpCancelDestroy   Op = "cancel-destroy"
)

// Approval — подтверждение одного человека. Sig — его подпись над
// (op, scope, kekID); проверяет её Policy, кейринг записывает только Who.
type Approval struct {
	Who string
	Sig []byte
}

// Policy решает, хватает ли подтверждений.
//
// Настоящий двойной контроль — только если проверка исполняется там, куда
// администратор хоста не дотягивается (кворум HSM, хранитель у другой
// команды). Проверка внутри этого процесса — учёт «кто подтвердил», а не
// запрет: администратор хоста её обойдёт.
type Policy interface {
	Check(op Op, scope string, kekID [kekIDSize]byte, approvals []Approval) error
}

// TwoPeople — политика по умолчанию, только учёт: заявка на уничтожение —
// два разных человека, отмена — один (отмена — безопасное направление).
// Подписи не проверяет.
type TwoPeople struct{}

func (TwoPeople) Check(op Op, _ string, _ [kekIDSize]byte, approvals []Approval) error {
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
			changed = append(changed, e)
		case Deactivated:
		default:
			return fmt.Errorf("%w: %q is %v", ErrBadState, s, e.state)
		}
	}
	if len(changed) == 0 {
		return nil
	}
	now := k.now()
	for _, e := range changed {
		e.state, e.deactivated = Deactivated, now
	}
	committed, err := k.persistLocked()
	if !committed {
		for _, e := range changed {
			e.state, e.deactivated = Active, time.Time{}
		}
	}
	return err
}

// ScheduleDestroy — первый шаг уничтожения: Deactivated → Pending. Ключ
// сразу перестаёт работать, но до срока уничтожение можно отменить. Срок не
// короче Options.MinWait.
func (k *Keyring) ScheduleDestroy(scope string, wait time.Duration, approvals []Approval) (KeyInfo, error) {
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
		return e.info(), fmt.Errorf("%w: %q is %v, schedule needs %v", ErrBadState, scope, e.state, Deactivated)
	}
	if wait < k.opt.MinWait {
		return e.info(), fmt.Errorf("%w: wait %v is shorter than minimum %v", ErrBadState, wait, k.opt.MinWait)
	}
	who, err := k.approve(OpScheduleDestroy, e, approvals)
	if err != nil {
		return e.info(), err
	}
	prev := *e
	e.state, e.destroyAfter, e.approvals = Pending, k.now().Add(wait), who
	committed, err := k.persistLocked()
	if !committed {
		*e = prev
	}
	return e.info(), err
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
		return e.info(), fmt.Errorf("%w: %q is %v, cancel needs %v", ErrBadState, scope, e.state, Pending)
	}
	if _, err := k.approve(OpCancelDestroy, e, approvals); err != nil {
		return e.info(), err
	}
	prev := *e
	e.state, e.destroyAfter, e.approvals = Deactivated, time.Time{}, nil
	committed, err := k.persistLocked()
	if !committed {
		*e = prev
	}
	return e.info(), err
}

// approve проверяет пределы и зовёт Policy; отдаёт имена подтвердивших.
// Пределы — до Policy: имя или их число сверх предела записалось бы в файл,
// который потом не откроется.
func (k *Keyring) approve(op Op, e *entry, approvals []Approval) ([]string, error) {
	if len(approvals) > MaxApprovals {
		return nil, fmt.Errorf("%w: %d approvals, at most %d", ErrApproval, len(approvals), MaxApprovals)
	}
	for _, a := range approvals {
		if len(a.Who) > MaxApproverLen {
			return nil, fmt.Errorf("%w: approver name longer than %d", ErrApproval, MaxApproverLen)
		}
	}
	p := k.opt.Policy
	if p == nil {
		p = TwoPeople{}
	}
	if err := p.Check(op, e.scope, e.id, approvals); err != nil {
		return nil, err
	}
	who := make([]string, 0, len(approvals))
	for _, a := range approvals {
		who = append(who, a.Who)
	}
	return who, nil
}

// CompleteDue — второй шаг: уничтожает ключи с истёкшим сроком ожидания и
// добивает старые корни. Звать по расписанию. Отдаёт ключи, у которых
// что-то изменилось (уничтожен, стал окончательным): по каждому движок пишет
// квитанцию в цепь. При ошибке тоже отдаёт то, что успело измениться.
func (k *Keyring) CompleteDue() ([]KeyInfo, error) {
	k.wmu.Lock()
	defer k.wmu.Unlock()
	k.mu.Lock()
	defer k.mu.Unlock()
	if k.closed {
		return nil, ErrClosed
	}
	now := k.now()
	var due []*entry
	for _, e := range k.byName {
		if e.state == Pending && !now.Before(e.destroyAfter) {
			due = append(due, e)
		}
	}
	sort.Slice(due, func(i, j int) bool { return due[i].scope < due[j].scope })

	var changed []*entry
	if len(due) > 0 {
		committed, err := k.rotateLocked(due)
		if committed {
			changed = append(changed, due...)
		}
		if err != nil {
			return infos(changed), err
		}
	}
	eff, err := k.finishLocked()
	return infos(append(changed, eff...)), err
}

// infos — KeyInfo по списку без повторов, в порядке первого появления.
func infos(es []*entry) []KeyInfo {
	seen := make(map[*entry]bool, len(es))
	var out []KeyInfo
	for _, e := range es {
		if !seen[e] {
			seen[e] = true
			out = append(out, e.info())
		}
	}
	return out
}
