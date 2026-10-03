package keyring

import (
	"errors"
	"fmt"
	"slices"
	"time"
)

// Уничтожение ключей — поворот корня:
//
//  1. заводится новый корень;
//  2. файл без уничтожаемых ключей запирается новым корнем, пишется и
//     уходит в резерв;
//  3. только после этого уничтожаются старые корни.
//
// После шага 3 ни одна копия keyring.dat с этими ключами не открывается: ни
// в резерве, ни в старых блоках диска. Порядок 2 → 3 менять нельзя:
// уничтожив старый корень до того, как новый файл дошёл до резерва, при
// потере диска теряешь все ключи.

// rotateLocked убирает ключи due из файла и перезапирает файл новым корнем.
// committed — файл заменён: ключи уничтожены, даже если err != nil (не
// прошла копия). Тогда память уже равна диску и не откатывается.
func (k *Keyring) rotateLocked(due []*entry) (committed bool, err error) {
	newRoot, err := k.newRoot()
	if err != nil {
		return false, err
	}
	oldRoot, oldRetired := k.rootID, k.retired
	prev := make([]entry, len(due))
	now := k.now()
	for i, e := range due {
		prev[i] = *e
		e.state, e.destroyed = Destroyed, now
	}
	k.rootID = newRoot
	k.retired = append(slices.Clone(oldRetired), oldRoot)
	committed, err = k.persistLocked()
	if !committed {
		// Файл не заменён: ключи живы, корень прежний. Новый корень — в
		// уничтожение: им мог быть заперт недописанный .tmp.
		for i, e := range due {
			*e = prev[i]
		}
		k.rootID = oldRoot
		k.retired = append(slices.Clone(oldRetired), newRoot)
		return false, err
	}
	for _, e := range due {
		zeroize(e.key)
		e.key, e.aead = nil, nil
	}
	return true, err
}

// finishLocked уничтожает старые корни и отдаёт ключи, ставшие
// окончательно уничтоженными. Сначала — полная запись текущего состояния с
// копией в резерв, если её ещё не было: пока резерв заперт старым корнем,
// уничтожать этот корень нельзя.
func (k *Keyring) finishLocked() ([]*entry, error) {
	if len(k.retired) == 0 {
		return nil, nil
	}
	if k.safe != k.gen {
		if _, err := k.persistLocked(); err != nil {
			return nil, err
		}
	}
	var rest []string
	var errs []error
	for _, id := range k.retired {
		if err := k.roots.DestroyRoot(id); err != nil {
			rest = append(rest, id)
			errs = append(errs, fmt.Errorf("keyring destroy root %s: %w", id, err))
		}
	}
	prev := k.retired
	k.retired = rest
	var marked []*entry
	if len(rest) == 0 {
		now := k.now()
		for _, e := range k.byName {
			if !e.live() && e.effective.IsZero() {
				e.effective = now
				marked = append(marked, e)
			}
		}
	}
	committed, err := k.persistLocked()
	if !committed {
		// Уничтоженные корни не вернуть, и не нужно: DestroyRoot повторяется
		// без ошибки. Не записалась только отметка — поставим её в следующий раз.
		k.retired = prev
		for _, e := range marked {
			e.effective = time.Time{}
		}
		marked = nil
	}
	return marked, errors.Join(append(errs, err)...)
}
