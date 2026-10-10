package keyring

import (
	"errors"
	"fmt"
	"slices"
	"strings"
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
// at — время уничтожения (то, по которому истёк срок).
func (k *Keyring) rotateLocked(due []*entry, at time.Time) (committed bool, err error) {
	// Корень заводится с отпущенным mu: хранилище корней бывает медленным
	// (зеркало на NFS), а Seal ждать его не должен. Вызывающий держит wmu —
	// состояние в этом окне не меняет никто.
	k.mu.Unlock()
	newRoot, err := k.newRoot()
	k.mu.Lock()
	if err != nil {
		return false, err
	}
	oldRoot, oldRetired := k.rootID, k.retired
	prev := make([]entry, len(due))
	for i, e := range due {
		prev[i] = *e
		e.state, e.destroyed, e.changed = Destroyed, at, k.gen+1
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
// уничтожать этот корень нельзя. Окончательным уничтожение становится, когда
// старых корней не осталось и сирот нет (OrphanRoots).
func (k *Keyring) finishLocked() ([]*entry, error) {
	waiting := false // уничтожены, но ещё не окончательно
	for _, e := range k.byName {
		if !e.live() && e.effective.IsZero() {
			waiting = true
			break
		}
	}
	if len(k.retired) == 0 && !waiting {
		return nil, nil
	}
	if len(k.retired) > 0 && k.safe != k.gen {
		if _, err := k.persistLocked(); err != nil {
			return nil, err
		}
	}
	// Уничтожение корней и их перечисление — ввод-вывод, бывает медленным
	// (зеркало): идут с отпущенным mu, как копия в резерв. Вызывающий держит
	// wmu.
	var rest []string
	var errs []error
	prev := k.retired
	k.mu.Unlock()
	for _, id := range prev {
		if err := k.roots.DestroyRoot(id); err != nil {
			rest = append(rest, id)
			errs = append(errs, fmt.Errorf("keyring destroy root %s: %w", id, err))
		}
	}
	var all []string
	var listErr error
	if len(rest) == 0 && waiting {
		all, listErr = k.roots.Roots()
	}
	k.mu.Lock()
	k.retired = rest
	type mark struct {
		e       *entry
		changed uint64
	}
	var marks []mark
	if len(rest) == 0 && waiting {
		switch orphans := orphansOf(all, k.knownRootsLocked()); {
		case listErr != nil:
			errs = append(errs, fmt.Errorf("keyring list roots: %w", listErr))
		case len(orphans) > 0:
			errs = append(errs, fmt.Errorf("%w: %s", ErrOrphanRoots, strings.Join(orphans, ", ")))
		default:
			now := k.now()
			for _, e := range k.byName {
				if !e.live() && e.effective.IsZero() {
					marks = append(marks, mark{e, e.changed})
					e.effective, e.changed = now, k.gen+1
				}
			}
		}
	}
	if len(rest) == len(prev) && len(marks) == 0 {
		return nil, errors.Join(errs...) // файл не изменился
	}
	committed, err := k.persistLocked()
	if !committed {
		// Уничтоженные корни не вернуть, и не нужно: DestroyRoot повторяется
		// без ошибки. Не записалась только отметка — поставим её в следующий раз.
		k.retired = prev
		for _, m := range marks {
			m.e.effective, m.e.changed = time.Time{}, m.changed
		}
		marks = nil
	}
	marked := make([]*entry, len(marks))
	for i, m := range marks {
		marked[i] = m.e
	}
	return marked, errors.Join(append(errs, err)...)
}
