package keyring

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

// FileRoots хранит корни файлами в отдельном каталоге, вне каталога данных
// (права 0700, каталог должен существовать). Для разработки и пилота.
//
// Mirror — необязательный второй каталог на другом диске или другой
// машине. Корень пишется в оба, читается из Dir, а если там его нет — из
// Mirror, и уничтожается в обоих. Так потеря диска с Dir не уносит тела
// всех месяцев, а уничтожение остаётся уничтожением: других копий корня
// кейринг не делает. Любая иная копия этих каталогов (бэкап, снапшот)
// хранит уничтоженные корни, пока жива сама, поэтому их быть не должно.
//
// Чего он НЕ даёт: администратор хоста читает корни, а удалённый корень может
// пережить удаление в старых блоках SSD. Поэтому ни «администратор не может»,
// ни уничтожения по NIST SP 800-88 здесь нет. Даёт он формат и порядок
// операций те же, что будут с HSM.
type FileRoots struct {
	Dir    string
	Mirror string
}

const rootSuffix = ".root"

func (f FileRoots) dirs() []string {
	if f.Mirror == "" {
		return []string{f.Dir}
	}
	return []string{f.Dir, f.Mirror}
}

// validRootID: id приходит из заголовка файла, и подложенный заголовок не
// должен увести путь из каталога корней.
func validRootID(id string) bool {
	return len(id) == 32 && strings.Trim(id, "0123456789abcdef") == ""
}

func (f FileRoots) path(dir, id string) (string, error) {
	if !validRootID(id) {
		return "", fmt.Errorf("keyring: bad root id %q", id)
	}
	return filepath.Join(dir, id+rootSuffix), nil
}

func (f FileRoots) NewRoot() (string, error) {
	var raw [16]byte
	rand.Read(raw[:])
	id := hex.EncodeToString(raw[:])
	key := make([]byte, kekSize)
	defer zeroize(key)
	rand.Read(key)
	for i, dir := range f.dirs() {
		p, _ := f.path(dir, id)
		if _, err := writeFileAtomic(p, key); err != nil {
			// Корень без второй копии не нужен: убрать уже записанные, иначе
			// они остались бы сиротами.
			for _, d := range f.dirs()[:i] {
				q, _ := f.path(d, id)
				destroyFile(q)
			}
			return "", err
		}
	}
	return id, nil
}

// keyIn — корень из одного каталога. Вызывающий обнуляет ключ сам.
func (f FileRoots) keyIn(dir, id string) ([]byte, error) {
	p, err := f.path(dir, id)
	if err != nil {
		return nil, err
	}
	key, err := os.ReadFile(p)
	if err != nil {
		return nil, fmt.Errorf("keyring root %s: %w", id, err)
	}
	if len(key) != kekSize {
		zeroize(key)
		return nil, fmt.Errorf("keyring root %s in %s: bad size %d", id, dir, len(key))
	}
	return key, nil
}

// Wrap заворачивает ключ файла корнем (AES-256-GCM). Копии корня в Dir и
// Mirror обязаны совпадать: завернуть испорченной копией — запереть файл
// тем, чего во второй копии нет.
func (f FileRoots) Wrap(id string, key, aad []byte) ([]byte, error) {
	var root []byte
	defer func() { zeroize(root) }()
	for _, dir := range f.dirs() {
		k, err := f.keyIn(dir, id)
		if errors.Is(err, os.ErrNotExist) {
			continue
		}
		if err != nil {
			return nil, err
		}
		if root != nil && !bytes.Equal(root, k) {
			zeroize(k)
			return nil, fmt.Errorf("keyring root %s: the copies in %s and %s differ", id, f.Dir, f.Mirror)
		}
		if root == nil {
			root = k
		} else {
			zeroize(k)
		}
	}
	if root == nil {
		return nil, fmt.Errorf("keyring root %s: %w", id, os.ErrNotExist)
	}
	a, err := newAEAD(root)
	if err != nil {
		return nil, err
	}
	return appendSealed(nil, a, key, aad), nil
}

// Unwrap разворачивает ключ файла. Копия, которая не открывает (испорчена
// или пропала), обходится второй.
func (f FileRoots) Unwrap(id string, wrapped, aad []byte) ([]byte, error) {
	var errs []error
	for _, dir := range f.dirs() {
		k, err := f.keyIn(dir, id)
		if err != nil {
			errs = append(errs, err)
			continue
		}
		a, err := newAEAD(k)
		zeroize(k)
		if err != nil {
			errs = append(errs, err)
			continue
		}
		key, _, err := openNext(a, wrapped, len(wrapped)-a.NonceSize(), aad)
		if err == nil {
			return key, nil
		}
		errs = append(errs, fmt.Errorf("keyring root %s in %s: %w", id, dir, err))
	}
	return nil, errors.Join(errs...)
}

// RepairRoots докладывает недостающие копии корней: корень, лежащий только в
// одном из каталогов (диск с Dir заменили, зеркало поднимали с нуля),
// копируется во второй. Иначе после потери roots_dir текущий корень месяцами
// жил бы в одной копии. Копии, которые есть в обоих каталогах, не трогаются.
//
// Пропавший каталог не создаётся: так выглядит и не смонтированный диск, и
// копия легла бы на тот же диск, что и первая. Каталог заводит оператор.
func (f FileRoots) RepairRoots(ids []string) error {
	if f.Mirror == "" {
		return nil
	}
	for _, dir := range f.dirs() {
		fi, err := os.Stat(dir)
		if err == nil && !fi.IsDir() {
			err = errors.New("not a directory")
		}
		if err != nil {
			return fmt.Errorf("keyring root copies: %s: %w (is the disk mounted?)", dir, err)
		}
	}
	var errs []error
	for _, id := range ids {
		var have []byte
		var missing []string
		for _, dir := range f.dirs() {
			k, err := f.keyIn(dir, id)
			switch {
			case errors.Is(err, os.ErrNotExist):
				missing = append(missing, dir)
			case err != nil:
				errs = append(errs, err)
			case have == nil:
				have = k
			default:
				zeroize(k)
			}
		}
		for _, dir := range missing {
			if have == nil {
				break
			}
			p, _ := f.path(dir, id)
			if _, err := writeFileAtomic(p, have); err != nil {
				errs = append(errs, fmt.Errorf("keyring repair root %s in %s: %w", id, dir, err))
			}
		}
		zeroize(have)
	}
	return errors.Join(errs...)
}

// DestroyRoot затирает файл нулями и удаляет — в Dir и в Mirror. Затирание —
// на совесть ФС: на SSD и в CoW-системах старые байты могут остаться.
func (f FileRoots) DestroyRoot(id string) error {
	var errs []error
	for _, dir := range f.dirs() {
		p, err := f.path(dir, id)
		if err != nil {
			return err
		}
		if err := destroyFile(p); err != nil {
			errs = append(errs, err)
		}
	}
	return errors.Join(errs...)
}

// Roots — корни, которые лежат хотя бы в одном из каталогов.
func (f FileRoots) Roots() ([]string, error) {
	seen := map[string]bool{}
	for _, dir := range f.dirs() {
		entries, err := os.ReadDir(dir)
		if err != nil {
			return nil, err
		}
		for _, e := range entries {
			id, ok := strings.CutSuffix(e.Name(), rootSuffix)
			if ok && !e.IsDir() && validRootID(id) {
				seen[id] = true
			}
		}
	}
	out := make([]string, 0, len(seen))
	for id := range seen {
		out = append(out, id)
	}
	sort.Strings(out)
	return out, nil
}

// destroyFile затирает файл корня и удаляет его. Файла нет — не ошибка.
func destroyFile(p string) error {
	fh, err := os.OpenFile(p, os.O_WRONLY, 0)
	if errors.Is(err, os.ErrNotExist) {
		return nil // уже уничтожен
	}
	if err != nil {
		return err
	}
	_, werr := fh.Write(make([]byte, kekSize))
	serr := fh.Sync()
	cerr := fh.Close()
	if err := errors.Join(werr, serr, cerr); err != nil {
		return err
	}
	if err := os.Remove(p); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	return syncDir(filepath.Dir(p))
}
