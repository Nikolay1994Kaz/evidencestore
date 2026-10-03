package keyring

import (
	"crypto/cipher"
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

func (f FileRoots) aead(id string) (cipher.AEAD, error) {
	var first error
	for _, dir := range f.dirs() {
		p, err := f.path(dir, id)
		if err != nil {
			return nil, err
		}
		key, err := os.ReadFile(p)
		if errors.Is(err, os.ErrNotExist) {
			if first == nil {
				first = fmt.Errorf("keyring root %s: %w", id, err)
			}
			continue
		}
		if err != nil {
			return nil, fmt.Errorf("keyring root %s: %w", id, err)
		}
		defer zeroize(key)
		if len(key) != kekSize {
			return nil, fmt.Errorf("keyring root %s: bad size %d", id, len(key))
		}
		return newAEAD(key)
	}
	return nil, first
}

// Wrap заворачивает ключ файла корнем (AES-256-GCM).
func (f FileRoots) Wrap(id string, key, aad []byte) ([]byte, error) {
	a, err := f.aead(id)
	if err != nil {
		return nil, err
	}
	return appendSealed(nil, a, key, aad), nil
}

// Unwrap разворачивает ключ файла.
func (f FileRoots) Unwrap(id string, wrapped, aad []byte) ([]byte, error) {
	a, err := f.aead(id)
	if err != nil {
		return nil, err
	}
	key, _, err := openNext(a, wrapped, len(wrapped)-a.NonceSize(), aad)
	return key, err
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
