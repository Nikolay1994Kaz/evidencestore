package ship

import (
	"context"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
)

// fileRemote — бэкенд «директория как объектный стор». Для NFS/rclone-mount и
// тестов. Put атомарен (tmp+rename) — читатель никогда не видит полуфайл.
//
// Сам каталог (root) не создаётся: так выглядит и не смонтированный диск, и
// копия легла бы на локальный незаметно (P-14). Пропавший каталог — ошибка
// Put и List, а не открытия: недоступная копия хранилищу стартовать не
// мешает. Каталог заводит оператор; подкаталоги ключей под ним — Put.
type fileRemote struct {
	root string
}

func (f *fileRemote) path(key string) string {
	return filepath.Join(f.root, filepath.FromSlash(key))
}

// checkRoot — каталог копии на месте.
func (f *fileRemote) checkRoot() error {
	fi, err := os.Stat(f.root)
	switch {
	case err != nil:
		return fmt.Errorf("ship: %w (is the disk mounted? the directory of a file:// URL is not created)", err)
	case !fi.IsDir():
		return fmt.Errorf("ship: %s is not a directory", f.root)
	}
	return nil
}

func (f *fileRemote) Put(_ context.Context, key string, data []byte) error {
	if err := f.checkRoot(); err != nil {
		return err
	}
	p := f.path(key)
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		return fmt.Errorf("ship: mkdir for %s: %w", key, err)
	}
	tmp := p + ".tmp"
	if err := os.WriteFile(tmp, data, 0o644); err != nil {
		return fmt.Errorf("ship: write %s: %w", key, err)
	}
	// fsync файла и каталога: file://-бэкенд — это и есть «удалённая» копия,
	// его durability не слабее локальной.
	if err := syncFile(tmp); err != nil {
		os.Remove(tmp)
		return fmt.Errorf("ship: sync %s: %w", key, err)
	}
	if err := os.Rename(tmp, p); err != nil {
		os.Remove(tmp)
		return fmt.Errorf("ship: rename %s: %w", key, err)
	}
	return syncDir(filepath.Dir(p))
}

func (f *fileRemote) Get(_ context.Context, key string) ([]byte, error) {
	b, err := os.ReadFile(f.path(key))
	if err != nil {
		if os.IsNotExist(err) {
			return nil, fmt.Errorf("%w: %s", ErrNotExist, key)
		}
		return nil, fmt.Errorf("ship: get %s: %w", key, err)
	}
	return b, nil
}

func (f *fileRemote) List(_ context.Context, prefix string) ([]string, error) {
	// Пропавший каталог — ошибка, а не пустая копия: пустую проход начал бы
	// писать с нуля, а подъём не нашёл бы в ней головы.
	if err := f.checkRoot(); err != nil {
		return nil, err
	}
	var keys []string
	base := f.root
	err := filepath.WalkDir(base, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			// Файл исчез во время обхода (.tmp параллельного Put уже
			// переименован) — пропускаем.
			if os.IsNotExist(err) {
				return nil
			}
			return err
		}
		if d.IsDir() || strings.HasSuffix(p, ".tmp") {
			return nil
		}
		rel, err := filepath.Rel(base, p)
		if err != nil {
			return err
		}
		key := filepath.ToSlash(rel)
		if strings.HasPrefix(key, prefix) {
			keys = append(keys, key)
		}
		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("ship: list %s: %w", prefix, err)
	}
	return keys, nil
}

func syncFile(path string) error {
	fd, err := os.Open(path)
	if err != nil {
		return err
	}
	defer fd.Close()
	return fd.Sync()
}

func syncDir(dir string) error {
	fd, err := os.Open(dir)
	if err != nil {
		return err
	}
	defer fd.Close()
	return fd.Sync()
}
