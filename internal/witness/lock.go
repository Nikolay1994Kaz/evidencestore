package witness

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"golang.org/x/sys/unix"
)

// Lock берёт замок на каталог данных свидетеля (flock на dir/LOCK) и держит
// его, пока открыт файл. Два процесса над одним каталогом подписывали бы
// головы мимо общего замка: сверка размера и запись перестали бы быть
// атомарными, и состояние можно было бы откатить (tlog-witness).
func Lock(dir string) (*os.File, error) {
	f, err := os.OpenFile(filepath.Join(dir, "LOCK"), os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return nil, err
	}
	if err := unix.Flock(int(f.Fd()), unix.LOCK_EX|unix.LOCK_NB); err != nil {
		f.Close()
		if errors.Is(err, unix.EWOULDBLOCK) {
			return nil, fmt.Errorf("witness: %s is used by another eswitness process", dir)
		}
		return nil, fmt.Errorf("witness: lock %s: %w", dir, err)
	}
	return f, nil
}
