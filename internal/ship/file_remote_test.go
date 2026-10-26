package ship

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
)

// P-14: каталог file:// не создаётся ни при открытии, ни при записи: так
// выглядит не смонтированный NFS или rclone-mount, и копия легла бы на
// локальный диск. Пропавший каталог — ошибка записи и листинга, а не пустая
// копия; появился — всё работает, подкаталоги под ним создаются.
func TestFileRemoteRootNotCreated(t *testing.T) {
	ctx := context.Background()
	root := filepath.Join(t.TempDir(), "copy")
	r, err := OpenRemote("file://" + root)
	if err != nil {
		t.Fatalf("открытие без каталога: %v", err)
	}
	if err := r.Put(ctx, "heads/1.json", []byte("{}")); err == nil {
		t.Fatal("запись без каталога прошла")
	}
	if _, err := r.List(ctx, ""); err == nil {
		t.Fatal("листинг без каталога — пустая копия вместо ошибки")
	}
	if _, err := os.Stat(root); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("каталог создан сам")
	}
	if err := os.WriteFile(root, nil, 0o600); err != nil { // на месте каталога — файл
		t.Fatal(err)
	}
	if _, err := r.List(ctx, ""); err == nil {
		t.Fatal("листинг файла на месте каталога прошёл")
	}
	if err := os.Remove(root); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(root, 0o755); err != nil { // диск смонтирован
		t.Fatal(err)
	}
	if err := r.Put(ctx, "heads/1.json", []byte("{}")); err != nil {
		t.Fatal(err)
	}
	if keys, err := r.List(ctx, ""); err != nil || len(keys) != 1 || keys[0] != "heads/1.json" {
		t.Fatalf("после монтирования: %v, %v", keys, err)
	}
}
