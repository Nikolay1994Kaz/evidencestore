package keyring

import (
	"crypto/cipher"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// FileRoots хранит корни файлами в отдельном каталоге, вне каталога данных
// (права 0700, каталог должен существовать). Для разработки и пилота.
//
// Чего он НЕ даёт: администратор хоста читает корни, а удалённый корень может
// пережить удаление в старых блоках SSD и в бэкапах этого каталога. Поэтому
// ни «администратор не может», ни уничтожения по NIST SP 800-88 здесь нет.
// Даёт он формат и порядок операций те же, что будут с HSM.
type FileRoots struct {
	Dir string
}

// path проверяет id: он приходит из заголовка файла, и подложенный заголовок
// не должен увести путь из каталога корней.
func (f FileRoots) path(id string) (string, error) {
	if len(id) != 32 || strings.Trim(id, "0123456789abcdef") != "" {
		return "", fmt.Errorf("keyring: bad root id %q", id)
	}
	return filepath.Join(f.Dir, id+".root"), nil
}

func (f FileRoots) NewRoot() (string, error) {
	var raw [16]byte
	rand.Read(raw[:])
	id := hex.EncodeToString(raw[:])
	p, _ := f.path(id)
	key := make([]byte, kekSize)
	defer zeroize(key)
	rand.Read(key)
	if _, err := writeFileAtomic(p, key); err != nil {
		return "", err
	}
	return id, nil
}

func (f FileRoots) aead(id string) (cipher.AEAD, error) {
	p, err := f.path(id)
	if err != nil {
		return nil, err
	}
	key, err := os.ReadFile(p)
	if err != nil {
		return nil, fmt.Errorf("keyring root %s: %w", id, err)
	}
	defer zeroize(key)
	if len(key) != kekSize {
		return nil, fmt.Errorf("keyring root %s: bad size %d", id, len(key))
	}
	return newAEAD(key)
}

func (f FileRoots) Seal(id string, plaintext, aad []byte) ([]byte, error) {
	a, err := f.aead(id)
	if err != nil {
		return nil, err
	}
	return appendSealed(nil, a, plaintext, aad), nil
}

func (f FileRoots) Open(id string, ciphertext, aad []byte) ([]byte, error) {
	a, err := f.aead(id)
	if err != nil {
		return nil, err
	}
	pt, _, err := openNext(a, ciphertext, len(ciphertext)-a.NonceSize(), aad)
	return pt, err
}

// DestroyRoot затирает файл нулями и удаляет. Затирание — на совесть ФС:
// на SSD и в CoW-системах старые байты могут остаться.
func (f FileRoots) DestroyRoot(id string) error {
	p, err := f.path(id)
	if err != nil {
		return err
	}
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
	return syncDir(f.Dir)
}
