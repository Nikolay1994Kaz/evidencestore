package store

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"github.com/Nikolay1994Kaz/evidencestore/internal/config"
)

// Ключ копии наружу (P-24). Куски журнала улик и цепи уезжают в копию
// зашифрованными: держатель копии — по совету документов другая организация
// или чужой S3 — иначе видел бы метаданные всех источников (имена, номера,
// время приёма, события). Подписанные головы остаются открытыми: по ним
// копия — след для проверки (esverify -heads), и по ним подъём выбирает
// поколение. Держатель видит размеры кусков, время их появления и головы —
// темп хранилища, но не его содержимое.
//
// Ключ — 32 случайных байта в data_dir/copy.key, не выведенный из ключа
// подписи: подпись может переехать в HSM или на ключи по эпохам. Его, как
// sign.key, заводит init; до первого куска он обязан лечь в keys.backup_dir —
// копия, чей ключ пропал вместе с data_dir, не поднимается. Другой ключ в
// резерве не затирается. Копия наружу без keys.backup_dir не настраивается
// (config).
//
// Кусок в копии: "ESC1" ‖ nonce (12 случайных байт) ‖ AES-256-GCM.
// Дополнительные данные — домен и полное имя объекта: кусок, переложенный под
// другое имя, другое смещение или в другое поколение, не открывается.

// CopyKeyFileName — ключ копии в data_dir и в keys.backup_dir.
const CopyKeyFileName = "copy.key"

const (
	copyMagic  = "ESC1"
	copyDomain = "evidencestore/copy/v1"
	copyKeyLen = 32
)

// errCopyChunk — кусок копии не открывается ключом этой установки.
var errCopyChunk = errors.New("replica: chunk does not open with this installation's copy key")

// errCopyKeyPending — ключ копии не подтверждён в keys.backup_dir: копию
// наружу не пишем, пока его нет в резерве.
var errCopyKeyPending = errors.New("replica: copy.key is not confirmed in keys.backup_dir: nothing is copied until it is, since a copy whose key is lost with data_dir cannot be restored")

// errCopyKeyDiffers — в keys.backup_dir лежит другой ключ копии.
var errCopyKeyDiffers = errors.New("store: keys.backup_dir holds another copy key")

// readCopyKey читает ключ копии из файла.
func readCopyKey(path string) ([]byte, error) {
	key, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	if len(key) != copyKeyLen {
		return nil, fmt.Errorf("store: %s is %d bytes, a copy key is %d", path, len(key), copyKeyLen)
	}
	return key, nil
}

// loadOrCreateCopyKey читает ключ копии из data_dir; нет файла — заводит
// новый. Звать после checkLostCopyKey: новый ключ заводится, только когда
// старым в копии ничего не зашифровано.
func loadOrCreateCopyKey(dataDir string) ([]byte, error) {
	path := filepath.Join(dataDir, CopyKeyFileName)
	key, err := readCopyKey(path)
	if !errors.Is(err, os.ErrNotExist) {
		return key, err
	}
	key = make([]byte, copyKeyLen)
	if _, err := rand.Read(key); err != nil {
		return nil, err
	}
	if err := writeAtomic(path, key); err != nil {
		return nil, err
	}
	return key, nil
}

// checkLostCopyKey — можно ли завести ключ копии, если его нет в data_dir.
// Ключ в резерве при пропавшем в data_dir — его и надо вернуть: новый не
// открыл бы уже отправленных кусков, и резерв бы с ним не сошёлся. С копией
// наружу и цепью ключ мог зашифровать куски — новый не заводится, пока
// человек не вернёт старый или не направит копию в новое место (как
// checkLostSigner, S-08, P-13). Без копии наружу ключ ничего не шифровал.
func checkLostCopyKey(cfg *config.Config, links uint64) error {
	path := filepath.Join(cfg.DataDir, CopyKeyFileName)
	if _, err := os.Stat(path); !errors.Is(err, os.ErrNotExist) {
		return nil
	}
	// unchecked — резерв не прочесть (диск не смонтирован): он не
	// подтверждает, что ключа в нём нет.
	var unchecked error
	if dir := cfg.Keys.BackupDir; dir != "" {
		backup := filepath.Join(dir, CopyKeyFileName)
		_, err := os.Stat(backup)
		if err == nil {
			return fmt.Errorf("store: %s is missing, while keys.backup_dir holds the copy key: copy %s there", path, backup)
		}
		if errors.Is(err, os.ErrNotExist) {
			err = needDir(dir, "keys.backup_dir")
		}
		unchecked = err
	}
	switch {
	case cfg.Replica.URL == "":
		return nil
	case links > 0:
		return fmt.Errorf("store: %s is missing while the chain holds %d links and replica.url is set: put copy.key back from keys.backup_dir, or point replica.url at a new location (chunks already in the copy open only with the old key)", path, links)
	case unchecked != nil:
		return fmt.Errorf("store: %s is missing, and the backup cannot be checked for it: %w", path, unchecked)
	}
	return nil
}

// backupCopyKey кладёт ключ копии в keys.backup_dir, если его там нет.
// Другой ключ в резерве не затирается.
func backupCopyKey(cfg *config.Config) error {
	dir := cfg.Keys.BackupDir
	if dir == "" {
		return nil
	}
	src := filepath.Join(cfg.DataDir, CopyKeyFileName)
	backup := filepath.Join(dir, CopyKeyFileName)
	have, err := os.ReadFile(backup)
	switch {
	case err == nil:
		want, err := os.ReadFile(src)
		if err != nil {
			return err
		}
		if bytes.Equal(have, want) {
			return nil
		}
		return fmt.Errorf("%w: %s differs from %s: not overwritten, check which one is right", errCopyKeyDiffers, backup, src)
	case !errors.Is(err, os.ErrNotExist):
		return err
	}
	if err := backupFile(src, dir, 0); err != nil {
		return fmt.Errorf("backup copy key: %w", err)
	}
	return nil
}

// confirmCopyKey — backupCopyKey с тревогой: пока ключ копии не подтверждён в
// резерве, copy_key_backup_pending, копия наружу не пишется, и обслуживание
// повторяет раз в минуту.
func (s *Store) confirmCopyKey() error {
	err := backupCopyKey(s.cfg)
	s.copyKeyBackupPending.Store(err != nil)
	return err
}

// sealCopy шифрует кусок копии, который ляжет под именем name.
func sealCopy(key []byte, name string, plain []byte) ([]byte, error) {
	aead, err := copyAEAD(key)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, aead.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}
	out := make([]byte, 0, len(copyMagic)+len(nonce)+len(plain)+aead.Overhead())
	out = append(append(out, copyMagic...), nonce...)
	return aead.Seal(out, nonce, plain, copyAD(name)), nil
}

// openCopy — кусок копии, взятый из-под имени name, в открытом виде.
func openCopy(key []byte, name string, sealed []byte) ([]byte, error) {
	aead, err := copyAEAD(key)
	if err != nil {
		return nil, err
	}
	head := len(copyMagic) + aead.NonceSize()
	if len(sealed) < head+aead.Overhead() || string(sealed[:len(copyMagic)]) != copyMagic {
		return nil, fmt.Errorf("%w: %s is not an encrypted chunk", errCopyChunk, name)
	}
	plain, err := aead.Open(nil, sealed[len(copyMagic):head], sealed[head:], copyAD(name))
	if err != nil {
		return nil, fmt.Errorf("%w: %s (another installation's copy, a damaged or moved object, or a wrong copy.key)", errCopyChunk, name)
	}
	return plain, nil
}

func copyAEAD(key []byte) (cipher.AEAD, error) {
	if len(key) != copyKeyLen {
		return nil, fmt.Errorf("replica: copy key is %d bytes, want %d", len(key), copyKeyLen)
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(block)
}

func copyAD(name string) []byte {
	return []byte(copyDomain + "\x00" + name)
}
