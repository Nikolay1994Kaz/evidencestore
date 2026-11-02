package store

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Nikolay1994Kaz/evidencestore/internal/config"
	"github.com/Nikolay1994Kaz/evidencestore/internal/proof"
	"github.com/Nikolay1994Kaz/evidencestore/internal/ship"
)

// P-24: держатель копии наружу не видит метаданных. Куски журнала и цепи
// зашифрованы ключом копии, головы открыты; ключом из резерва копия
// поднимается, чужим — нет, и кусок, переложенный под другое имя, не
// открывается.
func TestCopyChunksAreSealed(t *testing.T) {
	c := newClock()
	cfg, remote := replicaConfig(t)
	s := openStore(t, cfg, c)
	ctx := context.Background()
	ingest(t, s, "abs-core", 1, 3)
	mustStamp(t, s)
	ingest(t, s, "abs-core", 4, 5)
	if _, err := s.ShipOnce(ctx, remote); err != nil {
		t.Fatal(err)
	}
	keys, err := remote.List(ctx, "")
	if err != nil {
		t.Fatal(err)
	}
	files, heads, err := parseReplica(keys, "")
	if err != nil {
		t.Fatal(err)
	}
	if len(heads) == 0 || len(files) == 0 {
		t.Fatalf("в копии голов %d, файлов %d", len(heads), len(files))
	}
	for _, h := range heads {
		data, err := remote.Get(ctx, h)
		if err != nil {
			t.Fatal(err)
		}
		if c, err := proof.ParseCheckpoint(data); err != nil || proof.VerifyCheckpoint(c, s.signer.PublicKey()) != nil {
			t.Fatalf("голова %s не открыта: %v", h, err)
		}
	}
	key := copyKeyOf(t, cfg)
	var first chunk
	for name, chunks := range files {
		for _, ch := range chunks {
			sealed, err := remote.Get(ctx, ch.key)
			if err != nil {
				t.Fatal(err)
			}
			for _, secret := range []string{"abs-core", "event"} {
				if bytes.Contains(sealed, []byte(secret)) {
					t.Fatalf("кусок %s в копии несёт %q открытым текстом", ch.key, secret)
				}
			}
			plain, err := openCopy(key, ch.key, sealed)
			if err != nil || int64(len(plain)) != ch.end-ch.start {
				t.Fatalf("кусок %s файла %s: %d байт, %v", ch.key, name, len(plain), err)
			}
			if first.key == "" {
				first = ch
			}
		}
	}
	s.Close()

	// Подъём ключом из резерва — проходит; чужим ключом — нет.
	s2, err := restoreCopy(t, cfg, s, remote, c)
	if err != nil {
		t.Fatalf("подъём ключом из резерва: %v", err)
	}
	s2.Close()
	wrong := make([]byte, copyKeyLen)
	rand.Read(wrong)
	pub, _ := base64.RawStdEncoding.DecodeString(s.PublicKey())
	if _, err := RestoreReplica(ctx, remote, filepath.Join(t.TempDir(), "data"), ed25519.PublicKey(pub), wrong); !errors.Is(err, errCopyChunk) {
		t.Fatalf("подъём чужим ключом: %v", err)
	}

	// Кусок под чужим именем не открывается: имя — в дополнительных данных.
	sealed, _ := remote.Get(ctx, first.key)
	moved := filepath.Join(t.TempDir(), "moved")
	os.CopyFS(moved, os.DirFS(strings.TrimPrefix(cfg.Replica.URL, "file://")))
	movedRemote, _ := ship.OpenRemote("file://" + moved)
	other := strings.Replace(first.key, "-", "-9", 1) // другое смещение конца
	if _, err := openCopy(key, other, sealed); !errors.Is(err, errCopyChunk) {
		t.Fatalf("кусок под другим именем открылся: %v", err)
	}
	if err := movedRemote.Put(ctx, first.key, append(append([]byte(nil), sealed[:len(sealed)-1]...), sealed[len(sealed)-1]^1)); err != nil {
		t.Fatal(err)
	}
	if _, err := RestoreReplica(ctx, movedRemote, filepath.Join(t.TempDir(), "data"), ed25519.PublicKey(pub), key); !errors.Is(err, errCopyChunk) {
		t.Fatalf("подъём с испорченным куском: %v", err)
	}
}

// Пока ключ копии не подтверждён в резерве, копия не пишется: копия, чей ключ
// пропадёт вместе с data_dir, не поднимется. В резерве другой ключ — тревога,
// а на пустой цепи — отказ стартовать (как с ключом подписи).
func TestCopyKeyGatesCopy(t *testing.T) {
	c := newClock()
	cfg, remote := replicaConfig(t)
	s := openStore(t, cfg, c)
	ingest(t, s, "abs-core", 1, 2)
	mustStamp(t, s)
	s.Close()
	backup := filepath.Join(cfg.Keys.BackupDir, CopyKeyFileName)
	good, err := os.ReadFile(backup)
	if err != nil {
		t.Fatal(err)
	}
	other := bytes.Repeat([]byte{7}, copyKeyLen)
	if err := os.WriteFile(backup, other, 0o600); err != nil {
		t.Fatal(err)
	}
	s = openStore(t, cfg, c)
	if !s.Status().CopyKeyBackupPending {
		t.Fatal("другой ключ в резерве, а тревоги нет")
	}
	if _, err := s.ShipOnce(context.Background(), remote); !errors.Is(err, errCopyKeyPending) {
		t.Fatalf("копия при неподтверждённом ключе: %v", err)
	}
	if got, _ := os.ReadFile(backup); !bytes.Equal(got, other) {
		t.Fatal("другой ключ в резерве затёрт")
	}
	if err := os.WriteFile(backup, good, 0o600); err != nil {
		t.Fatal(err)
	}
	s.confirmKeys()
	if s.Status().CopyKeyBackupPending {
		t.Fatal("ключ вернули в резерв, а тревога осталась")
	}
	if _, err := s.ShipOnce(context.Background(), remote); err != nil {
		t.Fatalf("копия после подтверждения ключа: %v", err)
	}
	s.Close()

	// Пустая цепь и другой ключ в резерве — какой верный, решает человек.
	fresh, _ := replicaConfig(t)
	if err := os.WriteFile(filepath.Join(fresh.Keys.BackupDir, CopyKeyFileName), other, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Open(fresh, Options{Logger: quiet, Now: c.now, NoBackground: true}); !errors.Is(err, errCopyKeyDiffers) {
		t.Fatalf("пустая цепь, другой ключ копии в резерве: %v", err)
	}
}

// Ключ копии пропал из data_dir: с цепью и копией наружу новый не заводится —
// старый лежит в резерве или им зашифрованы куски. Без копии наружу ключ
// ничего не шифровал, и новый заводится молча.
func TestCopyKeyLost(t *testing.T) {
	c := newClock()
	cfg, _ := replicaConfig(t)
	s := openStore(t, cfg, c)
	ingest(t, s, "abs-core", 1, 2)
	mustStamp(t, s)
	s.Close()
	own := filepath.Join(cfg.DataDir, CopyKeyFileName)
	key, _ := os.ReadFile(own)
	os.Remove(own)
	open := func(cfg *config.Config) error {
		s, err := Open(cfg, Options{Logger: quiet, Now: c.now, NoBackground: true})
		if err == nil {
			s.Close()
		}
		return err
	}
	if err := open(cfg); err == nil || !strings.Contains(err.Error(), "keys.backup_dir holds the copy key") {
		t.Fatalf("ключ копии в резерве, в data_dir нет: %v", err)
	}
	os.Remove(filepath.Join(cfg.Keys.BackupDir, CopyKeyFileName))
	if err := open(cfg); err == nil || !strings.Contains(err.Error(), "replica.url is set") {
		t.Fatalf("ключа копии нет нигде, цепь и копия есть: %v", err)
	}
	if _, err := os.Stat(own); !os.IsNotExist(err) {
		t.Fatal("новый ключ копии заведён поверх цепи с копией")
	}
	noCopy := *cfg
	noCopy.Replica.URL = ""
	if err := open(&noCopy); err != nil {
		t.Fatalf("без копии наружу: %v", err)
	}
	if got, err := readCopyKey(own); err != nil || bytes.Equal(got, key) {
		t.Fatalf("новый ключ копии без копии наружу: %v", err)
	}
	// Путь из подсказки: новый ключ уже в резерве — копия наружу в новом
	// месте пишется им.
	moved := *cfg
	moved.Replica.URL = "file://" + t.TempDir()
	s2 := openStore(t, &moved, c)
	newRemote, err := ship.OpenRemote(moved.Replica.URL)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s2.ShipOnce(context.Background(), newRemote); err != nil {
		t.Fatalf("копия в новом месте с новым ключом: %v", err)
	}
}

// Копию в этом месте писала другая установка (другой ключ): хранилище её не
// дописывает и говорит почему.
func TestCopyFromAnotherInstallation(t *testing.T) {
	c := newClock()
	cfg, remote := replicaConfig(t)
	s := openStore(t, cfg, c)
	ingest(t, s, "abs-core", 1, 2)
	mustStamp(t, s)
	if _, err := s.ShipOnce(context.Background(), remote); err != nil {
		t.Fatal(err)
	}
	s.Close()
	before, _ := remote.List(context.Background(), "")

	b := testConfig(t, func(c *config.Config) {
		c.Replica.URL = cfg.Replica.URL
		c.Keys.BackupDir = t.TempDir()
	})
	sb := openStore(t, b, c)
	ingest(t, sb, "abs-core", 1, 2)
	mustStamp(t, sb)
	_, err := sb.ShipOnce(context.Background(), remote)
	if !errors.Is(err, ErrReplicaDiverged) || !strings.Contains(err.Error(), "another installation") {
		t.Fatalf("копия другой установки: %v", err)
	}
	if after, _ := remote.List(context.Background(), ""); len(after) != len(before) {
		t.Fatalf("в чужую копию дописано: было %d объектов, стало %d", len(before), len(after))
	}
}

// Подъём кладёт в data_dir ключ, которым открылась копия; другой ключ в
// поднимаемом data_dir — отказ.
func TestRestorePlacesCopyKey(t *testing.T) {
	c := newClock()
	cfg, remote := replicaConfig(t)
	s := openStore(t, cfg, c)
	ingest(t, s, "abs-core", 1, 2)
	mustStamp(t, s)
	if _, err := s.ShipOnce(context.Background(), remote); err != nil {
		t.Fatal(err)
	}
	s.Close()
	pub, _ := base64.RawStdEncoding.DecodeString(s.PublicKey())
	key := copyKeyOf(t, cfg)
	dir := filepath.Join(t.TempDir(), "data")
	if _, err := RestoreReplica(context.Background(), remote, dir, ed25519.PublicKey(pub), key); err != nil {
		t.Fatal(err)
	}
	if got, err := readCopyKey(filepath.Join(dir, CopyKeyFileName)); err != nil || !bytes.Equal(got, key) {
		t.Fatalf("ключ копии в поднятом data_dir: %v", err)
	}
	dir2 := filepath.Join(t.TempDir(), "data")
	os.MkdirAll(dir2, 0o700)
	os.WriteFile(filepath.Join(dir2, CopyKeyFileName), bytes.Repeat([]byte{9}, copyKeyLen), 0o600)
	if _, err := RestoreReplica(context.Background(), remote, dir2, ed25519.PublicKey(pub), key); err == nil || !strings.Contains(err.Error(), "another copy key") {
		t.Fatalf("подъём в data_dir с другим ключом копии: %v", err)
	}
	// Отказ — до кусков: каталог остаётся пустым, и подъём туда можно
	// повторить, вернув верный ключ.
	if entries, _ := os.ReadDir(filepath.Join(dir2, "evidence")); len(entries) > 0 {
		t.Fatalf("после отказа в data_dir лежат куски: %d", len(entries))
	}
	os.WriteFile(filepath.Join(dir2, CopyKeyFileName), key, 0o600)
	if _, err := RestoreReplica(context.Background(), remote, dir2, ed25519.PublicKey(pub), key); err != nil {
		t.Fatalf("повторный подъём с верным ключом: %v", err)
	}
	if _, err := RestoreReplica(context.Background(), remote, filepath.Join(t.TempDir(), "data"), ed25519.PublicKey(pub), key[:16]); err == nil {
		t.Fatal("подъём с ключом не той длины")
	}
}

// init при ключе копии в резерве — отказ, как при keyring.dat и sign.key.
func TestInitRefusesWithCopyKeyInBackup(t *testing.T) {
	backupDir := t.TempDir()
	os.WriteFile(filepath.Join(backupDir, CopyKeyFileName), bytes.Repeat([]byte{1}, copyKeyLen), 0o600)
	cfg := &config.Config{
		DataDir:  filepath.Join(t.TempDir(), "data"),
		RootsDir: filepath.Join(t.TempDir(), "roots"),
		TSA:      config.TSA{URL: "local"},
		Keys:     config.Keys{BackupDir: backupDir},
		Sources:  []config.Source{{Name: "abs-core", ContentType: "syslog"}},
	}
	cfg.Defaults()
	if _, err := Init(cfg); !errors.Is(err, ErrBackupExists) || !strings.Contains(err.Error(), CopyKeyFileName) {
		t.Fatalf("init при ключе копии в резерве: %v", err)
	}
}
