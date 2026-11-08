package keyring

import (
	"errors"
	"testing"
	"time"
)

// Ключ, выведенный из ключа скоупа: свой у каждого скоупа и домена, тот же после
// перезапуска, и его нет, пока ключ ждёт уничтожения и после уничтожения.
func TestDeriveKeyFollowsTheScopeKey(t *testing.T) {
	dir, roots := t.TempDir(), FileRoots{Dir: t.TempDir()}
	clock := time.Date(2026, 9, 25, 10, 0, 0, 0, time.UTC)
	opt := Options{MinWait: time.Nanosecond, Now: func() time.Time { return clock }}
	k, err := Create(dir, roots, opt)
	if err != nil {
		t.Fatal(err)
	}
	if err := k.EnsureScopes("a/2026-09", "a/2026-10"); err != nil {
		t.Fatal(err)
	}
	sep, err := k.DeriveKey("a/2026-09", "d1")
	if err != nil {
		t.Fatal(err)
	}
	oct, _ := k.DeriveKey("a/2026-10", "d1")
	other, _ := k.DeriveKey("a/2026-09", "d2")
	if sep == ([32]byte{}) || sep == oct || sep == other {
		t.Fatal("выведенный ключ не свой у скоупа и домена")
	}
	if _, err := k.DeriveKey("a/2026-11", "d1"); !errors.Is(err, ErrUnknownScope) {
		t.Fatalf("неизвестный скоуп: %v", err)
	}

	// Тот же после перезапуска: ключ скоупа лежит в keyring.dat.
	k.Close()
	if k, err = Open(dir, roots, opt); err != nil {
		t.Fatal(err)
	}
	defer k.Close()
	if err := k.Confirm(); err != nil { // как хранилище при запуске: последняя запись — в резерв
		t.Fatal(err)
	}
	if again, err := k.DeriveKey("a/2026-09", "d1"); err != nil || again != sep {
		t.Fatalf("после перезапуска другой ключ: %v", err)
	}

	// Ждёт уничтожения — не выводится; уничтожен — тоже, а соседний месяц живёт.
	if err := k.Deactivate("a/2026-09"); err != nil {
		t.Fatal(err)
	}
	approvals := []Approval{{Who: "operator"}, {Who: "security"}}
	if _, err := k.ScheduleDestroyFrom("a/2026-09", clock, time.Hour, approvals); err != nil {
		t.Fatal(err)
	}
	if _, err := k.DeriveKey("a/2026-09", "d1"); !errors.Is(err, ErrKeyPending) {
		t.Fatalf("ждёт уничтожения: %v", err)
	}
	if _, err := k.CompleteDueAt(clock.Add(2 * time.Hour)); err != nil {
		t.Fatal(err)
	}
	if _, err := k.DeriveKey("a/2026-09", "d1"); !errors.Is(err, ErrKeyDestroyed) {
		t.Fatalf("уничтожен: %v", err)
	}
	if again, err := k.DeriveKey("a/2026-10", "d1"); err != nil || again != oct {
		t.Fatalf("соседний месяц: %v", err)
	}
}

// Закрытие месяца для записи (Deactivate) ключ не меняет: на нём держатся
// пакеты за прошлые месяцы — метка, посчитанная при приёме, и метка при выдаче
// должны совпасть.
func TestDeriveKeySurvivesDeactivate(t *testing.T) {
	k, err := Create(t.TempDir(), FileRoots{Dir: t.TempDir()}, Options{MinWait: time.Nanosecond})
	if err != nil {
		t.Fatal(err)
	}
	defer k.Close()
	if err := k.EnsureScopes("a/2026-09"); err != nil {
		t.Fatal(err)
	}
	open, err := k.DeriveKey("a/2026-09", "d")
	if err != nil {
		t.Fatal(err)
	}
	if err := k.Deactivate("a/2026-09"); err != nil {
		t.Fatal(err)
	}
	closed, err := k.DeriveKey("a/2026-09", "d")
	if err != nil || closed != open {
		t.Fatalf("после Deactivate другой ключ: %v", err)
	}
}

// Ключ, который ещё не дошёл до резерва, ничего не выводит: метку из него после
// потери диска не повторить. Резерв поднялся — тот же ключ выводится.
func TestDeriveKeyWaitsForBackup(t *testing.T) {
	down := false
	backup := func(string, uint64) error {
		if down {
			return errors.New("резерв лежит")
		}
		return nil
	}
	k, err := Create(t.TempDir(), FileRoots{Dir: t.TempDir()}, Options{MinWait: time.Nanosecond, Backup: backup})
	if err != nil {
		t.Fatal(err)
	}
	defer k.Close()
	down = true
	if err := k.EnsureScopes("a/2026-09"); err == nil {
		t.Fatal("ключ заведён при лежащем резерве")
	}
	if _, err := k.DeriveKey("a/2026-09", "d"); !errors.Is(err, ErrNotBackedUp) {
		t.Fatalf("ключ не в резерве: %v", err)
	}
	down = false
	if err := k.Confirm(); err != nil {
		t.Fatal(err)
	}
	if got, err := k.DeriveKey("a/2026-09", "d"); err != nil || got == ([32]byte{}) {
		t.Fatalf("после резерва: %v", err)
	}
}
