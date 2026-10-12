package keyring

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"
)

// Находки проверки агентами 09.10 по кейрингу (docs/FINDINGS.md).

// K-05: после потери roots_dir текущий корень не живёт месяцами в одной
// копии: RepairRoots докладывает его из зеркала. Испорченная копия в Dir
// при чтении обходится зеркалом, а заворачивать при расходящихся копиях
// нельзя.
func TestRootCopiesRepairedAndChecked(t *testing.T) {
	dir := t.TempDir()
	roots := FileRoots{Dir: filepath.Join(t.TempDir(), "roots"), Mirror: t.TempDir()}
	os.MkdirAll(roots.Dir, 0o700)
	k, err := Create(dir, roots, Options{})
	if err != nil {
		t.Fatal(err)
	}
	env := seal(t, k, "a", "secret")
	id := k.rootID
	k.Close()

	os.RemoveAll(roots.Dir) // диск с roots_dir потерян
	os.MkdirAll(roots.Dir, 0o700)
	k2, err := Open(dir, roots, Options{})
	if err != nil {
		t.Fatalf("без копии в roots_dir: %v", err)
	}
	if err := k2.RepairRoots(); err != nil {
		t.Fatal(err)
	}
	k2.Close()
	main, _ := os.ReadFile(filepath.Join(roots.Dir, id+rootSuffix))
	mirror, _ := os.ReadFile(filepath.Join(roots.Mirror, id+rootSuffix))
	if len(main) != kekSize || !bytes.Equal(main, mirror) {
		t.Fatal("корень не доложен в roots_dir")
	}

	bad := bytes.Clone(main)
	bad[0] ^= 1 // копия в Dir испорчена
	os.WriteFile(filepath.Join(roots.Dir, id+rootSuffix), bad, 0o600)
	k3, err := Open(dir, roots, Options{})
	if err != nil {
		t.Fatalf("испорченная копия в Dir не обойдена зеркалом: %v", err)
	}
	defer k3.Close()
	if body, err := k3.Unseal(env); err != nil || string(body) != "secret" {
		t.Fatalf("тело: %q, %v", body, err)
	}
	if err := k3.EnsureScopes("b"); err == nil {
		t.Fatal("файл заперт при расходящихся копиях корня")
	}
}

// Пропавший каталог зеркала (диск не смонтирован) RepairRoots не создаёт:
// копия легла бы на тот же диск, что и первая. Ошибка — громко.
func TestRepairDoesNotCreateMissingDir(t *testing.T) {
	roots := FileRoots{Dir: t.TempDir(), Mirror: filepath.Join(t.TempDir(), "mirror")}
	os.MkdirAll(roots.Mirror, 0o700)
	id, err := roots.NewRoot()
	if err != nil {
		t.Fatal(err)
	}
	os.RemoveAll(roots.Mirror)
	if err := roots.RepairRoots([]string{id}); err == nil {
		t.Fatal("каталог зеркала пропал, а RepairRoots молчит")
	}
	if _, err := os.Stat(roots.Mirror); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("каталог зеркала создан заново: %v", err)
	}
}

// slowRoots — хранилище корней с медленным вводом-выводом (зеркало на
// зависшем NFS).
type slowRoots struct {
	FileRoots
	delay time.Duration
	slow  atomic.Bool
}

func (s *slowRoots) NewRoot() (string, error) {
	if s.slow.Load() {
		time.Sleep(s.delay)
	}
	return s.FileRoots.NewRoot()
}

func (s *slowRoots) DestroyRoot(id string) error {
	if s.slow.Load() {
		time.Sleep(s.delay)
	}
	return s.FileRoots.DestroyRoot(id)
}

func (s *slowRoots) Roots() ([]string, error) {
	if s.slow.Load() {
		time.Sleep(s.delay)
	}
	return s.FileRoots.Roots()
}

// K-08: медленное хранилище корней при уничтожении ключа не держит Seal:
// корни заводятся, уничтожаются и перечисляются с отпущенным общим замком,
// как копия в резерв.
func TestSlowRootsDoNotBlockSeal(t *testing.T) {
	roots := &slowRoots{FileRoots: FileRoots{Dir: t.TempDir()}, delay: 400 * time.Millisecond}
	k, err := Create(t.TempDir(), roots, Options{})
	if err != nil {
		t.Fatal(err)
	}
	defer k.Close()
	seal(t, k, "live", "x")
	seal(t, k, "old", "x")
	schedule(t, k, "old")
	roots.slow.Store(true)
	done := make(chan error, 1)
	go func() { _, err := k.CompleteDueAt(time.Now().Add(time.Hour)); done <- err }()
	time.Sleep(50 * time.Millisecond) // поворот корня начался
	start := time.Now()
	if _, err := k.Seal("live", []byte("y")); err != nil {
		t.Fatal(err)
	}
	if d := time.Since(start); d > roots.delay/2 {
		t.Fatalf("Seal ждал медленное хранилище корней %v", d)
	}
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	if info(t, k, "old").State != Destroyed {
		t.Fatal("ключ не уничтожен")
	}
}

// K-06: срок ожидания не длиннее MaxWait — дальше время не помещается в
// unix-нс, и после рестарта срок читался бы как 1681 год. Время до 1970
// года в файле — порча.
func TestWaitLimitAndTimeRange(t *testing.T) {
	k, _, _ := newRing(t, Options{})
	seal(t, k, "a", "x")
	if err := k.Deactivate("a"); err != nil {
		t.Fatal(err)
	}
	if _, err := k.ScheduleDestroy("a", 240*365*24*time.Hour, two); !errors.Is(err, ErrBadState) {
		t.Fatalf("срок 240 лет: %v", err)
	}
	d := &dec{b: []byte{0x80, 0, 0, 0, 0, 0, 0, 1}}
	if d.time(); !errors.Is(d.err, ErrCorrupt) {
		t.Fatalf("время до 1970: %v", d.err)
	}
}

// V-07: AES-GCM не связывает шифротекст с ключом. Конверт EV2 несёт
// обязательство на ключ записи под отпечатком улики: шифротекст под другим
// ключом записи (другое тело при том же конверте) не открывается, хотя тег
// GCM с этим ключом сошёлся бы.
func TestDEKCommitment(t *testing.T) {
	k, _, _ := newRing(t, Options{})
	env := seal(t, k, "a", "the real body")
	if string(env[:len(envelopeTag)]) != envelopeTag {
		t.Fatal("Seal пишет не EV2")
	}
	dek, err := k.UnwrapDEK(env)
	if err != nil {
		t.Fatal(err)
	}
	if body, err := OpenWithDEK(env, dek); err != nil || string(body) != "the real body" {
		t.Fatalf("ПАРНЫЙ КОНТРОЛЬ: %q, %v", body, err)
	}
	// Подмена: тело другим ключом записи, обязательство прежнее.
	other := bytes.Repeat([]byte{7}, dekSize)
	aead, _ := newAEAD(other)
	id, _ := KEKIDOf(env)
	forged := append([]byte(nil), env[:dekAt+12+dekSize+16]...)
	forged = appendSealed(forged, aead, []byte("another body"), id[:])
	if _, err := OpenWithDEK(forged, other); err == nil {
		t.Fatal("ключ записи, не сходящийся с обязательством, открыл тело")
	}
}

// W-12: конверт прежнего формата EV1 (без обязательства на ключ записи) не
// читается. Иначе нечестное хранилище запечатывало бы записи по-старому и
// обходило V-07: двум проверяющим — два ключа записи, два тела, оба
// «проверено». Конверт EV1 здесь — настоящий EV2 с вырезанным
// обязательством: ключ записи тот же, тело то же.
func TestLegacyEnvelopeRejected(t *testing.T) {
	k, _, _ := newRing(t, Options{})
	env := seal(t, k, "a", "the real body")
	dek, err := k.UnwrapDEK(env)
	if err != nil {
		t.Fatal(err)
	}
	head := len(envelopeTag) + kekIDSize
	legacy := append([]byte("EV1"), env[len(envelopeTag):head]...)
	legacy = append(legacy, env[head+commitSize:]...)
	if _, ok := KEKIDOf(legacy); ok {
		t.Error("конверт EV1 распознан")
	}
	if body, err := OpenWithDEK(legacy, dek); err == nil {
		t.Errorf("конверт EV1 вскрыт ключом записи: %q", body)
	}
	if body, err := k.Unseal(legacy); err == nil {
		t.Errorf("конверт EV1 вскрыт кейрингом: %q", body)
	}
}

// pausingRoots — FileRoots, у которого RepairRoots стоит, пока тест не
// отпустит: окно между чтением копий корня в Dir и в Mirror.
type pausingRoots struct {
	FileRoots
	entered, release chan struct{}
}

func (p pausingRoots) RepairRoots(ids []string) error {
	p.entered <- struct{}{}
	<-p.release
	return p.FileRoots.RepairRoots(ids)
}

// W-08: доклад копий корня и изменения кейринга не перемежаются. Иначе
// поворот корня (keys complete) проходил целиком между чтением копии в Dir
// и в Mirror, и уничтоженный корень записывался обратно в зеркало после
// квитанции destroyed-effective. Изменение (здесь — заведение скоупа: тот
// же замок wmu, что у поворота) ждёт, пока доклад не кончится.
func TestRepairRootsExcludesKeyringChanges(t *testing.T) {
	roots := pausingRoots{
		FileRoots: FileRoots{Dir: t.TempDir(), Mirror: t.TempDir()},
		entered:   make(chan struct{}), release: make(chan struct{}),
	}
	k, err := Create(t.TempDir(), roots, Options{})
	if err != nil {
		t.Fatal(err)
	}
	defer k.Close()
	repaired := make(chan error, 1)
	go func() { repaired <- k.RepairRoots() }()
	<-roots.entered
	changed := make(chan error, 1)
	go func() { changed <- k.EnsureScopes("b") }()
	select {
	case err := <-changed:
		close(roots.release)
		t.Fatalf("кейринг изменился посреди доклада копий корня (err=%v)", err)
	case <-time.After(200 * time.Millisecond):
	}
	close(roots.release)
	if err := <-repaired; err != nil {
		t.Fatal(err)
	}
	if err := <-changed; err != nil {
		t.Fatal(err)
	}
}
