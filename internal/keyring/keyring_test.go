package keyring

import (
	"bytes"
	"encoding/binary"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

var two = []Approval{{Who: "operator"}, {Who: "security"}}

func newRing(t *testing.T, opt Options) (k *Keyring, dir string, roots FileRoots) {
	t.Helper()
	dir, roots = t.TempDir(), FileRoots{Dir: t.TempDir()}
	k, err := Create(dir, roots, opt)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { k.Close() })
	return k, dir, roots
}

func seal(t *testing.T, k *Keyring, scope, text string) []byte {
	t.Helper()
	if _, err := k.EnsureScope(scope); err != nil {
		t.Fatal(err)
	}
	env, err := k.Seal(scope, []byte(text))
	if err != nil {
		t.Fatal(err)
	}
	return env
}

// schedule проводит скоуп до Pending без ожидания.
func schedule(t *testing.T, k *Keyring, scope string) {
	t.Helper()
	if err := k.Deactivate(scope); err != nil {
		t.Fatal(err)
	}
	if _, err := k.ScheduleDestroy(scope, 0, two); err != nil {
		t.Fatal(err)
	}
}

func info(t *testing.T, k *Keyring, scope string) KeyInfo {
	t.Helper()
	for _, ki := range k.List() {
		if ki.Scope == scope {
			return ki
		}
	}
	t.Fatalf("скоупа %q нет", scope)
	return KeyInfo{}
}

func readFile(t *testing.T, path string) []byte {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// openCopy открывает байты файла кейринга, положенные в чистый каталог:
// так выглядит восстановление из резерва.
func openCopy(t *testing.T, data []byte, roots RootStore) (*Keyring, error) {
	t.Helper()
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, FileName), data, 0o600); err != nil {
		t.Fatal(err)
	}
	return Open(dir, roots, Options{})
}

// bodyOf вскрывает файл кейринга корнем и отдаёт открытое тело.
func bodyOf(t *testing.T, data []byte, roots RootStore) []byte {
	t.Helper()
	hdr := len(fileMagic) + 2 + int(binary.BigEndian.Uint16(data[len(fileMagic):]))
	body, err := roots.Open(string(data[len(fileMagic)+2:hdr]), data[hdr:], data[:hdr])
	if err != nil {
		t.Fatal(err)
	}
	return body
}

func rootCount(t *testing.T, roots FileRoots) int {
	t.Helper()
	m, err := filepath.Glob(filepath.Join(roots.Dir, "*.root"))
	if err != nil {
		t.Fatal(err)
	}
	return len(m)
}

// backupLog — резерв для тестов: хранит каждую копию и отвечает err.
// Копия уходит и при ошибке: так выглядит потерянное подтверждение.
type backupLog struct {
	copies [][]byte
	err    error
}

func (b *backupLog) backup(path string, _ uint64) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	b.copies = append(b.copies, data)
	return b.err
}

// clock — подвижные часы для сроков ожидания.
type clock struct{ t time.Time }

func (c *clock) now() time.Time { return c.t }

func TestSealUnsealRoundTrip(t *testing.T) {
	k, _, _ := newRing(t, Options{})
	want := "user=admin action=delete table=payments"
	env := seal(t, k, "abs-core/2026-09", want)
	if bytes.Contains(env, []byte(want)) {
		t.Fatal("конверт содержит открытый текст")
	}
	if len(env) != envelopeOverhead+len(want) {
		t.Fatalf("конверт %d байт, ожидали %d+%d", len(env), envelopeOverhead, len(want))
	}
	got, err := k.Unseal(env)
	if err != nil || string(got) != want {
		t.Fatalf("unseal: %q, %v", got, err)
	}
	// Повторный EnsureScope отдаёт тот же ключ: иначе прежние конверты не открыть.
	id, _ := KEKIDOf(env)
	if again, err := k.EnsureScope("abs-core/2026-09"); err != nil || again != id {
		t.Fatalf("повторный EnsureScope: %x, %v", again, err)
	}
}

// Ключ одной записи вскрывает ровно её и ничего больше.
func TestUnwrapDEKOpensOneRecord(t *testing.T) {
	k, _, _ := newRing(t, Options{})
	envA := seal(t, k, "a", "first")
	envB := seal(t, k, "a", "second")
	dek, err := k.UnwrapDEK(envA)
	if err != nil {
		t.Fatal(err)
	}
	if got, err := OpenWithDEK(envA, dek); err != nil || string(got) != "first" {
		t.Fatalf("своя запись: %q, %v", got, err)
	}
	if _, err := OpenWithDEK(envB, dek); !errors.Is(err, ErrMalformed) {
		t.Fatalf("чужая запись тем же DEK: %v", err)
	}
	bad := bytes.Clone(envA)
	bad[len(bad)-1] ^= 1
	if _, err := OpenWithDEK(bad, dek); !errors.Is(err, ErrMalformed) {
		t.Fatalf("изменённое тело: %v", err)
	}
	if _, err := OpenWithDEK(envA[:len(envelopeTag)+kekIDSize+10], dek); !errors.Is(err, ErrMalformed) {
		t.Fatalf("обрезанный конверт: %v", err)
	}
}

// Create не затирает живой файл, Open не выдумывает пустой кейринг.
func TestCreateAndOpen(t *testing.T) {
	k, dir, roots := newRing(t, Options{})
	env := seal(t, k, "a", "secret")
	if _, err := Create(dir, roots, Options{}); !errors.Is(err, ErrExists) {
		t.Fatalf("повторный Create: %v", err)
	}
	if _, err := Open(t.TempDir(), roots, Options{}); !errors.Is(err, ErrNotFound) {
		t.Fatalf("Open без файла: %v", err)
	}
	k.Close()
	k2, err := Open(dir, roots, Options{})
	if err != nil {
		t.Fatal(err)
	}
	if got, err := k2.Unseal(env); err != nil || string(got) != "secret" {
		t.Fatalf("после переоткрытия: %q, %v", got, err)
	}
}

// Любой битый байт и любая обрезка — ErrCorrupt, а не тихая потеря части
// ключей.
func TestCorruptionIsLoud(t *testing.T) {
	k, dir, roots := newRing(t, Options{})
	if err := k.EnsureScopes("a", "b", "c"); err != nil {
		t.Fatal(err)
	}
	schedule(t, k, "b") // в файле и состояния, и подтверждения
	good := readFile(t, filepath.Join(dir, FileName))
	for i := range good {
		bad := bytes.Clone(good)
		bad[i] ^= 1
		if _, err := openCopy(t, bad, roots); !errors.Is(err, ErrCorrupt) {
			t.Fatalf("битый байт %d: %v", i, err)
		}
		if _, err := openCopy(t, good[:i], roots); !errors.Is(err, ErrCorrupt) {
			t.Fatalf("обрезка до %d байт: %v", i, err)
		}
	}
}

// Не тот каталог корней: файл не открыть, но причина видна.
func TestMissingRootIsVisible(t *testing.T) {
	_, dir, _ := newRing(t, Options{})
	_, err := Open(dir, FileRoots{Dir: t.TempDir()}, Options{})
	if !errors.Is(err, ErrCorrupt) || !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("err = %v", err)
	}
}

// Реплей различает исходы: стёрто, ждёт уничтожения, чужой ключ, повреждено.
func TestUnsealOutcomes(t *testing.T) {
	k, _, _ := newRing(t, Options{})
	env := seal(t, k, "a", "secret")
	other, _, _ := newRing(t, Options{})
	foreign := seal(t, other, "a", "secret")
	bad := bytes.Clone(env)
	bad[len(bad)-1] ^= 1

	cases := []struct {
		name string
		env  []byte
		want error
	}{
		{"чужой кейринг", foreign, ErrUnknownKey},
		{"битый тег", bad, ErrMalformed},
		{"обрезан", env[:len(env)-1], ErrMalformed},
		{"один заголовок", env[:len(envelopeTag)+kekIDSize], ErrMalformed},
		{"не конверт", []byte("plain text"), ErrMalformed},
	}
	for _, c := range cases {
		if _, err := k.Unseal(c.env); !errors.Is(err, c.want) {
			t.Errorf("%s: %v, want %v", c.name, err, c.want)
		}
	}
	schedule(t, k, "a")
	if _, err := k.Unseal(env); !errors.Is(err, ErrKeyPending) {
		t.Fatalf("в ожидании уничтожения: %v", err)
	}
	if _, err := k.CompleteDue(); err != nil {
		t.Fatal(err)
	}
	if _, err := k.Unseal(env); !errors.Is(err, ErrKeyDestroyed) {
		t.Fatalf("после уничтожения: %v", err)
	}
}

// Жизнь ключа: закрыт для записи → заявка двух людей → срок ожидания →
// отмена → повторная заявка → уничтожение. Всё переживает переоткрытие.
func TestLifecycle(t *testing.T) {
	c := &clock{t: time.Date(2026, 10, 3, 12, 0, 0, 0, time.UTC)}
	opt := Options{MinWait: 7 * 24 * time.Hour, Now: c.now}
	k, dir, roots := newRing(t, opt)
	env := seal(t, k, "abs-core/2026-09", "secret")

	if err := k.Deactivate("abs-core/2026-09"); err != nil {
		t.Fatal(err)
	}
	onDisk := func() KeyInfo {
		t.Helper()
		kd, err := Open(dir, roots, opt)
		if err != nil {
			t.Fatal(err)
		}
		defer kd.Close()
		return info(t, kd, "abs-core/2026-09")
	}
	if got := onDisk(); got.State != Deactivated {
		t.Fatalf("на диске после Deactivate: %v", got.State)
	}
	if _, err := k.Seal("abs-core/2026-09", nil); !errors.Is(err, ErrScopeClosed) {
		t.Fatalf("запись в закрытый месяц: %v", err)
	}
	if _, err := k.EnsureScope("abs-core/2026-09"); !errors.Is(err, ErrScopeClosed) {
		t.Fatalf("EnsureScope закрытого: %v", err)
	}
	if got, err := k.Unseal(env); err != nil || string(got) != "secret" {
		t.Fatalf("закрытый месяц читается: %q, %v", got, err)
	}

	if _, err := k.ScheduleDestroy("abs-core/2026-09", opt.MinWait, two[:1]); !errors.Is(err, ErrApproval) {
		t.Fatalf("одно подтверждение: %v", err)
	}
	if _, err := k.ScheduleDestroy("abs-core/2026-09", opt.MinWait, []Approval{{Who: "x"}, {Who: "x"}}); !errors.Is(err, ErrApproval) {
		t.Fatalf("один человек дважды: %v", err)
	}
	if _, err := k.ScheduleDestroy("abs-core/2026-09", time.Hour, two); !errors.Is(err, ErrBadState) {
		t.Fatalf("срок короче минимума: %v", err)
	}
	ki, err := k.ScheduleDestroy("abs-core/2026-09", opt.MinWait, two)
	if err != nil {
		t.Fatal(err)
	}
	if ki.State != Pending || !ki.DestroyAfter.Equal(c.t.Add(opt.MinWait)) || len(ki.Approvals) != 2 {
		t.Fatalf("заявка: %+v", ki)
	}
	if got := onDisk(); got.State != Pending || !got.DestroyAfter.Equal(ki.DestroyAfter) {
		t.Fatalf("на диске после заявки: %+v", got)
	}

	c.t = c.t.Add(opt.MinWait - time.Second)
	if out, err := k.CompleteDue(); err != nil || len(out) != 0 {
		t.Fatalf("до срока: %v, %v", out, err)
	}
	if _, err := k.CancelDestroy("abs-core/2026-09", nil); !errors.Is(err, ErrApproval) {
		t.Fatalf("отмена без подтверждения: %v", err)
	}
	if ki, err := k.CancelDestroy("abs-core/2026-09", two[1:]); err != nil || ki.State != Deactivated {
		t.Fatalf("отмена: %+v, %v", ki, err)
	}
	if got := onDisk(); got.State != Deactivated {
		t.Fatalf("на диске после отмены: %v", got.State)
	}
	if got, err := k.Unseal(env); err != nil || string(got) != "secret" {
		t.Fatalf("после отмены: %q, %v", got, err)
	}

	if _, err := k.ScheduleDestroy("abs-core/2026-09", opt.MinWait, two); err != nil {
		t.Fatal(err)
	}
	c.t = c.t.Add(opt.MinWait)
	out, err := k.CompleteDue()
	if err != nil {
		t.Fatal(err)
	}
	if len(out) != 1 || out[0].State != Destroyed || out[0].EffectiveAt.IsZero() || len(out[0].Approvals) != 2 {
		t.Fatalf("уничтожение: %+v", out)
	}
	if _, err := k.Unseal(env); !errors.Is(err, ErrKeyDestroyed) {
		t.Fatalf("после уничтожения: %v", err)
	}

	k.Close()
	k2, err := Open(dir, roots, opt)
	if err != nil {
		t.Fatal(err)
	}
	if got := info(t, k2, "abs-core/2026-09"); got.State != Destroyed || got.EffectiveAt.IsZero() ||
		!got.DeactivatedAt.Equal(out[0].DeactivatedAt) || got.Approvals[1] != "security" {
		t.Fatalf("после переоткрытия: %+v", got)
	}
}

// Переходы только по стрелкам.
func TestStateMachineRejects(t *testing.T) {
	k, _, _ := newRing(t, Options{})
	if err := k.EnsureScopes("a", "b"); err != nil {
		t.Fatal(err)
	}
	if _, err := k.ScheduleDestroy("a", 0, two); !errors.Is(err, ErrBadState) {
		t.Fatalf("заявка на активный: %v", err)
	}
	if _, err := k.CancelDestroy("a", two); !errors.Is(err, ErrBadState) {
		t.Fatalf("отмена без заявки: %v", err)
	}
	schedule(t, k, "b")
	if err := k.Deactivate("b"); !errors.Is(err, ErrBadState) {
		t.Fatalf("Deactivate в ожидании: %v", err)
	}
	if _, err := k.EnsureScope("b"); !errors.Is(err, ErrScopeClosed) {
		t.Fatalf("EnsureScope в ожидании: %v", err)
	}
	if err := k.Deactivate("nope"); !errors.Is(err, ErrUnknownScope) {
		t.Fatalf("неизвестный скоуп: %v", err)
	}
	if err := k.Deactivate("a", "a"); err != nil {
		t.Fatalf("повтор Deactivate: %v", err)
	}
	if err := k.Deactivate("a"); err != nil {
		t.Fatalf("Deactivate закрытого: %v", err)
	}
}

// Пределы подтверждений проверяются до записи: иначе файл записался бы, а
// потом не открылся (P7 разбора 29.09: u16 и 65536 подтверждений).
func TestApprovalLimits(t *testing.T) {
	k, dir, roots := newRing(t, Options{})
	if err := k.EnsureScopes("a"); err != nil {
		t.Fatal(err)
	}
	if err := k.Deactivate("a"); err != nil {
		t.Fatal(err)
	}
	many := make([]Approval, MaxApprovals+1)
	for i := range many {
		many[i] = Approval{Who: string(rune('a' + i))}
	}
	if _, err := k.ScheduleDestroy("a", 0, many); !errors.Is(err, ErrApproval) {
		t.Fatalf("%d подтверждений: %v", len(many), err)
	}
	long := []Approval{{Who: strings.Repeat("x", MaxApproverLen+1)}, {Who: "y"}}
	if _, err := k.ScheduleDestroy("a", 0, long); !errors.Is(err, ErrApproval) {
		t.Fatalf("длинное имя: %v", err)
	}
	edge := many[:MaxApprovals]
	edge[0].Who = strings.Repeat("x", MaxApproverLen)
	if _, err := k.ScheduleDestroy("a", 0, edge); err != nil {
		t.Fatal(err)
	}
	k.Close()
	k2, err := Open(dir, roots, Options{})
	if err != nil {
		t.Fatalf("файл с подтверждениями на пределе не открылся: %v", err)
	}
	if got := info(t, k2, "a"); len(got.Approvals) != MaxApprovals || got.Approvals[0] != edge[0].Who {
		t.Fatalf("подтверждения после переоткрытия: %d", len(got.Approvals))
	}
}

// ⭐ Главное свойство: после уничтожения ключа нет ни в файле, ни в
// резервных копиях — их корень уничтожен. Соседний скоуп жив, стёртый не
// воскресает.
func TestDestroy(t *testing.T) {
	bl := &backupLog{}
	opt := Options{Backup: bl.backup}
	k, dir, roots := newRing(t, opt)
	envA := seal(t, k, "a", "secret A")
	envB := seal(t, k, "b", "secret B")
	schedule(t, k, "a")
	withA := len(bl.copies)
	keyA := bytes.Clone(k.byName["a"].key)

	out, err := k.CompleteDue()
	if err != nil {
		t.Fatal(err)
	}
	for i, c := range bl.copies[withA:] {
		if bytes.Contains(bodyOf(t, c, roots), keyA) {
			t.Fatalf("копия %d после уничтожения содержит ключ", withA+i)
		}
	}
	if id, _ := KEKIDOf(envA); len(out) != 1 || out[0].KEKID != id || out[0].DestroyedAt.IsZero() || out[0].EffectiveAt.IsZero() {
		t.Fatalf("надгробие: %+v", out)
	}
	if _, err := k.Unseal(envA); !errors.Is(err, ErrKeyDestroyed) {
		t.Fatalf("a: %v", err)
	}
	if got, err := k.Unseal(envB); err != nil || string(got) != "secret B" {
		t.Fatalf("b: %q, %v", got, err)
	}
	if _, err := k.EnsureScope("a"); !errors.Is(err, ErrScopeDestroyed) {
		t.Fatalf("стёртый скоуп воскрес: %v", err)
	}
	if _, err := k.Seal("a", nil); !errors.Is(err, ErrScopeDestroyed) {
		t.Fatalf("Seal в стёртый скоуп: %v", err)
	}
	if got := k.Scopes(); len(got) != 1 || got[0] != "b" {
		t.Fatalf("Scopes: %v", got)
	}

	for i, c := range bl.copies[:withA] {
		if _, err := openCopy(t, c, roots); !errors.Is(err, ErrCorrupt) {
			t.Fatalf("старая копия %d открылась: %v", i, err)
		}
	}
	latest, err := openCopy(t, bl.copies[len(bl.copies)-1], roots)
	if err != nil {
		t.Fatalf("свежая копия не открылась: %v", err)
	}
	if got, err := latest.Unseal(envB); err != nil || string(got) != "secret B" {
		t.Fatalf("b из свежей копии: %q, %v", got, err)
	}
	if n := rootCount(t, roots); n != 1 {
		t.Fatalf("корней %d, ожидали 1", n)
	}

	k.Close()
	k2, err := Open(dir, roots, opt)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := k2.Unseal(envA); !errors.Is(err, ErrKeyDestroyed) {
		t.Fatalf("a после переоткрытия: %v", err)
	}
	if got := info(t, k2, "a"); got.State != Destroyed || got.EffectiveAt.IsZero() {
		t.Fatalf("надгробие после переоткрытия: %+v", got)
	}
	if out, err := k2.CompleteDue(); err != nil || len(out) != 0 {
		t.Fatalf("повторный CompleteDue: %v, %v", out, err)
	}
}

// После Close — ErrClosed, а не «стёрто».
func TestClosedKeyringReportsClosed(t *testing.T) {
	k, _, _ := newRing(t, Options{})
	env := seal(t, k, "a", "x")
	k.Close()
	errs := map[string]error{}
	_, errs["Seal"] = k.Seal("a", nil)
	_, errs["Unseal"] = k.Unseal(env)
	_, errs["UnwrapDEK"] = k.UnwrapDEK(env)
	_, errs["EnsureScope"] = k.EnsureScope("a")
	errs["Deactivate"] = k.Deactivate("a")
	_, errs["ScheduleDestroy"] = k.ScheduleDestroy("a", 0, two)
	_, errs["CancelDestroy"] = k.CancelDestroy("a", two)
	_, errs["CompleteDue"] = k.CompleteDue()
	for name, err := range errs {
		if !errors.Is(err, ErrClosed) {
			t.Errorf("%s: %v", name, err)
		}
	}
}

// Seal и Unseal держат замок всю операцию: уничтожение и Close не обнулят
// ключ посреди шифрования. Ловит только go test -race.
func TestConcurrentUseWithDestroyAndClose(t *testing.T) {
	k, _, _ := newRing(t, Options{})
	envA := seal(t, k, "a", "x")
	envB := seal(t, k, "b", "y")
	ops := []func() error{
		func() error { _, err := k.Seal("b", []byte("x")); return err },
		func() error { _, err := k.Unseal(envA); return err },
		func() error { _, err := k.Unseal(envB); return err },
	}
	var started, done sync.WaitGroup
	for _, op := range ops {
		for range 2 {
			started.Add(1)
			done.Add(1)
			go func() {
				defer done.Done()
				op()
				started.Done()
				for i := 0; i < 10000 && !errors.Is(op(), ErrClosed); i++ {
				}
			}()
		}
	}
	started.Wait() // уничтожение и Close — только когда все уже крутятся
	k.Deactivate("a")
	k.ScheduleDestroy("a", 0, two)
	k.CompleteDue()
	k.Close()
	done.Wait()
}

// Предел имени один на запись и на чтение: что записали, то и откроется.
func TestScopeNameLimits(t *testing.T) {
	k, dir, roots := newRing(t, Options{})
	for _, bad := range []string{"", strings.Repeat("x", MaxScopeLen+1)} {
		if err := k.EnsureScopes(bad); !errors.Is(err, ErrScopeName) {
			t.Fatalf("имя %d байт: %v", len(bad), err)
		}
	}
	if s := k.Scopes(); len(s) != 0 {
		t.Fatalf("негодные имена завели ключи: %v", s)
	}
	long := strings.Repeat("x", MaxScopeLen)
	if err := k.EnsureScopes(long); err != nil {
		t.Fatal(err)
	}
	k.Close()
	k2, err := Open(dir, roots, Options{})
	if err != nil {
		t.Fatal(err)
	}
	if s := k2.Scopes(); len(s) != 1 || s[0] != long {
		t.Fatalf("после переоткрытия: %d скоупов", len(s))
	}
}

// Ключ выдаётся, только когда он уже в резерве. Сбой копии не откатывает
// память: файл на диске уже новый.
func TestNewKeyWaitsForBackup(t *testing.T) {
	bl := &backupLog{}
	opt := Options{Backup: bl.backup}
	k, dir, roots := newRing(t, opt)
	bl.err = errors.New("backup down")
	for i := range 2 {
		if _, err := k.EnsureScope("a"); !errors.Is(err, bl.err) {
			t.Fatalf("попытка %d: ключ выдан без резерва: %v", i, err)
		}
	}
	// Файл с ключом a уже записан, поэтому и в памяти a есть.
	if s := k.Scopes(); len(s) != 1 {
		t.Fatalf("в памяти %v, а на диске ключ уже есть", s)
	}
	// «Упали» и поднялись, резерв всё ещё лежит: ключ по-прежнему не выдаётся.
	k.Close()
	k, err := Open(dir, roots, opt)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := k.EnsureScope("a"); !errors.Is(err, bl.err) {
		t.Fatalf("после рестарта ключ выдан без резерва: %v", err)
	}

	bl.err = nil
	id, err := k.EnsureScope("a")
	if err != nil {
		t.Fatal(err)
	}
	// Файл не знает, дошла ли до резерва его собственная копия: это узнаётся
	// только следующей записью. Она и несёт отметку «a в резерве», и после
	// рестарта a выдаётся сразу, без записи файла.
	if _, err := k.EnsureScope("b"); err != nil {
		t.Fatal(err)
	}
	k.Close()
	k2, err := Open(dir, roots, opt)
	if err != nil {
		t.Fatal(err)
	}
	before := readFile(t, filepath.Join(dir, FileName))
	if again, err := k2.EnsureScope("a"); err != nil || again != id {
		t.Fatalf("после рестарта: %x, %v", again, err)
	}
	if !bytes.Equal(before, readFile(t, filepath.Join(dir, FileName))) {
		t.Fatal("EnsureScope сохранённого ключа переписал файл")
	}
}

// ⭐ Копия в резерв не прошла при повороте корня. Память не откатывается
// (на диске уже новый файл), старый корень живёт, пока новый файл не дойдёт
// до резерва, и корня-сироты не остаётся: ключ, стёртый позже, не открывает
// ни одна копия, даже ушедшая при сбое.
func TestDestroyWaitsForBackup(t *testing.T) {
	bl := &backupLog{}
	k, dir, roots := newRing(t, Options{Backup: bl.backup})
	envA := seal(t, k, "a", "secret A")
	envB := seal(t, k, "b", "secret B")
	schedule(t, k, "a")
	lastGood := bl.copies[len(bl.copies)-1]

	bl.err = errors.New("ack lost")
	out, err := k.CompleteDue()
	if err == nil || len(out) != 1 || out[0].State != Destroyed || !out[0].EffectiveAt.IsZero() {
		t.Fatalf("уничтожение при сбое резерва: %+v, %v", out, err)
	}
	if _, err := k.Unseal(envA); !errors.Is(err, ErrKeyDestroyed) {
		t.Fatalf("a в памяти: %v", err)
	}
	onDisk, err := Open(dir, roots, Options{})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := onDisk.Unseal(envA); !errors.Is(err, ErrKeyDestroyed) {
		t.Fatalf("a на диске: %v", err)
	}
	if _, err := k.CompleteDue(); err == nil {
		t.Fatal("повтор прошёл, хотя резерв лежит")
	}
	if _, err := openCopy(t, lastGood, roots); err != nil {
		t.Fatalf("резерв стал нечитаемым раньше новой копии: %v", err)
	}

	bl.err = nil
	if out, err := k.CompleteDue(); err != nil || len(out) != 1 || out[0].EffectiveAt.IsZero() {
		t.Fatalf("повтор: %+v, %v", out, err)
	}
	schedule(t, k, "b")
	if _, err := k.CompleteDue(); err != nil {
		t.Fatal(err)
	}
	for i, c := range bl.copies {
		kc, err := openCopy(t, c, roots)
		if err != nil {
			continue // корень копии уничтожен
		}
		if _, err := kc.Unseal(envB); !errors.Is(err, ErrKeyDestroyed) && !errors.Is(err, ErrKeyPending) {
			t.Fatalf("копия %d открывает стёртый b: %v", i, err)
		}
	}
	if n := rootCount(t, roots); n != 1 {
		t.Fatalf("корней %d, ожидали 1", n)
	}
}

// flakyRoots отказывает по флагам: в Seal (сбой до замены файла) и в
// DestroyRoot.
type flakyRoots struct {
	FileRoots
	failSeal, failDestroy bool
}

func (f *flakyRoots) Seal(id string, plaintext, aad []byte) ([]byte, error) {
	if f.failSeal {
		return nil, errors.New("hsm unavailable")
	}
	return f.FileRoots.Seal(id, plaintext, aad)
}

func (f *flakyRoots) DestroyRoot(id string) error {
	if f.failDestroy {
		return errors.New("hsm unavailable")
	}
	return f.FileRoots.DestroyRoot(id)
}

func newFlakyRing(t *testing.T) (*Keyring, string, *flakyRoots) {
	t.Helper()
	dir, roots := t.TempDir(), &flakyRoots{FileRoots: FileRoots{Dir: t.TempDir()}}
	k, err := Create(dir, roots, Options{})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { k.Close() })
	return k, dir, roots
}

// Сбой до замены файла: уничтожение не состоялось ни в памяти, ни на диске,
// а корень неудачной попытки уничтожается следующей.
func TestDestroyRollsBackWhenFileNotReplaced(t *testing.T) {
	k, dir, roots := newFlakyRing(t)
	env := seal(t, k, "a", "secret")
	schedule(t, k, "a")

	roots.failSeal = true
	if _, err := k.CompleteDue(); err == nil {
		t.Fatal("уничтожение прошло при сбое корня")
	}
	roots.failSeal = false
	if got := info(t, k, "a"); got.State != Pending {
		t.Fatalf("в памяти: %v", got.State)
	}
	onDisk, err := Open(dir, roots, Options{})
	if err != nil {
		t.Fatal(err)
	}
	if got := info(t, onDisk, "a"); got.State != Pending {
		t.Fatalf("на диске: %v", got.State)
	}
	if _, err := onDisk.UnwrapDEK(env); !errors.Is(err, ErrKeyPending) {
		t.Fatalf("ключ на диске: %v", err)
	}

	if _, err := k.CompleteDue(); err != nil {
		t.Fatal(err)
	}
	if n := rootCount(t, roots.FileRoots); n != 1 {
		t.Fatalf("корней %d: корень неудачной попытки остался", n)
	}
}

// EffectiveAt ставится, только когда старый корень уничтожен на самом деле:
// до этого старая копия файла ещё открывает ключ, и квитанция не должна
// обещать иного.
func TestEffectiveOnlyAfterRootDestroyed(t *testing.T) {
	k, dir, roots := newFlakyRing(t)
	env := seal(t, k, "a", "secret")
	old := readFile(t, filepath.Join(dir, FileName))
	schedule(t, k, "a")

	roots.failDestroy = true
	out, err := k.CompleteDue()
	if err == nil || len(out) != 1 || out[0].State != Destroyed || !out[0].EffectiveAt.IsZero() {
		t.Fatalf("при сбое корня: %+v, %v", out, err)
	}
	kc, err := openCopy(t, old, roots)
	if err != nil {
		t.Fatalf("старый корень жив, а копия не открылась: %v", err)
	}
	if got, err := kc.Unseal(env); err != nil || string(got) != "secret" {
		t.Fatalf("старая копия: %q, %v", got, err)
	}

	roots.failDestroy = false
	if out, err := k.CompleteDue(); err != nil || len(out) != 1 || out[0].EffectiveAt.IsZero() {
		t.Fatalf("повтор: %+v, %v", out, err)
	}
	if _, err := openCopy(t, old, roots); !errors.Is(err, ErrCorrupt) {
		t.Fatalf("старая копия после уничтожения корня: %v", err)
	}
}
