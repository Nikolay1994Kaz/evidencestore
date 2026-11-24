package mcpserver

// Третий заход проверки (R2, 24.11): как сломать исправления второго захода
// (P-363: счёт пределов идёт за ротацией файла квитанций).
// go test ./internal/mcpserver -run R2Rev8 -count=1 -v

import (
	"io"
	"os"
	"path/filepath"
	"testing"
)

const r2rev8SQL = "UPDATE accounts SET note = 'x' WHERE id = 1"

// R2-4 (первое лицо). Сервер живёт один сеанс агента, а счёт — по общему
// файлу квитанций, «чтобы не обнулялся с каждым новым сеансом». После
// ротации (logrotate create: mv) прежний файл дочитывает только сеанс,
// который уже читал файл до неё (по inode). Новый сеанс того же агента
// (новый процесс esmcp) читает только то, что по пути, — счёт до ротации для
// него пуст: минута и окно строк начинаются заново. Ротацию по размеру агент
// вызывает сам (review2_test.go, R2-9). Ожидание: счёт тот же, что без ротации.
func TestR2Rev8NewSessionAfterRotationResetsTheLimits(t *testing.T) {
	path := filepath.Join(t.TempDir(), "receipts.jsonl")
	a := serverOn(t, &fakeDB{}, path, func(c *Config) { c.ActionsPerMinute = 2 })
	for i := 0; i < 2; i++ {
		if _, err := a.execute([]string{r2rev8SQL}, ""); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := a.execute([]string{r2rev8SQL}, ""); err == nil {
		t.Fatal("the third action in a minute passed before the rotation")
	}
	if err := os.Rename(path, path+".1"); err != nil { // logrotate create
		t.Fatal(err)
	}
	b := serverOn(t, &fakeDB{}, path, func(c *Config) { c.ActionsPerMinute = 2 }) // новый сеанс агента
	passed := 0
	for i := 0; i < 5; i++ {
		if _, err := b.execute([]string{r2rev8SQL}, ""); err == nil {
			passed++
		}
	}
	t.Logf("a new session after the rotation, within the same minute: %d of 5 actions passed (limit 2 a minute, 2 already made)", passed)
	if passed > 0 {
		t.Errorf("a new session after the rotation does not see the actions made before it: %d more actions passed in the same minute", passed)
	}
}

// R2-4 (второе лицо). copytruncate: inode тот же, файл обрезан и снова
// дописан. refresh узнаёт обрезку только по размеру меньше прочитанного; если
// до следующего чтения сеанса файл дорос за его место (другие сеансы
// агента), сеанс читает с прежнего места посреди нового содержимого — начало
// нового файла (действия другого сеанса сразу после ротации) в его счёт не
// попадает никогда. Ожидание: сеанс a видит все действия агента за минуту.
func TestR2Rev8CopytruncateRegrownSkipsTheNewHead(t *testing.T) {
	path := filepath.Join(t.TempDir(), "receipts.jsonl")
	limit := func(c *Config) { c.ActionsPerMinute = 3 }
	a := serverOn(t, &fakeDB{}, path, limit)
	if _, err := a.execute([]string{r2rev8SQL}, ""); err != nil {
		t.Fatal(err)
	}
	// logrotate copytruncate: копия рядом, сам файл — в ноль.
	src, _ := os.Open(path)
	dst, _ := os.Create(path + ".1")
	io.Copy(dst, src)
	src.Close()
	dst.Close()
	if err := os.Truncate(path, 0); err != nil {
		t.Fatal(err)
	}
	// Другой сеанс того же агента сразу после ротации — два действия: файл
	// дорос за место сеанса a.
	b := serverOn(t, &fakeDB{}, path, limit)
	b.newID = func() func() string { n := 100; return func() string { n++; return "b-" + itoa(n) } }()
	for i := 0; i < 2; i++ {
		if _, err := b.execute([]string{r2rev8SQL}, ""); err != nil {
			t.Fatal(err)
		}
	}
	actions, _, _, err := a.usage(a.now(), "")
	t.Logf("session a counts %d actions in the last minute; made: 1 by a, 2 by b (limit 3)", actions)
	if err != nil || actions != 3 {
		t.Errorf("after copytruncate and regrowth session a counts %d of 3 actions of the agent in the minute (%v): the head of the new file is skipped", actions, err)
	}
	if _, err := a.execute([]string{r2rev8SQL}, ""); err == nil {
		t.Errorf("the 4th action in a minute passed with a limit of 3")
	}
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var b []byte
	for ; n > 0; n /= 10 {
		b = append([]byte{byte('0' + n%10)}, b...)
	}
	return string(b)
}
