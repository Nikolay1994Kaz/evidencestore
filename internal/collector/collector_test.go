package collector

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Nikolay1994Kaz/evidencestore/internal/config"
	"github.com/Nikolay1994Kaz/evidencestore/internal/evidence"
	"github.com/Nikolay1994Kaz/evidencestore/internal/evlog"
	"github.com/Nikolay1994Kaz/evidencestore/internal/keyring"
	"github.com/Nikolay1994Kaz/evidencestore/internal/pki"
	"github.com/Nikolay1994Kaz/evidencestore/internal/proof"
	"github.com/Nikolay1994Kaz/evidencestore/internal/server"
	"github.com/Nikolay1994Kaz/evidencestore/internal/store"
)

var quiet = slog.New(slog.NewTextHandler(io.Discard, nil))

type rig struct {
	st     *store.Store
	srv    *httptest.Server
	cfg    *Config
	logDir string
}

// newRig — настоящие хранилище и сервер приёма; wrap, если задан,
// оборачивает обработчик сервера (подменить ответ).
func newRig(t *testing.T, wrap ...func(http.Handler) http.Handler) *rig {
	t.Helper()
	saved := rotateQuiet
	rotateQuiet = 0 // ротированный файл считается замолчавшим сразу; тест на тишину ставит своё
	t.Cleanup(func() { rotateQuiet = saved })
	dir := t.TempDir()
	ca, _ := pki.NewCA("ca")
	srvCert, _ := ca.Server("127.0.0.1")
	srvCert.Write(dir, "server")
	pki.WriteCert(filepath.Join(dir, "ca.crt"), ca.Cert)
	cl, _ := ca.Client("abs-core")
	cl.Write(dir, "abs-core")

	scfg := &config.Config{
		DataDir: filepath.Join(dir, "data"), RootsDir: filepath.Join(dir, "roots"),
		TLS:     config.TLS{Cert: filepath.Join(dir, "server.crt"), Key: filepath.Join(dir, "server.key"), ClientCA: filepath.Join(dir, "ca.crt")},
		TSA:     config.TSA{URL: "local"},
		Sources: []config.Source{{Name: "abs-core", ContentType: "syslog"}},
	}
	scfg.Defaults()
	if _, err := store.Init(scfg); err != nil {
		t.Fatal(err)
	}
	st, err := store.Open(scfg, store.Options{Logger: quiet, NoBackground: true})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	tlsCfg, err := server.TLSConfig(scfg)
	if err != nil {
		t.Fatal(err)
	}
	h := server.New(scfg, st, quiet).IntakeHandler()
	for _, w := range wrap {
		h = w(h)
	}
	hs := httptest.NewUnstartedServer(h)
	hs.TLS = tlsCfg
	hs.StartTLS()
	t.Cleanup(hs.Close)

	logDir := t.TempDir()
	cfg := &Config{
		Server: hs.URL, CA: filepath.Join(dir, "ca.crt"),
		Cert: filepath.Join(dir, "abs-core.crt"), Key: filepath.Join(dir, "abs-core.key"),
		StoreKey: st.PublicKey(), SpoolDir: filepath.Join(t.TempDir(), "spool"),
		File: filepath.Join(logDir, "audit.log"), FromStart: true,
	}
	if err := cfg.validate(); err != nil {
		t.Fatal(err)
	}
	return &rig{st: st, srv: hs, cfg: cfg, logDir: logDir}
}

func (r *rig) collector(t *testing.T) *Collector {
	t.Helper()
	c, err := New(r.cfg, quiet)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { c.Close() })
	if err := c.Bootstrap(context.Background()); err != nil {
		t.Fatal(err)
	}
	return c
}

func appendLines(t *testing.T, path string, lines ...string) {
	t.Helper()
	f, err := os.OpenFile(path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	for _, l := range lines {
		f.WriteString(l)
	}
}

func cycle(t *testing.T, c *Collector) {
	t.Helper()
	if _, err := c.ReadOnce(); err != nil {
		t.Fatal(err)
	}
	if err := c.SendOnce(context.Background()); err != nil {
		t.Fatal(err)
	}
}

// reinstalled — сборщик на новом spool_dir для источника, за которым
// хранилище уже закрепило прежнюю установку: отказ, пока оператор не
// примет новую (evidencestore sources bind), потом — запуск.
func (r *rig) reinstalled(t *testing.T, log *slog.Logger) *Collector {
	t.Helper()
	c, err := New(r.cfg, log)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { c.Close() })
	if err := c.Bootstrap(context.Background()); !errors.Is(err, ErrEpoch) {
		t.Fatalf("новая установка без слова оператора: %v", err)
	}
	if err := r.st.BindEpoch("abs-core", c.epoch); err != nil {
		t.Fatal(err)
	}
	if err := c.Bootstrap(context.Background()); err != nil {
		t.Fatal(err)
	}
	return c
}

// bodies — что хранилище приняло от источника, по номерам.
func (r *rig) bodies(t *testing.T) []string {
	t.Helper()
	last, _ := r.st.LastSeq("abs-core")
	var out []string
	for q := uint64(1); q <= last; q++ {
		b, err := r.st.Proof("abs-core", q, true)
		if err != nil {
			out = append(out, fmt.Sprintf("<нет %d: %v>", q, err))
			continue
		}
		sealed, _ := evidence.Unmarshal(b.Evidence)
		body, _ := keyring.OpenWithDEK(sealed.Envelope, b.DEK)
		out = append(out, string(body))
	}
	return out
}

func TestDeliveryAndPromises(t *testing.T) {
	r := newRig(t)
	c := r.collector(t)
	appendLines(t, r.cfg.File, "login admin\n", "delete table payments\n", "half a li")
	cycle(t, c)
	if got := strings.Join(r.bodies(t), "|"); got != "login admin|delete table payments" {
		t.Fatalf("доставлено: %q", got)
	}
	appendLines(t, r.cfg.File, "ne\n")
	cycle(t, c)
	if got := r.bodies(t); len(got) != 3 || got[2] != "half a line" {
		t.Fatalf("дописанная строка: %q", got)
	}
	ps, bad, err := Promises(r.cfg.SpoolDir)
	if err != nil || bad != 0 || len(ps) != 3 {
		t.Fatalf("обещания: %d, нечитаемых %d, %v", len(ps), bad, err)
	}
	pub, _ := base64.RawStdEncoding.DecodeString(r.st.PublicKey())
	for _, p := range ps {
		if err := proof.VerifyPromise(p, ed25519.PublicKey(pub)); err != nil {
			t.Fatal(err)
		}
	}
}

// Падение после записи в буфер, до отправки: после рестарта те же строки
// уходят с теми же номерами, без повторов.
func TestRestartNoDuplicates(t *testing.T) {
	r := newRig(t)
	c := r.collector(t)
	appendLines(t, r.cfg.File, "a\n", "b\n")
	cycle(t, c)
	appendLines(t, r.cfg.File, "c\n", "d\n")
	if _, err := c.ReadOnce(); err != nil { // в буфере, не отправлено
		t.Fatal(err)
	}
	c.Close()
	c2 := r.collector(t)
	if c2.Pending() != 2 {
		t.Fatalf("после рестарта в буфере %d", c2.Pending())
	}
	cycle(t, c2)
	appendLines(t, r.cfg.File, "e\n")
	cycle(t, c2)
	if got := strings.Join(r.bodies(t), ""); got != "abcde" {
		t.Fatalf("принято: %q", got)
	}
}

// Ротация файла: новый файл читается с начала.
func TestRotation(t *testing.T) {
	r := newRig(t)
	c := r.collector(t)
	appendLines(t, r.cfg.File, "1\n", "2\n")
	cycle(t, c)
	os.Rename(r.cfg.File, r.cfg.File+".1")
	appendLines(t, r.cfg.File, "3\n")
	cycle(t, c)
	if got := strings.Join(r.bodies(t), ""); got != "123" {
		t.Fatalf("после ротации: %q", got)
	}
}

// Переустановка сборщика (буфер потерян): нумерация продолжается с
// последнего принятого номера, а не с единицы.
func TestReinstallContinuesNumbering(t *testing.T) {
	r := newRig(t)
	c := r.collector(t)
	appendLines(t, r.cfg.File, "x\n", "y\n")
	cycle(t, c)
	c.Close()
	os.RemoveAll(r.cfg.SpoolDir)
	r.cfg.FromStart = false
	c2 := r.reinstalled(t, quiet)
	appendLines(t, r.cfg.File, "z\n")
	cycle(t, c2)
	if got := strings.Join(r.bodies(t), ""); got != "xyz" {
		t.Fatalf("после переустановки: %q", got)
	}
}

// Хранилище недоступно: записи ждут в буфере и уходят, когда оно вернётся.
func TestStoreDownKeepsSpool(t *testing.T) {
	r := newRig(t)
	c := r.collector(t)
	good := r.cfg.Server
	c.cfg.Server = "https://127.0.0.1:1"
	appendLines(t, r.cfg.File, "p\n", "q\n")
	c.ReadOnce()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := c.SendOnce(ctx); err == nil {
		t.Fatal("отправка в недоступное хранилище прошла")
	}
	if c.Pending() != 2 {
		t.Fatalf("в буфере %d", c.Pending())
	}
	c.cfg.Server = good
	cycle(t, c)
	if got := strings.Join(r.bodies(t), ""); got != "pq" {
		t.Fatalf("после возврата: %q", got)
	}
}

// Сборщик с закреплённым ключом не станет говорить с чужим хранилищем.
func TestPinnedStoreKey(t *testing.T) {
	r := newRig(t)
	other := newRig(t)
	r.cfg.StoreKey = other.st.PublicKey()
	c, err := New(r.cfg, quiet)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	if err := c.Bootstrap(context.Background()); err == nil {
		t.Fatal("сборщик принял хранилище с чужим ключом")
	}
}

// Ротация с недочитанным хвостом: старый файл дочитывается до конца, вместе
// с последней строкой без перевода строки.
func TestRotationDrainsOldFile(t *testing.T) {
	r := newRig(t)
	c := r.collector(t)
	appendLines(t, r.cfg.File, "1\n", "2\n")
	cycle(t, c)
	appendLines(t, r.cfg.File, "2b\n", "2c")
	os.Rename(r.cfg.File, r.cfg.File+".1")
	appendLines(t, r.cfg.File, "3\n")
	cycle(t, c)
	if got := strings.Join(r.bodies(t), ","); got != "1,2,2b,2c,3" {
		t.Fatalf("после ротации: %q", got)
	}
}

// Ротированный файл удалили раньше, чем его дочитали, и дочитать нечем:
// сборщик стоял (дескриптора нет). Потеря не тихая — в нумерации пропуск,
// который хранилище запишет в цепь. (Работающий сборщик дочитывает и
// удалённый файл — через свой дескриптор.)
func TestLostRotatedTailLeavesGap(t *testing.T) {
	r := newRig(t)
	c := r.collector(t)
	appendLines(t, r.cfg.File, "1\n")
	cycle(t, c)
	c.Close() // сборщик остановлен
	appendLines(t, r.cfg.File, "lost\n")
	os.Rename(r.cfg.File, r.cfg.File+".1")
	appendLines(t, r.cfg.File, "2\n") // новый файл создан, пока старый ещё есть: inode другой
	os.Remove(r.cfg.File + ".1")
	c = r.collector(t)
	cycle(t, c)
	if last, _ := r.st.LastSeq("abs-core"); last != 3 {
		t.Fatalf("последний номер %d, ожидали 3 (номер 2 пропущен)", last)
	}
	if _, err := r.st.Proof("abs-core", 2, false); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("номер 2: %v", err)
	}
	if got := r.bodies(t); got[2] != "2" {
		t.Fatalf("принято: %q", got)
	}
}

// Q-44: журнал исчез с непрочитанным хвостом, пока сборщик стоял, и новых
// строк нет. Пропуск номера хранилище записывает по пульсу, а не со
// следующей строкой, которой может не быть.
func TestPulseDeclaresTrailingGap(t *testing.T) {
	r := newRig(t)
	r.cfg.HeartbeatEvery = config.Duration(100 * time.Millisecond)
	c := r.collector(t)
	appendLines(t, r.cfg.File, "1\n")
	cycle(t, c)
	c.Close() // сборщик остановлен
	appendLines(t, r.cfg.File, "lost\n")
	os.Remove(r.cfg.File)
	c = r.collector(t)
	cycle(t, c)
	if last, _ := r.st.LastSeq("abs-core"); last != 1 {
		t.Fatalf("до пульса последний номер %d, ожидали 1", last)
	}
	time.Sleep(150 * time.Millisecond)
	if err := c.SendOnce(context.Background()); err != nil {
		t.Fatal(err)
	}
	if last, _ := r.st.LastSeq("abs-core"); last != 2 {
		t.Fatalf("после пульса последний номер %d, ожидали 2 (пропуск)", last)
	}
	appendLines(t, r.cfg.File, "3\n")
	cycle(t, c)
	if got := r.bodies(t); len(got) != 3 || got[0] != "1" || !strings.Contains(got[1], "нет 2") || got[2] != "3" {
		t.Fatalf("принято: %q", got)
	}
}

// Сборщик стоял, пока журнал ротировали, а ротированный файл остался рядом
// (audit.log.1): после рестарта он находится по inode и дочитывается —
// хвост не теряется, пропуска нет. (Работающий сборщик дочитывает через
// свой дескриптор, этот путь он не проходит.)
func TestRotatedFileFoundByInodeAfterRestart(t *testing.T) {
	r := newRig(t)
	c := r.collector(t)
	appendLines(t, r.cfg.File, "1\n")
	cycle(t, c)
	c.Close() // сборщик остановлен
	appendLines(t, r.cfg.File, "tail\n")
	os.Rename(r.cfg.File, r.cfg.File+".1")
	appendLines(t, r.cfg.File, "2\n")
	c = r.collector(t)
	cycle(t, c)
	if got := strings.Join(r.bodies(t), ","); got != "1,tail,2" {
		t.Fatalf("после ротации, пока сборщик стоял: %q", got)
	}
}

// Пачка ограничена и числом записей, и байтами: длинные строки не упираются
// в предел запроса хранилища.
func TestBigLinesFitRequestLimit(t *testing.T) {
	r := newRig(t)
	c := r.collector(t)
	line := strings.Repeat("x", 900<<10)
	for i := 0; i < 20; i++ {
		appendLines(t, r.cfg.File, fmt.Sprintf("%02d%s\n", i, line))
	}
	cycle(t, c)
	if last, _ := r.st.LastSeq("abs-core"); last != 20 {
		t.Fatalf("доставлено %d из 20", last)
	}
}

// pipelockShards — шарды настоящего бортового журнала Pipelock из тестовых
// данных пакета gateway, по порядку записи.
var pipelockShards = []string{"0", "8", "16", "25", "33"}

const pipelockDir = "../gateway/testdata/pipelock-v3.6.0/session1"
const pipelockSession = "proxy.run.699f05e62af002bf3614fd97248a719a"

func shardName(n string) string { return "evidence-" + pipelockSession + "-" + n + ".jsonl" }

// copyShards кладёт шарды в каталог журнала; mtime — время изменения
// каждого (по порядку), nil — у всех одно.
func copyShards(t *testing.T, dir string, shards []string, mtime func(i int) time.Time) []string {
	t.Helper()
	var lines []string
	for i, n := range shards {
		data, err := os.ReadFile(filepath.Join(pipelockDir, shardName(n)))
		if err != nil {
			t.Fatal(err)
		}
		p := filepath.Join(dir, shardName(n))
		if err := os.WriteFile(p, data, 0o600); err != nil {
			t.Fatal(err)
		}
		if err := os.Chtimes(p, mtime(i), mtime(i)); err != nil {
			t.Fatal(err)
		}
		lines = append(lines, strings.Split(strings.TrimSuffix(string(data), "\n"), "\n")...)
	}
	return lines
}

func globRig(t *testing.T) *rig {
	t.Helper()
	r := newRig(t)
	r.cfg.File, r.cfg.Glob = "", filepath.Join(r.logDir, "evidence-*.jsonl")
	if err := r.cfg.validate(); err != nil {
		t.Fatal(err)
	}
	return r
}

// ⭐ Pipelock пишет каждый шард в новый файл: сборщик по маске читает шарды
// по порядку записи, без пропусков и повторов, и после перезапуска
// продолжает с того же места.
func TestGlobFollowsPipelockShards(t *testing.T) {
	r := globRig(t)
	base := time.Now().Add(-time.Hour)
	want := copyShards(t, r.logDir, pipelockShards[:3], func(i int) time.Time { return base.Add(time.Duration(i) * time.Second) })
	c := r.collector(t)
	cycle(t, c)
	c.Close()

	// Перезапуск, потом новые шарды.
	c = r.collector(t)
	want = append(want, copyShards(t, r.logDir, pipelockShards[3:], func(i int) time.Time { return base.Add(time.Duration(10+i) * time.Second) })...)
	cycle(t, c)
	cycle(t, c)
	if got := r.bodies(t); strings.Join(got, "\n") != strings.Join(want, "\n") {
		t.Fatalf("принято %d строк, ожидали %d; первые расхождения видны в выводе:\n%v", len(got), len(want), got)
	}
}

// Время изменения у шардов одно (грубые часы ФС): порядок — по числу в
// имени, а не по строке: «-16» после «-8».
func TestGlobEqualMTimesUseNaturalOrder(t *testing.T) {
	r := globRig(t)
	same := time.Now().Add(-time.Hour)
	want := copyShards(t, r.logDir, pipelockShards, func(int) time.Time { return same })
	c := r.collector(t)
	cycle(t, c)
	if got := r.bodies(t); strings.Join(got, "\n") != strings.Join(want, "\n") {
		t.Fatalf("порядок строк нарушен: принято %d, ожидали %d", len(got), len(want))
	}
}

// Текущий файл удалили недочитанным, пока сборщик стоял: потеря видна
// пропуском номера, чтение продолжается со следующего файла. Два порядка:
// новый файл создан до удаления старого — inode у него точно другой, и
// старого под маской нет; после удаления — ФС может отдать ему inode
// старого (ext4 отдаёт), и тогда подмену видно по первой строке.
func TestGlobCurrentFileGoneLeavesGap(t *testing.T) {
	for _, createFirst := range []bool{true, false} {
		r := globRig(t)
		base := time.Now().Add(-time.Hour)
		first := filepath.Join(r.logDir, "evidence-a-0.jsonl")
		appendLines(t, first, "one\n")
		os.Chtimes(first, base, base)
		c := r.collector(t)
		cycle(t, c)
		c.Close()
		appendLines(t, first, "two\n") // не прочитана
		second := filepath.Join(r.logDir, "evidence-a-2.jsonl")
		if createFirst {
			appendLines(t, second, "three\n")
			os.Remove(first)
		} else {
			os.Remove(first)
			appendLines(t, second, "three\n")
		}
		c = r.collector(t)
		cycle(t, c)
		if got := r.bodies(t); len(got) != 3 || got[0] != "one" || !strings.HasPrefix(got[1], "<нет 2") || got[2] != "three" {
			t.Fatalf("новый файл до удаления старого: %v; принято %q", createFirst, got)
		}
	}
}

// Текущий файл под маской подменён на месте (copytruncate, файл дорос):
// пропуск номера и чтение нового содержимого с начала — как в режиме file.
// Раньше подмена принималась за «файла нет»: новое содержимое дочитывалось
// со старого смещения, а потом читалось ещё раз с начала (дубль, пропуска
// нет).
func TestGlobReplacedInPlaceIsGapNotDuplicate(t *testing.T) {
	r := globRig(t)
	f := filepath.Join(r.logDir, "evidence-a-0.jsonl")
	appendLines(t, f, "one\n", "two\n")
	c := r.collector(t)
	cycle(t, c)
	if err := os.WriteFile(f, []byte("x-first\nx-second\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	cycle(t, c)
	got := r.bodies(t)
	if len(got) != 5 || got[0] != "one" || got[1] != "two" || !strings.HasPrefix(got[2], "<нет 3") ||
		got[3] != "x-first" || got[4] != "x-second" {
		t.Fatalf("принято %q", got)
	}
}

// Файл под маской, известный реестру, но уже не тот (его inode ядро отдало
// новому файлу, первая строка другая), забывается: новый файл читается с
// начала, а не с места прежнего.
func TestGlobForgetsFileWithReusedInode(t *testing.T) {
	r := globRig(t)
	c := r.collector(t)
	p := filepath.Join(r.logDir, "evidence-b-0.jsonl")
	appendLines(t, p, "new file, first line\n")
	fi, err := os.Stat(p)
	if err != nil {
		t.Fatal(err)
	}
	ino := inode(fi)
	listing := []globFile{{path: p, ino: ino, size: fi.Size(), mtime: fi.ModTime().UnixNano()}}
	// Реестр помнит прежний файл с этим inode (закрыт за простоем): прочитан
	// до 8, первая строка другая.
	c.files[ino] = &tracked{ino: ino, off: 8, mtime: 1, head: "old file", idle: true, size: -1}
	if err := c.reconcile(listing); err != nil {
		t.Fatal(err)
	}
	if e := c.files[ino]; e == nil || e.off != 0 || e.head != "" {
		t.Fatalf("файл с чужой первой строкой читается не с начала: %+v", e)
	}
	// ПАРНЫЙ КОНТРОЛЬ: тот же файл, дописанный, — помнится.
	c.files[ino].f.Close()
	c.files[ino] = &tracked{ino: ino, off: 8, mtime: 1, head: "new file, first line", idle: true, size: -1}
	if err := c.reconcile(listing); err != nil {
		t.Fatal(err)
	}
	if e := c.files[ino]; e == nil || e.off != 8 {
		t.Fatalf("дописанный файл забыт: %+v", e)
	}
}

// Y-01…Y-05: inode удалённого файла ядро отдаёт новому. Запись реестра
// узнаёт свой файл по времени рождения, даже если первая строка та же
// (заголовок журнала): другое рождение — другой файл, читается с начала.
func TestRegistryKnowsFileByBirth(t *testing.T) {
	r := globRig(t)
	c := r.collector(t)
	p := filepath.Join(r.logDir, "evidence-b-0.jsonl")
	appendLines(t, p, "header\n", "body\n")
	fi, err := os.Stat(p)
	if err != nil {
		t.Fatal(err)
	}
	ino := inode(fi)
	f, _ := os.Open(p)
	birth := birthOf(f)
	f.Close()
	if birth == 0 {
		t.Skip("файловая система не знает времени рождения")
	}
	listing := []globFile{{path: p, ino: ino, size: fi.Size(), mtime: fi.ModTime().UnixNano()}}
	// Реестр помнит другой файл с этим inode и той же первой строкой.
	c.files[ino] = &tracked{ino: ino, off: 7, mtime: 1, head: "header", birth: birth + 1, idle: true, size: -1}
	if err := c.reconcile(listing); err != nil {
		t.Fatal(err)
	}
	if e := c.files[ino]; e == nil || e.off != 0 || e.birth != birth {
		t.Fatalf("чужой файл с тем же inode и первой строкой не узнан: %+v", e)
	}
	// ПАРНЫЙ КОНТРОЛЬ: то же рождение — тот же файл.
	c.files[ino].f.Close()
	c.files[ino] = &tracked{ino: ino, off: 7, mtime: 1, head: "header", birth: birth, idle: true, size: -1}
	if err := c.reconcile(listing); err != nil {
		t.Fatal(err)
	}
	if e := c.files[ino]; e == nil || e.off != 7 {
		t.Fatalf("свой файл забыт: %+v", e)
	}
}

// Файл, открытый по inode записи реестра (после рестарта сборщика он ищется
// по inode), — тот же, только если совпало время рождения: другое рождение
// при той же первой строке — чужой файл, которому достался inode. Раньше это
// ловила только симуляция — когда диск переиспользовал номера inode.
func TestSameFileByBirth(t *testing.T) {
	p := filepath.Join(t.TempDir(), "a.log")
	if err := os.WriteFile(p, []byte("header\nbody\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	f, err := os.Open(p)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	birth := birthOf(f)
	if birth == 0 {
		t.Skip("файловая система не знает времени рождения")
	}
	if !sameFile(&tracked{off: 7, head: "header", birth: birth}, f) {
		t.Fatal("свой файл не узнан")
	}
	if sameFile(&tracked{off: 7, head: "header", birth: birth + 1}, f) {
		t.Fatal("чужой файл с той же первой строкой и другим рождением узнан своим")
	}
}

// Q-56: время приёма в обещании — слово хранилища, и сдвиг его вперёд
// выдаёт сборщик: позже ответа хранилища больше чем на receiveAhead — ошибка
// в журнал и обещание в promises-ahead.jsonl. Запись доставлена: у хранилища
// она есть, повтор вернул бы то же обещание.
func TestPromiseReceiveTimeAhead(t *testing.T) {
	certs := simCerts(t)
	fs := newFakeStore(certs.storeSK)
	logDir := t.TempDir()
	cfg := &Config{
		Server: "https://store.invalid", CA: filepath.Join(certs.dir, "ca.crt"),
		Cert: filepath.Join(certs.dir, "abs-core.crt"), Key: filepath.Join(certs.dir, "abs-core.key"),
		StoreKey: fs.pub, SpoolDir: filepath.Join(t.TempDir(), "spool"),
		File: filepath.Join(logDir, "audit.log"), FromStart: true,
	}
	if err := cfg.validate(); err != nil {
		t.Fatal(err)
	}
	c, err := New(cfg, quiet)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	fs.attach(c)
	if err := c.Bootstrap(context.Background()); err != nil {
		t.Fatal(err)
	}
	ahead := filepath.Join(cfg.SpoolDir, aheadFile)
	fs.recvAt = time.Now().Add(receiveAhead / 2).UnixNano() // расхождение часов
	appendLines(t, cfg.File, "1\n")
	cycle(t, c)
	if _, err := os.Stat(ahead); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("время приёма в пределах допуска сочтено сдвигом: %v", err)
	}
	fs.recvAt = time.Now().Add(10 * time.Minute).UnixNano()
	appendLines(t, cfg.File, "2\n")
	cycle(t, c)
	data, err := os.ReadFile(ahead)
	if err != nil || strings.Count(string(data), "\n") != 1 || !strings.Contains(string(data), `"seq":2,`) {
		t.Fatalf("обещание со временем приёма на 10 минут позже ответа: %q, %v", data, err)
	}
	if c.Pending() != 0 || c.Acked() != 2 {
		t.Fatalf("запись не доставлена: в буфере %d, подтверждено до %d", c.Pending(), c.Acked())
	}
}

// Q-57: срок обещания — тоже слово хранилища. Срок дальше
// proof.MaxPromiseMMD от времени приёма пропускает запись, придержанную за
// метку, что закрывает окно: ошибка в журнал и обещание в
// promises-deadline.jsonl, запись доставлена. Срок ровно MaxPromiseMMD —
// честный.
func TestPromiseLongDeadline(t *testing.T) {
	certs := simCerts(t)
	fs := newFakeStore(certs.storeSK)
	logDir := t.TempDir()
	cfg := &Config{
		Server: "https://store.invalid", CA: filepath.Join(certs.dir, "ca.crt"),
		Cert: filepath.Join(certs.dir, "abs-core.crt"), Key: filepath.Join(certs.dir, "abs-core.key"),
		StoreKey: fs.pub, SpoolDir: filepath.Join(t.TempDir(), "spool"),
		File: filepath.Join(logDir, "audit.log"), FromStart: true,
	}
	if err := cfg.validate(); err != nil {
		t.Fatal(err)
	}
	c, err := New(cfg, quiet)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	fs.attach(c)
	if err := c.Bootstrap(context.Background()); err != nil {
		t.Fatal(err)
	}
	late := filepath.Join(cfg.SpoolDir, deadlineFile)
	fs.recvAt, fs.mmd = time.Now().UnixNano(), int64(proof.MaxPromiseMMD)
	appendLines(t, cfg.File, "1\n")
	cycle(t, c)
	if _, err := os.Stat(late); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("срок ровно MaxPromiseMMD сочтён слишком длинным: %v", err)
	}
	fs.recvAt, fs.mmd = time.Now().UnixNano(), int64(proof.MaxPromiseMMD+time.Second)
	appendLines(t, cfg.File, "2\n")
	cycle(t, c)
	data, err := os.ReadFile(late)
	if err != nil || strings.Count(string(data), "\n") != 1 || !strings.Contains(string(data), `"seq":2,`) {
		t.Fatalf("обещание со сроком на секунду дальше предела: %q, %v", data, err)
	}
	if _, err := os.Stat(filepath.Join(cfg.SpoolDir, aheadFile)); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("длинный срок сочтён сдвигом времени приёма: %v", err)
	}
	if c.Pending() != 0 || c.Acked() != 2 {
		t.Fatalf("запись не доставлена: в буфере %d, подтверждено до %d", c.Pending(), c.Acked())
	}
}

// Z-04: то же, когда файл не открыть (права): рождение сверяется по пути,
// без открытия. Раньше «не открыть» значило «тот же файл»: чужой файл жил в
// реестре под чужим местом, а ротированный — «пропадал» с пропуском, и его
// строки терялись (симуляция с правами).
func TestRegistryKnowsUnreadableFileByBirth(t *testing.T) {
	r := globRig(t)
	c := r.collector(t)
	p := filepath.Join(r.logDir, "evidence-b-0.jsonl")
	appendLines(t, p, "header\n", "body\n")
	fi, err := os.Stat(p)
	if err != nil {
		t.Fatal(err)
	}
	ino := inode(fi)
	birth := birthAt(p, ino)
	if birth == 0 {
		t.Skip("файловая система не знает времени рождения")
	}
	os.Chmod(p, 0o200)
	listing := []globFile{{path: p, ino: ino, size: fi.Size(), mtime: fi.ModTime().UnixNano()}}
	c.files[ino] = &tracked{ino: ino, off: 7, mtime: 1, head: "header", birth: birth + 1, idle: true, size: -1}
	if err := c.reconcile(listing); err != nil {
		t.Fatal(err)
	}
	if e := c.files[ino]; e == nil || e.off != 0 || e.birth != birth || e.f != nil {
		t.Fatalf("чужой файл, которого не открыть, не узнан: %+v", e)
	}
}

func TestNaturalLess(t *testing.T) {
	for _, tc := range []struct {
		a, b string
		less bool
	}{
		{"e-8.jsonl", "e-16.jsonl", true},
		{"e-16.jsonl", "e-8.jsonl", false},
		{"e-08", "e-8", true}, // числа равны: порядок по записи, но устойчивый
		{"a", "b", true},
		{"e-2", "e-2.x", true},
	} {
		if got := naturalLess(tc.a, tc.b); got != tc.less {
			t.Errorf("%s < %s = %v", tc.a, tc.b, got)
		}
	}
}

func TestGlobConfig(t *testing.T) {
	base := Config{Server: "https://x", CA: "ca", Cert: "c", Key: "k", SpoolDir: "s", StoreKey: anyKey}
	both, none, bad, dirs := base, base, base, base
	both.File, both.Glob = "/a.log", "/b/*.log"
	bad.Glob = "/b/[*.log"
	dirs.Glob = "/var/log/*/audit.log" // каталог маски — один, без подстановок
	for name, c := range map[string]Config{"file и glob": both, "ни того ни другого": none, "кривая маска": bad, "подстановка в каталоге": dirs} {
		if err := c.validate(); err == nil {
			t.Errorf("%s: принято", name)
		}
	}
}

// anyKey — годный по форме ключ хранилища для проверок настроек.
var anyKey = base64.RawStdEncoding.EncodeToString(make([]byte, ed25519.PublicKeySize))

// Опасные значения настроек — ошибка при загрузке, а не тихая замена или
// беда потом: пачку больше 512 хранилище отвергнет навсегда, http://
// уводит тела открытым текстом, отрицательная пауза крутит цикл без сна,
// кривой адрес ронял сборщик паникой, без закреплённого ключа подмену
// хранилища не видно.
func TestConfigRejectsDangerousValues(t *testing.T) {
	if maxBatch != store.MaxBatch || codeSeqConflict != server.CodeSeqConflict {
		t.Fatal("сборщик и хранилище разошлись в протоколе")
	}
	good := func() Config {
		return Config{Server: "https://store:8443/", CA: "ca", Cert: "c", Key: "k", StoreKey: anyKey, SpoolDir: "s", File: "/a.log"}
	}
	c := good()
	if err := c.validate(); err != nil {
		t.Fatal(err)
	}
	if c.Batch != defaultBatch || c.FlushEvery.D() != time.Second || c.HeartbeatEvery.D() != 30*time.Second || c.Server != "https://store:8443" {
		t.Fatalf("умолчания: %+v", c)
	}
	for name, spoil := range map[string]func(*Config){
		"batch 1000":             func(c *Config) { c.Batch = 1000 },
		"batch -5":               func(c *Config) { c.Batch = -5 },
		"flush_every -1s":        func(c *Config) { c.FlushEvery = config.Duration(-time.Second) },
		"heartbeat_every -1s":    func(c *Config) { c.HeartbeatEvery = config.Duration(-time.Second) },
		"http://":                func(c *Config) { c.Server = "http://store:8443" },
		"кривой порт":            func(c *Config) { c.Server = "https://127.0.0.1:abc" },
		"без хоста":              func(c *Config) { c.Server = "https://" },
		"без store_key":          func(c *Config) { c.StoreKey = "" },
		"store_key не ключ":      func(c *Config) { c.StoreKey = "PIN-THE-STORE-PUBLIC-KEY" },
		"store_key не той длины": func(c *Config) { c.StoreKey = base64.RawStdEncoding.EncodeToString(make([]byte, 31)) },
	} {
		c := good()
		spoil(&c)
		if err := c.validate(); err == nil {
			t.Errorf("%s: принято", name)
		}
	}
}

// Кривой адрес, минуя проверку настроек, — ошибка, а не паника.
func TestBadServerAddressIsAnError(t *testing.T) {
	r := newRig(t)
	good := r.cfg.Server
	r.cfg.Server = "https://127.0.0.1:abc"
	c, err := New(r.cfg, quiet)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	if err := c.Bootstrap(context.Background()); err == nil {
		t.Fatal("первый запуск с кривым адресом прошёл")
	}
	r.cfg.Server = good
	if err := c.Bootstrap(context.Background()); err != nil {
		t.Fatal(err)
	}
	appendLines(t, r.cfg.File, "a\n")
	if _, err := c.ReadOnce(); err != nil {
		t.Fatal(err)
	}
	r.cfg.Server = "https://127.0.0.1:abc"
	if err := c.SendOnce(context.Background()); err == nil || c.Pending() != 1 {
		t.Fatalf("отправка с кривым адресом: %v, в буфере %d", err, c.Pending())
	}
}

// ⭐ Первый запуск без from_start помнит, с какого места читать: после
// перезапуска без новых строк журнал не перечитывается с начала (раньше
// стартовое место жило только в памяти — дубли всех улик).
func TestBootstrapPositionSurvivesRestart(t *testing.T) {
	r := newRig(t)
	c := r.collector(t)
	appendLines(t, r.cfg.File, "x\n", "y\n")
	cycle(t, c)
	c.Close()
	os.RemoveAll(r.cfg.SpoolDir) // переустановка
	r.cfg.FromStart = false
	r.reinstalled(t, quiet).Close() // запуск; новых строк нет
	c = r.collector(t)              // перезапуск
	appendLines(t, r.cfg.File, "z\n")
	cycle(t, c)
	if got := strings.Join(r.bodies(t), ""); got != "xyz" {
		t.Fatalf("принято: %q", got)
	}
}

// ⭐ Строки, дописанные, пока сборщик стоял после первого запуска (ещё
// ничего не прочитав), не теряются молча (раньше место чтения снова ставилось
// в конец файла).
func TestLinesWrittenWhileDownAfterFirstStart(t *testing.T) {
	r := newRig(t)
	r.cfg.FromStart = false
	appendLines(t, r.cfg.File, "before\n")
	r.collector(t).Close()
	appendLines(t, r.cfg.File, "during-downtime\n")
	c := r.collector(t)
	appendLines(t, r.cfg.File, "after\n")
	cycle(t, c)
	if got := strings.Join(r.bodies(t), ","); got != "during-downtime,after" {
		t.Fatalf("принято: %q", got)
	}
}

// Буфер потерян, а состояние осталось: место чтения неизвестно, и сборщик
// не гадает (раньше читал журнал с начала под новыми номерами).
func TestLostSpoolRefusesToGuess(t *testing.T) {
	r := newRig(t)
	c := r.collector(t)
	appendLines(t, r.cfg.File, "a\n")
	cycle(t, c)
	c.Close()
	os.RemoveAll(filepath.Join(r.cfg.SpoolDir, "spool"))
	if c, err := New(r.cfg, quiet); err == nil || !strings.Contains(err.Error(), "spool was lost") {
		if c != nil {
			c.Close()
		}
		t.Fatalf("запуск без буфера: %v", err)
	}
}

// spoolSegments — файлы сегментов буфера.
func spoolSegments(t *testing.T, spoolDir string) []string {
	t.Helper()
	segs, err := filepath.Glob(filepath.Join(spoolDir, "spool", "seg_*.log"))
	if err != nil {
		t.Fatal(err)
	}
	return segs
}

// Длинная строка режется на куски. Оборвался хвост буфера посреди кусков —
// после рестарта строка дочитывается с места обрыва, а не целиком под
// новыми номерами (раньше у промежуточного куска позицией было начало
// строки).
func TestTornLongLineResumesAtChunk(t *testing.T) {
	r := newRig(t)
	c := r.collector(t)
	m := evidence.MaxBodyLen
	appendLines(t, r.cfg.File, strings.Repeat("a", m)+strings.Repeat("b", m)+"c\n")
	if n, err := c.ReadOnce(); err != nil || n != 3 {
		t.Fatalf("прочитано %d, %v", n, err)
	}
	c.Close()
	segs := spoolSegments(t, r.cfg.SpoolDir)
	last := segs[len(segs)-1]
	frames := spoolFrames(t, last)
	cut := frames[len(frames)-1]
	for i := len(frames) - 1; i >= 0 && frames[i].kind != kindLine; i-- {
		cut = frames[i-1] // последний кусок строки — за ним только метки места
	}
	if err := os.Truncate(last, cut.off+2); err != nil { // последний кусок оборван
		t.Fatal(err)
	}
	c = r.collector(t)
	if c.Pending() != 2 {
		t.Fatalf("в буфере %d кусков", c.Pending())
	}
	cycle(t, c)
	got := r.bodies(t)
	want := []string{strings.Repeat("a", m), strings.Repeat("b", m), "c"}
	if len(got) != len(want) {
		t.Fatalf("принято %d записей, ожидали %d", len(got), len(want))
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("запись %d: %d байт %.10q…", i+1, len(got[i]), got[i])
		}
	}
}

// Падение посреди записи обещания: обрывок строки отрезается при запуске, и
// следующее обещание к нему не приклеивается; нечитаемая строка не прячет
// остальные обещания.
func TestTornPromiseLine(t *testing.T) {
	r := newRig(t)
	c := r.collector(t)
	appendLines(t, r.cfg.File, "a\n")
	cycle(t, c)
	c.Close()
	path := filepath.Join(r.cfg.SpoolDir, "promises.jsonl")
	appendLines(t, path, `{"source":"abs-core","se`)
	c = r.collector(t)
	appendLines(t, r.cfg.File, "b\n")
	cycle(t, c)
	ps, bad, err := Promises(r.cfg.SpoolDir)
	if err != nil || bad != 0 || len(ps) != 2 {
		t.Fatalf("обещания после обрыва: %d, нечитаемых %d, %v", len(ps), bad, err)
	}
	data, _ := os.ReadFile(path)
	os.WriteFile(path, append([]byte("garbage\n"), data...), 0o600)
	if ps, bad, err = Promises(r.cfg.SpoolDir); err != nil || bad != 1 || len(ps) != 2 {
		t.Fatalf("обещания со строкой мусора: %d, нечитаемых %d, %v", len(ps), bad, err)
	}
}

// ⭐ Машину сборщика откатили из снимка: буфер и журнал вернулись в прошлое,
// хранилище — нет. Сборщик не выдаёт занятые номера (раньше хранилище
// отвечало «duplicate», и новые строки пропадали молча), а останавливается.
func TestRolledBackSpoolStops(t *testing.T) {
	r := newRig(t)
	c := r.collector(t)
	appendLines(t, r.cfg.File, "a\n")
	cycle(t, c)
	c.Close()
	snap := filepath.Join(t.TempDir(), "snap")
	if err := os.CopyFS(snap, os.DirFS(r.cfg.SpoolDir)); err != nil {
		t.Fatal(err)
	}
	snapLog, _ := os.ReadFile(r.cfg.File)

	c = r.collector(t)
	appendLines(t, r.cfg.File, "b\n", "c\n")
	cycle(t, c)
	c.Close()

	os.RemoveAll(r.cfg.SpoolDir) // откат
	if err := os.CopyFS(r.cfg.SpoolDir, os.DirFS(snap)); err != nil {
		t.Fatal(err)
	}
	os.WriteFile(r.cfg.File, snapLog, 0o600)
	appendLines(t, r.cfg.File, "X\n", "Y\n")
	c, err := New(r.cfg, quiet)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	if err := c.Bootstrap(context.Background()); !errors.Is(err, ErrStoreAhead) {
		t.Fatalf("откат не замечен: %v", err)
	}
	if got := strings.Join(r.bodies(t), ""); got != "abc" {
		t.Fatalf("у хранилища: %q", got)
	}
}

// ⭐ B-03: второй сборщик с тем же сертификатом (скопированный конфиг, свой
// spool_dir) — другая установка, другая эпоха. Хранилище отказывает ему при
// запуске, раньше, чем он прочтёт строку, кто бы ни отправил первым; первый
// работает дальше (раньше вставал тот, кто отправил позже, — и законный
// тоже). Если второй — законная замена, его принимает оператор, и отказ
// получает прежний.
func TestSecondCollectorWithSameCertificateStops(t *testing.T) {
	r := newRig(t)
	a := r.collector(t)
	cfgB := *r.cfg
	cfgB.SpoolDir = filepath.Join(t.TempDir(), "spool-b")
	cfgB.File = filepath.Join(r.logDir, "other.log")
	b, err := New(&cfgB, quiet)
	if err != nil {
		t.Fatal(err)
	}
	defer b.Close()
	ctx := context.Background()
	err = b.Bootstrap(ctx)
	if !errors.Is(err, ErrEpoch) || !strings.Contains(err.Error(), "sources bind -source abs-core -epoch "+b.epoch) {
		t.Fatalf("второй сборщик: %v", err)
	}
	appendLines(t, r.cfg.File, "from-a\n")
	cycle(t, a)
	if got := strings.Join(r.bodies(t), "|"); got != "from-a" {
		t.Fatalf("у хранилища: %q", got)
	}
	// Оператор принимает второго как замену: отказ теперь у первого.
	if err := r.st.BindEpoch("abs-core", b.epoch); err != nil {
		t.Fatal(err)
	}
	if err := b.Bootstrap(ctx); err != nil {
		t.Fatalf("принятая установка: %v", err)
	}
	appendLines(t, r.cfg.File, "from-a-late\n")
	if _, err := a.ReadOnce(); err != nil {
		t.Fatal(err)
	}
	if err := a.SendOnce(ctx); !errors.Is(err, ErrEpoch) {
		t.Fatalf("прежняя установка после замены: %v", err)
	}
	a.Close()
	a2, err := New(r.cfg, quiet) // прежняя установка перезапущена
	if err != nil {
		t.Fatal(err)
	}
	defer a2.Close()
	if err := a2.Bootstrap(ctx); !errors.Is(err, ErrEpoch) {
		t.Fatalf("прежняя установка при перезапуске: %v", err)
	}
	appendLines(t, cfgB.File, "from-b\n")
	cycle(t, b)
	if got := strings.Join(r.bodies(t), "|"); got != "from-a|from-b" {
		t.Fatalf("у хранилища: %q", got)
	}
}

// Эпоха живёт в spool_dir и переживает перезапуск. Потерян epoch.json —
// это новая установка: новая эпоха и отказ хранилища, пока её не примет
// оператор (как после потери всего spool_dir).
func TestLostEpochFileIsNewInstallation(t *testing.T) {
	r := newRig(t)
	c := r.collector(t)
	appendLines(t, r.cfg.File, "a\n")
	cycle(t, c)
	first := c.epoch
	c.Close()
	c = r.collector(t) // перезапуск: та же эпоха, хранилище принимает
	if c.epoch != first {
		t.Fatalf("эпоха сменилась при перезапуске: %s → %s", first, c.epoch)
	}
	c.Close()
	if err := os.Remove(filepath.Join(r.cfg.SpoolDir, "epoch.json")); err != nil {
		t.Fatal(err)
	}
	c = r.reinstalled(t, quiet)
	if c.epoch == first {
		t.Fatal("без epoch.json эпоха прежняя")
	}
	appendLines(t, r.cfg.File, "b\n")
	cycle(t, c)
	if got := strings.Join(r.bodies(t), ","); got != "a,b" {
		t.Fatalf("принято %q", got)
	}
}

// Оператор принял другую установку, пока эта работает: на следующей
// отправке хранилище ей отказывает, и Run останавливается, а не повторяет
// вечно.
func TestRunStopsWhenRebound(t *testing.T) {
	r := newRig(t)
	c, err := New(r.cfg, quiet)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	done := make(chan error, 1)
	appendLines(t, r.cfg.File, "a\n")
	go func() { done <- c.Run(ctx) }()
	stopped := false
	defer func() {
		cancel()
		if !stopped {
			<-done
		}
		c.Close()
	}()
	for deadline := time.Now().Add(10 * time.Second); ; time.Sleep(20 * time.Millisecond) {
		if last, _ := r.st.LastSeq("abs-core"); last == 1 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("строка не доставлена")
		}
	}
	if err := r.st.BindEpoch("abs-core", strings.Repeat("b", 32)); err != nil {
		t.Fatal(err)
	}
	appendLines(t, r.cfg.File, "b\n")
	select {
	case err := <-done:
		stopped = true
		if !errors.Is(err, ErrEpoch) {
			t.Fatalf("Run: %v", err)
		}
	case <-ctx.Done():
		t.Fatal("Run не остановился после отказа")
	}
}

// P-05: сборщику нечего слать — раз в heartbeat_every он делает пульс
// (GET /v1/state), и хранилище видит, что он на связи. Пока идут пачки,
// пульса нет: на связи держат сами пачки.
func TestPulseWhenIdle(t *testing.T) {
	var states atomic.Int64
	r := newRig(t, func(h http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
			if req.URL.Path == "/v1/state" {
				states.Add(1)
			}
			h.ServeHTTP(w, req)
		})
	})
	r.cfg.HeartbeatEvery = config.Duration(100 * time.Millisecond)
	c := r.collector(t) // запуск: первый state
	contact := func() time.Time {
		for _, src := range r.st.Status().Sources {
			if src.Name == "abs-core" {
				return src.LastContact
			}
		}
		return time.Time{}
	}
	ctx := context.Background()
	started := contact()
	if err := c.SendOnce(ctx); err != nil || states.Load() != 1 {
		t.Fatalf("пульс сразу после ответа хранилища: %v, state %d", err, states.Load())
	}
	time.Sleep(150 * time.Millisecond)
	if err := c.SendOnce(ctx); err != nil || states.Load() != 2 {
		t.Fatalf("нет пульса в простое: %v, state %d", err, states.Load())
	}
	if !contact().After(started) {
		t.Fatal("хранилище не заметило пульса")
	}
	if err := c.SendOnce(ctx); err != nil || states.Load() != 2 {
		t.Fatalf("второй пульс сразу за первым: %v, state %d", err, states.Load())
	}
	appendLines(t, r.cfg.File, "x\n")
	time.Sleep(150 * time.Millisecond)
	if _, err := c.ReadOnce(); err != nil {
		t.Fatal(err)
	}
	if err := c.SendOnce(ctx); err != nil || states.Load() != 2 {
		t.Fatalf("пульс поверх пачки: %v, state %d", err, states.Load())
	}
}

// P-05: прежняя установка после sources bind останавливается и тогда, когда
// ей нечего слать: отказ приходит в ответ на пульс. Раньше она узнавала об
// отказе только со следующей строкой журнала.
func TestIdleCollectorStopsWhenRebound(t *testing.T) {
	r := newRig(t)
	r.cfg.HeartbeatEvery = config.Duration(50 * time.Millisecond)
	c := r.collector(t)
	if err := r.st.BindEpoch("abs-core", strings.Repeat("b", 32)); err != nil {
		t.Fatal(err)
	}
	time.Sleep(80 * time.Millisecond)
	if err := c.SendOnce(context.Background()); !errors.Is(err, ErrEpoch) {
		t.Fatalf("простаивающая прежняя установка: %v", err)
	}
}

// Копия одной установки (снимок ВМ, скопированный spool_dir) несёт ту же
// эпоху, и эпоха их не различает. Различает сверка номеров: второй
// получает отказ «номер занят другим телом» и останавливается. Его строки
// не пропадают молча, а ждут в буфере; хранилище хранит строки первого и
// ничего из пачки второго.
func TestInstallationCloneStopsOnConflict(t *testing.T) {
	r := newRig(t)
	a := r.collector(t)
	cfgB := *r.cfg
	cfgB.SpoolDir = filepath.Join(t.TempDir(), "spool-b")
	cfgB.File = filepath.Join(r.logDir, "other.log")
	epoch, err := os.ReadFile(filepath.Join(r.cfg.SpoolDir, "epoch.json"))
	if err != nil {
		t.Fatal(err)
	}
	os.MkdirAll(cfgB.SpoolDir, 0o700)
	if err := os.WriteFile(filepath.Join(cfgB.SpoolDir, "epoch.json"), epoch, 0o600); err != nil {
		t.Fatal(err)
	}
	b, err := New(&cfgB, quiet)
	if err != nil {
		t.Fatal(err)
	}
	defer b.Close()
	if err := b.Bootstrap(context.Background()); err != nil {
		t.Fatal(err)
	}
	appendLines(t, r.cfg.File, "from-a\n")
	cycle(t, a)
	appendLines(t, cfgB.File, "from-b-1\n", "from-b-2\n")
	if _, err := b.ReadOnce(); err != nil {
		t.Fatal(err)
	}
	// Хранилище помнит номер 1, у второго выданы 1 и 2: на старте не видно,
	// видно на отправке.
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	err = b.Run(ctx)
	if !errors.Is(err, ErrConflict) {
		t.Fatalf("второй сборщик: %v", err)
	}
	// Причину называет хранилище (G-05): при ключе, ждущем уничтожения, она
	// другая, и диагноз «второй сборщик» от себя сборщик не добавляет.
	if !strings.Contains(err.Error(), "another collector uses the source certificate") {
		t.Fatalf("причина хранилища не дошла: %v", err)
	}
	if b.Pending() != 2 || b.Acked() != 0 {
		t.Fatalf("у второго в буфере %d, подтверждено до %d", b.Pending(), b.Acked())
	}
	if got := r.bodies(t); len(got) != 1 || got[0] != "from-a" {
		t.Fatalf("у хранилища: %q", got)
	}
}

// Хранилище приняло запись, а ответ до сборщика не дошёл (падение,
// таймаут): повтор получает «duplicate» с обещанием, расписка не теряется.
func TestResendGetsPromise(t *testing.T) {
	r := newRig(t)
	c := r.collector(t)
	appendLines(t, r.cfg.File, "a\n")
	if _, err := c.ReadOnce(); err != nil {
		t.Fatal(err)
	}
	if _, err := r.st.Ingest("abs-core", []store.Incoming{{Seq: 1, Body: []byte("a")}}); err != nil { // ответ «потерялся»
		t.Fatal(err)
	}
	if err := c.SendOnce(context.Background()); err != nil {
		t.Fatal(err)
	}
	ps, _, err := Promises(r.cfg.SpoolDir)
	if err != nil || c.Acked() != 1 {
		t.Fatalf("подтверждено до %d, %v", c.Acked(), err)
	}
	pub, _ := base64.RawStdEncoding.DecodeString(r.st.PublicKey())
	if p, ok := ps[1]; !ok || proof.VerifyPromise(p, ed25519.PublicKey(pub)) != nil {
		t.Fatalf("обещания на повтор нет: %+v", ps)
	}
}

// ⭐ Обещание не сходится (подпись; честно подписано, но о другой записи)
// или его нет: записи не считаются доставленными и остаются в буфере,
// неверное обещание ложится отдельно как улика против хранилища. Когда
// хранилище отвечает честно, записи уходят.
func TestBadPromiseKeepsRecords(t *testing.T) {
	var spoil atomic.Pointer[func([]server.IngestResult)]
	r := newRig(t, func(h http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
			f := spoil.Load()
			if f == nil || req.URL.Path != "/v1/ingest" {
				h.ServeHTTP(w, req)
				return
			}
			rec := httptest.NewRecorder()
			h.ServeHTTP(rec, req)
			var out server.IngestResponse
			if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
				t.Error(err)
			}
			(*f)(out.Results)
			w.WriteHeader(rec.Code)
			json.NewEncoder(w).Encode(out)
		})
	})
	c := r.collector(t)
	rejected := filepath.Join(r.cfg.SpoolDir, rejectedFile)
	for i, tc := range []struct {
		name  string
		f     func([]server.IngestResult)
		saved bool // обещание ложится в promises-rejected.jsonl
	}{
		{"подпись", func(res []server.IngestResult) { res[0].Promise.Signature[0] ^= 1 }, true},
		{"о другой записи", func(res []server.IngestResult) { res[0].Promise, res[1].Promise = res[1].Promise, res[0].Promise }, true},
		{"без обещания", func(res []server.IngestResult) { res[0].Promise = nil }, false},
	} {
		before, _ := os.ReadFile(rejected)
		spoil.Store(&tc.f)
		appendLines(t, r.cfg.File, fmt.Sprintf("line %d\n", 2*i), fmt.Sprintf("line %d\n", 2*i+1))
		if _, err := c.ReadOnce(); err != nil {
			t.Fatal(err)
		}
		if err := c.SendOnce(context.Background()); !errors.Is(err, ErrBadPromise) {
			t.Fatalf("%s: %v", tc.name, err)
		}
		if c.Pending() != 2 || c.Acked() != uint64(2*i) {
			t.Fatalf("%s: в буфере %d, подтверждено до %d", tc.name, c.Pending(), c.Acked())
		}
		after, _ := os.ReadFile(rejected)
		if saved := len(after) > len(before); saved != tc.saved {
			t.Fatalf("%s: обещание сохранено отдельно = %v", tc.name, saved)
		}
		spoil.Store(nil)
		cycle(t, c)
		if c.Pending() != 0 || c.Acked() != uint64(2*i+2) {
			t.Fatalf("%s: после честного ответа в буфере %d, подтверждено до %d", tc.name, c.Pending(), c.Acked())
		}
	}
	ps, _, _ := Promises(r.cfg.SpoolDir)
	pub, _ := base64.RawStdEncoding.DecodeString(r.st.PublicKey())
	for seq, p := range ps {
		if err := proof.VerifyPromise(p, ed25519.PublicKey(pub)); err != nil {
			t.Fatalf("в promises.jsonl неверное обещание %d: %v", seq, err)
		}
	}
}

// Файл обрезан на месте и успел дорасти дальше прежнего места
// (copytruncate), или inode удалённого файла достался новому: первая строка
// не та. Новый файл читается с начала, потеря хвоста — пропуск номера
// (раньше чтение шло с середины чужого содержимого).
func TestFileReplacedInPlaceIsReadFromStart(t *testing.T) {
	r := newRig(t)
	c := r.collector(t)
	appendLines(t, r.cfg.File, "old-1\n", "old-2\n")
	cycle(t, c)
	appendLines(t, r.cfg.File, "old-unread\n")
	if err := os.WriteFile(r.cfg.File, []byte("new-1, a longer line\nnew-2\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	cycle(t, c)
	got := r.bodies(t)
	if len(got) != 5 || got[0] != "old-1" || got[1] != "old-2" || !strings.HasPrefix(got[2], "<нет 3") ||
		got[3] != "new-1, a longer line" || got[4] != "new-2" {
		t.Fatalf("принято %q", got)
	}
}

// Доставленное уходит с диска целыми сегментами буфера; после рестарта
// ничего не посылается заново, нумерация продолжается.
func TestSpoolReleasesDelivered(t *testing.T) {
	saved := spoolSegmentBytes
	spoolSegmentBytes = 256
	t.Cleanup(func() { spoolSegmentBytes = saved })
	r := newRig(t)
	c := r.collector(t)
	var want []string
	for round := range 5 {
		for i := range 10 {
			line := fmt.Sprintf("line %d-%d", round, i)
			appendLines(t, r.cfg.File, line+"\n")
			want = append(want, line)
		}
		cycle(t, c)
	}
	// Остаётся сегмент с последней записью (и, может быть, сегмент с повторённой
	// меткой места), остальное доставлено и удалено.
	if segs := spoolSegments(t, r.cfg.SpoolDir); len(segs) > 2 {
		t.Fatalf("сегментов буфера %d: доставленное не удалено", len(segs))
	}
	c.Close()
	c = r.collector(t)
	if c.Pending() != 0 {
		t.Fatalf("после рестарта в буфере %d", c.Pending())
	}
	appendLines(t, r.cfg.File, "tail\n")
	cycle(t, c)
	if got := strings.Join(r.bodies(t), ","); got != strings.Join(append(want, "tail"), ",") {
		t.Fatalf("принято: %q", got)
	}
}

// Первый запуск с from_start, когда хранилище уже знает источник
// (переустановка): строки уйдут повторно под новыми номерами — сборщик
// говорит об этом в журнал.
func TestFromStartOverKnownSourceWarns(t *testing.T) {
	r := newRig(t)
	c := r.collector(t)
	appendLines(t, r.cfg.File, "a\n")
	cycle(t, c)
	c.Close()
	os.RemoveAll(r.cfg.SpoolDir)
	var buf bytes.Buffer
	r.reinstalled(t, slog.New(slog.NewTextHandler(&buf, nil)))
	if !strings.Contains(buf.String(), "from_start") {
		t.Fatalf("предупреждения нет:\n%s", buf.String())
	}
}

// ⭐ Часы ушли назад: новый шард получил время изменения раньше текущего. Он
// всё равно читается: сборщик помнит, что прочитал, а не опирается на
// порядок времени (раньше такой шард не читался никогда).
func TestGlobFileFromThePastIsRead(t *testing.T) {
	r := globRig(t)
	base := time.Now().Add(-time.Hour)
	first := filepath.Join(r.logDir, "evidence-a-0.jsonl")
	appendLines(t, first, `{"n":1}`+"\n")
	os.Chtimes(first, base, base)
	c := r.collector(t)
	cycle(t, c)
	second := filepath.Join(r.logDir, "evidence-b-0.jsonl")
	appendLines(t, second, `{"n":2}`+"\n")
	past := base.Add(-10 * time.Second)
	os.Chtimes(second, past, past)
	cycle(t, c)
	cycle(t, c)
	want := `{"n":1},{"n":2}`
	if got := strings.Join(r.bodies(t), ","); got != want {
		t.Fatalf("принято: %s", got)
	}
	c.Close()
	cycle(t, r.collector(t)) // после рестарта ничего не перечитывается
	if got := strings.Join(r.bodies(t), ","); got != want {
		t.Fatalf("после рестарта: %s", got)
	}
}

// ⭐ Первый запуск по маске без from_start: записанное раньше не читается,
// дописанное в последний шард и новые шарды — читаются, в том числе после
// рестарта без новых строк и после падения до записи files.json.
func TestGlobFirstStartSkipsExisting(t *testing.T) {
	r := globRig(t)
	r.cfg.FromStart = false
	base := time.Now().Add(-time.Hour)
	old := filepath.Join(r.logDir, "evidence-a-0.jsonl")
	cur := filepath.Join(r.logDir, "evidence-a-1.jsonl")
	appendLines(t, old, "old-1\n")
	appendLines(t, cur, "old-2\n")
	os.Chtimes(old, base, base)
	os.Chtimes(cur, base.Add(time.Second), base.Add(time.Second))
	r.collector(t).Close() // первый запуск
	// Падение после записи «старт», до files.json: места чтения — из буфера.
	if err := os.Remove(filepath.Join(r.cfg.SpoolDir, "files.json")); err != nil {
		t.Fatal(err)
	}
	c := r.collector(t)
	appendLines(t, cur, "new-1\n")
	appendLines(t, filepath.Join(r.logDir, "evidence-a-2.jsonl"), "new-2\n")
	cycle(t, c)
	cycle(t, c)
	if got := strings.Join(r.bodies(t), ","); got != "new-1,new-2" {
		t.Fatalf("принято: %q", got)
	}
}

// Текущий файл удалили, а более ранний с тем же временем изменения ещё
// лежит: он уже прочитан и не перечитывается под новыми номерами.
func TestGlobDeletedCurrentDoesNotRereadOlder(t *testing.T) {
	r := globRig(t)
	same := time.Now().Add(-time.Hour)
	a0 := filepath.Join(r.logDir, "evidence-a-0.jsonl")
	a1 := filepath.Join(r.logDir, "evidence-a-1.jsonl")
	appendLines(t, a0, "1\n")
	appendLines(t, a1, "2\n")
	os.Chtimes(a0, same, same)
	os.Chtimes(a1, same, same)
	c := r.collector(t)
	cycle(t, c)
	appendLines(t, a1, "lost\n")
	os.Remove(a1)
	appendLines(t, filepath.Join(r.logDir, "evidence-a-2.jsonl"), "3\n")
	cycle(t, c)
	// «lost» дописан в текущий файл перед удалением: работающий сборщик
	// дочитывает его через дескриптор. Пропуска нет, «1» не перечитан.
	if got := strings.Join(r.bodies(t), ","); got != "1,2,lost,3" {
		t.Fatalf("принято %q", got)
	}
}

// ⭐ W-02: ротация уводит текущий файл из-под маски (`*.jsonl`,
// evidence-a.jsonl → evidence-a.jsonl.1), а приложение до переоткрытия
// пишет в него. Ушедший файл дочитывается через дескриптор, пока не
// замолчит, как в режиме file. Раньше он дочитывался сразу и забывался:
// «two» терялась без пропуска в цепи.
func TestGlobRotatedOutOfMaskWaitsForQuiet(t *testing.T) {
	r := globRig(t)
	rotateQuiet = 300 * time.Millisecond
	log := filepath.Join(r.logDir, "evidence-a.jsonl")
	appendLines(t, log, "one\n")
	c := r.collector(t)
	cycle(t, c)
	os.Rename(log, log+".1")
	appendLines(t, log) // create: новый пустой журнал
	cycle(t, c)
	appendLines(t, log+".1", "two\n") // приложение ещё пишет в старый
	cycle(t, c)
	appendLines(t, log, "three\n") // переоткрыло журнал (HUP)
	cycle(t, c)
	time.Sleep(rotateQuiet + 100*time.Millisecond)
	cycle(t, c)
	cycle(t, c)
	if got := strings.Join(r.bodies(t), ","); got != "one,two,three" {
		t.Fatalf("принято %q", got)
	}
}

// ⭐ X-02: маска над ротируемым журналом, вторая ротация, пока ушедший
// из-под маски файл ждёт тишины. Новый файл (b) уходит из-под маски, не
// став текущим. Раньше он не читался никогда, без пропуска в цепи; теперь
// непрочитанные файлы под маской держатся открытыми, пока ушедший ждёт, и
// читаются по очереди, даже ушедшие.
func TestGlobSecondRotationWhileDrainingKeepsMiddleFile(t *testing.T) {
	r := globRig(t)
	rotateQuiet = 300 * time.Millisecond
	log := filepath.Join(r.logDir, "evidence-a.jsonl")
	appendLines(t, log, "a1\n")
	c := r.collector(t)
	cycle(t, c)
	os.Rename(log, log+".1")
	appendLines(t, log, "b1\n")
	appendLines(t, log+".1", "a2\n")
	cycle(t, c) // a ушёл из-под маски и ждёт тишины; b замечен
	os.Rename(log+".1", log+".2")
	os.Rename(log, log+".1")
	appendLines(t, log, "c1\n")
	appendLines(t, log+".1", "b2\n")
	cycle(t, c)
	for range 3 {
		time.Sleep(rotateQuiet + 100*time.Millisecond)
		cycle(t, c)
	}
	if got := strings.Join(r.bodies(t), ","); got != "a1,a2,b1,b2,c1" {
		t.Fatalf("принято %q", got)
	}
}

// X-02: файл из очереди, уже частично прочитанный, ушёл из-под маски, пока
// ждал: его место не забывается (forgetGone), и он дочитывается с него, без
// повтора доставленного.
func TestGlobQueuedFileKeepsItsOffset(t *testing.T) {
	r := globRig(t)
	rotateQuiet = 300 * time.Millisecond
	old := time.Now().Add(-time.Hour)
	f1 := filepath.Join(r.logDir, "evidence-1.jsonl")
	f2 := filepath.Join(r.logDir, "evidence-2.jsonl")
	appendLines(t, f1, "one\n")
	appendLines(t, f2, "two\n")
	os.Chtimes(f1, old, old)
	os.Chtimes(f2, old.Add(time.Second), old.Add(time.Second))
	c := r.collector(t)
	cycle(t, c) // прочитаны оба, текущий — f2
	appendLines(t, f1, "late\n")
	os.Rename(f2, f2+".gone") // текущий ушёл из-под маски
	cycle(t, c)               // f2 ждёт тишины, f1 (с непрочитанным) — в очереди
	os.Rename(f1, f1+".gone") // и f1 ушёл, не дождавшись
	cycle(t, c)
	for range 3 {
		time.Sleep(rotateQuiet + 100*time.Millisecond)
		cycle(t, c)
	}
	if got := strings.Join(r.bodies(t), ","); got != "one,two,late" {
		t.Fatalf("принято %q", got)
	}
}

// X-03: новый файл на пути журнала не открыть (logrotate create с правами,
// которых у сборщика нет). Это не мешает дочитать ротированный: раньше
// ошибка открытия нового файла обрывала проход раньше дочитывания, и
// поздние строки ждали, пока починят права.
func TestUnopenableNewFileDoesNotBlockDrain(t *testing.T) {
	r := newRig(t)
	rotateQuiet = 300 * time.Millisecond
	c := r.collector(t)
	f := r.cfg.File
	appendLines(t, f, "a1\n")
	cycle(t, c)
	os.Rename(f, f+".1")
	if err := os.WriteFile(f, nil, 0); err != nil {
		t.Fatal(err)
	}
	appendLines(t, f+".1", "a2\n")
	pass := func() {
		c.ReadOnce() // ошибка нового файла ожидаема
		if err := c.SendOnce(context.Background()); err != nil {
			t.Fatal(err)
		}
	}
	for range 3 {
		pass()
		time.Sleep(rotateQuiet + 100*time.Millisecond)
	}
	pass()
	if got := strings.Join(r.bodies(t), "|"); got != "a1|a2" {
		t.Fatalf("ротированный не дочитан, пока новый не открыть: %q", got)
	}
	os.Chmod(f, 0o600)
	appendLines(t, f, "b1\n")
	pass()
	pass()
	if got := strings.Join(r.bodies(t), "|"); got != "a1|a2|b1" {
		t.Fatalf("после починки прав: %q", got)
	}
}

// onLog — обработчик журнала, который зовёт fn на каждой записи: тест
// вклинивается в окно между шагами сборщика.
type onLog struct {
	slog.Handler
	fn func(slog.Record)
}

func (h onLog) Handle(ctx context.Context, r slog.Record) error { h.fn(r); return nil }

// W-06: файл под маской переименован в другое имя под той же маской между
// листингом и открытием. По устаревшему листингу он не открывается — это
// повод перечитать каталог, а не «файл пропал»: раньше каждый такой виток
// оставлял ложный пропуск номера, а файл под новым именем читался с начала
// (повтор доставленного под новыми номерами).
func TestGlobRenameBetweenListingAndOpen(t *testing.T) {
	r := globRig(t)
	same := time.Now().Add(-time.Hour)
	var paths []string
	for i, body := range []string{"1\n", "2\n", "3\n"} {
		p := filepath.Join(r.logDir, fmt.Sprintf("evidence-a-%d.jsonl", i))
		appendLines(t, p, body)
		os.Chtimes(p, same, same)
		paths = append(paths, p)
	}
	renamed := filepath.Join(r.logDir, "evidence-a-9.jsonl")
	c := r.collector(t) // первый запуск вносит три файла в реестр, по путям
	// Строка первого файла ложится в буфер раньше, чем открывается третий:
	// здесь третий переименовывают — листинг этого прохода устарел.
	var done atomic.Bool
	c.persistHook = func(what string) error {
		if what == "spool" && done.CompareAndSwap(false, true) {
			os.Rename(paths[2], renamed)
		}
		return nil
	}
	cycle(t, c)
	cycle(t, c)
	if !done.Load() {
		t.Fatal("переименование не случилось: сценарий не воспроизведён")
	}
	if got := strings.Join(r.bodies(t), ","); got != "1,2,3" {
		t.Fatalf("принято %q", got)
	}
}

// Номера в буфере только растут; буфер, где это не так, испорчен, и
// сборщик из него не шлёт.
func TestSpoolSeqMustGrow(t *testing.T) {
	r := newRig(t)
	l, err := evlog.Open(filepath.Join(r.cfg.SpoolDir, "spool"), evlog.Options{AllowRelease: true}, nil)
	if err != nil {
		t.Fatal(err)
	}
	var recs [][]byte
	for _, seq := range []uint64{5, 3} {
		recs = append(recs, spoolRecord{kind: kindLine, seq: seq, pos: filePos{1, int64(seq)}, body: []byte("x")}.marshal())
	}
	if _, err := l.Append(recs); err != nil {
		t.Fatal(err)
	}
	l.Close()
	// Всё остальное в порядке: files.json на месте.
	if err := os.WriteFile(filepath.Join(r.cfg.SpoolDir, "files.json"), []byte("[]"), 0o600); err != nil {
		t.Fatal(err)
	}
	c, err := New(r.cfg, quiet)
	if err == nil {
		c.Close()
		t.Fatal("буфер с убывающими номерами принят")
	}
	if !strings.Contains(err.Error(), "seq 3 after 5") {
		t.Fatalf("отказ не о номерах: %v", err)
	}
}

type spoolFrame struct {
	off  int64
	kind byte
}

// spoolFrames — записи сегмента буфера: смещение и вид.
func spoolFrames(t *testing.T, path string) []spoolFrame {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var out []spoolFrame
	for off := 16; off+8 <= len(data); { // заголовок сегмента evlog — 16 байт
		n := int(binary.BigEndian.Uint32(data[off:]))
		out = append(out, spoolFrame{off: int64(off), kind: data[off+8]})
		off += 8 + n
	}
	return out
}

// ⭐ C-01: logrotate create (так по умолчанию в дистрибутивах): журнал
// переименован, создан новый, а приложение до переоткрытия пишет в старый
// — дописывает недописанную строку и следующие. Старый файл читается через
// дескриптор, пока не замолчит, — даже удалённый. Раньше он дочитывался
// сразу (с обрывком строки) и забывался: «half» вместо «half line», «late»
// терялась без пропуска в цепи.
func TestRotationWaitsForQuietOldFile(t *testing.T) {
	r := newRig(t)
	rotateQuiet = 300 * time.Millisecond
	c := r.collector(t)
	appendLines(t, r.cfg.File, "a\n", "half")
	cycle(t, c)
	os.Rename(r.cfg.File, r.cfg.File+".1")
	appendLines(t, r.cfg.File) // create: новый пустой журнал
	cycle(t, c)
	appendLines(t, r.cfg.File+".1", " line\n", "late\n") // приложение ещё пишет в старый
	os.Remove(r.cfg.File + ".1")                         // и его даже удалили
	cycle(t, c)
	appendLines(t, r.cfg.File, "b\n") // переоткрыло журнал (HUP)
	cycle(t, c)
	time.Sleep(rotateQuiet + 100*time.Millisecond)
	cycle(t, c)
	if got := strings.Join(r.bodies(t), "|"); got != "a|half line|late|b" {
		t.Fatalf("принято %q", got)
	}
}

// ⭐ W-03: вторая ротация, пока сборщик ждёт тишины на первом ротированном
// файле. Раньше по тишине чтение переходило к тому, что лежит на пути
// сейчас, и средний файл не читался никогда, без пропуска в цепи (у
// работающего сборщика, не только у остановленного). Каждый новый файл на
// пути открывается, как только замечен, и ждёт своей очереди; поздняя
// строка в нём тоже не теряется.
func TestSecondRotationWhileDrainingKeepsMiddleFile(t *testing.T) {
	r := newRig(t)
	rotateQuiet = 300 * time.Millisecond
	c := r.collector(t)
	f := r.cfg.File
	appendLines(t, f, "a1\n")
	cycle(t, c)
	os.Rename(f, f+".1")
	appendLines(t, f, "b1\n")
	cycle(t, c) // замечен b; a ещё не замолчал
	os.Rename(f+".1", f+".2")
	os.Rename(f, f+".1")
	appendLines(t, f, "c1\n")
	cycle(t, c)
	appendLines(t, f+".1", "b2\n") // приложение ещё пишет в b
	cycle(t, c)
	for range 3 {
		time.Sleep(rotateQuiet + 100*time.Millisecond)
		cycle(t, c)
	}
	// Файлы читаются каждый сам по себе: строки разных файлов перемежаются,
	// внутри файла — порядок записи.
	if got := r.bodies(t); !perFile(got, "a1", "b1|b2", "c1") {
		t.Fatalf("принято %q", got)
	}
}

// perFile — got содержит ровно строки files (каждый — строки одного файла
// через «|») и строки каждого файла идут в своём порядке.
func perFile(got []string, files ...string) bool {
	n := 0
	for _, f := range files {
		lines := strings.Split(f, "|")
		n += len(lines)
		at := -1
		for _, l := range lines {
			i := slices.Index(got, l)
			if i <= at {
				return false
			}
			at = i
		}
	}
	return n == len(got)
}

// W-03: хранилище недоступно — отправка ждёт с растущей паузой (до минуты),
// а чтение идёт прежним шагом: иначе две ротации за паузу теряли средний
// файл. Ротации каждые 200 мс, пока хранилище отказывает; потом всё
// доставлено.
func TestReadingGoesOnWhileStoreIsDown(t *testing.T) {
	var down atomic.Bool
	down.Store(true)
	r := newRig(t, func(h http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
			if down.Load() && req.URL.Path == "/v1/ingest" {
				http.Error(w, "down", http.StatusServiceUnavailable)
				return
			}
			h.ServeHTTP(w, req)
		})
	})
	rotateQuiet = 50 * time.Millisecond
	r.cfg.FlushEvery = config.Duration(20 * time.Millisecond)
	c := r.collector(t)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- c.Run(ctx) }()
	f := r.cfg.File
	var want []string
	for i := range 6 {
		line := fmt.Sprintf("line %d", i)
		want = append(want, line)
		appendLines(t, f, line+"\n")
		time.Sleep(200 * time.Millisecond)
		for j := 5; j >= 1; j-- {
			os.Rename(fmt.Sprintf("%s.%d", f, j), fmt.Sprintf("%s.%d", f, j+1))
		}
		os.Rename(f, f+".1")
	}
	appendLines(t, f, "last\n")
	want = append(want, "last")
	down.Store(false)
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		if last, _ := r.st.LastSeq("abs-core"); last >= uint64(len(want)) {
			break
		}
		time.Sleep(50 * time.Millisecond)
	}
	cancel()
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	if got := strings.Join(r.bodies(t), "|"); got != strings.Join(want, "|") {
		t.Fatalf("принято %q", got)
	}
}

// Y-02 (класс): файл молчал дольше rotateQuiet ещё до ротации — тишина
// после ротации всё равно отсчитывается от ухода с пути: приложение пишет в
// ротированный файл до HUP. Раньше такой файл считался давно замолчавшим и
// закрывался сразу, поздняя строка терялась без пропуска (симуляция нашла
// это в новой модели; в гейте её сценариев мало — нужен свой тест).
func TestQuietCountsFromRotation(t *testing.T) {
	r := newRig(t)
	c := r.collector(t)
	vt := time.Now()
	c.now, c.quietFor = func() time.Time { return vt }, 10*time.Second
	f := r.cfg.File
	appendLines(t, f, "a1\n")
	cycle(t, c)
	vt = vt.Add(30 * time.Second) // файл молчит 30 с
	cycle(t, c)
	os.Rename(f, f+".1")
	cycle(t, c) // замечен уход
	// Приложение ещё пишет в ротированный.
	appendLines(t, f+".1", "a2\n")
	vt = vt.Add(time.Second)
	cycle(t, c)
	for range 3 {
		vt = vt.Add(11 * time.Second)
		cycle(t, c)
	}
	if got := strings.Join(r.bodies(t), "|"); got != "a1|a2" {
		t.Fatalf("принято %q", got)
	}
}

// Первая строка файла ложится в буфер в одной пачке с его первыми строками.
// Раньше — отдельной записью после них: упал между ними, файл обрезали
// (copytruncate) и он дорос за прежнее место — после перезапуска первая
// строка неизвестна, подмену не видно, чтение шло с середины нового
// содержимого (обрывок вместо строк, потеря без пропуска). Нашла длинная
// симуляция: 13 сценариев из 1000.
func TestHeadSurvivesCrashAfterFirstLines(t *testing.T) {
	r := newRig(t)
	c := r.collector(t)
	f := r.cfg.File
	appendLines(t, f, "a-1\n", "b-2\n")
	// Записи прохода: 'P' нового файла, его строки, (раньше) отдельная 'P' с
	// первой строкой — перед ней процесс и падал. Считаются точки перед
	// записью.
	n := 0
	c.persistHook = func(what string) error {
		if strings.HasSuffix(what, "+") {
			return nil
		}
		if n++; n == 3 {
			return errors.New("падение")
		}
		return nil
	}
	c.ReadOnce() // строки — в буфере; дальше процесс падает
	c.Close()
	// Пока сборщик стоял: copytruncate, и файл дорос за прежнее место.
	if err := os.WriteFile(f, []byte("c-3, a line longer than both old ones together\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	c = r.collector(t)
	cycle(t, c)
	cycle(t, c)
	got := r.bodies(t)
	if len(got) != 4 || got[0] != "a-1" || got[1] != "b-2" || !strings.HasPrefix(got[2], "<нет 3") || got[3] != "c-3, a line longer than both old ones together" {
		t.Fatalf("принято %q", got)
	}
}

// C-02: первую строку текущего файла на миг не прочитать (права, ротация в
// окне) — это «не знаю», а не «файл подменён»: ни ложного пропуска, ни
// чтения всего файла заново. Первая строка читается через открытый
// дескриптор.
func TestUnreadableHeadIsNotReplacement(t *testing.T) {
	r := newRig(t)
	c := r.collector(t)
	appendLines(t, r.cfg.File, "a\n", "b\n")
	cycle(t, c)
	os.Chmod(r.cfg.File, 0)
	cycle(t, c)
	os.Chmod(r.cfg.File, 0o600)
	appendLines(t, r.cfg.File, "c\n")
	cycle(t, c)
	if got := strings.Join(r.bodies(t), "|"); got != "a|b|c" {
		t.Fatalf("принято %q", got)
	}
}

// C-03: смена места после подмены файла ложится в буфер записью 'P' вместе
// с пропуском номера. Упали сразу после неё — после рестарта чтение идёт с
// начала нового содержимого и пропуск на месте (раньше смена жила в
// памяти: чтение со старого смещения в новом содержимом, пропуска нет).
func TestPositionSwitchSurvivesCrash(t *testing.T) {
	r := newRig(t)
	c := r.collector(t)
	appendLines(t, r.cfg.File, "hdr\n", "old-2\n")
	cycle(t, c)
	if err := os.WriteFile(r.cfg.File, []byte("hdr\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	// То, что делает обнаружение обрезки (файл короче места чтения), — и
	// падение до чтения.
	fi, err := os.Stat(r.cfg.File)
	if err != nil {
		t.Fatal(err)
	}
	tr := c.files[inode(fi)]
	c.nextSeq++
	tr.off, tr.head = 0, ""
	if err := c.mark(tr); err != nil {
		t.Fatal(err)
	}
	c.Close()
	// Пока сборщик стоял, файл дорос за прежнее место, а первая строка та
	// же (заголовок журнала): ни размер, ни первая строка подмену уже не
	// выдают — новое место знает только запись 'P'.
	appendLines(t, r.cfg.File, "new-2, a longer line\n")
	c = r.collector(t)
	cycle(t, c)
	got := r.bodies(t)
	if len(got) != 5 || got[0] != "hdr" || got[1] != "old-2" || !strings.HasPrefix(got[2], "<нет 3") ||
		got[3] != "hdr" || got[4] != "new-2, a longer line" {
		t.Fatalf("принято %q", got)
	}
}

// copytruncate, после которого приложение снова пишет ту же первую строку
// (заголовок журнала): первая строка подмену не выдаёт, выдаёт только размер —
// файл короче места чтения. Пропуск номера и чтение с начала; иначе чтение
// продолжилось бы с прежнего места в новом содержимом — с обрывка строки, а
// строки до него пропали бы молча (мутация C37).
func TestTruncatedWithSameHeadSeenBySize(t *testing.T) {
	r := newRig(t)
	c := r.collector(t)
	appendLines(t, r.cfg.File, "hdr\n", "old-2\n", "old-3\n")
	cycle(t, c)
	if err := os.Truncate(r.cfg.File, 0); err != nil {
		t.Fatal(err)
	}
	appendLines(t, r.cfg.File, "hdr\n", "new-2\n") // короче прежнего места
	cycle(t, c)
	appendLines(t, r.cfg.File, "new-3, a longer line\n") // дорос за прежнее место
	cycle(t, c)
	got := r.bodies(t)
	if len(got) != 7 || got[2] != "old-3" || !strings.HasPrefix(got[3], "<нет 4") ||
		got[4] != "hdr" || got[5] != "new-2" || got[6] != "new-3, a longer line" {
		t.Fatalf("принято %q", got)
	}
}

// Новый файл ложится в реестр записью 'P' до своей первой строки (Y-03).
// Сборщик упал, когда новый журнал ещё пуст и files.json его не знает; пока
// сборщик стоял, в журнал записали строку и ротировали его. После рестарта
// файл находится по inode под новым именем; без 'P' о нём не знал бы никто,
// и строка пропала бы молча (мутация C42).
func TestNewFileKnownAfterCrashBeforeFirstLine(t *testing.T) {
	r := newRig(t)
	c := r.collector(t)
	f := r.cfg.File
	appendLines(t, f, "a1\n")
	cycle(t, c)
	os.Rename(f, f+".1")
	if err := os.WriteFile(f, nil, 0o600); err != nil { // logrotate create
		t.Fatal(err)
	}
	cycle(t, c) // новый журнал пуст: о нём знает только буфер
	c.Close()   // упал
	appendLines(t, f, "b1\n")
	os.Rename(f+".1", f+".2")
	os.Rename(f, f+".1")
	appendLines(t, f, "c1\n")
	c = r.collector(t)
	cycle(t, c)
	if got := strings.Join(r.bodies(t), "|"); got != "a1|b1|c1" {
		t.Fatalf("принято %q", got)
	}
}

// Первая строка файла после рестарта поднимается из записи 'P' буфера, а не
// только из files.json: сборщик упал раньше, чем снимок реестра её узнал, а
// пока стоял, файл подменили на месте (copytruncate, новое содержимое
// длиннее прежнего места). По первой строке подмена видна: пропуск и чтение
// с начала, а не с прежнего места в чужом содержимом (мутация C48).
func TestHeadRestoredFromSpool(t *testing.T) {
	r := newRig(t)
	c := r.collector(t)
	appendLines(t, r.cfg.File, "hdr-1\n", "a-2\n")
	if _, err := c.ReadOnce(); err != nil { // в буфере, не отправлено: files.json файла не знает
		t.Fatal(err)
	}
	c.Close() // упал
	// Тот же inode, новое содержимое.
	if err := os.WriteFile(r.cfg.File, []byte("new-1, another first line\nnew-2\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	c = r.collector(t)
	cycle(t, c)
	got := r.bodies(t)
	if len(got) != 5 || got[0] != "hdr-1" || got[1] != "a-2" || !strings.HasPrefix(got[2], "<нет 3") ||
		got[3] != "new-1, another first line" || got[4] != "new-2" {
		t.Fatalf("принято %q", got)
	}
}

// spoolInodes — файлы, о которых есть записи в буфере (по всем сегментам).
func spoolInodes(t *testing.T, spoolDir string) map[uint64]bool {
	t.Helper()
	out := map[uint64]bool{}
	for _, seg := range spoolSegments(t, spoolDir) {
		data, err := os.ReadFile(seg)
		if err != nil {
			t.Fatal(err)
		}
		for off := 16; off+8 <= len(data); { // заголовок сегмента evlog — 16 байт
			n := int(binary.BigEndian.Uint32(data[off:]))
			if r, err := parseRecord(data[off+8 : off+8+n]); err == nil && r.pos.Inode != 0 {
				out[r.pos.Inode] = true
			}
			off += 8 + n
		}
	}
	return out
}

// Доставленное уходит из буфера только после снимка реестра (files.json):
// место файла, о котором в буфере ничего не осталось, живёт в снимке. Без
// снимка такой файл после рестарта читался бы с начала — повтор под новыми
// номерами (мутация C66).
func TestReleasedRecordsKeptInRegistrySnapshot(t *testing.T) {
	saved := spoolSegmentBytes
	spoolSegmentBytes = 256
	t.Cleanup(func() { spoolSegmentBytes = saved })
	r := globRig(t)
	c := r.collector(t)
	c.quietFor = time.Hour // файл a не закрывается за простоем: это тоже пишет снимок
	a := filepath.Join(r.logDir, "evidence-a-1.jsonl")
	b := filepath.Join(r.logDir, "evidence-b-1.jsonl")
	appendLines(t, a, "a1\n", "a2\n")
	cycle(t, c)
	want := []string{"a1", "a2"}
	for i := range 8 {
		line := fmt.Sprintf("b%d", i)
		appendLines(t, b, line+"\n")
		want = append(want, line)
		cycle(t, c)
	}
	fi, err := os.Stat(a)
	if err != nil {
		t.Fatal(err)
	}
	if spoolInodes(t, r.cfg.SpoolDir)[inode(fi)] {
		t.Fatal("о файле a в буфере ещё есть записи: сценарий не воспроизведён")
	}
	c.Close()
	c = r.collector(t)
	appendLines(t, a, "a3\n")
	cycle(t, c)
	if got, w := strings.Join(r.bodies(t), ","), strings.Join(append(want, "a3"), ","); got != w {
		t.Fatalf("принято %q, ожидали %q", got, w)
	}
}

// Дочитанный файл уходит из реестра записью 'D': ротированный журнал
// дочитан, потом удалён (logrotate rotate N), сборщик перезапущен — ложного
// пропуска номера нет. Без 'D' файл поднимался бы из своих записей в буфере
// и после рестарта считался пропавшим недочитанным (мутация C67).
func TestDoneFileGoneAfterRestartIsNoGap(t *testing.T) {
	r := newRig(t)
	c := r.collector(t)
	f := r.cfg.File
	appendLines(t, f, "a1\n")
	cycle(t, c)
	os.Rename(f, f+".1")
	appendLines(t, f, "b1\n")
	cycle(t, c) // a дочитан и замолчал (rotateQuiet = 0): из реестра
	c.Close()
	os.Remove(f + ".1")
	c = r.collector(t)
	appendLines(t, f, "b2\n")
	cycle(t, c)
	if got := strings.Join(r.bodies(t), "|"); got != "a1|b1|b2" {
		t.Fatalf("принято %q", got)
	}
}

// Z-01: ушедший с пути файл, который после рестарта не открыть (права),
// ждёт в реестре, а остальные файлы читаются. Раньше проход прерывался
// ошибкой, и сборщик стоял, пока права не вернут.
func TestUnreadableRotatedFileDoesNotBlockReading(t *testing.T) {
	r := newRig(t)
	c := r.collector(t)
	f := r.cfg.File
	appendLines(t, f, "a1\n")
	cycle(t, c)
	c.Close()
	appendLines(t, f, "a2\n")
	os.Rename(f, f+".1")
	os.Chmod(f+".1", 0o200)
	appendLines(t, f, "b1\n")
	c = r.collector(t)
	cycle(t, c)
	if got := strings.Join(r.bodies(t), "|"); got != "a1|b1" {
		t.Fatalf("пока ротированный не открыть: %q", got)
	}
	os.Chmod(f+".1", 0o600)
	cycle(t, c)
	if got := strings.Join(r.bodies(t), "|"); got != "a1|b1|a2" {
		t.Fatalf("после починки прав: %q", got)
	}
}

// Z-02: новый журнал, который сборщику не открыть (logrotate create с
// чужими правами), всё равно в реестре. Ротирован раньше, чем права
// исправили, — дочитывается по inode под новым именем. Раньше он не
// попадал в реестр, и его строки пропадали молча.
func TestUnreadableNewFileIsFollowed(t *testing.T) {
	r := newRig(t)
	c := r.collector(t)
	f := r.cfg.File
	appendLines(t, f, "a1\n")
	cycle(t, c)
	os.Rename(f, f+".1")
	if err := os.WriteFile(f, nil, 0o200); err != nil { // приложению писать, сборщику не прочитать
		t.Fatal(err)
	}
	cycle(t, c)
	appendLines(t, f, "b1\n")
	cycle(t, c)
	os.Rename(f+".1", f+".2")
	os.Rename(f, f+".1") // ротирован, права всё ещё не те
	appendLines(t, f, "c1\n")
	cycle(t, c)
	os.Chmod(f+".1", 0o600)
	cycle(t, c)
	if got := strings.Join(r.bodies(t), "|"); got != "a1|c1|b1" {
		t.Fatalf("принято %q", got)
	}
}

// Z-02: неоткрытый файл пропал раньше, чем его прочитали, — пропуск номера,
// а не тихая потеря.
func TestUnreadableNewFileGoneIsGap(t *testing.T) {
	r := newRig(t)
	c := r.collector(t)
	f := r.cfg.File
	appendLines(t, f, "a1\n")
	cycle(t, c)
	os.Rename(f, f+".1")
	if err := os.WriteFile(f, nil, 0o200); err != nil {
		t.Fatal(err)
	}
	cycle(t, c)
	appendLines(t, f, "b1\n")
	os.Remove(f) // удалён, не будучи прочитан
	appendLines(t, f, "c1\n")
	cycle(t, c)
	got := r.bodies(t)
	if len(got) != 3 || got[0] != "a1" || !strings.HasPrefix(got[1], "<нет 2") || got[2] != "c1" {
		t.Fatalf("принято %q", got)
	}
}

// Z-03: каталог журнала на время не прочитать (права, нехватка
// дескрипторов, сбой ФС) — это не «файлов нет». Раньше все файлы под маской
// считались ушедшими, дочитанные выписывались из реестра, а когда каталог
// снова читался — вносились как новые и читались с начала: повторы под
// новыми номерами.
func TestUnreadableLogDirIsNotEmpty(t *testing.T) {
	r := globRig(t)
	c := r.collector(t)
	a := filepath.Join(r.logDir, "evidence-a-1.jsonl")
	appendLines(t, a, "a1\n")
	cycle(t, c)
	os.Chmod(r.logDir, 0o300) // файлы открываются, листинга нет
	t.Cleanup(func() { os.Chmod(r.logDir, 0o700) })
	for range 3 {
		c.ReadOnce() // ошибка листинга ожидаема
		if err := c.SendOnce(context.Background()); err != nil {
			t.Fatal(err)
		}
	}
	os.Chmod(r.logDir, 0o700)
	appendLines(t, a, "a2\n")
	cycle(t, c)
	if got := strings.Join(r.bodies(t), "|"); got != "a1|a2" {
		t.Fatalf("принято %q", got)
	}
}

// Z-03, режим file: после рестарта ротированный файл ищется по inode в
// каталоге; каталог не прочитать — файл не «пропал». Раньше он забывался с
// пропуском номера, и непрочитанный хвост терялся, хотя лежал на месте.
func TestUnreadableDirKeepsRotatedFile(t *testing.T) {
	r := newRig(t)
	c := r.collector(t)
	f := r.cfg.File
	appendLines(t, f, "a1\n")
	cycle(t, c)
	c.Close()
	appendLines(t, f, "a2\n")
	os.Rename(f, f+".1")
	appendLines(t, f, "b1\n")
	os.Chmod(r.logDir, 0o300)
	t.Cleanup(func() { os.Chmod(r.logDir, 0o700) })
	c = r.collector(t)
	cycle(t, c)
	os.Chmod(r.logDir, 0o700)
	cycle(t, c)
	if got := strings.Join(r.bodies(t), "|"); got != "a1|b1|a2" {
		t.Fatalf("принято %q", got)
	}
}

// C-04: первый запуск без from_start посреди недописанной строки встаёт на
// конец последней целой: первая улика — вся строка, а не её обрывок.
func TestFirstStartMidLineTakesWholeLine(t *testing.T) {
	r := newRig(t)
	r.cfg.FromStart = false
	appendLines(t, r.cfg.File, "admin\n", "hal")
	c := r.collector(t)
	appendLines(t, r.cfg.File, "f line\n")
	cycle(t, c)
	if got := strings.Join(r.bodies(t), "|"); got != "half line" {
		t.Fatalf("принято %q", got)
	}
}

// Первый запуск без from_start сразу запоминает первую строку файла:
// подмена на месте до первой новой строки видна — пропуск и чтение с
// начала, а не со старого места в новом содержимом.
func TestFirstStartRemembersHead(t *testing.T) {
	r := newRig(t)
	r.cfg.FromStart = false
	appendLines(t, r.cfg.File, "a\n", "b\n")
	c := r.collector(t)
	if err := os.WriteFile(r.cfg.File, []byte("x-line-1\n"), 0o600); err != nil { // тот же inode
		t.Fatal(err)
	}
	cycle(t, c)
	got := r.bodies(t)
	if len(got) != 2 || !strings.HasPrefix(got[0], "<нет 1") || got[1] != "x-line-1" {
		t.Fatalf("принято %q", got)
	}
}

// tornWriter обрывает запись посередине — как кончившееся место на диске.
type tornWriter struct {
	*os.File
	fail bool
}

func (w *tornWriter) Write(p []byte) (int, error) {
	if w.fail {
		w.fail = false
		n, _ := w.File.Write(p[:len(p)/2])
		return n, errors.New("no space left on device (тест)")
	}
	return w.File.Write(p)
}

// C-07: запись обещания оборвалась во время работы — обрывок отрезается,
// следующее обещание к нему не приклеивается, запись остаётся в буфере и
// получает обещание на повторе.
func TestTornPromiseWriteIsCut(t *testing.T) {
	r := newRig(t)
	c := r.collector(t)
	appendLines(t, r.cfg.File, "a\n")
	cycle(t, c)
	w := &tornWriter{File: c.promises.(*os.File), fail: true}
	c.promises = w
	appendLines(t, r.cfg.File, "b\n")
	if _, err := c.ReadOnce(); err != nil {
		t.Fatal(err)
	}
	if err := c.SendOnce(context.Background()); err == nil || c.Pending() != 1 {
		t.Fatalf("оборванная запись обещания: %v, в буфере %d", err, c.Pending())
	}
	cycle(t, c)
	ps, bad, err := Promises(r.cfg.SpoolDir)
	if err != nil || bad != 0 || len(ps) != 2 {
		t.Fatalf("обещания: %d, нечитаемых %d, %v", len(ps), bad, err)
	}
}

// B-05: файла источника нет (опечатка в пути) или маска пуста — об этом
// говорится в журнал, а не молча «прочитано 0».
func TestMissingSourceIsReported(t *testing.T) {
	r := newRig(t)
	var buf bytes.Buffer
	c, err := New(r.cfg, slog.New(slog.NewTextHandler(&buf, nil)))
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	if err := c.Bootstrap(context.Background()); err != nil {
		t.Fatal(err)
	}
	if _, err := c.ReadOnce(); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(buf.String(), "does not exist") {
		t.Fatalf("о пропавшем файле ни слова:\n%s", buf.String())
	}
}

// G-04: реестр первого запуска лежит не в записи «старт» (тысячи файлов под
// маской в запись буфера не помещались — первый запуск был невозможен), а в
// start-files.json, записанном раньше неё.
func TestStartRecordCarriesNoRegistry(t *testing.T) {
	r := globRig(t)
	r.cfg.FromStart = false
	for i := range 50 {
		appendLines(t, filepath.Join(r.logDir, fmt.Sprintf("evidence-a-%d.jsonl", i)), strings.Repeat("x", 100)+"\n")
	}
	r.collector(t).Close()
	frames := spoolFrames(t, spoolSegments(t, r.cfg.SpoolDir)[0])
	if frames[0].kind != kindStart {
		t.Fatalf("первая запись буфера — %q", frames[0].kind)
	}
	data, _ := os.ReadFile(spoolSegments(t, r.cfg.SpoolDir)[0])
	if n := int(binary.BigEndian.Uint32(data[frames[0].off:])); n != recHead {
		t.Fatalf("запись «старт» несёт %d байт тела", n-recHead)
	}
	var files []fileState
	if ok, err := readJSON(filepath.Join(r.cfg.SpoolDir, "start-files.json"), &files); !ok || err != nil || len(files) != 50 {
		t.Fatalf("start-files.json: %d файлов, %v, %v", len(files), ok, err)
	}
}
