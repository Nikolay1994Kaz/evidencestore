package collector

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"evidencestore/internal/config"
	"evidencestore/internal/evidence"
	"evidencestore/internal/evlog"
	"evidencestore/internal/keyring"
	"evidencestore/internal/pki"
	"evidencestore/internal/proof"
	"evidencestore/internal/server"
	"evidencestore/internal/store"
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
	c2 := r.collector(t)
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

// Ротированный файл удалили раньше, чем его дочитали: потеря не тихая — в
// нумерации пропуск, который хранилище запишет в цепь.
func TestLostRotatedTailLeavesGap(t *testing.T) {
	r := newRig(t)
	c := r.collector(t)
	appendLines(t, r.cfg.File, "1\n")
	cycle(t, c)
	appendLines(t, r.cfg.File, "lost\n")
	os.Rename(r.cfg.File, r.cfg.File+".1")
	appendLines(t, r.cfg.File, "2\n") // новый файл создан, пока старый ещё есть: inode другой
	os.Remove(r.cfg.File + ".1")
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

// Текущий файл удалили недочитанным: потеря видна пропуском номера, чтение
// продолжается со следующего файла.
func TestGlobCurrentFileGoneLeavesGap(t *testing.T) {
	r := globRig(t)
	base := time.Now().Add(-time.Hour)
	first := filepath.Join(r.logDir, "evidence-a-0.jsonl")
	appendLines(t, first, "one\n")
	os.Chtimes(first, base, base)
	c := r.collector(t)
	cycle(t, c)
	appendLines(t, first, "two\n") // не прочитана
	os.Remove(first)
	second := filepath.Join(r.logDir, "evidence-a-2.jsonl")
	appendLines(t, second, "three\n")
	cycle(t, c)
	if got := r.bodies(t); len(got) != 3 || got[0] != "one" || !strings.HasPrefix(got[1], "<нет 2") || got[2] != "three" {
		t.Fatalf("принято %q", got)
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
	both, none, bad := base, base, base
	both.File, both.Glob = "/a.log", "/b/*.log"
	bad.Glob = "/b/[*.log"
	for name, c := range map[string]Config{"file и glob": both, "ни того ни другого": none, "кривая маска": bad} {
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
	if c.Batch != defaultBatch || c.FlushEvery.D() != time.Second || c.Server != "https://store:8443" {
		t.Fatalf("умолчания: %+v", c)
	}
	for name, spoil := range map[string]func(*Config){
		"batch 1000":             func(c *Config) { c.Batch = 1000 },
		"batch -5":               func(c *Config) { c.Batch = -5 },
		"flush_every -1s":        func(c *Config) { c.FlushEvery = config.Duration(-time.Second) },
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
	r.collector(t).Close() // запуск; новых строк нет
	c = r.collector(t)     // перезапуск
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
	fi, err := os.Stat(segs[len(segs)-1])
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Truncate(segs[len(segs)-1], fi.Size()-2); err != nil { // последний кусок оборван
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

// ⭐ Два сборщика с одним сертификатом (скопированный конфиг): второй
// получает отказ «номер занят другим телом» и останавливается. Его строки
// не пропадают молча, а ждут в буфере; хранилище хранит строки первого и
// ничего из пачки второго.
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
	if err := b.Run(ctx); !errors.Is(err, ErrConflict) {
		t.Fatalf("второй сборщик: %v", err)
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
	if segs := spoolSegments(t, r.cfg.SpoolDir); len(segs) != 1 {
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
	c, err := New(r.cfg, slog.New(slog.NewTextHandler(&buf, nil)))
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	if err := c.Bootstrap(context.Background()); err != nil {
		t.Fatal(err)
	}
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
	got := r.bodies(t)
	if len(got) != 4 || got[0] != "1" || got[1] != "2" || !strings.HasPrefix(got[2], "<нет 3") || got[3] != "3" {
		t.Fatalf("принято %q", got)
	}
}

// Номера в буфере только растут; буфер, где это не так, испорчен, и
// сборщик из него не шлёт.
func TestSpoolSeqMustGrow(t *testing.T) {
	r := newRig(t)
	l, err := evlog.Open(filepath.Join(r.cfg.SpoolDir, "spool"), evlog.Options{}, nil)
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
	if c, err := New(r.cfg, quiet); err == nil {
		c.Close()
		t.Fatal("буфер с убывающими номерами принят")
	}
}
