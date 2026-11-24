package pginput

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/Nikolay1994Kaz/evidencestore/internal/alert"
	"github.com/Nikolay1994Kaz/evidencestore/internal/gateway"
	"github.com/Nikolay1994Kaz/evidencestore/internal/pgtap"
)

// rig — читатель квитанций над файлами шлюзов в своём каталоге и тревоги,
// которые он поднял.
type rig struct {
	t      *testing.T
	dir    string
	cfg    ReceiptsConfig
	keys   map[string]ed25519.PrivateKey // по файлу
	r      *receipts
	alerts []alert.Event
}

func newRig(t *testing.T, files ...string) *rig {
	t.Helper()
	g := &rig{t: t, dir: t.TempDir(), keys: map[string]ed25519.PrivateKey{}}
	for _, f := range files {
		pub, key, _ := ed25519.GenerateKey(rand.Reader)
		path := filepath.Join(g.dir, f)
		g.keys[path] = key
		g.cfg.Files = append(g.cfg.Files, path)
		g.cfg.GatewayKeys = append(g.cfg.GatewayKeys, hex.EncodeToString(pub))
	}
	if err := g.cfg.validate(); err != nil {
		t.Fatal(err)
	}
	g.open()
	return g
}

// open — читатель заново (сборщик перезапущен): место тревог — из
// receipts.json.
func (g *rig) open() {
	g.t.Helper()
	if g.r != nil {
		g.r.close()
	}
	var err error
	if g.r, err = openReceipts(g.cfg, g.dir, func(ev alert.Event) error { g.alerts = append(g.alerts, ev); return nil }); err != nil {
		g.t.Fatal(err)
	}
	g.t.Cleanup(g.r.close)
	if err := g.r.poll(); err != nil {
		g.t.Fatal(err)
	}
}

// sign дописывает квитанцию шлюза файла file (имя шлюза — имя файла без
// расширения).
func (g *rig) sign(file string, d gateway.Draft) gateway.Receipt {
	g.t.Helper()
	return g.append(file, d).Receipt
}

// append — квитанция шлюза, как пишет его сервер: голова цепочки — состояние
// шлюза (рядом с ключом), а не файла.
func (g *rig) append(file string, d gateway.Draft) gateway.Appended {
	g.t.Helper()
	path := filepath.Join(g.dir, file)
	a, err := gateway.AppendHead(path, path+".head", g.keys[path], strings.TrimSuffix(file, ".jsonl"), d)
	if err != nil {
		g.t.Fatal(err)
	}
	return a
}

func intent(action string, at time.Time, xids ...string) gateway.Draft {
	d := gateway.Draft{Time: at, Action: action, Step: alert.StepIntent, Body: json.RawMessage(`{"agent":"bot","tool":"execute","reason":"tidy"}`)}
	for _, x := range xids {
		d.Refs = append(d.Refs, gateway.Ref{Source: "postgres", Subject: x})
	}
	return d
}

func outcome(action string, body string) gateway.Draft {
	return gateway.Draft{Action: action, Step: alert.StepOutcome, Body: json.RawMessage(body)}
}

func (g *rig) kinds() string {
	var k []string
	for _, e := range g.alerts {
		k = append(k, e.Kinds()...)
	}
	return strings.Join(k, ",")
}

// Намерение находится по xid из ссылки на этот источник; ссылка на другой
// источник и транзакция без намерения — не через шлюз. Намерение, дописанное
// после открытия, находится дочитыванием файла на промахе.
func TestIntentsByXID(t *testing.T) {
	g := newRig(t, "esmcp.jsonl")
	now := time.Now()
	rc := g.sign("esmcp.jsonl", intent("a-1", now, "751"))
	g.sign("esmcp.jsonl", gateway.Draft{Time: now, Action: "a-2", Step: alert.StepIntent, Refs: []gateway.Ref{{Source: "billing", Subject: "752"}}})
	in, ok, err := g.r.Intent(751, now, 0)
	if err != nil || !ok || in.ID != "a-1" || in.Gateway != "esmcp" || in.Seq != 1 || in.Hash != rc.Hash || in.Agent != "bot" || in.Reason != "tidy" {
		t.Fatalf("%+v %v %v", in, ok, err)
	}
	for _, xid := range []uint32{752, 753} {
		if _, ok, err := g.r.Intent(xid, now, 0); ok || err != nil {
			t.Fatalf("xid %d: found %v, %v", xid, ok, err)
		}
	}
	// Намерение, дописанное после открытия, — находится (о транзакции, о
	// которой ещё не спрашивали: спрошенная раньше своего намерения — уже
	// отпечаток, и её намерение потом — тревога, TestIntentPutBack…).
	g.sign("esmcp.jsonl", intent("a-3", now, "756"))
	if in, ok, _ := g.r.Intent(756, now, 0); !ok || in.ID != "a-3" {
		t.Fatalf("an intent written after the open: %+v %v", in, ok)
	}
	// Откат — тоже намерение, шагом undo; что он возвращает — из тела.
	g.sign("esmcp.jsonl", gateway.Draft{Time: now, Action: "u-1", Step: alert.StepUndo, Refs: []gateway.Ref{{Source: "postgres", Subject: "754"}},
		Body: json.RawMessage(`{"undoes":"a-1"}`)})
	if in, ok, _ := g.r.Intent(754, now, 0); !ok || in.Step != alert.StepUndo || in.Undoes != "a-1" {
		t.Fatalf("an undo: %+v %v", in, ok)
	}
	if g.kinds() != "" {
		t.Fatalf("alerts %s", g.kinds())
	}
}

// Номер транзакции 32 бита и занимается снова: намерение старше фиксации
// больше чем на intentWindow — о давней транзакции.
func TestIntentOfAnOldTransactionIsNotTaken(t *testing.T) {
	g := newRig(t, "esmcp.jsonl")
	at := time.Now().Add(-48 * time.Hour)
	g.sign("esmcp.jsonl", intent("a-1", at, "751"))
	if _, ok, _ := g.r.Intent(751, time.Now(), 0); ok {
		t.Fatal("an intent of two days ago decided a transaction committed now")
	}
	if _, ok, _ := g.r.Intent(751, at.Add(time.Minute), 0); !ok {
		t.Fatal("the intent of its own transaction is not taken")
	}
}

// Строку с чужой подписью дописал тот, у кого ключа нет: она ничего не
// решает, а людям — тревога forged-receipt, один раз, и после перезапуска
// сборщика тоже один.
func TestForgedReceiptDecidesNothing(t *testing.T) {
	g := newRig(t, "esmcp.jsonl")
	now := time.Now()
	g.sign("esmcp.jsonl", intent("a-1", now, "751"))
	// Подделку дописывает тот, у кого ключа нет: своей цепочкой от имени шлюза.
	_, other, _ := ed25519.GenerateKey(rand.Reader)
	forger, _ := gateway.NewSigner(other, "esmcp", nil)
	line, err := forger.Sign(intent("a-x", now, "999"))
	if err != nil {
		t.Fatal(err)
	}
	f, _ := os.OpenFile(g.cfg.Files[0], os.O_APPEND|os.O_WRONLY, 0)
	f.Write(append(line, '\n'))
	f.Close()
	if _, ok, _ := g.r.Intent(999, now, 0); ok {
		t.Fatal("a forged intent decided a transaction")
	}
	if g.kinds() != alert.KindForgedReceipt || !strings.Contains(g.alerts[0].Signals[0].Detail, "esmcp.jsonl") {
		t.Fatalf("alerts %s %+v", g.kinds(), g.alerts)
	}
	g.open()
	g.r.poll()
	if g.kinds() != alert.KindForgedReceipt {
		t.Fatalf("after a restart: %s", g.kinds())
	}
	// Цепочка шлюза идёт мимо подделки: следующее намерение — его.
	g.sign("esmcp.jsonl", intent("a-2", now, "752"))
	if in, ok, _ := g.r.Intent(752, now, 0); !ok || in.ID != "a-2" {
		t.Fatalf("after a forgery: %+v %v", in, ok)
	}
}

// Исход действия — тревога по его причине; committed и failed — без тревоги,
// отказ за частоту — только с alerted. Каждая — один раз.
func TestOutcomesRaiseAlertsOnce(t *testing.T) {
	g := newRig(t, "esmcp.jsonl")
	g.sign("esmcp.jsonl", intent("a-1", time.Now(), "751"))
	for _, b := range []string{
		`{"outcome":"committed","xid":"751","rows":3}`,
		`{"outcome":"failed","error":"permission denied"}`,
		`{"outcome":"refused","cause":"row-limit","rows":3000,"limit":500,"agent":"bot","reason":"close all"}`,
		`{"outcome":"refused","cause":"rate","actions":30,"limit":30}`,
		`{"outcome":"refused","cause":"rate","actions":30,"limit":30,"alerted":true}`,
		`{"outcome":"refused","cause":"window-rows","rows":400,"window_rows":800,"limit":1000,"window":"10m0s"}`,
		`{"outcome":"failed","cause":"timeout","timeout":"1m0s"}`,
		`{"outcome":"escaped","cause":"escaped","xid":"751","tool":"execute"}`,
		`{"outcome":"unknown","cause":"unknown","xid":"752","rows":3}`,
	} {
		g.sign("esmcp.jsonl", outcome("a-1", b))
	}
	g.r.poll()
	want := []string{
		"would change 3000 rows (the limit for one action is 500)",
		"30 in the last minute (the limit is 30)",
		"would have changed 1200 rows in 10m0s (the limit is 1000)",
		"cancelled an action that ran longer than 1m0s",
		"ended the MCP server's transaction 751 itself",
		"broke during COMMIT of an action (transaction 752, 3 rows): it may be committed",
	}
	if len(g.alerts) != len(want) || g.kinds() != "refused,refused,refused,refused,escaped,commit-unknown" {
		t.Fatalf("alerts %s", g.kinds())
	}
	for i, w := range want {
		if d := g.alerts[i].Signals[0].Detail; !strings.Contains(d, w) {
			t.Errorf("alert %d: %q lacks %q", i+1, d, w)
		}
	}
	if a := g.alerts[0].Action; a == nil || a.ID != "a-1" || a.Gateway != "esmcp" || a.Agent != "bot" || a.Reason != "close all" {
		t.Fatalf("the action of the alert: %+v", a)
	}
	// Перезапуск: тревоги о прочитанном не повторяются, о новом — да.
	g.open()
	g.sign("esmcp.jsonl", outcome("a-2", `{"outcome":"refused","cause":"row-limit","rows":9,"limit":1}`))
	g.r.poll()
	if len(g.alerts) != len(want)+1 {
		t.Fatalf("after a restart: %d alerts", len(g.alerts))
	}
	// Файл заменили (другой inode): о нём тревоги — с начала.
	os.Rename(g.cfg.Files[0], g.cfg.Files[0]+".1")
	g.open()
	g.sign("esmcp.jsonl", outcome("a-3", `{"outcome":"refused","cause":"row-limit","rows":9,"limit":1}`))
	g.r.poll()
	if len(g.alerts) != len(want)+2 {
		t.Fatalf("after the file was replaced: %d alerts", len(g.alerts))
	}
}

// У каждого шлюза свой файл, своя цепочка и свой ключ: намерения — из
// всех, тревоги — каждая один раз, место — у каждого файла своё.
func TestReceiptsOfSeveralGateways(t *testing.T) {
	g := newRig(t, "esmcp.jsonl", "esundo.jsonl")
	now := time.Now()
	g.sign("esmcp.jsonl", intent("a-1", now, "751"))
	g.sign("esundo.jsonl", gateway.Draft{Time: now, Action: "undo-751", Step: alert.StepUndo, Refs: []gateway.Ref{{Source: "postgres", Subject: "760"}}})
	if in, ok, _ := g.r.Intent(760, now, 0); !ok || in.Gateway != "esundo" || in.Step != alert.StepUndo {
		t.Fatalf("the undo: %+v %v", in, ok)
	}
	if in, ok, _ := g.r.Intent(751, now, 0); !ok || in.Gateway != "esmcp" {
		t.Fatalf("the action: %+v %v", in, ok)
	}
	// Исходы обоих — тревоги, каждая один раз; место — у каждого файла своё.
	g.sign("esmcp.jsonl", outcome("a-1", `{"outcome":"refused","cause":"row-limit","rows":9,"limit":1}`))
	g.sign("esundo.jsonl", outcome("undo-751", `{"outcome":"refused","cause":"row-limit","rows":9,"limit":1}`))
	g.r.poll()
	g.open()
	if g.kinds() != "refused,refused" {
		t.Fatalf("alerts %s", g.kinds())
	}
	data, _ := os.ReadFile(filepath.Join(g.dir, ReceiptsState))
	var st receiptsState
	if json.Unmarshal(data, &st) != nil || len(st.Files) != 2 || st.Files[0].Alerted == 0 || st.Files[1].Alerted == 0 {
		t.Fatalf("the state: %s", data)
	}
}

// В памяти — не больше maxIntents последних намерений, причина — не длиннее
// maxReason знаков: сборщик не растёт с файлом квитанций.
func TestIntentsAreBounded(t *testing.T) {
	old := maxIntents
	maxIntents = 3
	t.Cleanup(func() { maxIntents = old })
	g := newRig(t, "esmcp.jsonl")
	now := time.Now()
	for i := 1; i <= 5; i++ {
		g.sign("esmcp.jsonl", intent(fmt.Sprint("a-", i), now, fmt.Sprint(i)))
	}
	g.r.poll()
	if len(g.r.byXID) != 3 || len(g.r.order) != 3 {
		t.Fatalf("%d intents in memory", len(g.r.byXID))
	}
	if _, ok, _ := g.r.Intent(5, now, 0); !ok {
		t.Fatal("the last intent is gone")
	}
	g.sign("esmcp.jsonl", gateway.Draft{Time: now, Action: "a-long", Step: alert.StepIntent, Refs: []gateway.Ref{{Source: "postgres", Subject: "9"}},
		Body: json.RawMessage(`{"reason":"` + strings.Repeat("я", 50000) + `"}`)})
	if in, ok, _ := g.r.Intent(9, now, 0); !ok || len([]rune(in.Reason)) > maxReason+1 {
		t.Fatalf("a reason of %d characters in memory", len([]rune(in.Reason)))
	}
}

// Файла ещё нет — шлюз не писал: намерений нет, ошибки нет; появился —
// читается.
func TestReceiptsFileThatIsNotThereYet(t *testing.T) {
	g := newRig(t, "esmcp.jsonl")
	if _, ok, err := g.r.Intent(1, time.Now(), 0); ok || err != nil {
		t.Fatalf("%v %v", ok, err)
	}
	g.sign("esmcp.jsonl", intent("a-1", time.Now(), "1"))
	if _, ok, err := g.r.Intent(1, time.Now(), 0); !ok || err != nil {
		t.Fatalf("%v %v", ok, err)
	}
}

func (g *rig) raw(file string, data []byte) {
	g.t.Helper()
	f, err := os.OpenFile(filepath.Join(g.dir, file), os.O_APPEND|os.O_WRONLY|os.O_CREATE, 0o640)
	if err != nil {
		g.t.Fatal(err)
	}
	defer f.Close()
	if _, err := f.Write(data); err != nil {
		g.t.Fatal(err)
	}
}

func (g *rig) count(kind string) int {
	n := 0
	for _, e := range g.alerts {
		for _, k := range e.Kinds() {
			if k == kind {
				n++
			}
		}
	}
	return n
}

// intent8 — намерение с номером транзакции и его эпохой (xid8), как пишут
// esmcp и esundo.
func intent8(action string, at time.Time, xid8 uint64) gateway.Draft {
	d := intent(action, at, fmt.Sprint(uint32(xid8)))
	d.Body = json.RawMessage(fmt.Sprintf(`{"agent":"bot","tool":"execute","reason":"tidy","xid8":"%d"}`, xid8))
	return d
}

// Файл квитанций заменили на ходу — logrotate (create) или mv поверх:
// шлюз пишет по пути в новый файл, а сборщик читал старый до перезапуска,
// и каждое действие шлюза шло отпечатком, исходы — без тревог (R2-3, T-1).
func TestReceiptsFileReplacedWhileRunning(t *testing.T) {
	g := newRig(t, "esmcp.jsonl")
	now := time.Now()
	path := g.cfg.Files[0]
	g.sign("esmcp.jsonl", intent("a-1", now, "751"))
	if _, ok, _ := g.r.Intent(751, now, 0); !ok {
		t.Fatal("the first intent")
	}
	// Ротация: старый файл — под другим именем, шлюз пишет в новый.
	if err := os.Rename(path, path+".1"); err != nil {
		t.Fatal(err)
	}
	g.sign("esmcp.jsonl", intent("a-2", now, "752"))
	g.sign("esmcp.jsonl", outcome("a-2", `{"outcome":"refused","cause":"row-limit","rows":9,"limit":1}`))
	if in, ok, _ := g.r.Intent(752, now, 0); !ok || in.ID != "a-2" {
		t.Fatalf("after a rotation: %+v %v", in, ok)
	}
	if g.count(alert.KindRefused) != 1 {
		t.Fatalf("the refusal after a rotation: alerts %s", g.kinds())
	}
	// mv поверх: новый файл собран рядом и переименован на место.
	tmp := path + ".new"
	data, _ := os.ReadFile(path)
	os.WriteFile(tmp, data, 0o640)
	a, err := gateway.Append(tmp, g.keys[path], "esmcp", intent("a-3", now, "753"))
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(tmp, path); err != nil {
		t.Fatal(err)
	}
	if in, ok, _ := g.r.Intent(753, now, 0); !ok || in.Hash != a.Receipt.Hash {
		t.Fatalf("after a file was moved over: %+v %v", in, ok)
	}
	if g.count(alert.KindRefused) != 1 {
		t.Fatalf("the refusal was raised again: alerts %s", g.kinds())
	}
}

// Файл ротировали, пока сборщик стоял, а в старом остались непрочитанные
// намерения: он дочитывается из того же каталога по inode.
func TestReceiptsFileRotatedWhileDown(t *testing.T) {
	g := newRig(t, "esmcp.jsonl")
	now := time.Now()
	path := g.cfg.Files[0]
	g.sign("esmcp.jsonl", intent("a-1", now, "751"))
	g.r.poll()
	g.r.close()
	g.sign("esmcp.jsonl", intent("a-2", now, "752")) // сборщик стоит
	os.Rename(path, path+".1")
	g.sign("esmcp.jsonl", intent("a-3", now, "753"))
	g.open()
	for xid, id := range map[uint32]string{751: "a-1", 752: "a-2", 753: "a-3"} {
		if in, ok, _ := g.r.Intent(xid, now, 0); !ok || in.ID != id {
			t.Errorf("xid %d: %+v %v", xid, in, ok)
		}
	}
}

// Кто пишет в файл без ключа, дописывает мусор: сборщик читал весь прирост
// одним куском (дважды: буфер и копия) и падал на нехватке памяти, по кругу
// при каждом перезапуске; на каждую строку мусора — своя тревога с fsync
// (R2-6, T-2). Теперь — кусками, длинная строка пропускается, тревога одна.
func TestReceiptsReadInBoundedMemory(t *testing.T) {
	g := newRig(t, "esmcp.jsonl")
	now := time.Now()
	g.raw("esmcp.jsonl", append(bytes.Repeat([]byte("x"), 48<<20), '\n'))
	g.raw("esmcp.jsonl", []byte(strings.Repeat("{\"v\":1}\n", 2000)))
	g.sign("esmcp.jsonl", intent("a-1", now, "751"))
	var before, after runtime.MemStats
	runtime.ReadMemStats(&before)
	if in, ok, err := g.r.Intent(751, now, 0); !ok || err != nil || in.ID != "a-1" {
		t.Fatalf("the intent after the garbage: %+v %v %v", in, ok, err)
	}
	runtime.ReadMemStats(&after)
	if got := after.TotalAlloc - before.TotalAlloc; got > 16<<20 {
		t.Fatalf("the reader allocated %d MiB for 48 MiB of garbage", got>>20)
	}
	if g.count(alert.KindForgedReceipt) != 1 || !strings.Contains(g.alerts[0].Signals[0].Detail, "2001 lines ending at bytes") ||
		!strings.Contains(g.alerts[0].Signals[0].Detail, "(1 of them longer than any receipt)") ||
		!strings.Contains(g.alerts[0].Signals[0].Detail, "a gateway died in the middle of writing it, or someone without the key wrote it") {
		t.Fatalf("alerts %s: %+v", g.kinds(), g.alerts)
	}
}

// В памяти — давнее намерение о том же 32-битном xid: оно затеняло свежее,
// уже лежащее на диске, и транзакция шлюза шла отпечатком (R2-9).
func TestStaleIntentDoesNotShadowTheFreshOne(t *testing.T) {
	g := newRig(t, "esmcp.jsonl")
	now := time.Now()
	g.sign("esmcp.jsonl", intent("a-old", now.Add(-48*time.Hour), "751"))
	g.r.poll()
	g.sign("esmcp.jsonl", intent("a-new", now, "751"))
	if in, ok, _ := g.r.Intent(751, now, 0); !ok || in.ID != "a-new" {
		t.Fatalf("%+v %v", in, ok)
	}
}

// Намерение с номером с эпохой (xid8) — только о своей транзакции: тот же
// 32-битный номер другой эпохи (после оборота) — не его, и окно в сутки
// этого не ловило (R2-1).
func TestIntentsByFullXID(t *testing.T) {
	g := newRig(t, "esmcp.jsonl")
	now := time.Now()
	epoch1 := uint64(1) << 32
	g.sign("esmcp.jsonl", intent8("a-1", now, epoch1+751))
	g.r.setRef(epoch1 + 900) // база выдаст следующим номер эпохи 1
	if in, ok, _ := g.r.Intent(751, now, 0); !ok || in.ID != "a-1" {
		t.Fatalf("the intent of its own transaction: %+v %v", in, ok)
	}
	g.sign("esmcp.jsonl", intent8("a-2", now, epoch1+1000))
	g.r.poll()
	g.r.setRef(2*epoch1 + 2000) // оборот: номер 1000 занят заново в эпохе 2
	if _, ok, _ := g.r.Intent(1000, now, 0); ok {
		t.Fatal("the intent of epoch 1 was taken for a transaction of epoch 2")
	}
	if got := fullXID(2*epoch1+5, 4294967290); got != epoch1+4294967290 {
		t.Fatalf("fullXID across an epoch: %d", got)
	}
}

// База ушла назад (поднята из копии): намерения, дописанные до того, не в
// счёт — их номера она выдаст снова чужим транзакциям (R2-1, T-7). Так же
// после перезапуска сборщика и после того, как файл переписали на месте.
func TestVoidedIntentsStayVoid(t *testing.T) {
	g := newRig(t, "esmcp.jsonl")
	now := time.Now()
	g.sign("esmcp.jsonl", intent("a-1", now, "751"))
	if err := g.r.void(voidSpec{}); err != nil {
		t.Fatal(err)
	}
	if _, ok, _ := g.r.Intent(751, now, 0); ok {
		t.Fatal("a voided intent decided a transaction")
	}
	g.sign("esmcp.jsonl", intent("a-2", now.Add(time.Second), "752")) // время шлюза — после подъёма
	check := func(when string) {
		t.Helper()
		if _, ok, _ := g.r.Intent(751, now, 0); ok {
			t.Fatalf("%s: a voided intent decided a transaction", when)
		}
		if in, ok, _ := g.r.Intent(752, now, 0); !ok || in.ID != "a-2" {
			t.Fatalf("%s: the intent after the void: %+v %v", when, in, ok)
		}
	}
	check("now")
	g.open()
	check("after a restart")
	data, _ := os.ReadFile(g.cfg.Files[0])
	f, _ := os.OpenFile(g.cfg.Files[0], os.O_WRONLY|os.O_TRUNC, 0)
	f.Write(data)
	f.Close()
	g.r.poll()
	check("after the file was rewritten in place")
}

// Обрезка хвоста файла квитанций: читатель перечитывал файл с начала с
// местом тревог 0 — каждый прежний отказ поднимал тревогу снова (T-6а);
// намерение, дописанное шлюзом до того, как сборщик заметил обрезку,
// читалось с середины, и транзакция шла отпечатком (T-6б).
func TestTruncatedReceiptsFile(t *testing.T) {
	g := newRig(t, "esmcp.jsonl")
	now := time.Now()
	path := g.cfg.Files[0]
	for i := range 3 {
		g.sign("esmcp.jsonl", outcome(fmt.Sprintf("a-%d", i), `{"outcome":"refused","cause":"row-limit","rows":9,"limit":1}`))
	}
	g.r.poll()
	if g.count(alert.KindRefused) != 3 {
		t.Fatalf("alerts %s", g.kinds())
	}
	fi, _ := os.Stat(path)
	os.Truncate(path, fi.Size()-20)
	g.sign("esmcp.jsonl", intent("a-d", now, "760")) // раньше, чем сборщик перечитал
	if in, ok, _ := g.r.Intent(760, now, 0); !ok || in.ID != "a-d" {
		t.Fatalf("the intent after the truncation: %+v %v", in, ok)
	}
	if g.count(alert.KindRefused) != 3 {
		t.Fatalf("the old refusals were raised again: alerts %s", g.kinds())
	}
	// Состояние прежней версии (тревоги — по месту в файле): после
	// обновления старые тревоги не повторяются.
	os.WriteFile(filepath.Join(g.dir, ReceiptsState), []byte(fmt.Sprintf(`{"files":[{"file":%q,"inode":%d,"alerted":%d}]}`, path, inodeOfPath(t, path), fileSize(t, path))), 0o600)
	g.alerts = nil
	g.open()
	os.Truncate(path, fileSize(t, path)-5)
	g.sign("esmcp.jsonl", outcome("a-e", `{"outcome":"refused","cause":"row-limit","rows":9,"limit":1}`))
	g.r.poll()
	if g.count(alert.KindRefused) != 1 {
		t.Fatalf("after an upgrade and a truncation: alerts %s", g.kinds())
	}
}

func fileSize(t *testing.T, path string) int64 {
	fi, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	return fi.Size()
}

func inodeOfPath(t *testing.T, path string) uint64 {
	ino, ok := pathInode(path)
	if !ok {
		t.Fatal("no file")
	}
	return ino
}

// Намерение решает одну транзакцию: другая с тем же номером и другим местом
// фиксации — не его (база поднята из копии и выдала номер снова, R2-1);
// повтор той же транзакции (сервер шлёт её снова после обрыва) — его. И после
// перезапуска сборщика.
func TestIntentDecidesOneTransaction(t *testing.T) {
	g := newRig(t, "esmcp.jsonl")
	now := time.Now()
	g.sign("esmcp.jsonl", intent("a-1", now, "751"))
	if _, ok, _ := g.r.Intent(751, now, 0x1000); !ok {
		t.Fatal("the transaction of the intent")
	}
	if _, ok, _ := g.r.Intent(751, now, 0x1000); !ok {
		t.Fatal("the same transaction sent again")
	}
	if _, ok, _ := g.r.Intent(751, now, 0x2000); ok {
		t.Fatal("another transaction with the same number took the intent")
	}
	g.open()
	if _, ok, _ := g.r.Intent(751, now, 0x2000); ok {
		t.Fatal("after a restart, another transaction with the same number took the intent")
	}
	if _, ok, _ := g.r.Intent(751, now, 0x1000); !ok {
		t.Fatal("after a restart, the same transaction sent again")
	}
	// Свежее намерение о том же номере — для своей транзакции.
	g.sign("esmcp.jsonl", intent("a-2", now, "751"))
	if in, ok, _ := g.r.Intent(751, now, 0x2000); !ok || in.ID != "a-2" {
		t.Fatalf("a fresh intent for the number: %+v %v", in, ok)
	}
}

// T-2 второго захода: писатель файла без ключа вынимает строку намерения,
// пока идёт SQL агента. Транзакция ляжет отпечатком; людям — тревога о
// пропуске в цепочке и об исходе без намерения.
func TestRemovedIntentIsSeen(t *testing.T) {
	g := newRig(t, "esmcp.jsonl")
	now := time.Now()
	path := g.cfg.Files[0]
	g.sign("esmcp.jsonl", intent("a-1", now, "750"))
	g.sign("esmcp.jsonl", outcome("a-1", `{"outcome":"committed","xid":"750","rows":1}`))
	g.r.poll()
	before, _ := os.ReadFile(path)
	g.sign("esmcp.jsonl", intent("a-2", now, "751"))
	if err := os.WriteFile(path, before, 0o600); err != nil { // намерение вынуто
		t.Fatal(err)
	}
	if _, ok, err := g.r.Intent(751, now, 0x751); ok || err != nil {
		t.Fatalf("an intent removed from the file: %v %v", ok, err)
	}
	g.sign("esmcp.jsonl", outcome("a-2", `{"outcome":"committed","xid":"751","rows":1}`))
	g.r.poll()
	if g.kinds() != "receipts-gap,intent-missing" {
		t.Fatalf("alerts %s", g.kinds())
	}
	if d := g.alerts[0].Signals[0].Detail; !strings.Contains(d, "seq 4 follows its seq 2") || !strings.Contains(d, "1 receipts between them") {
		t.Errorf("the gap: %s", d)
	}
	if d := g.alerts[1].Signals[0].Detail; !strings.Contains(d, `action "a-2"`) || !strings.Contains(d, "transaction 751 went as a fingerprint") {
		t.Errorf("the outcome without its intent: %s", d)
	}
	// Копии исхода, дописанные без ключа, тревоги не повторяют.
	data, _ := os.ReadFile(path)
	lines := bytes.Split(bytes.TrimRight(data, "\n"), []byte("\n"))
	f, _ := os.OpenFile(path, os.O_APPEND|os.O_WRONLY, 0)
	for range 3 {
		f.Write(append(bytes.Clone(lines[len(lines)-1]), '\n'))
	}
	f.Close()
	g.r.poll()
	if len(g.alerts) != 2 {
		t.Fatalf("copies of the outcome: %s", g.kinds())
	}
	// Перезапуск: о прочитанном — не снова.
	g.open()
	g.r.poll()
	if len(g.alerts) != 2 {
		t.Fatalf("after a restart: %s", g.kinds())
	}
}

// T-6 второго захода: пока сборщик стоял, файл квитанций повернули и
// прежний сжали — недочитанные намерения в нём. Пропуск виден по цепочке,
// которую сборщик помнит с прошлого запуска.
func TestRotatedAwayWhileStoppedIsSeen(t *testing.T) {
	g := newRig(t, "esmcp.jsonl")
	now := time.Now()
	path := g.cfg.Files[0]
	g.sign("esmcp.jsonl", intent("a-1", now, "750"))
	g.r.poll()
	g.r.close()
	g.sign("esmcp.jsonl", intent("a-2", now, "751")) // сборщик стоит
	if err := os.Rename(path, path+".1.gz"); err != nil {
		t.Fatal(err)
	}
	os.WriteFile(path+".1.gz", []byte("compressed"), 0o600) // сжат: другой inode, не квитанции
	g.sign("esmcp.jsonl", intent("a-3", now, "752"))
	g.open()
	g.r.poll()
	if g.kinds() != "receipts-gap" {
		t.Fatalf("alerts %s", g.kinds())
	}
	if _, ok, _ := g.r.Intent(752, now, 0x752); !ok {
		t.Fatal("the intent after the gap is not read")
	}
}

// Копии прежних строк и начала цепочки, дописанные без ключа, — не пропуск;
// у двух цепочек с одним именем (два esmcp, свои файлы и ключи) — у каждой
// своя сцепка.
func TestCopiesAreNotAGap(t *testing.T) {
	g := newRig(t, "esmcp.jsonl")
	now := time.Now()
	path := g.cfg.Files[0]
	var lines [][]byte
	for i := 1; i <= 3; i++ {
		lines = append(lines, g.append("esmcp.jsonl", intent(fmt.Sprint("a-", i), now, fmt.Sprint(750+i))).Line)
	}
	f, _ := os.OpenFile(path, os.O_APPEND|os.O_WRONLY, 0)
	for _, l := range lines { // копии и последней прочитанной
		f.Write(append(bytes.TrimRight(l, "\n"), '\n'))
	}
	f.Close()
	g.sign("esmcp.jsonl", intent("a-4", now, "754"))
	g.r.poll()
	if len(g.alerts) != 0 {
		t.Fatalf("copies raised %s", g.kinds())
	}
}

// Намерение прочитано до перезапуска, а файл с ним с тех пор повернули и
// сжали: транзакция уже лежит в справочнике этим действием — исход без
// намерения в нынешнем файле не тревога.
func TestOutcomeOfARecordedActionIsNotMissing(t *testing.T) {
	g := newRig(t, "esmcp.jsonl")
	line := `{"xid":751,"first_seq":1,"last_seq":1,"changes":1,"action":{"id":"a-2","gateway":"esmcp","seq":3}}` + "\n"
	if err := os.WriteFile(filepath.Join(g.dir, pgtap.IndexFile), []byte(line), 0o600); err != nil {
		t.Fatal(err)
	}
	g.sign("esmcp.jsonl", outcome("a-2", `{"outcome":"committed","xid":"751","rows":1}`))
	g.sign("esmcp.jsonl", outcome("a-3", `{"outcome":"committed","xid":"752","rows":1}`))
	g.r.poll()
	if g.kinds() != "intent-missing" || !strings.Contains(g.alerts[0].Signals[0].Detail, `"a-3"`) {
		t.Fatalf("alerts %s", g.kinds())
	}
}

// Вторая ветвь цепочки: квитанция с seq за последней прочитанной, но её prev
// — не эта квитанция (шлюз потерял голову и пошёл от прежнего места, или
// строку принесли из другой ветви) — тоже пропуск.
func TestSecondBranchIsSeen(t *testing.T) {
	g := newRig(t, "esmcp.jsonl")
	now := time.Now()
	path := g.cfg.Files[0]
	key := g.keys[path]
	other := filepath.Join(g.dir, "branch.jsonl")
	for i := 1; i <= 2; i++ {
		g.sign("esmcp.jsonl", intent(fmt.Sprint("a-", i), now, fmt.Sprint(750+i)))
	}
	data, _ := os.ReadFile(path)
	head, _ := os.ReadFile(path + ".head")
	os.WriteFile(other, data, 0o600)
	var h gateway.Head
	json.Unmarshal(head, &h)
	h.Receipts = other
	head, _ = json.Marshal(h)
	os.WriteFile(other+".head", head, 0o600)
	g.sign("esmcp.jsonl", intent("a-3", now, "753"))
	var b4 gateway.Appended
	for i := 3; i <= 4; i++ {
		a, err := gateway.AppendHead(other, other+".head", key, "esmcp", intent(fmt.Sprint("b-", i), now, fmt.Sprint(850+i)))
		if err != nil {
			t.Fatal(err)
		}
		b4 = a
	}
	if b4.Receipt.Seq != 4 {
		t.Fatalf("the branch is at seq %d", b4.Receipt.Seq)
	}
	g.r.poll()
	f, _ := os.OpenFile(path, os.O_APPEND|os.O_WRONLY, 0)
	f.Write(append(bytes.TrimRight(b4.Line, "\n"), '\n'))
	f.Close()
	g.r.poll()
	if g.kinds() != "receipts-gap" || !strings.Contains(g.alerts[0].Signals[0].Detail, "names another one before it") {
		t.Fatalf("alerts %s", g.kinds())
	}
}

// void с границей (запуск поднятой базы): намерения без отметки базы — все
// прочитанные до подъёма (их время — по часам шлюза, с запуском базы его не
// сравнить, T-3 третьего захода), и копия старого, дописанная позже, тоже;
// дописанные после — в счёте.
func TestVoidSinceKeepsLaterIntents(t *testing.T) {
	g := newRig(t, "esmcp.jsonl")
	t0 := time.Now().Add(-time.Minute)
	old := g.append("esmcp.jsonl", intent("a-1", t0, "751")).Line
	g.r.poll()
	since := t0.Add(10 * time.Second)
	g.sign("esmcp.jsonl", intent("a-2", since.Add(time.Second), "752")) // часы шлюза впереди: «после запуска», а писалось до подъёма
	if err := g.r.void(voidSpec{since: since}); err != nil {
		t.Fatal(err)
	}
	for xid, at := range map[uint32]time.Time{751: t0, 752: since.Add(2 * time.Second)} {
		if _, ok, _ := g.r.Intent(xid, at, uint64(xid)); ok {
			t.Errorf("an intent without the database's start, read before the void, decides transaction %d", xid)
		}
	}
	g.sign("esmcp.jsonl", intent("a-3", since.Add(3*time.Second), "753")) // после подъёма
	if _, ok, _ := g.r.Intent(753, since.Add(4*time.Second), 0x753); !ok {
		t.Fatal("an intent written after the void is void")
	}
	f, _ := os.OpenFile(g.cfg.Files[0], os.O_APPEND|os.O_WRONLY, 0)
	f.Write(append(bytes.TrimRight(old, "\n"), '\n')) // копия старого намерения, дописанная без ключа
	f.Close()
	if _, ok, _ := g.r.Intent(751, t0, 0x751); ok {
		t.Fatal("a copy of a voided intent, appended later, decides a transaction")
	}
	g.open() // и после перезапуска
	if _, ok, _ := g.r.Intent(751, t0, 0x751); ok {
		t.Fatal("after a restart a voided intent decides a transaction")
	}
	if _, ok, _ := g.r.Intent(753, since.Add(4*time.Second), 0x753); !ok {
		t.Fatal("after a restart the intent written after the void is void")
	}
}

// R2-1, R2-2 третьего захода: намерение с отметкой базы (db_started) снимается
// по ней, в часах базы: из прежней истории — даже с часами шлюза впереди; из
// новой — даже если поднятую базу потом перезапустили. Намерение с номером,
// которого поднятая база ещё не выдавала, — из прежней истории.
func TestVoidByTheDatabaseStart(t *testing.T) {
	g := newRig(t, "esmcp.jsonl")
	now := time.Now()
	oldStart, place, newStart, restart := now.Add(-time.Hour), now.Add(-10*time.Minute), now.Add(-5*time.Minute), now.Add(-time.Minute)
	marked := func(id string, gw time.Time, xid string, started time.Time, xid8 uint64) gateway.Draft {
		d := intent(id, gw, xid)
		d.Body = json.RawMessage(fmt.Sprintf(`{"agent":"bot","tool":"execute","xid8":"%d","db_started":"%d"}`, xid8, started.UnixMicro()))
		return d
	}
	g.sign("esmcp.jsonl", marked("old", now.Add(time.Hour), "751", oldStart, 751)) // прежняя история, часы шлюза впереди
	g.sign("esmcp.jsonl", marked("new", newStart, "752", newStart, 752))           // новая история, до перезапуска
	ahead := intent("ahead", now, "799")                                           // без отметки базы, номер, которого база ещё не выдавала
	ahead.Body = json.RawMessage(`{"agent":"bot","tool":"execute","xid8":"799"}`)
	g.sign("esmcp.jsonl", ahead)
	if err := g.r.void(voidSpec{since: restart, startedBefore: place.UnixMicro()}); err != nil {
		t.Fatal(err)
	}
	if _, ok, _ := g.r.Intent(751, now.Add(time.Hour), 0x751); ok {
		t.Error("an intent of the history before the restore, with the gateway's clock ahead, decides a transaction")
	}
	if _, ok, _ := g.r.Intent(752, newStart.Add(time.Second), 0x752); !ok {
		t.Error("an intent made in the restored database before its restart is void")
	}
	if _, ok, _ := g.r.Intent(799, now, 0x799); ok {
		t.Error("an intent with a transaction number the restored database has not given yet decides a transaction")
	}
	g.sign("esmcp.jsonl", marked("late", now.Add(2*time.Hour), "753", oldStart, 753)) // прежней истории, прочитано позже
	if _, ok, _ := g.r.Intent(753, now.Add(2*time.Hour), 0x753); ok {
		t.Error("an intent of the history before the restore, read after the void, decides a transaction")
	}
	g.open() // и после перезапуска сборщика
	if _, ok, _ := g.r.Intent(751, now.Add(time.Hour), 0x751); ok {
		t.Error("after a restart the intent of the history before the restore decides a transaction")
	}
	if _, ok, _ := g.r.Intent(752, newStart.Add(time.Second), 0x752); !ok {
		t.Error("after a restart the intent made in the restored database is void")
	}
	if _, ok, _ := g.r.Intent(799, now, 0x799); ok {
		t.Error("after a restart the intent with a number the restored database had not given decides a transaction")
	}
}

// T-2 третьего захода: писатель файла без ключа вынимает намерение, пока
// идёт действие, а после того как сборщик прочёл транзакцию, возвращает те
// же байты на то же место. Пропуска в цепочке нет, исход — за намерением; а
// транзакция легла отпечатком — тревога.
func TestIntentPutBackAfterItsTransactionIsSeen(t *testing.T) {
	g := newRig(t, "esmcp.jsonl")
	now := time.Now()
	path := g.cfg.Files[0]
	g.sign("esmcp.jsonl", intent("a-1", now, "750"))
	g.r.poll()
	before, _ := os.ReadFile(path)
	line := g.append("esmcp.jsonl", intent("a-2", now, "751")).Line
	if err := os.WriteFile(path, before, 0o600); err != nil { // вынуто
		t.Fatal(err)
	}
	if _, ok, _ := g.r.Intent(751, now.Add(time.Second), 0x751); ok {
		t.Fatal("the removed intent was found")
	}
	f, _ := os.OpenFile(path, os.O_APPEND|os.O_WRONLY, 0)
	f.Write(append(bytes.TrimRight(line, "\n"), '\n')) // возвращено на то же место
	f.Close()
	g.sign("esmcp.jsonl", outcome("a-2", `{"outcome":"committed","xid":"751","rows":1}`))
	g.r.poll()
	if g.kinds() != "intent-missing" || !strings.Contains(g.alerts[0].Signals[0].Detail, "only after the collector had read the transaction") {
		t.Fatalf("alerts %s", g.kinds())
	}
}

// Состояние прежней версии (до третьего захода) помнило обработанные исходы
// местом в файле, а не хэшем: при обновлении исходы до этого места —
// обработаны, тревоги о них не повторяются; о дописанных после — да.
func TestStateOfThePreviousVersionKeepsItsAlerts(t *testing.T) {
	g := newRig(t, "esmcp.jsonl")
	g.sign("esmcp.jsonl", outcome("a-1", `{"outcome":"refused","cause":"row-limit","rows":9,"limit":1}`))
	g.sign("esmcp.jsonl", outcome("a-2", `{"outcome":"escaped","cause":"escaped","xid":"751","tool":"execute"}`))
	g.r.close()
	g.r = nil
	path := g.cfg.Files[0]
	old := fmt.Sprintf(`{"version":2,"files":[{"file":%q,"inode":%d,"alerted":%d}]}`, path, inodeOfPath(t, path), fileSize(t, path))
	if err := os.WriteFile(filepath.Join(g.dir, ReceiptsState), []byte(old), 0o600); err != nil {
		t.Fatal(err)
	}
	os.Remove(filepath.Join(g.dir, ReceiptsAlerted))
	g.open()
	if len(g.alerts) != 0 {
		t.Fatalf("the alerts of the previous version came again: %s", g.kinds())
	}
	g.sign("esmcp.jsonl", outcome("a-3", `{"outcome":"refused","cause":"row-limit","rows":9,"limit":1}`))
	g.r.poll()
	g.open() // и после перезапуска уже новой версии — без повторов
	if g.kinds() != "refused" {
		t.Fatalf("after the upgrade: %s", g.kinds())
	}
}

// Шлюз потерял голову, файл повернули: цепочка пошла заново (вторая ветвь).
// Копия квитанции прежней ветви — seq выше, время старше прочитанного —
// место цепочки не двигает: иначе пропуски новой ветви до её seq не были бы
// видны (P-381).
func TestCopyFromAnOldBranchDoesNotMoveTheChain(t *testing.T) {
	g := newRig(t, "esmcp.jsonl")
	path := g.cfg.Files[0]
	base := time.Now().Add(-time.Hour)
	at := func(s int) time.Time { return base.Add(time.Duration(s) * time.Second) }
	var old []byte
	for i := 1; i <= 5; i++ {
		old = g.append("esmcp.jsonl", intent(fmt.Sprint("a-", i), at(i), fmt.Sprint(750+i))).Line
	}
	g.r.poll()
	os.Remove(path + ".head")
	os.Rename(path, path+".1")
	for i := 1; i <= 2; i++ {
		g.sign("esmcp.jsonl", intent(fmt.Sprint("b-", i), at(10+i), fmt.Sprint(850+i)))
	}
	g.r.poll()
	f, _ := os.OpenFile(path, os.O_APPEND|os.O_WRONLY, 0)
	f.Write(append(bytes.TrimRight(old, "\n"), '\n')) // копия прежней пятой
	f.Close()
	g.r.poll()
	if len(g.alerts) != 0 {
		t.Fatalf("before the gap: %s", g.kinds())
	}
	// Новая ветвь дальше: третья прочитана, четвёртую вынули, пятая — за ней.
	g.sign("esmcp.jsonl", intent("b-3", at(13), "853"))
	g.r.poll()
	size := fileSize(t, path)
	g.sign("esmcp.jsonl", intent("b-4", at(14), "854"))
	if err := os.Truncate(path, size); err != nil {
		t.Fatal(err)
	}
	g.sign("esmcp.jsonl", intent("b-5", at(15), "855"))
	g.r.poll()
	if g.kinds() != "receipts-gap" || !strings.Contains(g.alerts[0].Signals[0].Detail, "with seq 5 follows its seq 3") {
		t.Fatalf("alerts %s", g.kinds())
	}
}

// Дыру разреженного файла квитанций (truncate -s +32G места не занимает)
// сборщик перешагивает, а не читает: минуты простоя потока на каждом
// чтении — и в хвосте файла, и посреди, когда за ней дописали. Намерения за
// дырами находятся, а сами нули — строка без подписи: тревога, как о любой
// такой строке (P-378).
func TestHoleInTheReceiptsFileIsSteppedOver(t *testing.T) {
	g := newRig(t, "esmcp.jsonl")
	path := g.cfg.Files[0]
	now := time.Now()
	g.sign("esmcp.jsonl", intent("a-1", now, "751"))
	g.r.poll()
	hole := func() {
		if err := os.Truncate(path, fileSize(t, path)+32<<30); err != nil {
			t.Fatal(err)
		}
	}
	start := time.Now()
	hole()
	g.r.poll() // хвост — одна дыра
	g.sign("esmcp.jsonl", intent("a-2", now, "752"))
	hole()
	g.sign("esmcp.jsonl", intent("a-3", now, "753")) // дыра посреди: за ней намерение
	in, ok, err := g.r.Intent(753, now, 0)
	if took := time.Since(start); took > time.Second {
		t.Fatalf("the holes were read: %v", took)
	}
	if err != nil || !ok || in.ID != "a-3" {
		t.Fatalf("the intent after the hole: %+v %v %v", in, ok, err)
	}
	if in, ok, _ := g.r.Intent(752, now, 0); !ok || in.ID != "a-2" || !strings.HasPrefix(g.kinds(), "forged-receipt") {
		t.Fatalf("the intent between the holes: %+v %v, alerts %s", in, ok, g.kinds())
	}
}
