package pginput

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Nikolay1994Kaz/evidencestore/internal/alert"
	"github.com/Nikolay1994Kaz/evidencestore/internal/gateway"
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
	path := filepath.Join(g.dir, file)
	a, err := gateway.Append(path, g.keys[path], strings.TrimSuffix(file, ".jsonl"), d)
	if err != nil {
		g.t.Fatal(err)
	}
	return a.Receipt
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
	in, ok, err := g.r.Intent(751, now)
	if err != nil || !ok || in.ID != "a-1" || in.Gateway != "esmcp" || in.Seq != 1 || in.Hash != rc.Hash || in.Agent != "bot" || in.Reason != "tidy" {
		t.Fatalf("%+v %v %v", in, ok, err)
	}
	for _, xid := range []uint32{752, 753} {
		if _, ok, err := g.r.Intent(xid, now); ok || err != nil {
			t.Fatalf("xid %d: found %v, %v", xid, ok, err)
		}
	}
	g.sign("esmcp.jsonl", intent("a-3", now, "753"))
	if in, ok, _ := g.r.Intent(753, now); !ok || in.ID != "a-3" {
		t.Fatalf("an intent written after the open: %+v %v", in, ok)
	}
	// Откат — тоже намерение, шагом undo; что он возвращает — из тела.
	g.sign("esmcp.jsonl", gateway.Draft{Time: now, Action: "u-1", Step: alert.StepUndo, Refs: []gateway.Ref{{Source: "postgres", Subject: "754"}},
		Body: json.RawMessage(`{"undoes":"a-1"}`)})
	if in, ok, _ := g.r.Intent(754, now); !ok || in.Step != alert.StepUndo || in.Undoes != "a-1" {
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
	if _, ok, _ := g.r.Intent(751, time.Now()); ok {
		t.Fatal("an intent of two days ago decided a transaction committed now")
	}
	if _, ok, _ := g.r.Intent(751, at.Add(time.Minute)); !ok {
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
	if _, ok, _ := g.r.Intent(999, now); ok {
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
	if in, ok, _ := g.r.Intent(752, now); !ok || in.ID != "a-2" {
		t.Fatalf("after a forgery: %+v %v", in, ok)
	}
}

// Исход действия — тревога по его причине; committed и failed — без тревоги,
// отказ за частоту — только с alerted. Каждая — один раз.
func TestOutcomesRaiseAlertsOnce(t *testing.T) {
	g := newRig(t, "esmcp.jsonl")
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
	if in, ok, _ := g.r.Intent(760, now); !ok || in.Gateway != "esundo" || in.Step != alert.StepUndo {
		t.Fatalf("the undo: %+v %v", in, ok)
	}
	if in, ok, _ := g.r.Intent(751, now); !ok || in.Gateway != "esmcp" {
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
	if _, ok, _ := g.r.Intent(5, now); !ok {
		t.Fatal("the last intent is gone")
	}
	g.sign("esmcp.jsonl", gateway.Draft{Time: now, Action: "a-long", Step: alert.StepIntent, Refs: []gateway.Ref{{Source: "postgres", Subject: "9"}},
		Body: json.RawMessage(`{"reason":"` + strings.Repeat("я", 50000) + `"}`)})
	if in, ok, _ := g.r.Intent(9, now); !ok || len([]rune(in.Reason)) > maxReason+1 {
		t.Fatalf("a reason of %d characters in memory", len([]rune(in.Reason)))
	}
}

// Файла ещё нет — шлюз не писал: намерений нет, ошибки нет; появился —
// читается.
func TestReceiptsFileThatIsNotThereYet(t *testing.T) {
	g := newRig(t, "esmcp.jsonl")
	if _, ok, err := g.r.Intent(1, time.Now()); ok || err != nil {
		t.Fatalf("%v %v", ok, err)
	}
	g.sign("esmcp.jsonl", intent("a-1", time.Now(), "1"))
	if _, ok, err := g.r.Intent(1, time.Now()); !ok || err != nil {
		t.Fatalf("%v %v", ok, err)
	}
}
