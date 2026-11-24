package alert

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
	"unicode/utf8"
)

// hook — получатель тревог: помнит принятые запросы; fail — столько
// следующих запросов отклонить ответом reject.
type hook struct {
	mu     sync.Mutex
	srv    *httptest.Server
	got    []call // принятые (ответ 200)
	tried  []time.Time
	fail   int
	reject func(w http.ResponseWriter)
}

type call struct {
	path string
	body map[string]any
}

func newHook(t *testing.T) *hook {
	h := &hook{reject: func(w http.ResponseWriter) { http.Error(w, "down", http.StatusBadGateway) }}
	h.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		raw, _ := io.ReadAll(r.Body)
		h.mu.Lock()
		defer h.mu.Unlock()
		h.tried = append(h.tried, time.Now())
		if h.fail != 0 {
			if h.fail > 0 {
				h.fail--
			}
			h.reject(w)
			return
		}
		var body map[string]any
		if err := json.Unmarshal(raw, &body); err != nil || r.Method != http.MethodPost || r.Header.Get("Content-Type") != "application/json" {
			http.Error(w, "bad request", http.StatusBadRequest)
			return
		}
		h.got = append(h.got, call{r.URL.Path, body})
		w.Write([]byte(`{"ok":true,"result":{}}`))
	}))
	t.Cleanup(h.srv.Close)
	return h
}

func (h *hook) calls() []call {
	h.mu.Lock()
	defer h.mu.Unlock()
	return append([]call(nil), h.got...)
}

func (h *hook) texts() []string {
	var out []string
	for _, c := range h.calls() {
		out = append(out, c.body["text"].(string))
	}
	return out
}

func (h *hook) setFail(n int) {
	h.mu.Lock()
	h.fail = n
	h.mu.Unlock()
}

func waitFor(t *testing.T, what string, ok func() bool) {
	t.Helper()
	for deadline := time.Now().Add(10 * time.Second); !ok(); {
		if time.Now().After(deadline) {
			t.Fatalf("not within 10 s: %s", what)
		}
		time.Sleep(2 * time.Millisecond)
	}
}

// rig — файл тревог и доставка одному получателю.
type rig struct {
	t   *testing.T
	dir string
	log *Log
	n   *Notifier
	out *syncWriter // журнал доставки
}

func newRig(t *testing.T, dir string, targets ...Target) *rig {
	t.Helper()
	l, err := OpenLog(filepath.Join(dir, "alerts.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	r := &rig{t: t, dir: dir, log: l, out: &syncWriter{}}
	r.start(targets...)
	t.Cleanup(func() { r.stop(); l.Close() })
	return r
}

type syncWriter struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (w *syncWriter) Write(p []byte) (int, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.b.Write(p)
}

func (r *rig) start(targets ...Target) {
	r.t.Helper()
	if err := ValidateTargets(targets); err != nil {
		r.t.Fatal(err)
	}
	n, err := Start(Options{File: r.log.Path(), Dir: r.dir, Targets: targets,
		Text: TextOptions{Title: "database shop", UndoHint: "esundo check -config undo.json -xid {xid}"},
		Pace: time.Millisecond, Poll: 20 * time.Millisecond, Retry: 5 * time.Millisecond},
		slog.New(slog.NewTextHandler(r.out, nil)))
	if err != nil {
		r.t.Fatal(err)
	}
	r.n = n
	r.log.OnAppend(n.Wake)
}

func (r *rig) stop() {
	if r.n != nil {
		r.n.Close()
		r.n = nil
	}
}

func (r *rig) raise(xid uint32, kind, detail string) {
	r.t.Helper()
	e := Event{XID: xid}
	e.Add(kind, detail)
	if err := r.log.Append(e); err != nil {
		r.t.Fatal(err)
	}
}

func txEvent() Event {
	e := Event{XID: 749, Changes: 1173, FirstSeq: 3, LastSeq: 4,
		Tables: map[string]Counts{"public.accounts": {U: 667, D: 1}, "public.orders": {I: 1, D: 504}, "public.docs": {U: 1}},
		Action: &Action{ID: "20261121T142008Z-11ad", Gateway: "esmcp", Seq: 41, Step: StepIntent, Agent: "support-bot", Reason: "close inactive accounts"},
	}
	e.Add(KindCanary, "public.accounts: the canary row id=3 was touched (U)")
	e.Add(KindCanary, "public.accounts: the canary row id=3 was touched (U)") // тот же оператор тронул её дважды
	e.Add(KindMassChange, "1173 row changes in one transaction (the threshold is 500)")
	return e
}

// Одно сообщение на транзакцию: все поводы, кто, какое действие, сколько строк
// и готовая команда — посмотреть откат.
func TestTextOfATransactionAlert(t *testing.T) {
	got := Text(txEvent(), TextOptions{Title: "database shop", UndoHint: "esundo check -config undo.json -xid {xid}"})
	want := strings.Join([]string{
		"evidencestore, database shop: agent transaction 749",
		"• canary: public.accounts: the canary row id=3 was touched (U)",
		"• mass-change: 1173 row changes in one transaction (the threshold is 500)",
		`action: 20261121T142008Z-11ad, agent support-bot (receipt 41 of gateway esmcp) — reason given: "close inactive accounts"`,
		"changed: 1173 rows — public.accounts (updated 667, deleted 1); public.orders (inserted 1, deleted 504); public.docs (updated 1)",
		"store records: 3–4",
		"undo preview: esundo check -config undo.json -xid 749",
	}, "\n")
	if got != want {
		t.Fatalf("text:\n%s\nwant:\n%s", got, want)
	}
	// Служебное событие — без транзакции и без команды отката.
	down := Event{}
	down.Add(KindDBDown, "no connection to the database for 1m0s")
	if got := Text(down, TextOptions{Title: "database shop", UndoHint: "x {xid}"}); got != "evidencestore, database shop\n• db-down: no connection to the database for 1m0s" {
		t.Fatalf("service text: %q", got)
	}
	// Откат откатом не предлагается; отпечаток — тоже: строк в хранилище нет.
	undo := txEvent()
	undo.Action = &Action{ID: "u-1", Gateway: "esundo", Seq: 2, Step: StepUndo, Undoes: "20261121T142008Z-11ad"}
	fp := Event{XID: 5, Fingerprint: true, FirstSeq: 7, LastSeq: 7}
	fp.Add(KindMassChange, "…")
	for _, e := range []Event{undo, fp} {
		if strings.Contains(Text(e, TextOptions{UndoHint: "esundo {xid}"}), "undo preview") {
			t.Fatalf("an undo is offered for %+v", e)
		}
	}
	// Сотни таблиц и поводов, длинные имена и причины: сообщение короче
	// предела Telegram (4096 знаков) и всё равно доходит до команды отката.
	big := txEvent()
	for i := 0; i < 300; i++ {
		big.Tables[fmt.Sprintf("schema_%d.%s", i, strings.Repeat("t", 600))] = Counts{U: 1000 + i}
		big.Add(KindCanary, fmt.Sprint(i)+strings.Repeat("ж", 900))
	}
	big.Action = &Action{ID: "a1", Gateway: "esmcp", Step: StepIntent, Reason: strings.Repeat("because ", 500)}
	text := Text(big, TextOptions{UndoHint: "esundo check -xid {xid}"})
	for _, want := range []string{"and 294 more signals", "store records: 3–4\nundo preview: esundo check -xid 749"} {
		if !strings.Contains(text, want) {
			t.Fatalf("the long alert lacks %q", want)
		}
	}
	wide := txEvent()
	for i := 0; i < 300; i++ {
		wide.Tables[fmt.Sprintf("schema_%d.t", i)] = Counts{U: 1000 + i}
	}
	if got := Text(wide, TextOptions{}); !strings.Contains(got, "schema_299.t (updated 1299); schema_298.t") || !strings.Contains(got, "and 295 more tables") || strings.Contains(got, "cut:") {
		t.Fatalf("the wide alert:\n%s", got)
	}
	if n := utf8.RuneCountInString(text); n > maxText || !utf8.ValidString(text) || !strings.Contains(text, "cut:") {
		t.Fatalf("%d characters, valid UTF-8: %v, cut: %v", n, utf8.ValidString(text), strings.Contains(text, "cut:"))
	}
}

// Три вида получателей: что именно уходит по сети.
func TestTargetFormats(t *testing.T) {
	h := newHook(t)
	r := newRig(t, t.TempDir(),
		Target{Type: TypeTelegram, URL: h.srv.URL, Token: "123456:SECRET", Chat: "-1001234567890"},
		Target{Type: TypeSlack, URL: h.srv.URL + "/services/T0/B0/KEY"},
		Target{Type: TypeJSON, URL: h.srv.URL + "/my/hook"},
		Target{Name: "channel", Type: TypeTelegram, URL: h.srv.URL + "/", Token: "7:OTHER", Chat: "@ops_alerts"})
	if err := r.log.Append(txEvent()); err != nil {
		t.Fatal(err)
	}
	waitFor(t, "four deliveries", func() bool { return len(h.calls()) == 4 })
	by := map[string]map[string]any{}
	for _, c := range h.calls() {
		by[c.path] = c.body
	}
	text := Text(txEvent(), TextOptions{Title: "database shop", UndoHint: "esundo check -config undo.json -xid {xid}"})
	tg := by["/bot123456:SECRET/sendMessage"]
	if tg == nil || tg["chat_id"] != float64(-1001234567890) || tg["text"] != text || tg["link_preview_options"].(map[string]any)["is_disabled"] != true {
		t.Fatalf("telegram: %v", tg)
	}
	if ch := by["/bot7:OTHER/sendMessage"]; ch == nil || ch["chat_id"] != "@ops_alerts" {
		t.Fatalf("telegram channel: %v", ch)
	}
	if sl := by["/services/T0/B0/KEY"]; len(sl) != 1 || sl["text"] != text {
		t.Fatalf("slack: %v", sl)
	}
	js := by["/my/hook"]
	if js == nil || js["text"] != text || js["title"] != "database shop" {
		t.Fatalf("json: %v", js)
	}
	ev := js["events"].([]any)[0].(map[string]any)
	if ev["xid"] != float64(749) || len(ev["signals"].([]any)) != 2 || ev["first_seq"] != float64(3) {
		t.Fatalf("json event: %v", ev)
	}
}

// Поля действия (номер, агент, причина) — одной строкой и не длиннее строки
// тревоги: номер и агента шлюз берёт у агента, и агент не дописывает в
// тревогу строк. Раньше «changed: 1 row» и «approved by the on-call DBA» из
// номера действия вставали отдельными строками.
func TestMarkerFieldsStayOnTheirLine(t *testing.T) {
	e := Event{XID: 9, Changes: 700, Tables: map[string]Counts{"public.accounts": {U: 700}},
		Action: &Action{ID: "a-1\nchanged: 1 row — public.docs\u2028reviewed and approved by the on-call DBA", Gateway: "esmcp", Step: StepIntent,
			Agent: "bot\x1b[8m" + strings.Repeat("x", 5000)}}
	e.Add(KindMassChange, "700 row changes in one transaction")
	text := Text(e, TextOptions{Title: "shop"})
	for _, bad := range []string{"\nchanged: 1 row", "\u2028", "\x1b"} {
		if strings.Contains(text, bad) {
			t.Fatalf("%q in the alert:\n%s", bad, text)
		}
	}
	if !strings.Contains(text, `a-1\u000achanged: 1 row`) || len(text) > 3000 {
		t.Fatalf("%d bytes:\n%s", len(text), text)
	}
	// Экранированное поле — тоже не длиннее строки тревоги: раньше предел шёл
	// до экранирования, и тысяча управляющих символов давала 6000 знаков
	// (R1, R2 заход 3).
	if got := []rune(field(strings.Repeat("\x1b", 1000))); len(got) > maxLine+1 {
		t.Fatalf("an escaped field of %d characters", len(got))
	}
}

// Причина агента с разметкой Slack не зовёт весь канал и не рисует ссылку с
// чужой подписью: &, <, > — сущностями, за @ упоминания всех — U+2060. До
// исправления P-254 <!channel> из причины звал канал, а
// <https://…|Approve the undo> был ссылкой с этой подписью. Telegram и свой
// адрес получают текст как есть.
func TestSlackTextIsNotMarkup(t *testing.T) {
	h := newHook(t)
	r := newRig(t, t.TempDir(), Target{Type: TypeSlack, URL: h.srv.URL + "/slack"}, Target{Type: TypeJSON, URL: h.srv.URL + "/json"})
	e := Event{XID: 9, Action: &Action{ID: "a-1", Gateway: "esmcp", Step: StepIntent, Agent: "bot", Reason: "<!channel> <https://evil.example|Approve the undo> @here @Everyone R&D"}}
	e.Add(KindNotViaGateway, "x")
	if err := r.log.Append(e); err != nil {
		t.Fatal(err)
	}
	waitFor(t, "two deliveries", func() bool { return len(h.calls()) == 2 })
	by := map[string]string{}
	for _, c := range h.calls() {
		by[c.path] = c.body["text"].(string)
	}
	want := "&lt;!channel&gt; &lt;https://evil.example|Approve the undo&gt; @\u2060here @\u2060Everyone R&amp;D"
	if sl := by["/slack"]; !strings.Contains(sl, want) || strings.ContainsAny(sl, "<>") {
		t.Fatalf("slack: %q", sl)
	}
	if js := by["/json"]; !strings.Contains(js, "<!channel> <https://evil.example|Approve the undo> @here @Everyone R&D") {
		t.Fatalf("json: %q", js)
	}
}

// Файл — очередь: тревога уходит один раз. Прежние тревоги новому получателю
// не идут; после перезапуска отправленное не повторяется, а то, что легло в
// файл, пока доставка стояла, уходит.
func TestQueueSendsEachAlertOnce(t *testing.T) {
	h := newHook(t)
	dir := t.TempDir()
	l, _ := OpenLog(filepath.Join(dir, "alerts.jsonl"))
	old := Event{XID: 1}
	old.Add(KindNotViaGateway, "before the channel was set up")
	l.Append(old)
	l.Close()

	target := Target{Type: TypeSlack, URL: h.srv.URL}
	r := newRig(t, dir, target)
	r.raise(2, KindNotViaGateway, "first")
	r.raise(3, KindNotViaGateway, "second")
	waitFor(t, "two deliveries", func() bool { return len(h.calls()) == 2 })
	r.stop()
	r.raise(4, KindNotViaGateway, "while delivery was down")
	r.start(target)
	waitFor(t, "the third delivery", func() bool { return len(h.calls()) == 3 })
	time.Sleep(60 * time.Millisecond) // три прохода опроса: лишнего не пришло
	var xids []string
	for _, text := range h.texts() {
		head := strings.Fields(strings.SplitN(text, "\n", 2)[0])
		xids = append(xids, head[len(head)-1])
	}
	if got := strings.Join(xids, " "); got != "2 3 4" {
		t.Fatalf("delivered transactions %s", got)
	}
	var c cursorFile
	data, _ := os.ReadFile(filepath.Join(dir, "notify-slack.json"))
	fi, _ := os.Stat(filepath.Join(dir, "alerts.jsonl"))
	if json.Unmarshal(data, &c) != nil || c.Offset != fi.Size() {
		t.Fatalf("cursor %s, the file is %d bytes", data, fi.Size())
	}
}

// Получатель отказал: тревога ждёт в файле и уходит позже, порядок не
// меняется, вторая не обгоняет первую.
func TestFailedDeliveryIsRetriedInOrder(t *testing.T) {
	h := newHook(t)
	h.setFail(3)
	r := newRig(t, t.TempDir(), Target{Type: TypeJSON, URL: h.srv.URL})
	r.raise(1, KindMassChange, "first")
	r.raise(2, KindMassChange, "second")
	waitFor(t, "both deliveries", func() bool { return len(h.calls()) == 2 })
	got := h.texts()
	if !strings.Contains(got[0], "transaction 1") || !strings.Contains(got[1], "transaction 2") {
		t.Fatalf("order: %q", got)
	}
	h.mu.Lock()
	tried := len(h.tried)
	h.mu.Unlock()
	if tried != 5 {
		t.Fatalf("%d requests for two alerts after three refusals", tried)
	}
	waitFor(t, "the log says delivery is back", func() bool {
		return strings.Contains(r.logText(), "alerts are delivered again")
	})
	if n := strings.Count(r.logText(), "alert not delivered"); n != 1 {
		t.Fatalf("%d complaints about three refusals in a row:\n%s", n, r.logText())
	}
}

func (r *rig) logText() string {
	r.out.mu.Lock()
	defer r.out.mu.Unlock()
	return r.out.b.String()
}

// Telegram при потоке сообщений отвечает 429 и говорит, сколько ждать:
// следующая попытка — не раньше.
func TestTelegramRetryAfterIsHonoured(t *testing.T) {
	h := newHook(t)
	h.reject = func(w http.ResponseWriter) {
		w.WriteHeader(http.StatusTooManyRequests)
		w.Write([]byte(`{"ok":false,"error_code":429,"description":"Too Many Requests: retry after 1","parameters":{"retry_after":1}}`))
	}
	h.setFail(1)
	r := newRig(t, t.TempDir(), Target{Type: TypeTelegram, URL: h.srv.URL, Token: "1:T", Chat: "5"})
	r.raise(1, KindCanary, "x")
	waitFor(t, "the delivery", func() bool { return len(h.calls()) == 1 })
	h.mu.Lock()
	gap := h.tried[1].Sub(h.tried[0])
	h.mu.Unlock()
	if gap < time.Second {
		t.Fatalf("retried %v after a 429 that asked for a second", gap)
	}
	if !strings.Contains(r.logText(), "Too Many Requests: retry after 1") {
		t.Fatalf("the reason is not in the log:\n%s", r.logText())
	}
}

// Ответ 200 без ok: true у Telegram — не доставка.
func TestTelegramOKFalseIsNotDelivery(t *testing.T) {
	h := newHook(t)
	h.reject = func(w http.ResponseWriter) { w.Write([]byte(`{"ok":false,"description":"chat not found"}`)) }
	h.setFail(2)
	r := newRig(t, t.TempDir(), Target{Type: TypeTelegram, URL: h.srv.URL, Token: "1:T", Chat: "5"})
	r.raise(1, KindCanary, "x")
	waitFor(t, "the delivery", func() bool { return len(h.calls()) == 1 })
	h.mu.Lock()
	defer h.mu.Unlock()
	if len(h.tried) != 3 {
		t.Fatalf("%d requests", len(h.tried))
	}
}

// Получатель долго был недоступен: старые тревоги уходят одной сводкой,
// последние — по одной.
func TestBacklogBecomesADigest(t *testing.T) {
	h := newHook(t)
	h.setFail(-1) // отказывать, пока не починят
	r := newRig(t, t.TempDir(), Target{Type: TypeSlack, URL: h.srv.URL})
	for i := 1; i <= 25; i++ {
		kind := KindNotViaGateway
		if i%5 == 0 {
			kind = KindMassChange
		}
		r.raise(uint32(100+i), kind, fmt.Sprint("alert ", i))
	}
	// Чинить получателя — когда доставка уже видела всю очередь: запрос,
	// который был в пути, пока писалась последняя тревога, собран по очереди
	// покороче, и сводка в нём была бы на тревогу меньше. Второй отказ после
	// конца записи — уже точно по полной очереди.
	h.mu.Lock()
	base := len(h.tried)
	h.mu.Unlock()
	waitFor(t, "two refused attempts with the whole queue", func() bool { h.mu.Lock(); defer h.mu.Unlock(); return len(h.tried) >= base+2 })
	h.setFail(0)
	waitFor(t, "the digest and the latest ten", func() bool { return len(h.calls()) == 11 })
	time.Sleep(60 * time.Millisecond)
	got := h.texts()
	if len(got) != 11 {
		t.Fatalf("%d messages", len(got))
	}
	for _, want := range []string{"15 alerts were waiting for this channel", "mass-change ×3, not-via-gateway ×12", "transactions: 101, 102,"} {
		if !strings.Contains(got[0], want) {
			t.Fatalf("the digest lacks %q:\n%s", want, got[0])
		}
	}
	// (Номер ищется в строке транзакций: в сводке есть и время, а в нём — любые цифры.)
	if strings.Contains(got[0], ", 116") || !strings.HasSuffix(strings.Split(got[0], "\n")[2], ", 115") ||
		!strings.Contains(got[1], "transaction 116") || !strings.Contains(got[10], "transaction 125") {
		t.Fatalf("after the digest: %q … %q", got[1], got[10])
	}
}

// Адрес получателя — секрет: ни ключ бота, ни адрес веб-хука не попадают в
// журнал — ни при отказе сети, ни при ответе с ошибкой.
func TestSecretsStayOutOfTheLog(t *testing.T) {
	h := newHook(t)
	h.reject = func(w http.ResponseWriter) {
		http.Error(w, `{"ok":false,"description":"Unauthorized"}`, http.StatusUnauthorized)
	}
	h.setFail(-1)
	closed := httptest.NewServer(http.NotFoundHandler())
	closed.Close() // по этому адресу никто не слушает
	r := newRig(t, t.TempDir(),
		Target{Type: TypeTelegram, URL: h.srv.URL, Token: "123456:TOKENSECRET", Chat: "5"},
		Target{Type: TypeSlack, URL: closed.URL + "/services/HOOKSECRET"})
	r.raise(1, KindCanary, "x")
	waitFor(t, "both complaints", func() bool { return strings.Count(r.logText(), "alert not delivered") == 2 })
	log := r.logText()
	for _, secret := range []string{"TOKENSECRET", "HOOKSECRET", "/bot", closed.URL, h.srv.URL} {
		if strings.Contains(log, secret) {
			t.Fatalf("%q is in the log:\n%s", secret, log)
		}
	}
	if !strings.Contains(log, "level=ERROR") || !strings.Contains(log, "check the notify settings") || !strings.Contains(log, "Unauthorized") {
		t.Fatalf("a refused key must be an error that names the settings:\n%s", log)
	}
	if !strings.Contains(log, "notify=telegram") || !strings.Contains(log, "notify=slack") || !strings.Contains(log, "connection refused") {
		t.Fatalf("the log does not say which target failed and why:\n%s", log)
	}
	// И проверка настроек адрес не повторяет.
	bad := Target{Type: TypeSlack, URL: "http://example.com/services/HOOKSECRET"}
	if err := bad.Validate(); err == nil || strings.Contains(err.Error(), "HOOKSECRET") {
		t.Fatalf("validate: %v", err)
	}
}

// Тревога, поднятая перед самым выходом (escollect -once), уходит до выхода;
// получателя, который не отвечает, выход не ждёт.
func TestCloseDeliversWhatIsQueued(t *testing.T) {
	h := newHook(t)
	dead := newHook(t)
	dead.setFail(-1)
	r := newRig(t, t.TempDir(), Target{Type: TypeSlack, URL: h.srv.URL}, Target{Type: TypeJSON, URL: dead.srv.URL})
	for i := 1; i <= 5; i++ {
		r.raise(uint32(i), KindCanary, "on the way out")
	}
	start := time.Now()
	r.stop()
	if len(h.calls()) != 5 {
		t.Fatalf("%d of 5 alerts were delivered before the exit", len(h.calls()))
	}
	if took := time.Since(start); took > 2*time.Second {
		t.Fatalf("the exit waited %v for a target that does not answer", took)
	}
}

func TestValidateTargets(t *testing.T) {
	good := []Target{
		{Type: TypeTelegram, Token: "1:T", Chat: "@ops"},
		{Type: TypeSlack, URL: "https://hooks.slack.com/services/T/B/X"},
		{Type: TypeJSON, URL: "http://127.0.0.1:9000/hook"},
		{Name: "second", Type: TypeJSON, URL: "http://localhost/hook"},
	}
	if err := ValidateTargets(good); err != nil {
		t.Fatal(err)
	}
	if good[0].Name != "telegram" || good[3].Name != "second" {
		t.Fatalf("names: %+v", good)
	}
	for name, bad := range map[string][]Target{
		"telegram without chat":     {{Type: TypeTelegram, Token: "1:T"}},
		"telegram without token":    {{Type: TypeTelegram, Chat: "5"}},
		"slack without url":         {{Type: TypeSlack}},
		"http to another machine":   {{Type: TypeJSON, URL: "http://alerts.example.com/hook"}},
		"not an address":            {{Type: TypeJSON, URL: "alerts"}},
		"ftp":                       {{Type: TypeJSON, URL: "ftp://127.0.0.1/x"}},
		"unknown type":              {{Type: "email", URL: "https://x"}},
		"no type":                   {{URL: "https://x"}},
		"token for slack":           {{Type: TypeSlack, URL: "https://x", Token: "t"}},
		"two targets with one name": {{Type: TypeJSON, URL: "https://a"}, {Type: TypeJSON, URL: "https://b"}},
		"name with a slash":         {{Name: "../x", Type: TypeJSON, URL: "https://a"}},
	} {
		if err := ValidateTargets(bad); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

// Падение посреди записи тревоги: обрывок без перевода строки отрезается при
// открытии, а доставка недописанную строку не читает.
func TestTornTail(t *testing.T) {
	h := newHook(t)
	dir := t.TempDir()
	path := filepath.Join(dir, "alerts.jsonl")
	r := newRig(t, dir, Target{Type: TypeSlack, URL: h.srv.URL})
	r.raise(1, KindCanary, "whole")
	waitFor(t, "the delivery", func() bool { return len(h.calls()) == 1 })
	f, _ := os.OpenFile(path, os.O_APPEND|os.O_WRONLY, 0)
	f.WriteString(`{"time":"x","xid":2,"signals":[{"kind":"can`)
	f.Close()
	r.n.Wake()
	time.Sleep(60 * time.Millisecond)
	if len(h.calls()) != 1 {
		t.Fatal("a torn line was sent")
	}
	r.stop()
	r.log.Close()
	l, err := OpenLog(path)
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	e := Event{XID: 3}
	e.Add(KindCanary, "after the restart")
	l.Append(e)
	data, _ := os.ReadFile(path)
	if lines := strings.Split(strings.TrimSpace(string(data)), "\n"); len(lines) != 2 || !strings.Contains(lines[1], `"xid":3`) {
		t.Fatalf("the file after the restart:\n%s", data)
	}
	if err := l.Append(Event{}); err == nil {
		t.Fatal("an event without a signal was written")
	}
}

// Файл тревог заменили коротким (ротация): в нём всё новое, и оно уходит.
func TestReplacedFileIsReadFromItsStart(t *testing.T) {
	h := newHook(t)
	dir := t.TempDir()
	path := filepath.Join(dir, "alerts.jsonl")
	r := newRig(t, dir, Target{Type: TypeSlack, URL: h.srv.URL})
	r.raise(1, KindCanary, strings.Repeat("long ", 50))
	r.raise(2, KindCanary, strings.Repeat("long ", 50))
	waitFor(t, "two deliveries", func() bool { return len(h.calls()) == 2 })
	if err := os.WriteFile(path, []byte(`{"time":"t","xid":9,"signals":[{"kind":"canary","detail":"new file"}]}`+"\nnot an alert\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	r.n.Wake()
	waitFor(t, "the alert of the new file", func() bool { return len(h.calls()) == 3 })
	if text := h.texts()[2]; !strings.Contains(text, "transaction 9") {
		t.Fatalf("%q", text)
	}
	time.Sleep(60 * time.Millisecond)
	if len(h.calls()) != 3 {
		t.Fatal("the line that is not an alert was sent, or the alert was sent twice")
	}
}

// Тревога длиннее блока чтения (4 МиБ) доставляется, и тревоги после неё —
// тоже; длиннее предела разбора — вместо неё уходит короткая с местом в файле.
// До исправления P-245 такая строка считалась «ещё дописывается», и доставка
// всем получателям вставала навсегда, а показатели говорили «ничего не ждёт».
// Длинную строку агент делал одной причиной отказа в 5 МБ.
func TestLongAlertLineDoesNotStopDelivery(t *testing.T) {
	h := newHook(t)
	r := newRig(t, t.TempDir(), Target{Type: TypeSlack, URL: h.srv.URL})
	r.raise(1, KindNotViaGateway, "before")
	waitFor(t, "the first delivery", func() bool { return len(h.calls()) == 1 })
	big := Event{Time: time.Now().UTC().Format(time.RFC3339Nano),
		Action: &Action{ID: "a-1", Gateway: "esmcp", Step: StepOutcome, Reason: strings.Repeat("x", 5<<20)}}
	big.Add(KindRefused, "the MCP server stopped an action")
	if err := r.log.Append(big); err != nil {
		t.Fatal(err)
	}
	huge := Event{Time: time.Now().UTC().Format(time.RFC3339Nano),
		Action: &Action{ID: "a-2", Gateway: "esmcp", Step: StepOutcome, Reason: strings.Repeat("y", maxEvent)}}
	huge.Add(KindRefused, "too long to parse")
	if err := r.log.Append(huge); err != nil {
		t.Fatal(err)
	}
	r.raise(2, KindCanary, "public.accounts: the canary row id=3 was touched (U)")
	waitFor(t, "every alert after the long ones", func() bool { return len(h.calls()) == 4 })
	calls := strings.Join(h.texts(), "\n")
	if !strings.Contains(calls, "the MCP server stopped an action") || !strings.Contains(calls, "too long to send") || !strings.Contains(calls, "canary") {
		t.Fatalf("%s", calls[:min(len(calls), 2000)])
	}
	// Показатели доставка обновляет после ответа получателя: ждём и их.
	waitFor(t, "nothing waiting", func() bool { st := r.n.Stats(); return st[0].Waiting == 0 && !st[0].Failing })
}

// Заголовок тревоги — по тому, что известно о транзакции: действие шлюза,
// откат, транзакция не через шлюз (P-306; заход 2; п. 42).
func TestTitleSaysWhatTheTransactionIs(t *testing.T) {
	for want, e := range map[string]Event{
		"agent transaction 5": {XID: 5, Action: &Action{ID: "a", Gateway: "esmcp", Step: StepIntent}},
		"undo transaction 5":  {XID: 5, Action: &Action{ID: "u", Gateway: "esundo", Step: StepUndo}},
		"db: transaction 5":   {XID: 5},
	} {
		e.Add(KindMassChange, "x")
		if text := Text(e, TextOptions{Title: "db"}); !strings.Contains(strings.SplitN(text, "\n", 2)[0], want) {
			t.Errorf("%s: %q", want, text)
		}
	}
	e := Event{XID: 5, Fingerprint: true, FirstSeq: 3, LastSeq: 3}
	e.Add(KindMassChange, "x")
	if text := Text(e, TextOptions{Title: "db", UndoHint: "esundo -xid {xid}"}); !strings.Contains(text, "not through the gateway (only its fingerprint is kept)") || strings.Contains(text, "undo preview") {
		t.Errorf("a fingerprint: %q", text)
	}
	// TRUNCATE esundo не откатывает: и подсказки нет (T-8, заход 2).
	e = Event{XID: 5, FirstSeq: 3, LastSeq: 3}
	e.Add(KindTruncate, "x")
	if text := Text(e, TextOptions{Title: "db", UndoHint: "esundo -xid {xid}"}); strings.Contains(text, "undo preview") {
		t.Errorf("TRUNCATE: %q", text)
	}
}
