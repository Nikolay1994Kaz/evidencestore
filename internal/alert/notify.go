package alert

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// Виды получателей.
const (
	TypeTelegram = "telegram" // бот Telegram: token и chat
	TypeSlack    = "slack"    // входящий веб-хук Slack и совместимые (Mattermost, Rocket.Chat): {"text": …}
	TypeJSON     = "json"     // свой адрес: {"text": …, "event": …}
)

// telegramAPI — адрес Bot API, если у получателя не задан свой.
const telegramAPI = "https://api.telegram.org"

// Target — получатель тревог.
type Target struct {
	// Name — имя получателя: по нему назван его курсор и строки журнала.
	// По умолчанию — вид; два получателя одного вида называют явно.
	Name string `json:"name"`
	Type string `json:"type"` // telegram, slack или json
	// URL — адрес веб-хука (slack, json). У telegram — адрес Bot API, если он
	// не https://api.telegram.org (свой сервер Bot API).
	URL string `json:"url"`
	// Token — ключ бота Telegram (выдаёт @BotFather); Chat — куда писать:
	// номер чата или @имя_канала. Бот должен состоять в этом чате.
	Token string `json:"token"`
	Chat  string `json:"chat"`
}

var nameRE = regexp.MustCompile(`^[a-z0-9][a-z0-9_-]{0,31}$`)

// Validate проверяет получателя и ставит имя по умолчанию.
func (t *Target) Validate() error {
	if t.Name == "" {
		t.Name = t.Type
	}
	var errs []error
	if !nameRE.MatchString(t.Name) {
		errs = append(errs, fmt.Errorf("name %q: lower-case letters, digits, - and _, 32 at most", t.Name))
	}
	switch t.Type {
	case TypeTelegram:
		if t.Token == "" || t.Chat == "" {
			errs = append(errs, errors.New("telegram needs token (from @BotFather) and chat (a chat id or @channel)"))
		}
		if t.URL != "" {
			errs = append(errs, checkURL(t.URL))
		}
	case TypeSlack, TypeJSON:
		if t.URL == "" {
			errs = append(errs, fmt.Errorf("%s needs url", t.Type))
		} else {
			errs = append(errs, checkURL(t.URL))
		}
		if t.Token != "" || t.Chat != "" {
			errs = append(errs, fmt.Errorf("token and chat are for telegram, not for %s", t.Type))
		}
	default:
		errs = append(errs, fmt.Errorf("type %q: telegram, slack or json", t.Type))
	}
	if err := errors.Join(errs...); err != nil {
		return fmt.Errorf("notify target %s: %w", t.Name, err)
	}
	return nil
}

// checkURL — адрес получателя: https, а http — только на этой же машине. В
// тревоге имена таблиц, ролей и причины действий: открытым текстом по сети
// они не ходят. Сам адрес в ошибку не идёт: в нём может быть ключ.
func checkURL(raw string) error {
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" {
		return errors.New("url is not an address")
	}
	switch u.Scheme {
	case "https":
		return nil
	case "http":
		if host := u.Hostname(); host == "localhost" || net.ParseIP(host).IsLoopback() {
			return nil
		}
		return errors.New("url must be https:// (http:// is accepted for this machine only)")
	}
	return errors.New("url must be an https:// address")
}

// ValidateTargets проверяет список получателей: каждый годен, имена разные.
func ValidateTargets(targets []Target) error {
	var errs []error
	seen := map[string]bool{}
	for i := range targets {
		if err := targets[i].Validate(); err != nil {
			errs = append(errs, err)
			continue
		}
		if seen[targets[i].Name] {
			errs = append(errs, fmt.Errorf("two notify targets are called %q: give them different names", targets[i].Name))
		}
		seen[targets[i].Name] = true
	}
	return errors.Join(errs...)
}

// request собирает запрос к получателю: text — сообщение, events — тревоги, о
// которых оно (одна; у сводки — все).
func (t Target) request(ctx context.Context, text, title string, events []Event) (*http.Request, error) {
	var addr string
	var body any
	switch t.Type {
	case TypeTelegram:
		base := t.URL
		if base == "" {
			base = telegramAPI
		}
		addr = strings.TrimRight(base, "/") + "/bot" + t.Token + "/sendMessage"
		// Номер чата — числом, имя канала (@channel) — строкой.
		var chat any = t.Chat
		if n, err := strconv.ParseInt(t.Chat, 10, 64); err == nil {
			chat = n
		}
		body = map[string]any{"chat_id": chat, "text": text, "link_preview_options": map[string]bool{"is_disabled": true}}
	case TypeSlack:
		addr, body = t.URL, map[string]string{"text": text}
	default:
		addr, body = t.URL, map[string]any{"text": text, "title": title, "events": events}
	}
	data, err := json.Marshal(body)
	if err != nil {
		return nil, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, addr, bytes.NewReader(data))
	if err != nil {
		return nil, errors.New("the target address is not a URL")
	}
	req.Header.Set("Content-Type", "application/json")
	return req, nil
}

// sendError — получатель не принял сообщение.
type sendError struct {
	msg   string
	after time.Duration // получатель сам сказал, сколько ждать
	fatal bool          // дело в настройках (ключ, чат, адрес): само не пройдёт
}

func (e *sendError) Error() string { return e.msg }

// send отправляет одно сообщение. В тексте ошибки нет адреса получателя.
func (t Target) send(ctx context.Context, client *http.Client, text, title string, events []Event) error {
	req, err := t.request(ctx, text, title, events)
	if err != nil {
		return &sendError{msg: err.Error(), fatal: true}
	}
	resp, err := client.Do(req)
	if err != nil {
		// url.Error несёт адрес целиком — с ключом. Наружу — только причина.
		var ue *url.Error
		if errors.As(err, &ue) {
			err = ue.Err
		}
		return &sendError{msg: "request failed: " + err.Error()}
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(io.LimitReader(resp.Body, 64<<10))
	var tg struct {
		OK          *bool  `json:"ok"`
		Description string `json:"description"`
		Parameters  struct {
			RetryAfter int `json:"retry_after"`
		} `json:"parameters"`
	}
	if t.Type == TypeTelegram {
		json.Unmarshal(raw, &tg)
	}
	if resp.StatusCode/100 == 2 && (t.Type != TypeTelegram || tg.OK != nil && *tg.OK) {
		return nil
	}
	se := &sendError{msg: "the target answered " + resp.Status}
	switch {
	case tg.Description != "":
		se.msg += ": " + tg.Description
	case t.Type == TypeTelegram && resp.StatusCode/100 == 2:
		se.msg += " without ok: true"
	}
	if tg.Parameters.RetryAfter > 0 {
		se.after = time.Duration(tg.Parameters.RetryAfter) * time.Second
	} else if s, err := strconv.Atoi(resp.Header.Get("Retry-After")); err == nil && s > 0 {
		se.after = time.Duration(s) * time.Second
	}
	// 4xx, кроме «подожди»: неверный ключ, бот не в чате, веб-хук отозван.
	se.fatal = resp.StatusCode/100 == 4 && resp.StatusCode != http.StatusTooManyRequests && resp.StatusCode != http.StatusRequestTimeout
	return se
}

// Options — настройки доставки.
type Options struct {
	File    string   // alerts.jsonl
	Dir     string   // где лежат курсоры получателей (notify-<имя>.json)
	Targets []Target // проверенные (ValidateTargets)
	Text    TextOptions
	// Client — клиент HTTP; nil — свой, с ожиданием 15 с. Прокси берётся из
	// окружения (HTTPS_PROXY): получатели обычно снаружи.
	Client *http.Client

	// Pace — пауза между сообщениями одному получателю; 0 — секунда (у
	// Telegram предел — сообщение в секунду на чат). Poll — как часто
	// заглядывать в файл без побудки; 0 — 5 с. Retry — первая пауза после
	// отказа; 0 — 2 с, дальше растёт до 5 мин.
	Pace, Poll, Retry time.Duration
}

const (
	// burst — столько тревог в очереди ещё идут по одной; больше — старые
	// уходят одной сводкой, по одной — последние keepLast.
	burst    = 20
	keepLast = 10
	maxRetry = 5 * time.Minute
	// readChunk — столько байт очереди читается за раз.
	readChunk = 4 << 20
)

// Notifier несёт тревоги из файла получателям: по потоку на каждого.
type Notifier struct {
	senders []*sender
	wakes   []chan struct{}
	closing chan struct{} // закрыт — дослать очередь и выйти
	cancel  context.CancelFunc
	wg      sync.WaitGroup
}

// closeGrace — столько Close ждёт, пока очередь дойдёт до получателей.
const closeGrace = 5 * time.Second

// Start запускает доставку. Тревоги, которые лежали в файле до первого
// запуска получателя, ему не отправляются: курсор встаёт в конец файла.
func Start(o Options, log *slog.Logger) (*Notifier, error) {
	if log == nil {
		log = slog.New(slog.DiscardHandler)
	}
	if o.Client == nil {
		o.Client = &http.Client{Timeout: 15 * time.Second}
	}
	if o.Pace == 0 {
		o.Pace = time.Second
	}
	if o.Poll == 0 {
		o.Poll = 5 * time.Second
	}
	if o.Retry == 0 {
		o.Retry = 2 * time.Second
	}
	ctx, cancel := context.WithCancel(context.Background())
	n := &Notifier{cancel: cancel, closing: make(chan struct{})}
	for _, t := range o.Targets {
		s := &sender{o: o, target: t, log: log.With("notify", t.Name), wake: make(chan struct{}, 1), closing: n.closing,
			cursor: filepath.Join(o.Dir, "notify-"+t.Name+".json")}
		if err := s.load(); err != nil {
			cancel()
			return nil, err
		}
		n.senders = append(n.senders, s)
		n.wakes = append(n.wakes, s.wake)
		n.wg.Add(1)
		go func() {
			defer n.wg.Done()
			s.run(ctx)
		}()
	}
	return n, nil
}

// TargetStats — очередь одного получателя: сколько тревог ждёт отправки и
// отказывает ли он сейчас.
type TargetStats struct {
	Name    string
	Waiting int
	Failing bool
}

// Stats — состояние очередей получателей (для показателей сборщика). Можно
// звать с любого потока.
func (n *Notifier) Stats() []TargetStats {
	out := make([]TargetStats, len(n.senders))
	for i, s := range n.senders {
		out[i] = TargetStats{Name: s.target.Name, Waiting: int(s.waiting.Load()), Failing: s.down.Load()}
	}
	return out
}

// Wake будит доставку: в файле новая тревога.
func (n *Notifier) Wake() {
	for _, w := range n.wakes {
		select {
		case w <- struct{}{}:
		default:
		}
	}
}

// Close останавливает доставку, дав очереди дойти: тревога, поднятая перед
// самым выходом (escollect -once), не должна ждать следующего запуска.
// Получателя, который не отвечает, Close не ждёт, и всего ждёт не дольше
// closeGrace: неотправленное остаётся в файле и уйдёт после следующего запуска.
func (n *Notifier) Close() {
	close(n.closing)
	done := make(chan struct{})
	go func() { n.wg.Wait(); close(done) }()
	select {
	case <-done:
	case <-time.After(closeGrace):
	}
	n.cancel()
	n.wg.Wait()
}

// cursorFile — notify-<имя>.json.
type cursorFile struct {
	Offset int64 `json:"offset"` // файл тревог отправлен до этого байта
}

type sender struct {
	o       Options
	target  Target
	log     *slog.Logger
	wake    chan struct{}
	closing <-chan struct{}
	cursor  string
	offset  int64

	failing  bool      // последний запрос не прошёл
	loggedAt time.Time // когда последний раз сказали об отказе

	// Для Stats: сколько тревог в очереди и отказывает ли получатель.
	waiting atomic.Int64
	down    atomic.Bool
}

// item — тревога в очереди и где кончается её строка.
type item struct {
	event Event
	end   int64
}

func (s *sender) load() error {
	data, err := os.ReadFile(s.cursor)
	if err == nil {
		var c cursorFile
		if err := json.Unmarshal(data, &c); err != nil || c.Offset < 0 {
			return fmt.Errorf("alert: %s is not a cursor", s.cursor)
		}
		s.offset = c.Offset
		return nil
	}
	if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	// Новый получатель: прежние тревоги — не ему.
	if fi, err := os.Stat(s.o.File); err == nil {
		s.offset = fi.Size()
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	return s.save()
}

func (s *sender) save() error {
	data, _ := json.Marshal(cursorFile{Offset: s.offset})
	tmp := s.cursor + ".tmp"
	f, err := os.OpenFile(tmp, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	_, err = f.Write(data)
	if err = errors.Join(err, f.Sync(), f.Close()); err != nil {
		return err
	}
	return os.Rename(tmp, s.cursor)
}

// pending читает из файла тревоги после курсора: только целые строки.
func (s *sender) pending() ([]item, error) {
	f, err := os.Open(s.o.File)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	defer f.Close()
	fi, err := f.Stat()
	if err != nil {
		return nil, err
	}
	if fi.Size() < s.offset {
		// Файл заменили или обрезали (ротация): в нём всё новое.
		s.log.Warn("the alerts file became shorter than what was already sent: reading it from the start")
		s.offset = 0
	}
	if fi.Size() == s.offset {
		return nil, nil
	}
	r := bufio.NewReaderSize(io.NewSectionReader(f, s.offset, min(fi.Size()-s.offset, readChunk)), 1<<16)
	var out []item
	at := s.offset
	for {
		line, err := r.ReadBytes('\n')
		if err != nil {
			break // обрывок без перевода строки ещё дописывается
		}
		at += int64(len(line))
		var e Event
		if json.Unmarshal(line, &e) != nil || len(e.Signals) == 0 {
			// Не тревога (чужая строка): пропустить, но не застрять на ней.
			s.log.Warn("a line of the alerts file is not an alert: skipped")
			if len(out) == 0 {
				s.offset = at
			} else {
				out[len(out)-1].end = at
			}
			continue
		}
		out = append(out, item{event: e, end: at})
	}
	return out, nil
}

// message — одно сообщение получателю и докуда очередь им закрыта.
type message struct {
	text   string
	events []Event
	end    int64
}

// plan раскладывает очередь на сообщения: по одному на тревогу, а когда их
// накопилось больше burst, старые — одной сводкой.
func (s *sender) plan(items []item) []message {
	var out []message
	if len(items) > burst {
		old := items[:len(items)-keepLast]
		events := make([]Event, len(old))
		for i, it := range old {
			events[i] = it.event
		}
		out = append(out, message{text: Digest(events, s.o.Text), events: events, end: old[len(old)-1].end})
		items = items[len(old):]
	}
	for _, it := range items {
		out = append(out, message{text: Text(it.event, s.o.Text), events: []Event{it.event}, end: it.end})
	}
	return out
}

// sleep ждёт d или отмены; false — отменили.
func sleep(ctx context.Context, d time.Duration) bool {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return false
	case <-t.C:
		return true
	}
}

func (s *sender) run(ctx context.Context) {
	retry := time.Duration(0)
	for ctx.Err() == nil {
		items, err := s.pending()
		if err != nil {
			s.complain("the alerts file cannot be read", err, false)
			if !sleep(ctx, s.o.Poll) {
				return
			}
			continue
		}
		s.waiting.Store(int64(len(items)))
		if len(items) == 0 {
			select {
			case <-ctx.Done():
				return
			case <-s.closing:
				return // очередь пуста
			case <-s.wake:
			case <-time.After(s.o.Poll):
			}
			continue
		}
		// Очередь перечитывается после каждого отказа: за время простоя она
		// растёт, и план (по одной или сводкой) должен это видеть.
		for _, m := range s.plan(items) {
			err := s.target.send(ctx, s.o.Client, m.text, s.o.Text.Title, m.events)
			if ctx.Err() != nil {
				return
			}
			if err != nil {
				retry = min(max(retry*2, s.o.Retry), maxRetry)
				wait := retry
				var se *sendError
				if errors.As(err, &se) {
					wait = max(wait, min(se.after, 2*maxRetry))
					s.complain("alert not delivered; it waits in the alerts file", err, se.fatal)
				}
				select {
				case <-s.closing:
					return // на выходе получателя, который не отвечает, не ждут
				default:
				}
				if !sleep(ctx, wait) {
					return
				}
				break
			}
			if s.failing {
				s.log.Info("alerts are delivered again")
				s.failing, s.loggedAt = false, time.Time{}
			}
			s.down.Store(false)
			s.waiting.Add(-int64(len(m.events)))
			retry = 0
			s.offset = m.end
			if err := s.save(); err != nil {
				// Курсор не записан: после перезапуска это сообщение уйдёт ещё раз.
				s.log.Error("the notify cursor was not written: this alert may be sent again after a restart", "err", err)
			}
			if !sleep(ctx, s.o.Pace) {
				return
			}
		}
	}
}

// complain говорит об отказе в журнал: первый раз сразу, потом — раз в
// десять минут. fatal — дело в настройках, это ошибка, а не предупреждение.
func (s *sender) complain(msg string, err error, fatal bool) {
	s.down.Store(true)
	if s.failing && time.Since(s.loggedAt) < 10*time.Minute {
		return
	}
	s.failing, s.loggedAt = true, time.Now()
	if fatal {
		s.log.Error(msg+": check the notify settings (key, chat, address)", "err", err)
		return
	}
	s.log.Warn(msg, "err", err)
}
