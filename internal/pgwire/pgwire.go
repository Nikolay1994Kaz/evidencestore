// Package pgwire — клиент протокола PostgreSQL (версия 3.0) в том объёме,
// который нужен сборщику изменений и MCP-серверу: подключение (unix-сокет или
// TCP, по желанию TLS), вход (trust, пароль, MD5, SCRAM-SHA-256), простой
// протокол запросов и поток логической репликации.
//
// ЗАЧЕМ СВОЙ. Как и с RFC 3161 (internal/tsa): у проекта нет зависимостей,
// кроме golang.org/x, а нужная часть протокола мала и описана в документации
// PostgreSQL («Frontend/Backend Protocol», «Streaming Replication Protocol»).
// Расширенного протокола (Parse/Bind), COPY и уведомлений здесь нет.
package pgwire

import (
	"bufio"
	"context"
	"crypto/md5"
	"crypto/tls"
	"crypto/x509"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"strconv"
	"strings"
	"time"
)

// Config — куда и кем подключаться.
type Config struct {
	Network  string // "unix" или "tcp"
	Address  string // путь сокета или host:port
	Host     string // имя сервера для проверки сертификата
	User     string
	Password string
	Database string
	AppName  string
	// Replication — соединение репликации (replication=database): по нему
	// идут IDENTIFY_SYSTEM и START_REPLICATION, обычные запросы тоже работают.
	Replication bool
	// SSLMode: "disable" (по умолчанию), "require" (шифрование без проверки
	// сертификата) или "verify-full" (проверка по SSLRootCert или системным корням).
	SSLMode     string
	SSLRootCert string
	Timeout     time.Duration // на подключение и вход; 0 — 15 с
}

// ParseDSN разбирает строку вида "host=/var/run/postgresql port=5432 user=u
// dbname=d password=p sslmode=require application_name=x". Значение с
// пробелами — в одинарных кавычках. host, начинающийся с "/", — каталог
// unix-сокета. Пароля нет — берётся PGPASSWORD.
func ParseDSN(dsn string) (Config, error) {
	kv, err := splitDSN(dsn)
	if err != nil {
		return Config{}, err
	}
	host, port := "localhost", "5432"
	c := Config{SSLMode: "disable"}
	for k, v := range kv {
		switch k {
		case "host":
			host = v
		case "port":
			port = v
		case "user":
			c.User = v
		case "password":
			c.Password = v
		case "dbname":
			c.Database = v
		case "application_name":
			c.AppName = v
		case "sslmode":
			c.SSLMode = v
		case "sslrootcert":
			c.SSLRootCert = v
		case "replication":
			c.Replication = v == "database" || v == "true" || v == "1"
		default:
			return Config{}, fmt.Errorf("pgwire: unknown connection parameter %q", k)
		}
	}
	if _, err := strconv.ParseUint(port, 10, 16); err != nil {
		return Config{}, fmt.Errorf("pgwire: port %q is not a number", port)
	}
	if strings.HasPrefix(host, "/") {
		c.Network, c.Address = "unix", host+"/.s.PGSQL."+port
	} else {
		c.Network, c.Address, c.Host = "tcp", net.JoinHostPort(host, port), host
	}
	if c.User == "" {
		return Config{}, errors.New("pgwire: user is required")
	}
	if c.Database == "" {
		c.Database = c.User
	}
	if c.Password == "" {
		c.Password = os.Getenv("PGPASSWORD")
	}
	switch c.SSLMode {
	case "disable", "require", "verify-full":
	default:
		return Config{}, fmt.Errorf("pgwire: sslmode %q: use disable, require or verify-full", c.SSLMode)
	}
	return c, nil
}

func splitDSN(s string) (map[string]string, error) {
	out := map[string]string{}
	for i := 0; i < len(s); {
		for i < len(s) && s[i] == ' ' {
			i++
		}
		if i == len(s) {
			break
		}
		eq := strings.IndexByte(s[i:], '=')
		if eq <= 0 {
			return nil, fmt.Errorf("pgwire: connection string: expected key=value at %q", s[i:])
		}
		key := s[i : i+eq]
		i += eq + 1
		var val strings.Builder
		if i < len(s) && s[i] == '\'' {
			i++
			closed := false
			for i < len(s) {
				if s[i] == '\\' && i+1 < len(s) {
					val.WriteByte(s[i+1])
					i += 2
					continue
				}
				if s[i] == '\'' {
					closed = true
					i++
					break
				}
				val.WriteByte(s[i])
				i++
			}
			if !closed {
				return nil, fmt.Errorf("pgwire: connection string: unterminated quote in %s", key)
			}
		} else {
			for i < len(s) && s[i] != ' ' {
				val.WriteByte(s[i])
				i++
			}
		}
		out[key] = val.String()
	}
	return out, nil
}

// PgError — ошибка, которую прислал сервер.
type PgError struct {
	Severity, Code, Message, Detail, Hint string
}

func (e *PgError) Error() string {
	s := fmt.Sprintf("postgres: %s: %s (SQLSTATE %s)", e.Severity, e.Message, e.Code)
	if e.Detail != "" {
		s += "; " + e.Detail
	}
	return s
}

// ErrTimeout — за отведённое время сервер ничего не прислал (ReadReplication).
var ErrTimeout = errors.New("pgwire: no message within the timeout")

// maxMessage — предел одного сообщения сервера. Значение поля в PostgreSQL —
// до 1 ГиБ; больше сообщение быть не может.
const maxMessage = 1<<30 + 1<<20

// Conn — одно соединение. Не для одновременного использования из нескольких горутин.
type Conn struct {
	nc     net.Conn
	r      *bufio.Reader
	params map[string]string // ParameterStatus сервера
	stream bool              // идёт поток репликации (CopyBoth)
}

// Dial подключается и проходит вход.
func Dial(ctx context.Context, cfg Config) (_ *Conn, err error) {
	if cfg.Timeout == 0 {
		cfg.Timeout = 15 * time.Second
	}
	d := net.Dialer{Timeout: cfg.Timeout}
	nc, err := d.DialContext(ctx, cfg.Network, cfg.Address)
	if err != nil {
		return nil, fmt.Errorf("pgwire: connect %s: %w", cfg.Address, err)
	}
	defer func() {
		if err != nil {
			nc.Close()
		}
	}()
	nc.SetDeadline(time.Now().Add(cfg.Timeout))
	if cfg.SSLMode == "require" || cfg.SSLMode == "verify-full" {
		if nc, err = startTLS(nc, cfg); err != nil {
			return nil, err
		}
	}
	c := &Conn{nc: nc, r: bufio.NewReaderSize(nc, 64<<10), params: map[string]string{}}
	if err := c.startup(cfg); err != nil {
		return nil, err
	}
	nc.SetDeadline(time.Time{})
	return c, nil
}

func startTLS(nc net.Conn, cfg Config) (net.Conn, error) {
	// SSLRequest: длина 8, код 80877103; ответ — один байт 'S' или 'N'.
	req := binary.BigEndian.AppendUint32(binary.BigEndian.AppendUint32(nil, 8), 80877103)
	if _, err := nc.Write(req); err != nil {
		return nil, err
	}
	var ans [1]byte
	if _, err := io.ReadFull(nc, ans[:]); err != nil {
		return nil, err
	}
	if ans[0] != 'S' {
		return nil, errors.New("pgwire: the server refused TLS (sslmode asks for it)")
	}
	tc := &tls.Config{MinVersion: tls.VersionTLS12, ServerName: cfg.Host}
	if cfg.SSLMode == "require" {
		tc.InsecureSkipVerify = true // «require» у PostgreSQL — шифрование без проверки сертификата
	} else if cfg.SSLRootCert != "" {
		pem, err := os.ReadFile(cfg.SSLRootCert)
		if err != nil {
			return nil, fmt.Errorf("pgwire: sslrootcert: %w", err)
		}
		tc.RootCAs = x509.NewCertPool()
		if !tc.RootCAs.AppendCertsFromPEM(pem) {
			return nil, fmt.Errorf("pgwire: sslrootcert %s holds no certificate", cfg.SSLRootCert)
		}
	}
	conn := tls.Client(nc, tc)
	if err := conn.Handshake(); err != nil {
		return nil, fmt.Errorf("pgwire: TLS: %w", err)
	}
	return conn, nil
}

func (c *Conn) startup(cfg Config) error {
	body := binary.BigEndian.AppendUint32(nil, 196608) // протокол 3.0
	add := func(k, v string) { body = append(append(append(append(body, k...), 0), v...), 0) }
	add("user", cfg.User)
	add("database", cfg.Database)
	add("client_encoding", "UTF8")
	// Времена и числа в тексте — в одном виде, от настроек роли не зависят.
	add("DateStyle", "ISO, YMD")
	add("extra_float_digits", "3")
	if cfg.AppName != "" {
		add("application_name", cfg.AppName)
	}
	if cfg.Replication {
		add("replication", "database")
	}
	body = append(body, 0)
	if _, err := c.nc.Write(append(binary.BigEndian.AppendUint32(nil, uint32(len(body)+4)), body...)); err != nil {
		return err
	}
	var scram *scramClient
	for {
		typ, msg, err := c.read()
		if err != nil {
			return err
		}
		switch typ {
		case 'E':
			return parseError(msg)
		case 'R':
			if len(msg) < 4 {
				return errors.New("pgwire: short authentication message")
			}
			switch code := binary.BigEndian.Uint32(msg); code {
			case 0: // AuthenticationOk
			case 3: // пароль открытым текстом
				if err := c.send('p', append([]byte(cfg.Password), 0)); err != nil {
					return err
				}
			case 5: // MD5: "md5" + md5(md5(пароль+имя) + соль)
				if len(msg) < 8 {
					return errors.New("pgwire: short MD5 salt")
				}
				inner := md5.Sum([]byte(cfg.Password + cfg.User))
				outer := md5.Sum(append([]byte(hex.EncodeToString(inner[:])), msg[4:8]...))
				if err := c.send('p', append([]byte("md5"+hex.EncodeToString(outer[:])), 0)); err != nil {
					return err
				}
			case 10: // SASL: список механизмов
				if !strings.Contains("\x00"+string(msg[4:]), "\x00SCRAM-SHA-256\x00") {
					return errors.New("pgwire: the server offers no SCRAM-SHA-256")
				}
				if scram, err = newScram(cfg.Password, nil); err != nil {
					return err
				}
				first := scram.first()
				p := append([]byte("SCRAM-SHA-256\x00"), binary.BigEndian.AppendUint32(nil, uint32(len(first)))...)
				if err := c.send('p', append(p, first...)); err != nil {
					return err
				}
			case 11: // SASLContinue
				if scram == nil {
					return errors.New("pgwire: SASL continue without a start")
				}
				final, err := scram.final(msg[4:])
				if err != nil {
					return err
				}
				if err := c.send('p', final); err != nil {
					return err
				}
			case 12: // SASLFinal: подпись сервера
				if scram == nil {
					return errors.New("pgwire: SASL final without a start")
				}
				if err := scram.verify(msg[4:]); err != nil {
					return err
				}
			default:
				return fmt.Errorf("pgwire: authentication method %d is not supported", code)
			}
		case 'S':
			if k, v, ok := strings.Cut(strings.TrimRight(string(msg), "\x00"), "\x00"); ok {
				c.params[k] = v
			}
		case 'K', 'N':
		case 'Z':
			return nil
		default:
			return fmt.Errorf("pgwire: unexpected message %q during startup", typ)
		}
	}
}

// Param — значение параметра сервера из ParameterStatus (server_version и т. п.).
func (c *Conn) Param(name string) string { return c.params[name] }

// Close прощается с сервером и закрывает соединение.
func (c *Conn) Close() error {
	if !c.stream {
		c.nc.SetWriteDeadline(time.Now().Add(time.Second))
		c.send('X', nil)
	}
	return c.nc.Close()
}

func (c *Conn) send(typ byte, body []byte) error {
	buf := make([]byte, 0, 5+len(body))
	buf = append(buf, typ)
	buf = binary.BigEndian.AppendUint32(buf, uint32(len(body)+4))
	_, err := c.nc.Write(append(buf, body...))
	return err
}

func (c *Conn) read() (byte, []byte, error) {
	var head [5]byte
	if _, err := io.ReadFull(c.r, head[:]); err != nil {
		return 0, nil, err
	}
	n := binary.BigEndian.Uint32(head[1:])
	if n < 4 || n > maxMessage {
		return 0, nil, fmt.Errorf("pgwire: message %q of %d bytes", head[0], n)
	}
	body := make([]byte, n-4)
	if _, err := io.ReadFull(c.r, body); err != nil {
		return 0, nil, err
	}
	return head[0], body, nil
}

func parseError(msg []byte) *PgError {
	e := &PgError{}
	for len(msg) > 1 {
		end := 1
		for end < len(msg) && msg[end] != 0 {
			end++
		}
		val := string(msg[1:end])
		switch msg[0] {
		case 'S':
			e.Severity = val
		case 'C':
			e.Code = val
		case 'M':
			e.Message = val
		case 'D':
			e.Detail = val
		case 'H':
			e.Hint = val
		}
		if end >= len(msg) {
			break
		}
		msg = msg[end+1:]
	}
	return e
}

// Result — ответ на одну команду запроса.
type Result struct {
	Columns []string
	Rows    [][]*string // nil — NULL
	Tag     string      // "UPDATE 3", "SELECT 1" …
}

// Query исполняет текст простым протоколом. В тексте может быть несколько
// команд через ";": на каждую — свой Result. При ошибке сервера возвращаются
// результаты команд до неё и *PgError; соединение остаётся рабочим.
func (c *Conn) Query(sql string) ([]Result, error) {
	if c.stream {
		return nil, errors.New("pgwire: the connection is streaming replication")
	}
	if strings.IndexByte(sql, 0) >= 0 {
		return nil, errors.New("pgwire: a query cannot hold a zero byte")
	}
	if err := c.send('Q', append([]byte(sql), 0)); err != nil {
		return nil, err
	}
	var out []Result
	var cur *Result
	var failed error
	for {
		typ, msg, err := c.read()
		if err != nil {
			return out, err
		}
		switch typ {
		case 'T':
			cols, err := parseRowDescription(msg)
			if err != nil {
				return out, err
			}
			cur = &Result{Columns: cols}
		case 'D':
			row, err := parseDataRow(msg)
			if err != nil {
				return out, err
			}
			if cur == nil {
				cur = &Result{}
			}
			cur.Rows = append(cur.Rows, row)
		case 'C':
			if cur == nil {
				cur = &Result{}
			}
			cur.Tag = strings.TrimRight(string(msg), "\x00")
			out = append(out, *cur)
			cur = nil
		case 'I':
			out = append(out, Result{})
		case 'E':
			if failed == nil {
				failed = parseError(msg)
			}
		case 'W':
			c.stream = true
			return out, nil
		case 'Z':
			return out, failed
		case 'N', 'S', 'A':
		default:
			return out, fmt.Errorf("pgwire: unexpected message %q in a query answer", typ)
		}
	}
}

// QueryRow — первая строка первого результата; ok = false — строк нет.
func (c *Conn) QueryRow(sql string) (row []*string, ok bool, err error) {
	res, err := c.Query(sql)
	if err != nil {
		return nil, false, err
	}
	if len(res) == 0 || len(res[0].Rows) == 0 {
		return nil, false, nil
	}
	return res[0].Rows[0], true, nil
}

func parseRowDescription(msg []byte) ([]string, error) {
	if len(msg) < 2 {
		return nil, errors.New("pgwire: short row description")
	}
	n := int(binary.BigEndian.Uint16(msg))
	msg = msg[2:]
	cols := make([]string, 0, n)
	for i := 0; i < n; i++ {
		end := 0
		for end < len(msg) && msg[end] != 0 {
			end++
		}
		if end+1+18 > len(msg) {
			return nil, errors.New("pgwire: truncated row description")
		}
		cols = append(cols, string(msg[:end]))
		msg = msg[end+1+18:]
	}
	return cols, nil
}

func parseDataRow(msg []byte) ([]*string, error) {
	if len(msg) < 2 {
		return nil, errors.New("pgwire: short data row")
	}
	n := int(binary.BigEndian.Uint16(msg))
	msg = msg[2:]
	row := make([]*string, 0, n)
	for i := 0; i < n; i++ {
		if len(msg) < 4 {
			return nil, errors.New("pgwire: truncated data row")
		}
		l := int32(binary.BigEndian.Uint32(msg))
		msg = msg[4:]
		if l < 0 {
			row = append(row, nil)
			continue
		}
		if int(l) > len(msg) {
			return nil, errors.New("pgwire: truncated data row")
		}
		v := string(msg[:l])
		row = append(row, &v)
		msg = msg[l:]
	}
	return row, nil
}

// Literal — строковый литерал SQL: одинарные кавычки удвоены. Рассчитан на
// standard_conforming_strings = on (по умолчанию с PostgreSQL 9.1).
func Literal(s string) string { return "'" + strings.ReplaceAll(s, "'", "''") + "'" }

// Ident — идентификатор SQL в двойных кавычках.
func Ident(s string) string { return `"` + strings.ReplaceAll(s, `"`, `""`) + `"` }

// LSN — позиция в журнале PostgreSQL.
type LSN uint64

func (l LSN) String() string { return fmt.Sprintf("%X/%X", uint32(l>>32), uint32(l)) }

// ParseLSN разбирает запись "16/B374D848".
func ParseLSN(s string) (LSN, error) {
	hi, lo, ok := strings.Cut(s, "/")
	h, err1 := strconv.ParseUint(hi, 16, 32)
	l, err2 := strconv.ParseUint(lo, 16, 32)
	if !ok || err1 != nil || err2 != nil {
		return 0, fmt.Errorf("pgwire: %q is not an LSN", s)
	}
	return LSN(h<<32 | l), nil
}

// pgEpoch — начало отсчёта времени в протоколе репликации: 2000-01-01 UTC.
var pgEpoch = time.Date(2000, 1, 1, 0, 0, 0, 0, time.UTC)

// Time — время протокола (микросекунды от 2000-01-01) как time.Time.
func Time(micros int64) time.Time { return pgEpoch.Add(time.Duration(micros) * time.Microsecond) }

// StartReplication начинает поток логической репликации из слота с того места,
// которое слот подтвердил. options — параметры плагина парами "имя", "значение".
// Соединение должно быть открыто с Replication.
func (c *Conn) StartReplication(slot string, options ...string) error {
	if len(options)%2 != 0 {
		return errors.New("pgwire: plugin options come in pairs")
	}
	var opts []string
	for i := 0; i < len(options); i += 2 {
		opts = append(opts, Ident(options[i])+" "+Literal(options[i+1]))
	}
	sql := "START_REPLICATION SLOT " + Ident(slot) + " LOGICAL 0/0"
	if len(opts) > 0 {
		sql += " (" + strings.Join(opts, ", ") + ")"
	}
	if _, err := c.Query(sql); err != nil {
		return err
	}
	if !c.stream {
		return errors.New("pgwire: the server did not start a replication stream")
	}
	return nil
}

// ReplMessage — сообщение потока: либо данные журнала, либо «я жив» от сервера.
type ReplMessage struct {
	Keepalive      bool
	ReplyRequested bool   // сервер ждёт отчёт сейчас (иначе оборвёт по wal_sender_timeout)
	WALStart       LSN    // начало данных (только у данных)
	WALEnd         LSN    // конец журнала на сервере
	Data           []byte // сообщение плагина (pgoutput)
}

// ReadReplication ждёт следующее сообщение потока не дольше timeout (0 — без
// предела). Нет сообщения — ErrTimeout, и поток остаётся целым: ожидание
// обрывается только до первого байта сообщения, начатое читается до конца.
func (c *Conn) ReadReplication(timeout time.Duration) (ReplMessage, error) {
	if !c.stream {
		return ReplMessage{}, errors.New("pgwire: replication is not started")
	}
	for {
		if timeout > 0 {
			c.nc.SetReadDeadline(time.Now().Add(timeout))
		}
		_, err := c.r.Peek(1)
		c.nc.SetReadDeadline(time.Time{})
		if err != nil {
			var ne net.Error
			if errors.As(err, &ne) && ne.Timeout() {
				return ReplMessage{}, ErrTimeout
			}
			return ReplMessage{}, err
		}
		typ, msg, err := c.read()
		if err != nil {
			return ReplMessage{}, err
		}
		switch typ {
		case 'd':
			if len(msg) == 0 {
				return ReplMessage{}, errors.New("pgwire: empty copy data")
			}
			switch msg[0] {
			case 'w':
				if len(msg) < 25 {
					return ReplMessage{}, errors.New("pgwire: short XLogData")
				}
				return ReplMessage{
					WALStart: LSN(binary.BigEndian.Uint64(msg[1:])),
					WALEnd:   LSN(binary.BigEndian.Uint64(msg[9:])),
					Data:     msg[25:],
				}, nil
			case 'k':
				if len(msg) < 18 {
					return ReplMessage{}, errors.New("pgwire: short keepalive")
				}
				return ReplMessage{Keepalive: true, WALEnd: LSN(binary.BigEndian.Uint64(msg[1:])), ReplyRequested: msg[17] != 0}, nil
			default:
				return ReplMessage{}, fmt.Errorf("pgwire: unknown replication message %q", msg[0])
			}
		case 'E':
			return ReplMessage{}, parseError(msg)
		case 'c':
			return ReplMessage{}, io.EOF // сервер закончил поток
		case 'N', 'S':
		default:
			return ReplMessage{}, fmt.Errorf("pgwire: unexpected message %q in the replication stream", typ)
		}
	}
}

// SendStandbyStatus сообщает серверу, до какой позиции журнал у нас надёжно
// сохранён: всё до неё сервер может больше не держать для слота.
func (c *Conn) SendStandbyStatus(flushed LSN) error {
	if !c.stream {
		return errors.New("pgwire: replication is not started")
	}
	b := make([]byte, 0, 34)
	b = append(b, 'r')
	b = binary.BigEndian.AppendUint64(b, uint64(flushed)) // записано
	b = binary.BigEndian.AppendUint64(b, uint64(flushed)) // сброшено на диск
	b = binary.BigEndian.AppendUint64(b, uint64(flushed)) // применено
	b = binary.BigEndian.AppendUint64(b, uint64(time.Since(pgEpoch)/time.Microsecond))
	b = append(b, 0)
	return c.send('d', b)
}
