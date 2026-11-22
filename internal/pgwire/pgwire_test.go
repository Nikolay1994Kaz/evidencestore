package pgwire

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"strings"
	"testing"
	"time"
)

// Вектор RFC 7677, раздел 3: пользователь user, пароль pencil.
func TestScramRFC7677(t *testing.T) {
	s, err := newScram("pencil", []byte("rOprNGfwEbeRWgbNEkqO"))
	if err != nil {
		t.Fatal(err)
	}
	s.user = "user"
	if got := string(s.first()); got != "n,,n=user,r=rOprNGfwEbeRWgbNEkqO" {
		t.Fatalf("client-first: %s", got)
	}
	final, err := s.final([]byte("r=rOprNGfwEbeRWgbNEkqO%hvYDpWUa2RaTCAfuxFIlj)hNlF$k0,s=W22ZaJ0SNY7soEsUEjb6gQ==,i=4096"))
	if err != nil {
		t.Fatal(err)
	}
	want := "c=biws,r=rOprNGfwEbeRWgbNEkqO%hvYDpWUa2RaTCAfuxFIlj)hNlF$k0,p=dHzbZapWIk4jUhN+Ute9ytag9zjfMHgsqmmiz7AndVQ="
	if string(final) != want {
		t.Fatalf("client-final:\n got %s\nwant %s", final, want)
	}
	if err := s.verify([]byte("v=6rriTRBi23WpRR/wtup+mMhUZUn/dB5nLTJRsjl95G4=")); err != nil {
		t.Fatal(err)
	}
	// Сервер без пароля сложить подпись не может: чужая подпись — отказ.
	if err := s.verify([]byte("v=7rriTRBi23WpRR/wtup+mMhUZUn/dB5nLTJRsjl95G4=")); err == nil {
		t.Fatal("a wrong server signature passed")
	}
}

func TestScramRefusesBadServerFirst(t *testing.T) {
	for _, first := range []string{
		"r=other,s=W22ZaJ0SNY7soEsUEjb6gQ==,i=4096", // nonce не продолжает наш
		"r=abc,s=W22ZaJ0SNY7soEsUEjb6gQ==,i=4096",   // сервер не добавил своей части
		"r=abcd,s=,i=4096",                          // нет соли
		"r=abcd,s=W22ZaJ0SNY7soEsUEjb6gQ==,i=0",     // нет итераций
	} {
		s, _ := newScram("p", []byte("abc"))
		s.first()
		if _, err := s.final([]byte(first)); err == nil {
			t.Errorf("accepted %q", first)
		}
	}
}

func TestParseDSN(t *testing.T) {
	c, err := ParseDSN("host=/tmp/sock port=5433 user=tap dbname=shop application_name='es tap' replication=database")
	if err != nil {
		t.Fatal(err)
	}
	if c.Network != "unix" || c.Address != "/tmp/sock/.s.PGSQL.5433" || c.User != "tap" || c.Database != "shop" || c.AppName != "es tap" || !c.Replication {
		t.Fatalf("%+v", c)
	}
	c, err = ParseDSN(`host=db.example user=u password='a b\'c' sslmode=verify-full`)
	if err != nil {
		t.Fatal(err)
	}
	if c.Network != "tcp" || c.Address != "db.example:5432" || c.Host != "db.example" || c.Password != "a b'c" || c.Database != "u" {
		t.Fatalf("%+v", c)
	}
	for _, bad := range []string{"user=u sslmode=prefer", "host=h", "user=u port=x", "user=u nope=1", "user=u password='x"} {
		if _, err := ParseDSN(bad); err == nil {
			t.Errorf("accepted %q", bad)
		}
	}
}

func TestLSN(t *testing.T) {
	l, err := ParseLSN("16/B374D848")
	if err != nil || l != 0x16B374D848 || l.String() != "16/B374D848" {
		t.Fatalf("%v %x %s", err, uint64(l), l)
	}
	for _, bad := range []string{"", "16", "x/1", "1/100000000"} {
		if _, err := ParseLSN(bad); err == nil {
			t.Errorf("accepted %q", bad)
		}
	}
}

func TestLiteralAndIdent(t *testing.T) {
	if Literal("it's") != "'it''s'" || Ident(`a"b`) != `"a""b"` {
		t.Fatal(Literal("it's"), Ident(`a"b`))
	}
	// С чертой — E'…' и черта удвоена: литерал не зависит от
	// standard_conforming_strings (P-256). Как его читает база — TestLive.
	if got := Literal(`x\`); got != ` E'x\\'` {
		t.Fatal(got)
	}
	if got := Literal(`a\'b`); got != ` E'a\\''b'` {
		t.Fatal(got)
	}
}

func TestParseError(t *testing.T) {
	e := parseError([]byte("SERROR\x00C42501\x00Mpermission denied\x00Hask\x00\x00"))
	if e.Code != "42501" || e.Message != "permission denied" || e.Hint != "ask" || !strings.Contains(e.Error(), "42501") {
		t.Fatalf("%+v", e)
	}
}

func TestRows(t *testing.T) {
	cols, err := parseRowDescription(append([]byte{0, 1, 'a', 0}, make([]byte, 18)...))
	if err != nil || len(cols) != 1 || cols[0] != "a" {
		t.Fatal(cols, err)
	}
	row, err := parseDataRow([]byte{0, 2, 0xff, 0xff, 0xff, 0xff, 0, 0, 0, 2, 'o', 'k'})
	if err != nil || row[0] != nil || *row[1] != "ok" {
		t.Fatal(row, err)
	}
	if _, err := parseDataRow([]byte{0, 1, 0, 0, 0, 9, 'x'}); err == nil {
		t.Fatal("a truncated row passed")
	}
}

// Вход по TLS не удался: Dial возвращает ошибку и закрывает соединение.
// Сервер здесь — заглушка: читает SSLRequest и отвечает, как сказано в reply
// ("" — рвёт соединение молча). До исправления P-231 каждый из путей ронял
// процесс: отложенное закрытие шло по nil.
func TestDialTLSFailureIsAnError(t *testing.T) {
	for _, tc := range []struct{ name, reply, dsn, want string }{
		{"the server has TLS off", "N", "sslmode=require", "refused TLS"},
		{"the server drops the connection", "", "sslmode=require", "EOF"},
		{"no root file", "S", "sslmode=verify-full sslrootcert=/nonexistent/root.crt", "sslrootcert"},
		{"not a TLS server", "Sthis is not a TLS handshake", "sslmode=require", "pgwire: TLS"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ln, err := net.Listen("tcp", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			defer ln.Close()
			closed := make(chan struct{}) // заглушка увидела конец соединения
			go func() {
				defer close(closed)
				c, err := ln.Accept()
				if err != nil {
					return
				}
				defer c.Close()
				var req [8]byte
				if _, err := io.ReadFull(c, req[:]); err != nil || tc.reply == "" {
					return
				}
				c.Write([]byte(tc.reply))
				io.Copy(io.Discard, c) // до тех пор, пока клиент не закроет соединение
			}()
			cfg, err := ParseDSN(fmt.Sprintf("host=127.0.0.1 port=%d user=u dbname=d %s", ln.Addr().(*net.TCPAddr).Port, tc.dsn))
			if err != nil {
				t.Fatal(err)
			}
			c, err := Dial(context.Background(), cfg)
			if err == nil {
				c.Close()
				t.Fatal("connected")
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("error %q, expected one with %q", err, tc.want)
			}
			select {
			case <-closed:
			case <-time.After(5 * time.Second):
				t.Fatal("the connection was left open")
			}
		})
	}
}

// Отмена запроса идёт новым соединением; TLS на нём не удался — Cancel
// возвращает ошибку и закрывает соединение, а не роняет процесс: таймер
// MCP-сервера после неудачной отмены закрывает соединение с запросом сам.
func TestCancelTLSFailureIsAnError(t *testing.T) {
	for _, tc := range []struct{ name, reply, want string }{
		{"the server has TLS off", "N", "refused TLS"},
		{"the server drops the connection", "", "EOF"},
		{"not a TLS server", "Sthis is not a TLS handshake", "pgwire: TLS"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ln, err := net.Listen("tcp", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			defer ln.Close()
			closed := make(chan struct{}) // заглушка увидела конец соединения
			go func() {
				defer close(closed)
				c, err := ln.Accept()
				if err != nil {
					return
				}
				defer c.Close()
				var req [8]byte
				if _, err := io.ReadFull(c, req[:]); err != nil || tc.reply == "" {
					return
				}
				c.Write([]byte(tc.reply))
				io.Copy(io.Discard, c)
			}()
			cfg, err := ParseDSN(fmt.Sprintf("host=127.0.0.1 port=%d user=u dbname=d sslmode=require", ln.Addr().(*net.TCPAddr).Port))
			if err != nil {
				t.Fatal(err)
			}
			c := &Conn{cfg: cfg, pid: 7, secret: 9}
			err = c.Cancel()
			if err == nil {
				t.Fatal("no error")
			}
			if !strings.Contains(err.Error(), tc.want) || !strings.Contains(err.Error(), "cancel") {
				t.Fatalf("error %q, expected a cancel error with %q", err, tc.want)
			}
			select {
			case <-closed:
			case <-time.After(5 * time.Second):
				t.Fatal("the connection was left open")
			}
		})
	}
	// Сервер не дал ключа отмены — просить нечем.
	if err := (&Conn{}).Cancel(); err == nil {
		t.Fatal("cancelled without a key")
	}
}

// msg — сообщение сервера: тип, длина, тело.
func msg(typ byte, body ...byte) []byte {
	return append([]byte{typ, 0, 0, 0, byte(len(body) + 4)}, body...)
}

// Пачка уходит одной записью: на каждую команду Parse, Bind, Describe,
// Execute, в конце один Sync. Ответ разбирается по командам; после ошибки
// сервер пропускает остальное, и состояние транзакции — из ReadyForQuery.
func TestPipelineFramesAndAnswers(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	got := make(chan string, 1) // типы сообщений пачки, как их прочла заглушка
	go func() {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		defer c.Close()
		var n [4]byte
		io.ReadFull(c, n[:]) // стартовое сообщение
		io.CopyN(io.Discard, c, int64(n[0])<<24|int64(n[1])<<16|int64(n[2])<<8|int64(n[3])-4)
		c.Write(append(msg('R', 0, 0, 0, 0), msg('Z', 'I')...)) // вход без пароля
		var types []byte
		for {
			var head [5]byte
			if _, err := io.ReadFull(c, head[:]); err != nil {
				return
			}
			body := make([]byte, int(head[1])<<24|int(head[2])<<16|int(head[3])<<8|int(head[4])-4)
			io.ReadFull(c, body)
			types = append(types, head[0])
			if head[0] == 'P' && !strings.Contains(string(body), "SELECT") {
				types = append(types, '?') // Parse без текста команды
			}
			if head[0] == 'S' {
				break
			}
		}
		got <- string(types)
		var answer []byte
		answer = append(answer, msg('1')...)
		answer = append(answer, msg('2')...)
		answer = append(answer, msg('T', append([]byte{0, 1, 'a', 0}, make([]byte, 18)...)...)...)
		answer = append(answer, msg('D', 0, 1, 0, 0, 0, 1, '7')...)
		answer = append(answer, msg('C', []byte("SELECT 1\x00")...)...)
		answer = append(answer, msg('E', []byte("SERROR\x00C42601\x00Mcannot insert multiple commands into a prepared statement\x00\x00")...)...)
		answer = append(answer, msg('Z', 'E')...)
		c.Write(answer)
		io.Copy(io.Discard, c)
	}()
	cfg, err := ParseDSN(fmt.Sprintf("host=127.0.0.1 port=%d user=u dbname=d", ln.Addr().(*net.TCPAddr).Port))
	if err != nil {
		t.Fatal(err)
	}
	c, err := Dial(context.Background(), cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	if c.TxStatus() != TxIdle {
		t.Fatalf("after the start: %c", c.TxStatus())
	}
	res, err := c.Pipeline([]string{"SELECT 7 AS a", "SELECT 1; SELECT 2"})
	if types := <-got; types != "PBDEPBDES" {
		t.Fatalf("the pipeline went as %q", types)
	}
	var pg *PgError
	if !errors.As(err, &pg) || pg.Code != "42601" || len(res) != 1 || res[0].Columns[0] != "a" || *res[0].Rows[0][0] != "7" || res[0].Tag != "SELECT 1" {
		t.Fatalf("%+v %v", res, err)
	}
	if c.TxStatus() != TxFailed {
		t.Fatalf("after the error: %c", c.TxStatus())
	}
	if _, err := c.Pipeline([]string{"SELECT 1\x00"}); err == nil {
		t.Fatal("a zero byte went through")
	}
}
