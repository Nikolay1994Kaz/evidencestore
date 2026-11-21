package pgwire

import (
	"strings"
	"testing"
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
