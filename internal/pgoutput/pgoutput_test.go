package pgoutput

import (
	"encoding/binary"
	"errors"
	"reflect"
	"testing"
	"time"
)

type b []byte

func (x b) u8(v byte) b    { return append(x, v) }
func (x b) u16(v uint16) b { return binary.BigEndian.AppendUint16(x, v) }
func (x b) u32(v uint32) b { return binary.BigEndian.AppendUint32(x, v) }
func (x b) u64(v uint64) b { return binary.BigEndian.AppendUint64(x, v) }
func (x b) str(s string) b { return append(append(x, s...), 0) }
func (x b) tuple(vals ...any) b {
	x = x.u16(uint16(len(vals)))
	for _, v := range vals {
		switch v := v.(type) {
		case nil:
			x = x.u8('n')
		case byte:
			x = x.u8(v) // 'u'
		case string:
			x = append(x.u8('t').u32(uint32(len(v))), v...)
		}
	}
	return x
}

func text(s string) Value { return Value{Kind: Text, Data: []byte(s)} }

func TestParse(t *testing.T) {
	at := time.Date(2026, 11, 21, 10, 0, 0, 0, time.UTC)
	micros := uint64(at.Sub(epoch) / time.Microsecond)
	cases := []struct {
		name string
		in   b
		want any
	}{
		{"begin", b{'B'}.u64(100).u64(micros).u32(751), Begin{FinalLSN: 100, CommitTime: at, XID: 751}},
		{"commit", b{'C'}.u8(0).u64(100).u64(180).u64(micros), Commit{CommitLSN: 100, EndLSN: 180, CommitTime: at}},
		{"relation", b{'R'}.u32(7).str("public").str("accounts").u8('f').u16(2).u8(1).str("id").u32(23).u32(0xffffffff).u8(1).str("note").u32(25).u32(0xffffffff),
			Relation{ID: 7, Namespace: "public", Name: "accounts", Identity: 'f', Columns: []Column{{true, "id", 23, -1}, {true, "note", 25, -1}}}},
		{"insert", b{'I'}.u32(7).u8('N').tuple("6", nil), Insert{RelID: 7, New: []Value{text("6"), {Kind: Null}}}},
		{"update with the old row", b{'U'}.u32(7).u8('O').tuple("6", "a").u8('N').tuple("6", byte('u')),
			Update{RelID: 7, OldKind: 'O', Old: []Value{text("6"), text("a")}, New: []Value{text("6"), {Kind: Unchanged}}}},
		{"update without the old row", b{'U'}.u32(7).u8('N').tuple("6"), Update{RelID: 7, New: []Value{text("6")}}},
		{"delete", b{'D'}.u32(7).u8('O').tuple("6", ""), Delete{RelID: 7, OldKind: 'O', Old: []Value{text("6"), text("")}}},
		{"truncate", b{'T'}.u32(2).u8(1).u32(7).u32(8), Truncate{Cascade: true, RelIDs: []uint32{7, 8}}},
		{"message", append(b{'M'}.u8(1).u64(55).str("evidence/who").u32(2), "{}"...), Message{Transactional: true, LSN: 55, Prefix: "evidence/who", Content: []byte("{}")}},
		{"origin", b{'O'}.u64(1).str("x"), Other{Type: 'O'}},
	}
	for _, c := range cases {
		got, err := Parse(c.in)
		if err != nil {
			t.Errorf("%s: %v", c.name, err)
			continue
		}
		if !reflect.DeepEqual(got, c.want) {
			t.Errorf("%s:\n got %+v\nwant %+v", c.name, got, c.want)
		}
		if c.name == "origin" {
			continue
		}
		// Любой обрезок и любой лишний байт — ошибка, а не паника и не полразбора.
		for n := 0; n < len(c.in); n++ {
			if _, err := Parse(c.in[:n]); !errors.Is(err, ErrMalformed) {
				t.Errorf("%s cut to %d bytes: %v", c.name, n, err)
			}
		}
		if _, err := Parse(append(append(b{}, c.in...), 0)); !errors.Is(err, ErrMalformed) {
			t.Errorf("%s with a trailing byte: %v", c.name, err)
		}
	}
}

func TestParseRefusesUnknown(t *testing.T) {
	for _, in := range []b{{'Z'}, b{'I'}.u32(7).u8('X').tuple("1"), b{'D'}.u32(7).u8('N').tuple("1"), b{'I'}.u32(7).u8('N').u16(1).u8('?'),
		// длина значения больше остатка сообщения, в том числе «отрицательная»
		b{'I'}.u32(7).u8('N').u16(1).u8('t').u32(9), b{'I'}.u32(7).u8('N').u16(1).u8('t').u32(0xffffffff)} {
		if _, err := Parse(in); !errors.Is(err, ErrMalformed) {
			t.Errorf("%q: %v", []byte(in), err)
		}
	}
}

func FuzzParse(f *testing.F) {
	f.Add([]byte(b{'U'}.u32(7).u8('O').tuple("6", "a").u8('N').tuple("6", byte('u'))))
	f.Add([]byte(b{'R'}.u32(7).str("public").str("t").u8('f').u16(1).u8(1).str("id").u32(23).u32(0)))
	f.Fuzz(func(t *testing.T, in []byte) { Parse(in) })
}
