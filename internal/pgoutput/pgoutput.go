// Package pgoutput разбирает сообщения встроенного плагина логического
// декодирования PostgreSQL (pgoutput, версия протокола 1; документация —
// «Logical Replication Message Formats»).
//
// Плагин отдаёт транзакцию целиком после её фиксации: Begin, затем Relation
// (описание таблицы перед первым её изменением), Insert/Update/Delete/Truncate
// и Message (pg_logical_emit_message), в конце Commit. Значения колонок — текстом.
package pgoutput

import (
	"encoding/binary"
	"errors"
	"fmt"
	"time"
)

// ErrMalformed — байты не складываются в сообщение pgoutput.
var ErrMalformed = errors.New("pgoutput: malformed message")

// Begin — начало транзакции.
type Begin struct {
	FinalLSN   uint64
	CommitTime time.Time
	XID        uint32
}

// Commit — конец транзакции. EndLSN — позиция, до которой журнал прочитан,
// когда транзакция обработана целиком: её и подтверждают серверу.
type Commit struct {
	CommitLSN, EndLSN uint64
	CommitTime        time.Time
}

// Column — колонка таблицы. Key — входит в идентичность строки; при
// REPLICA IDENTITY FULL это все колонки, и первичный ключ отсюда не узнать.
type Column struct {
	Key     bool
	Name    string
	TypeOID uint32
	TypeMod int32
}

// Relation — описание таблицы. Identity: 'd' — первичный ключ, 'f' — вся
// строка (FULL), 'i' — индекс, 'n' — ничего.
type Relation struct {
	ID        uint32
	Namespace string
	Name      string
	Identity  byte
	Columns   []Column
}

// Виды значения в кортеже.
const (
	Null      = 'n'
	Unchanged = 'u' // значение в TOAST, запросом не менялось и в журнал не попало
	Text      = 't'
	Binary    = 'b'
)

// Value — значение одной колонки.
type Value struct {
	Kind byte
	Data []byte
}

// Insert — вставленная строка.
type Insert struct {
	RelID uint32
	New   []Value
}

// Update — правка строки. OldKind: 'O' — старая строка целиком (REPLICA
// IDENTITY FULL), 'K' — только её ключ, 0 — старой строки в журнале нет.
type Update struct {
	RelID   uint32
	OldKind byte
	Old     []Value
	New     []Value
}

// Delete — удалённая строка. OldKind — как у Update.
type Delete struct {
	RelID   uint32
	OldKind byte
	Old     []Value
}

// Truncate — TRUNCATE таблиц: строк в журнале нет.
type Truncate struct {
	Cascade bool
	RelIDs  []uint32
}

// Message — pg_logical_emit_message.
type Message struct {
	Transactional bool
	LSN           uint64
	Prefix        string
	Content       []byte
}

// Other — сообщение, которое этому разбору не нужно (Origin, Type).
type Other struct{ Type byte }

var epoch = time.Date(2000, 1, 1, 0, 0, 0, 0, time.UTC)

type reader struct {
	b   []byte
	err error
}

func (r *reader) take(n int) []byte {
	if r.err != nil || n < 0 || n > len(r.b) {
		r.err = ErrMalformed
		return nil
	}
	out := r.b[:n]
	r.b = r.b[n:]
	return out
}

func (r *reader) u8() byte {
	if b := r.take(1); b != nil {
		return b[0]
	}
	return 0
}

func (r *reader) u16() uint16 {
	if b := r.take(2); b != nil {
		return binary.BigEndian.Uint16(b)
	}
	return 0
}

func (r *reader) u32() uint32 {
	if b := r.take(4); b != nil {
		return binary.BigEndian.Uint32(b)
	}
	return 0
}

func (r *reader) u64() uint64 {
	if b := r.take(8); b != nil {
		return binary.BigEndian.Uint64(b)
	}
	return 0
}

func (r *reader) time() time.Time {
	return epoch.Add(time.Duration(int64(r.u64())) * time.Microsecond)
}

func (r *reader) str() string {
	for i, c := range r.b {
		if c == 0 {
			s := string(r.b[:i])
			r.b = r.b[i+1:]
			return s
		}
	}
	r.err = ErrMalformed
	return ""
}

func (r *reader) tuple() []Value {
	n := int(r.u16())
	if r.err != nil {
		return nil
	}
	out := make([]Value, 0, min(n, 1024))
	for i := 0; i < n && r.err == nil; i++ {
		switch kind := r.u8(); kind {
		case Null, Unchanged:
			out = append(out, Value{Kind: kind})
		case Text, Binary:
			out = append(out, Value{Kind: kind, Data: r.take(int(int32(r.u32())))})
		default:
			r.err = ErrMalformed
		}
	}
	return out
}

// Parse разбирает одно сообщение плагина. Лишние байты в конце — ошибка.
func Parse(data []byte) (any, error) {
	if len(data) == 0 {
		return nil, ErrMalformed
	}
	r := &reader{b: data[1:]}
	var out any
	switch data[0] {
	case 'B':
		out = Begin{FinalLSN: r.u64(), CommitTime: r.time(), XID: r.u32()}
	case 'C':
		r.u8() // флаги, сейчас всегда 0
		out = Commit{CommitLSN: r.u64(), EndLSN: r.u64(), CommitTime: r.time()}
	case 'R':
		rel := Relation{ID: r.u32(), Namespace: r.str(), Name: r.str(), Identity: r.u8()}
		n := int(r.u16())
		for i := 0; i < n && r.err == nil; i++ {
			rel.Columns = append(rel.Columns, Column{Key: r.u8()&1 != 0, Name: r.str(), TypeOID: r.u32(), TypeMod: int32(r.u32())})
		}
		out = rel
	case 'I':
		ins := Insert{RelID: r.u32()}
		if r.u8() != 'N' {
			r.err = ErrMalformed
		}
		ins.New = r.tuple()
		out = ins
	case 'U':
		up := Update{RelID: r.u32()}
		kind := r.u8()
		if kind == 'K' || kind == 'O' {
			up.OldKind, up.Old = kind, r.tuple()
			kind = r.u8()
		}
		if kind != 'N' {
			r.err = ErrMalformed
		}
		up.New = r.tuple()
		out = up
	case 'D':
		del := Delete{RelID: r.u32(), OldKind: r.u8()}
		if del.OldKind != 'K' && del.OldKind != 'O' {
			r.err = ErrMalformed
		}
		del.Old = r.tuple()
		out = del
	case 'T':
		n := int(r.u32())
		tr := Truncate{Cascade: r.u8()&1 != 0}
		for i := 0; i < n && r.err == nil; i++ {
			tr.RelIDs = append(tr.RelIDs, r.u32())
		}
		out = tr
	case 'M':
		m := Message{Transactional: r.u8()&1 != 0, LSN: r.u64(), Prefix: r.str()}
		m.Content = r.take(int(int32(r.u32())))
		out = m
	case 'O', 'Y':
		return Other{Type: data[0]}, nil
	default:
		return nil, fmt.Errorf("%w: unknown type %q", ErrMalformed, data[0])
	}
	if r.err != nil {
		return nil, fmt.Errorf("%w: type %q", r.err, data[0])
	}
	if len(r.b) != 0 {
		return nil, fmt.Errorf("%w: %d trailing bytes after type %q", ErrMalformed, len(r.b), data[0])
	}
	return out, nil
}
