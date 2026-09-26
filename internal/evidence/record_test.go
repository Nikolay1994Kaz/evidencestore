package evidence

import (
	"bytes"
	"encoding/hex"
	"errors"
	"reflect"
	"strings"
	"testing"
)

func sample() Sealed {
	return Sealed{
		Header: Header{
			Source:      "abs-core",
			Seq:         42,
			ReceivedAt:  1758800000000000000,
			ContentType: "syslog",
		},
		Envelope: []byte("EV1-test-envelope"),
	}
}

func maxSample() Sealed {
	s := sample()
	s.Source = strings.Repeat("s", MaxSourceLen)
	s.ContentType = strings.Repeat("c", MaxContentTypeLen)
	s.Envelope = bytes.Repeat([]byte{7}, MaxEnvelopeLen)
	return s
}

// Кодирование → разбор → снова кодирование даёт те же байты,
// в том числе когда все поля на пределе.
func TestRoundTrip(t *testing.T) {
	for _, s := range []Sealed{sample(), maxSample()} {
		b, err := s.Marshal()
		if err != nil {
			t.Fatal(err)
		}
		got, err := Unmarshal(b)
		if err != nil {
			t.Fatal(err)
		}
		if !reflect.DeepEqual(got, s) {
			t.Fatalf("round trip changed the record (source %q)", s.Source)
		}
		b2, err := got.Marshal()
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(b, b2) {
			t.Fatal("re-marshal gave different bytes")
		}
	}
}

// Формат закреплён байт в байт. Если тест упал, значит изменился формат, а с
// ним и отпечатки всех прежних записей: нужна новая Version, а не правка эталона.
func TestGoldenBytes(t *testing.T) {
	want := "01" + // version
		"000000000000002a" + // seq = 42
		"186883480ef50000" + // received_at
		"00000008" + "6162732d636f7265" + // "abs-core"
		"00000006" + "7379736c6f67" + // "syslog"
		"00000011" + "4556312d746573742d656e76656c6f7065" // "EV1-test-envelope"
	b, err := sample().Marshal()
	if err != nil {
		t.Fatal(err)
	}
	if got := hex.EncodeToString(b); got != want {
		t.Fatalf("bytes:\n got %s\nwant %s", got, want)
	}
	const wantDigest = "7898975b39a617570d234c872d51ab48db6dc27eed1da34d67122d2b11748019"
	d := Digest(b)
	if got := hex.EncodeToString(d[:]); got != wantDigest {
		t.Fatalf("digest: got %s, want %s", got, wantDigest)
	}
}

func TestMarshalRejectsInvalid(t *testing.T) {
	cases := map[string]func(*Sealed){
		"empty source":       func(s *Sealed) { s.Source = "" },
		"long source":        func(s *Sealed) { s.Source = strings.Repeat("a", MaxSourceLen+1) },
		"invalid utf8":       func(s *Sealed) { s.Source = "\xff" },
		"zero seq":           func(s *Sealed) { s.Seq = 0 },
		"zero received_at":   func(s *Sealed) { s.ReceivedAt = 0 },
		"long content type":  func(s *Sealed) { s.ContentType = strings.Repeat("a", MaxContentTypeLen+1) },
		"empty envelope":     func(s *Sealed) { s.Envelope = nil },
		"oversized envelope": func(s *Sealed) { s.Envelope = make([]byte, MaxEnvelopeLen+1) },
	}
	for name, mutate := range cases {
		s := sample()
		mutate(&s)
		if _, err := s.Marshal(); err == nil {
			t.Errorf("%s: Marshal accepted invalid record", name)
		}
	}
}

// Любой обрезанный префикс, лишний байт в конце и чужая версия — ошибка,
// а не «частично разобранная» улика.
func TestUnmarshalRejectsMalformed(t *testing.T) {
	b, err := sample().Marshal()
	if err != nil {
		t.Fatal(err)
	}
	for n := 0; n < len(b); n++ {
		if _, err := Unmarshal(b[:n]); !errors.Is(err, ErrMalformed) {
			t.Fatalf("truncated to %d bytes: err = %v, want ErrMalformed", n, err)
		}
	}
	trailing := append(append([]byte(nil), b...), 0)
	if _, err := Unmarshal(trailing); !errors.Is(err, ErrMalformed) {
		t.Fatalf("trailing byte: err = %v, want ErrMalformed", err)
	}
	zeroSeq := append([]byte(nil), b...)
	copy(zeroSeq[1:9], make([]byte, 8))
	if _, err := Unmarshal(zeroSeq); !errors.Is(err, ErrMalformed) {
		t.Fatalf("zero seq: err = %v, want ErrMalformed", err)
	}
	bad := append([]byte(nil), b...)
	bad[0] = Version + 1
	if _, err := Unmarshal(bad); !errors.Is(err, ErrMalformed) {
		t.Fatalf("unknown version: err = %v, want ErrMalformed", err)
	}
}

// Префикс длины делает разбиение однозначным: "ab"+"c" и "a"+"bc" — разные записи.
func TestFieldBoundariesUnambiguous(t *testing.T) {
	x, y := sample(), sample()
	x.Source, x.ContentType = "ab", "c"
	y.Source, y.ContentType = "a", "bc"
	bx, err := x.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	by, err := y.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	if Digest(bx) == Digest(by) {
		t.Fatal("different records gave the same digest")
	}
}

// Разобранная улика не должна зависеть от буфера, из которого её разобрали.
func TestUnmarshalCopiesEnvelope(t *testing.T) {
	b, err := sample().Marshal()
	if err != nil {
		t.Fatal(err)
	}
	s, err := Unmarshal(b)
	if err != nil {
		t.Fatal(err)
	}
	for i := range b {
		b[i] = 0
	}
	if string(s.Envelope) != "EV1-test-envelope" {
		t.Fatalf("envelope changed with input buffer: %q", s.Envelope)
	}
}

// Всё, что Unmarshal принял, кодируется обратно в те же байты: у улики ровно
// одно представление. Запуск: go test -fuzz=FuzzUnmarshal ./internal/evidence
func FuzzUnmarshal(f *testing.F) {
	b, err := sample().Marshal()
	if err != nil {
		f.Fatal(err)
	}
	f.Add(b)
	f.Fuzz(func(t *testing.T, data []byte) {
		s, err := Unmarshal(data)
		if err != nil {
			return
		}
		again, err := s.Marshal()
		if err != nil {
			t.Fatalf("accepted record does not marshal: %v", err)
		}
		if !bytes.Equal(again, data) {
			t.Fatalf("non-canonical input accepted:\n in  %x\n out %x", data, again)
		}
	})
}
