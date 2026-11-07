package evidence

import (
	"bytes"
	"errors"
	"strings"
	"testing"
)

func TestSubjectOf(t *testing.T) {
	long := strings.Repeat("x", MaxSubjectLen)
	for _, tc := range []struct {
		name, body string
		want       string
		ok         bool
	}{
		{"строка", `{"client":"c-1","text":"перевод"}`, "c-1", true},
		{"поле не первое", `{"ts":1,"nested":{"client":"x"},"client":"c-1"}`, "c-1", true},
		{"число", `{"client":104233}`, "104233", true},
		{"большое число не теряет цифр", `{"client":123456789012345678901}`, "123456789012345678901", true},
		{"экранирование", `{"client":"c-1"}`, "c-1", true},
		{"пробелы вокруг", " \n{\"client\": \"c-1\"}\n ", "c-1", true},
		{"кириллица", `{"client":"Клиент 1"}`, "Клиент 1", true},
		{"на пределе", `{"client":"` + long + `"}`, long, true},

		{"длиннее предела", `{"client":"` + long + `x"}`, "", false},
		{"нет поля", `{"account":"c-1"}`, "", false},
		{"только вложенное", `{"meta":{"client":"c-1"}}`, "", false},
		{"другой регистр", `{"Client":"c-1"}`, "", false},
		{"пустое значение", `{"client":""}`, "", false},
		{"null", `{"client":null}`, "", false},
		{"булево", `{"client":true}`, "", false},
		{"объект", `{"client":{"id":1}}`, "", false},
		{"массив", `{"client":["c-1"]}`, "", false},
		{"поле дважды, одно значение", `{"client":"c-1","client":"c-1"}`, "", false},
		{"поле дважды, разные", `{"client":"c-1","text":"x","client":"c-2"}`, "", false},
		{"массив вместо объекта", `["client","c-1"]`, "", false},
		{"строка вместо объекта", `"client"`, "", false},
		{"не JSON", `client=c-1`, "", false},
		{"пусто", ``, "", false},
		{"обрыв", `{"client":"c-1"`, "", false},
		{"обрыв после запятой", `{"client":"c-1",`, "", false},
		{"мусор внутри", `{"client":"c-1",,}`, "", false},
		{"мусор в чужом значении", `{"client":"c-1","text":tru}`, "", false},
		{"хвост после объекта", `{"client":"c-1"} {"client":"c-2"}`, "", false},
		{"хвост мусором", `{"client":"c-1"}x`, "", false},
	} {
		got, ok := SubjectOf([]byte(tc.body), "client")
		if got != tc.want || ok != tc.ok {
			t.Errorf("%s: %q %v, ждали %q %v", tc.name, got, ok, tc.want, tc.ok)
		}
	}
}

func TestNewSubjectTag(t *testing.T) {
	key := bytes.Repeat([]byte{7}, 32)
	a := NewSubjectTag(key, "agent", "client", "c-1")
	if a.IsZero() {
		t.Fatal("нулевая метка")
	}
	if a != NewSubjectTag(key, "agent", "client", "c-1") {
		t.Fatal("метка не детерминирована")
	}
	for name, other := range map[string]SubjectTag{
		"другой субъект":  NewSubjectTag(key, "agent", "client", "c-2"),
		"другой источник": NewSubjectTag(key, "agent2", "client", "c-1"),
		"другое поле":     NewSubjectTag(key, "agent", "to_client", "c-1"),
		"другой ключ":     NewSubjectTag(bytes.Repeat([]byte{8}, 32), "agent", "client", "c-1"),
		// Границы полей: длины входят в метку, «ab|c» — не «a|bc».
		"сдвиг границы": NewSubjectTag(key, "agent", "clientc", "-1"),
	} {
		if a == other {
			t.Fatalf("%s: та же метка", name)
		}
	}
}

func subjectSealed() Sealed {
	return Sealed{
		Header: Header{Source: "agent", Seq: 7, ReceivedAt: 1_700_000_000_000_000_000, ContentType: "application/json",
			Subject: SubjectTag{1, 2, 3}, SubjectField: "client"},
		Envelope: []byte("sealed body"),
	}
}

func TestSubjectRoundTrip(t *testing.T) {
	s := subjectSealed()
	data, err := s.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	if data[0] != VersionSubject {
		t.Fatalf("версия %d", data[0])
	}
	got, err := Unmarshal(data)
	if err != nil {
		t.Fatal(err)
	}
	if got.Header != s.Header || !bytes.Equal(got.Envelope, s.Envelope) {
		t.Fatalf("разобрано %+v", got)
	}
}

// Запись без метки — байт в байт версия 1: журналы прежних выпусков читаются,
// а отпечатки в их цепях сходятся.
func TestNoSubjectKeepsVersionOne(t *testing.T) {
	s := subjectSealed()
	with, err := s.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	s.Subject, s.SubjectField = SubjectTag{}, ""
	without, err := s.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	if without[0] != Version || len(with) != len(without)+4+len("client")+SubjectTagLen {
		t.Fatalf("версия %d, длины %d и %d", without[0], len(with), len(without))
	}
	if Digest(with) == Digest(without) {
		t.Fatal("отпечаток не покрывает метку")
	}
}

// Метка и поле ходят парой: Marshal не пишет одно без другого.
func TestSubjectGoesWithItsField(t *testing.T) {
	s := subjectSealed()
	s.SubjectField = ""
	if _, err := s.Marshal(); err == nil {
		t.Fatal("метка без поля записана")
	}
	s = subjectSealed()
	s.Subject = SubjectTag{}
	if _, err := s.Marshal(); err == nil {
		t.Fatal("поле без метки записано")
	}
	s = subjectSealed()
	s.SubjectField = strings.Repeat("x", MaxSubjectField+1)
	if _, err := s.Marshal(); err == nil {
		t.Fatal("длинное поле записано")
	}
}

// versionTwo — запись версии 2 с пустым именем поля и этой меткой: Marshal такую
// не напишет, она из чужого файла.
func versionTwo(tag SubjectTag) []byte {
	s := subjectSealed()
	b, _ := Sealed{Header: Header{Source: s.Source, Seq: s.Seq, ReceivedAt: s.ReceivedAt, ContentType: s.ContentType}, Envelope: s.Envelope}.Marshal()
	cut := 1 + 8 + 8 + 4 + len(s.Source) + 4 + len(s.ContentType)
	out := append([]byte{VersionSubject}, b[1:cut]...)
	out = append(out, 0, 0, 0, 0)
	out = append(out, tag[:]...)
	return append(out, b[cut:]...)
}

func TestSubjectMalformed(t *testing.T) {
	good, err := subjectSealed().Marshal()
	if err != nil {
		t.Fatal(err)
	}
	off := 1 + 8 + 8 + 4 + len("agent") + 4 + len("application/json") + 4 + len("client")
	for name, data := range map[string][]byte{
		// Нулевая метка — запись версии 1: второго представления быть не должно.
		"нулевая метка": func() []byte {
			b := bytes.Clone(good)
			clear(b[off : off+SubjectTagLen])
			return b
		}(),
		"обрыв посреди метки": good[:off+SubjectTagLen-1],
		"поле без метки": func() []byte {
			s := subjectSealed()
			s.Subject = SubjectTag{}
			b := bytes.Clone(good)
			clear(b[off : off+SubjectTagLen])
			_ = s
			return b
		}(),
		"метка без поля": versionTwo(subjectSealed().Subject),
		// Запись без метки — всегда версия 1: у неё одно представление.
		"версия 2 без метки и поля": versionTwo(SubjectTag{}),
		"версия 1 с меткой": func() []byte {
			b := bytes.Clone(good)
			b[0] = Version
			return b
		}(),
		"неизвестная версия": func() []byte {
			b := bytes.Clone(good)
			b[0] = VersionSubject + 1
			return b
		}(),
	} {
		if _, err := Unmarshal(data); !errors.Is(err, ErrMalformed) {
			t.Fatalf("%s: %v", name, err)
		}
	}
}
