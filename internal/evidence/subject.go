package evidence

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/json"
	"io"
	"strconv"
	"unicode/utf16"
	"unicode/utf8"
)

// Метка субъекта (DECISIONS, п. 32). Один источник — один агент, а записи в нём
// разных клиентов. Цепочка источника доказывает полноту по источнику; чтобы
// показать записи одного клиента и не открыть остальных, каждой записи при
// приёме ставится метка клиента, и пакет выдаёт ключи только записям с нужной
// меткой. Цепочка остаётся одна: метка — фильтр поверх неё, а не новый источник.
//
// Метка и имя поля лежат в открытом заголовке, их покрывает отпечаток в цепи:
// после приёма их не поменять. Это HMAC, а не хэш: номер клиента перебирается,
// и по хэшу проверяющий узнал бы, чьи записи рядом закрыты.

// SubjectTagLen — длина метки субъекта.
const SubjectTagLen = 16

// SubjectTag — обезличенная метка субъекта записи. Нулевая — метки нет.
type SubjectTag [SubjectTagLen]byte

// IsZero — метки нет.
func (t SubjectTag) IsZero() bool { return t == SubjectTag{} }

// MaxSubjectLen — предел значения субъекта: длиннее — это не номер клиента, и
// запись остаётся без метки.
const MaxSubjectLen = 256

// domainSubject отделяет метку субъекта от других HMAC проекта.
const domainSubject = "evidencestore/subject/v1"

// NewSubjectTag — метка субъекта: значение value поля field в источнике source.
// Источник входит в метку: один клиент в двух источниках — разные метки, и
// пакеты разных источников его не свяжут. Поле входит тоже: одно значение в
// разных полях — разные субъекты.
func NewSubjectTag(key []byte, source, field, value string) SubjectTag {
	m := hmac.New(sha256.New, key)
	m.Write(appendField(nil, []byte(domainSubject)))
	m.Write(appendField(nil, []byte(source)))
	m.Write(appendField(nil, []byte(field)))
	m.Write(appendField(nil, []byte(value)))
	var t SubjectTag
	copy(t[:], m.Sum(nil))
	return t
}

// SubjectOf достаёт субъекта из тела записи: значение поля field верхнего
// уровня JSON-объекта, строка или число. Им же esverify сверяет открытые тела
// с тем, о ком пакет: разбор один на приём и проверку, иначе метка и проверка
// разошлись бы на краях.
//
// ok = false — субъекта назвать нельзя: тело не целый JSON-объект, поля нет или
// оно другого типа, значение пустое или длиннее MaxSubjectLen, поле названо
// дважды (чья это запись — неясно), строка не в UTF-8 или с одиночным
// суррогатом (разбор подменил бы их на U+FFFD, и разные значения стали бы одним
// субъектом, T-01). Такая запись остаётся без метки.
func SubjectOf(body []byte, field string) (string, bool) {
	dec := json.NewDecoder(bytes.NewReader(body))
	dec.UseNumber()
	if tok, err := dec.Token(); err != nil || tok != json.Delim('{') {
		return "", false
	}
	var value string
	found := false
	for dec.More() {
		key, err := dec.Token()
		if err != nil {
			return "", false
		}
		if name, _ := key.(string); name != field {
			var skip json.RawMessage
			if err := dec.Decode(&skip); err != nil {
				return "", false
			}
			continue
		}
		if found {
			return "", false
		}
		found = true
		// Значение — как записано: строку разбор отдал бы уже с U+FFFD вместо
		// чужих байтов, и сверить её с телом «как записано» было бы нечем.
		var raw json.RawMessage
		if err := dec.Decode(&raw); err != nil {
			return "", false
		}
		switch {
		case raw[0] == '"':
			if !validRawString(raw) || json.Unmarshal(raw, &value) != nil {
				return "", false
			}
		case raw[0] == '-' || raw[0] >= '0' && raw[0] <= '9':
			// Число — его запись, как её отдал бы json.Number.
			value = string(raw)
		default:
			// null, true, false, объект, массив.
			return "", false
		}
	}
	// Закрывающая скобка, и за ней ничего, кроме пробелов.
	if _, err := dec.Token(); err != nil {
		return "", false
	}
	if _, err := dec.Token(); err != io.EOF {
		return "", false
	}
	if value == "" || len(value) > MaxSubjectLen {
		return "", false
	}
	return value, true
}

// ValidSubject — значение, которое метку получить может: UTF-8. Им хранилище
// проверяет субъекта, о котором просят пакет (T-01).
func ValidSubject(v string) bool { return utf8.ValidString(v) }

// validRawString — строка JSON (с кавычками) в UTF-8, и каждая \u-половина
// суррогата — в паре. Разбор json заменяет и то и другое на U+FFFD.
func validRawString(raw []byte) bool {
	if !utf8.Valid(raw) {
		return false
	}
	for i := 0; i < len(raw); i++ {
		if raw[i] != '\\' {
			continue
		}
		if i+1 < len(raw) && raw[i+1] != 'u' {
			// \n, \", \\ и прочие: байт после них — не начало escape.
			i++
			continue
		}
		hi, ok := escapeAt(raw, i)
		if !ok {
			return false
		}
		i += 5
		if !utf16.IsSurrogate(rune(hi)) {
			continue
		}
		// Старшая половина — только с младшей следом; младшая одна — нет.
		lo, ok := escapeAt(raw, i+1)
		if hi >= 0xDC00 || !ok || lo < 0xDC00 || lo >= 0xE000 {
			return false
		}
		i += 6
	}
	return true
}

// escapeAt — код \uXXXX, который начинается с raw[i].
func escapeAt(raw []byte, i int) (uint16, bool) {
	if i+6 > len(raw) || raw[i] != '\\' || raw[i+1] != 'u' {
		return 0, false
	}
	v, err := strconv.ParseUint(string(raw[i+2:i+6]), 16, 16)
	return uint16(v), err == nil
}
