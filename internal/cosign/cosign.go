// Package cosign — подпись свидетеля по C2SP: заметка (signed-note),
// контрольная точка (tlog-checkpoint), подпись свидетеля cosignature/v1
// (tlog-cosignature) и тело запроса add-checkpoint (tlog-witness).
//
// ЗАЧЕМ. Свидетель S3 (witness.url) — пассивное хранилище: принимает любую
// голову, которую положит тот, у кого ключи записи, а это администратор
// хранилища. Поэтому esverify разбирается задним числом, что лежит в бакете и
// когда пришло (P-21, P-92…P-107). Свидетель C2SP сам сверяет, что новая
// голова продолжает последнюю, которую он подписал, и только тогда
// подписывает её своим ключом вместе со временем. Развилка подписи не
// получает, а подпись едет в пакете: аудитор проверяет её офлайн открытым
// ключом свидетеля, без доступа к его хранилищу.
//
// Пакет — только форматы, без сети и состояния: его зовут хранилище
// (internal/store), свидетель (internal/witness) и проверка (internal/proof).
// Подписи — только Ed25519: тип 0x01 у хранилища (подпись заметки) и 0x04 у
// свидетеля (cosignature/v1). ML-DSA-44 (тип 0x06), который C2SP советует для
// новых установок, требует crypto/mldsa из Go 1.27 и появится вторым ключом
// свидетеля позже.
package cosign

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"unicode"
	"unicode/utf8"
)

// Типы подписей signed-note.
const (
	TypeEd25519        byte = 0x01 // подпись заметки ключом журнала (хранилища)
	TypeCosignatureV1  byte = 0x04 // подпись свидетеля с временем, Ed25519
	cosignatureV1Label      = "cosignature/v1\n"
)

// BlobSize — подпись свидетеля в строке подписи: номер ключа (4), время (8),
// подпись Ed25519 (64).
const BlobSize = 4 + 8 + ed25519.SignatureSize

// MaxProofLines — предел строк доказательства в add-checkpoint (tlog-witness).
const MaxProofLines = 63

// MaxNameLen — предел имени ключа (tlog-cosignature).
const MaxNameLen = 255

var b64 = base64.StdEncoding.Strict()

// decode64 — base64 только в каноническом виде: C2SP требует отвергать
// неканонические записи, иначе у одной подписи было бы много написаний.
func decode64(s string) ([]byte, error) {
	b, err := b64.DecodeString(s)
	if err != nil || b64.EncodeToString(b) != s {
		return nil, errors.New("not canonical base64")
	}
	return b, nil
}

// ValidName — имя ключа или происхождения: непустое, не длиннее 255 байт, в
// UTF-8, без пробелов Unicode, плюса и управляющих символов.
func ValidName(name string) bool {
	if name == "" || len(name) > MaxNameLen || !utf8.ValidString(name) {
		return false
	}
	for _, r := range name {
		if unicode.IsSpace(r) || r == '+' || r < 0x20 {
			return false
		}
	}
	return true
}

// KeyID — номер ключа: первые 4 байта SHA-256(имя ‖ "\n" ‖ тип ‖ ключ),
// big-endian (signed-note).
func KeyID(name string, typ byte, pub []byte) uint32 {
	h := sha256.New()
	h.Write([]byte(name))
	h.Write([]byte{'\n', typ})
	h.Write(pub)
	return binary.BigEndian.Uint32(h.Sum(nil))
}

// CheckpointText — текст контрольной точки: происхождение, размер, корень
// base64, каждая строка с переводом строки. Без строк расширений: хранилище
// их не пишет, а свидетель такие точки не берёт.
func CheckpointText(origin string, size uint64, root [32]byte) []byte {
	return fmt.Appendf(nil, "%s\n%d\n%s\n", origin, size, b64.EncodeToString(root[:]))
}

// ParseCheckpointText разбирает текст точки строго: ровно три строки,
// размер — десятичный без ведущих нулей, корень — 32 байта в каноническом
// base64.
func ParseCheckpointText(text []byte) (origin string, size uint64, root [32]byte, err error) {
	if !bytes.HasSuffix(text, []byte("\n")) {
		return "", 0, root, errors.New("checkpoint text does not end with a newline")
	}
	lines := strings.Split(string(text[:len(text)-1]), "\n")
	if len(lines) != 3 {
		return "", 0, root, fmt.Errorf("checkpoint text has %d lines, want 3 (extension lines are not accepted)", len(lines))
	}
	if !ValidName(lines[0]) {
		return "", 0, root, errors.New("checkpoint origin is not a valid name")
	}
	if size, err = ParseDecimal(lines[1]); err != nil {
		return "", 0, root, fmt.Errorf("checkpoint size: %w", err)
	}
	r, err := decode64(lines[2])
	if err != nil || len(r) != 32 {
		return "", 0, root, errors.New("checkpoint root is not 32 bytes of canonical base64")
	}
	copy(root[:], r)
	return lines[0], size, root, nil
}

// ParseDecimal — неотрицательное целое без ведущих нулей, не больше 2⁶³−1
// (tlog считает размеры в int64).
func ParseDecimal(s string) (uint64, error) {
	if s == "" || len(s) > 1 && s[0] == '0' || strings.Trim(s, "0123456789") != "" {
		return 0, fmt.Errorf("%q is not a decimal without leading zeros", s)
	}
	n, err := strconv.ParseUint(s, 10, 63)
	if err != nil {
		return 0, fmt.Errorf("%q is out of range", s)
	}
	return n, nil
}

// Message — что подписывает свидетель (cosignature/v1): строка
// «cosignature/v1», строка «time <время>» и текст точки.
func Message(timestamp uint64, text []byte) []byte {
	m := make([]byte, 0, len(cosignatureV1Label)+32+len(text))
	m = append(m, cosignatureV1Label...)
	m = fmt.Appendf(m, "time %d\n", timestamp)
	return append(m, text...)
}

// Verifier — открытый ключ свидетеля (cosignature/v1): имя, номер ключа,
// ключ Ed25519.
type Verifier struct {
	Name string
	ID   uint32
	Key  ed25519.PublicKey
}

// ParseVerifier разбирает ключ проверки (vkey) свидетеля:
// «<имя>+<номер, 8 hex>+<base64(0x04 ‖ ключ)>». Номер обязан сходиться с
// именем и ключом: опечатка в ключе — ошибка разбора, а не вечный отказ
// подписей.
func ParseVerifier(vkey string) (Verifier, error) {
	// В base64 бывает «+»: делятся только два первых, в имени и номере его нет.
	parts := strings.SplitN(vkey, "+", 3)
	if len(parts) != 3 {
		return Verifier{}, errors.New("witness key must be <name>+<key id>+<base64 key> (a C2SP vkey)")
	}
	name, idHex, keyB64 := parts[0], parts[1], parts[2]
	if !ValidName(name) {
		return Verifier{}, fmt.Errorf("witness key: %q is not a valid name", name)
	}
	idb, err := hex.DecodeString(idHex)
	if err != nil || len(idb) != 4 || hex.EncodeToString(idb) != idHex {
		return Verifier{}, errors.New("witness key: the key id must be 8 lowercase hex digits")
	}
	raw, err := decode64(keyB64)
	if err != nil {
		return Verifier{}, errors.New("witness key: the key is not canonical base64")
	}
	if len(raw) != 1+ed25519.PublicKeySize || raw[0] != TypeCosignatureV1 {
		return Verifier{}, fmt.Errorf("witness key: want an Ed25519 cosignature/v1 key (type 0x%02x, 32 bytes)", TypeCosignatureV1)
	}
	v := Verifier{Name: name, ID: binary.BigEndian.Uint32(idb), Key: ed25519.PublicKey(raw[1:])}
	if KeyID(name, TypeCosignatureV1, v.Key) != v.ID {
		return Verifier{}, errors.New("witness key: the key id does not match the name and the key")
	}
	return v, nil
}

// String — ключ проверки в виде vkey.
func (v Verifier) String() string {
	return fmt.Sprintf("%s+%08x+%s", v.Name, v.ID, b64.EncodeToString(append([]byte{TypeCosignatureV1}, v.Key...)))
}

// ErrOtherKey — подпись не этого ключа: другой номер ключа. По signed-note
// такую подпись не проверяют, а пропускают.
var ErrOtherKey = errors.New("the signature is by another key")

// Verify проверяет подпись свидетеля blob (номер ключа ‖ время ‖ подпись)
// над текстом точки и возвращает время подписи (секунды POSIX). Нулевое
// время — отказ: tlog-witness требует ненулевое.
func (v Verifier) Verify(text, blob []byte) (uint64, error) {
	if len(blob) != BlobSize {
		return 0, fmt.Errorf("the cosignature is %d bytes, want %d", len(blob), BlobSize)
	}
	if binary.BigEndian.Uint32(blob) != v.ID {
		return 0, ErrOtherKey
	}
	ts := binary.BigEndian.Uint64(blob[4:12])
	if ts == 0 {
		return 0, errors.New("the cosignature carries no time")
	}
	if !ed25519.Verify(v.Key, Message(ts, text), blob[12:]) {
		return 0, errors.New("the cosignature does not verify with the witness key")
	}
	return ts, nil
}

// Signer — закрытый ключ свидетеля.
type Signer struct {
	Name string
	ID   uint32
	key  ed25519.PrivateKey
}

// NewSigner — ключ свидетеля с именем name.
func NewSigner(name string, key ed25519.PrivateKey) (Signer, error) {
	if !ValidName(name) {
		return Signer{}, fmt.Errorf("witness name %q: non-empty, at most %d bytes, no spaces, '+' or control characters", name, MaxNameLen)
	}
	if len(key) != ed25519.PrivateKeySize {
		return Signer{}, errors.New("witness key: not an Ed25519 private key")
	}
	pub := key.Public().(ed25519.PublicKey)
	return Signer{Name: name, ID: KeyID(name, TypeCosignatureV1, pub), key: key}, nil
}

// Verifier — ключ проверки этой подписи.
func (s Signer) Verifier() Verifier {
	return Verifier{Name: s.Name, ID: s.ID, Key: s.key.Public().(ed25519.PublicKey)}
}

// Cosign — подпись свидетеля над текстом точки с временем timestamp:
// номер ключа ‖ время ‖ подпись.
func (s Signer) Cosign(text []byte, timestamp uint64) []byte {
	blob := binary.BigEndian.AppendUint32(make([]byte, 0, BlobSize), s.ID)
	blob = binary.BigEndian.AppendUint64(blob, timestamp)
	return append(blob, ed25519.Sign(s.key, Message(timestamp, text))...)
}

// SigLine — строка подписи заметки: «— <имя> <base64>\n».
func SigLine(name string, sig []byte) string {
	return "— " + name + " " + b64.EncodeToString(sig) + "\n"
}

// ParseSigLine разбирает строку подписи без перевода строки.
func ParseSigLine(line string) (name string, sig []byte, err error) {
	rest, ok := strings.CutPrefix(line, "— ")
	if !ok {
		return "", nil, errors.New("a signature line starts with an em dash and a space")
	}
	name, enc, ok := strings.Cut(rest, " ")
	if !ok || !ValidName(name) {
		return "", nil, errors.New("a signature line names no valid key")
	}
	if sig, err = decode64(enc); err != nil || len(sig) < 4 {
		return "", nil, errors.New("a signature line carries no valid signature")
	}
	return name, sig, nil
}

// MaxSigLines — сколько строк подписи разбирается в одной заметке и в одном
// ответе свидетеля (signed-note требует принимать хотя бы 16).
const MaxSigLines = 64

// SplitNote делит заметку на текст и строки подписей. Текст отделён от
// подписей последней пустой строкой; заметка — UTF-8 без управляющих
// символов, кроме перевода строки.
func SplitNote(note []byte) (text []byte, sigs []string, err error) {
	if !utf8.Valid(note) {
		return nil, nil, errors.New("the note is not valid UTF-8")
	}
	for _, c := range note {
		if c < 0x20 && c != '\n' {
			return nil, nil, errors.New("the note contains a control character")
		}
	}
	if !bytes.HasSuffix(note, []byte("\n")) {
		return nil, nil, errors.New("the note does not end with a newline")
	}
	i := bytes.LastIndex(note, []byte("\n\n"))
	if i < 0 || i+2 >= len(note) {
		return nil, nil, errors.New("the note has no signatures")
	}
	text = note[:i+1]
	lines := strings.Split(string(note[i+2:len(note)-1]), "\n")
	if len(lines) > MaxSigLines {
		return nil, nil, fmt.Errorf("the note has more than %d signatures", MaxSigLines)
	}
	for _, l := range lines {
		if l == "" {
			return nil, nil, errors.New("the note has an empty signature line")
		}
	}
	return text, lines, nil
}

// LogSignature — подпись журнала (хранилища) над текстом точки: тип 0x01,
// имя ключа — происхождение.
func LogSignature(origin string, pub ed25519.PublicKey, sig []byte) string {
	id := binary.BigEndian.AppendUint32(nil, KeyID(origin, TypeEd25519, pub))
	return SigLine(origin, append(id, sig...))
}

// VerifyLogSignature — среди строк подписей есть подпись журнала с
// происхождением origin и ключом pub, и она сходится. Строка с тем же именем
// и номером, но неверной подписью — отказ: такая заметка испорчена
// (signed-note). Чужие строки пропускаются.
func VerifyLogSignature(text []byte, sigs []string, origin string, pub ed25519.PublicKey) error {
	id := KeyID(origin, TypeEd25519, pub)
	found := false
	for _, l := range sigs {
		name, sig, err := ParseSigLine(l)
		if err != nil {
			return err
		}
		if name != origin || binary.BigEndian.Uint32(sig) != id {
			continue
		}
		if len(sig) != 4+ed25519.SignatureSize || !ed25519.Verify(pub, text, sig[4:]) {
			return errors.New("the log signature does not verify")
		}
		found = true
	}
	if !found {
		return errors.New("no signature by the log key")
	}
	return nil
}

// AddCheckpoint — тело запроса add-checkpoint: «old <размер>», строки
// доказательства продолжения, пустая строка, заметка точки.
func AddCheckpoint(old uint64, proof [][32]byte, note []byte) []byte {
	b := fmt.Appendf(nil, "old %d\n", old)
	for _, h := range proof {
		b = append(b, b64.EncodeToString(h[:])...)
		b = append(b, '\n')
	}
	b = append(b, '\n')
	return append(b, note...)
}

// ParseAddCheckpoint разбирает тело add-checkpoint строго по tlog-witness.
func ParseAddCheckpoint(body []byte) (old uint64, proof [][32]byte, note []byte, err error) {
	line, rest, ok := bytes.Cut(body, []byte("\n"))
	if !ok {
		return 0, nil, nil, errors.New("no old size line")
	}
	num, ok := strings.CutPrefix(string(line), "old ")
	if !ok {
		return 0, nil, nil, errors.New("the first line must be 'old <size>'")
	}
	if old, err = ParseDecimal(num); err != nil {
		return 0, nil, nil, fmt.Errorf("old size: %w", err)
	}
	for {
		line, rest, ok = bytes.Cut(rest, []byte("\n"))
		if !ok {
			return 0, nil, nil, errors.New("no empty line before the checkpoint")
		}
		if len(line) == 0 {
			break
		}
		if len(proof) == MaxProofLines {
			return 0, nil, nil, fmt.Errorf("more than %d consistency proof lines", MaxProofLines)
		}
		h, err := decode64(string(line))
		if err != nil || len(h) != 32 {
			return 0, nil, nil, errors.New("a consistency proof line is not a 32-byte hash in canonical base64")
		}
		proof = append(proof, [32]byte(h))
	}
	return old, proof, rest, nil
}
