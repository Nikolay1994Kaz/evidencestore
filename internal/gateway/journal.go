package gateway

// Файл квитанций шлюза. Пишут его шлюзы (esmcp, esundo, esreceipt sign),
// иногда несколько процессов и несколько шлюзов сразу: каждая квитанция
// дописывается под flock, цепочка шлюза идёт от его последней квитанции в
// файле, подписанной его ключом, мимо чужих строк, и квитанция ложится на
// диск (fsync) до того, как Append вернётся.

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"os"

	"golang.org/x/sys/unix"
)

// Appended — что сделал Append: строка квитанции, сколько чужих строк в
// конце файла цепочка обошла (Skipped) и была ли последняя строка порвана
// (Torn).
type Appended struct {
	Line    []byte
	Receipt Receipt
	Skipped int
	Torn    bool
}

// Append подписывает шаг d квитанцией шлюза name и дописывает её в файл path.
// Строки от имени шлюза, ни одна из которых не подписана этим ключом, —
// отказ: ключ, скорее всего, не тот, и вторая цепочка рядом с первой хуже
// отказа. Порванная последняя строка (файл кончается не переводом строки:
// писавший умер посреди строки — все пишут под flock) закрывается переводом
// строки и остаётся в файле поломанной строкой, а цепочка идёт от последней
// квитанции до неё: шлюз после падения не встаёт, хранилище называет обрывок,
// и чинить файл улик руками не нужно.
func Append(path string, key ed25519.PrivateKey, name string, d Draft) (Appended, error) {
	f, err := os.OpenFile(path, os.O_RDWR|os.O_CREATE|os.O_APPEND, 0o640)
	if err != nil {
		return Appended{}, err
	}
	defer f.Close()
	if err := unix.Flock(int(f.Fd()), unix.LOCK_EX); err != nil {
		return Appended{}, fmt.Errorf("gateway: lock %s: %w", path, err)
	}
	torn, err := tornTail(f)
	if err != nil {
		return Appended{}, err
	}
	last, skipped, claimed, err := LastOwn(f, key.Public().(ed25519.PublicKey), name)
	if err != nil {
		return Appended{}, err
	}
	if last == nil && claimed > 0 {
		return Appended{}, fmt.Errorf("gateway: %d lines of %s claim gateway %q, and none is signed with this key: is it the gateway's key? A second chain is not started next to them", claimed, path, name)
	}
	s, err := NewSigner(key, name, last)
	if err != nil {
		return Appended{}, err
	}
	line, err := s.Sign(d)
	if err != nil {
		return Appended{}, err
	}
	out := append(bytes.Clone(line), '\n')
	if torn {
		out = append([]byte{'\n'}, out...)
	}
	if _, err := f.Write(out); err != nil {
		return Appended{}, err
	}
	if err := f.Sync(); err != nil {
		return Appended{}, err
	}
	r, _ := ParseReceipt(line)
	return Appended{Line: line, Receipt: r, Skipped: skipped, Torn: torn}, nil
}

// tornTail — файл не пуст и кончается не переводом строки.
func tornTail(f *os.File) (bool, error) {
	st, err := f.Stat()
	if err != nil || st.Size() == 0 {
		return false, err
	}
	one := make([]byte, 1)
	if _, err := f.ReadAt(one, st.Size()-1); err != nil {
		return false, err
	}
	return one[0] != '\n', nil
}

// LastOwn — последняя квитанция шлюза name с подписью ключа pub; nil — таких
// в файле нет. skipped — строк после неё (чужие, подделанные, другого
// шлюза, порванная последняя), claimed — из них от имени шлюза name.
func LastOwn(f *os.File, pub ed25519.PublicKey, name string) (last []byte, skipped, claimed int, err error) {
	st, err := f.Stat()
	if err != nil {
		return nil, 0, 0, err
	}
	size := st.Size()
	if size == 0 {
		return nil, 0, 0, nil
	}
	torn, err := tornTail(f)
	if err != nil {
		return nil, 0, 0, err
	}
	lines := backLines{f: f, pos: size - 1}
	if torn {
		lines.pos = size // обрывок — первая строка с конца
	}
	for {
		line, ok, err := lines.next()
		if err != nil || !ok {
			return nil, skipped, claimed, err
		}
		r, _ := ParseReceipt(line)
		if r.Gateway == name && r.Seq > 0 && r.Prev != "" && r.Verify(pub) == nil {
			return line, skipped, claimed, nil
		}
		skipped++
		if r.Gateway == name {
			claimed++
		}
	}
}

// backLines читает строки файла с конца. pos — где кончаются ещё не
// прочитанные байты; buf — прочитанные, но не отданные.
type backLines struct {
	f    *os.File
	pos  int64
	buf  []byte
	done bool
}

func (b *backLines) next() ([]byte, bool, error) {
	for {
		if i := bytes.LastIndexByte(b.buf, '\n'); i >= 0 {
			line := b.buf[i+1:]
			b.buf = b.buf[:i]
			return line, true, nil
		}
		if b.pos == 0 {
			if b.done {
				return nil, false, nil
			}
			b.done = true
			return b.buf, true, nil
		}
		n := min(int64(64<<10), b.pos)
		chunk := make([]byte, n, int(n)+len(b.buf))
		if _, err := b.f.ReadAt(chunk, b.pos-n); err != nil {
			return nil, false, err
		}
		b.pos -= n
		b.buf = append(chunk, b.buf...)
		if len(b.buf) > 2*MaxReceiptLen {
			return nil, false, fmt.Errorf("gateway: %s: a line is longer than a receipt can be", b.f.Name())
		}
	}
}

// GenerateKey пишет новый ключ шлюза в path (PKCS#8 PEM, права 0600) и
// отдаёт открытый. Файл, который уже есть, не трогается: чужой ключ,
// перезаписанный по ошибке, — потерянная цепочка.
func GenerateKey(path string) (ed25519.PublicKey, error) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	der, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		return nil, err
	}
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return nil, err
	}
	if err := pem.Encode(f, &pem.Block{Type: "PRIVATE KEY", Bytes: der}); err != nil {
		f.Close()
		return nil, err
	}
	if err := f.Sync(); err != nil {
		f.Close()
		return nil, err
	}
	return pub, f.Close()
}

// LoadKey читает ключ шлюза (PKCS#8 PEM, Ed25519).
func LoadKey(path string) (ed25519.PrivateKey, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	block, _ := pem.Decode(data)
	if block == nil || block.Type != "PRIVATE KEY" {
		return nil, fmt.Errorf("%s: not a PKCS#8 PEM private key (esreceipt keygen writes one)", path)
	}
	k, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	key, ok := k.(ed25519.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("%s: not an Ed25519 key", path)
	}
	return key, nil
}

// ValidName — годится ли s в имя шлюза (поле gateway квитанции).
func ValidName(s string) bool { return validName(s, MaxGatewayName) }
