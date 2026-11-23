// Command esreceipt — квитанции шлюза (content_type "receipt/v1") без своего
// кода подписи: ключ, подпись шагов в файл квитанций, проверка файла.
//
//	esreceipt keygen -key FILE
//	esreceipt pubkey -key FILE
//	esreceipt sign -key FILE -gateway NAME -file RECEIPTS < steps.jsonl
//	esreceipt verify -gateway-key KEY -file RECEIPTS
//
// Шаг на входе sign — объект JSON в строке: "action" и "step" обязательны,
// "time", "refs", "approval", "body" — по желанию. Номер, сцепку и подпись
// ставит esreceipt; цепочка продолжается с последней строки файла, файл под
// замком (flock), каждая квитанция — на диске (fsync) до следующей.
package main

import (
	"bufio"
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"golang.org/x/sys/unix"

	"github.com/Nikolay1994Kaz/evidencestore/internal/gateway"
	"github.com/Nikolay1994Kaz/evidencestore/internal/version"
)

const (
	exitOK      = 0
	exitInvalid = 1 // verify: квитанции не целы
	exitUsage   = 2
)

func main() { os.Exit(run(os.Args[1:], os.Stdin, os.Stdout, os.Stderr)) }

const usage = `usage:
  esreceipt keygen -key FILE                              new gateway key (PKCS#8 PEM, mode 0600); prints its public key for gateway_key
  esreceipt pubkey -key FILE                              prints the public key (64 hex)
  esreceipt sign -key FILE -gateway NAME -file RECEIPTS   signs the steps on stdin and appends them to RECEIPTS
  esreceipt verify -gateway-key KEY -file RECEIPTS        checks every receipt in RECEIPTS: format, signature, chain
  esreceipt version`

func run(args []string, stdin io.Reader, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		fmt.Fprintln(stderr, usage)
		return exitUsage
	}
	cmd, rest := args[0], args[1:]
	fs := flag.NewFlagSet("esreceipt "+cmd, flag.ContinueOnError)
	fs.SetOutput(stderr)
	keyPath := fs.String("key", "", "gateway private key (PKCS#8 PEM)")
	name := fs.String("gateway", "", "gateway name: 1 to 128 letters, digits and . _ : - (it stays readable in the store's verdicts)")
	file := fs.String("file", "", "receipts file (JSONL)")
	pubKey := fs.String("gateway-key", "", "gateway public key (64 hex) or file containing it")
	usageErr := func(err error) int {
		fmt.Fprintln(stderr, "error:", err)
		return exitUsage
	}
	switch cmd {
	case "version", "-version", "--version":
		fmt.Fprintln(stdout, version.String("esreceipt"))
		return exitOK
	case "keygen", "pubkey", "sign", "verify":
	default:
		fmt.Fprintln(stderr, usage)
		return exitUsage
	}
	if err := fs.Parse(rest); err != nil {
		return exitUsage
	}
	if fs.NArg() > 0 {
		return usageErr(fmt.Errorf("unexpected arguments: %s", strings.Join(fs.Args(), " ")))
	}
	switch cmd {
	case "keygen":
		if *keyPath == "" {
			return usageErr(errors.New("-key is required"))
		}
		pub, err := keygen(*keyPath)
		if err != nil {
			return usageErr(err)
		}
		fmt.Fprintln(stdout, hex.EncodeToString(pub))
	case "pubkey":
		key, err := loadKey(*keyPath)
		if err != nil {
			return usageErr(err)
		}
		fmt.Fprintln(stdout, hex.EncodeToString(key.Public().(ed25519.PublicKey)))
	case "sign":
		if *file == "" || *name == "" {
			return usageErr(errors.New("-key, -gateway and -file are required"))
		}
		key, err := loadKey(*keyPath)
		if err != nil {
			return usageErr(err)
		}
		n, err := sign(key, *name, *file, stdin, stderr)
		if err != nil {
			fmt.Fprintf(stderr, "error: %v (%d receipts written before it)\n", err, n)
			return exitInvalid
		}
	case "verify":
		if *file == "" || *pubKey == "" {
			return usageErr(errors.New("-gateway-key and -file are required"))
		}
		key, err := parsePub(*pubKey)
		if err != nil {
			return usageErr(err)
		}
		f, err := os.Open(*file)
		if err != nil {
			return usageErr(err)
		}
		defer f.Close()
		ok, err := verify(key, f, stdout)
		if err != nil {
			return usageErr(err)
		}
		if !ok {
			return exitInvalid
		}
	}
	return exitOK
}

// keygen пишет новый ключ шлюза. Файл, который уже есть, не трогается: чужой
// ключ, перезаписанный по ошибке, — потерянная цепочка.
func keygen(path string) (ed25519.PublicKey, error) {
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

func loadKey(path string) (ed25519.PrivateKey, error) {
	if path == "" {
		return nil, errors.New("-key is required")
	}
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

func parsePub(v string) (ed25519.PublicKey, error) {
	if k, err := gateway.ParseKey(v); err == nil {
		return k, nil
	}
	data, err := os.ReadFile(v)
	if err != nil {
		return nil, errors.New("-gateway-key: neither 64 hex characters nor a readable file")
	}
	return gateway.ParseKey(string(data))
}

// step — шаг на входе sign.
type step struct {
	Time     string            `json:"time"`
	Action   string            `json:"action"`
	Step     string            `json:"step"`
	Refs     []gateway.Ref     `json:"refs"`
	Approval *gateway.Approval `json:"approval"`
	Body     json.RawMessage   `json:"body"`
}

func parseStep(line []byte) (gateway.Draft, error) {
	dec := json.NewDecoder(bytes.NewReader(line))
	dec.DisallowUnknownFields()
	var s step
	if err := dec.Decode(&s); err != nil {
		return gateway.Draft{}, fmt.Errorf("step: %w (fields: action, step, time, refs, approval, body)", err)
	}
	if dec.More() {
		return gateway.Draft{}, errors.New("step: one JSON object per line")
	}
	d := gateway.Draft{Action: s.Action, Step: s.Step, Refs: s.Refs, Approval: s.Approval, Body: s.Body}
	if s.Time != "" {
		t, err := time.Parse(time.RFC3339Nano, s.Time)
		if err != nil {
			return gateway.Draft{}, fmt.Errorf("step: time: %w", err)
		}
		d.Time = t
	}
	return d, nil
}

// sign дописывает квитанции шагов в файл. Сколько записано — даже при ошибке:
// записанное уже подписано и сцеплено, повторять его нельзя.
func sign(key ed25519.PrivateKey, name, path string, in io.Reader, warn io.Writer) (int, error) {
	f, err := os.OpenFile(path, os.O_RDWR|os.O_CREATE|os.O_APPEND, 0o640)
	if err != nil {
		return 0, err
	}
	defer f.Close()
	// Два подписывающих над одним файлом развели бы цепочку надвое.
	if err := unix.Flock(int(f.Fd()), unix.LOCK_EX); err != nil {
		return 0, fmt.Errorf("lock %s: %w", path, err)
	}
	last, skipped, claimed, err := lastOwn(f, key.Public().(ed25519.PublicKey), name)
	if err != nil {
		return 0, err
	}
	if last == nil && claimed > 0 {
		// Ни одной своей квитанции, а строки от имени этого шлюза есть: ключ,
		// скорее всего, не тот. Вторая цепочка рядом с первой — хуже отказа.
		return 0, fmt.Errorf("%d lines of %s claim gateway %q, and none is signed with this key: is it the gateway's key? A second chain is not started next to them", claimed, path, name)
	}
	if skipped > 0 {
		// Чужая строка в файле шлюза — не повод останавливать шлюз: хранилище
		// назовёт её поломанной, а цепочка шлюза идёт мимо неё.
		fmt.Fprintf(warn, "warning: the last %d lines of %s are not receipts of gateway %q signed with this key; the chain goes on from its last receipt before them\n", skipped, path, name)
	}
	signer, err := gateway.NewSigner(key, name, last)
	if err != nil {
		return 0, err
	}
	sc := bufio.NewScanner(in)
	sc.Buffer(make([]byte, 64<<10), gateway.MaxReceiptLen)
	n := 0
	for sc.Scan() {
		if len(bytes.TrimSpace(sc.Bytes())) == 0 {
			continue
		}
		d, err := parseStep(sc.Bytes())
		if err != nil {
			return n, fmt.Errorf("input line %d: %w", n+1, err)
		}
		line, err := signer.Sign(d)
		if err != nil {
			return n, fmt.Errorf("input line %d: %w", n+1, err)
		}
		if _, err := f.Write(append(line, '\n')); err != nil {
			return n, err
		}
		if err := f.Sync(); err != nil {
			return n, err
		}
		n++
	}
	return n, sc.Err()
}

// lastOwn — последняя квитанция шлюза name с подписью этого ключа; nil —
// таких в файле нет. skipped — строк после неё: чужие, подделанные, другого
// шлюза; claimed — из них от имени шлюза name. Файл обязан кончаться
// переводом строки: иначе последняя строка порвана (шлюз упал посреди
// записи), и дописывать после неё нельзя.
func lastOwn(f *os.File, pub ed25519.PublicKey, name string) (last []byte, skipped, claimed int, err error) {
	st, err := f.Stat()
	if err != nil {
		return nil, 0, 0, err
	}
	size := st.Size()
	if size == 0 {
		return nil, 0, 0, nil
	}
	one := make([]byte, 1)
	if _, err := f.ReadAt(one, size-1); err != nil {
		return nil, 0, 0, err
	}
	if one[0] != '\n' {
		return nil, 0, 0, fmt.Errorf("%s does not end with a newline: its last line is torn; remove that partial line before signing more", f.Name())
	}
	lines := backLines{f: f, pos: size - 1}
	for {
		line, ok, err := lines.next()
		if err != nil || !ok {
			return nil, skipped, claimed, err
		}
		r, _ := gateway.ParseReceipt(line)
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
		if len(b.buf) > 2*gateway.MaxReceiptLen {
			return nil, false, fmt.Errorf("%s: a line is longer than a receipt can be", b.f.Name())
		}
	}
}

// verify проверяет все квитанции файла тем же разбором, что и хранилище, и
// печатает каждую поломку и итог.
func verify(key ed25519.PublicKey, in io.Reader, out io.Writer) (bool, error) {
	tr := gateway.NewReceiptTracker(key)
	sc := bufio.NewScanner(in)
	sc.Buffer(make([]byte, 64<<10), gateway.MaxReceiptLen+2)
	total, bad := 0, 0
	gateways := map[string]bool{}
	for sc.Scan() {
		total++
		v := tr.Check(sc.Bytes())
		if v.Writer != "" {
			gateways[v.Writer] = true
		}
		if !v.Clean() {
			bad++
			fmt.Fprintf(out, "line %d: gateway %q, seq %d, link %s, signature %s: %s\n", total, v.Writer, v.Seq, dash(v.Link), dash(v.Signature), v.Problem)
		}
	}
	if err := sc.Err(); err != nil {
		return false, err
	}
	fmt.Fprintf(out, "%d receipts of %d gateways, %d not intact\n", total, len(gateways), bad)
	return bad == 0, nil
}

func dash(s string) string {
	if s == "" {
		return "—"
	}
	return s
}
