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
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

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
	head := fs.String("head", "", "where sign keeps the head of the gateway's chain (default: next to -key); only the gateway may write there")
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
		h := *head
		if h == "" {
			h = gateway.DefaultHead(*keyPath, *file, *name)
		}
		n, err := sign(key, *name, *file, h, stdin, stderr)
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

func keygen(path string) (ed25519.PublicKey, error) { return gateway.GenerateKey(path) }

func loadKey(path string) (ed25519.PrivateKey, error) {
	if path == "" {
		return nil, errors.New("-key is required")
	}
	return gateway.LoadKey(path)
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

// sign дописывает квитанции шагов в файл (gateway.Append: flock, цепочка от
// последней своей квитанции мимо чужих строк, fsync каждой). Сколько
// записано — даже при ошибке: записанное уже подписано и сцеплено,
// повторять его нельзя.
func sign(key ed25519.PrivateKey, name, path, head string, in io.Reader, warn io.Writer) (int, error) {
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
		a, err := gateway.AppendHead(path, head, key, name, d)
		if err != nil {
			return n, fmt.Errorf("input line %d: %w", n+1, err)
		}
		if a.Torn {
			fmt.Fprintf(warn, "warning: the last line of %s was torn (its writer died in the middle of it): it is closed with a newline and stays there as a broken line, which the store names\n", path)
		}
		switch {
		case a.Claimed > 0 && a.Receipt.Seq == 1:
			// Ни одной своей квитанции, а строки от его имени есть: не тот
			// ключ или строки, дописанные без ключа. Отказ здесь превращал бы
			// одну подложенную строку в остановку шлюза (R1-3).
			fmt.Fprintf(warn, "warning: %d lines of %s claim gateway %q, and none is signed with this key: is it the gateway's key? A new chain is started; if the key is wrong, the store names every receipt it signs\n", a.Claimed, path, name)
		case a.Skipped > 0:
			// Чужая строка в файле шлюза — не повод его останавливать:
			// хранилище назовёт её поломанной, а цепочка идёт мимо неё.
			fmt.Fprintf(warn, "warning: the last %d lines of %s are not receipts of gateway %q signed with this key; the chain goes on from its last receipt before them\n", a.Skipped, path, name)
		}
		if a.Glued {
			fmt.Fprintf(warn, "warning: the receipt was glued to bytes that someone wrote into %s without its lock: it is written once more on a line of its own\n", path)
		}
		if a.Stale > 0 {
			fmt.Fprintf(warn, "warning: %d lines of %s are copies of earlier receipts of gateway %q or a second branch of its chain: someone who can write the file wrote them, and the chain does not go on from them\n", a.Stale, path, name)
		}
		n++
	}
	return n, sc.Err()
}

// verify проверяет все квитанции файла тем же разбором, что и хранилище, и
// печатает каждую поломку и итог.
func verify(key ed25519.PublicKey, in io.Reader, out io.Writer) (bool, error) {
	tr := gateway.NewReceiptTracker(key)
	br := bufio.NewReaderSize(in, 64<<10)
	total, bad := 0, 0
	gateways := map[string]bool{}
	for {
		line, long, err := readLine(br, gateway.MaxReceiptLen+2)
		if err == io.EOF {
			break
		}
		if err != nil {
			return false, err
		}
		total++
		if long {
			// Строка длиннее любой квитанции — поломка, а не конец проверки
			// (R1-3): её дописал не шлюз.
			bad++
			fmt.Fprintf(out, "line %d: longer than a receipt can be (%d bytes): not a receipt\n", total, gateway.MaxReceiptLen)
			continue
		}
		v := tr.Check(line)
		if v.Writer != "" {
			gateways[v.Writer] = true
		}
		if !v.Clean() {
			bad++
			fmt.Fprintf(out, "line %d: gateway %q, seq %d, link %s, signature %s: %s\n", total, v.Writer, v.Seq, dash(v.Link), dash(v.Signature), v.Problem)
		}
	}
	fmt.Fprintf(out, "%d receipts of %d gateways, %d not intact\n", total, len(gateways), bad)
	return bad == 0, nil
}

// readLine — следующая строка без перевода строки; long — строка длиннее
// max, её байты пропущены и не копятся. io.EOF — строк больше нет; обрывок
// в конце без перевода строки — тоже строка.
func readLine(br *bufio.Reader, max int) (line []byte, long bool, err error) {
	var buf []byte
	for {
		chunk, err := br.ReadSlice('\n')
		if !long {
			buf = append(buf, chunk...)
			if len(buf) > max {
				buf, long = nil, true
			}
		}
		switch {
		case err == bufio.ErrBufferFull:
			continue
		case err == io.EOF && len(buf) == 0 && !long:
			return nil, false, io.EOF
		case err != nil && err != io.EOF:
			return nil, false, err
		}
		return bytes.TrimSuffix(buf, []byte("\n")), long, nil
	}
}

func dash(s string) string {
	if s == "" {
		return "—"
	}
	return s
}
