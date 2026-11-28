// Command esreceipt — квитанции шлюза (content_type "receipt/v2") без своего
// кода подписи: ключ, подпись шагов в файл квитанций, проверка файла.
//
//	esreceipt keygen -key FILE
//	esreceipt pubkey -key FILE [-jwk]
//	esreceipt sign -key FILE -gateway NAME -file RECEIPTS < steps.jsonl
//	esreceipt verify -gateway-key KEY [-gateway-key KEY]… -file RECEIPTS
//	esreceipt jws -file RECEIPTS
//
// Подпись квитанции — отсоединённый JWS: jws печатает каждую квитанцию файла
// обычным компактным JWS, а pubkey -jwk — ключ в виде JWK, и проверить их
// можно любой библиотекой JOSE, без этого кода.
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
  esreceipt pubkey -key FILE [-jwk]                       prints the public key (64 hex), or with -jwk as a JSON Web Key with its kid
  esreceipt sign -key FILE -gateway NAME -file RECEIPTS   signs the steps on stdin and appends them to RECEIPTS
  esreceipt verify -gateway-key KEY -file RECEIPTS        checks every receipt in RECEIPTS: format, signature, chain; repeat -gateway-key for more keys
  esreceipt jws -file RECEIPTS                            prints every receipt as a compact JWS, for any JOSE library to verify
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
	var pubKeys []string
	fs.Func("gateway-key", "gateway public key (64 hex) or a file containing it; repeat the flag for more keys. The file may be the gateway_keys array of the store's source", func(v string) error {
		pubKeys = append(pubKeys, v)
		return nil
	})
	asJWK := fs.Bool("jwk", false, "pubkey: print the key as a JSON Web Key (RFC 8037) with its kid")
	head := fs.String("head", "", "where sign keeps the head of the gateway's chain (default: next to -key); only the gateway may write there")
	usageErr := func(err error) int {
		fmt.Fprintln(stderr, "error:", err)
		return exitUsage
	}
	switch cmd {
	case "version", "-version", "--version":
		fmt.Fprintln(stdout, version.String("esreceipt"))
		return exitOK
	case "keygen", "pubkey", "sign", "verify", "jws":
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
		if pub := key.Public().(ed25519.PublicKey); *asJWK {
			fmt.Fprintln(stdout, string(gateway.JWK(pub)))
		} else {
			fmt.Fprintln(stdout, hex.EncodeToString(pub))
		}
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
		if err := gateway.CheckHead(h, *file); err != nil {
			fmt.Fprintf(stderr, "error: %v\n", err)
			return exitInvalid
		}
		n, err := sign(key, *name, *file, h, stdin, stderr)
		if err != nil {
			fmt.Fprintf(stderr, "error: %v (%d receipts written before it)\n", err, n)
			return exitInvalid
		}
	case "verify":
		if *file == "" || len(pubKeys) == 0 {
			return usageErr(errors.New("-gateway-key and -file are required"))
		}
		keys, err := parsePubs(pubKeys)
		if err != nil {
			return usageErr(err)
		}
		f, err := os.Open(*file)
		if err != nil {
			return usageErr(err)
		}
		defer f.Close()
		ok, err := verify(keys, f, stdout)
		if err != nil {
			return usageErr(err)
		}
		if !ok {
			return exitInvalid
		}
	case "jws":
		if *file == "" {
			return usageErr(errors.New("-file is required"))
		}
		f, err := os.Open(*file)
		if err != nil {
			return usageErr(err)
		}
		defer f.Close()
		ok, err := compact(f, stdout, stderr)
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

// parsePubs — ключи шлюза из -gateway-key: каждый — 64 hex, файл с ключом или
// файл с массивом gateway_keys источника хранилища.
func parsePubs(vals []string) (*gateway.KeySet, error) {
	var entries []gateway.KeyEntry
	for _, v := range vals {
		more, err := gateway.ParseKeyList([]byte(v))
		if err != nil {
			data, ferr := os.ReadFile(v)
			if ferr != nil {
				return nil, errors.New("-gateway-key: neither 64 hex characters nor a readable file")
			}
			if more, err = gateway.ParseKeyList(data); err != nil {
				return nil, fmt.Errorf("-gateway-key %s: %w", v, err)
			}
		}
		entries = append(entries, more...)
	}
	return gateway.ParseKeySet(entries)
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
		if a.KeyChanged {
			fmt.Fprintf(warn, "note: gateway %q signs with a new key (%s), and its chain goes on from seq %d: list the new key in gateway_keys of the store's source, and give the previous one a not_after\n", name, a.Receipt.Kid, a.Receipt.Seq)
		}
		if a.Stale > 0 {
			fmt.Fprintf(warn, "warning: %d lines of %s are copies of earlier receipts of gateway %q or a second branch of its chain: someone who can write the file wrote them, and the chain does not go on from them\n", a.Stale, path, name)
		}
		n++
	}
	return n, sc.Err()
}

// verify проверяет все квитанции файла тем же разбором, что и хранилище, и
// печатает каждую поломку и итог. Срок ключа здесь не сверяется: когда
// квитанцию приняло хранилище, знает только оно.
func verify(keys *gateway.KeySet, in io.Reader, out io.Writer) (bool, error) {
	tr := gateway.NewReceiptTracker(keys)
	for _, k := range keys.Keys() {
		if !k.NotBefore.IsZero() || !k.NotAfter.IsZero() {
			fmt.Fprintln(out, "note: the periods of the gateway keys are not checked here: a period is compared with the time the store received a receipt, which only the store's bundle shows")
			break
		}
	}
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
		v := tr.Check(line, time.Time{})
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

// compact печатает каждую квитанцию файла компактным JWS (заголовок, тело —
// строка без поля jws — и подпись): по одному в строке, в порядке файла.
// Подписи он не проверяет — для того их и печатает; строка, которая не
// кончается подписью квитанции, называется в warn, и итог тогда — false.
func compact(in io.Reader, out, warn io.Writer) (bool, error) {
	br := bufio.NewReaderSize(in, 64<<10)
	ok := true
	for n := 1; ; n++ {
		line, long, err := readLine(br, gateway.MaxReceiptLen+2)
		if err == io.EOF {
			return ok, nil
		}
		if err != nil {
			return false, err
		}
		if len(bytes.TrimSpace(line)) == 0 {
			continue
		}
		var jws string
		signed := false
		if !long {
			r, _ := gateway.ParseReceipt(line)
			jws, signed = r.Compact()
		}
		if !signed {
			ok = false
			fmt.Fprintf(warn, "line %d: not a receipt with a signature, skipped\n", n)
			continue
		}
		fmt.Fprintln(out, jws)
	}
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
