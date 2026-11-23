package main

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/Nikolay1994Kaz/evidencestore/internal/gateway"
)

func call(t *testing.T, stdin string, args ...string) (int, string, string) {
	t.Helper()
	var out, errOut bytes.Buffer
	code := run(args, strings.NewReader(stdin), &out, &errOut)
	return code, out.String(), errOut.String()
}

func newKey(t *testing.T, dir, name string) (string, string) {
	t.Helper()
	path := filepath.Join(dir, name)
	code, out, errOut := call(t, "", "keygen", "-key", path)
	if code != exitOK {
		t.Fatalf("keygen: %d %s", code, errOut)
	}
	return path, strings.TrimSpace(out)
}

func TestSignAndVerify(t *testing.T) {
	dir := t.TempDir()
	key, pub := newKey(t, dir, "gw.key")
	if st, err := os.Stat(key); err != nil || st.Mode().Perm() != 0o600 {
		t.Fatalf("key file mode %v, %v", st.Mode(), err)
	}
	if _, err := gateway.ParseKey(pub); err != nil {
		t.Fatalf("public key %q: %v", pub, err)
	}
	if code, out, _ := call(t, "", "pubkey", "-key", key); code != exitOK || strings.TrimSpace(out) != pub {
		t.Fatalf("pubkey: %d %q", code, out)
	}
	// Ключ, который уже есть, не перезаписывается.
	if code, _, _ := call(t, "", "keygen", "-key", key); code != exitUsage {
		t.Fatalf("keygen over an existing key: %d", code)
	}

	file := filepath.Join(dir, "receipts.jsonl")
	steps := `{"action":"p-1","step":"mandate","approval":{"format":"jws","credential":"a.b.c"},"body":{"customer":"c-1"}}
{"action":"p-1","step":"cart","time":"2026-11-23T12:00:00Z","refs":[{"source":"pay","subject":"n-1"}]}

{"action":"p-2","step":"mandate"}
`
	if code, _, errOut := call(t, steps, "sign", "-key", key, "-gateway", "shop-gw", "-file", file); code != exitOK {
		t.Fatalf("sign: %d %s", code, errOut)
	}
	if code, _, errOut := call(t, `{"action":"p-1","step":"payment"}`, "sign", "-key", key, "-gateway", "shop-gw", "-file", file); code != exitOK {
		t.Fatalf("sign, second run: %d %s", code, errOut)
	}
	data, _ := os.ReadFile(file)
	lines := strings.Split(strings.TrimSuffix(string(data), "\n"), "\n")
	if len(lines) != 4 {
		t.Fatalf("%d lines:\n%s", len(lines), data)
	}
	last, err := gateway.ParseReceipt([]byte(lines[3]))
	if err != nil || last.Seq != 4 || last.Action != "p-1" || last.Step != "payment" {
		t.Fatalf("the last receipt: %+v, %v", last, err)
	}
	if code, out, _ := call(t, "", "verify", "-gateway-key", pub, "-file", file); code != exitOK || !strings.Contains(out, "4 receipts of 1 gateways, 0 not intact") {
		t.Fatalf("verify: %d\n%s", code, out)
	}

	// Ключ из файла — тоже.
	pubFile := filepath.Join(dir, "gw.pub")
	os.WriteFile(pubFile, []byte(pub+"\n"), 0o644)
	if code, _, _ := call(t, "", "verify", "-gateway-key", pubFile, "-file", file); code != exitOK {
		t.Fatalf("verify with a key file: %d", code)
	}

	// Порча строки — провал, и строка названа. В цепочку шлюза подделка не
	// входит: следующая строка ссылается на настоящую, которой здесь нет, и
	// читается как начало цепочки без неё.
	spoiled := strings.Replace(string(data), `"c-1"`, `"c-2"`, 1)
	bad := filepath.Join(dir, "bad.jsonl")
	os.WriteFile(bad, []byte(spoiled), 0o644)
	if code, out, _ := call(t, "", "verify", "-gateway-key", pub, "-file", bad); code != exitInvalid || !strings.Contains(out, "line 1:") || !strings.Contains(out, "1 not intact") {
		t.Fatalf("verify of a changed file: %d\n%s", code, out)
	}
	// Выпала строка — поломка сцепки у следующей.
	dropped := filepath.Join(dir, "dropped.jsonl")
	os.WriteFile(dropped, []byte(lines[0]+"\n"+lines[2]+"\n"+lines[3]+"\n"), 0o644)
	if code, out, _ := call(t, "", "verify", "-gateway-key", pub, "-file", dropped); code != exitInvalid || !strings.Contains(out, "link broken") {
		t.Fatalf("verify of a file with a line taken out: %d\n%s", code, out)
	}
	// Чужим ключом — подписи не сходятся.
	_, otherPub := newKey(t, dir, "other.key")
	if code, out, _ := call(t, "", "verify", "-gateway-key", otherPub, "-file", file); code != exitInvalid || !strings.Contains(out, "4 not intact") {
		t.Fatalf("verify with another key: %d\n%s", code, out)
	}
}

func TestSignRefuses(t *testing.T) {
	dir := t.TempDir()
	key, _ := newKey(t, dir, "gw.key")
	other, _ := newKey(t, dir, "other.key")
	file := filepath.Join(dir, "receipts.jsonl")
	if code, _, errOut := call(t, `{"action":"p-1","step":"mandate"}`, "sign", "-key", key, "-gateway", "gw", "-file", file); code != exitOK {
		t.Fatalf("sign: %s", errOut)
	}
	for name, c := range map[string]struct {
		stdin string
		args  []string
		want  string
	}{
		"another key on the same chain": {`{"action":"p-1","step":"cart"}`, []string{"-key", other, "-gateway", "gw"}, "none is signed with this key"},
		"unknown field":                 {`{"action":"p-1","step":"cart","purchase_id":"p-1"}`, []string{"-key", key, "-gateway", "gw"}, "unknown field"},
		"no action":                     {`{"step":"cart"}`, []string{"-key", key, "-gateway", "gw"}, `"action"`},
		"bad time":                      {`{"action":"p-1","step":"cart","time":"yesterday"}`, []string{"-key", key, "-gateway", "gw"}, "time"},
		"two objects in a line":         {`{"action":"p-1","step":"cart"} {"action":"p-1","step":"pay"}`, []string{"-key", key, "-gateway", "gw"}, "one JSON object"},
	} {
		t.Run(name, func(t *testing.T) {
			code, _, errOut := call(t, c.stdin, append([]string{"sign", "-file", file}, c.args...)...)
			if code == exitOK || !strings.Contains(errOut, c.want) {
				t.Fatalf("code %d, %s", code, errOut)
			}
		})
	}
	// Ничего из отвергнутого в файл не попало.
	data, _ := os.ReadFile(file)
	if strings.Count(string(data), "\n") != 1 {
		t.Fatalf("the file:\n%s", data)
	}
	// Чужая строка в конце файла (подделка с чужой подписью) шлюз не
	// останавливает: цепочка идёт от его последней квитанции, и проверка
	// называет поломанной только подделку.
	own, _ := os.ReadFile(file)
	ownLines := strings.Split(strings.TrimSuffix(string(own), "\n"), "\n")
	fake := strings.Replace(ownLines[len(ownLines)-1], `"step":"mandate"`, `"step":"cancel"`, 1)
	os.WriteFile(file, []byte(string(own)+fake+"\n"), 0o640)
	code, _, errOut := call(t, `{"action":"p-1","step":"cart"}`, "sign", "-key", key, "-gateway", "gw", "-file", file)
	if code != exitOK || !strings.Contains(errOut, "the last 1 lines") {
		t.Fatalf("after a foreign line: %d %s", code, errOut)
	}
	keyPub := strings.TrimSpace(func() string { _, o, _ := call(t, "", "pubkey", "-key", key); return o }())
	if code, out, _ := call(t, "", "verify", "-gateway-key", keyPub, "-file", file); code != exitInvalid || !strings.Contains(out, "3 receipts of 1 gateways, 1 not intact") || !strings.Contains(out, "line 2:") {
		t.Fatalf("verify after a foreign line: %d\n%s", code, out)
	}
	// Второй шлюз в том же файле — своя цепочка.
	if code, _, errOut := call(t, `{"action":"p-9","step":"cart"}`, "sign", "-key", other, "-gateway", "gw-2", "-file", file); code != exitOK {
		t.Fatalf("a second gateway in the file: %s", errOut)
	}
	if code, out, _ := call(t, "", "verify", "-gateway-key", keyPub, "-file", file); code != exitInvalid || !strings.Contains(out, "4 receipts of 2 gateways, 2 not intact") {
		t.Fatalf("verify with a second gateway: %d\n%s", code, out)
	}
	data, _ = os.ReadFile(file)

	// Порванная последняя строка (писавший умер посреди неё): она закрыта
	// переводом строки и осталась поломанной строкой, цепочка — от квитанции
	// до неё.
	os.WriteFile(file, append(data, []byte(`{"v":1,"gateway":"gw"`)...), 0o640)
	if code, _, errOut := call(t, `{"action":"p-1","step":"cart"}`, "sign", "-key", key, "-gateway", "gw", "-file", file); code != exitOK || !strings.Contains(errOut, "torn") {
		t.Fatalf("after a torn line: %d %s", code, errOut)
	}
	if code, out, _ := call(t, "", "verify", "-gateway-key", keyPub, "-file", file); code != exitInvalid || !strings.Contains(out, "6 receipts of 2 gateways, 3 not intact") || !strings.Contains(out, "line 5:") {
		t.Fatalf("verify after a torn line: %d\n%s", code, out)
	}
	if after, _ := os.ReadFile(file); !bytes.HasPrefix(after, data) || !bytes.Contains(after, []byte(`{"v":1,"gateway":"gw"`+"\n")) {
		t.Fatalf("the file after a torn line:\n%s", after[len(data):])
	}
}

// Два подписывающих над одним файлом не разводят цепочку: файл под замком.
func TestSignConcurrent(t *testing.T) {
	dir := t.TempDir()
	key, pub := newKey(t, dir, "gw.key")
	file := filepath.Join(dir, "receipts.jsonl")
	var wg sync.WaitGroup
	for i := range 8 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			var in strings.Builder
			for j := range 5 {
				fmt.Fprintf(&in, `{"action":"a-%d","step":"s%d"}`+"\n", i, j)
			}
			var out, errOut bytes.Buffer
			if code := run([]string{"sign", "-key", key, "-gateway", "gw", "-file", file}, strings.NewReader(in.String()), &out, &errOut); code != exitOK {
				t.Errorf("sign %d: %s", i, errOut.String())
			}
		}()
	}
	wg.Wait()
	if code, out, _ := call(t, "", "verify", "-gateway-key", pub, "-file", file); code != exitOK || !strings.Contains(out, "40 receipts of 1 gateways, 0 not intact") {
		t.Fatalf("verify: %d\n%s", code, out)
	}
}

func TestUsage(t *testing.T) {
	for _, args := range [][]string{{}, {"nope"}, {"sign"}, {"verify", "-file", "x"}, {"keygen"}, {"sign", "-key", "k", "extra"}} {
		if code, _, _ := call(t, "", args...); code != exitUsage {
			t.Fatalf("%v: code %d", args, code)
		}
	}
}
