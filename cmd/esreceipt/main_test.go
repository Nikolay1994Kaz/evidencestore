package main

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
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
	key, pub := newKey(t, t.TempDir(), "gw.key") // ключ и голова — не в каталоге квитанций
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
	_, otherPub := newKey(t, t.TempDir(), "other.key")
	if code, out, _ := call(t, "", "verify", "-gateway-key", otherPub, "-file", file); code != exitInvalid || !strings.Contains(out, "4 not intact") {
		t.Fatalf("verify with another key: %d\n%s", code, out)
	}
}

func TestSignRefuses(t *testing.T) {
	dir := t.TempDir()
	key, _ := newKey(t, t.TempDir(), "gw.key") // ключ и голова — не в каталоге квитанций
	other, _ := newKey(t, t.TempDir(), "other.key")
	file := filepath.Join(dir, "receipts.jsonl")
	if code, _, errOut := call(t, `{"action":"p-1","step":"mandate"}`, "sign", "-key", key, "-gateway", "gw", "-file", file); code != exitOK {
		t.Fatalf("sign: %s", errOut)
	}
	for name, c := range map[string]struct {
		stdin string
		args  []string
		want  string
	}{
		"unknown field":         {`{"action":"p-1","step":"cart","purchase_id":"p-1"}`, []string{"-key", key, "-gateway", "gw"}, "unknown field"},
		"no action":             {`{"step":"cart"}`, []string{"-key", key, "-gateway", "gw"}, `"action"`},
		"bad time":              {`{"action":"p-1","step":"cart","time":"yesterday"}`, []string{"-key", key, "-gateway", "gw"}, "time"},
		"two objects in a line": {`{"action":"p-1","step":"cart"} {"action":"p-1","step":"pay"}`, []string{"-key", key, "-gateway", "gw"}, "one JSON object"},
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
	os.WriteFile(file, append(data, []byte(`{"v":2,"gateway":"gw"`)...), 0o640)
	if code, _, errOut := call(t, `{"action":"p-1","step":"cart"}`, "sign", "-key", key, "-gateway", "gw", "-file", file); code != exitOK || !strings.Contains(errOut, "torn") {
		t.Fatalf("after a torn line: %d %s", code, errOut)
	}
	if code, out, _ := call(t, "", "verify", "-gateway-key", keyPub, "-file", file); code != exitInvalid || !strings.Contains(out, "6 receipts of 2 gateways, 3 not intact") || !strings.Contains(out, "line 5:") {
		t.Fatalf("verify after a torn line: %d\n%s", code, out)
	}
	if after, _ := os.ReadFile(file); !bytes.HasPrefix(after, data) || !bytes.Contains(after, []byte(`{"v":2,"gateway":"gw"`+"\n")) {
		t.Fatalf("the file after a torn line:\n%s", after[len(data):])
	}

	// Другой ключ на той же цепочке — не отказ, а новая цепочка с
	// предупреждением: отказ здесь давал любому, кто пишет в файл, остановить
	// шлюз одной строкой от его имени (R1-3). Не тот ключ называют проверка и
	// хранилище: подпись не та.
	code, _, errOut = call(t, `{"action":"p-1","step":"cart"}`, "sign", "-key", other, "-gateway", "gw", "-file", file)
	if code != exitOK || !strings.Contains(errOut, `claim gateway "gw", and none is signed with this key`) {
		t.Fatalf("another key on the same chain: %d %s", code, errOut)
	}
	if code, out, _ := call(t, "", "verify", "-gateway-key", keyPub, "-file", file); code != exitInvalid || !strings.Contains(out, "7 receipts of 2 gateways, 4 not intact") || !strings.Contains(out, "line 7:") {
		t.Fatalf("verify after another key: %d\n%s", code, out)
	}
	// Строка длиннее любой квитанции — поломка, а не конец проверки.
	f, _ := os.OpenFile(file, os.O_APPEND|os.O_WRONLY, 0o640)
	f.Write(append(bytes.Repeat([]byte("x"), 3<<20), '\n'))
	f.Close()
	if code, out, _ := call(t, "", "verify", "-gateway-key", keyPub, "-file", file); code != exitInvalid || !strings.Contains(out, "line 8: longer than a receipt can be") || !strings.Contains(out, "8 receipts of 2 gateways, 5 not intact") {
		t.Fatalf("verify after a long line: %d\n%s", code, out)
	}
}

// Два подписывающих над одним файлом не разводят цепочку: файл под замком.
func TestSignConcurrent(t *testing.T) {
	dir := t.TempDir()
	key, pub := newKey(t, t.TempDir(), "gw.key") // ключ и голова — не в каталоге квитанций
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

// T-5 третьего захода: голова по умолчанию — рядом с ключом; ключ в каталоге
// квитанций — голова там же, и её подменяет тот, у кого ключа нет: sign
// отказывает и называет "head".
func TestSignRefusesAHeadInTheReceiptsDirectory(t *testing.T) {
	dir := t.TempDir()
	key, _ := newKey(t, dir, "gw.key")
	file := filepath.Join(dir, "receipts.jsonl")
	var stdout, stderr bytes.Buffer
	code := run([]string{"sign", "-key", key, "-gateway", "gw", "-file", file}, strings.NewReader(`{"action":"a","step":"s"}`+"\n"), &stdout, &stderr)
	if code == 0 || !strings.Contains(stderr.String(), "lies in the directory of the receipts file") {
		t.Fatalf("code %d: %s", code, stderr.String())
	}
	if _, err := os.Stat(file); err == nil {
		t.Fatal("a receipt was written")
	}
}

// Ключ шлюза как JWK и квитанции обычным компактным JWS: всё, что нужно
// чужой библиотеке JOSE, чтобы проверить подпись без этого кода.
func TestReceiptsForAJOSELibrary(t *testing.T) {
	dir := t.TempDir()
	key, pub := newKey(t, t.TempDir(), "gw.key")
	raw, _ := gateway.ParseKey(pub)
	code, out, errOut := call(t, "", "pubkey", "-key", key, "-jwk")
	var jwk struct{ Kty, Crv, X, Kid string }
	if err := json.Unmarshal([]byte(out), &jwk); code != exitOK || err != nil || jwk.Kty != "OKP" || jwk.Crv != "Ed25519" ||
		jwk.X != base64.RawURLEncoding.EncodeToString(raw) || jwk.Kid != gateway.KeyID(raw) {
		t.Fatalf("pubkey -jwk: %d %q %s %v", code, out, errOut, err)
	}

	file := filepath.Join(dir, "receipts.jsonl")
	steps := `{"action":"p-1","step":"mandate","body":{"customer":"c-1"}}` + "\n" + `{"action":"p-1","step":"cart"}` + "\n"
	if code, _, errOut := call(t, steps, "sign", "-key", key, "-gateway", "shop-gw", "-file", file); code != exitOK {
		t.Fatalf("sign: %d %s", code, errOut)
	}
	data, _ := os.ReadFile(file)
	lines := strings.Split(strings.TrimSuffix(string(data), "\n"), "\n")
	code, out, errOut = call(t, "", "jws", "-file", file)
	tokens := strings.Fields(out)
	if code != exitOK || len(tokens) != 2 {
		t.Fatalf("jws: %d, %d tokens, %s", code, len(tokens), errOut)
	}
	for i, tok := range tokens {
		parts := strings.Split(tok, ".")
		if len(parts) != 3 {
			t.Fatalf("token %d has %d parts", i+1, len(parts))
		}
		// Как проверяет библиотека: заголовок, тело и подпись — из токена, ключ —
		// из JWK по kid заголовка.
		var hdr struct{ Alg, Kid, Typ string }
		h, _ := base64.RawURLEncoding.DecodeString(parts[0])
		if err := json.Unmarshal(h, &hdr); err != nil || hdr.Alg != "Ed25519" || hdr.Kid != jwk.Kid || hdr.Typ != gateway.ReceiptType {
			t.Fatalf("token %d header %s", i+1, h)
		}
		sig, _ := base64.RawURLEncoding.DecodeString(parts[2])
		if !ed25519.Verify(raw, []byte(parts[0]+"."+parts[1]), sig) {
			t.Fatalf("token %d does not verify as a JWS", i+1)
		}
		// Тело токена — строка файла без поля jws, а поле jws — тот же токен
		// без тела.
		payload, _ := base64.RawURLEncoding.DecodeString(parts[1])
		if want := string(payload[:len(payload)-1]) + `,"jws":"` + parts[0] + ".." + parts[2] + `"}`; want != lines[i] {
			t.Fatalf("token %d is not line %d of the file:\n%s\n%s", i+1, i+1, want, lines[i])
		}
	}
	// Строка без подписи квитанции названа, остальные напечатаны, код — 1.
	os.WriteFile(file, []byte(lines[0]+"\nnot a receipt\n"+lines[1]+"\n"), 0o640)
	if code, out, errOut := call(t, "", "jws", "-file", file); code != exitInvalid || len(strings.Fields(out)) != 2 || !strings.Contains(errOut, "line 2: not a receipt with a signature") {
		t.Fatalf("jws of a file with a foreign line: %d, %q, %q", code, out, errOut)
	}
}

// Шлюз сменил ключ на том же месте: цепочка идёт дальше, sign говорит об
// этом, а verify проверяет файл обоими ключами — по одному каждому или
// списком gateway_keys источника.
func TestSignAfterAKeyChange(t *testing.T) {
	dir, keys := t.TempDir(), t.TempDir()
	key, oldPub := newKey(t, keys, "gw.key")
	file := filepath.Join(dir, "receipts.jsonl")
	if code, _, errOut := call(t, `{"action":"p-1","step":"mandate"}`+"\n"+`{"action":"p-1","step":"cart"}`, "sign", "-key", key, "-gateway", "gw", "-file", file); code != exitOK {
		t.Fatalf("sign: %s", errOut)
	}
	if err := os.Rename(key, key+".2026"); err != nil {
		t.Fatal(err)
	}
	_, newPub := newKey(t, keys, "gw.key")
	code, _, errOut := call(t, `{"action":"p-1","step":"payment"}`+"\n"+`{"action":"p-1","step":"delivery"}`, "sign", "-key", key, "-gateway", "gw", "-file", file)
	if code != exitOK || strings.Count(errOut, "signs with a new key") != 1 || !strings.Contains(errOut, "its chain goes on from seq 3") {
		t.Fatalf("sign with a new key: %d %s", code, errOut)
	}
	if code, out, _ := call(t, "", "verify", "-gateway-key", oldPub, "-gateway-key", newPub, "-file", file); code != exitOK || !strings.Contains(out, "4 receipts of 1 gateways, 0 not intact") {
		t.Fatalf("verify with both keys: %d\n%s", code, out)
	}
	for _, one := range []string{oldPub, newPub} {
		if code, out, _ := call(t, "", "verify", "-gateway-key", one, "-file", file); code != exitInvalid || !strings.Contains(out, "not among the gateway keys") {
			t.Fatalf("verify with one key of two: %d\n%s", code, out)
		}
	}
	// Ключи списком, как в настройках источника; о сроках verify предупреждает:
	// времени приёма у него нет.
	list := filepath.Join(dir, "keys.json")
	os.WriteFile(list, []byte(`[{"key":"`+oldPub+`","not_after":"2026-12-01T00:00:00Z"},"`+newPub+`"]`), 0o644)
	if code, out, _ := call(t, "", "verify", "-gateway-key", list, "-file", file); code != exitOK || !strings.Contains(out, "periods of the gateway keys are not checked here") || !strings.Contains(out, "0 not intact") {
		t.Fatalf("verify with a key list: %d\n%s", code, out)
	}
	if code, _, errOut := call(t, "", "verify", "-gateway-key", oldPub, "-gateway-key", oldPub, "-file", file); code != exitUsage || !strings.Contains(errOut, "listed twice") {
		t.Fatalf("verify with a key twice: %d %s", code, errOut)
	}
}
