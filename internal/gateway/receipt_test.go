package gateway

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"math/rand"
	"strconv"
	"strings"
	"testing"
	"time"
)

func receiptKey(t *testing.T, seed byte) ed25519.PrivateKey {
	t.Helper()
	return ed25519.NewKeyFromSeed(bytes.Repeat([]byte{seed}, ed25519.SeedSize))
}

// signRaw подписывает готовые байты B так, как это делает шлюз на другом
// языке: объект без sig, подпись дописана перед последней скобкой.
func signRaw(key ed25519.PrivateKey, b string) []byte {
	sig := ed25519.Sign(key, append([]byte(receiptDomain), b...))
	return []byte(b[:len(b)-1] + `,"sig":"` + hex.EncodeToString(sig) + `"}`)
}

func mustSign(t *testing.T, s *Signer, d Draft) []byte {
	t.Helper()
	line, err := s.Sign(d)
	if err != nil {
		t.Fatal(err)
	}
	return line
}

var at = time.Date(2026, 11, 23, 12, 0, 0, 123456789, time.UTC)

func TestReceiptRoundTrip(t *testing.T) {
	key := receiptKey(t, 1)
	s, err := NewSigner(key, "shop-gw-1", nil)
	if err != nil {
		t.Fatal(err)
	}
	d := Draft{
		Time: at, Action: "p-1002", Step: "mandate",
		Refs:     []Ref{{Source: "pg-agent", Subject: "751"}},
		Approval: &Approval{Format: "jws", Credential: "eyJhbGciOiJFUzI1NiJ9.e30.c2ln"},
		Body:     json.RawMessage(`{"customer":"c-1","note":"<b>&</b>"}`),
	}
	line := mustSign(t, s, d)
	r, err := ParseReceipt(line)
	if err != nil {
		t.Fatalf("%v\n%s", err, line)
	}
	if err := r.Verify(key.Public().(ed25519.PublicKey)); err != nil {
		t.Fatal(err)
	}
	if r.Gateway != "shop-gw-1" || r.Seq != 1 || r.Prev != Genesis || !r.Time.Equal(at) || r.Action != "p-1002" || r.Step != "mandate" ||
		len(r.Refs) != 1 || r.Refs[0] != d.Refs[0] || *r.Approval != *d.Approval || string(r.Body) != string(d.Body) {
		t.Fatalf("parsed %+v", r)
	}
	sum := sha256.Sum256(line)
	if r.Hash != hex.EncodeToString(sum[:]) {
		t.Fatal("the hash is not SHA-256 of the line")
	}
	// HTML-символы не экранируются: квитанцию читают люди.
	if !bytes.Contains(line, []byte(`<b>&</b>`)) {
		t.Fatalf("the body was rewritten: %s", line)
	}
	// Хвост подписи — ровно в конце строки.
	if !bytes.HasSuffix(line[:len(line)-130], []byte(`,"sig":"`)) {
		t.Fatalf("the signature is not the last field: %s", line)
	}
	next := mustSign(t, s, Draft{Time: at, Action: "p-1002", Step: "cart"})
	n, err := ParseReceipt(next)
	if err != nil || n.Seq != 2 || n.Prev != r.Hash {
		t.Fatalf("the next receipt: seq %d, prev %s, err %v", n.Seq, n.Prev, err)
	}
}

// Квитанцию шлюза на другом языке: ключи в своём порядке, пробелы, \u-escape
// с суррогатной парой (так пишет json.dumps Python по умолчанию).
func TestReceiptFromAnotherWriter(t *testing.T) {
	key := receiptKey(t, 2)
	b := `{"step": "cart", "action": "p-😀", "time": "2026-11-23T12:00:00Z", "prev": "genesis", "seq": 1, "gateway": "py", "v": 1, "body": {"total": 10}}`
	r, err := ParseReceipt(signRaw(key, b))
	if err != nil {
		t.Fatal(err)
	}
	if err := r.Verify(key.Public().(ed25519.PublicKey)); err != nil {
		t.Fatal(err)
	}
	if r.Action != "p-😀" || r.Step != "cart" || r.Gateway != "py" {
		t.Fatalf("parsed %+v", r)
	}
	// Строка с \r\n — те же байты подписи и тот же хэш.
	line := signRaw(key, b)
	crlf, err := ParseReceipt(append(bytes.Clone(line), '\r', '\n'))
	if err != nil || crlf.Hash != r.Hash || crlf.Verify(key.Public().(ed25519.PublicKey)) != nil {
		t.Fatalf("CRLF: %v, hash %s vs %s", err, crlf.Hash, r.Hash)
	}
}

func TestReceiptRejectsMalformed(t *testing.T) {
	key := receiptKey(t, 3)
	ok := `{"v":1,"gateway":"g","seq":1,"prev":"genesis","time":"2026-11-23T12:00:00Z","action":"a-1","step":"s"`
	cases := map[string]string{
		"v 2":                  strings.Replace(ok, `"v":1`, `"v":2`, 1),
		"v as a string":        strings.Replace(ok, `"v":1`, `"v":"1"`, 1),
		"v 1.0":                strings.Replace(ok, `"v":1`, `"v":1.0`, 1),
		"no gateway":           strings.Replace(ok, `"gateway":"g",`, ``, 1),
		"gateway with a space": strings.Replace(ok, `"gateway":"g"`, `"gateway":"g w"`, 1),
		"gateway too long":     strings.Replace(ok, `"gateway":"g"`, `"gateway":"`+strings.Repeat("g", MaxGatewayName+1)+`"`, 1),
		"lone surrogate":       strings.Replace(ok, `"gateway":"g"`, `"gateway":"\ud800"`, 1),
		"lone half in body":    strings.Replace(ok, `"step":"s"`, `"step":"s","body":{"reason":"\ud800 x"}`, 1),
		"lone low half":        strings.Replace(ok, `"step":"s"`, `"step":"s","body":{"reason":"\udfff"}`, 1),
		"seq 0":                strings.Replace(ok, `"seq":1`, `"seq":0`, 1),
		"seq 01":               strings.Replace(ok, `"seq":1`, `"seq":01`, 1),
		"seq 1.0":              strings.Replace(ok, `"seq":1`, `"seq":1.0`, 1),
		"seq 1e0":              strings.Replace(ok, `"seq":1`, `"seq":1e0`, 1),
		"seq -1":               strings.Replace(ok, `"seq":1`, `"seq":-1`, 1),
		"seq as a string":      strings.Replace(ok, `"seq":1`, `"seq":"1"`, 1),
		"seq past 2^53":        strings.Replace(ok, `"seq":1`, `"seq":9007199254740992`, 1),
		"prev in upper case":   strings.Replace(ok, `"genesis"`, `"`+strings.Repeat("A", 64)+`"`, 1),
		"prev short":           strings.Replace(ok, `"genesis"`, `"abcd"`, 1),
		"time not RFC 3339":    strings.Replace(ok, `2026-11-23T12:00:00Z`, `23.11.2026 12:00`, 1),
		"no time":              strings.Replace(ok, `"time":"2026-11-23T12:00:00Z",`, ``, 1),
		"action a number":      strings.Replace(ok, `"action":"a-1"`, `"action":1002`, 1),
		"action empty":         strings.Replace(ok, `"action":"a-1"`, `"action":""`, 1),
		"action too long":      strings.Replace(ok, `"action":"a-1"`, `"action":"`+strings.Repeat("a", 257)+`"`, 1),
		"action lone half":     strings.Replace(ok, `"action":"a-1"`, `"action":"a\udc00"`, 1),
		"step with a slash":    strings.Replace(ok, `"step":"s"`, `"step":"s/1"`, 1),
		"unknown field":        ok + `,"purchase_id":"p-1"`,
		"key twice":            ok + `,"step":"t"`,
		"key twice folded":     ok + `,"STEP":"t"`,
		"refs not an array":    ok + `,"refs":{"source":"s","subject":"1"}`,
		"refs null":            ok + `,"refs":null`,
		"ref with a slash":     ok + `,"refs":[{"source":"a/b","subject":"1"}]`,
		"ref without subject":  ok + `,"refs":[{"source":"s"}]`,
		"ref extra key":        ok + `,"refs":[{"source":"s","subject":"1","x":1}]`,
		"ref key twice":        ok + `,"refs":[{"source":"s","subject":"1","source":"t"}]`,
		"too many refs":        ok + `,"refs":[` + strings.TrimSuffix(strings.Repeat(`{"source":"s","subject":"1"},`, MaxRefs+1), ",") + `]`,
		"approval a string":    ok + `,"approval":"eyJ"`,
		"approval no format":   ok + `,"approval":{"credential":"x"}`,
		"approval empty":       ok + `,"approval":{"format":"jws","credential":""}`,
	}
	for name, b := range cases {
		t.Run(name, func(t *testing.T) {
			line := signRaw(key, b+`}`)
			if _, err := ParseReceipt(line); err == nil {
				t.Fatalf("accepted: %s", line)
			}
			v := NewReceiptTracker(key.Public().(ed25519.PublicKey)).Check(line)
			if v.Clean() || v.Problem == "" {
				t.Fatalf("verdict is clean: %+v", v)
			}
		})
	}
	// Контроль: та же строка без порчи принимается.
	if _, err := ParseReceipt(signRaw(key, ok+`}`)); err != nil {
		t.Fatal(err)
	}
}

func TestReceiptSignatureMustBeTheTail(t *testing.T) {
	key := receiptKey(t, 4)
	pub := key.Public().(ed25519.PublicKey)
	b := `{"v":1,"gateway":"g","seq":1,"prev":"genesis","time":"2026-11-23T12:00:00Z","action":"a-1","step":"s"}`
	line := signRaw(key, b)
	sig := line[len(line)-130 : len(line)-2]
	cases := map[string]string{
		"no signature":             b,
		"signature first":          `{"sig":"` + string(sig) + `",` + b[1:],
		"signature in upper case":  string(line[:len(line)-130]) + strings.ToUpper(string(sig)) + `"}`,
		"space before the tail":    b[:len(b)-1] + ` ,"sig":"` + string(sig) + `"}`,
		"signature inside body":    b[:len(b)-1] + `,"body":{"sig":"` + string(sig) + `"}}`,
		"signature twice":          string(line[:len(line)-1]) + `,"sig":"` + string(sig) + `"}`,
		"short signature":          b[:len(b)-1] + `,"sig":"` + string(sig[:126]) + `"}`,
		"data after the signature": string(line) + ` {}`,
	}
	for name, l := range cases {
		t.Run(name, func(t *testing.T) {
			r, err := ParseReceipt([]byte(l))
			if err == nil && r.Verify(pub) == nil {
				t.Fatalf("a receipt with its signature out of place passes: %s", l)
			}
		})
	}
	// Подпись — ровно над B: байт тела меняется — подпись не сходится.
	bad := bytes.Replace(bytes.Clone(line), []byte(`"a-1"`), []byte(`"a-2"`), 1)
	r, err := ParseReceipt(bad)
	if err != nil {
		t.Fatal(err)
	}
	if r.Verify(pub) == nil {
		t.Fatal("a changed receipt verifies")
	}
	// Чужой ключ — не та подпись.
	r, _ = ParseReceipt(line)
	if r.Verify(receiptKey(t, 5).Public().(ed25519.PublicKey)) == nil {
		t.Fatal("verifies with another key")
	}
	// Подпись над B, но без домена — не подпись квитанции.
	raw := ed25519.Sign(key, []byte(b))
	noDomain := b[:len(b)-1] + `,"sig":"` + hex.EncodeToString(raw) + `"}`
	if r, err := ParseReceipt([]byte(noDomain)); err != nil || r.Verify(pub) == nil {
		t.Fatalf("a signature without the domain verifies (err %v)", err)
	}
}

func TestReceiptTrackerLinks(t *testing.T) {
	key := receiptKey(t, 6)
	pub := key.Public().(ed25519.PublicKey)
	s, _ := NewSigner(key, "gw", nil)
	var lines [][]byte
	for i := range 6 {
		lines = append(lines, mustSign(t, s, Draft{Time: at.Add(time.Duration(i) * time.Second), Action: "act-" + string(rune('a'+i%2)), Step: "intent"}))
	}
	tr := NewReceiptTracker(pub)
	want := []string{LinkGenesis, LinkOK, LinkOK}
	for i, l := range lines[:3] {
		v := tr.Check(l)
		if v.Link != want[i] || !v.Clean() || v.Signature != SigValid || v.Seq != uint64(i+1) || v.Writer != "gw" {
			t.Fatalf("receipt %d: %+v", i+1, v)
		}
	}
	// Квитанция 4 выпала: пятая — поломка, шестая — снова цела.
	if v := tr.Check(lines[4]); v.Link != LinkBroken || v.Clean() || !strings.Contains(v.Problem, "seq 3") {
		t.Fatalf("after a lost receipt: %+v", v)
	}
	if v := tr.Check(lines[5]); v.Link != LinkOK || !v.Clean() {
		t.Fatalf("after the break: %+v", v)
	}
	// Повтор уже принятой — поломка, но цепочку он не двигает (R1-2): копию
	// своей прежней строки дописать может любой, кто пишет в файл, без ключа,
	// и раньше следующая настоящая квитанция выходила поломанной.
	for i, want := range map[int]string{5: "a copy of the gateway's last receipt (seq 6)", 2: "seq 3 after seq 6", 0: "a copy of the start of the gateway's chain"} {
		if v := tr.Check(lines[i]); v.Link != LinkStale || v.Clean() || v.Signature != SigValid || !strings.Contains(v.Problem, want) {
			t.Fatalf("a replayed receipt %d: %+v", i+1, v)
		}
	}
	seven := mustSign(t, s, Draft{Time: at.Add(7 * time.Second), Action: "act-c", Step: "intent"})
	if v := tr.Check(seven); v.Link != LinkOK || !v.Clean() {
		t.Fatalf("the next real receipt after the replays: %+v", v)
	}
	// prev верный, а seq перескочил: шлюз нумерует не по порядку — поломка.
	last, _ := ParseReceipt(seven)
	jump := signRaw(key, `{"v":1,"gateway":"gw","seq":`+strconv.FormatUint(last.Seq+2, 10)+`,"prev":"`+last.Hash+`","time":"2026-11-23T12:00:00Z","action":"a","step":"s"}`)
	if v := tr.Check(jump); v.Link != LinkBroken || v.Signature != SigValid || !strings.Contains(v.Problem, "follows seq") {
		t.Fatalf("a seq that jumps: %+v", v)
	}

	// Новая цепочка после принятых — поломка: квитанции между ними могли пропасть.
	s2, _ := NewSigner(key, "gw", nil)
	if v := tr.Check(mustSign(t, s2, Draft{Time: at, Action: "a", Step: "s"})); v.Link != LinkBroken || !strings.Contains(v.Problem, "new chain") {
		t.Fatalf("a restarted chain: %+v", v)
	}

	// Цепочку начали без нас — цела, но «first-seen».
	tr2 := NewReceiptTracker(pub)
	if v := tr2.Check(lines[2]); v.Link != LinkFirstSeen || !v.Clean() {
		t.Fatalf("first seen: %+v", v)
	}
	// Цепочки разных шлюзов не мешают друг другу.
	other, _ := NewSigner(key, "gw-2", nil)
	if v := tr2.Check(mustSign(t, other, Draft{Time: at, Action: "a", Step: "s"})); v.Link != LinkGenesis || !v.Clean() {
		t.Fatalf("a second gateway: %+v", v)
	}
	if v := tr2.Check(lines[3]); v.Link != LinkOK {
		t.Fatalf("the first gateway after the second: %+v", v)
	}

	// Чужая подпись — поломка подписи, а цепочка шлюза её не берёт: следующая
	// настоящая квитанция цела.
	forger, _ := NewSigner(receiptKey(t, 7), "gw", nil)
	tr3 := NewReceiptTracker(pub)
	if v := tr3.Check(mustSign(t, forger, Draft{Time: at, Action: "a", Step: "s"})); v.Signature != SigInvalid || v.Clean() || v.Link != LinkGenesis {
		t.Fatalf("a forged receipt: %+v", v)
	}
	if v := tr3.Check(lines[0]); v.Link != LinkGenesis || !v.Clean() {
		t.Fatalf("the gateway's first receipt after a forged one: %+v", v)
	}
	// Подделка посреди цепочки, с верным prev: следующая настоящая — цела.
	forged := signRaw(receiptKey(t, 7), strings.Replace(string(lines[1][:len(lines[1])-138])+"}", `"step":"intent"`, `"step":"cancel"`, 1))
	if v := tr3.Check(forged); v.Signature != SigInvalid || v.Link != LinkOK {
		t.Fatalf("a forged receipt in the middle: %+v", v)
	}
	if v := tr3.Check(lines[1]); v.Link != LinkOK || !v.Clean() {
		t.Fatalf("the gateway's receipt after a forged one: %+v", v)
	}
	// Без ключа подписи не проверяются, сцепка — да.
	if v := NewReceiptTracker(nil).Check(lines[0]); v.Signature != SigNoKey || !v.Clean() {
		t.Fatalf("no key: %+v", v)
	}
}

func TestReceiptTrackerResume(t *testing.T) {
	key := receiptKey(t, 8)
	pub := key.Public().(ed25519.PublicKey)
	s, _ := NewSigner(key, "gw", nil)
	a := NewReceiptTracker(pub)
	var verdicts []Verdict
	for i := range 3 {
		verdicts = append(verdicts, a.Check(mustSign(t, s, Draft{Time: at, Action: "x", Step: "s" + string(rune('0'+i))})))
	}
	// Хранилище перезапустилось: состояние — из вердиктов в цепи.
	b := NewReceiptTracker(pub)
	for _, v := range verdicts {
		b.Resume(v)
	}
	next := mustSign(t, s, Draft{Time: at, Action: "x", Step: "s3"})
	va, vb := a.Check(next), b.Check(next)
	if va != vb || vb.Link != LinkOK {
		t.Fatalf("after resume %+v, without restart %+v", vb, va)
	}
	// Вердикт без шлюза состояние не трогает.
	b.Resume(Verdict{Problem: "receipt is not valid UTF-8", Hash: strings.Repeat("0", 64)})
	if v := b.Check(mustSign(t, s, Draft{Time: at, Action: "x", Step: "s4"})); v.Link != LinkOK {
		t.Fatalf("resume of a nameless verdict moved the chain: %+v", v)
	}
}

// Вердикт лежит в цепи открыто: номера действия, шага и тела в нём нет.
func TestReceiptVerdictKeepsTheActionClosed(t *testing.T) {
	key := receiptKey(t, 9)
	s, _ := NewSigner(key, "gw", nil)
	line := mustSign(t, s, Draft{Time: at, Action: "customer-4417-secret", Step: "cancel-step",
		Refs: []Ref{{Source: "pay", Subject: "ref-secret"}}, Body: json.RawMessage(`{"secret":"body-secret"}`)})
	v := NewReceiptTracker(key.Public().(ed25519.PublicKey)).Check(line)
	raw, _ := json.Marshal(v)
	for _, secret := range []string{"customer-4417", "cancel-step", "ref-secret", "body-secret"} {
		if bytes.Contains(raw, []byte(secret)) {
			t.Errorf("the verdict shows %q: %s", secret, raw)
		}
	}
	// И в поломке — тоже: имя лишнего поля в тексте не называется.
	bad := signRaw(key, `{"v":1,"gateway":"gw","seq":1,"prev":"genesis","time":"2026-11-23T12:00:00Z","action":"a","step":"s","customer-4417-secret":1}`)
	v = NewReceiptTracker(key.Public().(ed25519.PublicKey)).Check(bad)
	if v.Clean() || strings.Contains(v.Problem, "customer-4417") {
		t.Fatalf("problem %q", v.Problem)
	}
}

func TestSignerResumesTheChain(t *testing.T) {
	key := receiptKey(t, 10)
	s, _ := NewSigner(key, "gw", nil)
	mustSign(t, s, Draft{Time: at, Action: "a", Step: "s"})
	last := mustSign(t, s, Draft{Time: at, Action: "a", Step: "t"})
	r, _ := ParseReceipt(last)
	s2, err := NewSigner(key, "gw", append(bytes.Clone(last), '\n'))
	if err != nil {
		t.Fatal(err)
	}
	n, _ := ParseReceipt(mustSign(t, s2, Draft{Time: at, Action: "a", Step: "u"}))
	if n.Seq != 3 || n.Prev != r.Hash {
		t.Fatalf("resumed at seq %d, prev %s", n.Seq, n.Prev)
	}
	if _, err := NewSigner(key, "other", last); err == nil {
		t.Fatal("continues the chain of another gateway")
	}
	if _, err := NewSigner(receiptKey(t, 11), "gw", last); err == nil {
		t.Fatal("continues a chain signed with another key")
	}
	if _, err := NewSigner(key, "gw", last[:len(last)-10]); err == nil {
		t.Fatal("continues after a torn last line")
	}
	if _, err := NewSigner(key, "g w", nil); err == nil {
		t.Fatal("a gateway name with a space")
	}
	// Шаг, который не пройдёт проверку, не подписывается, и цепочка стоит.
	if _, err := s2.Sign(Draft{Time: at, Action: "", Step: "s"}); err == nil {
		t.Fatal("signed a receipt without action")
	}
	if _, err := s2.Sign(Draft{Time: at, Action: "a", Step: "s", Body: json.RawMessage(`{`)}); err == nil {
		t.Fatal("signed a receipt with a broken body")
	}
	// Квитанция длиннее записи хранилища не подписывается: сборщик разрезал
	// бы её на куски, и ни один кусок квитанцией бы не был.
	big := json.RawMessage(`"` + strings.Repeat("x", MaxReceiptLen) + `"`)
	if _, err := s2.Sign(Draft{Time: at, Action: "a", Step: "s", Body: big}); err == nil || !strings.Contains(err.Error(), "longer than a store record") {
		t.Fatalf("signed a receipt longer than a record: %v", err)
	}
	fits := json.RawMessage(`"` + strings.Repeat("x", MaxReceiptLen-400) + `"`)
	if line, err := s2.Sign(Draft{Time: at, Action: "a", Step: "s", Body: fits}); err != nil || len(line) > MaxReceiptLen {
		t.Fatalf("a receipt that fits: %d bytes, %v", len(line), err)
	}
	n2, _ := ParseReceipt(mustSign(t, s2, Draft{Time: at, Action: "a", Step: "v"}))
	if n2.Seq != 5 {
		t.Fatalf("a refused draft moved the chain: seq %d", n2.Seq)
	}
}

// Порча любого байта — не паника и не чистый вердикт с той же подписью.
func TestReceiptMutationsDoNotPanic(t *testing.T) {
	key := receiptKey(t, 12)
	pub := key.Public().(ed25519.PublicKey)
	s, _ := NewSigner(key, "gw", nil)
	line := mustSign(t, s, Draft{Time: at, Action: "a-1", Step: "pay", Refs: []Ref{{Source: "pg", Subject: "1"}},
		Approval: &Approval{Format: "jws", Credential: "x.y.z"}, Body: json.RawMessage(`{"n":[1,2,{"k":"v"}]}`)})
	rnd := rand.New(rand.NewSource(1))
	for range 5000 {
		m := bytes.Clone(line)
		for range 1 + rnd.Intn(3) {
			m[rnd.Intn(len(m))] = byte(rnd.Intn(256))
		}
		if bytes.Equal(m, line) {
			continue
		}
		v := NewReceiptTracker(pub).Check(m)
		if v.Clean() && v.Signature == SigValid {
			r, _ := ParseReceipt(m)
			// Тот же смысл в других байтах подписи не сохраняет: подпись — над B.
			t.Fatalf("a changed line passes: %q (parsed %+v)", m, r)
		}
	}
}

// Пара суррогатов в body — один знак, как его ни экранируй: квитанция цела.
func TestReceiptAcceptsASurrogatePairInBody(t *testing.T) {
	key := receiptKey(t, 4)
	line := signRaw(key, `{"v":1,"gateway":"g","seq":1,"prev":"genesis","time":"2026-11-23T12:00:00Z","action":"a-1","step":"s","body":{"reason":"😀 \\ud800 \"\\\""}}`)
	if r, err := ParseReceipt(line); err != nil || r.Verify(key.Public().(ed25519.PublicKey)) != nil {
		t.Fatalf("%v", err)
	}
}
