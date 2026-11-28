package gateway

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
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

func pubOf(key ed25519.PrivateKey) ed25519.PublicKey { return key.Public().(ed25519.PublicKey) }

// keySet — ключи без сроков.
func keySet(t *testing.T, keys ...ed25519.PrivateKey) *KeySet {
	t.Helper()
	var ks []Key
	for _, k := range keys {
		ks = append(ks, Key{Pub: pubOf(k)})
	}
	s, err := NewKeySet(ks...)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func b64(b []byte) string { return base64.RawURLEncoding.EncodeToString(b) }

// signWith подписывает готовые байты B так, как это делает шлюз на другом
// языке: объект без jws, обычный JWS с телом B и защищённым заголовком
// header (JSON), заголовок и подпись дописаны перед последней скобкой.
func signWith(key ed25519.PrivateKey, header, b string) []byte {
	p := b64([]byte(header))
	sig := ed25519.Sign(key, []byte(p+"."+b64([]byte(b))))
	return []byte(b[:len(b)-1] + `,"jws":"` + p + ".." + b64(sig) + `"}`)
}

func headerOf(key ed25519.PrivateKey, alg string) string {
	return `{"alg":"` + alg + `","kid":"` + KeyID(pubOf(key)) + `","typ":"` + ReceiptType + `"}`
}

// signRaw — signWith с заголовком, какой пишет Signer.
func signRaw(key ed25519.PrivateKey, b string) []byte {
	return signWith(key, headerOf(key, AlgEd25519), b)
}

// unsigned — B подписанной строки и её хвост P..S.
func unsigned(t *testing.T, line []byte) (b, tail string) {
	t.Helper()
	raw, p, sig, ok := splitJWS(line)
	if !ok {
		t.Fatalf("the line does not end with its signature: %s", line)
	}
	return string(raw), p + ".." + b64(sig)
}

// noTime — время приёма неизвестно: срок ключа не сверяется.
var noTime time.Time

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
	// Хвост подписи — ровно в конце строки, и в нём заголовок, пустое тело и
	// подпись: отсоединённый JWS.
	b, tail := unsigned(t, line)
	if string(line) != b[:len(b)-1]+`,"jws":"`+tail+`"}` || strings.Count(tail, ".") != 2 {
		t.Fatalf("the signature is not the last field: %s", line)
	}
	if r.Alg != AlgEd25519 || r.Kid != KeyID(pubOf(key)) {
		t.Fatalf("alg %q, kid %q", r.Alg, r.Kid)
	}
	// Та же квитанция обычным компактным JWS: тело — B, подпись — над
	// «заголовок.тело», как в RFC 7515.
	jws, ok := r.Compact()
	parts := strings.Split(jws, ".")
	if !ok || len(parts) != 3 {
		t.Fatalf("compact: %q", jws)
	}
	if payload, err := base64.RawURLEncoding.DecodeString(parts[1]); err != nil || string(payload) != b {
		t.Fatalf("the payload of the compact JWS is not the line without its jws field: %q", payload)
	}
	if hdr, _ := base64.RawURLEncoding.DecodeString(parts[0]); string(hdr) != headerOf(key, AlgEd25519) {
		t.Fatalf("protected header %s", hdr)
	}
	sig, _ := base64.RawURLEncoding.DecodeString(parts[2])
	if !ed25519.Verify(pubOf(key), []byte(parts[0]+"."+parts[1]), sig) {
		t.Fatal("the compact JWS does not verify as RFC 7515 says")
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
	b := `{"step": "cart", "action": "p-😀", "time": "2026-11-23T12:00:00Z", "prev": "genesis", "seq": 1, "gateway": "py", "v": 2, "body": {"total": 10, "jws": "a..b"}}`
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
	// Поле jws внутри body, записанное без пробелов, — те же байты, с каких
	// начинается хвост подписи. Хвост — последний: его начало ищут с конца.
	inner := `{"v":2,"gateway":"py","seq":2,"prev":"` + r.Hash + `","time":"2026-11-23T12:00:00Z","action":"a","step":"s","body":{"n":1,"jws":"QQ..QQ"}}`
	if r, err := ParseReceipt(signRaw(key, inner)); err != nil || r.Verify(pubOf(key)) != nil || string(r.Body) != `{"n":1,"jws":"QQ..QQ"}` {
		t.Fatalf("a receipt whose body holds a jws field of its own: %v", err)
	}
	// Библиотека постарше называет тот же алгоритм EdDSA (RFC 8037), и ключи
	// заголовка пишет в своём порядке и с пробелами: подписан заголовок, как
	// он есть.
	old := `{"typ": "` + ReceiptType + `", "kid": "` + KeyID(pubOf(key)) + `", "alg": "EdDSA"}`
	if r, err := ParseReceipt(signWith(key, old, b)); err != nil || r.Alg != AlgEdDSA || r.Verify(pubOf(key)) != nil {
		t.Fatalf("a receipt with alg EdDSA: %v, %+v", err, r)
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
	ok := `{"v":2,"gateway":"g","seq":1,"prev":"genesis","time":"2026-11-23T12:00:00Z","action":"a-1","step":"s"`
	cases := map[string]string{
		"v 1":                  strings.Replace(ok, `"v":2`, `"v":1`, 1),
		"v 3":                  strings.Replace(ok, `"v":2`, `"v":3`, 1),
		"v as a string":        strings.Replace(ok, `"v":2`, `"v":"2"`, 1),
		"v 2.0":                strings.Replace(ok, `"v":2`, `"v":2.0`, 1),
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
		"the field of v1":      ok + `,"sig":"` + strings.Repeat("ab", 64) + `"`,
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
			v := NewReceiptTracker(keySet(t, key)).Check(line, noTime)
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
	b := `{"v":2,"gateway":"g","seq":1,"prev":"genesis","time":"2026-11-23T12:00:00Z","action":"a-1","step":"s"}`
	line := signRaw(key, b)
	_, tail := unsigned(t, line)
	p, sig, _ := strings.Cut(tail, "..")
	// Последний знак подписи несёт два значащих бита и четыре лишних: с
	// ненулевыми лишними те же 64 байта записаны другой строкой.
	loose := sig[:len(sig)-1] + string("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"[strings.IndexByte("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_", sig[len(sig)-1])+1])
	if a, _ := base64.RawURLEncoding.DecodeString(sig); true {
		if c, err := base64.RawURLEncoding.DecodeString(loose); err != nil || !bytes.Equal(a, c) {
			t.Fatalf("the test's second spelling of the signature is not the same bytes: %v", err)
		}
	}
	cases := map[string]string{
		"no signature":              b,
		"signature first":           `{"jws":"` + tail + `",` + b[1:],
		"space before the tail":     b[:len(b)-1] + ` ,"jws":"` + tail + `"}`,
		"signature inside body":     b[:len(b)-1] + `,"body":{"jws":"` + tail + `"}}`,
		"signature twice":           string(line[:len(line)-1]) + `,"jws":"` + tail + `"}`,
		"short signature":           b[:len(b)-1] + `,"jws":"` + p + ".." + sig[:len(sig)-4] + `"}`,
		"data after the signature":  string(line) + ` {}`,
		"an attached payload":       b[:len(b)-1] + `,"jws":"` + p + "." + b64([]byte(b)) + "." + sig + `"}`,
		"one dot":                   b[:len(b)-1] + `,"jws":"` + p + "." + sig + `"}`,
		"no header":                 b[:len(b)-1] + `,"jws":"..` + sig + `"}`,
		"padded base64":             b[:len(b)-1] + `,"jws":"` + p + ".." + sig + `=="}`,
		"standard base64 alphabet":  b[:len(b)-1] + `,"jws":"` + p + ".." + strings.NewReplacer("-", "+", "_", "/").Replace(sig) + `"}`,
		"a second spelling of bits": b[:len(b)-1] + `,"jws":"` + p + ".." + loose + `"}`,
		"the signature of v1":       b[:len(b)-1] + `,"sig":"` + hex.EncodeToString(ed25519.Sign(key, append([]byte("evidencestore/receipt/v1\n"), b...))) + `"}`,
		"an empty tail":             b[:len(b)-1] + `,"jws":"}`,
	}
	if sig == strings.NewReplacer("-", "+", "_", "/").Replace(sig) {
		delete(cases, "standard base64 alphabet") // в этой подписи нет знаков, которыми алфавиты различаются
	}
	for name, l := range cases {
		t.Run(name, func(t *testing.T) {
			r, err := ParseReceipt([]byte(l))
			if err == nil && r.Verify(pub) == nil {
				t.Fatalf("a receipt with its signature out of place passes: %s", l)
			}
			if v := NewReceiptTracker(keySet(t, key)).Check([]byte(l), noTime); v.Clean() || v.Signature == SigValid {
				t.Fatalf("the verdict is clean: %+v", v)
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
}

// Заголовок подписи — ровно alg, kid и typ. Подпись под каждым из этих
// заголовков настоящая, ключом шлюза: отвергает их разбор заголовка, а не
// арифметика.
func TestReceiptProtectedHeader(t *testing.T) {
	key, other := receiptKey(t, 4), receiptKey(t, 5)
	pub := pubOf(key)
	kid := KeyID(pub)
	b := `{"v":2,"gateway":"g","seq":1,"prev":"genesis","time":"2026-11-23T12:00:00Z","action":"a-1","step":"s"}`
	if r, err := ParseReceipt(signWith(key, headerOf(key, AlgEd25519), b)); err != nil || r.Verify(pub) != nil {
		t.Fatalf("the control receipt: %v", err)
	}
	h := func(members string) string { return `{` + members + `}` }
	std := `"alg":"Ed25519","kid":"` + kid + `","typ":"` + ReceiptType + `"`
	cases := map[string]string{
		// Подпись тем же ключом под другим типом — не подпись квитанции: так
		// typ отделяет квитанцию от всего остального, что шлюз подписывает.
		"another typ":         h(`"alg":"Ed25519","kid":"` + kid + `","typ":"JWT"`),
		"no typ":              h(`"alg":"Ed25519","kid":"` + kid + `"`),
		"typ in another case": h(`"alg":"Ed25519","kid":"` + kid + `","typ":"` + strings.ToUpper(ReceiptType) + `"`),
		"no kid":              h(`"alg":"Ed25519","typ":"` + ReceiptType + `"`),
		"kid a number":        h(`"alg":"Ed25519","kid":7,"typ":"` + ReceiptType + `"`),
		"kid with a quote":    h(`"alg":"Ed25519","kid":"a\"b","typ":"` + ReceiptType + `"`),
		"kid too long":        h(`"alg":"Ed25519","kid":"` + strings.Repeat("k", MaxKeyID+1) + `","typ":"` + ReceiptType + `"`),
		"no alg":              h(`"kid":"` + kid + `","typ":"` + ReceiptType + `"`),
		"alg none":            h(`"alg":"none","kid":"` + kid + `","typ":"` + ReceiptType + `"`),
		"alg of another key":  h(`"alg":"ES256","kid":"` + kid + `","typ":"` + ReceiptType + `"`),
		"alg in another case": h(`"alg":"ed25519","kid":"` + kid + `","typ":"` + ReceiptType + `"`),
		// Ключ в самой подписи: проверяющий, который возьмёт его оттуда,
		// проверит подпись ключом подписавшего.
		"a key in the header":    h(std + `,"jwk":{"kty":"OKP","crv":"Ed25519","x":"` + b64(pubOf(other)) + `"}`),
		"a key address":          h(std + `,"jku":"https://example.org/keys"`),
		"crit":                   h(std + `,"crit":["b64"],"b64":false`),
		"a member twice":         h(std + `,"alg":"Ed25519"`),
		"a member twice, folded": h(std + `,"ALG":"none"`),
		"not an object":          `["Ed25519"]`,
		"not JSON":               `alg=Ed25519`,
		"data after":             h(std) + ` {}`,
	}
	for name, header := range cases {
		t.Run(name, func(t *testing.T) {
			line := signWith(key, header, b)
			r, err := ParseReceipt(line)
			if err == nil {
				t.Fatalf("accepted: %s", header)
			}
			if r.Sig != nil || r.Verify(pub) == nil {
				t.Fatalf("a receipt with this header keeps a usable signature: %s", header)
			}
			if v := NewReceiptTracker(keySet(t, key)).Check(line, noTime); v.Clean() || v.Signature != SigInvalid || v.Problem == "" {
				t.Fatalf("verdict %+v", v)
			}
		})
	}
	// Имя ключа — часть подписанного: подпись ключом key под именем другого
	// ключа не сходится ни с тем, ни с другим.
	line := signWith(key, headerOf(other, AlgEd25519), b)
	r, err := ParseReceipt(line)
	if err != nil {
		t.Fatal(err)
	}
	if r.Verify(pub) == nil || r.Verify(pubOf(other)) == nil {
		t.Fatal("a receipt that names another key verifies")
	}
	if v := NewReceiptTracker(keySet(t, key, other)).Check(line, noTime); v.Signature != SigInvalid || v.Kid != KeyID(pubOf(other)) {
		t.Fatalf("verdict %+v", v)
	}
}

// RFC 8037, приложение A: открытый ключ Ed25519, его отпечаток JWK (A.3) и
// подпись JWS (A.4). Имя ключа и то, что подписывается, — как в стандарте, а
// не «похоже на него».
func TestReceiptKeyIDAndSigningInputAreTheStandards(t *testing.T) {
	pub, err := base64.RawURLEncoding.DecodeString("11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo")
	if err != nil {
		t.Fatal(err)
	}
	if id := KeyID(pub); id != "kPrK_qmxVWaYVA9wwBF6Iuo3vVzz7TxHCTwXBygrS4k" {
		t.Fatalf("key id %s is not the JWK thumbprint of RFC 8037, A.3", id)
	}
	var jwk struct{ Kty, Crv, X, Kid string }
	if err := json.Unmarshal(JWK(pub), &jwk); err != nil || jwk.Kty != "OKP" || jwk.Crv != "Ed25519" || jwk.X != b64(pub) || jwk.Kid != KeyID(pub) {
		t.Fatalf("JWK %s: %v", JWK(pub), err)
	}
	in := signingInput("eyJhbGciOiJFZERTQSJ9", []byte("Example of Ed25519 signing"))
	if string(in) != "eyJhbGciOiJFZERTQSJ9.RXhhbXBsZSBvZiBFZDI1NTE5IHNpZ25pbmc" {
		t.Fatalf("signing input %s", in)
	}
	sig, _ := base64.RawURLEncoding.DecodeString("hgyY0il_MGCjP0JzlnLWG1PPOt7-09PGcvMg3AIbQR6dWbhijcNR4ki4iylGjg5BhVsPt9g7sVvpAr_MuM0KAg")
	if !ed25519.Verify(pub, in, sig) {
		t.Fatal("the JWS of RFC 8037, A.4 does not verify over this signing input")
	}
}

// Ключей у источника несколько, у каждого срок, и сверяется он со временем
// приёма: шлюз сменил ключ — цепочка идёт дальше; квитанция, принятая после
// not_after её ключа, за шлюз не говорит и в его цепочку не входит.
func TestReceiptKeysAndTheirPeriods(t *testing.T) {
	first, second, stranger := receiptKey(t, 20), receiptKey(t, 21), receiptKey(t, 22)
	change := time.Date(2026, 12, 1, 0, 0, 0, 0, time.UTC)
	keys, err := NewKeySet(Key{Pub: pubOf(first), NotAfter: change}, Key{Pub: pubOf(second), NotBefore: change.Add(-time.Hour)})
	if err != nil {
		t.Fatal(err)
	}
	s1, _ := NewSigner(first, "gw", nil)
	one := mustSign(t, s1, Draft{Time: at, Action: "a", Step: "s1"})
	two := mustSign(t, s1, Draft{Time: at, Action: "a", Step: "s2"})
	// Шлюз сменил ключ и продолжает ту же цепочку.
	s2, _ := NewSigner(second, "gw", nil)
	last, _ := ParseReceipt(two)
	if err := s2.After(last.Seq, last.Hash); err != nil {
		t.Fatal(err)
	}
	if s2.After(0, last.Hash) == nil || s2.After(last.Seq, "abcd") == nil || s2.After(MaxSeq, last.Hash) == nil {
		t.Fatal("a chain goes on from a receipt that cannot be")
	}
	three := mustSign(t, s2, Draft{Time: at, Action: "a", Step: "s3"})

	tr := NewReceiptTracker(keys)
	before := change.Add(-30 * time.Minute)
	for i, l := range [][]byte{one, two} {
		v := tr.Check(l, before)
		if !v.Clean() || v.Signature != SigValid || v.Kid != KeyID(pubOf(first)) {
			t.Fatalf("receipt %d under the first key: %+v", i+1, v)
		}
	}
	if v := tr.Check(three, before); !v.Clean() || v.Link != LinkOK || v.Kid != KeyID(pubOf(second)) {
		t.Fatalf("the first receipt under the second key: %+v", v)
	}

	// Держатель прежнего ключа пишет после его срока: с верной подписью и
	// верной сцепкой, но за шлюз строка не говорит.
	thief, _ := NewSigner(first, "gw", nil)
	l3, _ := ParseReceipt(three)
	thief.After(l3.Seq, l3.Hash)
	late := mustSign(t, thief, Draft{Time: at /* часы шлюза — прежние */, Action: "a", Step: "cancel"})
	v := tr.Check(late, change)
	if v.Signature != SigInvalid || v.Clean() || !strings.Contains(v.Problem, "no longer speaks") || !strings.Contains(v.Problem, KeyID(pubOf(first))) {
		t.Fatalf("a receipt received at not_after of its key: %+v", v)
	}
	// В цепочку она не вошла: следующая настоящая сцеплена с третьей.
	if v := tr.Check(mustSign(t, s2, Draft{Time: at, Action: "a", Step: "s4"}), change); !v.Clean() || v.Link != LinkOK {
		t.Fatalf("the gateway's receipt after one under an expired key: %+v", v)
	}
	// За миг до not_after прежний ключ ещё говорит, второй до своего not_before — ещё нет.
	if err := keys.Verify(mustParse(t, one), change.Add(-time.Nanosecond)); err != nil {
		t.Fatal(err)
	}
	if err := keys.Verify(mustParse(t, three), change.Add(-2*time.Hour)); err == nil || !strings.Contains(err.Error(), "before gateway key") {
		t.Fatalf("a receipt received before not_before of its key: %v", err)
	}
	// Без времени приёма срок не сверяется: подпись и имя ключа — да.
	if err := keys.Verify(mustParse(t, late), noTime); err != nil {
		t.Fatal(err)
	}
	// Ключ не из списка: подпись настоящая, но источнику этот ключ не знаком.
	s3, _ := NewSigner(stranger, "gw", nil)
	if v := NewReceiptTracker(keys).Check(mustSign(t, s3, Draft{Time: at, Action: "a", Step: "s"}), before); v.Signature != SigInvalid || !strings.Contains(v.Problem, "not among the gateway keys") {
		t.Fatalf("a receipt under an unlisted key: %+v", v)
	}
	// Вердикт подделки с именем настоящего ключа называет арифметику, не срок.
	forged := signWith(stranger, headerOf(first, AlgEd25519), `{"v":2,"gateway":"gw","seq":1,"prev":"genesis","time":"2026-11-23T12:00:00Z","action":"a","step":"s"}`)
	if v := NewReceiptTracker(keys).Check(forged, change.Add(time.Hour)); v.Signature != SigInvalid || !strings.Contains(v.Problem, "does not verify") {
		t.Fatalf("a forgery under the name of a listed key: %+v", v)
	}
}

func mustParse(t *testing.T, line []byte) Receipt {
	t.Helper()
	r, err := ParseReceipt(line)
	if err != nil {
		t.Fatal(err)
	}
	return r
}

// Ключи в настройках: строка или объект со сроками, без лишних полей.
func TestKeyEntries(t *testing.T) {
	a, b := hex.EncodeToString(pubOf(receiptKey(t, 30))), hex.EncodeToString(pubOf(receiptKey(t, 31)))
	var entries []KeyEntry
	if err := json.Unmarshal([]byte(`["`+a+`", {"key": "`+b+`", "not_before": "2026-12-01T00:00:00+05:00", "not_after": "2027-12-01T00:00:00Z"}]`), &entries); err != nil {
		t.Fatal(err)
	}
	set, err := ParseKeySet(entries)
	if err != nil || set.Len() != 2 {
		t.Fatalf("%v, %d keys", err, set.Len())
	}
	if k, ok := set.Lookup(KeyID(pubOf(receiptKey(t, 31)))); !ok || !k.NotBefore.Equal(time.Date(2026, 11, 30, 19, 0, 0, 0, time.UTC)) || k.NotAfter.IsZero() {
		t.Fatalf("the second key: %+v, %v", k, ok)
	}
	if k := set.Keys(); len(k) != 2 || !bytes.Equal(k[0].Pub, pubOf(receiptKey(t, 30))) || !k[0].NotAfter.IsZero() {
		t.Fatalf("keys in the order of the settings: %+v", k)
	}
	for name, raw := range map[string]string{
		"a misspelt period":   `[{"key": "` + a + `", "not_afer": "2026-12-01T00:00:00Z"}]`,
		"a period not a time": `[{"key": "` + a + `", "not_after": "tomorrow"}]`,
		"a date without time": `[{"key": "` + a + `", "not_before": "2026-12-01"}]`,
		"a period backwards":  `[{"key": "` + a + `", "not_before": "2026-12-02T00:00:00Z", "not_after": "2026-12-01T00:00:00Z"}]`,
		"an empty period":     `[{"key": "` + a + `", "not_before": "2026-12-01T00:00:00Z", "not_after": "2026-12-01T00:00:00Z"}]`,
		"a key twice":         `["` + a + `", {"key": "` + strings.ToUpper(a) + `"}]`,
		"a short key":         `["` + a[:62] + `"]`,
		"a key a number":      `[7]`,
		"no key":              `[{"not_after": "2026-12-01T00:00:00Z"}]`,
	} {
		var e []KeyEntry
		if err := json.Unmarshal([]byte(raw), &e); err == nil {
			if _, err = ParseKeySet(e); err == nil {
				t.Errorf("%s: accepted %s", name, raw)
			}
		}
	}
	// Как ключи даёт проверяющий: один ключ в hex или массив настроек.
	if e, err := ParseKeyList([]byte(" " + strings.ToUpper(a) + "\n")); err != nil || len(e) != 1 || e[0].Key != a {
		t.Fatalf("a key in hex: %+v, %v", e, err)
	}
	if e, err := ParseKeyList([]byte(`[{"key":"` + a + `","not_after":"2026-12-01T00:00:00Z"},"` + b + `"]`)); err != nil || len(e) != 2 || e[0].NotAfter == "" {
		t.Fatalf("keys as an array: %+v, %v", e, err)
	}
	for _, raw := range []string{``, `[]`, `["` + a + `"] x`, `{"key":"` + a + `"}`, a + a} {
		if _, err := ParseKeyList([]byte(raw)); err == nil {
			t.Errorf("ParseKeyList accepted %q", raw)
		}
	}
	// Пустой набор — «ключей нет», и nil — тоже.
	var none *KeySet
	if none.Len() != 0 || len(none.Keys()) != 0 {
		t.Fatal("a nil key set is not empty")
	}
	if _, ok := none.Lookup("x"); ok {
		t.Fatal("a nil key set knows a key")
	}
}

func TestReceiptTrackerLinks(t *testing.T) {
	key := receiptKey(t, 6)
	s, _ := NewSigner(key, "gw", nil)
	var lines [][]byte
	for i := range 6 {
		lines = append(lines, mustSign(t, s, Draft{Time: at.Add(time.Duration(i) * time.Second), Action: "act-" + string(rune('a'+i%2)), Step: "intent"}))
	}
	tr := NewReceiptTracker(keySet(t, key))
	want := []string{LinkGenesis, LinkOK, LinkOK}
	for i, l := range lines[:3] {
		v := tr.Check(l, noTime)
		if v.Link != want[i] || !v.Clean() || v.Signature != SigValid || v.Seq != uint64(i+1) || v.Writer != "gw" {
			t.Fatalf("receipt %d: %+v", i+1, v)
		}
	}
	// Квитанция 4 выпала: пятая — поломка, шестая — снова цела.
	if v := tr.Check(lines[4], noTime); v.Link != LinkBroken || v.Clean() || !strings.Contains(v.Problem, "seq 3") {
		t.Fatalf("after a lost receipt: %+v", v)
	}
	if v := tr.Check(lines[5], noTime); v.Link != LinkOK || !v.Clean() {
		t.Fatalf("after the break: %+v", v)
	}
	// Повтор уже принятой — поломка, но цепочку он не двигает (R1-2): копию
	// своей прежней строки дописать может любой, кто пишет в файл, без ключа,
	// и раньше следующая настоящая квитанция выходила поломанной.
	for i, want := range map[int]string{5: "a copy of the gateway's last receipt (seq 6)", 2: "seq 3 after seq 6", 0: "a copy of the start of the gateway's chain"} {
		if v := tr.Check(lines[i], noTime); v.Link != LinkStale || v.Clean() || v.Signature != SigValid || !strings.Contains(v.Problem, want) {
			t.Fatalf("a replayed receipt %d: %+v", i+1, v)
		}
	}
	seven := mustSign(t, s, Draft{Time: at.Add(7 * time.Second), Action: "act-c", Step: "intent"})
	if v := tr.Check(seven, noTime); v.Link != LinkOK || !v.Clean() {
		t.Fatalf("the next real receipt after the replays: %+v", v)
	}
	// prev верный, а seq перескочил: шлюз нумерует не по порядку — поломка.
	last, _ := ParseReceipt(seven)
	jump := signRaw(key, `{"v":2,"gateway":"gw","seq":`+strconv.FormatUint(last.Seq+2, 10)+`,"prev":"`+last.Hash+`","time":"2026-11-23T12:00:00Z","action":"a","step":"s"}`)
	if v := tr.Check(jump, noTime); v.Link != LinkBroken || v.Signature != SigValid || !strings.Contains(v.Problem, "follows seq") {
		t.Fatalf("a seq that jumps: %+v", v)
	}

	// Новая цепочка после принятых — поломка: квитанции между ними могли пропасть.
	s2, _ := NewSigner(key, "gw", nil)
	if v := tr.Check(mustSign(t, s2, Draft{Time: at, Action: "a", Step: "s"}), noTime); v.Link != LinkBroken || !strings.Contains(v.Problem, "new chain") {
		t.Fatalf("a restarted chain: %+v", v)
	}

	// Цепочку начали без нас — цела, но «first-seen».
	tr2 := NewReceiptTracker(keySet(t, key))
	if v := tr2.Check(lines[2], noTime); v.Link != LinkFirstSeen || !v.Clean() {
		t.Fatalf("first seen: %+v", v)
	}
	// Цепочки разных шлюзов не мешают друг другу.
	other, _ := NewSigner(key, "gw-2", nil)
	if v := tr2.Check(mustSign(t, other, Draft{Time: at, Action: "a", Step: "s"}), noTime); v.Link != LinkGenesis || !v.Clean() {
		t.Fatalf("a second gateway: %+v", v)
	}
	if v := tr2.Check(lines[3], noTime); v.Link != LinkOK {
		t.Fatalf("the first gateway after the second: %+v", v)
	}

	// Чужая подпись — поломка подписи, а цепочка шлюза её не берёт: следующая
	// настоящая квитанция цела.
	forger, _ := NewSigner(receiptKey(t, 7), "gw", nil)
	tr3 := NewReceiptTracker(keySet(t, key))
	if v := tr3.Check(mustSign(t, forger, Draft{Time: at, Action: "a", Step: "s"}), noTime); v.Signature != SigInvalid || v.Clean() || v.Link != LinkGenesis {
		t.Fatalf("a forged receipt: %+v", v)
	}
	if v := tr3.Check(lines[0], noTime); v.Link != LinkGenesis || !v.Clean() {
		t.Fatalf("the gateway's first receipt after a forged one: %+v", v)
	}
	// Подделка посреди цепочки, с верным prev: следующая настоящая — цела.
	second, _ := unsigned(t, lines[1])
	forged := signRaw(receiptKey(t, 7), strings.Replace(second, `"step":"intent"`, `"step":"cancel"`, 1))
	if v := tr3.Check(forged, noTime); v.Signature != SigInvalid || v.Link != LinkOK {
		t.Fatalf("a forged receipt in the middle: %+v", v)
	}
	if v := tr3.Check(lines[1], noTime); v.Link != LinkOK || !v.Clean() {
		t.Fatalf("the gateway's receipt after a forged one: %+v", v)
	}
	// Без ключа подписи не проверяются, сцепка — да.
	if v := NewReceiptTracker(nil).Check(lines[0], noTime); v.Signature != SigNoKey || !v.Clean() {
		t.Fatalf("no key: %+v", v)
	}
}

func TestReceiptTrackerResume(t *testing.T) {
	key := receiptKey(t, 8)
	s, _ := NewSigner(key, "gw", nil)
	a := NewReceiptTracker(keySet(t, key))
	var verdicts []Verdict
	for i := range 3 {
		verdicts = append(verdicts, a.Check(mustSign(t, s, Draft{Time: at, Action: "x", Step: "s" + string(rune('0'+i))}), noTime))
	}
	// Хранилище перезапустилось: состояние — из вердиктов в цепи.
	b := NewReceiptTracker(keySet(t, key))
	for _, v := range verdicts {
		b.Resume(v)
	}
	next := mustSign(t, s, Draft{Time: at, Action: "x", Step: "s3"})
	va, vb := a.Check(next, noTime), b.Check(next, noTime)
	if va != vb || vb.Link != LinkOK {
		t.Fatalf("after resume %+v, without restart %+v", vb, va)
	}
	// Вердикт без шлюза состояние не трогает.
	b.Resume(Verdict{Problem: "receipt is not valid UTF-8", Hash: strings.Repeat("0", 64)})
	if v := b.Check(mustSign(t, s, Draft{Time: at, Action: "x", Step: "s4"}), noTime); v.Link != LinkOK {
		t.Fatalf("resume of a nameless verdict moved the chain: %+v", v)
	}
}

// Вердикт лежит в цепи открыто: номера действия, шага и тела в нём нет.
func TestReceiptVerdictKeepsTheActionClosed(t *testing.T) {
	key := receiptKey(t, 9)
	s, _ := NewSigner(key, "gw", nil)
	line := mustSign(t, s, Draft{Time: at, Action: "customer-4417-secret", Step: "cancel-step",
		Refs: []Ref{{Source: "pay", Subject: "ref-secret"}}, Body: json.RawMessage(`{"secret":"body-secret"}`)})
	v := NewReceiptTracker(keySet(t, key)).Check(line, noTime)
	raw, _ := json.Marshal(v)
	for _, secret := range []string{"customer-4417", "cancel-step", "ref-secret", "body-secret"} {
		if bytes.Contains(raw, []byte(secret)) {
			t.Errorf("the verdict shows %q: %s", secret, raw)
		}
	}
	// И в поломке — тоже: имя лишнего поля в тексте не называется.
	bad := signRaw(key, `{"v":2,"gateway":"gw","seq":1,"prev":"genesis","time":"2026-11-23T12:00:00Z","action":"a","step":"s","customer-4417-secret":1}`)
	v = NewReceiptTracker(keySet(t, key)).Check(bad, noTime)
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
	fits := json.RawMessage(`"` + strings.Repeat("x", MaxReceiptLen-600) + `"`)
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
	keys := keySet(t, key)
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
		v := NewReceiptTracker(keys).Check(m, noTime)
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
	line := signRaw(key, `{"v":2,"gateway":"g","seq":1,"prev":"genesis","time":"2026-11-23T12:00:00Z","action":"a-1","step":"s","body":{"reason":"😀 \\ud800 \"\\\""}}`)
	if r, err := ParseReceipt(line); err != nil || r.Verify(key.Public().(ed25519.PublicKey)) != nil {
		t.Fatalf("%v", err)
	}
}
