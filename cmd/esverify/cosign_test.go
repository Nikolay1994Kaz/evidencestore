package main

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/Nikolay1994Kaz/evidencestore/internal/config"
	"github.com/Nikolay1994Kaz/evidencestore/internal/cosign"
	"github.com/Nikolay1994Kaz/evidencestore/internal/proof"
	"github.com/Nikolay1994Kaz/evidencestore/internal/store"
	"github.com/Nikolay1994Kaz/evidencestore/internal/witness"
)

// cosignedWorld — хранилище со свидетелем C2SP (eswitness в процессе): пакет
// улики, подписанный свидетелем, ключ хранилища, корень демо-TSA и ключ
// проверки свидетеля в файлах.
func cosignedWorld(t *testing.T) (bundle, key, trust, vkey string) {
	t.Helper()
	dir := t.TempDir()
	_, priv, _ := ed25519.GenerateKey(rand.Reader)
	wkey, err := cosign.NewSigner("witness.example/w1", priv)
	if err != nil {
		t.Fatal(err)
	}
	// Ключ хранилища известен только после его открытия — свидетель
	// заводится тогда же, а до того отвечает 503.
	var srv atomic.Pointer[witness.Server]
	ts := httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, r *http.Request) {
		if w := srv.Load(); w != nil {
			w.Handler().ServeHTTP(rw, r)
			return
		}
		http.Error(rw, "not yet", http.StatusServiceUnavailable)
	}))
	t.Cleanup(ts.Close)
	cfg := &config.Config{
		DataDir: filepath.Join(dir, "data"), RootsDir: filepath.Join(dir, "roots"),
		TSA:     config.TSA{URL: "local"},
		Sources: []config.Source{{Name: "abs-core", ContentType: "syslog"}},
		Demo:    true,
		Witness: config.Witness{Cosigners: []config.Cosigner{{URL: ts.URL, Key: wkey.Verifier().String()}}},
	}
	cfg.Defaults()
	if _, err := store.Init(cfg); err != nil {
		t.Fatal(err)
	}
	quiet := slog.New(slog.NewTextHandler(io.Discard, nil))
	s, err := store.Open(cfg, store.Options{Logger: quiet, NoBackground: true})
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	pub, _ := base64.RawStdEncoding.DecodeString(s.PublicKey())
	w, err := witness.New(wkey, []witness.Log{{Origin: proof.OriginFor(pub), Key: pub}}, t.TempDir(), quiet)
	if err != nil {
		t.Fatal(err)
	}
	srv.Store(w)
	if _, err := s.Stamp(t.Context()); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Ingest("abs-core", []store.Incoming{{Seq: 1, Body: []byte("login admin")}}); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Stamp(t.Context()); err != nil {
		t.Fatal(err)
	}
	if err := s.CosignOnce(t.Context()); err != nil {
		t.Fatal(err)
	}
	b, err := s.Proof("abs-core", 1, false)
	if err != nil {
		t.Fatal(err)
	}
	// Подпись головы не раньше записи и подпись головы звена токена T2 (POE
	// для T2 при отзыве сертификата службы).
	if len(b.Cosignatures) != 2 || b.Upper == nil || b.Upper.Inclusion == nil || b.Cosignatures[1].Size != b.Upper.Inclusion.LinkSeq {
		t.Fatalf("в пакете %d подписей свидетеля", len(b.Cosignatures))
	}
	write := func(name string, data []byte) string {
		p := filepath.Join(dir, name)
		if err := os.WriteFile(p, data, 0o600); err != nil {
			t.Fatal(err)
		}
		return p
	}
	data, _ := json.Marshal(b)
	return write("proof.json", data), write("store.key", []byte(s.PublicKey())), write("tsa-root.crt", s.TSARoot()), wkey.Verifier().String()
}

// -witness-key: подпись свидетеля в пакете проверяется его ключом — из
// строки или файла; без подписи и с чужим ключом пакет не проходит; не ключ —
// неверный вызов; -json называет закрепившую голову.
func TestWitnessKeyFlag(t *testing.T) {
	bundle, key, trust, vkey := cosignedWorld(t)
	base := []string{"-proof", bundle, "-store-key", key, "-tsa-trust", trust}
	var out, errb bytes.Buffer
	if code := run(append(base, "-witness-key", vkey), &out, &errb); code != exitValid || !strings.Contains(out.String(), "witness witness.example/w1 cosigned head") {
		t.Fatalf("с ключом свидетеля: %d\n%s%s", code, out.String(), errb.String())
	}
	vfile := filepath.Join(t.TempDir(), "witness.vkey")
	os.WriteFile(vfile, []byte(vkey+"\n"), 0o600)
	out.Reset()
	if code := run(append(base, "-witness-key", vfile, "-json"), &out, &errb); code != exitValid {
		t.Fatalf("ключ из файла: %d\n%s", code, out.String())
	}
	var j struct {
		Cosigned []proof.CosignedHead `json:"cosigned"`
	}
	if err := json.Unmarshal(out.Bytes(), &j); err != nil || len(j.Cosigned) != 1 || j.Cosigned[0].Witness != "witness.example/w1" {
		t.Fatalf("-json: %v %s", err, out.String())
	}

	// Без ключа — подписи не сверяются, пакет проходит и говорит об этом.
	out.Reset()
	if code := run(base, &out, &errb); code != exitValid || !strings.Contains(out.String(), "not checked: pass each witness's key with -witness-key") {
		t.Fatalf("без ключа: %d\n%s", code, out.String())
	}

	// Подпись вынута из пакета — с ключом свидетеля провал.
	data, _ := os.ReadFile(bundle)
	var b map[string]any
	json.Unmarshal(data, &b)
	delete(b, "cosignatures")
	stripped, _ := json.Marshal(b)
	sfile := filepath.Join(t.TempDir(), "stripped.json")
	os.WriteFile(sfile, stripped, 0o600)
	out.Reset()
	if code := run([]string{"-proof", sfile, "-store-key", key, "-tsa-trust", trust, "-witness-key", vkey}, &out, &errb); code != exitInvalid {
		t.Fatalf("пакет без подписи: %d\n%s", code, out.String())
	}

	// Ключ другого свидетеля того же имени — его подписи нет.
	_, priv, _ := ed25519.GenerateKey(rand.Reader)
	twin, _ := cosign.NewSigner("witness.example/w1", priv)
	out.Reset()
	if code := run(append(base, "-witness-key", twin.Verifier().String()), &out, &errb); code != exitInvalid {
		t.Fatalf("ключ тёзки: %d\n%s", code, out.String())
	}

	errb.Reset()
	if code := run(append(base, "-witness-key", "witness.example/w1"), &out, &errb); code != exitUsage || !strings.Contains(errb.String(), "-witness-key") {
		t.Fatalf("не ключ: %d %s", code, errb.String())
	}

	// Ключ хранилища под видом свидетеля — неверный вызов: его подписи держит
	// администратор хранилища.
	raw, _ := os.ReadFile(key)
	pub, _ := base64.RawStdEncoding.DecodeString(strings.TrimSpace(string(raw)))
	self := cosign.Verifier{Name: "witness.example/self", ID: cosign.KeyID("witness.example/self", cosign.TypeCosignatureV1, pub), Key: pub}
	errb.Reset()
	if code := run(append(base, "-witness-key", self.String()), &out, &errb); code != exitUsage || !strings.Contains(errb.String(), "the store's own key") {
		t.Fatalf("ключ хранилища как ключ свидетеля: %d %s", code, errb.String())
	}
}

// Ключ в -witness-key разбирается как ключ раньше, чем как путь: файл по пути,
// равному настоящему ключу (подложенный в каталог аудитора вместе с пакетом),
// не подменяет ключ. Один ключ под двумя именами — неверный вызов.
func TestWitnessKeyNotShadowedByFile(t *testing.T) {
	bundle, key, trust, vkey := cosignedWorld(t)
	// Ключ, что кончается на «/», файлом по такому пути не подложить: путь
	// называл бы каталог, и подложенного файла esverify не видит. Так кончается
	// один ключ из 64, и тест падал раз в 64 прогона (P-230): берётся другой.
	for strings.HasSuffix(vkey, "/") {
		bundle, key, trust, vkey = cosignedWorld(t)
	}
	_, priv, _ := ed25519.GenerateKey(rand.Reader)
	evil, _ := cosign.NewSigner("witness.example/w1", priv)
	dir := t.TempDir()
	t.Chdir(dir)
	planted := filepath.Join(dir, filepath.FromSlash(vkey))
	if err := os.MkdirAll(filepath.Dir(planted), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(planted, []byte(evil.Verifier().String()+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	var out, errb bytes.Buffer
	// Строка — и ключ, и путь к файлу: какой имел в виду аудитор, не угадать,
	// и подложенный ключ не берётся молча — неверный вызов.
	if code := run([]string{"-proof", bundle, "-store-key", key, "-tsa-trust", trust, "-witness-key", vkey}, &out, &errb); code != exitUsage || !strings.Contains(errb.String(), "both a key and the name of a file") {
		t.Fatalf("ключ при подложенном файле: %d\n%s%s", code, out.String(), errb.String())
	}
	os.RemoveAll(filepath.Join(dir, strings.SplitN(filepath.FromSlash(vkey), string(filepath.Separator), 2)[0]))
	errb.Reset()
	if code := run([]string{"-proof", bundle, "-store-key", key, "-tsa-trust", trust, "-witness-key", vkey}, &out, &errb); code != exitValid {
		t.Fatalf("ключ без подложенного файла: %d\n%s%s", code, out.String(), errb.String())
	}
	// Ключ хранилища в файле, чьё имя — 43 знака base64: имя разбирается и
	// как ключ — неверный вызов, а с «./» — файл.
	pub, _ := os.ReadFile(key)
	keyName := strings.Repeat("A", 43)
	os.WriteFile(filepath.Join(dir, keyName), pub, 0o600)
	errb.Reset()
	if code := run([]string{"-proof", bundle, "-store-key", keyName, "-tsa-trust", trust, "-witness-key", vkey}, &out, &errb); code != exitUsage || !strings.Contains(errb.String(), "both a key and the name of a file") {
		t.Fatalf("-store-key — имя файла в виде ключа: %d %s", code, errb.String())
	}
	if code := run([]string{"-proof", bundle, "-store-key", "./" + keyName, "-tsa-trust", trust, "-witness-key", vkey}, &out, &errb); code != exitValid {
		t.Fatalf("-store-key ./файл: %d %s", code, errb.String())
	}
	v, _ := cosign.ParseVerifier(vkey)
	twin := strings.Replace(vkey, "witness.example/w1+", "witness.example/w2+", 1)
	twin = strings.Replace(twin, fmt.Sprintf("+%08x+", v.ID), fmt.Sprintf("+%08x+", cosign.KeyID("witness.example/w2", cosign.TypeCosignatureV1, v.Key)), 1)
	errb.Reset()
	if code := run([]string{"-proof", bundle, "-store-key", key, "-tsa-trust", trust, "-witness-key", vkey, "-witness-key", twin}, &out, &errb); code != exitUsage || !strings.Contains(errb.String(), "it is one witness") {
		t.Fatalf("один ключ под двумя именами: %d %s", code, errb.String())
	}
}
