package proof

import (
	"bufio"
	"os"
	"path/filepath"
	"testing"
	"time"

	"evidencestore/internal/auditchain"
	"evidencestore/internal/evidence"
	"evidencestore/internal/gateway"
	"evidencestore/internal/keyring"
)

// gatewayWorld — синтетическая цепь с уликой из журнала гейтвея: тело —
// настоящая строка журнала Pipelock, запечатанная настоящим кейрингом, рядом
// лист вердикта v. Отдаёт пакет с ключом записи.
func gatewayWorld(t *testing.T, edit func(*gateway.Verdict)) (*world, Bundle) {
	t.Helper()
	f, err := os.Open(filepath.Join("..", "gateway", "testdata", "pipelock-v3.6.0", "session1",
		"evidence-proxy.run.699f05e62af002bf3614fd97248a719a-0.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	sc.Buffer(nil, 1<<20)
	if !sc.Scan() {
		t.Fatal("пустой шард")
	}
	line := append([]byte(nil), sc.Bytes()...)

	k, err := keyring.Create(t.TempDir(), keyring.FileRoots{Dir: t.TempDir()}, keyring.Options{})
	if err != nil {
		t.Fatal(err)
	}
	defer k.Close()
	if _, err := k.EnsureScope("agent-gw/2026-10"); err != nil {
		t.Fatal(err)
	}
	env, err := k.Seal("agent-gw/2026-10", line)
	if err != nil {
		t.Fatal(err)
	}
	dek, err := k.UnwrapDEK(env)
	if err != nil {
		t.Fatal(err)
	}

	w := newWorld(t)
	w.link(auditchain.Leaf{Type: auditchain.EventStart})
	h1, t1 := w.stamp()
	w.now = w.now.Add(time.Second)
	w.link(tokenLeaf(h1, t1))
	h := evidence.Header{Source: "agent-gw", Seq: 1, ReceivedAt: w.now.Add(time.Second).UnixNano(), ContentType: gateway.ContentType}
	data, err := evidence.Sealed{Header: h, Envelope: env}.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	v := gateway.NewTracker(nil).Check(line)
	if !v.Clean() {
		t.Fatalf("вердикт по настоящей строке: %+v", v)
	}
	edit(&v)
	w.now = w.now.Add(3 * time.Second)
	w.link(EvidenceLeaf(h, 1, evidence.Digest(data)), GatewayLeaf(h, 1, v))
	h3, t2 := w.stamp()
	w.link(tokenLeaf(h3, t2))
	b := w.bundle(data, 3, 0, h3, t2, 2)
	b.DEK = dek
	b.Gateway = &GatewayProof{Entry: w.inclusion(3, 1)}
	return w, b
}

// Тело сверяется с хэшем в вердикте: вердикт, согласованный во всём, кроме
// хэша, пакет не проходит.
func TestGatewayBodyMustMatchVerdict(t *testing.T) {
	w, b := gatewayWorld(t, func(*gateway.Verdict) {})
	if r := Verify(b, w.trust()); !r.Valid() || r.Gateway == nil {
		t.Fatalf("исходный пакет:\n%s", r.Text())
	}
	w, b = gatewayWorld(t, func(v *gateway.Verdict) {
		v.Hash = "0000000000000000000000000000000000000000000000000000000000000000"
	})
	mustFail(t, "чужой хэш в вердикте", b, w.trust())
}
