package store

import (
	"bufio"
	"bytes"
	"crypto/ed25519"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"testing"

	"evidencestore/internal/auditchain"
	"evidencestore/internal/config"
	"evidencestore/internal/gateway"
	"evidencestore/internal/proof"
)

// Настоящий бортовой журнал Pipelock v3.6.0 из тестовых данных пакета
// gateway: 34 записи в 5 шардах, 6 подписанных контрольных точек.
const pipelockVectors = "../gateway/testdata/pipelock-v3.6.0"

func pipelockKey(t *testing.T) string {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join(pipelockVectors, "pubkey.hex"))
	if err != nil {
		t.Fatal(err)
	}
	return strings.TrimSpace(string(raw))
}

func readLines(t *testing.T, path string) [][]byte {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var out [][]byte
	sc := bufio.NewScanner(bytes.NewReader(data))
	sc.Buffer(nil, 1<<20)
	for sc.Scan() {
		out = append(out, append([]byte(nil), sc.Bytes()...))
	}
	return out
}

// pipelockSession — строки шардов первой сессии по порядку (номер первой
// записи в имени шарда — число).
func pipelockSession(t *testing.T) [][]byte {
	t.Helper()
	paths, _ := filepath.Glob(filepath.Join(pipelockVectors, "session1", "evidence-*.jsonl"))
	first := func(p string) int {
		n, _ := strconv.Atoi(strings.TrimSuffix(p[strings.LastIndexByte(p, '-')+1:], ".jsonl"))
		return n
	}
	sort.Slice(paths, func(i, j int) bool { return first(paths[i]) < first(paths[j]) })
	var out [][]byte
	for _, p := range paths {
		out = append(out, readLines(t, p)...)
	}
	if len(out) != 34 {
		t.Fatalf("в сессии %d записей, ожидали 34", len(out))
	}
	return out
}

func withGateway(key string) func(*config.Config) {
	return func(c *config.Config) {
		c.Sources = append(c.Sources, config.Source{Name: "agent-gw", ContentType: config.GatewayContentType, GatewayKey: key})
	}
}

// ingestLines — строки как улики источника с номерами from, from+1, …
func ingestLines(t *testing.T, s *Store, from uint64, lines [][]byte) {
	t.Helper()
	recs := make([]Incoming, len(lines))
	for i, l := range lines {
		recs[i] = Incoming{Seq: from + uint64(i), Body: l}
	}
	if _, err := s.Ingest("agent-gw", recs); err != nil {
		t.Fatal(err)
	}
}

func gatewayTrust(t *testing.T, s *Store, key string) proof.Trust {
	t.Helper()
	tr := trustOf(t, s)
	k, err := gateway.ParseKey(key)
	if err != nil {
		t.Fatal(err)
	}
	tr.GatewayKey = k
	return tr
}

func hasCheck(r proof.Report, name string) bool {
	for _, c := range r.Checks {
		if c.Name == name && c.OK {
			return true
		}
	}
	return false
}

// ⭐ Журнал Pipelock через хранилище: каждая строка — улика, рядом в цепи —
// вердикт при приёме. Пакет по записи из середины проверяется офлайн с
// ключом гейтвея: тело — та самая запись (хэш пересчитан), её накрывает
// контрольная точка, подписанная гейтвеем.
func TestGatewayJournalProof(t *testing.T) {
	key := pipelockKey(t)
	c := newClock()
	cfg := testConfig(t, withGateway(key))
	s := openStore(t, cfg, c)
	lines := pipelockSession(t)
	ingestLines(t, s, 1, lines[:20])
	ingestLines(t, s, 21, lines[20:])
	mustStamp(t, s)

	b, err := s.Proof("agent-gw", 4, true) // запись гейтвея seq 3
	if err != nil {
		t.Fatal(err)
	}
	tr := gatewayTrust(t, s, key)
	r := proof.Verify(b, tr)
	if !r.Valid() {
		t.Fatalf("пакет не прошёл:\n%s", r.Text())
	}
	if r.Gateway == nil || r.Gateway.Seq != 3 || r.GatewayCheckpoint == nil || !r.GatewayKeyChecked {
		t.Fatalf("вердикт %+v, точка %+v, ключ проверен %v", r.Gateway, r.GatewayCheckpoint, r.GatewayKeyChecked)
	}
	for _, name := range []string{
		"тело — та самая запись журнала гейтвея (хэш пересчитан)",
		"контрольная точка подписана закреплённым ключом гейтвея",
	} {
		if !hasCheck(r, name) {
			t.Fatalf("нет пройденной проверки %q:\n%s", name, r.Text())
		}
	}

	other, _, _ := ed25519.GenerateKey(nil)
	tr.GatewayKey = other
	if proof.Verify(b, tr).Valid() {
		t.Fatal("подпись контрольной точки сошлась с чужим ключом гейтвея")
	}
	// Без ключа проверяющего подпись проверило только хранилище — это
	// предел, а не провал, и он назван.
	tr.GatewayKey = nil
	r = proof.Verify(b, tr)
	if !r.Valid() || !strings.Contains(strings.Join(r.Notes(), "\n"), "esverify -gateway-key") {
		t.Fatalf("без ключа гейтвея:\n%s", r.Text())
	}
}

// Запись с изменённым байтом принимается, но вердикт и пакет говорят, что с
// ней не так, и контрольной точкой она не накрыта.
func TestGatewayTamperedEntry(t *testing.T) {
	key := pipelockKey(t)
	c := newClock()
	cfg := testConfig(t, withGateway(key))
	s := openStore(t, cfg, c)
	ingestLines(t, s, 1, readLines(t, filepath.Join(pipelockVectors, "tampered.jsonl")))
	mustStamp(t, s)

	b, err := s.Proof("agent-gw", 3, true) // запись гейтвея seq 2, в ней изменён байт
	if err != nil {
		t.Fatal(err)
	}
	r := proof.Verify(b, gatewayTrust(t, s, key))
	if r.Valid() || r.Gateway == nil || r.Gateway.HashOK || r.GatewayCheckpoint != nil {
		t.Fatalf("подменённая запись:\n%s", r.Text())
	}
	// Без ключа записи пакет тоже не проходит: поломку говорит вердикт.
	nb, err := s.Proof("agent-gw", 3, false)
	if err != nil {
		t.Fatal(err)
	}
	if r := proof.Verify(nb, gatewayTrust(t, s, key)); r.Valid() {
		t.Fatalf("подменённая запись без тела:\n%s", r.Text())
	}
	if s.sources["agent-gw"].gwProblems.Load() != 1 {
		t.Fatalf("поломок %d, ожидали 1", s.sources["agent-gw"].gwProblems.Load())
	}
	// Целую запись перед поломкой контрольная точка за поломкой не накрывает.
	b, err = s.Proof("agent-gw", 2, true) // запись гейтвея seq 1
	if err != nil {
		t.Fatal(err)
	}
	if r := proof.Verify(b, gatewayTrust(t, s, key)); !r.Valid() || r.Gateway == nil || r.GatewayCheckpoint != nil {
		t.Fatalf("запись перед поломкой:\n%s", r.Text())
	}
}

// Вердикт чужой улики в пакете не проходит.
func TestGatewayVerdictOfAnotherRecord(t *testing.T) {
	key := pipelockKey(t)
	c := newClock()
	cfg := testConfig(t, withGateway(key))
	s := openStore(t, cfg, c)
	ingestLines(t, s, 1, pipelockSession(t))
	mustStamp(t, s)
	b4, err := s.Proof("agent-gw", 4, true)
	if err != nil {
		t.Fatal(err)
	}
	b5, err := s.Proof("agent-gw", 5, true)
	if err != nil {
		t.Fatal(err)
	}
	b4.Gateway = b5.Gateway
	if r := proof.Verify(b4, gatewayTrust(t, s, key)); r.Valid() {
		t.Fatalf("чужой вердикт прошёл:\n%s", r.Text())
	}
	// Без ключа записи (тело закрыто, ключ месяца уничтожен) хэш тела не
	// пересчитать — подмену ловит сверка вердикта с уликой.
	c4, err := s.Proof("agent-gw", 4, false)
	if err != nil {
		t.Fatal(err)
	}
	c5, err := s.Proof("agent-gw", 5, false)
	if err != nil {
		t.Fatal(err)
	}
	c4.Gateway = c5.Gateway
	if r := proof.Verify(c4, gatewayTrust(t, s, key)); r.Valid() {
		t.Fatalf("чужой вердикт без тела прошёл:\n%s", r.Text())
	}
}

// Падение между журналом улик и вердиктом: при подъёме вердикты
// досчитываются по телам, и проверка сцепки продолжается с того же места.
func TestGatewayVerdictCatchUp(t *testing.T) {
	key := pipelockKey(t)
	c := newClock()
	cfg := testConfig(t, withGateway(key))
	s := openStore(t, cfg, c)
	lines := pipelockSession(t)
	ingestLines(t, s, 1, lines[:10])
	s.flush()
	ingestLines(t, s, 11, lines[10:20]) // вердикты ещё в памяти
	crashed := copyDirs(t, cfg)

	s2 := openStore(t, crashed, c)
	ingestLines(t, s2, 21, lines[20:])
	s2.flush()
	got := leavesOf(t, crashed, auditchain.EventGateway)
	if len(got) != len(lines) {
		t.Fatalf("вердиктов %d, записей %d", len(got), len(lines))
	}
	for i, l := range got {
		_, v, err := proof.ParseGatewayLeaf(l)
		if err != nil || !v.Clean() || v.Seq != uint64(i) {
			t.Fatalf("вердикт %d: %+v, %v", i, v, err)
		}
		want := gateway.LinkOK
		if i == 0 {
			want = gateway.LinkGenesis
		}
		if v.Link != want {
			t.Fatalf("вердикт %d: сцепка %s, ожидали %s", i, v.Link, want)
		}
	}
}

// ⭐ V-01: из пакета по улике журнала гейтвея вырезали часть gateway — вердикт
// «запись не цела» больше не виден. Такой пакет не проходит: раньше
// «ПРОВЕРКА ПРОЙДЕНА», а -gateway-key молча не использовался.
func TestGatewayPartCannotBeStripped(t *testing.T) {
	key := pipelockKey(t)
	c := newClock()
	cfg := testConfig(t, withGateway(key))
	s := openStore(t, cfg, c)
	ingestLines(t, s, 1, pipelockSession(t))
	mustStamp(t, s)
	b, err := s.Proof("agent-gw", 4, true)
	if err != nil {
		t.Fatal(err)
	}
	tr := gatewayTrust(t, s, key)
	if r := proof.Verify(b, tr); !r.Valid() {
		t.Fatalf("ПАРНЫЙ КОНТРОЛЬ: целый пакет:\n%s", r.Text())
	}
	b.Gateway = nil
	if r := proof.Verify(b, tr); r.Valid() {
		t.Fatalf("пакет без части gateway прошёл:\n%s", r.Text())
	}
}

// V-02: ключ гейтвея не закреплён в реестре источников — подпись контрольной
// точки не проверял никто. Такая точка запись не накрывает, и отчёт говорит
// об этом прямо (раньше: «Накрыта контрольной точкой… подпись проверило
// хранилище»).
func TestNoKeyCheckpointDoesNotCover(t *testing.T) {
	c := newClock()
	cfg := testConfig(t, withGateway(""))
	s := openStore(t, cfg, c)
	ingestLines(t, s, 1, pipelockSession(t))
	mustStamp(t, s)
	b, err := s.Proof("agent-gw", 4, true)
	if err != nil {
		t.Fatal(err)
	}
	r := proof.Verify(b, trustOf(t, s))
	if !r.Valid() {
		t.Fatalf("пакет:\n%s", r.Text())
	}
	if r.GatewayCheckpoint != nil || !r.GatewayUnsigned {
		t.Fatalf("точка без проверенной подписи накрывает запись: %+v", r.GatewayCheckpoint)
	}
	text := r.Text()
	if strings.Contains(text, "Накрыта контрольной точкой") || !strings.Contains(text, "подпись не проверял никто") {
		t.Fatalf("отчёт:\n%s", text)
	}
	// С ключом у проверяющего та же точка накрывает: подпись проверена им.
	if r := proof.Verify(b, gatewayTrust(t, s, pipelockKey(t))); !r.Valid() || r.GatewayCheckpoint == nil {
		t.Fatalf("с ключом проверяющего:\n%s", r.Text())
	}
}
