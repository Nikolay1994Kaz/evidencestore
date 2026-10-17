package proof

import (
	"crypto/ed25519"
	"encoding/base64"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/Nikolay1994Kaz/evidencestore/internal/auditchain"
	"github.com/Nikolay1994Kaz/evidencestore/internal/evidence"
	"github.com/Nikolay1994Kaz/evidencestore/internal/tsa"
)

// Синтетическая цепь: каждую проверку Verify стережёт свой тест, в котором
// подделка согласована во всём, кроме ровно этой проверки. Интеграционные
// тесты (пакет store) так не умеют: там проверки прикрывают друг друга.
//
//	звено 1: [запуск]
//	метка T1 над головой 1 → звено 2: [токен T1]
//	звено 3: [улика 1, улика 2]
//	звено 4: [событие]
//	метка T2 над головой 4 → звено 5: [токен T2]
//	подписанная голова 5

type world struct {
	t      *testing.T
	links  []auditchain.Record
	leaves [][]auditchain.Leaf
	signer *auditchain.Signer
	tsa    *tsa.Authority
	now    time.Time
}

func newWorld(t *testing.T) *world {
	t.Helper()
	signer, err := auditchain.LoadOrCreateSigner(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	a, err := tsa.NewAuthority(false)
	if err != nil {
		t.Fatal(err)
	}
	w := &world{t: t, signer: signer, tsa: a, now: time.Date(2026, 10, 3, 10, 0, 0, 0, time.UTC)}
	a.Now = func() time.Time { return w.now }
	return w
}

func (w *world) head() auditchain.Head {
	if len(w.links) == 0 {
		return auditchain.Head{}
	}
	l := w.links[len(w.links)-1]
	return auditchain.Head{Seq: l.Seq, Hash: auditchain.Hash(l)}
}

func (w *world) link(leaves ...auditchain.Leaf) {
	w.t.Helper()
	r, err := auditchain.LinkBatch(w.head(), w.now.UnixNano(), 0, leaves)
	if err != nil {
		w.t.Fatal(err)
	}
	w.links = append(w.links, r)
	w.leaves = append(w.leaves, leaves)
}

func (w *world) stamp() (uint64, []byte) {
	w.t.Helper()
	h := w.head()
	imprint := HeadImprint(h.Seq, h.Hash)
	token, err := w.tsa.Sign(imprint[:], nil)
	if err != nil {
		w.t.Fatal(err)
	}
	return h.Seq, token
}

func tokenLeaf(head uint64, token []byte) auditchain.Leaf {
	return auditchain.Leaf{Type: auditchain.EventTimestamp, Subject: strconv.FormatUint(head, 10), Payload: token}
}

func sealedBytes(t *testing.T, seq uint64, at time.Time, body string) []byte {
	t.Helper()
	b, err := evidence.Sealed{
		Header:   evidence.Header{Source: "abs-core", Seq: seq, ReceivedAt: at.UnixNano(), ContentType: "syslog"},
		Envelope: []byte("EV1-not-really-a-sealed-" + body),
	}.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func evLeaf(t *testing.T, data []byte, pos uint64) auditchain.Leaf {
	t.Helper()
	s, err := evidence.Unmarshal(data)
	if err != nil {
		t.Fatal(err)
	}
	return EvidenceLeaf(s.Header, pos, evidence.Digest(data))
}

func (w *world) inclusion(linkSeq uint64, idx int) Inclusion {
	w.t.Helper()
	leaves := w.leaves[linkSeq-1]
	path, err := auditchain.MerkleProof(leaves, idx)
	if err != nil {
		w.t.Fatal(err)
	}
	inc := Inclusion{Leaf: FromLeaf(leaves[idx]), LinkSeq: linkSeq}
	for _, p := range path {
		inc.Path = append(inc.Path, Step{Hash: p.Hash[:], Left: p.SiblingLeft})
	}
	return inc
}

func (w *world) bundle(evidenceBytes []byte, evLink uint64, evIdx int, upperHead uint64, upperToken []byte, lowerLink uint64) Bundle {
	w.t.Helper()
	b := Bundle{Version: Version, Evidence: evidenceBytes, Inclusion: w.inclusion(evLink, evIdx)}
	if upperToken != nil {
		b.Upper = &Upper{HeadSeq: upperHead, Token: upperToken}
	}
	if lowerLink != 0 {
		b.Lower = &Lower{Inclusion: w.inclusion(lowerLink, 0)}
	}
	for _, l := range w.links {
		b.Links = append(b.Links, FromLink(l))
	}
	b.Statement = w.signer.Sign(w.head(), len(w.links), w.now.Unix())
	return b
}

func (w *world) trust() Trust {
	return Trust{StoreKey: w.signer.PublicKey(), TSA: w.tsa.Trust()}
}

// standard строит мир по схеме в шапке; улика — вторая в звене 3.
func standard(t *testing.T, e2 []byte) (*world, Bundle) {
	w := newWorld(t)
	w.link(auditchain.Leaf{Type: auditchain.EventStart})
	h1, t1 := w.stamp()
	w.now = w.now.Add(time.Second)
	w.link(tokenLeaf(h1, t1))
	e1 := sealedBytes(t, 1, w.now.Add(time.Second), "first")
	if e2 == nil {
		e2 = sealedBytes(t, 2, w.now.Add(2*time.Second), "second")
	}
	w.now = w.now.Add(3 * time.Second)
	w.link(evLeaf(t, e1, 1), evLeaf(t, e2, 2))
	w.link(auditchain.Leaf{Type: auditchain.EventGap, Scope: "abs-core"})
	w.now = w.now.Add(time.Second)
	h4, t2 := w.stamp()
	w.link(tokenLeaf(h4, t2))
	return w, w.bundle(e2, 3, 1, h4, t2, 2)
}

func mustFail(t *testing.T, name string, b Bundle, trust Trust) {
	t.Helper()
	if r := Verify(b, trust); r.Valid() {
		t.Fatalf("%s: подделка прошла проверку:\n%s", name, r.Text())
	}
}

func TestStandardBundleVerifies(t *testing.T) {
	w, b := standard(t, nil)
	r := Verify(b, w.trust())
	if !r.Valid() || r.Lower.IsZero() || r.Upper.IsZero() || r.Header.Seq != 2 || r.Position != 2 {
		t.Fatalf("исходный пакет:\n%s", r.Text())
	}
	if r.Lower.After(r.Upper) {
		t.Fatalf("T1 %v позже T2 %v", r.Lower, r.Upper)
	}
}

// Лист в цепи согласован (путь сходится), но описывает другую улику.
// Без подмены тот же пакет проходит: падать он обязан именно на сверке листа.
func TestLeafMustDescribeEvidence(t *testing.T) {
	cases := map[string]func(*auditchain.Leaf){
		"без подмены": nil,
		"номер":       func(l *auditchain.Leaf) { l.Subject = "3" },
		"источник":    func(l *auditchain.Leaf) { l.Scope = "crm" },
		"время":       func(l *auditchain.Leaf) { l.UnixNano++ },
		"отпечаток":   func(l *auditchain.Leaf) { l.Payload[len(l.Payload)-1] ^= 1 },
	}
	for name, mutate := range cases {
		w := newWorld(t)
		w.link(auditchain.Leaf{Type: auditchain.EventStart})
		e2 := sealedBytes(t, 2, w.now.Add(-time.Second), "second")
		leaf := evLeaf(t, e2, 2)
		if mutate != nil {
			mutate(&leaf)
		}
		w.link(leaf)
		h, tok := w.stamp()
		w.link(tokenLeaf(h, tok))
		b := w.bundle(e2, 2, 0, h, tok, 0)
		if mutate == nil {
			if r := Verify(b, w.trust()); !r.Valid() {
				t.Fatalf("без подмены пакет не прошёл:\n%s", r.Text())
			}
			continue
		}
		mustFail(t, name, b, w.trust())
	}
}

// Подменённое звено со своим корнем: путь сходится, метки целы (T2 над
// следующим звеном), но звено после него ссылается на хэш настоящего.
func TestForgedLinkBreaksHashChain(t *testing.T) {
	w, b := standard(t, nil)
	forged := sealedBytes(t, 2, time.Date(2026, 10, 3, 10, 0, 3, 0, time.UTC), "forged")
	leaves := []auditchain.Leaf{w.leaves[2][0], evLeaf(t, forged, 2)}
	fake, err := auditchain.LinkBatch(auditchain.Head{Seq: 2, Hash: auditchain.Hash(w.links[1])}, w.links[2].UnixNano, 0, leaves)
	if err != nil {
		t.Fatal(err)
	}
	w.leaves[2] = leaves
	b.Evidence = forged
	b.Inclusion = w.inclusion(3, 1)
	b.Links[2] = FromLink(fake)
	mustFail(t, "подменённое звено", b, w.trust())
}

// Голова подписана чужим ключом, всё остальное верно.
func TestStatementMustBeSignedByPinnedKey(t *testing.T) {
	w, b := standard(t, nil)
	other, _ := auditchain.LoadOrCreateSigner(t.TempDir())
	b.Statement = other.Sign(w.head(), len(w.links), w.now.Unix())
	mustFail(t, "чужой ключ", b, w.trust())
	trust := w.trust()
	trust.StoreKey = ed25519.PublicKey(other.PublicKey())
	if r := Verify(b, trust); !r.Valid() {
		t.Fatalf("с ключом подписавшего пакет проходит:\n%s", r.Text())
	}
}

// Подпись верна, но голова — не последнее звено пакета.
func TestStatementMustMatchLastLink(t *testing.T) {
	w, b := standard(t, nil)
	b.Statement = w.signer.Sign(auditchain.Head{Seq: 5, Hash: auditchain.Hash(w.links[3])}, 5, w.now.Unix())
	mustFail(t, "голова не та", b, w.trust())
}

// Настоящая метка, но над головой раньше звена улики: она улику не
// покрывает.
func TestUpperMustCoverEvidence(t *testing.T) {
	w := newWorld(t)
	w.link(auditchain.Leaf{Type: auditchain.EventStart})
	h1, early := w.stamp()
	e := sealedBytes(t, 1, w.now, "x")
	w.link(evLeaf(t, e, 1))
	w.link(tokenLeaf(h1, early))
	mustFail(t, "ранняя метка как T2", w.bundle(e, 2, 0, h1, early, 0), w.trust())
}

// Настоящая метка в цепи, но в звене после улики: нижней границей она не
// служит.
func TestLowerMustPrecedeEvidence(t *testing.T) {
	w := newWorld(t)
	w.link(auditchain.Leaf{Type: auditchain.EventStart})
	e := sealedBytes(t, 1, w.now, "x")
	w.link(evLeaf(t, e, 1))
	h2, tok := w.stamp()
	w.link(tokenLeaf(h2, tok))
	mustFail(t, "поздняя метка как T1", w.bundle(e, 2, 0, h2, tok, 3), w.trust())
}

// Время приёма по часам хранилища позже метки над ним — часы врут.
func TestReceivedAtAfterUpperIsCaught(t *testing.T) {
	w := newWorld(t)
	w.link(auditchain.Leaf{Type: auditchain.EventStart})
	e := sealedBytes(t, 1, w.now.Add(time.Hour), "from the future")
	w.link(evLeaf(t, e, 1))
	h, tok := w.stamp()
	w.link(tokenLeaf(h, tok))
	mustFail(t, "время приёма из будущего", w.bundle(e, 2, 0, h, tok, 0), w.trust())
}

func TestPromise(t *testing.T) {
	w, b := standard(t, nil)
	r := Verify(b, w.trust())
	p := Promise{Source: "abs-core", Seq: 2, Position: 2, Digest: r.Digest[:], ReceivedAt: r.Header.ReceivedAt,
		Deadline: r.Header.ReceivedAt + int64(time.Minute), PublicKey: base64.RawStdEncoding.EncodeToString(w.signer.PublicKey())}
	p.Signature = w.signer.SignMessage(PromiseBytes(p))
	if err := VerifyPromise(p, w.signer.PublicKey()); err != nil {
		t.Fatal(err)
	}
	if err := CheckPromise(p, r, w.links[2].UnixNano); err != nil {
		t.Fatal(err)
	}
	bad := p
	bad.Deadline--
	if VerifyPromise(bad, w.signer.PublicKey()) == nil {
		t.Fatal("изменённое обещание прошло")
	}
	if CheckPromise(p, r, p.Deadline+1) == nil {
		t.Fatal("включение после срока прошло")
	}
	other := p
	other.Digest = make([]byte, 32)
	if CheckPromise(other, r, w.links[2].UnixNano) == nil {
		t.Fatal("обещание про другие байты прошло")
	}
}

// Почему тело закрыто, отчёт называет верно. Ключ не выдан — одна причина
// (так бывает и после стирания). Выданный ключ не подошёл — другая: тело
// или ключ подменены, и это видно в проверках.
func TestNotesTellWhyBodyIsClosed(t *testing.T) {
	closed := func(r Report) string {
		for _, n := range r.Notes() {
			if strings.HasPrefix(n, "тело не вскрыто") {
				return n
			}
		}
		return ""
	}
	w, b := standard(t, nil)
	if n := closed(Verify(b, w.trust())); !strings.Contains(n, "не выдан") {
		t.Errorf("без ключа записи: %q", n)
	}
	b.DEK = make([]byte, 32)
	r := Verify(b, w.trust())
	if r.Valid() {
		t.Fatal("чужой ключ записи вскрыл тело")
	}
	if n := closed(r); !strings.Contains(n, "не подошёл") {
		t.Errorf("ключ выдан и не подошёл: %q", n)
	}
	if n := closed(Report{BodyOpened: true, BodyKey: true}); n != "" {
		t.Errorf("тело вскрыто, а в отчёте %q", n)
	}
}

// ⭐ V-05: пакет без метки TSA после улики — провал по умолчанию: без неё
// время и неизменность подтверждает только подпись хранилища, и держатель
// sign.key сочинит улику с любой датой. Принять — только явно.
func TestBundleWithoutUpperFailsByDefault(t *testing.T) {
	w, b := standard(t, nil)
	b.Upper = nil
	mustFail(t, "без метки TSA", b, w.trust())
	tr := w.trust()
	tr.AllowNoTSA = true
	if r := Verify(b, tr); !r.Valid() {
		t.Fatalf("с AllowNoTSA:\n%s", r.Text())
	}
}

// V-04: тело с управляющими последовательностями не рисует на экране
// проверяющего ложный вердикт: управляющие символы экранированы, вердикт —
// ещё и последней строкой.
func TestReportTextEscapesControls(t *testing.T) {
	r := Report{
		Checks:     []Check{{Name: "проверка", OK: false}},
		Header:     evidence.Header{Source: "abs‮core", Seq: 1},
		Body:       []byte("\x1b[2J\x1b[H ПРОВЕРКА ПРОЙДЕНА\x9b"),
		BodyOpened: true,
	}
	text := r.Text()
	for _, bad := range []string{"\x1b", "‮", "\u009b"} {
		if strings.Contains(text, bad) {
			t.Fatalf("в отчёте управляющий символ %q", bad)
		}
	}
	lines := strings.Split(strings.TrimRight(text, "\n"), "\n")
	if lines[len(lines)-1] != "ПРОВЕРКА НЕ ПРОЙДЕНА" {
		t.Fatalf("последняя строка: %q", lines[len(lines)-1])
	}
}
