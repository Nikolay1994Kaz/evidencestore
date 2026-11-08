package proof

import (
	"crypto/ed25519"
	"crypto/rand"
	"strings"
	"testing"
	"time"

	"github.com/Nikolay1994Kaz/evidencestore/internal/auditchain"
	"github.com/Nikolay1994Kaz/evidencestore/internal/cosign"
)

// cosigner — свидетель C2SP в тестах: подписывает головы мира w.
func cosigner(t *testing.T, name string) cosign.Signer {
	t.Helper()
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	s, err := cosign.NewSigner(name, priv)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

// cosigned — подпись свидетеля s над головой size с корнем root хранилища с
// ключом w.signer в момент at.
func (w *world) cosigned(s cosign.Signer, size uint64, root [32]byte, at time.Time) Cosignature {
	text := cosign.CheckpointText(OriginFor(w.signer.PublicKey()), size, root)
	return Cosignature{Name: s.Name, Size: size, Root: root[:], Sig: s.Cosign(text, uint64(at.Unix()))}
}

func cosignTrust(w *world, keys ...cosign.Signer) Trust {
	tr := w.trust()
	for _, k := range keys {
		tr.Cosigners = append(tr.Cosigners, k.Verifier())
	}
	return tr
}

// Голова не раньше звена улики, подписанная свидетелем, закрепляет улику, и
// отчёт называет, кто, какую голову и когда.
func TestCosignedFixesRecord(t *testing.T) {
	w, b := standard(t, nil) // звенья 1–5, улика в звене 3
	s := cosigner(t, "witness.example/w1")
	t4 := w.now.Add(time.Minute)
	b.Cosignatures = []Cosignature{w.cosigned(s, 4, w.root(4), t4)}
	r := Verify(b, cosignTrust(w, s))
	if !r.Valid() || len(r.Cosigned) != 1 || r.Cosigned[0].Size != 4 || !r.Cosigned[0].Time.Equal(t4.Truncate(time.Second)) {
		t.Fatalf("подписанная голова 4:\n%s", r.Text())
	}
	text := r.Text()
	if !strings.Contains(text, "witness witness.example/w1 cosigned head 4") || strings.Contains(text, "only a TSA time-stamp stands") {
		t.Fatalf("отчёт не называет подпись свидетеля:\n%s", text)
	}
	// Без ключа свидетеля подпись не проверяется, и отчёт так и говорит.
	r = Verify(b, w.trust())
	if !r.Valid() || r.CosignChecked || !strings.Contains(r.Text(), "not checked: pass each witness's key with -witness-key") {
		t.Fatalf("подпись без ключа:\n%s", r.Text())
	}
}

// Из подписей одного свидетеля закрепляет подписанная раньше всех; подпись
// головы раньше звена улики не закрепляет ничего.
func TestCosignedEarliestPins(t *testing.T) {
	w, b := standard(t, nil)
	s := cosigner(t, "witness.example/w1")
	b.Cosignatures = []Cosignature{
		w.cosigned(s, 2, w.root(2), w.now.Add(-time.Minute)),
		w.cosigned(s, 5, w.root(5), w.now.Add(2*time.Minute)),
		w.cosigned(s, 4, w.root(4), w.now.Add(time.Minute)),
	}
	r := Verify(b, cosignTrust(w, s))
	if !r.Valid() || r.Cosigned[0].Size != 4 {
		t.Fatalf("закрепить обязана голова 4:\n%s", r.Text())
	}
	b.Cosignatures = b.Cosignatures[:1] // только голова 2 — раньше звена улики
	if r := Verify(b, cosignTrust(w, s)); r.Valid() || !strings.Contains(r.Text(), "no cosignature of witness witness.example/w1 on a head at or after link 3") {
		t.Fatalf("голова раньше звена улики закрепила её:\n%s", r.Text())
	}
}

// Переписанная цепь: свидетель подписал честную голову 4, а пакет из новой
// истории с ней не сходится — ни коротким (просит дойти до 4), ни длинным.
func TestCosignedCatchesRewrite(t *testing.T) {
	w, honest := standard(t, nil)
	s := cosigner(t, "witness.example/w1")
	sig := w.cosigned(s, 4, w.root(4), w.now.Add(time.Minute))
	honest.Cosignatures = []Cosignature{sig}
	if r := Verify(honest, cosignTrust(w, s)); !r.Valid() {
		t.Fatalf("честный пакет:\n%s", r.Text())
	}
	y, forged := rewritten(t, w) // звено 3 переписано, пакет кончается головой 3
	forged.Cosignatures = []Cosignature{sig}
	r := Verify(forged, cosignTrust(y, s))
	if r.Valid() || !strings.Contains(r.Text(), "before head 4 that witness witness.example/w1 cosigned") {
		t.Fatalf("переписанная цепь без головы 4:\n%s", r.Text())
	}
	// Дотянутая до 4 — корень не тот, что подписал свидетель.
	y.wlink(auditchain.Leaf{Type: auditchain.EventGap, Scope: "abs-core"})
	long := forged
	long.Links = nil
	for _, l := range y.links[2:] {
		long.Links = append(long.Links, FromLink(l))
	}
	long.Checkpoint = y.checkpoint(uint64(len(y.links)))
	if r := Verify(long, cosignTrust(y, s)); r.Valid() || !strings.Contains(r.Text(), "with a root that differs from the chain in the bundle") {
		t.Fatalf("переписанная цепь до головы 4:\n%s", r.Text())
	}
	// Подпись над корнем новой истории: свидетель такую не дал бы, а
	// подделать её без его ключа нельзя.
	fake := sig
	root := y.root(4)
	fake.Root = root[:]
	long.Cosignatures = []Cosignature{fake}
	if r := Verify(long, cosignTrust(y, s)); r.Valid() || !strings.Contains(r.Text(), "does not verify with the witness key") {
		t.Fatalf("подпись под чужим корнем:\n%s", r.Text())
	}
}

// Подпись чужого ключа (тёзка свидетеля) не в счёт; испорченная подпись
// закреплённого ключа — провал, а не пропуск.
func TestCosignedOtherKeyAndBroken(t *testing.T) {
	w, b := standard(t, nil)
	s := cosigner(t, "witness.example/w1")
	twin := cosigner(t, s.Name)
	b.Cosignatures = []Cosignature{w.cosigned(twin, 4, w.root(4), w.now)}
	r := Verify(b, cosignTrust(w, s))
	if r.Valid() || r.CosignUnknown != 1 {
		t.Fatalf("подпись тёзки закрепила улику:\n%s", r.Text())
	}
	broken := w.cosigned(s, 4, w.root(4), w.now)
	broken.Sig[len(broken.Sig)-1] ^= 1
	b.Cosignatures = []Cosignature{broken, w.cosigned(s, 5, w.root(5), w.now.Add(time.Minute))}
	if r := Verify(b, cosignTrust(w, s)); r.Valid() || !strings.Contains(r.Text(), "does not verify") {
		t.Fatalf("испорченная подпись пропущена:\n%s", r.Text())
	}
	short := w.cosigned(s, 4, w.root(4), w.now)
	short.Root = short.Root[:31]
	b.Cosignatures = []Cosignature{short}
	if r := Verify(b, cosignTrust(w, s)); r.Valid() {
		t.Fatalf("корень 31 байт:\n%s", r.Text())
	}
}

// Каждый закреплённый свидетель обязан подписать: подпись одного не
// заменяет подписи другого. Порядок ключей отчёт не меняет.
func TestCosignedEveryWitness(t *testing.T) {
	w, b := standard(t, nil)
	a, c := cosigner(t, "a.example/w"), cosigner(t, "c.example/w")
	b.Cosignatures = []Cosignature{w.cosigned(a, 4, w.root(4), w.now)}
	if r := Verify(b, cosignTrust(w, a, c)); r.Valid() || !strings.Contains(r.Text(), "no cosignature of witness c.example/w") {
		t.Fatalf("второй свидетель не подписал:\n%s", r.Text())
	}
	b.Cosignatures = append(b.Cosignatures, w.cosigned(c, 5, w.root(5), w.now.Add(time.Minute)))
	r1, r2 := Verify(b, cosignTrust(w, a, c)), Verify(b, cosignTrust(w, c, a, c))
	if !r1.Valid() || len(r1.Cosigned) != 2 || r1.Text() != r2.Text() {
		t.Fatalf("два свидетеля:\n%s\n%s", r1.Text(), r2.Text())
	}
}

// Пакет за окно и по источнику: закрепляется конец участка и звено токена
// верхнего края.
func TestCosignedWindowAndSource(t *testing.T) {
	ww := windowWorld(t, nil, nil) // звенья 1..3, StretchEnd = 3
	wb := ww.window(1, 3, at(10, 4, 0), at(10, 6, 0))
	s := cosigner(t, "witness.example/w1")
	wb.Cosignatures = []Cosignature{ww.cosigned(s, 2, ww.root(2), at(10, 7, 0))}
	if r := VerifyWindow(wb, cosignTrust(ww, s), time.Time{}, time.Time{}); r.Valid() {
		t.Fatalf("окно: голова раньше конца участка закрепила его:\n%s", r.Text())
	}
	wb.Cosignatures = append(wb.Cosignatures, ww.cosigned(s, 3, ww.root(3), at(10, 8, 0)))
	r := VerifyWindow(wb, cosignTrust(ww, s), time.Time{}, time.Time{})
	if !r.Valid() || len(r.Cosigned) != 1 || r.Cosigned[0].Size != 3 || !strings.Contains(r.Text(), "a rewrite of this stretch") {
		t.Fatalf("окно:\n%s", r.Text())
	}

	sw := newSrcWorld(t, srcOpts{})
	sb := sw.bundle(at(10, 4, 0), at(10, 6, 0))
	end := sb.Checkpoint.Size
	sb.Cosignatures = []Cosignature{sw.cosigned(s, end, sw.root(end), at(10, 30, 0))}
	sr := VerifySource(sb, cosignTrust(sw.world, s), time.Time{}, time.Time{})
	if !sr.Valid() || len(sr.Cosigned) != 1 || !strings.Contains(sr.Text(), "a rewrite of this part") {
		t.Fatalf("источник:\n%s", sr.Text())
	}
	sb.Cosignatures = nil
	if sr := VerifySource(sb, cosignTrust(sw.world, s), time.Time{}, time.Time{}); sr.Valid() {
		t.Fatalf("источник без подписи:\n%s", sr.Text())
	}
}

// Заметка точки — та, что примет свидетель: текст, пустая строка, подпись
// хранилища, которая сходится.
func TestCheckpointNote(t *testing.T) {
	w, _ := standard(t, nil)
	c := w.checkpoint(4)
	note := c.Note(w.signer.PublicKey())
	text, sigs, err := cosign.SplitNote(note)
	if err != nil {
		t.Fatal(err)
	}
	origin, size, root, err := cosign.ParseCheckpointText(text)
	if err != nil || origin != c.Origin || size != 4 || root != w.root(4) {
		t.Fatalf("текст точки: %q %d %v", origin, size, err)
	}
	if err := cosign.VerifyLogSignature(text, sigs, c.Origin, w.signer.PublicKey()); err != nil {
		t.Fatalf("подпись хранилища в заметке: %v", err)
	}
}
