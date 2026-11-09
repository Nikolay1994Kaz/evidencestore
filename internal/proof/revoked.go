package proof

import (
	"crypto/ed25519"
	"encoding/binary"
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"

	"golang.org/x/mod/sumdb/tlog"

	"github.com/Nikolay1994Kaz/evidencestore/internal/cosign"
	"github.com/Nikolay1994Kaz/evidencestore/internal/tsa"
)

// Отзыв сертификатов служб меток в пакете (tsa.Revocations; RFC 3161, 4).
//
// Каждая метка пакета сверяется с отзывом своей цепочки. Отозванная без
// компрометации не позже её времени — метка не в силе, и пункт, где она
// нужна, не проходит. Отозванная из-за компрометации ключа (или без причины)
// — время метки ничего не доказывает, и метка в силе, только если пакет
// показывает, что она существовала раньше отсечки (POE, ETSI EN 319 102-1):
// метка, чья цепочка не под подозрением, над головой не раньше звена с её
// токеном и со временем раньше отсечки, — своя метка пакета, метка второй
// службы (Archive: tsa.archive хранилища) или подпись закреплённого
// свидетеля C2SP. Поздняя метка другой службы над головой, в которой лежит
// токен, — та самая переметка RFC 4998: задним числом её не поставить без
// её собственного ключа.

// ArchiveStamp — метка второй службы над головой цепи (tsa.archive
// хранилища): всё до этой головы, токены основной службы тоже, существовало
// ко времени метки. Голова может лежать дальше конца пакета: тогда её корень
// сверяется доказательством продолжения от последнего звена пакета (Proof),
// без звеньев между ними.
type ArchiveStamp struct {
	HeadSeq uint64   `json:"head_seq"`
	Root    []byte   `json:"root"`
	Proof   [][]byte `json:"proof,omitempty"`
	Token   []byte   `json:"token"`
}

// revocationCheckName — пункт отчёта об отзыве.
const revocationCheckName = "no time-stamp rests on a revoked TSA certificate, or each such one is shown to exist before the revocation"

// RevocationNotChecked — заметка, когда сведений об отзыве не дали.
const RevocationNotChecked = "the revocation of the TSA certificates was not checked: pass the CRLs of their CAs with -tsa-crl, or your own list with -tsa-revoked; a time-stamp made with a TSA key stolen later passes without it"

// stampCheck — проверка меток одного пакета с учётом отзыва.
type stampCheck struct {
	trust     tsa.Trust
	revs      *tsa.Revocations
	tokens    int
	poe       []poeMark
	pending   []pendingMark
	crls      []string
	unchecked []string
	stale     []string
	foreign   []string
	notes     []string
}

// poeMark — что показывает существование всего до головы head ко времени at.
type poeMark struct {
	head uint64
	at   time.Time
	what string
}

// pendingMark — метка отозванного по компрометации сертификата: ей нужна
// POE раньше cutoff. link — звено с её токеном (0 — пакет его не показывает).
type pendingMark struct {
	link   uint64
	head   uint64 // голова, которую заверяет метка
	cutoff time.Time
	what   string
	why    string
}

func newStampCheck(trust Trust) *stampCheck {
	return &stampCheck{trust: trust.TSA, revs: trust.TSARevocations}
}

// verify — токен над головой head с корнем root (tsa.Verify) и его отзыв.
// link — звено, в котором лежит токен (0 — неизвестно), what — какая это
// метка, для отчёта.
func (sc *stampCheck) verify(token []byte, head uint64, root [32]byte, link uint64, what string) (tsa.Info, error) {
	info, err := tsa.Verify(token, HeadImprint(head, root), sc.trust)
	if err != nil {
		return info, err
	}
	sc.tokens++
	if sc.revs == nil {
		return info, nil
	}
	v, err := sc.revs.Check(info.Chains, info.GenTime)
	if err != nil {
		return tsa.Info{}, err
	}
	sc.record(v)
	if v.NeedPOE {
		sc.pending = append(sc.pending, pendingMark{link: link, head: head, cutoff: v.Cutoff, what: what, why: revokedWhy(v)})
	} else {
		sc.poe = append(sc.poe, poeMark{head: head, at: info.GenTime.UTC(), what: fmt.Sprintf("the time-stamp of %q over head %d at %s", info.Signer.Subject.CommonName, head, fmtTime(info.GenTime))})
	}
	return info, nil
}

// revokedWhy — какой сертификат отозван и как, для отчёта.
func revokedWhy(v tsa.Verdict) string {
	s := fmt.Sprintf("certificate %q, revoked on %s (%s; %s)", v.Revoked.Subject.String(), fmtTime(v.Entry.Time), tsa.ReasonName(v.Entry.Reason), v.Entry.From)
	if v.Cutoff.Before(v.Entry.Time) {
		s += fmt.Sprintf(", its key suspected since %s", fmtTime(v.Cutoff))
	}
	return s
}

// record — по каким CRL проверено, что не проверено и что устарело.
func (sc *stampCheck) record(v tsa.Verdict) {
	add := func(list *[]string, s string) {
		if !slices.Contains(*list, s) {
			*list = append(*list, s)
		}
	}
	for _, s := range v.CRLs {
		add(&sc.crls, s)
	}
	for _, c := range v.Unchecked {
		add(&sc.unchecked, c.Subject.String())
	}
	for _, s := range v.Stale {
		add(&sc.stale, s)
	}
	for _, s := range v.Foreign {
		add(&sc.foreign, s)
	}
}

// finish — пункт отчёта об отзыве: метки второй службы и подписи
// закреплённых свидетелей добавляют POE, затем каждая метка отозванного по
// компрометации сертификата ищет свою. last — последнее звено пакета, rootAt
// — корни дерева на звеньях пакета. Без сведений об отзыве пункта нет, а
// заметка говорит, что отзыв не проверен.
func (sc *stampCheck) finish(archive []ArchiveStamp, cs []Cosignature, keys []cosign.Verifier, storeKey ed25519.PublicKey, last uint64, rootAt func(uint64) ([32]byte, bool), add func(string, error, string) bool) {
	if sc.revs == nil {
		if sc.tokens > 0 {
			sc.notes = append(sc.notes, RevocationNotChecked)
		}
		return
	}
	if len(sc.pending) > 0 {
		sc.archived(archive, last, rootAt)
		sc.cosigned(cs, keys, storeKey, last, rootAt)
	}
	var failed, shown []string
	for _, p := range sc.pending {
		m, ok := sc.poeFor(p)
		switch {
		case ok:
			shown = append(shown, fmt.Sprintf("%s rests on %s, and %s shows it existed before %s", p.what, p.why, m.what, fmtTime(p.cutoff)))
		case p.link == 0:
			failed = append(failed, fmt.Sprintf("%s rests on %s: its time proves nothing, and the bundle does not show where its token lies in the chain, so nothing can show it existed earlier: ask for a bundle that reaches the link holding it (evidencestore proof … -to-head a head after %d, from a store of this release)", p.what, p.why, p.head))
		default:
			failed = append(failed, fmt.Sprintf("%s rests on %s: its time proves nothing, and nothing in the bundle shows it existed before %s — a time-stamp of another TSA or a cosignature of a witness given with -witness-key, over a head at or after link %d and dated earlier", p.what, p.why, fmtTime(p.cutoff), p.link))
		}
	}
	var err error
	if len(failed) > 0 {
		err = errors.New(strings.Join(failed, "; "))
	}
	detail := fmt.Sprintf("%d time-stamps, none rests on a revoked certificate", sc.tokens)
	if len(shown) > 0 {
		detail = strings.Join(shown, "; ")
	}
	if len(sc.crls) > 0 {
		detail += "; checked against " + strings.Join(sc.crls, ", ")
	}
	add(revocationCheckName, err, detail)
	for _, s := range sc.unchecked {
		sc.notes = append(sc.notes, fmt.Sprintf("the revocation of certificate %q was not checked: no CRL of its issuer was given (-tsa-crl)", s))
	}
	for _, s := range sc.stale {
		sc.notes = append(sc.notes, fmt.Sprintf("%s is past its next update: a revocation after it is not seen; fetch a fresh one", s))
	}
	for _, s := range sc.foreign {
		sc.notes = append(sc.notes, s+": not used")
	}
}

// poeFor — самая ранняя POE для метки p: голова не раньше звена её токена и
// время раньше отсечки.
func (sc *stampCheck) poeFor(p pendingMark) (poeMark, bool) {
	var best *poeMark
	if p.link == 0 {
		return poeMark{}, false
	}
	for i, m := range sc.poe {
		if m.head >= p.link && m.at.Before(p.cutoff) && (best == nil || m.at.Before(best.at)) {
			best = &sc.poe[i]
		}
	}
	if best == nil {
		return poeMark{}, false
	}
	return *best, true
}

// archived — метки второй службы как POE: голова сходится с пакетом
// (корень на звене пакета или доказательство продолжения от его последнего
// звена), токен проходит Verify, и его цепочка не под подозрением. Не
// сошлась — заметка, не провал: метка второй службы пакету не обязательна.
func (sc *stampCheck) archived(archive []ArchiveStamp, last uint64, rootAt func(uint64) ([32]byte, bool)) {
	for _, a := range archive {
		if len(a.Root) != 32 {
			sc.notes = append(sc.notes, fmt.Sprintf("the archive time-stamp over head %d names a root of %d bytes: not used", a.HeadSeq, len(a.Root)))
			continue
		}
		root := [32]byte(a.Root)
		if a.HeadSeq <= last {
			if r, ok := rootAt(a.HeadSeq); !ok || r != root || len(a.Proof) != 0 {
				sc.notes = append(sc.notes, fmt.Sprintf("the archive time-stamp over head %d does not agree with the chain in the bundle: not used", a.HeadSeq))
				continue
			}
		} else {
			end, _ := rootAt(last)
			p := make(tlog.TreeProof, len(a.Proof))
			bad := false
			for i, h := range a.Proof {
				bad = bad || len(h) != 32
				if !bad {
					p[i] = tlog.Hash(h)
				}
			}
			if bad || tlog.CheckTree(p, int64(a.HeadSeq), tlog.Hash(root), int64(last), tlog.Hash(end)) != nil {
				sc.notes = append(sc.notes, fmt.Sprintf("the archive time-stamp over head %d: its head does not extend the chain in the bundle: not used", a.HeadSeq))
				continue
			}
		}
		info, err := tsa.Verify(a.Token, HeadImprint(a.HeadSeq, root), sc.trust)
		if err != nil {
			sc.notes = append(sc.notes, fmt.Sprintf("the archive time-stamp over head %d was not used: %v (is the root of that TSA in -tsa-trust?)", a.HeadSeq, err))
			continue
		}
		v, err := sc.revs.Check(info.Chains, info.GenTime)
		switch {
		case err != nil:
			sc.notes = append(sc.notes, fmt.Sprintf("the archive time-stamp over head %d was not used: %v", a.HeadSeq, err))
			continue
		case v.NeedPOE:
			sc.notes = append(sc.notes, fmt.Sprintf("the archive time-stamp over head %d rests on a revoked certificate itself: not used", a.HeadSeq))
			continue
		}
		sc.record(v)
		sc.poe = append(sc.poe, poeMark{head: a.HeadSeq, at: info.GenTime.UTC(), what: fmt.Sprintf("the archive time-stamp of %q over head %d at %s", info.Signer.Subject.CommonName, a.HeadSeq, fmtTime(info.GenTime))})
	}
}

// cosigned — подписи закреплённых свидетелей как POE: голова в пакете, её
// корень сходится, подпись проходит. Подписи дальше конца пакета не в счёт:
// их корень пакету не сверить.
func (sc *stampCheck) cosigned(cs []Cosignature, keys []cosign.Verifier, storeKey ed25519.PublicKey, last uint64, rootAt func(uint64) ([32]byte, bool)) {
	if len(storeKey) != ed25519.PublicKeySize {
		return
	}
	origin := OriginFor(storeKey)
	for _, c := range cs {
		if len(c.Root) != 32 || len(c.Sig) < 4 || c.Size == 0 || c.Size > last {
			continue
		}
		if r, ok := rootAt(c.Size); !ok || r != [32]byte(c.Root) {
			continue
		}
		for _, k := range keys {
			if c.Name != k.Name || binary.BigEndian.Uint32(c.Sig) != k.ID {
				continue
			}
			at, err := k.Verify(cosign.CheckpointText(origin, c.Size, [32]byte(c.Root)), c.Sig)
			if err != nil {
				continue
			}
			t := time.Unix(int64(at), 0).UTC()
			sc.poe = append(sc.poe, poeMark{head: c.Size, at: t, what: fmt.Sprintf("witness %s (key %08x), which cosigned head %d at %s", k.Name, k.ID, c.Size, fmtTime(t))})
		}
	}
}
