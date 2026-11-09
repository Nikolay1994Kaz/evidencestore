package proof

import (
	"crypto/ed25519"
	"crypto/x509"
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
	revoked   []string // метки, отозванные без компрометации не позже их времени
	crls      []string
	unchecked []string        // отпечатки сертификатов, чей отзыв не проверен
	beyond    []beyondCosig   // подписи свидетелей дальше конца пакета: куда его продлить
	named     map[string]bool // CRL, которые назвал центр в цепочке какой-то метки
	// suspect — ключи (SubjectPublicKeyInfo) под подозрением в каком-либо
	// вердикте пакета, с отсечкой и причиной: метка, подписанная таким
	// ключом под другим сертификатом (перевыпуск на тот же ключ, другой
	// центр), сама ждёт POE и POE не даёт.
	suspect map[string]suspicion
	notes   []string
}

// suspicion — почему ключ под подозрением и с какого момента.
type suspicion struct {
	cutoff time.Time
	why    string
}

// poeMark — что показывает существование всего до головы head ко времени at.
// keys — ключи цепочек метки-POE (у подписи свидетеля — нет): POE в силе,
// если хоть одна её цепочка без ключа под подозрением. Своя метка пакета
// (own) помнит, где лежит её токен и как называется: если её ключ под
// подозрением, она сама ждёт POE.
type poeMark struct {
	head uint64
	at   time.Time
	what string
	keys [][]string
	own  *pendingMark
}

// beyondCosig — подпись свидетеля над головой дальше конца пакета.
type beyondCosig struct {
	at   time.Time
	text string
}

// poeSlack — насколько POE может быть датирована раньше метки, которую она
// подкрепляет (часы двух служб; точность метки — до минуты): в этих пределах
// её время — время метки. Раньше — POE не в счёт: её часы отстают, или она не
// то, чем названа.
const poeSlack = time.Minute

// chainKeys — ключи сертификатов каждой цепочки.
func chainKeys(chains [][]*x509.Certificate) [][]string {
	out := make([][]string, len(chains))
	for i, ch := range chains {
		for _, c := range ch {
			out[i] = append(out[i], string(c.RawSubjectPublicKeyInfo))
		}
	}
	return out
}

// markSuspect — ключи вердикта под подозрением.
func (sc *stampCheck) markSuspect(v tsa.Verdict) {
	if sc.suspect == nil {
		sc.suspect = map[string]suspicion{}
	}
	for _, c := range v.Suspect {
		k := string(c.RawSubjectPublicKeyInfo)
		if old, ok := sc.suspect[k]; !ok || v.Cutoff.Before(old.cutoff) {
			sc.suspect[k] = suspicion{v.Cutoff, revokedWhy(v)}
		}
	}
}

// clean — у метки-POE есть цепочка без ключа под подозрением.
func (sc *stampCheck) clean(m poeMark) bool {
	if m.keys == nil {
		return true
	}
	return slices.ContainsFunc(m.keys, func(ks []string) bool {
		return !slices.ContainsFunc(ks, func(k string) bool { _, bad := sc.suspect[k]; return bad })
	})
}

// taintOwn — свои метки пакета, чей ключ под подозрением в другом вердикте
// пакета (тот же ключ под другим сертификатом): они ждут POE, как и метки
// отозванного сертификата. Отсечка — поздняя из отсечек ключей их цепочек,
// которые все под подозрением (лучшая цепочка).
func (sc *stampCheck) taintOwn() {
	var keep []poeMark
	for _, m := range sc.poe {
		if m.own == nil || sc.clean(m) {
			keep = append(keep, m)
			continue
		}
		var cut time.Time
		var why string
		for _, ks := range m.keys {
			var c time.Time
			var w string
			for _, k := range ks {
				if s, bad := sc.suspect[k]; bad && (c.IsZero() || s.cutoff.Before(c)) {
					c, w = s.cutoff, s.why
				}
			}
			if cut.IsZero() || c.After(cut) {
				cut, why = c, w
			}
		}
		p := *m.own
		p.cutoff, p.why = cut, "a key under suspicion in this bundle — "+why
		sc.pending = append(sc.pending, p)
	}
	sc.poe = keep
}

// pendingMark — метка отозванного по компрометации сертификата: ей нужна
// POE раньше cutoff. link — звено с её токеном (0 — пакет его не показывает),
// gen — её собственное время.
type pendingMark struct {
	link   uint64
	head   uint64 // голова, которую заверяет метка
	gen    time.Time
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
	sc.markNamed(v)
	if err != nil {
		// Пункт, где метка нужна, не проходит; пункт об отзыве — тоже, чтобы
		// не говорить «ни одна метка не на отозванном».
		sc.revoked = append(sc.revoked, fmt.Sprintf("%s: %v", what, err))
		return tsa.Info{}, err
	}
	sc.record(v)
	sc.markSuspect(v)
	if v.NeedPOE {
		sc.pending = append(sc.pending, pendingMark{link: link, head: head, gen: info.GenTime.UTC(), cutoff: v.Cutoff, what: what, why: revokedWhy(v)})
	} else {
		sc.poe = append(sc.poe, poeMark{head: head, at: info.GenTime.UTC(), keys: chainKeys(info.Chains), own: &pendingMark{link: link, head: head, gen: info.GenTime.UTC(), what: what},
			what: fmt.Sprintf("the time-stamp of %q over head %d at %s", info.Signer.Subject.CommonName, head, fmtTime(info.GenTime))})
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

// record — по каким CRL проверено, что не проверено, заметки.
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
		add(&sc.unchecked, tsa.Fingerprint(c))
	}
	for _, s := range v.Notes {
		add(&sc.notes, s)
	}
	sc.markNamed(v)
}

// markNamed — CRL, к которым относится хоть один сертификат меток пакета.
func (sc *stampCheck) markNamed(v tsa.Verdict) {
	if sc.named == nil {
		sc.named = map[string]bool{}
	}
	for _, s := range v.Named {
		sc.named[s] = true
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
	sc.taintOwn()
	if len(sc.pending) > 0 {
		sc.archived(archive, last, rootAt)
		sc.cosigned(cs, keys, storeKey, last, rootAt)
		sc.taintOwn() // метки второй службы могли назвать ещё ключи
	} else {
		sc.nameArchived(archive)
	}
	failed := slices.Clone(sc.revoked)
	var shown []string
	for _, p := range sc.pending {
		m, ok, rejected := sc.poeFor(p)
		switch {
		case ok:
			f := fmt.Sprintf("%s rests on %s, and %s shows it existed before %s", p.what, p.why, m.what, fmtTime(p.cutoff))
			if m.at.Before(p.gen) {
				f += fmt.Sprintf(" (dated %s before the time-stamp: its clock is behind, and it counts from the time of the time-stamp)", p.gen.Sub(m.at).Round(time.Second))
			}
			shown = append(shown, f)
		case p.link == 0:
			failed = append(failed, fmt.Sprintf("%s rests on %s: its time proves nothing, and the bundle does not show where its token lies in the chain, so nothing can show it existed earlier (a bundle from a store of this release with a second TSA or a cosigning witness carries it)", p.what, p.why))
		default:
			f := fmt.Sprintf("%s rests on %s: its time proves nothing, and nothing in the bundle shows it existed before %s — a time-stamp of another TSA or a cosignature of a witness given with -witness-key, over a head at or after link %d and dated earlier", p.what, p.why, fmtTime(p.cutoff), p.link)
			for _, r := range rejected {
				f += "; " + r
			}
			for _, b := range sc.beyond {
				if b.at.Before(p.cutoff) {
					f += "; " + b.text
				}
			}
			failed = append(failed, f)
		}
	}
	var err error
	if len(failed) > 0 {
		err = errors.New(strings.Join(failed, "; "))
	}
	detail := fmt.Sprintf("%d time-stamps, none found revoked", sc.tokens)
	if len(shown) > 0 {
		detail = strings.Join(shown, "; ")
	}
	if n := len(sc.unchecked); n > 0 {
		detail += fmt.Sprintf("; the revocation of %d certificates was not checked (see the notes)", n)
	}
	if len(sc.crls) > 0 {
		detail += "; checked against " + strings.Join(sc.crls, ", ")
	}
	add(revocationCheckName, err, detail)
	for _, l := range sc.revs.CRLs() {
		if !sc.named[l] {
			sc.notes = append(sc.notes, l+" is of no CA in the chains of the time-stamps checked in this bundle: not used")
		}
	}
}

// nameArchived — CRL центров второй службы, когда её метки не понадобились
// (POE не нужна): только чтобы не назвать их CRL посторонними.
func (sc *stampCheck) nameArchived(archive []ArchiveStamp) {
	for _, a := range archive {
		if len(a.Root) != 32 {
			continue
		}
		info, err := tsa.Verify(a.Token, HeadImprint(a.HeadSeq, [32]byte(a.Root)), sc.trust)
		if err != nil {
			continue
		}
		v, _ := sc.revs.Check(info.Chains, info.GenTime)
		sc.markNamed(v)
	}
}

// poeFor — самая ранняя POE для метки p: голова не раньше звена её токена,
// время раньше отсечки, цепочка без ключа под подозрением. Голову с токеном
// не заверить раньше, чем токен выдан: POE с часами, отстающими от метки в
// пределах poeSlack, считается со времени метки, а датированная ещё раньше —
// не в счёт. rejected — что не засчитано и почему, для отчёта.
func (sc *stampCheck) poeFor(p pendingMark) (poeMark, bool, []string) {
	var best *poeMark
	var rejected []string
	if p.link == 0 {
		return poeMark{}, false, nil
	}
	at := func(m poeMark) time.Time {
		if m.at.Before(p.gen) {
			return p.gen
		}
		return m.at
	}
	for i, m := range sc.poe {
		switch {
		case m.head < p.link:
			continue
		case !sc.clean(m):
			rejected = append(rejected, fmt.Sprintf("%s is signed with a key under suspicion in this bundle: not used", m.what))
			continue
		case m.at.Before(p.gen.Add(-poeSlack)):
			rejected = append(rejected, fmt.Sprintf("%s is dated before %s itself (%s): its clock is behind, or it is not what it claims; not used", m.what, p.what, fmtTime(p.gen)))
			continue
		}
		if at(m).Before(p.cutoff) && (best == nil || at(m).Before(at(*best))) {
			best = &sc.poe[i]
		}
	}
	if best == nil {
		return poeMark{}, false, rejected
	}
	return *best, true, nil
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
		sc.markNamed(v)
		sc.markSuspect(v)
		switch {
		case err != nil:
			sc.notes = append(sc.notes, fmt.Sprintf("the archive time-stamp over head %d was not used: %v", a.HeadSeq, err))
			continue
		case v.NeedPOE:
			sc.notes = append(sc.notes, fmt.Sprintf("the archive time-stamp over head %d rests on a revoked certificate itself: not used", a.HeadSeq))
			continue
		}
		sc.record(v)
		sc.poe = append(sc.poe, poeMark{head: a.HeadSeq, at: info.GenTime.UTC(), keys: chainKeys(info.Chains), what: fmt.Sprintf("the archive time-stamp of %q over head %d at %s", info.Signer.Subject.CommonName, a.HeadSeq, fmtTime(info.GenTime))})
	}
}

// cosigned — подписи закреплённых свидетелей как POE: голова в пакете, её
// корень сходится, подпись проходит. Подписи дальше конца пакета не в счёт:
// их корень пакету не сверить, — но называют голову, до которой продлить
// пакет.
func (sc *stampCheck) cosigned(cs []Cosignature, keys []cosign.Verifier, storeKey ed25519.PublicKey, last uint64, rootAt func(uint64) ([32]byte, bool)) {
	if len(storeKey) != ed25519.PublicKeySize {
		return
	}
	origin := OriginFor(storeKey)
	for _, c := range cs {
		if len(c.Root) != 32 || len(c.Sig) < 4 || c.Size == 0 {
			continue
		}
		if r, ok := rootAt(c.Size); c.Size <= last && (!ok || r != [32]byte(c.Root)) {
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
			if c.Size > last {
				// Корень дальше конца пакета не сверить: подсказка, до какой
				// головы просить пакет.
				sc.beyond = append(sc.beyond, beyondCosig{t, fmt.Sprintf("witness %s cosigned head %d at %s, past the end of the bundle: ask for one up to it (evidencestore proof … -to-head %d)", k.Name, c.Size, fmtTime(t), c.Size)})
				continue
			}
			sc.poe = append(sc.poe, poeMark{head: c.Size, at: t, what: fmt.Sprintf("witness %s (key %08x), which cosigned head %d at %s", k.Name, k.ID, c.Size, fmtTime(t))})
		}
	}
}
