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
// Все метки пакета — свои и второй службы — судятся вместе (tsa.Assessment):
// компрометация — свойство ключа, и запись о ней у любого сертификата ключа в
// любой цепочке любой метки пакета ставит под подозрение каждую метку, чьи
// цепочки все несут этот ключ, с самой ранней отсечкой ключа. Отозванная без
// компрометации не позже её времени — метка не в силе, и пункт, где она
// нужна, не проходит. Под подозрением — время метки ничего не доказывает, и
// метка в силе, только если пакет показывает, что она существовала раньше
// отсечки (POE, ETSI EN 319 102-1): метка не под подозрением над головой не
// раньше звена с её токеном и со временем раньше отсечки — своя метка пакета,
// метка второй службы (Archive: tsa.archive хранилища) или подпись
// закреплённого свидетеля C2SP. Поздняя метка другой службы над головой, в
// которой лежит токен, — та самая переметка RFC 4998: задним числом её не
// поставить без её собственного ключа. Время POE — не раньше времени самой
// метки: голову с токеном не заверить раньше токена, и POE с отстающими
// часами считается со времени метки.

// ArchiveStamp — метка второй службы над головой цепи (tsa.archive
// хранилища): всё до этой головы, токены основной службы тоже, существовало
// ко времени метки. Голова может лежать дальше конца пакета: тогда её корень
// сверяется доказательством продолжения от последнего звена пакета (Proof),
// без звеньев между ними.
//
// Cert — сертификат, которым подписан токен (DER), когда служба не кладёт его
// в токен: журнал второй службы его хранит. Не подписан, как и поле
// certificates в токене: подпись токена сверяется с ним, а путь — до корня
// проверяющего.
type ArchiveStamp struct {
	HeadSeq uint64   `json:"head_seq"`
	Root    []byte   `json:"root"`
	Proof   [][]byte `json:"proof,omitempty"`
	Token   []byte   `json:"token"`
	Cert    []byte   `json:"cert,omitempty"`
}

// revocationCheckName — пункт отчёта об отзыве.
const revocationCheckName = "no time-stamp rests on a revoked TSA certificate, or each such one is shown to exist before the revocation"

// RevocationNotChecked — заметка, когда сведений об отзыве не дали.
const RevocationNotChecked = "the revocation of the TSA certificates was not checked: pass the CRLs of their CAs with -tsa-crl, or your own list with -tsa-revoked; a time-stamp made with a TSA key stolen later passes without it"

// stampCheck — проверка меток одного пакета с учётом отзыва.
type stampCheck struct {
	trust     tsa.Trust
	revs      *tsa.Revocations
	as        *tsa.Assessment // все метки пакета, судимые вместе
	tokens    int
	own       []ownStamp
	poe       []poeMark
	weak      []poeMark // метки, чей собственный отзыв не проверен: не POE
	pending   []pendingMark
	revoked   []string // метки, отозванные без компрометации не позже их времени
	crls      []string
	unchecked []string        // отпечатки сертификатов, чей отзыв не проверен
	beyond    []beyondCosig   // подписи свидетелей дальше конца пакета: куда его продлить
	named     map[string]bool // CRL, которые назвал центр в цепочке какой-то метки
	notes     []string
}

// ownStamp — своя метка пакета в оценке: номер в ней, где лежит токен и как
// метка называется.
type ownStamp struct {
	id   int
	mark pendingMark // без отсечки и причины: их даст вердикт
	poe  string      // как она называется, когда сама — POE
}

// poeMark — что показывает существование всего до головы head ко времени at.
type poeMark struct {
	head uint64
	at   time.Time
	what string
}

// beyondCosig — подпись свидетеля над головой дальше конца пакета.
type beyondCosig struct {
	at   time.Time
	text string
}

// pendingMark — метка под подозрением: ей нужна POE раньше cutoff. link —
// звено с её токеном (0 — пакет его не показывает), gen — её собственное
// время.
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
// метка, для отчёта. Ошибка — и когда метка отозвана без компрометации не
// позже её времени: это от других меток не зависит. Подозрение на её ключ
// судится в finish, по всему пакету.
func (sc *stampCheck) verify(token []byte, head uint64, root [32]byte, link uint64, what string) (tsa.Info, error) {
	info, err := tsa.Verify(token, HeadImprint(head, root), sc.trust)
	if err != nil {
		return info, err
	}
	sc.tokens++
	if sc.revs == nil {
		return info, nil
	}
	sc.ensureAssessment()
	sc.as.Known(info.Certs...)
	id, err := sc.as.Add(info.Chains, info.GenTime)
	if err != nil {
		// Пункт, где метка нужна, не проходит; пункт об отзыве — тоже, чтобы
		// не говорить «ни одна метка не на отозванном».
		sc.revoked = append(sc.revoked, fmt.Sprintf("%s: %v", what, err))
		return tsa.Info{}, err
	}
	sc.own = append(sc.own, ownStamp{id: id,
		mark: pendingMark{link: link, head: head, gen: info.GenTime.UTC(), what: what},
		poe:  fmt.Sprintf("the time-stamp of %q over head %d at %s", info.Signer.Subject.CommonName, head, fmtTime(info.GenTime))})
	return info, nil
}

// ensureAssessment — оценка отзыва пакета; сертификаты, которые проверяющий
// дал в -tsa-trust, входят в неё сразу: ключ перевыпущенного сертификата
// судится и тогда, когда цепочки меток через него не идут.
func (sc *stampCheck) ensureAssessment() {
	if sc.as == nil {
		sc.as = sc.revs.NewAssessment()
		sc.as.KnownTrusted(sc.trust.Intermediates...)
		sc.as.KnownTrusted(sc.trust.RootCerts...)
	}
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
}

// archiveCheck — метка второй службы пакета: номер в оценке и почему она не
// POE (пусто — годна, если сама не под подозрением).
type archiveCheck struct {
	a   ArchiveStamp
	id  int
	at  time.Time
	cn  string
	why string
}

// finish — пункт отчёта об отзыве. Метки второй службы, что проходят Verify,
// входят в оценку всегда: ключи их цепочек судятся вместе со своими, даже
// когда POE не понадобится. Затем вердикты всех меток пакета: своя под
// подозрением ищет POE — свою метку не под подозрением, метку второй службы,
// подпись закреплённого свидетеля. last — последнее звено пакета, rootAt —
// корни дерева на звеньях пакета. Без сведений об отзыве пункта нет, а
// заметка говорит, что отзыв не проверен.
func (sc *stampCheck) finish(archive []ArchiveStamp, cs []Cosignature, keys []cosign.Verifier, storeKey ed25519.PublicKey, last uint64, rootAt func(uint64) ([32]byte, bool), add func(string, error, string) bool) {
	if sc.revs == nil {
		if sc.tokens > 0 {
			sc.notes = append(sc.notes, RevocationNotChecked)
		}
		return
	}
	sc.ensureAssessment()
	archs := sc.archived(archive, last, rootAt)
	vs := sc.as.Verdicts()
	sc.markNamed(sc.as.Named())
	for _, o := range sc.own {
		v := vs[o.id]
		sc.record(v)
		if v.Retired != nil {
			// Не в силе по записям, которые видны только всей оценке (CRL
			// под новым ключом центра): как отзыв до её времени в verify.
			sc.revoked = append(sc.revoked, fmt.Sprintf("%s: %v", o.mark.what, v.Retired))
			continue
		}
		if v.NeedPOE {
			p := o.mark
			p.cutoff, p.why = v.Cutoff, revokedWhy(v)
			sc.pending = append(sc.pending, p)
			continue
		}
		sc.addPOE(v, poeMark{head: o.mark.head, at: o.mark.gen, what: o.poe})
	}
	if len(sc.pending) > 0 {
		for _, a := range archs {
			if a.why != "" {
				sc.notes = append(sc.notes, a.why)
				continue
			}
			if v := vs[a.id]; v.Retired != nil {
				sc.notes = append(sc.notes, fmt.Sprintf("the archive time-stamp over head %d was not used: %v", a.a.HeadSeq, v.Retired))
			} else if v.NeedPOE {
				sc.notes = append(sc.notes, fmt.Sprintf("the archive time-stamp over head %d rests on %s itself: not used", a.a.HeadSeq, revokedWhy(v)))
			} else {
				sc.record(v)
				sc.addPOE(v, poeMark{head: a.a.HeadSeq, at: a.at, what: fmt.Sprintf("the archive time-stamp of %q over head %d at %s", a.cn, a.a.HeadSeq, fmtTime(a.at))})
			}
		}
		sc.cosigned(cs, keys, storeKey, last, rootAt)
	}
	failed := slices.Clone(sc.revoked)
	var shown []string
	for _, p := range sc.pending {
		m, ok := sc.poeFor(p)
		switch {
		case ok:
			f := fmt.Sprintf("%s rests on %s, and %s shows it existed before %s", p.what, p.why, m.what, fmtTime(p.cutoff))
			if d := p.gen.Sub(m.at).Round(time.Second); d > 0 {
				f += fmt.Sprintf(" (dated %s before the time-stamp: its clock is behind, and it counts from the time of the time-stamp)", d)
			}
			shown = append(shown, f)
		case p.link == 0:
			failed = append(failed, fmt.Sprintf("%s rests on %s: its time proves nothing, and the bundle does not show where its token lies in the chain, so nothing can show it existed earlier (a bundle from a store of this release with a second TSA or a cosigning witness carries it)", p.what, p.why))
		default:
			f := fmt.Sprintf("%s rests on %s: its time proves nothing, and nothing in the bundle shows it existed before %s — a time-stamp of another TSA or a cosignature of a witness given with -witness-key, over a head at or after link %d and dated earlier", p.what, p.why, fmtTime(p.cutoff), p.link)
			if w, ok := poeIn(sc.weak, p); ok {
				f += fmt.Sprintf("; %s would show it, but the revocation of its own certificate was not checked (see the notes), and a time-stamp shows the time of another only when its own certificate is known not to be revoked (ETSI EN 319 102-1): pass the CRL of its CA with -tsa-crl", w.what)
			}
			for _, b := range sc.beyond {
				if laterOf(b.at, p.gen).Before(p.cutoff) {
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
	if len(sc.unchecked) > 0 {
		detail = fmt.Sprintf("%d time-stamps, none found revoked among the certificates checked", sc.tokens)
	}
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

// markNamed — CRL, к которым относится хоть один сертификат меток пакета.
func (sc *stampCheck) markNamed(named []string) {
	if sc.named == nil {
		sc.named = map[string]bool{}
	}
	for _, s := range named {
		sc.named[s] = true
	}
}

// laterOf — более позднее из двух времён.
func laterOf(a, b time.Time) time.Time {
	if a.Before(b) {
		return b
	}
	return a
}

// poeFor — самая ранняя POE для метки p: голова не раньше звена её токена,
// время раньше отсечки. Голову с токеном не заверить раньше, чем токен выдан:
// POE с отстающими часами считается со времени метки (метка, чьё время позже
// отсечки, так не спасается ничем). Отвергать POE за отставание незачем:
// время метки под подозрением выбирает тот, у кого ключ.
func (sc *stampCheck) poeFor(p pendingMark) (poeMark, bool) { return poeIn(sc.poe, p) }

// poeIn — самая ранняя из marks, что показала бы существование p раньше
// отсечки.
func poeIn(marks []poeMark, p pendingMark) (poeMark, bool) {
	if p.link == 0 {
		return poeMark{}, false
	}
	var best *poeMark
	for i, m := range marks {
		at := laterOf(m.at, p.gen)
		if m.head >= p.link && at.Before(p.cutoff) && (best == nil || at.Before(laterOf(best.at, p.gen))) {
			best = &marks[i]
		}
	}
	if best == nil {
		return poeMark{}, false
	}
	return *best, true
}

// addPOE — метка не под подозрением как POE: только если отзыв её
// собственных сертификатов проверен (ETSI EN 319 102-1: POE даёт метка,
// прошедшая проверку). Непроверенная — в weak, отчёт её назовёт.
func (sc *stampCheck) addPOE(v tsa.Verdict, m poeMark) {
	if len(v.Unchecked) > 0 {
		sc.weak = append(sc.weak, m)
		return
	}
	sc.poe = append(sc.poe, m)
}

// archived — метки второй службы пакета: токен проходит Verify — метка входит
// в оценку (её ключи судятся вместе со всеми); голова сходится с пакетом
// (корень на звене пакета или доказательство продолжения от его последнего
// звена) — может быть POE. Не сошлась — заметка, не провал: метка второй
// службы пакету не обязательна. Заметки — только когда POE понадобилась.
func (sc *stampCheck) archived(archive []ArchiveStamp, last uint64, rootAt func(uint64) ([32]byte, bool)) []archiveCheck {
	var out []archiveCheck
	for _, a := range archive {
		if len(a.Root) != 32 {
			out = append(out, archiveCheck{a: a, id: -1, why: fmt.Sprintf("the archive time-stamp over head %d names a root of %d bytes: not used", a.HeadSeq, len(a.Root))})
			continue
		}
		root := [32]byte(a.Root)
		trust := sc.trust
		var carried *x509.Certificate
		if len(a.Cert) > 0 {
			c, err := x509.ParseCertificate(a.Cert)
			if err != nil {
				out = append(out, archiveCheck{a: a, id: -1, why: fmt.Sprintf("the archive time-stamp over head %d carries a certificate that does not parse (%v): not used", a.HeadSeq, err)})
				continue
			}
			carried = c
			trust.Intermediates = append(slices.Clone(trust.Intermediates), c)
		}
		info, err := tsa.Verify(a.Token, HeadImprint(a.HeadSeq, root), trust)
		if err != nil {
			hint := "is the root of that TSA in -tsa-trust?"
			if errors.Is(err, tsa.ErrNoSigner) {
				hint = "that TSA does not put its certificate in its time-stamps, and the bundle does not carry it: pass that certificate in -tsa-trust"
			}
			out = append(out, archiveCheck{a: a, id: -1, why: fmt.Sprintf("the archive time-stamp over head %d was not used: %v (%s)", a.HeadSeq, err, hint)})
			continue
		}
		sc.as.Known(info.Certs...)
		if carried != nil {
			sc.as.Known(carried)
		}
		id, err := sc.as.Add(info.Chains, info.GenTime)
		if err != nil {
			out = append(out, archiveCheck{a: a, id: -1, why: fmt.Sprintf("the archive time-stamp over head %d was not used: %v", a.HeadSeq, err)})
			continue
		}
		ac := archiveCheck{a: a, id: id, at: info.GenTime.UTC(), cn: info.Signer.Subject.CommonName}
		if a.HeadSeq <= last {
			if r, ok := rootAt(a.HeadSeq); !ok || r != root || len(a.Proof) != 0 {
				ac.why = fmt.Sprintf("the archive time-stamp over head %d does not agree with the chain in the bundle: not used", a.HeadSeq)
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
				ac.why = fmt.Sprintf("the archive time-stamp over head %d: its head does not extend the chain in the bundle: not used", a.HeadSeq)
			}
		}
		out = append(out, ac)
	}
	return out
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
