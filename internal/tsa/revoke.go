package tsa

import (
	"bytes"
	"crypto/sha256"
	"crypto/x509"
	"encoding/asn1"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"sort"
	"time"
)

// Отзыв сертификатов службы меток (RFC 3161, 2.2 и 4; RFC 5280, 5.3).
//
// Проверяющий приносит сведения об отзыве сам — CRL центров, выпустивших
// сертификаты служб, или свой перечень: проверка офлайн, и о компрометации
// он мог узнать не из CRL. Правило RFC 3161, 4:
//   - сертификат отозван не из-за компрометации ключа (unspecified,
//     affiliationChanged, superseded, cessationOfOperation): метки до даты
//     отзыва в силе, начиная с неё — нет;
//   - из-за компрометации ключа или без причины в записи: времени метки
//     верить нельзя — у кого ключ, тот поставит любое. Метка в силе, только
//     если её существование раньше отсечки показано независимо (POE, ETSI EN
//     319 102-1): поздней меткой другой службы или подписью свидетеля над
//     головой, в которой она лежит. Это решает пакет (internal/proof);
//     отсечка — invalidityDate записи (предполагаемое время компрометации,
//     RFC 5280, 5.3.2), если она раньше даты отзыва.
//
// По CRL отзыв проверяется у каждого сертификата цепочки, кроме корня (его
// закрепляет сам проверяющий); подпись CRL сверяется с выпустившим центром
// из той же цепочки. В своём перечне проверяющий может отозвать и корень.
// Только полные CRL от самого выпустившего центра: дельта-CRL и косвенные
// CRL не разбираются.

// ErrRevoked — метка не в силе по отзыву сертификата её цепочки.
var ErrRevoked = errors.New("tsa: revoked")

// Причины отзыва (RFC 5280, 5.3.1). ReasonAbsent — в записи причины нет.
const (
	ReasonAbsent               = -1
	ReasonUnspecified          = 0
	ReasonKeyCompromise        = 1
	ReasonCACompromise         = 2
	ReasonAffiliationChanged   = 3
	ReasonSuperseded           = 4
	ReasonCessationOfOperation = 5
	ReasonCertificateHold      = 6
	ReasonRemoveFromCRL        = 8
	ReasonPrivilegeWithdrawn   = 9
	ReasonAACompromise         = 10
)

var reasonNames = map[int]string{
	ReasonUnspecified:          "unspecified",
	ReasonKeyCompromise:        "keyCompromise",
	ReasonCACompromise:         "cACompromise",
	ReasonAffiliationChanged:   "affiliationChanged",
	ReasonSuperseded:           "superseded",
	ReasonCessationOfOperation: "cessationOfOperation",
	ReasonCertificateHold:      "certificateHold",
	ReasonRemoveFromCRL:        "removeFromCRL",
	ReasonPrivilegeWithdrawn:   "privilegeWithdrawn",
	ReasonAACompromise:         "aACompromise",
}

// ReasonName — имя причины для отчёта.
func ReasonName(r int) string {
	if r == ReasonAbsent {
		return "no reason given"
	}
	if n, ok := reasonNames[r]; ok {
		return n
	}
	return fmt.Sprintf("reason %d", r)
}

// keepsEarlier — причина, при которой метки до даты отзыва в силе (RFC 3161,
// 4, п. 1). Остальные — и нет причины — п. 2: компрометация или неизвестно.
func keepsEarlier(r int) bool {
	switch r {
	case ReasonUnspecified, ReasonAffiliationChanged, ReasonSuperseded, ReasonCessationOfOperation:
		return true
	}
	return false
}

var (
	oidReasonCode     = asn1.ObjectIdentifier{2, 5, 29, 21}
	oidInvalidityDate = asn1.ObjectIdentifier{2, 5, 29, 24}
)

// Revocation — запись об отзыве одного сертификата.
type Revocation struct {
	Time       time.Time // дата отзыва
	Reason     int
	Invalidity time.Time // invalidityDate; ноль — нет
	From       string    // откуда запись: CRL или перечень проверяющего
}

// Cutoff — с какого момента метки этого ключа под подозрением.
func (r Revocation) Cutoff() time.Time {
	if !r.Invalidity.IsZero() && r.Invalidity.Before(r.Time) {
		return r.Invalidity
	}
	return r.Time
}

type crlFile struct {
	path string
	rl   *x509.RevocationList
	bySN map[string]Revocation // по номеру сертификата
}

// Revocations — что проверяющий знает об отзыве.
type Revocations struct {
	crls   []crlFile
	listed map[[32]byte]Revocation // по SHA-256 сертификата (DER)
	// Now — момент проверки: с ним сверяется свежесть CRL (nextUpdate).
	Now time.Time
}

// NewRevocations — пустые сведения на момент now.
func NewRevocations(now time.Time) *Revocations {
	return &Revocations{listed: map[[32]byte]Revocation{}, Now: now}
}

// AddCRL разбирает CRL (DER или PEM). Подпись сверяется при проверке метки:
// выпустивший центр — в её цепочке.
func (r *Revocations) AddCRL(path string) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("tsa: crl: %w", err)
	}
	der := data
	if b, _ := pem.Decode(data); b != nil {
		if b.Type != "X509 CRL" {
			return fmt.Errorf("tsa: crl %s: a PEM block %q, not X509 CRL", path, b.Type)
		}
		der = b.Bytes
	}
	rl, err := x509.ParseRevocationList(der)
	if err != nil {
		return fmt.Errorf("tsa: crl %s: %w", path, err)
	}
	f := crlFile{path: path, rl: rl, bySN: map[string]Revocation{}}
	from := fmt.Sprintf("CRL %s of %s", path, rl.ThisUpdate.UTC().Format(time.RFC3339))
	for _, e := range rl.RevokedCertificateEntries {
		rev := Revocation{Time: e.RevocationTime.UTC(), Reason: ReasonAbsent, From: from}
		for _, x := range e.Extensions {
			switch {
			case x.Id.Equal(oidReasonCode):
				// Присутствие причины значимо само (RFC 3161, 4): без неё не
				// в силе ни одна метка ключа, а x509 не отличает отсутствие
				// от unspecified.
				var code asn1.Enumerated
				if rest, err := asn1.Unmarshal(x.Value, &code); err != nil || len(rest) != 0 {
					return fmt.Errorf("tsa: crl %s: the reason code of serial %s does not parse", path, e.SerialNumber)
				}
				rev.Reason = int(code)
			case x.Id.Equal(oidInvalidityDate):
				var t time.Time
				if rest, err := asn1.UnmarshalWithParams(x.Value, &t, "generalized"); err != nil || len(rest) != 0 {
					return fmt.Errorf("tsa: crl %s: the invalidity date of serial %s does not parse", path, e.SerialNumber)
				}
				rev.Invalidity = t.UTC()
			}
		}
		if rev.Reason == ReasonRemoveFromCRL {
			continue // снят с удержания (дельта-CRL): не отозван
		}
		f.bySN[e.SerialNumber.String()] = rev
	}
	r.crls = append(r.crls, f)
	return nil
}

// AddList читает перечень проверяющего (JSON): сертификаты, которые он
// считает отозванными, — служба не публикует CRL, или о компрометации он
// узнал сам. reason — имя причины RFC 5280 (keyCompromise, superseded, …),
// пусто — причины нет; invalidity — предполагаемое время компрометации.
//
//	[{"cert_sha256": "<hex SHA-256 of the DER>", "revoked": "2026-11-01T00:00:00Z", "reason": "keyCompromise"}]
func (r *Revocations) AddList(path string) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("tsa: revoked list: %w", err)
	}
	var items []struct {
		Cert       string     `json:"cert_sha256"`
		Revoked    time.Time  `json:"revoked"`
		Reason     string     `json:"reason"`
		Invalidity *time.Time `json:"invalidity"`
	}
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&items); err != nil {
		return fmt.Errorf("tsa: revoked list %s: %w", path, err)
	}
	for i, it := range items {
		fp, err := hex.DecodeString(it.Cert)
		if err != nil || len(fp) != sha256.Size {
			return fmt.Errorf("tsa: revoked list %s, entry %d: cert_sha256 must be 64 hex digits of the certificate's SHA-256", path, i)
		}
		if it.Revoked.IsZero() {
			return fmt.Errorf("tsa: revoked list %s, entry %d: no revoked time", path, i)
		}
		rev := Revocation{Time: it.Revoked.UTC(), Reason: ReasonAbsent, From: "list " + path}
		if it.Reason != "" {
			rev.Reason = -2
			for code, name := range reasonNames {
				if name == it.Reason && code != ReasonRemoveFromCRL {
					rev.Reason = code
				}
			}
			if rev.Reason == -2 {
				return fmt.Errorf("tsa: revoked list %s, entry %d: reason %q is not one of RFC 5280 (keyCompromise, cACompromise, superseded, cessationOfOperation, …)", path, i, it.Reason)
			}
		}
		if it.Invalidity != nil {
			rev.Invalidity = it.Invalidity.UTC()
		}
		r.listed[[32]byte(fp)] = rev
	}
	return nil
}

// Verdict — что отзыв значит для одной метки.
type Verdict struct {
	// Revoked — отозванный сертификат цепочки с самой ранней отсечкой; nil —
	// не отозван ни один (или отозван раньше времени метки по причине без
	// компрометации).
	Revoked *x509.Certificate
	Entry   Revocation
	// NeedPOE — время метки ничего не доказывает (компрометация или нет
	// причины): метка в силе, только если её существование раньше Cutoff
	// показано независимо.
	NeedPOE bool
	Cutoff  time.Time
	// Unchecked — сертификаты цепочки, кроме корня, для чьих центров нет CRL:
	// их отзыв не проверен (перечень проверяющего полноты не обещает).
	Unchecked []*x509.Certificate
	// CRLs — по каким CRL проверено; Stale — те из них, чей nextUpdate
	// прошёл: отзыв после их thisUpdate не виден. Foreign — CRL с именем
	// центра цепочки, чья подпись с его ключом не сходится: это CRL другого
	// центра с тем же именем (или испорченный), по нему не проверено.
	CRLs, Stale, Foreign []string
}

// Check сверяет цепочки проверенного токена (Info.Chains) с отзывом. Ошибка
// (ErrRevoked) — метка не в силе: сертификат цепочки отозван без
// компрометации не позже её времени. Из нескольких цепочек берётся лучшая.
func (r *Revocations) Check(chains [][]*x509.Certificate, gen time.Time) (Verdict, error) {
	var best *Verdict
	var firstErr error
	for _, chain := range chains {
		v, err := r.checkChain(chain, gen)
		if err != nil {
			if firstErr == nil {
				firstErr = err
			}
			continue
		}
		if best == nil || v.better(*best) {
			best = &v
		}
	}
	switch {
	case best != nil:
		return *best, nil
	case firstErr != nil:
		return Verdict{}, firstErr
	}
	return Verdict{}, fmt.Errorf("%w: no certificate chain to check", ErrRevoked)
}

// better — цепочка без подозрения лучше; из подозрительных — с поздней
// отсечкой; при равных — с меньшим непроверенным.
func (v Verdict) better(o Verdict) bool {
	switch {
	case v.NeedPOE != o.NeedPOE:
		return !v.NeedPOE
	case v.NeedPOE && !v.Cutoff.Equal(o.Cutoff):
		return v.Cutoff.After(o.Cutoff)
	}
	return len(v.Unchecked) < len(o.Unchecked)
}

func (r *Revocations) checkChain(chain []*x509.Certificate, gen time.Time) (Verdict, error) {
	var v Verdict
	for i, c := range chain {
		var entries []Revocation
		if e, ok := r.listed[sha256.Sum256(c.Raw)]; ok {
			entries = append(entries, e)
		}
		if i < len(chain)-1 {
			e, found, from, stale, foreign := r.fromCRL(c, chain[i+1])
			v.Foreign = append(v.Foreign, foreign...)
			switch {
			case from == "":
				v.Unchecked = append(v.Unchecked, c)
			default:
				v.CRLs = append(v.CRLs, from)
				if stale {
					v.Stale = append(v.Stale, from)
				}
			}
			if found {
				entries = append(entries, e)
			}
		}
		for _, e := range entries {
			if keepsEarlier(e.Reason) {
				if !gen.Before(e.Time) {
					return Verdict{}, fmt.Errorf("%w: certificate %q was revoked on %s (%s; %s), and the time-stamp is of %s, not earlier: RFC 3161 keeps only the time-stamps made before such a revocation", ErrRevoked, c.Subject.String(), e.Time.Format(time.RFC3339), ReasonName(e.Reason), e.From, gen.UTC().Format(time.RFC3339))
				}
				continue
			}
			if cut := e.Cutoff(); !v.NeedPOE || cut.Before(v.Cutoff) {
				v.NeedPOE, v.Cutoff, v.Revoked, v.Entry = true, cut, c, e
			}
		}
	}
	return v, nil
}

// fromCRL — запись о сертификате c в самом свежем CRL его центра issuer,
// чья подпись с ним сходится. from — какой CRL (пусто — CRL этого центра
// нет: отзыв c не проверен); stale — его nextUpdate прошёл; foreign — CRL с
// именем этого центра, но не его подписью: не его CRL, по нему не судим.
func (r *Revocations) fromCRL(c, issuer *x509.Certificate) (e Revocation, found bool, from string, stale bool, foreign []string) {
	var named []crlFile
	for _, f := range r.crls {
		if bytes.Equal(f.rl.RawIssuer, c.RawIssuer) {
			named = append(named, f)
		}
	}
	sort.SliceStable(named, func(i, j int) bool { return named[i].rl.ThisUpdate.After(named[j].rl.ThisUpdate) })
	for _, f := range named {
		if f.rl.CheckSignatureFrom(issuer) != nil {
			foreign = append(foreign, fmt.Sprintf("CRL %s names the issuer %q, but does not verify with its certificate in the chain of the time-stamp", f.path, issuer.Subject.String()))
			continue
		}
		from = fmt.Sprintf("CRL %s of %s", f.path, f.rl.ThisUpdate.UTC().Format(time.RFC3339))
		stale = f.rl.NextUpdate.IsZero() || !r.Now.Before(f.rl.NextUpdate)
		e, found = f.bySN[c.SerialNumber.String()]
		return e, found, from, stale, nil
	}
	return e, false, "", false, foreign
}

// Fingerprint — SHA-256 сертификата для перечня проверяющего (cert_sha256).
func Fingerprint(c *x509.Certificate) string {
	sum := sha256.Sum256(c.Raw)
	return hex.EncodeToString(sum[:])
}
