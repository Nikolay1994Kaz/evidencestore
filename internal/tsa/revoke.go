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
	"io"
	"os"
	"slices"
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
// Только полные CRL от самого выпустившего центра: дельта-CRL, косвенный CRL
// и CRL с критичным расширением, которое здесь не разбирается, — отказ при
// чтении (RFC 5280, 5.2: такой CRL для проверки не годится), а не молчаливая
// проверка по неполному списку. Записи всех CRL центра действуют вместе:
// отзыв необратим (удержание снимает только более новый CRL), а истёкший
// сертификат центр вправе убрать из поздних CRL (RFC 5280, 3.3). О нынешнем
// статусе сертификата говорит самый свежий CRL, который его покрывает
// (issuingDistributionPoint) и выпущен до его истечения или держит истёкшие
// (expiredCertsOnCRL); нет такого — отзыв не проверен, и отчёт это говорит.
// Компрометация — свойство ключа: она переходит на сертификаты с тем же
// ключом в других цепочках метки.

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
	oidDeltaCRL       = asn1.ObjectIdentifier{2, 5, 29, 27}
	oidIssuingDP      = asn1.ObjectIdentifier{2, 5, 29, 28}
	oidCertIssuer     = asn1.ObjectIdentifier{2, 5, 29, 29}
	oidExpiredCerts   = asn1.ObjectIdentifier{2, 5, 29, 60} // expiredCertsOnCRL (X.509)
	oidFreshestCRL    = asn1.ObjectIdentifier{2, 5, 29, 46}
)

// keyCompromised — причина, которая говорит о краже ключа (службы, центра,
// органа атрибутов): подозрение переходит на любой сертификат с тем же
// ключом — перекрёстный сертификат центра, выпущенный другим корнем.
func keyCompromised(r int) bool {
	return r == ReasonKeyCompromise || r == ReasonCACompromise || r == ReasonAACompromise
}

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
	name  string // путь; с номером, если в файле несколько CRL
	rl    *x509.RevocationList
	bySN  map[string]Revocation // по номеру сертификата
	scope *crlScope             // issuingDistributionPoint; nil — все сертификаты центра
	// expired — expiredCertsOnCRL: CRL держит и сертификаты, истёкшие с
	// этого момента; ноль — нет.
	expired time.Time
	// deltas — CRL называет дельта-CRL (freshestCRL): отзывы после его
	// thisUpdate центр публикует в них, а их esverify не читает.
	deltas bool
}

func (f *crlFile) label() string {
	return fmt.Sprintf("CRL %s of %s", f.name, f.rl.ThisUpdate.UTC().Format(time.RFC3339))
}

// newer — f выпущен позже g (при равном thisUpdate — по номеру CRL).
func (f *crlFile) newer(g *crlFile) bool {
	if !f.rl.ThisUpdate.Equal(g.rl.ThisUpdate) {
		return f.rl.ThisUpdate.After(g.rl.ThisUpdate)
	}
	return f.rl.Number != nil && g.rl.Number != nil && f.rl.Number.Cmp(g.rl.Number) > 0
}

// speaks — говорит ли CRL о нынешнем статусе c: c в его области, и CRL
// выпущен до истечения c или держит истёкшие (запись истёкшего центр вправе
// убрать, RFC 5280, 3.3).
func (f *crlFile) speaks(c *x509.Certificate) bool {
	if !f.scope.covers(c) {
		return false
	}
	return !c.NotAfter.Before(f.rl.ThisUpdate) || !f.expired.IsZero() && !f.expired.After(c.NotAfter)
}

// crlScope — какие сертификаты центра покрывает CRL с issuingDistributionPoint
// (RFC 5280, 5.2.5): по нему отзыв проверен только у них.
type crlScope struct {
	uris     []string // точка распространения: fullName, URI
	otherDP  bool     // точка названа не URI — не сверить с сертификатом
	onlyUser bool
	onlyCA   bool
	onlyAttr bool
	some     bool // onlySomeReasons: не все причины
}

// idpASN1 — IssuingDistributionPoint. Точка — CHOICE, поэтому её [0] явный:
// DP — обёртка [0], внутри — fullName [0] или nameRelativeToCRLIssuer [1].
type idpASN1 struct {
	DP       asn1.RawValue  `asn1:"optional,tag:0"`
	OnlyUser bool           `asn1:"optional,tag:1"`
	OnlyCA   bool           `asn1:"optional,tag:2"`
	Some     asn1.BitString `asn1:"optional,tag:3"`
	Indirect bool           `asn1:"optional,tag:4"`
	OnlyAttr bool           `asn1:"optional,tag:5"`
}

// parseScope разбирает issuingDistributionPoint. indirect — косвенный CRL.
func parseScope(der []byte) (sc *crlScope, indirect bool, err error) {
	var idp idpASN1
	if rest, err := asn1.Unmarshal(der, &idp); err != nil || len(rest) != 0 {
		return nil, false, errors.New("the issuing distribution point does not parse")
	}
	sc = &crlScope{onlyUser: idp.OnlyUser, onlyCA: idp.OnlyCA, onlyAttr: idp.OnlyAttr, some: idp.Some.BitLength > 0}
	if len(idp.DP.FullBytes) > 0 {
		// fullName [0] GeneralNames — URI [6]; nameRelativeToCRLIssuer [1] и
		// прочие имена с сертификатом не сверить.
		var name asn1.RawValue
		if rest, err := asn1.Unmarshal(idp.DP.Bytes, &name); err != nil || len(rest) != 0 || !idp.DP.IsCompound {
			return nil, false, errors.New("the issuing distribution point does not parse")
		}
		if name.Class != asn1.ClassContextSpecific || name.Tag != 0 || !name.IsCompound {
			sc.otherDP = true
			return sc, idp.Indirect, nil
		}
		for rest := name.Bytes; len(rest) > 0; {
			var gn asn1.RawValue
			if rest, err = asn1.Unmarshal(rest, &gn); err != nil {
				return nil, false, errors.New("the issuing distribution point does not parse")
			}
			if gn.Class == asn1.ClassContextSpecific && gn.Tag == 6 && !gn.IsCompound {
				sc.uris = append(sc.uris, string(gn.Bytes))
			} else {
				sc.otherDP = true
			}
		}
	}
	return sc, idp.Indirect, nil
}

// covers — покрывает ли CRL сертификат c: без issuingDistributionPoint —
// любой сертификат центра; с ним — только своей части (RFC 5280, 6.3.3 b).
func (sc *crlScope) covers(c *x509.Certificate) bool {
	switch {
	case sc == nil:
		return true
	case sc.onlyAttr, sc.some, sc.onlyUser && c.IsCA, sc.onlyCA && !c.IsCA:
		return false
	case len(sc.uris) == 0 && !sc.otherDP:
		return true
	case sc.otherDP:
		return false
	}
	for _, u := range c.CRLDistributionPoints {
		if slices.Contains(sc.uris, u) {
			return true
		}
	}
	return false
}

// Revocations — что проверяющий знает об отзыве.
type Revocations struct {
	crls   []*crlFile
	listed map[[32]byte][]Revocation // по SHA-256 сертификата (DER)
	lists  int                       // сколько перечней прочитано
	// Now — момент проверки: с ним сверяется свежесть CRL (nextUpdate).
	Now time.Time
}

// NewRevocations — пустые сведения на момент now.
func NewRevocations(now time.Time) *Revocations {
	return &Revocations{listed: map[[32]byte][]Revocation{}, Now: now}
}

// AddCRL разбирает файл CRL: DER или PEM, один CRL или несколько подряд.
// Подпись сверяется при проверке метки: выпустивший центр — в её цепочке.
func (r *Revocations) AddCRL(path string) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("tsa: crl: %w", err)
	}
	ders, err := crlBlocks(data)
	if err != nil {
		return fmt.Errorf("tsa: crl %s: %w", path, err)
	}
	for i, der := range ders {
		name := path
		if len(ders) > 1 {
			name = fmt.Sprintf("%s (#%d)", path, i+1)
		}
		f, err := parseCRL(name, der)
		if err != nil {
			return err
		}
		r.crls = append(r.crls, f)
	}
	return nil
}

// crlBlocks — CRL файла: блоки PEM подряд (все — X509 CRL) или DER подряд.
func crlBlocks(data []byte) ([][]byte, error) {
	var out [][]byte
	if b, rest := pem.Decode(data); b != nil {
		for ; b != nil; b, rest = pem.Decode(rest) {
			if b.Type != "X509 CRL" {
				return nil, fmt.Errorf("a PEM block %q, not X509 CRL", b.Type)
			}
			out = append(out, b.Bytes)
		}
		if len(bytes.TrimSpace(rest)) != 0 {
			return nil, fmt.Errorf("data after PEM block #%d is not a PEM block", len(out))
		}
		return out, nil
	}
	for rest := data; len(rest) > 0; {
		var v asn1.RawValue
		next, err := asn1.Unmarshal(rest, &v)
		if err != nil {
			if len(out) == 0 {
				return nil, fmt.Errorf("neither DER nor PEM: %v", err)
			}
			return nil, fmt.Errorf("data after CRL #%d is not a CRL: %v", len(out), err)
		}
		out = append(out, v.FullBytes)
		rest = next
	}
	if len(out) == 0 {
		return nil, errors.New("the file is empty")
	}
	return out, nil
}

// parseCRL разбирает один CRL. Расширения (RFC 5280, 5.2 и 5.3): дельта и
// косвенный не годятся — по ним неотозванный сертификат не отличить от
// отозванного в другом CRL; иное критичное, которое здесь не разбирается, —
// тоже.
func parseCRL(name string, der []byte) (*crlFile, error) {
	rl, err := x509.ParseRevocationList(der)
	if err != nil {
		return nil, fmt.Errorf("tsa: crl %s: %w", name, err)
	}
	f := &crlFile{name: name, rl: rl, bySN: map[string]Revocation{}}
	for _, x := range rl.Extensions {
		switch {
		case x.Id.Equal(oidDeltaCRL):
			return nil, fmt.Errorf("tsa: crl %s is a delta CRL (RFC 5280, 5.2.4): it lists only what changed since a full CRL and is not supported; pass the full CRL of that CA", name)
		case x.Id.Equal(oidIssuingDP):
			sc, indirect, err := parseScope(x.Value)
			if err != nil {
				return nil, fmt.Errorf("tsa: crl %s: %v", name, err)
			}
			if indirect {
				return nil, fmt.Errorf("tsa: crl %s is an indirect CRL (RFC 5280, 5.2.5): it is not supported; pass the CRL the CA that issued the certificate signed itself", name)
			}
			f.scope = sc
		case x.Id.Equal(oidFreshestCRL):
			f.deltas = true
		case x.Id.Equal(oidExpiredCerts):
			var t time.Time
			if rest, err := asn1.UnmarshalWithParams(x.Value, &t, "generalized"); err != nil || len(rest) != 0 {
				return nil, fmt.Errorf("tsa: crl %s: expiredCertsOnCRL does not parse", name)
			}
			f.expired = t.UTC()
		case x.Critical:
			return nil, fmt.Errorf("tsa: crl %s has a critical extension %s that esverify cannot process (RFC 5280, 5.2: such a CRL must not be used)", name, x.Id)
		}
	}
	from := f.label()
	for _, e := range rl.RevokedCertificateEntries {
		rev := Revocation{Time: e.RevocationTime.UTC(), Reason: ReasonAbsent, From: from}
		for _, x := range e.Extensions {
			switch {
			case x.Id.Equal(oidCertIssuer):
				return nil, fmt.Errorf("tsa: crl %s: the entry of serial %s names another issuer (certificateIssuer): an indirect CRL is not supported", name, e.SerialNumber)
			case x.Id.Equal(oidReasonCode):
				// Присутствие причины значимо само (RFC 3161, 4): без неё не
				// в силе ни одна метка ключа, а x509 не отличает отсутствие
				// от unspecified.
				var code asn1.Enumerated
				if rest, err := asn1.Unmarshal(x.Value, &code); err != nil || len(rest) != 0 {
					return nil, fmt.Errorf("tsa: crl %s: the reason code of serial %s does not parse", name, e.SerialNumber)
				}
				rev.Reason = int(code)
			case x.Id.Equal(oidInvalidityDate):
				var t time.Time
				if rest, err := asn1.UnmarshalWithParams(x.Value, &t, "generalized"); err != nil || len(rest) != 0 {
					return nil, fmt.Errorf("tsa: crl %s: the invalidity date of serial %s does not parse", name, e.SerialNumber)
				}
				rev.Invalidity = t.UTC()
			case x.Critical:
				return nil, fmt.Errorf("tsa: crl %s: the entry of serial %s has a critical extension %s that esverify cannot process (RFC 5280, 5.3: such a CRL must not be used)", name, e.SerialNumber, x.Id)
			}
		}
		if rev.Reason == ReasonRemoveFromCRL {
			continue // бывает только в дельта-CRL (снят с удержания): не отозван
		}
		f.bySN[e.SerialNumber.String()] = rev
	}
	return f, nil
}

// AddList читает перечень проверяющего (JSON): сертификаты, которые он
// считает отозванными, — служба не публикует CRL, или о компрометации он
// узнал сам. reason — имя причины RFC 5280 (keyCompromise, superseded, …),
// пусто — причины нет; invalidity — предполагаемое время компрометации.
// Несколько записей одного сертификата действуют все.
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
	if err := listShape(data); err != nil {
		return fmt.Errorf("tsa: revoked list %s: %w", path, err)
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
		r.listed[[32]byte(fp)] = append(r.listed[[32]byte(fp)], rev)
	}
	r.lists++
	return nil
}

// listShape — строгая форма перечня: один список объектов, в объекте только
// известные поля, каждое один раз и с точным именем. encoding/json берёт
// последнее из повторённых полей и не различает регистр имён: запись о
// компрометации пропала бы за полем, повторённым ниже.
func listShape(data []byte) error {
	dec := json.NewDecoder(bytes.NewReader(data))
	delim := func(want json.Delim) error {
		tok, err := dec.Token()
		if err != nil {
			return err
		}
		if d, ok := tok.(json.Delim); !ok || d != want {
			return fmt.Errorf("expected %q, found %v", want, tok)
		}
		return nil
	}
	if err := delim('['); err != nil {
		return fmt.Errorf("not a JSON list: %w", err)
	}
	for i := 0; dec.More(); i++ {
		if err := delim('{'); err != nil {
			return fmt.Errorf("entry %d: %w", i, err)
		}
		seen := map[string]bool{}
		for dec.More() {
			tok, err := dec.Token()
			if err != nil {
				return fmt.Errorf("entry %d: %w", i, err)
			}
			k, _ := tok.(string)
			switch {
			case k != "cert_sha256" && k != "revoked" && k != "reason" && k != "invalidity":
				return fmt.Errorf("entry %d: unknown field %q", i, k)
			case seen[k]:
				return fmt.Errorf("entry %d: field %q given twice", i, k)
			}
			seen[k] = true
			var v json.RawMessage
			if err := dec.Decode(&v); err != nil {
				return fmt.Errorf("entry %d: %w", i, err)
			}
		}
		if err := delim('}'); err != nil {
			return fmt.Errorf("entry %d: %w", i, err)
		}
	}
	if err := delim(']'); err != nil {
		return err
	}
	if _, err := dec.Token(); err != io.EOF {
		return errors.New("data after the list (one JSON list per file; pass more files with -tsa-revoked)")
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
	// Unchecked — сертификаты цепочки, кроме корня, о чьём нынешнем статусе
	// не говорит ни один CRL (перечень проверяющего полноты не обещает).
	Unchecked []*x509.Certificate
	// CRLs — по каким CRL проверено; Notes — что о проверке сказать в
	// отчёте: почему сертификат не проверен, CRL несвежий, не того центра,
	// не покрывает сертификат. Named — CRL, названные центром цепочки
	// (подпись сошлась или нет): прочие к меткам пакета не относятся.
	CRLs, Notes, Named []string
}

// CRLs — все прочитанные CRL (как их называет отчёт).
func (r *Revocations) CRLs() []string {
	var out []string
	for _, f := range r.crls {
		out = append(out, f.label())
	}
	return out
}

// Check сверяет цепочки проверенного токена (Info.Chains) с отзывом. Ошибка
// (ErrRevoked) — метка не в силе: сертификат цепочки отозван без
// компрометации не позже её времени. Из нескольких цепочек берётся лучшая;
// компрометация ключа переходит на сертификаты с тем же ключом в каждой.
func (r *Revocations) Check(chains [][]*x509.Certificate, gen time.Time) (Verdict, error) {
	looked := make([][]certStatus, len(chains))
	byKey := map[string]keyRevocation{}
	for i, chain := range chains {
		looked[i] = make([]certStatus, len(chain))
		for j, c := range chain {
			st := r.status(chain, j)
			looked[i][j] = st
			for _, e := range st.entries {
				k := string(c.RawSubjectPublicKeyInfo)
				if old, ok := byKey[k]; keyCompromised(e.Reason) && (!ok || e.Cutoff().Before(old.e.Cutoff())) {
					byKey[k] = keyRevocation{e, c}
				}
			}
		}
	}
	var best *Verdict
	var firstErr error
	for i, chain := range chains {
		v, err := r.verdict(chain, looked[i], byKey, gen)
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

// keyRevocation — компрометация ключа: запись и сертификат, чья она.
type keyRevocation struct {
	e    Revocation
	cert *x509.Certificate
}

// certStatus — что известно об отзыве одного сертификата цепочки.
type certStatus struct {
	entries   []Revocation
	from      string // самый свежий CRL, что говорит о нём; пусто — нет
	unchecked bool
	notes     []string
	named     []string
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

// status — записи о сертификате chain[i]: по перечню и, кроме корня, по CRL
// его центра (chain[i+1]).
func (r *Revocations) status(chain []*x509.Certificate, i int) certStatus {
	c := chain[i]
	st := certStatus{entries: slices.Clone(r.listed[sha256.Sum256(c.Raw)])}
	if i == len(chain)-1 {
		return st
	}
	issuer := chain[i+1]
	es, from, notes, named := r.fromCRL(c, issuer)
	st.entries = append(st.entries, es...)
	st.from, st.notes, st.named = from, notes, named
	st.unchecked = from == ""
	return st
}

// verdict — вердикт одной цепочки: записи её сертификатов и компрометации
// ключей, найденные в любой цепочке метки.
func (r *Revocations) verdict(chain []*x509.Certificate, sts []certStatus, byKey map[string]keyRevocation, gen time.Time) (Verdict, error) {
	var v Verdict
	for i, c := range chain {
		st := sts[i]
		entries := st.entries
		if k, ok := byKey[string(c.RawSubjectPublicKeyInfo)]; ok && !bytes.Equal(k.cert.Raw, c.Raw) {
			e := k.e
			e.From = fmt.Sprintf("%s, for certificate %q issued by %q with the same key", e.From, k.cert.Subject.String(), k.cert.Issuer.String())
			entries = append(slices.Clone(entries), e)
		}
		v.Notes = append(v.Notes, st.notes...)
		v.Named = append(v.Named, st.named...)
		switch {
		case st.unchecked:
			v.Unchecked = append(v.Unchecked, c)
		case st.from != "":
			v.CRLs = append(v.CRLs, st.from)
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

// fromCRL — записи о сертификате c во всех CRL его центра issuer, чьи
// подписи с ним сходятся: отзыв необратим, а истёкший сертификат центр
// вправе убрать из поздних CRL, поэтому в силе запись любого из них;
// удержание снимает более новый CRL, что говорит о c и не держит его на
// удержании. from — самый свежий CRL, что говорит о c (пусто — ни один:
// отзыв c не проверен); notes — почему не проверен, CRL несвежий или не
// того центра.
func (r *Revocations) fromCRL(c, issuer *x509.Certificate) (entries []Revocation, from string, notes, named []string) {
	var own []*crlFile
	for _, f := range r.crls {
		if !bytes.Equal(f.rl.RawIssuer, c.RawIssuer) && f.rl.Issuer.String() != c.Issuer.String() {
			continue
		}
		named = append(named, f.label())
		if err := f.rl.CheckSignatureFrom(issuer); err != nil {
			notes = append(notes, fmt.Sprintf("CRL %s names the issuer %q, but does not verify with its certificate in the chain of the time-stamp (%v): not used", f.name, issuer.Subject.String(), err))
			continue
		}
		own = append(own, f)
	}
	if len(own) == 0 {
		n := fmt.Sprintf("the revocation of certificate %q (issued by %q) was not checked: no CRL of its issuer was given (-tsa-crl)", c.Subject.String(), issuer.Subject.String())
		if r.lists > 0 {
			n += ", and your list (-tsa-revoked) does not name it"
		}
		return nil, "", append(notes, n), named
	}
	sort.SliceStable(own, func(i, j int) bool { return own[i].newer(own[j]) })
	sn := c.SerialNumber.String()
	for i, f := range own {
		e, ok := f.bySN[sn]
		if !ok {
			continue
		}
		if e.Reason == ReasonCertificateHold && slices.ContainsFunc(own[:i], func(g *crlFile) bool {
			h, held := g.bySN[sn]
			return g.newer(f) && g.speaks(c) && (!held || h.Reason != ReasonCertificateHold)
		}) {
			continue // снят с удержания: более новый CRL его не держит
		}
		entries = append(entries, e)
	}
	// CRL, выпущенный позже момента проверки (с запасом на часы), о нынешнем
	// статусе не говорит: часы центра или проверяющего неверны.
	var cur *crlFile
	for _, f := range own {
		if f.rl.ThisUpdate.After(r.Now.Add(futureSlack)) {
			notes = append(notes, fmt.Sprintf("%s is dated after the time of this check (%s): its entries count, but it is not taken for the status of certificate %q; check the clocks", f.label(), r.Now.UTC().Format(time.RFC3339), c.Subject.String()))
			continue
		}
		if f.speaks(c) {
			cur = f
			break
		}
	}
	if cur == nil {
		for _, f := range own {
			switch {
			case f.rl.ThisUpdate.After(r.Now.Add(futureSlack)):
				// названа выше
			case !f.scope.covers(c):
				notes = append(notes, fmt.Sprintf("the revocation of certificate %q was not checked by %s: it covers only a part of the certificates of %q (issuing distribution point), not this one; its entries count, but it does not show the certificate is not revoked", c.Subject.String(), f.label(), issuer.Subject.String()))
			default:
				notes = append(notes, fmt.Sprintf("the revocation of certificate %q was not checked by %s: the certificate expired on %s, before that CRL, and a CA may drop an expired certificate from its CRLs; give a CRL of %q from before then too", c.Subject.String(), f.label(), c.NotAfter.UTC().Format(time.RFC3339), issuer.Subject.String()))
			}
		}
		return entries, "", notes, named
	}
	from = cur.label()
	if cur.deltas {
		notes = append(notes, fmt.Sprintf("%s points to delta CRLs (freshest CRL): a revocation published only in a delta CRL since then is not seen, and esverify does not read delta CRLs; check against a full CRL issued later, or list such a revocation with -tsa-revoked", from))
	}
	switch {
	case cur.rl.NextUpdate.IsZero():
		notes = append(notes, fmt.Sprintf("%s names no next update: a revocation after it is not seen; fetch a fresh one", from))
	case !r.Now.Before(cur.rl.NextUpdate):
		notes = append(notes, fmt.Sprintf("%s is past its next update (%s): a revocation after it is not seen; fetch a fresh one", from, cur.rl.NextUpdate.UTC().Format(time.RFC3339)))
	}
	return entries, from, notes, named
}

// futureSlack — насколько CRL может быть «из будущего» по часам проверяющего
// и всё же говорить о нынешнем статусе.
const futureSlack = time.Hour

// Fingerprint — SHA-256 сертификата для перечня проверяющего (cert_sha256).
func Fingerprint(c *x509.Certificate) string {
	sum := sha256.Sum256(c.Raw)
	return hex.EncodeToString(sum[:])
}
