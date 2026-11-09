package tsa

import (
	"bytes"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
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
	"strings"
	"sync"
	"time"
	"unicode"
	"unicode/utf8"
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
// закрепляет сам проверяющий). В своём перечне проверяющий может отозвать и
// корень. Только полные CRL от самого выпустившего центра: дельта-CRL,
// косвенный CRL и CRL с критичным расширением, которое здесь не разбирается,
// — отказ при чтении (RFC 5280, 5.2: такой CRL для проверки не годится), а не
// молчаливая проверка по неполному списку.
//
// Запись и статус — разные вещи.
//   - Запись об отзыве — свидетельство, и оно только добавляет подозрение.
//     Поэтому в силе записи каждого CRL с именем центра, подписанного ключом
//     центра или его новым ключом, выпущенным под тем же корнем (центр сменил
//     ключ и отозвал сертификат уже новым, RFC 5280, 6.3.3 f), что бы ни
//     говорили keyUsage сертификата центра, область CRL и его свежесть, и
//     записи всех таких CRL вместе:
//     отзыв необратим, а истёкший сертификат центр вправе убрать из поздних
//     CRL (RFC 5280, 3.3). Снимает запись только одно: удержание снимает более
//     новый CRL, годный для статуса, который сертификат не называет вовсе.
//   - Статус («не отозван») — по самому свежему CRL, годному для этого: его
//     подпись сходится с сертификатом центра, которому можно подписывать CRL
//     (центр, cRLSign; RFC 5280, 6.3.3 f), он покрывает сертификат
//     (issuingDistributionPoint), выпущен до его истечения или держит истёкшие
//     (expiredCertsOnCRL) и не позже момента проверки. Нет такого — отзыв не
//     проверен, и отчёт это говорит; на вердикт статус не влияет.
//
// Компрометация — свойство ключа, и судят о ней по всем меткам пакета сразу
// (Assessment): запись, требующая POE, у любого сертификата с этим ключом в
// любой цепочке любой метки — или среди сертификатов, которые дал
// проверяющий и несут токены (Known), — ставит под подозрение каждую цепочку,
// где этот ключ есть, с самой ранней отсечкой ключа. Отзыв сертификата центра
// без причины — не о ключе (chainOnly). CRL с именем центра под ключом,
// которого не связать с корнем, — не «другой центр», а неизвестность: статус
// сертификата, который он называет, не проверен.

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

// chainOnly — запись о c, которая ставит под подозрение цепочку через c, но
// не ключ c: сертификат центра, отозванный без причины. Правило «без причины
// не в силе метки соответствующего ключа» RFC 3161 пишет для сертификата
// самой службы; центр без причины отзывает и перекрёстный сертификат, когда
// прекращает перекрёстную сертификацию (тогда другая цепочка в силе), и
// промежуточный центр по умолчанию openssl ca -revoke (тогда единственная
// цепочка ждёт POE, как и у службы). Сертификат службы — первый в цепочке
// (signer); вне цепочки — не сертификат центра (IsCA).
//
// Остальные записи с причиной не из keepsEarlier — под подозрением ключ, а не
// только сертификат: подозрение переходит на любой сертификат с тем же
// ключом — перекрёстный сертификат центра, выпущенный другим корнем, или
// перевыпущенный на тот же ключ.
func chainOnly(c *x509.Certificate, signer bool, e Revocation) bool {
	return e.Reason == ReasonAbsent && c.IsCA && !signer
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
	lbl   string // как его называет отчёт (label)
	rl    *x509.RevocationList
	bySN  map[string][]Revocation // по номеру сертификата; записей может быть несколько
	scope *crlScope               // issuingDistributionPoint; nil — все сертификаты центра
	// expired — expiredCertsOnCRL: CRL держит и сертификаты, истёкшие с
	// этого момента; ноль — нет.
	expired time.Time
	// deltas — CRL называет дельта-CRL (freshestCRL): отзывы после его
	// thisUpdate центр публикует в них, а их esverify не читает.
	deltas bool
}

func (f *crlFile) label() string { return f.lbl }

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

// parseScope разбирает issuingDistributionPoint (RFC 5280, 5.2.5) строго по
// DER: поля по порядку тегов [0]…[5], каждое не больше раза, без лишнего —
// encoding/asn1 молча пропустил бы поле не на своём месте, и точка
// распространения потерялась бы. indirect — косвенный CRL.
func parseScope(der []byte) (sc *crlScope, indirect bool, err error) {
	bad := errors.New("the issuing distribution point does not parse")
	var seq asn1.RawValue
	if rest, err := asn1.Unmarshal(der, &seq); err != nil || len(rest) != 0 || seq.Class != asn1.ClassUniversal || seq.Tag != asn1.TagSequence || !seq.IsCompound {
		return nil, false, bad
	}
	sc = &crlScope{}
	last := -1
	for rest := seq.Bytes; len(rest) > 0; {
		var e asn1.RawValue
		if rest, err = asn1.Unmarshal(rest, &e); err != nil || e.Class != asn1.ClassContextSpecific || e.Tag <= last || e.Tag > 5 {
			return nil, false, bad
		}
		last = e.Tag
		if e.Tag == 0 {
			// distributionPoint — CHOICE, тег явный: внутри fullName [0]
			// GeneralNames (URI — [6]) или nameRelativeToCRLIssuer [1].
			var name asn1.RawValue
			if r, err := asn1.Unmarshal(e.Bytes, &name); err != nil || len(r) != 0 || !e.IsCompound {
				return nil, false, bad
			}
			if name.Class != asn1.ClassContextSpecific || name.Tag != 0 || !name.IsCompound {
				sc.otherDP = true
				continue
			}
			for r := name.Bytes; len(r) > 0; {
				var gn asn1.RawValue
				if r, err = asn1.Unmarshal(r, &gn); err != nil {
					return nil, false, bad
				}
				if gn.Class == asn1.ClassContextSpecific && gn.Tag == 6 && !gn.IsCompound {
					sc.uris = append(sc.uris, string(gn.Bytes))
				} else {
					sc.otherDP = true
				}
			}
			continue
		}
		if e.IsCompound || e.Tag != 3 && len(e.Bytes) != 1 {
			return nil, false, bad
		}
		on := e.Tag == 3 || e.Bytes[0] != 0
		switch e.Tag {
		case 1:
			sc.onlyUser = on
		case 2:
			sc.onlyCA = on
		case 3:
			sc.some = true // onlySomeReasons: не все причины
		case 4:
			indirect = on
		case 5:
			sc.onlyAttr = on
		}
	}
	return sc, indirect, nil
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
	}
	// Довольно совпадения одного имени (RFC 5280, 6.3.3 b2i); имена не URI
	// с сертификатом не сверить.
	for _, u := range c.CRLDistributionPoints {
		if slices.Contains(sc.uris, u) {
			return true
		}
	}
	return false
}

// why — почему CRL не покрывает сертификат, для заметки.
func (sc *crlScope) why() string {
	if sc != nil && sc.some {
		return "it covers only some reasons of revocation (onlySomeReasons)"
	}
	return "it covers only a part of the certificates of its CA (issuing distribution point), not this one"
}

// Revocations — что проверяющий знает об отзыве.
type Revocations struct {
	crls   []*crlFile
	listed map[[32]byte][]Revocation // по SHA-256 сертификата (DER)
	lists  int                       // сколько перечней прочитано
	// Now — момент проверки: с ним сверяется свежесть CRL (nextUpdate).
	Now time.Time

	mu   sync.Mutex
	sigs map[sigKey]sigCheck // подпись CRL и право центра на CRL: сверяются раз
	// naming — CRL с именем центра, по RawIssuer сертификата: CRL крупного
	// центра за год — сотни файлов, а меток в пакете — тысячи.
	naming map[string][]*crlFile
}

// sigKey — CRL и сертификат центра, чьим ключом сверяется его подпись.
type sigKey struct {
	crl    *crlFile
	issuer [32]byte
}

// sigCheck — подпись CRL ключом сертификата центра (key: записи CRL в силе) и
// право этого сертификата подписывать CRL (auth: центр с cRLSign, RFC 5280,
// 6.3.3 f — CRL годен и для статуса; при ошибке key — она же).
type sigCheck struct {
	key, auth error
}

// checkSig — подпись CRL f ключом issuer и право issuer на CRL, сверенные раз
// на пару: пакет за неделю несёт сотни меток, а CRL крупного центра —
// мегабайты.
func (r *Revocations) checkSig(f *crlFile, issuer *x509.Certificate) sigCheck {
	k := sigKey{f, sha256.Sum256(issuer.Raw)}
	r.mu.Lock()
	defer r.mu.Unlock()
	if s, ok := r.sigs[k]; ok {
		return s
	}
	if r.sigs == nil {
		r.sigs = map[sigKey]sigCheck{}
	}
	s := sigCheck{key: issuer.CheckSignature(f.rl.SignatureAlgorithm, f.rl.RawTBSRevocationList, f.rl.Signature)}
	s.auth = s.key
	if s.key == nil {
		s.auth = f.rl.CheckSignatureFrom(issuer)
	}
	r.sigs[k] = s
	return s
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
	r.mu.Lock()
	r.naming = nil
	r.mu.Unlock()
	return nil
}

// crlsNaming — CRL с именем центра, выпустившего c (namesIssuerOf), в
// порядке чтения.
func (r *Revocations) crlsNaming(c *x509.Certificate) []*crlFile {
	r.mu.Lock()
	defer r.mu.Unlock()
	if out, ok := r.naming[string(c.RawIssuer)]; ok {
		return out
	}
	if r.naming == nil {
		r.naming = map[string][]*crlFile{}
	}
	var out []*crlFile
	for _, f := range r.crls {
		if f.namesIssuerOf(c) {
			out = append(out, f)
		}
	}
	r.naming[string(c.RawIssuer)] = out
	return out
}

// signed — записи о c во всех CRL с именем его центра, подписанных ключом
// issuer.
func (r *Revocations) signed(c, issuer *x509.Certificate) []Revocation {
	var out []Revocation
	sn := c.SerialNumber.String()
	for _, f := range r.crlsNaming(c) {
		if es := f.bySN[sn]; len(es) > 0 && r.checkSig(f, issuer).key == nil {
			out = append(out, es...)
		}
	}
	return out
}

// crlBlocks — CRL файла: блоки PEM «X509 CRL» или DER подряд. Вне блоков PEM
// допустим текст UTF-8 (RFC 7468, 2: пояснение перед блоком, вывод openssl
// crl -text), но не двоичные данные — DER рядом с блоками PEM пропал бы молча
// — и не обломки границ блока (brokenBoundary): строка тире со словом
// границы вне блока бывает у блока с испорченной строкой начала или конца, а
// с ним пропала бы и запись о компрометации. Поэтому же начал блоков должно быть столько, сколько блоков
// разобрано. В блоке, как и в файле DER, — CRL подряд, с пробелами между ними.
func crlBlocks(data []byte) ([][]byte, error) {
	begin := []byte("-----BEGIN")
	if !bytes.Contains(data, begin) {
		out, err := derCRLs(data)
		if err != nil {
			return nil, fmt.Errorf("neither DER nor PEM: %v", err)
		}
		return out, nil
	}
	var out [][]byte
	blocks := 0
	for rest := data; ; {
		i := bytes.Index(rest, begin)
		outside := rest
		if i >= 0 {
			outside = rest[:i]
		}
		switch {
		case !utf8.Valid(outside):
			return nil, fmt.Errorf("text outside the PEM blocks (after block #%d) is not UTF-8: a DER CRL beside PEM ones (pass it in a file of its own), or text in another encoding (convert it to UTF-8, or remove it)", blocks)
		case !isText(outside):
			return nil, fmt.Errorf("control characters outside the PEM blocks (after block #%d): a DER CRL beside PEM ones? pass it in a file of its own, or remove them", blocks)
		case brokenBoundary(outside) != "":
			return nil, fmt.Errorf("a broken PEM boundary outside the PEM blocks (after block #%d): %q names X509 CRL, is a line of dashes with BEGIN or END, or is base64 like the body of a block, but no whole -----BEGIN line starts a block there; is a block damaged?", blocks, brokenBoundary(outside))
		}
		if i < 0 {
			break
		}
		b, r := pem.Decode(rest[i:])
		switch {
		case b == nil:
			return nil, fmt.Errorf("PEM block #%d does not parse", blocks+1)
		case b.Type != "X509 CRL":
			return nil, fmt.Errorf("a PEM block %q, not X509 CRL", b.Type)
		}
		blocks++
		ders, err := derCRLs(b.Bytes)
		if err != nil {
			return nil, fmt.Errorf("PEM block #%d: %v", blocks, err)
		}
		out = append(out, ders...)
		rest = r
	}
	if n := bytes.Count(data, begin); n != blocks {
		return nil, fmt.Errorf("%d PEM blocks begin, %d parse: a block is damaged", n, blocks)
	}
	return out, nil
}

// brokenBoundary — строка, похожая на границу или тело блока PEM, но не блок
// (пусто — такой нет): с меткой блока «X509 CRL», с пятью тире с краю и
// словом BEGIN или END, или строка base64 длиной с тело блока. Так выглядят
// строки блока с испорченными границами, а с ним пропала бы и запись о
// компрометации. Разделители «---------- CRL 1 of 2 ----------», «-- CRL of
// NCA RK --», вывод openssl crl -text (байты через двоеточие), отпечатки
// шестнадцатеричными цифрами — текст.
func brokenBoundary(text []byte) string {
	for _, line := range bytes.Split(text, []byte("\n")) {
		t := bytes.TrimSpace(line)
		l := bytes.ToUpper(t)
		if bytes.Contains(bytes.Join(bytes.Fields(l), []byte(" ")), []byte("X509 CRL")) || base64Body(t) {
			return string(t)
		}
		if !bytes.HasPrefix(l, []byte("-----")) && !bytes.HasSuffix(l, []byte("-----")) {
			continue
		}
		for _, w := range bytes.FieldsFunc(l, func(r rune) bool { return !unicode.IsLetter(r) && !unicode.IsDigit(r) }) {
			if string(w) == "BEGIN" || string(w) == "END" {
				return string(t)
			}
		}
	}
	return ""
}

// base64Body — строка тела блока PEM: не короче 40 знаков, только алфавит
// base64 и хотя бы один знак не из шестнадцатеричных цифр (отпечаток SHA-256
// — тоже 64 знака из алфавита).
func base64Body(t []byte) bool {
	if len(t) < 40 {
		return false
	}
	hex := true
	for _, c := range t {
		switch {
		case c >= '0' && c <= '9', c >= 'a' && c <= 'f', c >= 'A' && c <= 'F':
		case c >= 'g' && c <= 'z', c >= 'G' && c <= 'Z', c == '+', c == '/', c == '=':
			hex = false
		default:
			return false
		}
	}
	return !hex
}

// derCRLs — элементы DER подряд (пробелы между ними и по краям допустимы:
// ни один элемент DER с них не начинается).
func derCRLs(data []byte) ([][]byte, error) {
	var out [][]byte
	for rest := bytes.TrimLeft(data, " \t\r\n"); len(rest) > 0; rest = bytes.TrimLeft(rest, " \t\r\n") {
		var v asn1.RawValue
		next, err := asn1.Unmarshal(rest, &v)
		if err != nil {
			if len(out) == 0 {
				return nil, err
			}
			return nil, fmt.Errorf("data after CRL #%d is not DER: %v", len(out), err)
		}
		out = append(out, v.FullBytes)
		rest = next
	}
	if len(out) == 0 {
		return nil, errors.New("no CRL in it")
	}
	return out, nil
}

// isText — текст UTF-8 без управляющих символов, кроме табуляции и переводов
// строки.
func isText(b []byte) bool {
	if !utf8.Valid(b) {
		return false
	}
	for _, c := range string(b) {
		if c < 0x20 && c != '\t' && c != '\n' && c != '\r' || c == 0x7f {
			return false
		}
	}
	return true
}

// uniqueExtensions — каждое расширение один раз (RFC 5280, 4.2 и 5.2): из
// двух reasonCode x509 молча берёт последний, и компрометация пропала бы за
// выводом из работы.
func uniqueExtensions(xs []pkix.Extension) error {
	for i, x := range xs {
		for _, y := range xs[:i] {
			if x.Id.Equal(y.Id) {
				return fmt.Errorf("extension %s is given twice", x.Id)
			}
		}
	}
	return nil
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
	if err := uniqueExtensions(rl.Extensions); err != nil {
		return nil, fmt.Errorf("tsa: crl %s: %v", name, err)
	}
	f := &crlFile{name: name, rl: rl, bySN: map[string][]Revocation{}}
	f.lbl = fmt.Sprintf("CRL %s of %s", name, rl.ThisUpdate.UTC().Format(time.RFC3339))
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
			if sc.onlyAttr {
				return nil, fmt.Errorf("tsa: crl %s lists only attribute certificates (onlyContainsAttributeCerts, RFC 5280, 5.2.5): it says nothing of TSA certificates, and its serial numbers are of other certificates", name)
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
		if err := uniqueExtensions(e.Extensions); err != nil {
			return nil, fmt.Errorf("tsa: crl %s: the entry of serial %s: %v", name, e.SerialNumber, err)
		}
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
		// Номер дважды (компрометация, потом вывод из работы) — в силе обе.
		f.bySN[e.SerialNumber.String()] = append(f.bySN[e.SerialNumber.String()], rev)
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
	// Revoked — сертификат выбранной цепочки, чей ключ под подозрением с
	// самой ранней отсечкой; nil — ни один (или отозван раньше времени метки
	// по причине без компрометации). Entry — запись, от которой отсечка: его
	// собственная или другого сертификата с тем же ключом (From это говорит).
	Revoked *x509.Certificate
	Entry   Revocation
	// NeedPOE — время метки ничего не доказывает (компрометация или нет
	// причины): метка в силе, только если её существование раньше Cutoff
	// показано независимо. POE даёт только метка без NeedPOE.
	NeedPOE bool
	Cutoff  time.Time
	// Retired — метка не в силе: её цепочки отозваны без компрометации не
	// позже её времени по записям, которые видны только всей оценке (Add
	// ошибки не вернул). Остальные поля тогда пусты.
	Retired error
	// Unchecked — сертификаты цепочки, кроме корня, о чьём нынешнем статусе
	// не говорит ни один CRL (перечень проверяющего полноты не обещает).
	Unchecked []*x509.Certificate
	// CRLs — по каким CRL проверено; Notes — что о проверке сказать в
	// отчёте: почему сертификат не проверен, CRL несвежий, не того центра,
	// не покрывает сертификат. Named — CRL, названные центром какой-либо
	// цепочки какой-либо метки оценки (подпись сошлась или нет): прочие к
	// пакету не относятся.
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

// Assessment — отзыв для меток одного пакета, которые судятся вместе: статус
// сертификата — по всем цепочкам, где он есть; подозрение на ключ — по всем
// цепочкам всех меток, с самой ранней отсечкой ключа. Метки добавляются
// (Add), затем вердикты всех сразу (Verdicts).
type Assessment struct {
	r       *Revocations
	stamps  []assessed
	known   []*x509.Certificate // Known: сертификаты вне цепочек
	knownFP map[[32]byte]bool
	trusted map[[32]byte]bool // KnownTrusted: дал проверяющий
	dropped int               // Known сверх maxKnown
	gone    map[[32]byte]bool // какие отброшены (dropped — их число)
	named   []string          // Named, посчитанные после последнего Add
	extra   []*crlFile        // CRL, названные центрами сертификатов Known (Verdicts)
}

// maxKnown — сколько сертификатов вне цепочек судится: поле certificates в
// CMS не подписано, и дописать к токену можно сколько угодно.
const maxKnown = 1024

// assessed — метка оценки: цепочки, время; err — метка не в силе.
type assessed struct {
	chains [][]*x509.Certificate
	gen    time.Time
	err    error
}

// NewAssessment — пустая оценка по этим сведениям.
func (r *Revocations) NewAssessment() *Assessment { return &Assessment{r: r} }

// Known добавляет сертификаты, которые проверяющий дал сам (-tsa-trust) или
// которые несут токены, но которых может не быть ни в одной цепочке: ключ,
// перевыпущенный на тот же ключ сертификат которого отозван по компрометации,
// под подозрением и тогда, когда цепочки меток идут через прежний, истёкший
// и потому из CRL убранный (RFC 5280, 3.3). Их записи только добавляют
// подозрение на ключ; статуса и заметок о них нет.
func (a *Assessment) Known(certs ...*x509.Certificate) {
	a.known1(false, certs)
}

// KnownTrusted — Known для сертификатов, которые дал сам проверяющий
// (-tsa-trust, его корни тоже): только они и сертификаты цепочек годятся в
// центры сертификатов вне цепочек и в путь ключа, подписавшего CRL, к корню —
// сертификаты, что несут токены, подкладывает тот, кто собирал пакет (поле
// certificates в CMS не подписано). Сертификат, данный проверяющим, судится и
// без известного центра.
func (a *Assessment) KnownTrusted(certs ...*x509.Certificate) {
	a.known1(true, certs)
}

func (a *Assessment) known1(trusted bool, certs []*x509.Certificate) {
	if a.knownFP == nil {
		a.knownFP, a.trusted = map[[32]byte]bool{}, map[[32]byte]bool{}
	}
	for _, c := range certs {
		if c == nil {
			continue
		}
		fp := sha256.Sum256(c.Raw)
		if trusted {
			a.trusted[fp] = true
		}
		switch {
		case a.knownFP[fp]:
		case len(a.known) >= maxKnown && !trusted:
			if a.gone == nil {
				a.gone = map[[32]byte]bool{}
			}
			if !a.gone[fp] {
				a.gone[fp] = true
				a.dropped++
			}
		default:
			a.knownFP[fp] = true
			a.known = append(a.known, c)
		}
	}
}

// Add добавляет метку — цепочки проверенного токена (Info.Chains) и её время
// — и возвращает её номер в Verdicts. Ошибка (ErrRevoked) — метка не в силе:
// в каждой её цепочке сертификат отозван без компрометации не позже её
// времени; от других меток это не зависит. Цепочки и такой метки судятся
// вместе со всеми: её ключи — те же ключи.
func (a *Assessment) Add(chains [][]*x509.Certificate, gen time.Time) (int, error) {
	s := assessed{chains: chains, gen: gen}
	ok := false
	for _, ch := range chains {
		err := a.r.retired(ch, gen)
		if err == nil {
			ok = true
			break
		}
		if s.err == nil {
			s.err = err
		}
	}
	switch {
	case ok:
		s.err = nil
	case s.err == nil:
		s.err = fmt.Errorf("%w: no certificate chain to check", ErrRevoked)
	}
	a.stamps = append(a.stamps, s)
	a.named = nil
	return len(a.stamps) - 1, s.err
}

// Check — вердикт одной метки, судимой отдельно (Assessment из неё одной).
func (r *Revocations) Check(chains [][]*x509.Certificate, gen time.Time) (Verdict, error) {
	a := r.NewAssessment()
	i, err := a.Add(chains, gen)
	if err != nil {
		return Verdict{Named: a.Named()}, err
	}
	return a.Verdicts()[i], nil
}

// retired — ошибка, если сертификат цепочки отозван без компрометации не
// позже gen (RFC 3161, 4: такие метки до даты отзыва в силе, после — нет).
// Записи — те же, что у verdictOf: перечень и, кроме корня, CRL, подписанные
// ключом центра (удержание к этим причинам не относится).
func (r *Revocations) retired(chain []*x509.Certificate, gen time.Time) error {
	for i, c := range chain {
		es := r.listed[sha256.Sum256(c.Raw)]
		if i < len(chain)-1 {
			es = append(slices.Clone(es), r.signed(c, chain[i+1])...)
		}
		for _, e := range es {
			if keepsEarlier(e.Reason) && !gen.Before(e.Time) {
				return retiredErr(c, e, gen)
			}
		}
	}
	return nil
}

func retiredErr(c *x509.Certificate, e Revocation, gen time.Time) error {
	return fmt.Errorf("%w: certificate %q was revoked on %s (%s; %s), and the time-stamp is of %s, not earlier: RFC 3161 keeps only the time-stamps made before such a revocation", ErrRevoked, c.Subject.String(), e.Time.Format(time.RFC3339), ReasonName(e.Reason), e.From, gen.UTC().Format(time.RFC3339))
}

// namesIssuerOf — CRL выпущен от имени центра, выпустившего c.
func (f *crlFile) namesIssuerOf(c *x509.Certificate) bool {
	return bytes.Equal(f.rl.RawIssuer, c.RawIssuer) || f.rl.Issuer.String() == c.Issuer.String()
}

// Named — CRL, названные центром какой-либо цепочки какой-либо метки оценки
// (подпись сошлась или нет): прочие к пакету не относятся. Считается раз —
// по разным сертификатам цепочек, а не по меткам.
func (a *Assessment) Named() []string {
	if a.named != nil {
		return a.named
	}
	seen := map[[32]byte]bool{}
	hit := map[*crlFile]bool{}
	for _, s := range a.stamps {
		for _, ch := range s.chains {
			for _, c := range ch[:max(len(ch)-1, 0)] {
				fp := sha256.Sum256(c.Raw)
				if seen[fp] {
					continue
				}
				seen[fp] = true
				for _, f := range a.r.crlsNaming(c) {
					hit[f] = true
				}
			}
		}
	}
	for _, f := range a.extra {
		hit[f] = true
	}
	out := []string{}
	for _, f := range a.r.crls {
		if hit[f] {
			out = append(out, f.label())
		}
	}
	a.named = out
	return out
}

// keyRevocation — подозрение на ключ: запись и сертификат, чья она.
type keyRevocation struct {
	e    Revocation
	cert *x509.Certificate
}

// certStatus — что известно об отзыве одного сертификата.
type certStatus struct {
	entries []Revocation
	from    string // самый свежий CRL, годный для статуса; пусто — нет
	notes   []string
	// listing — CRL с именем центра под другим ключом, называющие сертификат
	// (смена ключа центра): Verdicts сверяет их путь к тому же корню.
	listing []*crlFile
	cur     *crlFile // CRL статуса (from); nil — нет
}

// Verdicts — вердикты всех добавленных меток по сведениям обо всех сразу (у
// метки, чей Add вернул ошибку, — пустой). Статус сертификата — по всем
// сертификатам его центра из всех цепочек (у одного ключа их бывает несколько:
// перекрёстный выпуск, перевыпуск); подозрение на ключ — запись, требующая
// POE, у любого сертификата с этим ключом, с самой ранней отсечкой.
//
// Сертификаты вне цепочек (Known) судятся так же, если их ключ есть в
// цепочках (иначе им не на что влиять): центр — сертификаты цепочек и
// проверяющего, чьей подписью они выпущены; записи — тем же judge, со
// снятием удержания и CRL под новым ключом центра. Их статус не нужен, но
// CRL, которого не связать с корнем и который называет такой сертификат,
// делает «не проверенными» сертификаты цепочек с тем же ключом.
func (a *Assessment) Verdicts() []Verdict {
	type certInfo struct {
		c       *x509.Certificate
		issuers []*x509.Certificate
		roots   []*x509.Certificate
		inChain bool
		st      certStatus
	}
	var order []*certInfo
	certs := map[[32]byte]*certInfo{}
	info := func(c *x509.Certificate) *certInfo {
		fp := sha256.Sum256(c.Raw)
		ci := certs[fp]
		if ci == nil {
			ci = &certInfo{c: c}
			certs[fp] = ci
			order = append(order, ci)
		}
		return ci
	}
	has := func(list []*x509.Certificate, c *x509.Certificate) bool {
		return slices.ContainsFunc(list, func(x *x509.Certificate) bool { return bytes.Equal(x.Raw, c.Raw) })
	}
	// chainKeys — ключи цепочек; signerKeys — ключи служб (первые в
	// цепочках): сертификат с таким ключом — сертификат службы, где бы он ни
	// был и что бы ни говорил его BasicConstraints.
	chainKeys, signerKeys := map[string]bool{}, map[string]bool{}
	for _, s := range a.stamps {
		for _, ch := range s.chains {
			for j, c := range ch {
				ci := info(c)
				ci.inChain = true
				chainKeys[string(c.RawSubjectPublicKeyInfo)] = true
				signerKeys[string(c.RawSubjectPublicKeyInfo)] = signerKeys[string(c.RawSubjectPublicKeyInfo)] || j == 0
				if j < len(ch)-1 && !has(ci.issuers, ch[j+1]) {
					ci.issuers = append(ci.issuers, ch[j+1])
				}
				if root := ch[len(ch)-1]; !has(ci.roots, root) {
					ci.roots = append(ci.roots, root)
				}
			}
		}
	}
	// Центры и сертификаты нового ключа центра ищутся по имени субъекта
	// среди сертификатов цепочек и данных проверяющим (paths).
	p := newPaths()
	for _, ci := range order {
		p.add(ci.c)
	}
	for _, c := range a.known {
		if a.trusted[sha256.Sum256(c.Raw)] {
			p.add(c)
		}
	}
	var allRoots []*x509.Certificate
	for _, ci := range order {
		for _, r := range ci.roots {
			if !has(allRoots, r) {
				allRoots = append(allRoots, r)
			}
		}
	}
	// anchors — корни, под которыми ключ, подписавший CRL под другим ключом
	// центра, засчитывается: корни всех цепочек и все корни проверяющего, а
	// не только корни цепочек самого сертификата. Цепочку выбирает тот, кто
	// собирал пакет (сертификаты в токенах): с перекрёстным сертификатом
	// центра от другого доверенного корня он увёл бы её от корня, под которым
	// выпущен новый ключ центра. Такой CRL только добавляет записи; цена —
	// центр того же имени под другим доверенным корнем, с теми же номерами,
	// считается тем же центром (limitations.md).
	anchors := anchorsOf(allRoots)
	for _, c := range a.known {
		if a.trusted[sha256.Sum256(c.Raw)] && bytes.Equal(c.RawIssuer, c.RawSubject) && c.CheckSignatureFrom(c) == nil {
			anchors[anchorOf(c)] = true
		}
	}
	a.extra = nil
	for _, k := range a.known {
		if certs[sha256.Sum256(k.Raw)] != nil || !chainKeys[string(k.RawSubjectPublicKeyInfo)] {
			continue
		}
		ci := info(k)
		if !bytes.Equal(k.RawIssuer, k.RawSubject) {
			for _, x := range p.named(k.RawIssuer, k.Issuer) {
				if !bytes.Equal(x.Raw, k.Raw) && x.CheckSignature(k.SignatureAlgorithm, k.RawTBSCertificate, k.Signature) == nil {
					ci.issuers = append(ci.issuers, x)
					if xi := certs[sha256.Sum256(x.Raw)]; xi != nil && xi.inChain {
						for _, r := range xi.roots {
							if !has(ci.roots, r) {
								ci.roots = append(ci.roots, r)
							}
						}
					}
				}
			}
			if len(ci.roots) == 0 {
				ci.roots = allRoots
			}
		}
		a.extra = append(a.extra, a.r.crlsNaming(k)...)
	}
	byKey := map[string]keyRevocation{}
	suspect := func(ci *certInfo, es []Revocation) {
		k := string(ci.c.RawSubjectPublicKeyInfo)
		for _, e := range es {
			if keepsEarlier(e.Reason) || chainOnly(ci.c, signerKeys[k], e) {
				continue
			}
			if old, ok := byKey[k]; !ok || e.Cutoff().Before(old.e.Cutoff()) {
				byKey[k] = keyRevocation{e, ci.c}
			}
		}
	}
	future := func(f *crlFile) bool { return f.rl.ThisUpdate.After(a.r.Now.Add(futureSlack)) }
	// unknownKey — ключи, чей сертификат вне цепочек называет CRL, которого
	// не связать с корнем, записью, которая поставила бы ключ под
	// подозрение: заметки для сертификатов цепочек с этим ключом.
	type keyDoubt struct{ ask, why string }
	unknownKey := map[string][]keyDoubt{}
	for _, ci := range order {
		ci.st = a.r.judge(ci.c, ci.issuers)
		if !ci.inChain && len(ci.issuers) == 0 && a.trusted[sha256.Sum256(ci.c.Raw)] && !bytes.Equal(ci.c.RawIssuer, ci.c.RawSubject) {
			// Дал проверяющий, центр не известен (сертификат нового ключа
			// центра не дан): подпись своего CRL не сверить, и любой CRL с
			// именем центра, называющий сертификат, — под другим ключом.
			// Сертификат из токена без известного центра не судится: его
			// подложит кто угодно.
			for _, f := range a.r.crlsNaming(ci.c) {
				if len(f.bySN[ci.c.SerialNumber.String()]) > 0 {
					ci.st.listing = append(ci.st.listing, f)
				}
			}
		}
		// CRL под другим ключом центра, называющие сертификат. Ключ, которым
		// он подписан, выпущен под корнем сертификата (центр сменил ключ):
		// записи в счёт, статуса он не даёт. Не выпущен, насколько видно, —
		// статус не известен, когда такой CRL новее статусного: это может
		// быть сам центр под ключом, сертификата которого здесь нет.
		issuer := ci.c.Issuer.String()
		if len(ci.issuers) > 0 {
			issuer = ci.issuers[0].Subject.String()
		}
		as := anchors
		sn := ci.c.SerialNumber.String()
		for _, g := range ci.st.listing {
			if bys := a.r.crlSigners(g, p, as); len(bys) > 0 {
				for _, e := range g.bySN[sn] {
					// Удержание снимает более новый CRL того же ключа, который
					// сертификат не называет вовсе, — как у своего CRL: право
					// на CRL хоть у одного сертификата этого ключа под корнем.
					if e.Reason == ReasonCertificateHold && slices.ContainsFunc(a.r.crlsNaming(ci.c), func(h *crlFile) bool {
						return h.newer(g) && !future(h) && h.speaks(ci.c) && len(h.bySN[sn]) == 0 &&
							slices.ContainsFunc(bys, func(x *x509.Certificate) bool { return a.r.checkSig(h, x).auth == nil })
					}) {
						continue
					}
					ci.st.entries = append(ci.st.entries, e)
				}
				ci.st.notes = append(ci.st.notes, fmt.Sprintf("%s is signed with another key of %q, certified by %q under a root of -tsa-trust (RFC 5280, 6.3.3 f): its entries about certificate %q count", g.label(), issuer, bys[0].Issuer.String(), ci.c.Subject.String()))
				continue
			}
			ask := fmt.Sprintf("%s lists certificate %q (serial %s) as revoked, but is not signed with the key of its issuer %q, and no certificate here with that name and the key that signed it is certified under a root of -tsa-trust (did the CA change its key? pass that certificate in -tsa-trust, with the CA certificates between it and the root)", g.label(), ci.c.Subject.String(), ci.c.SerialNumber, issuer)
			if x := slices.IndexFunc(p.named(g.rl.RawIssuer, g.rl.Issuer), func(x *x509.Certificate) bool { return a.r.checkSig(g, x).key == nil }); x >= 0 {
				ask = fmt.Sprintf("%s lists certificate %q (serial %s) as revoked, but is not signed with the key of its issuer %q; the certificate of the key that signed it (issued by %q) is here, but its issuers up to a root of -tsa-trust are not (pass them in -tsa-trust)", g.label(), ci.c.Subject.String(), ci.c.SerialNumber, issuer, p.named(g.rl.RawIssuer, g.rl.Issuer)[x].Issuer.String())
			}
			switch {
			case !ci.inChain:
				// Вне цепочек на вердикт влияет только запись, ставящая ключ
				// под подозрение (вывод из работы без компрометации и центр
				// без причины — нет): только она и делает ключ сомнительным.
				k := string(ci.c.RawSubjectPublicKeyInfo)
				var why []string
				for _, e := range g.bySN[sn] {
					if !keepsEarlier(e.Reason) && !chainOnly(ci.c, signerKeys[k], e) {
						why = append(why, ReasonName(e.Reason))
					}
				}
				if len(why) > 0 && !future(g) && (ci.st.cur == nil || g.newer(ci.st.cur)) {
					unknownKey[k] = append(unknownKey[k], keyDoubt{ask + ": that certificate has the same key",
						fmt.Sprintf("%s lists certificate %q (serial %s) with the same key as revoked (%s), and its signature cannot be checked", g.label(), ci.c.Subject.String(), ci.c.SerialNumber, strings.Join(why, ", "))})
				}
			case ci.st.cur != nil && g.newer(ci.st.cur) && !future(g):
				ci.st.notes = append(ci.st.notes, ask, fmt.Sprintf("the revocation of certificate %q was not checked: %s, newer than %s, lists it as revoked, and its signature cannot be checked", ci.c.Subject.String(), g.label(), ci.st.cur.label()))
				ci.st.from, ci.st.cur = "", nil
			default:
				ci.st.notes = append(ci.st.notes, ask+": not used")
			}
		}
		suspect(ci, ci.st.entries)
	}
	// Ключ сертификата вне цепочек, названного таким CRL, — ключ и
	// сертификатов цепочек: их статус тоже не известен.
	for _, ci := range order {
		ds := unknownKey[string(ci.c.RawSubjectPublicKeyInfo)]
		if !ci.inChain || len(ds) == 0 {
			continue
		}
		for _, d := range ds {
			ci.st.notes = append(ci.st.notes, d.ask, fmt.Sprintf("the revocation of certificate %q was not checked: %s", ci.c.Subject.String(), d.why))
		}
		ci.st.from, ci.st.cur = "", nil
	}
	status := func(c *x509.Certificate) *certStatus { return &certs[sha256.Sum256(c.Raw)].st }
	a.named = nil
	named := a.Named()
	out := make([]Verdict, len(a.stamps))
	for i, s := range a.stamps {
		out[i].Named = named
		if s.err != nil {
			continue
		}
		var best *Verdict
		var retired error
		for _, ch := range s.chains {
			v, err := a.r.verdictOf(ch, s.gen, status, byKey)
			if err != nil {
				retired = err
				continue
			}
			if best == nil || v.better(*best) {
				best = &v
			}
		}
		if best == nil {
			// Все цепочки не в силе по записям, которые видны только всей
			// оценке (CRL под новым ключом центра, retired их не знает).
			if retired == nil {
				retired = fmt.Errorf("%w: no certificate chain to check", ErrRevoked)
			}
			out[i] = Verdict{Retired: retired, Named: named}
			continue
		}
		best.Named = named
		if a.dropped > 0 {
			best.Notes = append(best.Notes, fmt.Sprintf("the time-stamps and -tsa-trust carry more than %d other certificates; %d of them were not looked at for revocations of their keys", maxKnown, a.dropped))
		}
		out[i] = *best
	}
	return out
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

// verdictOf — вердикт одной цепочки: отзыв без компрометации её сертификатов
// (у корня — только по перечню), отзыв центра без причины — подозрение на эту
// цепочку (chainOnly), и подозрение на их ключи по всей оценке.
func (r *Revocations) verdictOf(chain []*x509.Certificate, gen time.Time, status func(*x509.Certificate) *certStatus, byKey map[string]keyRevocation) (Verdict, error) {
	var v Verdict
	suspect := func(c *x509.Certificate, e Revocation) {
		if cut := e.Cutoff(); !v.NeedPOE || cut.Before(v.Cutoff) {
			v.NeedPOE, v.Cutoff, v.Revoked, v.Entry = true, cut, c, e
		}
	}
	for i, c := range chain {
		st := status(c)
		es := st.entries
		if i == len(chain)-1 {
			es = r.listed[sha256.Sum256(c.Raw)]
		} else {
			v.Notes = append(v.Notes, st.notes...)
			if st.from == "" {
				v.Unchecked = append(v.Unchecked, c)
			} else {
				v.CRLs = append(v.CRLs, st.from)
			}
		}
		for _, e := range es {
			switch {
			case keepsEarlier(e.Reason):
				if !gen.Before(e.Time) {
					return Verdict{}, retiredErr(c, e, gen)
				}
			case chainOnly(c, i == 0, e):
				e.From += "; a CA certificate revoked with no reason: the chains through it are under suspicion, not its key"
				suspect(c, e)
			}
		}
		k, ok := byKey[string(c.RawSubjectPublicKeyInfo)]
		if !ok {
			continue
		}
		e := k.e
		if !bytes.Equal(k.cert.Raw, c.Raw) {
			e.From = fmt.Sprintf("%s, for certificate %q (serial %s) issued by %q with the same key", e.From, k.cert.Subject.String(), k.cert.SerialNumber, k.cert.Issuer.String())
		}
		suspect(c, e)
	}
	return v, nil
}

// judge — что известно об отзыве сертификата c; issuers — сертификаты его
// центра из всех цепочек оценки (ключ у них один — тот, что подписал c; пусто
// — c только корень, и CRL не сверяется).
//
// Записи: перечень и все CRL с именем центра, подписанные его ключом (запись
// только добавляет подозрение, и её не отменяют ни keyUsage сертификата
// центра, ни область CRL, ни его возраст); удержание снимает более новый CRL,
// годный для статуса, который c не называет вовсе. Статус (from): самый
// свежий CRL, годный для статуса, — право центра на CRL хоть у одного из
// issuers, c в области, выпущен до истечения c или держит истёкшие, не из
// будущего; нет такого — notes говорят почему. CRL с именем центра под
// другим ключом, называющие c, — в listing: о ключе их судит Verdicts.
func (r *Revocations) judge(c *x509.Certificate, issuers []*x509.Certificate) certStatus {
	st := certStatus{entries: slices.Clone(r.listed[sha256.Sum256(c.Raw)])}
	if len(issuers) == 0 {
		return st
	}
	issuer := issuers[0].Subject.String()
	sn := c.SerialNumber.String()
	var own, foreign []*crlFile // подписан ключом центра — нет
	auth := map[*crlFile]bool{} // право на CRL — хоть у одного сертификата центра
	for _, f := range r.crlsNaming(c) {
		var keyErr, authErr error
		signed := false
		for _, is := range issuers {
			s := r.checkSig(f, is)
			switch {
			case s.key != nil:
				keyErr = s.key
			case s.auth != nil:
				signed, authErr = true, s.auth
			default:
				signed, auth[f] = true, true
			}
		}
		switch {
		case !signed && len(f.bySN[sn]) > 0:
			// Называет c: судит Verdicts (новый ключ центра или неизвестен).
			foreign = append(foreign, f)
			st.listing = append(st.listing, f)
			continue
		case !signed:
			foreign = append(foreign, f)
			st.notes = append(st.notes, fmt.Sprintf("CRL %s names the issuer %q, but is not signed with its key (%v): not used", f.name, issuer, keyErr))
			continue
		case !auth[f]:
			st.notes = append(st.notes, fmt.Sprintf("CRL %s is signed with the key of %q, but no certificate of that CA in the chains of the time-stamps may sign CRLs (%v): its entries count, but it does not show certificate %q is not revoked", f.name, issuer, authErr, c.Subject.String()))
		}
		own = append(own, f)
	}
	if len(own) == 0 {
		n := fmt.Sprintf("the revocation of certificate %q (issued by %q) was not checked: no CRL of its issuer was given (-tsa-crl)", c.Subject.String(), issuer)
		if len(foreign) > 0 {
			n = fmt.Sprintf("the revocation of certificate %q (issued by %q) was not checked: no CRL signed with the key of its issuer was given (-tsa-crl)", c.Subject.String(), issuer)
		}
		if r.lists > 0 && len(r.listed[sha256.Sum256(c.Raw)]) == 0 {
			n += ", and your list (-tsa-revoked) does not name it"
		}
		st.notes = append(st.notes, n)
		return st
	}
	sort.SliceStable(own, func(i, j int) bool { return own[i].newer(own[j]) })
	future := func(f *crlFile) bool { return f.rl.ThisUpdate.After(r.Now.Add(futureSlack)) }
	forStatus := func(f *crlFile) bool { return auth[f] && !future(f) && f.speaks(c) }
	for i, f := range own {
		for _, e := range f.bySN[sn] {
			// Снят с удержания: более новый CRL, годный для статуса, c не
			// называет вовсе (RFC 5280, 5.3.1). Названный в нём с другой
			// причиной — удержание сделано постоянным (так AD CS переписывает
			// и причину, и дату), и дата удержания в силе.
			if e.Reason == ReasonCertificateHold && slices.ContainsFunc(own[:i], func(g *crlFile) bool { return g.newer(f) && forStatus(g) && len(g.bySN[sn]) == 0 }) {
				continue
			}
			st.entries = append(st.entries, e)
		}
	}
	// CRL, выпущенный позже момента проверки (с запасом на часы), о нынешнем
	// статусе не говорит: часы центра или проверяющего неверны.
	var cur *crlFile
	for _, f := range own {
		if future(f) {
			st.notes = append(st.notes, fmt.Sprintf("%s is dated after the time of this check (%s): its entries count, but it is not taken for the status of certificate %q; check the clocks", f.label(), r.Now.UTC().Format(time.RFC3339), c.Subject.String()))
			continue
		}
		if forStatus(f) {
			cur = f
			break
		}
	}
	if cur == nil {
		for _, f := range own {
			switch {
			case future(f), !auth[f]:
				// названа выше
			case !f.scope.covers(c):
				st.notes = append(st.notes, fmt.Sprintf("the revocation of certificate %q was not checked by %s: %s; its entries count, but it does not show the certificate is not revoked", c.Subject.String(), f.label(), f.scope.why()))
			default:
				st.notes = append(st.notes, fmt.Sprintf("the revocation of certificate %q was not checked by %s: the certificate expired on %s, before that CRL, and a CA may drop an expired certificate from its CRLs; give a CRL of %q from before then too", c.Subject.String(), f.label(), c.NotAfter.UTC().Format(time.RFC3339), issuer))
			}
		}
		return st
	}
	// CRL с именем центра, но другим ключом, новее статусного и называющий c,
	// судит Verdicts (st.cur): центр мог сменить ключ. CRL другого ключа того
	// же центра (так их публикует AD CS) c не называет: статус по своему.
	st.from, st.cur = cur.label(), cur
	if cur.deltas {
		st.notes = append(st.notes, fmt.Sprintf("%s points to delta CRLs (freshest CRL): a revocation published only in a delta CRL since then is not seen, and esverify does not read delta CRLs; check against a full CRL issued later, or list such a revocation with -tsa-revoked", st.from))
	}
	switch {
	case cur.rl.NextUpdate.IsZero():
		st.notes = append(st.notes, fmt.Sprintf("%s names no next update: a revocation after it is not seen; fetch a fresh one", st.from))
	case !r.Now.Before(cur.rl.NextUpdate):
		st.notes = append(st.notes, fmt.Sprintf("%s is past its next update (%s): a revocation after it is not seen; fetch a fresh one", st.from, cur.rl.NextUpdate.UTC().Format(time.RFC3339)))
	}
	return st
}

// anchor — корень, как его понимает проверка пути: имя и ключ (RFC 5280,
// 6.1.1 d). Срок сертификата корня в него не входит: корень продлевают на тот
// же ключ, и прежний сертификат истекает.
type anchor struct{ name, key string }

func anchorOf(c *x509.Certificate) anchor {
	return anchor{string(c.RawSubject), string(c.RawSubjectPublicKeyInfo)}
}

// anchorsOf — корни цепочек сертификата.
func anchorsOf(roots []*x509.Certificate) map[anchor]bool {
	out := map[anchor]bool{}
	for _, r := range roots {
		out[anchorOf(r)] = true
	}
	return out
}

// maxPath — сколько центров может быть между сертификатом и корнем.
const maxPath = 8

// paths — выпуски между сертификатами, которым можно верить как данным о
// центрах: из цепочек меток и данными проверяющим (vouched). Сертификаты,
// что несут токены, сюда не входят: поле certificates в CMS не подписано, и
// подложить их можно сколько угодно, а путь через них ничего не добавил бы —
// ключ центра в цепочке или у проверяющего найдётся и так. По имени субъекта
// (байты и строка: кодировка имени у CRL и сертификата бывает разной), в
// порядке добавления. Подпись сверяется раз на пару.
type paths struct {
	by   map[string][]*x509.Certificate
	idx  map[*x509.Certificate]int
	fps  map[[32]byte]bool
	sigs map[[2]*x509.Certificate]bool
}

func newPaths() *paths {
	return &paths{by: map[string][]*x509.Certificate{}, idx: map[*x509.Certificate]int{}, fps: map[[32]byte]bool{}, sigs: map[[2]*x509.Certificate]bool{}}
}

func nameKeys(raw []byte, n pkix.Name) [2]string {
	return [2]string{"b" + string(raw), "s" + n.String()}
}

func (p *paths) add(c *x509.Certificate) {
	fp := sha256.Sum256(c.Raw)
	if p.fps[fp] {
		return
	}
	p.fps[fp] = true
	p.idx[c] = len(p.idx)
	for _, k := range nameKeys(c.RawSubject, c.Subject) {
		p.by[k] = append(p.by[k], c)
	}
}

// named — сертификаты с этим именем субъекта, без повторов, по порядку
// добавления.
func (p *paths) named(raw []byte, n pkix.Name) []*x509.Certificate {
	k := nameKeys(raw, n)
	out := slices.Clone(p.by[k[0]])
	for _, c := range p.by[k[1]] {
		if !slices.Contains(out, c) {
			out = append(out, c)
		}
	}
	slices.SortFunc(out, func(a, b *x509.Certificate) int { return p.idx[a] - p.idx[b] })
	return out
}

// issued — c подписан ключом parent, и parent — центр (CheckSignatureFrom:
// BasicConstraints, keyUsage). Сроки не сверяются.
func (p *paths) issued(c, parent *x509.Certificate) bool {
	k := [2]*x509.Certificate{c, parent}
	ok, done := p.sigs[k]
	if !done {
		ok = c.CheckSignatureFrom(parent) == nil
		p.sigs[k] = ok
	}
	return ok
}

// under — ключ c выпущен под одним из корней as: c сам с именем и ключом
// такого корня, или подписи от c вверх по сертификатам оценки доходят до
// него. Сроки не сверяются: CRL, засчитанный так, только добавляет записи
// (статуса не даёт, удержания не снимает), а ключ, однажды выпущенный под
// корнем с именем центра, — ключ этого центра.
func (p *paths) under(c *x509.Certificate, as map[anchor]bool, depth int, seen map[*x509.Certificate]int) bool {
	if as[anchorOf(c)] {
		return true
	}
	// seen — на какой глубине сертификат уже обойден: дойти до него ближе к
	// началу — обойти снова (глубже предел пути наступает позже).
	if d, ok := seen[c]; depth == maxPath || ok && d <= depth {
		return false
	}
	seen[c] = depth
	for _, parent := range p.named(c.RawIssuer, c.Issuer) {
		if parent != c && !bytes.Equal(parent.Raw, c.Raw) && p.issued(c, parent) && p.under(parent, as, depth+1, seen) {
			return true
		}
	}
	return false
}

// crlSigners — сертификаты с именем центра, выпустившего CRL g, чьим ключом g
// подписан и чей ключ выпущен под одним из корней as (RFC 5280, 6.3.3 f: путь
// издателя CRL — к тому же корню, что у сертификата; корень — имя и ключ):
// центр сменил ключ. Пусто — таких в оценке нет. Другого центра с тем же
// именем проверка не признаёт: имя издателя и номер называют один сертификат
// (RFC 5280, 4.1.2.2), и CRL, который нельзя связать с корнем, мог выпустить
// и сам центр под ключом, сертификата которого здесь нет.
func (r *Revocations) crlSigners(g *crlFile, p *paths, as map[anchor]bool) []*x509.Certificate {
	var out []*x509.Certificate
	for _, x := range p.named(g.rl.RawIssuer, g.rl.Issuer) {
		if r.checkSig(g, x).key == nil && p.under(x, as, 0, map[*x509.Certificate]int{}) {
			out = append(out, x)
		}
	}
	return out
}

// futureSlack — насколько CRL может быть «из будущего» по часам проверяющего
// и всё же говорить о нынешнем статусе.
const futureSlack = time.Hour

// Fingerprint — SHA-256 сертификата для перечня проверяющего (cert_sha256).
func Fingerprint(c *x509.Certificate) string {
	sum := sha256.Sum256(c.Raw)
	return hex.EncodeToString(sum[:])
}
