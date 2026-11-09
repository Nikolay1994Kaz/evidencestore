package proof

import (
	"bytes"
	"crypto/ed25519"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/Nikolay1994Kaz/evidencestore/internal/tsa"
)

// Печать организации на ключ хранилища (tsa.VerifySeal). Организация
// ставит печать сертификатом X.509 — печатью или ЭЦП юрлица — на заявление
// «этот ключ подписи голов — ключ моего хранилища» (SealStatement). Тогда
// проверяющему не нужно брать ключ хранилища у оператора: его закрепляет
// корень центра, выпустившего сертификат печати (esverify -seal-trust), а
// центр может сертификат отозвать.
//
// Отзыв сертификата печати сверяется вместе с метками пакета (одна оценка,
// revoked.go): печать в силе, если её сертификат не отозван до неё, а при
// компрометации — если она показана существовавшей раньше отсечки. Это
// показывает метка TSA над печатью (Token), которую хранилище берёт, как
// только ей дали печать: время самой печати (signingTime) ставит тот, у кого
// ключ.

// StoreSeal — печать на ключ хранилища в пакете.
type StoreSeal struct {
	CMS   []byte `json:"cms"`             // CMS SignedData с заявлением SealStatement
	Token []byte `json:"token,omitempty"` // метка TSA над печатью (SealImprint)
}

// SealDomain — домен метки над печатью: такую метку не выдать за метку
// головы.
const SealDomain = "evidencestore store seal v1\n"

const sealHeader = "evidencestore store key\n"

// SealStatement — заявление, на которое организация ставит печать: ключ
// подписи голов хранилища так, как его печатает evidencestore init и
// принимает esverify -store-key (base64 без «=»).
func SealStatement(pub ed25519.PublicKey) []byte {
	return []byte(sealHeader + base64.RawStdEncoding.EncodeToString(pub) + "\n")
}

// BundleSeal — печать из пакета любого вида, без разбора остального.
func BundleSeal(data []byte) *StoreSeal {
	var b struct {
		Seal *StoreSeal `json:"store_seal"`
	}
	if json.Unmarshal(data, &b) != nil {
		return nil
	}
	return b.Seal
}

// SealImprint — что заверяет метка над печатью.
func SealImprint(cms []byte) [32]byte { return tsa.Imprint(SealDomain, cms) }

// SealedStatementKey — ключ из заявления печати: ровно SealStatement, строки
// через LF или CRLF (openssl cms -sign без -binary пишет CRLF).
func SealedStatementKey(content []byte) (ed25519.PublicKey, error) {
	text := content
	if bytes.Contains(text, []byte("\r\n")) {
		text = bytes.ReplaceAll(text, []byte("\r\n"), []byte("\n"))
	}
	rest, ok := bytes.CutPrefix(text, []byte(sealHeader))
	line, tail, found := bytes.Cut(rest, []byte("\n"))
	if !ok || !found || len(tail) != 0 {
		return nil, errors.New("the sealed text is not an evidencestore store key statement (evidencestore seal-statement prints one)")
	}
	pub, err := base64.RawStdEncoding.Strict().DecodeString(string(line))
	if err != nil || len(pub) != ed25519.PublicKeySize {
		return nil, errors.New("the sealed statement names no Ed25519 key")
	}
	return ed25519.PublicKey(pub), nil
}

// sealTime — время метки над печатью: она заверяет SealImprint и проходит
// доверие к службам меток. Ноль — метки нет; why — почему её не взять.
func sealTime(s *StoreSeal, tsaTrust tsa.Trust) (tsa.Info, string) {
	if len(s.Token) == 0 {
		return tsa.Info{}, "the bundle carries no time-stamp over the seal"
	}
	info, err := tsa.Verify(s.Token, SealImprint(s.CMS), tsaTrust)
	if err != nil {
		return tsa.Info{}, fmt.Sprintf("the time-stamp over the seal does not verify (%v)", err)
	}
	return info, ""
}

// errNoOwner — ключ из печати без имени её владельца: под корнем центра
// сертификаты у многих, и печать любого ручалась бы за любой ключ.
var errNoOwner = errors.New("the store key is not pinned (-store-key), and nothing names whose seal must vouch for it (-seal-subject): a seal of anyone the CA certified would do")

// sealedBy — сертификат печати несёт все атрибуты имени, которых требует
// проверяющий.
func sealedBy(c *x509.Certificate, pins []tsa.SubjectPin) error {
	for _, p := range pins {
		if !p.In(c.Subject) {
			return fmt.Errorf("the seal is by %q, and its name has no %s (-seal-subject)", c.Subject.String(), p)
		}
	}
	return nil
}

// SealedKey — ключ хранилища из печати пакета, проверенной корнями
// t.SealTrust на момент метки над ней (без метки — на момент now), чей
// владелец назван в t.SealSubject: для esverify без -store-key. Отзыв
// сертификата печати сверяет Verify.
func SealedKey(s *StoreSeal, t Trust, now time.Time) (ed25519.PublicKey, error) {
	switch {
	case t.SealTrust == nil:
		return nil, errors.New("no roots for the seal (-seal-trust)")
	case len(t.SealSubject) == 0:
		return nil, errNoOwner
	case s == nil:
		return nil, errors.New("the bundle carries no seal of the store key")
	}
	at := now
	if info, why := sealTime(s, t.TSA); why == "" {
		at = info.GenTime
	}
	sealed, _, err := tsa.VerifySeal(s.CMS, *t.SealTrust, at)
	if err != nil {
		return nil, err
	}
	if err := sealedBy(sealed.Signer, t.SealSubject); err != nil {
		return nil, err
	}
	return SealedStatementKey(sealed.Content)
}

// withSealedKey — доверие с ключом хранилища из печати пакета, когда ключ не
// закреплён, а корни печати даны. Не сошлась — ключа нет, и пункт о подписи
// головы не проходит; почему — скажет пункт о печати.
func (t Trust) withSealedKey(s *StoreSeal) Trust {
	if t.StoreKey != nil || t.SealTrust == nil {
		return t
	}
	now := time.Now()
	if t.TSARevocations != nil {
		now = t.TSARevocations.Now
	}
	if k, err := SealedKey(s, t, now); err == nil {
		t.StoreKey = k
	}
	return t
}

// sealCheck — печать пакета, как её проверили; id, tokenID — номера печати и
// метки над ней в оценке отзыва (-1 — нет). nowID, nowErr — печать на
// момент проверки, когда метка есть: на случай, если метка окажется под
// подозрением и времени печати не покажет.
type sealCheck struct {
	err     error
	signer  *x509.Certificate
	at      time.Time // метка над печатью; ноль — нет
	why     string    // почему нет метки
	id      int
	tokenID int
	nowID   int
	nowErr  error
}

// sealCheckName — пункт отчёта о печати.
const sealCheckName = "the store key is sealed with an X.509 certificate of its owner"

// SealNotChecked — заметка, когда пакет несёт печать, а корня для неё не дали.
const SealNotChecked = "the bundle carries a seal of the store key (an X.509 certificate of its owner vouches for -store-key): pass the root of its CA with -seal-trust to check it"

// checkSeal — печать пакета (s) против trust.SealTrust: подпись, цепочка на
// момент метки над печатью, заявление о ключе trust.StoreKey. Сертификат
// печати и метка над ней входят в оценку отзыва пакета; пункт отчёта — в
// finish, вместе с отзывом.
func (sc *stampCheck) checkSeal(s *StoreSeal, trust Trust) {
	now := time.Now()
	if sc.revs != nil {
		now = sc.revs.Now
	}
	if trust.SealTrust == nil {
		if s != nil {
			sc.notes = append(sc.notes, SealNotChecked)
		}
		return
	}
	c := &sealCheck{id: -1, tokenID: -1, nowID: -1}
	sc.seal = c
	if s == nil {
		c.err = errors.New("the bundle carries no seal of the store key, and -seal-trust asks for one")
		return
	}
	// Метка, которая не в силе, времени печати не показывает: печать
	// судится на момент проверки, как без метки.
	info, why := sealTime(s, trust.TSA)
	if why == "" && sc.revs != nil {
		sc.ensureAssessment()
		sc.as.Known(info.Certs...)
		if id, err := sc.as.Add(info.Chains, info.GenTime); err == nil {
			c.tokenID = id
		} else {
			why = fmt.Sprintf("the time-stamp over the seal is not in force (%v)", err)
		}
	}
	at := now
	if why == "" {
		at, c.at = info.GenTime, info.GenTime
	}
	c.why = why
	sealed, chains, err := tsa.VerifySeal(s.CMS, *trust.SealTrust, at)
	if err != nil {
		c.err = err
		return
	}
	c.signer = sealed.Signer
	if err := sealedBy(sealed.Signer, trust.SealSubject); err != nil {
		c.err = err
		return
	}
	pub, err := SealedStatementKey(sealed.Content)
	switch {
	case err != nil:
		c.err = err
		return
	case trust.StoreKey == nil && len(trust.SealSubject) == 0:
		c.err = errNoOwner
		return
	case !pub.Equal(trust.StoreKey):
		c.err = errors.New("the seal vouches for another key than the store key this bundle is checked with")
		return
	}
	if sc.revs != nil {
		sc.ensureAssessment()
		sc.as.Known(sealed.Certs...)
		id, err := sc.as.Add(chains, at)
		if err != nil {
			c.err = fmt.Errorf("the seal certificate is not in force at %s: %v", fmtTime(at), err)
			return
		}
		c.id = id
		if c.tokenID >= 0 {
			if _, nowChains, err := tsa.VerifySeal(s.CMS, *trust.SealTrust, now); err != nil {
				c.nowErr = err
			} else if c.nowID, err = sc.as.Add(nowChains, now); err != nil {
				c.nowErr = fmt.Errorf("the seal certificate is not in force at %s: %v", fmtTime(now), err)
			}
		}
	}
}

// finishSeal — пункт о печати по вердиктам оценки (vs; nil — отзыв не
// сверяется). Печать под подозрением (сертификат отозван по компрометации)
// в силе, только если метка над ней раньше отсечки, сама не под подозрением
// и её отзыв проверен (время другой подписи показывает только метка,
// прошедшая проверку, ETSI EN 319 102-1).
func (sc *stampCheck) finishSeal(vs []tsa.Verdict, add func(string, error, string) bool) {
	c := sc.seal
	if c == nil {
		return
	}
	if c.err != nil {
		add(sealCheckName, c.err, "")
		return
	}
	// Метка над печатью под подозрением: её время выбирал тот, у кого ключ
	// службы, и цепочка печати на это время ничего не значит. Печать
	// судится на момент проверки, как без метки.
	at, id := c.at, c.id
	if c.tokenID >= 0 && (vs[c.tokenID].NeedPOE || vs[c.tokenID].Retired != nil) {
		if v := vs[c.tokenID]; v.Retired != nil {
			c.why = fmt.Sprintf("the time-stamp over the seal is not in force (%v)", v.Retired)
		} else {
			c.why = "the time-stamp over the seal rests on " + revokedWhy(v)
		}
		if c.nowErr != nil {
			add(sealCheckName, fmt.Errorf("%s, so it does not show when the seal was made, and at the time of the check the seal does not hold: %v", c.why, c.nowErr), "")
			return
		}
		at, id = time.Time{}, c.nowID
	}
	detail := fmt.Sprintf("%q, issued by %q", c.signer.Subject.String(), c.signer.Issuer.String())
	if at.IsZero() {
		detail += "; when the seal was made is not shown: " + c.why
	} else {
		detail += ", time-stamped at " + fmtTime(at)
	}
	if vs == nil {
		sc.notes = append(sc.notes, "the revocation of the seal certificate was not checked: pass the CRL of its CA with -tsa-crl, or list it with -tsa-revoked")
		add(sealCheckName, nil, detail)
		return
	}
	v := vs[id]
	sc.record(v)
	if v.Retired != nil {
		add(sealCheckName, fmt.Errorf("the seal certificate is not in force: %v (%s)", v.Retired, detail), "")
		return
	}
	if v.NeedPOE {
		if at.IsZero() || !at.Before(v.Cutoff) {
			add(sealCheckName, fmt.Errorf("the seal rests on %s: nothing shows it was made before %s (%s)", revokedWhy(v), fmtTime(v.Cutoff), detail), "")
			return
		}
		if tv := vs[c.tokenID]; len(tv.Unchecked) > 0 {
			add(sealCheckName, fmt.Errorf("the seal rests on %s, and the time-stamp over it would show it was made before %s, but the revocation of the time-stamp's own certificate was not checked (see the notes): pass the CRL of its CA with -tsa-crl (%s)", revokedWhy(v), fmtTime(v.Cutoff), detail), "")
			return
		}
		detail += "; it rests on " + revokedWhy(v) + ", and the time-stamp shows it was made earlier"
	}
	add(sealCheckName, nil, detail)
}
