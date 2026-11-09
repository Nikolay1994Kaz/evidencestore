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

// SealedKey — ключ хранилища из печати пакета, проверенной корнями seal на
// момент метки над ней (без метки — на момент now): для esverify без
// -store-key. Отзыв сертификата печати сверяет Verify.
func SealedKey(s *StoreSeal, seal, tsaTrust tsa.Trust, now time.Time) (ed25519.PublicKey, error) {
	if s == nil {
		return nil, errors.New("the bundle carries no seal of the store key")
	}
	at := now
	if info, why := sealTime(s, tsaTrust); why == "" {
		at = info.GenTime
	}
	sealed, _, err := tsa.VerifySeal(s.CMS, seal, at)
	if err != nil {
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
	if k, err := SealedKey(s, *t.SealTrust, t.TSA, now); err == nil {
		t.StoreKey = k
	}
	return t
}

// sealCheck — печать пакета, как её проверили; id, tokenID — номера печати и
// метки над ней в оценке отзыва (-1 — нет).
type sealCheck struct {
	err     error
	signer  *x509.Certificate
	at      time.Time // метка над печатью; ноль — нет
	why     string    // почему нет метки
	id      int
	tokenID int
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
	c := &sealCheck{id: -1, tokenID: -1}
	sc.seal = c
	if s == nil {
		c.err = errors.New("the bundle carries no seal of the store key, and -seal-trust asks for one")
		return
	}
	info, why := sealTime(s, trust.TSA)
	at := now
	if why == "" {
		at = info.GenTime
		if sc.revs != nil {
			sc.ensureAssessment()
			if id, err := sc.as.Add(info.Chains, info.GenTime); err == nil {
				c.tokenID = id
			} else {
				why = fmt.Sprintf("the time-stamp over the seal is not in force (%v)", err)
			}
		}
	}
	if why == "" {
		c.at = info.GenTime
	}
	c.why = why
	sealed, chains, err := tsa.VerifySeal(s.CMS, *trust.SealTrust, at)
	if err != nil {
		c.err = err
		return
	}
	c.signer = sealed.Signer
	pub, err := SealedStatementKey(sealed.Content)
	switch {
	case err != nil:
		c.err = err
		return
	case !pub.Equal(trust.StoreKey):
		c.err = errors.New("the seal vouches for another key than the store key this bundle is checked with")
		return
	}
	if sc.revs != nil {
		sc.ensureAssessment()
		id, err := sc.as.Add(chains, at)
		if err != nil {
			c.err = fmt.Errorf("the seal certificate is not in force at %s: %v", fmtTime(at), err)
			return
		}
		c.id = id
	}
}

// finishSeal — пункт о печати по вердиктам оценки (vs; nil — отзыв не
// сверяется). Печать под подозрением (сертификат отозван по компрометации)
// в силе, только если метка над ней не под подозрением и раньше отсечки.
func (sc *stampCheck) finishSeal(vs []tsa.Verdict, add func(string, error, string) bool) {
	c := sc.seal
	if c == nil {
		return
	}
	if c.err != nil {
		add(sealCheckName, c.err, "")
		return
	}
	at := c.at
	if c.tokenID >= 0 && vs != nil && vs[c.tokenID].NeedPOE {
		at, c.why = time.Time{}, "the time-stamp over the seal rests on "+revokedWhy(vs[c.tokenID])
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
	v := vs[c.id]
	sc.record(v)
	if v.NeedPOE {
		if at.IsZero() || !at.Before(v.Cutoff) {
			add(sealCheckName, fmt.Errorf("the seal rests on %s: nothing shows it was made before %s (%s)", revokedWhy(v), fmtTime(v.Cutoff), detail), "")
			return
		}
		detail += "; it rests on " + revokedWhy(v) + ", and the time-stamp shows it was made earlier"
	}
	add(sealCheckName, nil, detail)
}
