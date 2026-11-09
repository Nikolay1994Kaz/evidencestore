package tsa

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/pem"
	"errors"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// revWorld — служба, её токен и каталог для CRL.
type revWorld struct {
	t    *testing.T
	a    *Authority
	info Info
	gen  time.Time
	dir  string
}

func newRevWorld(t *testing.T) *revWorld {
	t.Helper()
	a, err := NewAuthority(false)
	if err != nil {
		t.Fatal(err)
	}
	gen := time.Date(2026, 10, 1, 12, 0, 0, 0, time.UTC)
	a.Now = func() time.Time { return gen }
	imprint := sha256.Sum256([]byte("head"))
	token, err := a.Sign(imprint[:], nil)
	if err != nil {
		t.Fatal(err)
	}
	info, err := Verify(token, imprint, a.Trust())
	if err != nil {
		t.Fatal(err)
	}
	if len(info.Chains) != 1 || len(info.Chains[0]) != 2 {
		t.Fatalf("цепочки токена: %d", len(info.Chains))
	}
	return &revWorld{t: t, a: a, info: info, gen: gen, dir: t.TempDir()}
}

// crl пишет CRL корня службы с записями и отдаёт путь.
func (w *revWorld) crl(name string, next time.Time, entries ...x509.RevocationListEntry) string {
	w.t.Helper()
	der, err := w.a.RevocationList(w.gen.Add(24*time.Hour), next, entries...)
	if err != nil {
		w.t.Fatal(err)
	}
	p := filepath.Join(w.dir, name)
	if err := os.WriteFile(p, der, 0o600); err != nil {
		w.t.Fatal(err)
	}
	return p
}

func (w *revWorld) check(r *Revocations) (Verdict, error) {
	return r.Check(w.info.Chains, w.info.GenTime)
}

// hasNote — есть ли у вердикта заметка с sub.
func hasNote(v Verdict, sub string) bool {
	for _, n := range v.Notes {
		if strings.Contains(n, sub) {
			return true
		}
	}
	return false
}

func ext(t *testing.T, id asn1.ObjectIdentifier, v any, params string) pkix.Extension {
	b, err := asn1.MarshalWithParams(v, params)
	if err != nil {
		t.Fatal(err)
	}
	return pkix.Extension{Id: id, Value: b}
}

// Без сведений об отзыве — проверять нечем: сертификат службы назван
// непроверенным. CRL центра, где его нет, — проверен и не отозван.
func TestRevocationsNotRevoked(t *testing.T) {
	w := newRevWorld(t)
	now := w.gen.Add(48 * time.Hour)
	v, err := w.check(NewRevocations(now))
	if err != nil || v.NeedPOE || len(v.Unchecked) != 1 || v.Unchecked[0] != w.info.Signer {
		t.Fatalf("без CRL: %+v %v", v, err)
	}
	r := NewRevocations(now)
	other := x509.RevocationListEntry{SerialNumber: big.NewInt(777), RevocationTime: w.gen}
	if err := r.AddCRL(w.crl("root.crl", now.Add(time.Hour), other)); err != nil {
		t.Fatal(err)
	}
	v, err = w.check(r)
	if err != nil || v.NeedPOE || v.Revoked != nil || len(v.Unchecked) != 0 || len(v.CRLs) != 1 || len(v.Notes) != 0 {
		t.Fatalf("CRL без записи о службе: %+v %v", v, err)
	}
}

// Отзыв без компрометации (RFC 3161, 4, п. 1): метки до даты отзыва в силе,
// с неё — нет. Явная причина unspecified — то же.
func TestRevocationsWithoutCompromise(t *testing.T) {
	w := newRevWorld(t)
	now := w.gen.Add(48 * time.Hour)
	serial := w.a.Cert().SerialNumber
	for name, reason := range map[string]int{"superseded": ReasonSuperseded, "cessation": ReasonCessationOfOperation, "unspecified": ReasonUnspecified} {
		for _, at := range []struct {
			when  time.Time
			valid bool
		}{{w.gen.Add(time.Hour), true}, {w.gen, false}} { // после метки — в силе; ровно во время — уже нет
			r := NewRevocations(now)
			if err := r.AddCRL(w.reasonCRL(name+".crl", now.Add(time.Hour), serial, at.when, reason)); err != nil {
				t.Fatal(err)
			}
			v, err := w.check(r)
			if at.valid && (err != nil || v.NeedPOE) || !at.valid && (!errors.Is(err, ErrRevoked) || !strings.Contains(err.Error(), "not earlier")) {
				t.Fatalf("%s, отзыв %s: %+v %v", name, at.when, v, err)
			}
		}
	}
}

// reasonCRL — CRL корня с одной записью и явной причиной, unspecified (0)
// тоже: x509 не пишет её через RevocationListEntry, только через прежнее
// поле RevokedCertificates.
func (w *revWorld) reasonCRL(name string, next time.Time, serial *big.Int, at time.Time, reason int) string {
	w.t.Helper()
	der, err := x509.CreateRevocationList(rand.Reader, &x509.RevocationList{
		Number: big.NewInt(1), ThisUpdate: w.gen.Add(24 * time.Hour), NextUpdate: next,
		RevokedCertificates: []pkix.RevokedCertificate{{SerialNumber: serial, RevocationTime: at,
			Extensions: []pkix.Extension{ext(w.t, oidReasonCode, asn1.Enumerated(reason), "")}}},
	}, w.a.root, w.a.rootKey)
	if err != nil {
		w.t.Fatal(err)
	}
	p := filepath.Join(w.dir, name)
	if err := os.WriteFile(p, der, 0o600); err != nil {
		w.t.Fatal(err)
	}
	return p
}

// Компрометация или нет причины (п. 2): времени метки верить нельзя — нужна
// POE раньше отсечки; отсечка — invalidityDate, если она раньше даты отзыва.
func TestRevocationsCompromiseNeedsPOE(t *testing.T) {
	w := newRevWorld(t)
	now := w.gen.Add(48 * time.Hour)
	serial := w.a.Cert().SerialNumber
	revoked := w.gen.Add(10 * time.Hour)
	suspected := w.gen.Add(-5 * time.Hour)
	cases := []struct {
		name   string
		e      x509.RevocationListEntry
		cutoff time.Time
		reason int
	}{
		{"keyCompromise", x509.RevocationListEntry{SerialNumber: serial, RevocationTime: revoked, ReasonCode: ReasonKeyCompromise}, revoked, ReasonKeyCompromise},
		{"keyCompromise с invalidityDate", x509.RevocationListEntry{SerialNumber: serial, RevocationTime: revoked, ReasonCode: ReasonKeyCompromise,
			ExtraExtensions: []pkix.Extension{ext(t, oidInvalidityDate, suspected, "generalized")}}, suspected, ReasonKeyCompromise},
		{"без причины", x509.RevocationListEntry{SerialNumber: serial, RevocationTime: revoked}, revoked, ReasonAbsent},
		{"certificateHold", x509.RevocationListEntry{SerialNumber: serial, RevocationTime: revoked, ReasonCode: ReasonCertificateHold}, revoked, ReasonCertificateHold},
	}
	for i, c := range cases {
		r := NewRevocations(now)
		if err := r.AddCRL(w.crl("c"+string(rune('a'+i))+".crl", now.Add(time.Hour), c.e)); err != nil {
			t.Fatal(err)
		}
		v, err := w.check(r)
		if err != nil || !v.NeedPOE || !v.Cutoff.Equal(c.cutoff) || v.Revoked != w.info.Signer || v.Entry.Reason != c.reason {
			t.Fatalf("%s: %+v %v", c.name, v, err)
		}
	}
	// Снятие с удержания (removeFromCRL) — не отзыв.
	r := NewRevocations(now)
	if err := r.AddCRL(w.crl("removed.crl", now.Add(time.Hour), x509.RevocationListEntry{SerialNumber: serial, RevocationTime: revoked, ReasonCode: ReasonRemoveFromCRL})); err != nil {
		t.Fatal(err)
	}
	if v, err := w.check(r); err != nil || v.NeedPOE {
		t.Fatalf("removeFromCRL: %+v %v", v, err)
	}
}

// CRL центра с тем же именем, но не его подписью, — не его CRL: отзыв не
// проверен, и это названо. Старый CRL (nextUpdate прошёл) — проверен, но
// назван несвежим. PEM — тоже CRL.
func TestRevocationsCRLItself(t *testing.T) {
	w := newRevWorld(t)
	now := w.gen.Add(48 * time.Hour)
	other, err := NewAuthority(false) // корень с тем же именем, другой ключ
	if err != nil {
		t.Fatal(err)
	}
	der, err := other.RevocationList(w.gen, now.Add(time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	p := filepath.Join(w.dir, "foreign.crl")
	os.WriteFile(p, der, 0o600)
	r := NewRevocations(now)
	if err := r.AddCRL(p); err != nil {
		t.Fatal(err)
	}
	if v, err := w.check(r); err != nil || len(v.Unchecked) != 1 || !hasNote(v, "is not signed with its key") || !hasNote(v, "no CRL signed with the key of its issuer") {
		t.Fatalf("чужой CRL: %+v %v", v, err)
	}
	// Есть и свой — берётся он.
	if err := r.AddCRL(w.crl("own.crl", now.Add(time.Hour))); err != nil {
		t.Fatal(err)
	}
	if v, err := w.check(r); err != nil || len(v.Unchecked) != 0 || len(v.CRLs) != 1 || !hasNote(v, "is not signed with its key") {
		t.Fatalf("свой CRL рядом с чужим: %+v %v", v, err)
	}
	// Чужой новее своего, сертификат не называет — CRL другого центра с тем же
	// именем или другого ключа того же центра (так публикует AD CS): статус по
	// своему.
	der, err = other.RevocationList(w.gen.Add(36*time.Hour), now.Add(time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	newer := filepath.Join(w.dir, "rollover.crl")
	os.WriteFile(newer, der, 0o600)
	if err := r.AddCRL(newer); err != nil {
		t.Fatal(err)
	}
	if v, err := w.check(r); err != nil || len(v.Unchecked) != 0 || len(v.CRLs) != 1 || hasNote(v, "did the CA change its key?") {
		t.Fatalf("CRL с тем же именем под другим ключом новее своего, без записи: %+v %v", v, err)
	}
	// Называет — центр мог сменить ключ и отозвать сертификат уже им, а его
	// подпись не сверить: статус не известен. Вердикт по нему не меняется.
	der, err = other.RevocationList(w.gen.Add(40*time.Hour), now.Add(time.Hour), x509.RevocationListEntry{SerialNumber: w.a.Cert().SerialNumber, RevocationTime: w.gen.Add(39 * time.Hour), ReasonCode: ReasonKeyCompromise})
	if err != nil {
		t.Fatal(err)
	}
	os.WriteFile(newer, der, 0o600)
	r = NewRevocations(now)
	r.AddCRL(w.crl("own.crl", now.Add(time.Hour)))
	if err := r.AddCRL(newer); err != nil {
		t.Fatal(err)
	}
	if v, err := w.check(r); err != nil || v.NeedPOE || len(v.Unchecked) != 1 || !hasNote(v, "did the CA change its key?") {
		t.Fatalf("CRL центра под другим ключом новее своего, с записью: %+v %v", v, err)
	}

	r = NewRevocations(now)
	stale := w.crl("stale.crl", now.Add(-time.Minute))
	data, _ := os.ReadFile(stale)
	pemPath := filepath.Join(w.dir, "stale.pem")
	os.WriteFile(pemPath, pem.EncodeToMemory(&pem.Block{Type: "X509 CRL", Bytes: data}), 0o600)
	if err := r.AddCRL(pemPath); err != nil {
		t.Fatal(err)
	}
	if v, err := w.check(r); err != nil || !hasNote(v, "past its next update") || len(v.CRLs) != 1 {
		t.Fatalf("несвежий CRL в PEM: %+v %v", v, err)
	}
	notCRL := filepath.Join(w.dir, "cert.pem")
	os.WriteFile(notCRL, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: w.a.Root().Raw}), 0o600)
	if err := NewRevocations(now).AddCRL(notCRL); err == nil {
		t.Fatal("сертификат принят за CRL")
	}
}

// Перечень проверяющего: отзыв по отпечатку, в том числе корня; разбор
// строгий.
func TestRevocationsList(t *testing.T) {
	w := newRevWorld(t)
	now := w.gen.Add(48 * time.Hour)
	write := func(body string) string {
		p := filepath.Join(w.dir, "list.json")
		os.WriteFile(p, []byte(body), 0o600)
		return p
	}
	r := NewRevocations(now)
	if err := r.AddList(write(`[{"cert_sha256": "` + Fingerprint(w.a.Cert()) + `", "revoked": "2026-10-03T00:00:00Z", "reason": "keyCompromise", "invalidity": "2026-09-30T00:00:00Z"}]`)); err != nil {
		t.Fatal(err)
	}
	v, err := w.check(r)
	if err != nil || !v.NeedPOE || !v.Cutoff.Equal(time.Date(2026, 9, 30, 0, 0, 0, 0, time.UTC)) {
		t.Fatalf("компрометация по перечню: %+v %v", v, err)
	}
	// Корень выведен из работы до метки — метка не в силе.
	r = NewRevocations(now)
	if err := r.AddList(write(`[{"cert_sha256": "` + Fingerprint(w.a.Root()) + `", "revoked": "2026-09-01T00:00:00Z", "reason": "cessationOfOperation"}]`)); err != nil {
		t.Fatal(err)
	}
	if _, err := w.check(r); !errors.Is(err, ErrRevoked) {
		t.Fatalf("корень выведен до метки: %v", err)
	}
	// Ключ корня скомпрометирован (по перечню): под подозрением всё под ним.
	r = NewRevocations(now)
	if err := r.AddList(write(`[{"cert_sha256": "` + Fingerprint(w.a.Root()) + `", "revoked": "2026-10-03T00:00:00Z", "reason": "keyCompromise"}]`)); err != nil {
		t.Fatal(err)
	}
	if v, err := w.check(r); err != nil || !v.NeedPOE || v.Revoked == nil || !bytes.Equal(v.Revoked.Raw, w.a.Root().Raw) {
		t.Fatalf("компрометация корня по перечню: %+v %v", v, err)
	}
	for name, body := range map[string]string{
		"не hex":        `[{"cert_sha256": "xyz", "revoked": "2026-09-01T00:00:00Z"}]`,
		"без времени":   `[{"cert_sha256": "` + Fingerprint(w.a.Root()) + `"}]`,
		"чужая причина": `[{"cert_sha256": "` + Fingerprint(w.a.Root()) + `", "revoked": "2026-09-01T00:00:00Z", "reason": "stolen"}]`,
		"removeFromCRL": `[{"cert_sha256": "` + Fingerprint(w.a.Root()) + `", "revoked": "2026-09-01T00:00:00Z", "reason": "removeFromCRL"}]`,
		"лишнее поле":   `[{"cert_sha256": "` + Fingerprint(w.a.Root()) + `", "revoked": "2026-09-01T00:00:00Z", "why": "x"}]`,
		"не список":     `{"cert_sha256": "x"}`,
	} {
		if err := NewRevocations(now).AddList(write(body)); err == nil {
			t.Errorf("%s: принято", name)
		}
	}
}

// crlAt — CRL корня службы с thisUpdate this и расширениями CRL extra.
func (w *revWorld) crlAt(name string, this, next time.Time, extra []pkix.Extension, entries ...x509.RevocationListEntry) string {
	w.t.Helper()
	der, err := x509.CreateRevocationList(rand.Reader, &x509.RevocationList{
		Number: big.NewInt(this.Unix()), ThisUpdate: this, NextUpdate: next,
		RevokedCertificateEntries: entries, ExtraExtensions: extra,
	}, w.a.root, w.a.rootKey)
	if err != nil {
		w.t.Fatal(err)
	}
	p := filepath.Join(w.dir, name)
	if err := os.WriteFile(p, der, 0o600); err != nil {
		w.t.Fatal(err)
	}
	return p
}

// Записи всех CRL центра действуют вместе: центр убрал истёкший отозванный
// сертификат из нового CRL — запись старого в силе, а не «не отозван» по
// самому свежему.
func TestRevocationsAllCRLsOfIssuer(t *testing.T) {
	w := newRevWorld(t)
	now := w.gen.Add(48 * time.Hour)
	serial := w.a.Cert().SerialNumber
	revoked := w.gen.Add(10 * time.Hour)
	r := NewRevocations(now)
	if err := r.AddCRL(w.crlAt("old.crl", w.gen.Add(11*time.Hour), w.gen.Add(12*time.Hour), nil,
		x509.RevocationListEntry{SerialNumber: serial, RevocationTime: revoked, ReasonCode: ReasonKeyCompromise})); err != nil {
		t.Fatal(err)
	}
	if err := r.AddCRL(w.crlAt("new.crl", w.gen.Add(24*time.Hour), now.Add(time.Hour), nil)); err != nil {
		t.Fatal(err)
	}
	v, err := w.check(r)
	if err != nil || !v.NeedPOE || !v.Cutoff.Equal(revoked) || len(v.CRLs) != 1 || !strings.Contains(v.CRLs[0], "new.crl") || len(v.Notes) != 0 {
		t.Fatalf("отзыв в старом CRL, нет в новом: %+v %v", v, err)
	}
}

// Дельта-CRL, косвенный CRL и CRL с непонятным критичным расширением — отказ
// при чтении: по ним отсутствие записи ничего не значит (RFC 5280, 5.2).
func TestRevocationsCRLExtensions(t *testing.T) {
	w := newRevWorld(t)
	now := w.gen.Add(48 * time.Hour)
	serial := w.a.Cert().SerialNumber
	base, _ := asn1.Marshal(big.NewInt(5))
	crit := func(id asn1.ObjectIdentifier, v []byte) []pkix.Extension {
		return []pkix.Extension{{Id: id, Critical: true, Value: v}}
	}
	idp := func(content ...[]byte) []byte {
		var b []byte
		for _, c := range content {
			b = append(b, c...)
		}
		return tlv(0x30, b)
	}
	uri := func(u string) []byte { return tlv(0xA0, tlv(0xA0, tlv(0x86, []byte(u)))) }
	for name, c := range map[string]struct {
		extra []pkix.Extension
		entry []pkix.Extension
		want  string
	}{
		"дельта":                     {extra: crit(oidDeltaCRL, base), want: "delta CRL"},
		"косвенный":                  {extra: crit(oidIssuingDP, idp(tlv(0x84, []byte{0xff}))), want: "indirect CRL"},
		"чужой центр в записи":       {entry: crit(oidCertIssuer, tlv(0x30, nil)), want: "indirect CRL"},
		"критичное расширение":       {extra: crit(asn1.ObjectIdentifier{1, 2, 3, 4}, []byte{0x05, 0x00}), want: "critical extension 1.2.3.4"},
		"критичное в записи":         {entry: crit(asn1.ObjectIdentifier{1, 2, 3, 5}, []byte{0x05, 0x00}), want: "critical extension 1.2.3.5"},
		"негодная точка":             {extra: crit(oidIssuingDP, []byte{0x30, 0x03, 0x81}), want: "does not parse"},
		"точка с URI — в порядке":    {extra: crit(oidIssuingDP, idp(uri("http://crl.example/a.crl")))},
		"только сертификаты центров": {extra: crit(oidIssuingDP, idp(tlv(0x82, []byte{0xff})))},
	} {
		p := w.crlAt(strings.ReplaceAll(name, " ", "_")+".crl", w.gen.Add(24*time.Hour), now.Add(time.Hour), c.extra,
			x509.RevocationListEntry{SerialNumber: serial, RevocationTime: w.gen.Add(10 * time.Hour), ReasonCode: ReasonKeyCompromise, ExtraExtensions: c.entry})
		err := NewRevocations(now).AddCRL(p)
		if c.want == "" && err != nil || c.want != "" && (err == nil || !strings.Contains(err.Error(), c.want)) {
			t.Errorf("%s: %v", name, err)
		}
	}
}

// CRL с issuingDistributionPoint проверяет только свою часть: CRL только
// сертификатов центров или точки, которой нет в сертификате службы, его
// не покрывает — «не проверено» с заметкой, но запись в нём в силе.
func TestRevocationsCRLScope(t *testing.T) {
	w := newRevWorld(t)
	now := w.gen.Add(48 * time.Hour)
	serial := w.a.Cert().SerialNumber
	idp := func(content []byte) []pkix.Extension {
		return []pkix.Extension{{Id: oidIssuingDP, Critical: true, Value: tlv(0x30, content)}}
	}
	onlyCA := idp(tlv(0x82, []byte{0xff}))
	onlyUser := idp(tlv(0x81, []byte{0xff}))
	someReasons := idp(tlv(0x83, []byte{0x07, 0x80}))
	dp := idp(tlv(0xA0, tlv(0xA0, tlv(0x86, []byte("http://crl.example/a.crl")))))
	for name, c := range map[string]struct {
		extra  []pkix.Extension
		covers bool
	}{
		"только центры":   {onlyCA, false},
		"только конечные": {onlyUser, true},
		"не все причины":  {someReasons, false},
		"точка не та":     {dp, false},
	} {
		r := NewRevocations(now)
		if err := r.AddCRL(w.crlAt("empty.crl", w.gen.Add(24*time.Hour), now.Add(time.Hour), c.extra)); err != nil {
			t.Fatal(err)
		}
		v, err := w.check(r)
		if err != nil || v.NeedPOE || (len(v.Unchecked) == 0) != c.covers || hasNote(v, "was not checked by") == c.covers {
			t.Errorf("%s, пустой CRL: %+v %v", name, v, err)
		}
		r = NewRevocations(now)
		if err := r.AddCRL(w.crlAt("listed.crl", w.gen.Add(24*time.Hour), now.Add(time.Hour), c.extra,
			x509.RevocationListEntry{SerialNumber: serial, RevocationTime: w.gen.Add(10 * time.Hour), ReasonCode: ReasonKeyCompromise})); err != nil {
			t.Fatal(err)
		}
		if v, err := w.check(r); err != nil || !v.NeedPOE {
			t.Errorf("%s, запись в CRL: %+v %v", name, v, err)
		}
	}
	// Сертификат с точкой распространения из CRL — покрыт.
	leaf := &x509.Certificate{CRLDistributionPoints: []string{"http://crl.example/a.crl"}}
	sc, indirect, err := parseScope(tlv(0x30, tlv(0xA0, tlv(0xA0, tlv(0x86, []byte("http://crl.example/a.crl"))))))
	if err != nil || indirect || !sc.covers(leaf) || sc.covers(&x509.Certificate{CRLDistributionPoints: []string{"http://other/b.crl"}}) {
		t.Fatalf("точка распространения: %+v %v %v", sc, indirect, err)
	}
}

// pki — свой УЦ для тестов отзыва: сертификаты с нужными сроками, ключами и
// перекрёстными выпусками.
type pki struct {
	cert *x509.Certificate
	key  crypto.Signer
}

func newKey(t *testing.T) crypto.Signer {
	t.Helper()
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return k
}

// issue выпускает сертификат tmpl с ключом key подписью ca (nil —
// самоподписанный).
func issue(t *testing.T, tmpl *x509.Certificate, key crypto.Signer, ca *pki) *pki {
	t.Helper()
	parent, signer := tmpl, key
	if ca != nil {
		parent, signer = ca.cert, ca.key
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, parent, key.Public(), signer)
	if err != nil {
		t.Fatal(err)
	}
	c, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return &pki{cert: c, key: key}
}

func caTmpl(serial int64, cn string) *x509.Certificate {
	return &x509.Certificate{SerialNumber: big.NewInt(serial), Subject: pkix.Name{CommonName: cn},
		NotBefore: time.Date(2020, 1, 1, 0, 0, 0, 0, time.UTC), NotAfter: time.Date(2040, 1, 1, 0, 0, 0, 0, time.UTC),
		KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageCRLSign, BasicConstraintsValid: true, IsCA: true}
}

// tsaUnder — служба меток с сертификатом от ca, сроком до notAfter; её токен
// на момент gen, проверенный корнями roots с промежуточными inter.
func tsaUnder(t *testing.T, ca *pki, notAfter, gen time.Time, roots []*x509.Certificate, inter ...*x509.Certificate) (*pki, Info) {
	t.Helper()
	leaf := issue(t, &x509.Certificate{SerialNumber: big.NewInt(77), Subject: pkix.Name{CommonName: "test TSA"},
		NotBefore: time.Date(2021, 1, 1, 0, 0, 0, 0, time.UTC), NotAfter: notAfter,
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageTimeStamping}}, newKey(t), ca)
	a := &Authority{key: leaf.key, cert: leaf.cert, root: ca.cert, policy: demoPolicy, Now: func() time.Time { return gen }}
	imprint := sha256.Sum256([]byte("head"))
	token, err := a.Sign(imprint[:], nil)
	if err != nil {
		t.Fatal(err)
	}
	pool := x509.NewCertPool()
	for _, r := range roots {
		pool.AddCert(r)
	}
	info, err := Verify(token, imprint, Trust{Roots: pool, Intermediates: inter})
	if err != nil {
		t.Fatal(err)
	}
	return leaf, info
}

// crlOf — CRL центра ca в каталоге dir.
func (ca *pki) crlOf(t *testing.T, dir, name string, this, next time.Time, extra []pkix.Extension, entries ...x509.RevocationListEntry) string {
	t.Helper()
	der, err := x509.CreateRevocationList(rand.Reader, &x509.RevocationList{Number: big.NewInt(this.Unix()), ThisUpdate: this, NextUpdate: next,
		RevokedCertificateEntries: entries, ExtraExtensions: extra}, ca.cert, ca.key)
	if err != nil {
		t.Fatal(err)
	}
	p := filepath.Join(dir, name)
	if err := os.WriteFile(p, der, 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

// Сертификат службы отозван по компрометации и истёк; центр убрал его из
// CRL, выпущенного после истечения (RFC 5280, 3.3). Такой CRL о нём не
// говорит: «не проверено» с заметкой, а не «не отозван». С CRL того времени
// — компрометация видна; CRL с expiredCertsOnCRL говорит и об истёкших.
func TestRevocationsAfterExpiry(t *testing.T) {
	dir := t.TempDir()
	root := issue(t, caTmpl(1, "expiry CA"), newKey(t), nil)
	expires := time.Date(2026, 10, 15, 0, 0, 0, 0, time.UTC)
	gen := time.Date(2026, 10, 1, 0, 0, 0, 0, time.UTC)
	leaf, info := tsaUnder(t, root, expires, gen, []*x509.Certificate{root.cert})
	now := time.Date(2026, 11, 6, 0, 0, 0, 0, time.UTC)
	entry := x509.RevocationListEntry{SerialNumber: leaf.cert.SerialNumber, RevocationTime: time.Date(2026, 10, 5, 0, 0, 0, 0, time.UTC), ReasonCode: ReasonKeyCompromise}
	old := root.crlOf(t, dir, "old.crl", time.Date(2026, 10, 10, 0, 0, 0, 0, time.UTC), time.Date(2026, 10, 17, 0, 0, 0, 0, time.UTC), nil, entry)
	fresh := root.crlOf(t, dir, "fresh.crl", time.Date(2026, 11, 5, 0, 0, 0, 0, time.UTC), now.Add(24*time.Hour), nil)
	keeps, _ := asn1.MarshalWithParams(time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC), "generalized")
	held := root.crlOf(t, dir, "keeps.crl", time.Date(2026, 11, 5, 0, 0, 0, 0, time.UTC), now.Add(24*time.Hour), []pkix.Extension{{Id: oidExpiredCerts, Value: keeps}})

	r := NewRevocations(now)
	r.AddCRL(fresh)
	v, err := r.Check(info.Chains, info.GenTime)
	if err != nil || v.NeedPOE || len(v.Unchecked) != 1 || len(v.CRLs) != 0 || !hasNote(v, "expired on 2026-10-15") {
		t.Fatalf("только CRL после истечения: %+v %v", v, err)
	}
	r.AddCRL(old)
	if v, err := r.Check(info.Chains, info.GenTime); err != nil || !v.NeedPOE || len(v.Unchecked) != 0 || !strings.Contains(v.CRLs[0], "old.crl") || !hasNote(v, "past its next update") {
		t.Fatalf("и CRL того времени: %+v %v", v, err)
	}
	r = NewRevocations(now)
	r.AddCRL(held)
	if v, err := r.Check(info.Chains, info.GenTime); err != nil || v.NeedPOE || len(v.Unchecked) != 0 || len(v.Notes) != 0 {
		t.Fatalf("CRL держит истёкшие: %+v %v", v, err)
	}
}

// Удержание (certificateHold) обратимо: его снимает более новый CRL, где
// записи нет. Удержание в самом новом — в силе (POE), а компрометация из
// любого CRL — тоже.
func TestRevocationsHold(t *testing.T) {
	w := newRevWorld(t)
	now := w.gen.Add(48 * time.Hour)
	serial := w.a.Cert().SerialNumber
	hold := x509.RevocationListEntry{SerialNumber: serial, RevocationTime: w.gen.Add(2 * time.Hour), ReasonCode: ReasonCertificateHold}
	early, late := w.gen.Add(3*time.Hour), w.gen.Add(24*time.Hour)
	held := w.crlAt("held.crl", early, now.Add(time.Hour), nil, hold)
	released := w.crlAt("released.crl", late, now.Add(time.Hour), nil)
	compromised := w.crlAt("compromised.crl", late, now.Add(time.Hour), nil, x509.RevocationListEntry{SerialNumber: serial, RevocationTime: w.gen.Add(20 * time.Hour), ReasonCode: ReasonKeyCompromise})
	future := w.crlAt("future.crl", now.Add(72*time.Hour), now.Add(96*time.Hour), nil)
	for name, c := range map[string]struct {
		files []string
		poe   bool
	}{
		"удержание":                  {[]string{held}, true},
		"снято новым CRL":            {[]string{held, released}, false},
		"снято, порядок иной":        {[]string{released, held}, false},
		"затем компрометация":        {[]string{held, compromised}, true},
		"CRL из будущего не снимает": {[]string{held, future}, true},
	} {
		r := NewRevocations(now)
		for _, f := range c.files {
			if err := r.AddCRL(f); err != nil {
				t.Fatal(err)
			}
		}
		if v, err := w.check(r); err != nil || v.NeedPOE != c.poe {
			t.Errorf("%s: %+v %v", name, v, err)
		}
	}
}

// Компрометация — свойство ключа: промежуточный центр выпущен двумя корнями
// с одним ключом; корень A отозвал свой выпуск по cACompromise, CRL корня B
// не дан — цепочка через B не прячет компрометацию; запись без причины —
// тоже (RFC 3161, 4: не в силе метки ключа). Отзыв без компрометации
// (superseded) на другой выпуск не переходит.
func TestRevocationsSameKeyCrossCert(t *testing.T) {
	dir := t.TempDir()
	rootA := issue(t, caTmpl(1, "root A"), newKey(t), nil)
	rootB := issue(t, caTmpl(1, "root B"), newKey(t), nil)
	kI := newKey(t)
	interA := issue(t, caTmpl(10, "TSA CA"), kI, rootA)
	interB := issue(t, caTmpl(11, "TSA CA"), kI, rootB)
	gen := time.Date(2026, 10, 1, 0, 0, 0, 0, time.UTC)
	now := gen.Add(48 * time.Hour)
	_, info := tsaUnder(t, interA, time.Date(2030, 1, 1, 0, 0, 0, 0, time.UTC), gen, []*x509.Certificate{rootA.cert, rootB.cert}, interA.cert, interB.cert)
	if len(info.Chains) != 2 {
		t.Fatalf("цепочек %d, ждали двух", len(info.Chains))
	}
	inter := interA.crlOf(t, dir, "inter.crl", gen.Add(time.Hour), now.Add(time.Hour), nil)
	for reason, poe := range map[int]bool{ReasonCACompromise: true, ReasonAbsent: true, ReasonSuperseded: false} {
		code := reason
		if reason == ReasonAbsent {
			code = 0 // x509 не пишет причину unspecified: записи без причины
		}
		r := NewRevocations(now)
		r.AddCRL(inter)
		r.AddCRL(rootA.crlOf(t, dir, "rootA"+ReasonName(reason)+".crl", gen.Add(time.Hour), now.Add(time.Hour), nil,
			x509.RevocationListEntry{SerialNumber: interA.cert.SerialNumber, RevocationTime: gen.Add(-time.Hour), ReasonCode: code}))
		v, err := r.Check(info.Chains, info.GenTime)
		if err != nil || v.NeedPOE != poe {
			t.Errorf("%s: %+v %v", ReasonName(reason), v, err)
		}
	}
}

// Файлы: несколько CRL в одном PEM или подряд в DER — все в деле; мусор после
// DER — отказ. Перечень: второй список в том же файле — отказ, записи одного
// сертификата — все в силе.
func TestRevocationsFiles(t *testing.T) {
	w := newRevWorld(t)
	now := w.gen.Add(48 * time.Hour)
	serial := w.a.Cert().SerialNumber
	a, _ := os.ReadFile(w.crlAt("a.crl", w.gen.Add(time.Hour), now.Add(time.Hour), nil,
		x509.RevocationListEntry{SerialNumber: serial, RevocationTime: w.gen.Add(10 * time.Hour), ReasonCode: ReasonKeyCompromise}))
	b, _ := os.ReadFile(w.crlAt("b.crl", w.gen.Add(24*time.Hour), now.Add(time.Hour), nil))
	write := func(name string, data []byte) string {
		p := filepath.Join(w.dir, name)
		os.WriteFile(p, data, 0o600)
		return p
	}
	for name, data := range map[string][]byte{
		"PEM": append(pem.EncodeToMemory(&pem.Block{Type: "X509 CRL", Bytes: a}), pem.EncodeToMemory(&pem.Block{Type: "X509 CRL", Bytes: b})...),
		"DER": append(append([]byte(nil), a...), b...),
	} {
		r := NewRevocations(now)
		if err := r.AddCRL(write("two."+name, data)); err != nil {
			t.Fatal(err)
		}
		if v, err := w.check(r); err != nil || !v.NeedPOE || len(v.CRLs) != 1 || !strings.Contains(v.CRLs[0], "(#2)") {
			t.Errorf("%s из двух CRL: %+v %v", name, v, err)
		}
	}
	if err := NewRevocations(now).AddCRL(write("tail.der", append(append([]byte(nil), a...), 0xff, 0xff))); err == nil {
		t.Error("мусор после CRL принят")
	}
	fp := Fingerprint(w.a.Cert())
	if err := NewRevocations(now).AddList(write("two.json", []byte(`[]`+"\n"+`[{"cert_sha256": "`+fp+`", "revoked": "2026-10-03T00:00:00Z", "reason": "keyCompromise"}]`))); err == nil {
		t.Error("второй список в файле принят")
	}
	r := NewRevocations(now)
	if err := r.AddList(write("dup.json", []byte(`[{"cert_sha256": "`+fp+`", "revoked": "2026-10-03T00:00:00Z", "reason": "keyCompromise"}, {"cert_sha256": "`+fp+`", "revoked": "2026-10-04T00:00:00Z", "reason": "superseded"}]`))); err != nil {
		t.Fatal(err)
	}
	if v, err := w.check(r); err != nil || !v.NeedPOE {
		t.Fatalf("две записи одного сертификата: %+v %v", v, err)
	}
}

// Строгий ввод: хвост после PEM — отказ; в перечне повтор поля, имя не в том
// регистре, null вместо списка — отказ (encoding/json взял бы последнее
// значение и потерял бы компрометацию). CRL из будущего (позже момента
// проверки) о статусе не говорит, но его записи в силе.
func TestRevocationsStrictInput(t *testing.T) {
	w := newRevWorld(t)
	now := w.gen.Add(48 * time.Hour)
	der, _ := os.ReadFile(w.crlAt("a.crl", w.gen.Add(time.Hour), now.Add(time.Hour), nil))
	write := func(name string, data []byte) string {
		p := filepath.Join(w.dir, name)
		os.WriteFile(p, data, 0o600)
		return p
	}
	block := pem.EncodeToMemory(&pem.Block{Type: "X509 CRL", Bytes: der})
	other, _ := os.ReadFile(w.crlAt("b.crl", w.gen.Add(2*time.Hour), now.Add(time.Hour), nil,
		x509.RevocationListEntry{SerialNumber: w.a.Cert().SerialNumber, RevocationTime: w.gen.Add(-time.Hour), ReasonCode: ReasonKeyCompromise}))
	cat := func(parts ...[]byte) []byte { return bytes.Join(parts, nil) }
	damaged := cat([]byte("-----BEGIN X509 CRL-----\nnot base64!\n-----END X509 CRL-----\n"), block)
	for name, data := range map[string][]byte{
		"испорченный блок перед целым": damaged,
		"двоичное после PEM":           cat(block, []byte{0x00, 0xff, 0x30}),
		"DER рядом с PEM":              cat(block, other),
		"хвост в блоке":                pem.EncodeToMemory(&pem.Block{Type: "X509 CRL", Bytes: cat(der, []byte{0xff, 0xff})}),
		"начало блока в тексте":        cat([]byte("see -----BEGIN X509 CRL----- below\n"), block),
	} {
		if err := NewRevocations(now).AddCRL(write("bad.pem", data)); err == nil {
			t.Errorf("%s: принято", name)
		}
	}
	for name, data := range map[string][]byte{
		"BOM в начале":               cat([]byte("\xef\xbb\xbf"), block),
		"DER с переводом строки":     cat(der, []byte("\n")),
		"DER подряд через пробелы":   cat([]byte("\n"), der, []byte(" \r\n"), other),
		"два блока с пустой строкой": cat(block, []byte("\n"), block),
		"пояснение перед блоком":     cat([]byte("Certificate Revocation List (CRL):\n    Issuer: CN = x\n"), block),
		"текст между блоками":        cat(block, []byte("<html>404</html>\n"), block),
		"BOM перед каждым блоком":    cat([]byte("\xef\xbb\xbf"), block, []byte("\xef\xbb\xbf"), block),
	} {
		if err := NewRevocations(now).AddCRL(write("good.crl", data)); err != nil {
			t.Errorf("%s: %v", name, err)
		}
	}
	// Два CRL в одном блоке PEM — оба: компрометация во втором не теряется.
	r0 := NewRevocations(now)
	if err := r0.AddCRL(write("two-in-block.pem", pem.EncodeToMemory(&pem.Block{Type: "X509 CRL", Bytes: cat(der, other)}))); err != nil {
		t.Fatal(err)
	}
	if v, err := w.check(r0); err != nil || len(r0.crls) != 2 || !v.NeedPOE {
		t.Fatalf("два CRL в одном блоке: %d CRL, %+v %v", len(r0.crls), v, err)
	}
	fp := Fingerprint(w.a.Cert())
	for name, body := range map[string]string{
		"повтор поля":  `[{"cert_sha256": "` + fp + `", "revoked": "2026-10-03T00:00:00Z", "reason": "keyCompromise", "reason": "superseded"}]`,
		"иной регистр": `[{"cert_sha256": "` + fp + `", "revoked": "2026-10-03T00:00:00Z", "reason": "keyCompromise", "Reason": "superseded"}]`,
		"null":         `null`,
		"не объект":    `["` + fp + `"]`,
	} {
		if err := NewRevocations(now).AddList(write("l.json", []byte(body))); err == nil {
			t.Errorf("%s: принято", name)
		}
	}
	// Полный CRL, что называет дельта-CRL (freshestCRL): отзыв, который есть
	// только в дельте, не виден — и отчёт это говорит.
	fresh, _ := asn1.Marshal([]asn1.RawValue{{FullBytes: tlv(0x30, tlv(0xA0, tlv(0xA0, tlv(0x86, []byte("http://crl.example/delta.crl")))))}})
	r := NewRevocations(now)
	r.AddCRL(w.crlAt("full.crl", w.gen.Add(24*time.Hour), now.Add(time.Hour), []pkix.Extension{{Id: oidFreshestCRL, Value: fresh}}))
	if v, err := w.check(r); err != nil || len(v.CRLs) != 1 || !hasNote(v, "delta CRL") {
		t.Fatalf("CRL с дельтами: %+v %v", v, err)
	}
	r = NewRevocations(now)
	r.AddCRL(w.crlAt("cur.crl", w.gen.Add(24*time.Hour), now.Add(time.Hour), nil,
		x509.RevocationListEntry{SerialNumber: w.a.Cert().SerialNumber, RevocationTime: w.gen.Add(10 * time.Hour), ReasonCode: ReasonKeyCompromise}))
	r.AddCRL(w.crlAt("future.crl", now.Add(240*time.Hour), now.Add(300*time.Hour), nil))
	if v, err := w.check(r); err != nil || !v.NeedPOE || len(v.CRLs) != 1 || !strings.Contains(v.CRLs[0], "cur.crl") || !hasNote(v, "dated after the time of this check") {
		t.Fatalf("CRL из будущего: %+v %v", v, err)
	}
	// Только он — не проверено, и причина — дата, а не истечение сертификата.
	r = NewRevocations(now)
	r.AddCRL(w.crlAt("future2.crl", now.Add(240*time.Hour), now.Add(300*time.Hour), nil))
	if v, err := w.check(r); err != nil || len(v.Unchecked) != 1 || !hasNote(v, "dated after the time of this check") || hasNote(v, "expired") {
		t.Fatalf("только CRL из будущего: %+v %v", v, err)
	}
}

// CRL, записанный openssl (не Go): причины, отсутствие причины и явный
// unspecified, invalidityDate, удержание с инструкцией, issuingDistributionPoint
// и подпись центра читаются так, как их понимает RFC 5280.
func TestRevocationsOpenSSLCRL(t *testing.T) {
	data, err := os.ReadFile(filepath.Join("testdata", "openssl", "ca.crt"))
	if err != nil {
		t.Fatal(err)
	}
	b, _ := pem.Decode(data)
	ca, err := x509.ParseCertificate(b.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	r := NewRevocations(time.Date(2026, 11, 10, 0, 0, 0, 0, time.UTC))
	if err := r.AddCRL(filepath.Join("testdata", "openssl", "fixture.crl")); err != nil {
		t.Fatal(err)
	}
	f := r.crls[0]
	if err := f.rl.CheckSignatureFrom(ca); err != nil {
		t.Fatal(err)
	}
	// Тот же CRL так, как его пишет openssl crl -text: описание, затем блок.
	rt := NewRevocations(r.Now)
	if err := rt.AddCRL(filepath.Join("testdata", "openssl", "fixture-text.pem")); err != nil || len(rt.crls) != 1 || !bytes.Equal(rt.crls[0].rl.Raw, f.rl.Raw) {
		t.Fatalf("вывод openssl crl -text: %v", err)
	}
	day := func(d, h int) time.Time { return time.Date(2026, 10, d, h, 0, 0, 0, time.UTC) }
	want := map[string]Revocation{
		"16": {Time: day(5, 12), Reason: ReasonKeyCompromise, Invalidity: day(1, 9)},
		"17": {Time: day(6, 12), Reason: ReasonSuperseded},
		"18": {Time: day(7, 12), Reason: ReasonAbsent},
		"19": {Time: day(8, 12), Reason: ReasonCertificateHold},
		"20": {Time: day(9, 12), Reason: ReasonUnspecified},
		"21": {Time: day(10, 12), Reason: ReasonCessationOfOperation},
		"22": {Time: day(11, 12), Reason: ReasonCACompromise, Invalidity: day(2, 9)},
	}
	if len(f.bySN) != len(want) {
		t.Fatalf("записей %d, ждали %d", len(f.bySN), len(want))
	}
	for sn, w := range want {
		gs := f.bySN[sn]
		if len(gs) != 1 {
			t.Fatalf("серийный %s: записей %d", sn, len(gs))
		}
		g := gs[0]
		if !g.Time.Equal(w.Time) || g.Reason != w.Reason || !g.Invalidity.Equal(w.Invalidity) {
			t.Errorf("серийный %s: %+v, ждали %+v", sn, g, w)
		}
	}
	leaf := &x509.Certificate{CRLDistributionPoints: []string{"http://crl.example/fixture.crl"}}
	if sc := f.scope; sc == nil || !sc.onlyUser || !sc.covers(leaf) || sc.covers(&x509.Certificate{IsCA: true, CRLDistributionPoints: leaf.CRLDistributionPoints}) {
		t.Fatalf("область CRL: %+v", f.scope)
	}
}

// Один и тот же сертификат службы в двух цепочках: центр выпущен двумя
// корнями на один ключ, у второго выпуска нет cRLSign, и CRL центра в его
// цепочке не сверяется. Статус сертификата — по обеим цепочкам: компрометация
// из CRL, сверенного в первой, не прячется за второй.
func TestRevocationsSameCertSeveralChains(t *testing.T) {
	dir := t.TempDir()
	rootA := issue(t, caTmpl(1, "root A"), newKey(t), nil)
	rootB := issue(t, caTmpl(1, "root B"), newKey(t), nil)
	kI := newKey(t)
	interA := issue(t, caTmpl(10, "TSA CA"), kI, rootA)
	noCRLSign := caTmpl(11, "TSA CA")
	noCRLSign.KeyUsage = x509.KeyUsageCertSign
	interB := issue(t, noCRLSign, kI, rootB)
	gen := time.Date(2026, 10, 1, 0, 0, 0, 0, time.UTC)
	now := gen.Add(48 * time.Hour)
	leaf, info := tsaUnder(t, interA, time.Date(2030, 1, 1, 0, 0, 0, 0, time.UTC), gen, []*x509.Certificate{rootA.cert, rootB.cert}, interA.cert, interB.cert)
	if len(info.Chains) != 2 {
		t.Fatalf("цепочек %d, ждали двух", len(info.Chains))
	}
	r := NewRevocations(now)
	r.AddCRL(interA.crlOf(t, dir, "inter.crl", gen.Add(time.Hour), now.Add(time.Hour), nil,
		x509.RevocationListEntry{SerialNumber: leaf.cert.SerialNumber, RevocationTime: gen.Add(10 * time.Hour), ReasonCode: ReasonKeyCompromise}))
	v, err := r.Check(info.Chains, info.GenTime)
	if err != nil || !v.NeedPOE || hasNote(v, "may sign CRLs") {
		t.Fatalf("компрометация за второй цепочкой: %+v %v", v, err)
	}
	r = NewRevocations(now)
	r.AddCRL(interA.crlOf(t, dir, "inter2.crl", gen.Add(time.Hour), now.Add(time.Hour), nil,
		x509.RevocationListEntry{SerialNumber: leaf.cert.SerialNumber, RevocationTime: gen.Add(-time.Hour), ReasonCode: ReasonSuperseded}))
	if _, err := r.Check(info.Chains, info.GenTime); !errors.Is(err, ErrRevoked) {
		t.Fatalf("вывод из работы до метки за второй цепочкой: %v", err)
	}
}

// Цепочка одна, и в ней выпуск центра без cRLSign (сертификаты SignedData не
// подписаны: какие положить в токен, решает тот, кто его собирает, в том
// числе владелец украденного ключа). CRL подписан ключом центра — его записи
// в силе: компрометация видна, хотя для статуса («не отозван») такой CRL не
// годится. Удержание снимает только CRL, годный для статуса: здесь — никакой.
func TestRevocationsEntriesWithoutCRLSign(t *testing.T) {
	dir := t.TempDir()
	rootA := issue(t, caTmpl(1, "root A"), newKey(t), nil)
	rootB := issue(t, caTmpl(1, "root B"), newKey(t), nil)
	kI := newKey(t)
	interA := issue(t, caTmpl(10, "TSA CA"), kI, rootA)
	noCRLSign := caTmpl(11, "TSA CA")
	noCRLSign.KeyUsage = x509.KeyUsageCertSign
	interB := issue(t, noCRLSign, kI, rootB)
	gen := time.Date(2026, 10, 1, 0, 0, 0, 0, time.UTC)
	now := gen.Add(48 * time.Hour)
	leaf, info := tsaUnder(t, interA, time.Date(2030, 1, 1, 0, 0, 0, 0, time.UTC), gen, []*x509.Certificate{rootA.cert, rootB.cert}, interB.cert)
	if len(info.Chains) != 1 {
		t.Fatalf("цепочек %d, ждали одну", len(info.Chains))
	}
	sn := leaf.cert.SerialNumber
	r := NewRevocations(now)
	r.AddCRL(interA.crlOf(t, dir, "inter.crl", gen.Add(time.Hour), now.Add(time.Hour), nil,
		x509.RevocationListEntry{SerialNumber: sn, RevocationTime: gen.Add(-10 * time.Hour), ReasonCode: ReasonKeyCompromise}))
	v, err := r.Check(info.Chains, info.GenTime)
	if err != nil || !v.NeedPOE || len(v.Unchecked) != 2 || !hasNote(v, "may sign CRLs") || hasNote(v, `"CN=test TSA" (issued by "CN=TSA CA") was not checked: no CRL`) {
		t.Fatalf("компрометация за выпуском центра без cRLSign: %+v %v", v, err)
	}
	r = NewRevocations(now)
	r.AddCRL(interA.crlOf(t, dir, "inter2.crl", gen.Add(time.Hour), now.Add(time.Hour), nil,
		x509.RevocationListEntry{SerialNumber: sn, RevocationTime: gen.Add(-time.Hour), ReasonCode: ReasonSuperseded}))
	if _, err := r.Check(info.Chains, info.GenTime); !errors.Is(err, ErrRevoked) {
		t.Fatalf("вывод из работы до метки за выпуском без cRLSign: %v", err)
	}
	// Удержание в старом CRL, более новый его не держит: снять его некому.
	hold := []string{
		interA.crlOf(t, dir, "held.crl", gen.Add(time.Hour), now.Add(time.Hour), nil,
			x509.RevocationListEntry{SerialNumber: sn, RevocationTime: gen.Add(-time.Hour), ReasonCode: ReasonCertificateHold}),
		interA.crlOf(t, dir, "released.crl", gen.Add(2*time.Hour), now.Add(time.Hour), nil),
	}
	r = NewRevocations(now)
	for _, p := range hold {
		r.AddCRL(p)
	}
	if v, err := r.Check(info.Chains, info.GenTime); err != nil || !v.NeedPOE {
		t.Fatalf("удержание снял CRL, не годный для статуса: %+v %v", v, err)
	}
	// Тот же токен с обоими выпусками центра: статус по выпуску с cRLSign, и
	// он же снимает удержание.
	for _, order := range [][]*x509.Certificate{{interA.cert, interB.cert}, {interB.cert, interA.cert}} {
		_, info2 := tsaUnder(t, interA, time.Date(2030, 1, 1, 0, 0, 0, 0, time.UTC), gen, []*x509.Certificate{rootA.cert, rootB.cert}, order...)
		if v, err := r.Check(info2.Chains, info2.GenTime); err != nil || v.NeedPOE || hasNote(v, "may sign CRLs") {
			t.Fatalf("удержание при выпуске с cRLSign в другой цепочке (первым — %s): %+v %v", order[0].Subject, v, err)
		}
	}
}

// Два разных центра с одним именем (или CRL каждого ключа одного центра, как
// публикует AD CS после смены ключа): CRL другого, новее своего, сертификат
// не называет — статус по своему, без «не проверено».
func TestRevocationsSameNameOtherKey(t *testing.T) {
	dir := t.TempDir()
	rootA := issue(t, caTmpl(1, "root A"), newKey(t), nil)
	rootC := issue(t, caTmpl(1, "root C"), newKey(t), nil)
	caA := issue(t, caTmpl(10, "TSA CA"), newKey(t), rootA)
	caC := issue(t, caTmpl(10, "TSA CA"), newKey(t), rootC)
	gen := time.Date(2026, 10, 1, 0, 0, 0, 0, time.UTC)
	now := gen.Add(48 * time.Hour)
	_, info := tsaUnder(t, caA, time.Date(2030, 1, 1, 0, 0, 0, 0, time.UTC), gen, []*x509.Certificate{rootA.cert, rootC.cert}, caA.cert)
	r := NewRevocations(now)
	r.AddCRL(caA.crlOf(t, dir, "a.crl", now.Add(-2*time.Hour), now.Add(48*time.Hour), nil))
	r.AddCRL(caC.crlOf(t, dir, "c.crl", now.Add(-time.Hour), now.Add(48*time.Hour), nil))
	r.AddCRL(rootA.crlOf(t, dir, "ra.crl", now.Add(-time.Hour), now.Add(48*time.Hour), nil))
	if v, err := r.Check(info.Chains, info.GenTime); err != nil || len(v.Unchecked) != 0 || len(v.CRLs) != 2 || hasNote(v, "did the CA change its key?") {
		t.Fatalf("CRL другого центра с тем же именем: %+v %v", v, err)
	}
}

// Мелочи разбора CRL: номер дважды в одном CRL — в силе обе записи; область
// с URI и другим именем покрывает по совпавшему URI; поле области не на своём
// месте — отказ, а не молча потерянная точка распространения.
func TestRevocationsCRLDetails(t *testing.T) {
	w := newRevWorld(t)
	now := w.gen.Add(48 * time.Hour)
	serial := w.a.Cert().SerialNumber
	r := NewRevocations(now)
	r.AddCRL(w.crlAt("dup.crl", w.gen.Add(24*time.Hour), now.Add(time.Hour), nil,
		x509.RevocationListEntry{SerialNumber: serial, RevocationTime: w.gen.Add(10 * time.Hour), ReasonCode: ReasonKeyCompromise},
		x509.RevocationListEntry{SerialNumber: serial, RevocationTime: w.gen.Add(20 * time.Hour), ReasonCode: ReasonSuperseded}))
	if v, err := w.check(r); err != nil || !v.NeedPOE {
		t.Fatalf("номер дважды в CRL: %+v %v", v, err)
	}
	uri := tlv(0x86, []byte("http://crl.example/a.crl"))
	dn := tlv(0xA4, tlv(0x30, nil)) // directoryName
	sc, _, err := parseScope(tlv(0x30, tlv(0xA0, tlv(0xA0, append(append([]byte(nil), dn...), uri...)))))
	if err != nil || !sc.covers(&x509.Certificate{CRLDistributionPoints: []string{"http://crl.example/a.crl"}}) {
		t.Fatalf("URI и другое имя: %+v %v", sc, err)
	}
	if _, _, err := parseScope(tlv(0x30, append(tlv(0x81, []byte{0xff}), tlv(0xA0, tlv(0xA0, uri))...))); err == nil {
		t.Fatal("поле области не по порядку принято")
	}
	// Перечень называет сертификат — заметка не говорит «не называет».
	list := filepath.Join(w.dir, "list.json")
	os.WriteFile(list, []byte(`[{"cert_sha256": "`+Fingerprint(w.a.Cert())+`", "revoked": "2026-10-03T00:00:00Z", "reason": "superseded"}]`), 0o600)
	r = NewRevocations(now)
	r.AddList(list)
	if v, err := w.check(r); err != nil || !hasNote(v, "no CRL of its issuer") || hasNote(v, "does not name it") {
		t.Fatalf("сертификат в перечне: %+v %v", v, err)
	}
}
