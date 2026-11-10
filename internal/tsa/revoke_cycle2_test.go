package tsa

// Находки захода 1 второго цикла (FINDINGS, P-157…): каждая — тест, красный
// на коде до исправления.

import (
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func day(y int, m time.Month, d int) time.Time { return time.Date(y, m, d, 0, 0, 0, 0, time.UTC) }

// P-157. Удержание, сделанное постоянным (AD CS переписывает причину и
// дату): более новый CRL называет сертификат с другой причиной — это не
// снятие удержания, и его дата в силе. Снимает удержание только CRL, который
// сертификат не называет вовсе.
func TestRevocationsHoldMadePermanent(t *testing.T) {
	w := newRevWorld(t)
	now := w.gen.Add(48 * time.Hour)
	serial := w.a.Cert().SerialNumber
	holdAt, later := w.gen.Add(-2*time.Hour), w.gen.Add(10*time.Hour)
	held := w.crlAt("held.crl", w.gen.Add(-time.Hour), now.Add(time.Hour), nil,
		x509.RevocationListEntry{SerialNumber: serial, RevocationTime: holdAt, ReasonCode: ReasonCertificateHold})
	for _, reason := range []int{ReasonKeyCompromise, ReasonCessationOfOperation, ReasonSuperseded} {
		perm := w.crlAt("perm.crl", w.gen.Add(24*time.Hour), now.Add(time.Hour), nil,
			x509.RevocationListEntry{SerialNumber: serial, RevocationTime: later, ReasonCode: reason})
		r := NewRevocations(now)
		r.AddCRL(held)
		r.AddCRL(perm)
		if v, err := w.check(r); err != nil || !v.NeedPOE || !v.Cutoff.Equal(holdAt) {
			t.Errorf("удержание, затем %s: %+v %v", ReasonName(reason), v, err)
		}
	}
	// Снятие: новый CRL сертификата не называет.
	released := w.crlAt("released.crl", w.gen.Add(24*time.Hour), now.Add(time.Hour), nil)
	r := NewRevocations(now)
	r.AddCRL(held)
	r.AddCRL(released)
	if v, err := w.check(r); err != nil || v.NeedPOE {
		t.Errorf("снят с удержания: %+v %v", v, err)
	}
}

// P-165. Расширение дважды — в записи (два reasonCode: компрометация и вывод
// из работы) и в самом CRL: отказ при чтении, а не последнее из двух.
func TestRevocationsDuplicateExtension(t *testing.T) {
	w := newRevWorld(t)
	now := w.gen.Add(48 * time.Hour)
	for name, rl := range map[string]*x509.RevocationList{
		"запись": {Number: big.NewInt(1), ThisUpdate: w.gen.Add(24 * time.Hour), NextUpdate: now.Add(time.Hour),
			RevokedCertificates: []pkix.RevokedCertificate{{SerialNumber: w.a.Cert().SerialNumber, RevocationTime: w.gen.Add(10 * time.Hour),
				Extensions: []pkix.Extension{ext(t, oidReasonCode, asn1.Enumerated(ReasonKeyCompromise), ""), ext(t, oidReasonCode, asn1.Enumerated(ReasonSuperseded), "")}}}},
		"CRL": {Number: big.NewInt(1), ThisUpdate: w.gen.Add(24 * time.Hour), NextUpdate: now.Add(time.Hour),
			ExtraExtensions: []pkix.Extension{ext(t, oidExpiredCerts, w.gen, "generalized"), ext(t, oidExpiredCerts, w.gen, "generalized")}},
	} {
		der, err := x509.CreateRevocationList(rand.Reader, rl, w.a.root, w.a.rootKey)
		if err != nil {
			t.Fatal(err)
		}
		p := filepath.Join(w.dir, "dup.crl")
		os.WriteFile(p, der, 0o600)
		if err := NewRevocations(now).AddCRL(p); err == nil || !strings.Contains(err.Error(), "given twice") {
			t.Errorf("%s: расширение дважды: %v", name, err)
		}
	}
}

// P-166. CRL только атрибутных сертификатов о сертификатах служб ничего не
// говорит, а номера в нём — других сертификатов: отказ при чтении.
func TestRevocationsAttributeOnlyCRL(t *testing.T) {
	w := newRevWorld(t)
	now := w.gen.Add(48 * time.Hour)
	idp, _ := asn1.Marshal(struct {
		OnlyAttr bool `asn1:"optional,tag:5"`
	}{true})
	p := w.crlAt("ac.crl", w.gen.Add(time.Hour), now.Add(time.Hour), []pkix.Extension{{Id: oidIssuingDP, Critical: true, Value: idp}},
		x509.RevocationListEntry{SerialNumber: w.a.Cert().SerialNumber, RevocationTime: w.gen.Add(-time.Hour), ReasonCode: ReasonKeyCompromise})
	if err := NewRevocations(now).AddCRL(p); err == nil || !strings.Contains(err.Error(), "attribute certificates") {
		t.Fatalf("CRL атрибутных сертификатов принят: %v", err)
	}
}

// P-164. Оценка при многих CRL: Named — по разным сертификатам, раз; CRL —
// по имени центра. Месяц меток при годе ежедневных CRL двух центров —
// доли секунды (было: десятки секунд).
func TestRevocationsManyCRLs(t *testing.T) {
	dir := t.TempDir()
	root := issue(t, caTmpl(1, "cost root"), newKey(t), nil)
	ca := issue(t, caTmpl(10, "TSA CA"), newKey(t), root)
	gen := day(2026, 10, 1)
	_, info := tsaUnder(t, ca, day(2030, 1, 1), gen, []*x509.Certificate{root.cert}, ca.cert)
	r := NewRevocations(day(2026, 11, 2))
	for i := range 365 {
		this := day(2025, 11, 1).Add(time.Duration(i) * 24 * time.Hour)
		r.AddCRL(ca.crlOf(t, dir, "ca"+this.Format("060102")+".crl", this, this.Add(48*time.Hour), nil))
		r.AddCRL(root.crlOf(t, dir, "root"+this.Format("060102")+".crl", this, this.Add(48*time.Hour), nil))
	}
	start := time.Now()
	a := r.NewAssessment()
	for i := range 4000 {
		a.Add(info.Chains, info.GenTime.Add(time.Duration(i)*time.Minute))
	}
	vs := a.Verdicts()
	named := a.Named()
	if took := time.Since(start); took > 10*time.Second || len(vs) != 4000 || len(named) != 730 {
		t.Fatalf("4000 меток, 730 CRL: %v, вердиктов %d, названо %d", took, len(vs), len(named))
	}
}
