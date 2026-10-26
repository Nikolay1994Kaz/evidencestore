package server

import (
	"bytes"
	"crypto/ed25519"
	"crypto/x509"
	"encoding/base64"
	"io"
	"net/url"
	"strconv"
	"testing"
	"time"

	"github.com/Nikolay1994Kaz/evidencestore/internal/proof"
)

// Пакет за окно через админку (DECISIONS, п. 27): окно в прошлом, до свежей
// метки, — с начала цепи; ответ без отступов; ошибки окна — 400, чужой
// источник — 404.
func TestAdminProofWindow(t *testing.T) {
	e := setup(t)
	c := e.collector(t, "abs-core")
	post(t, c, e.url+"/v1/ingest", records(1, 2))
	if resp, body := post(t, e.admin, "http://admin/admin/stamp", nil); resp == nil || resp.StatusCode != 200 {
		t.Fatalf("stamp: %v %s", resp, body)
	}
	now := time.Now().UTC()
	get := func(q url.Values) (int, []byte) {
		t.Helper()
		resp, err := e.admin.Get("http://admin/admin/proof-window?" + q.Encode())
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		data, _ := io.ReadAll(resp.Body)
		return resp.StatusCode, data
	}
	window := func(from, to time.Time) url.Values {
		return url.Values{"from": {from.Format(time.RFC3339Nano)}, "to": {to.Format(time.RFC3339Nano)}}
	}

	q := window(now.Add(-3*time.Minute), now.Add(-2*time.Minute))
	q.Set("source", "abs-core")
	q.Set("dek", "1")
	code, data := get(q)
	if code != 200 {
		t.Fatalf("пакет за окно: %d %s", code, data)
	}
	if bytes.Contains(data, []byte("\n ")) {
		t.Fatal("пакет за окно с отступами")
	}
	b, err := proof.ParseWindow(data)
	if err != nil {
		t.Fatal(err)
	}
	resp, _ := e.admin.Get("http://admin/admin/tsa-root")
	rootDER, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	root, err := x509.ParseCertificate(rootDER)
	if err != nil {
		t.Fatal(err)
	}
	pub, _ := base64.RawStdEncoding.DecodeString(e.st.PublicKey())
	trust := proof.Trust{StoreKey: ed25519.PublicKey(pub)}
	trust.TSA.Roots = x509.NewCertPool()
	trust.TSA.Roots.AddCert(root)
	r := proof.VerifyWindow(b, trust, time.Time{}, time.Time{})
	if !r.Valid() || !r.FromStart || len(r.Bodies) != 2 || string(r.Bodies[1].Body) != "event 2" {
		t.Fatalf("пакет за окно:\n%s", r.Text())
	}

	// До головы свидетеля (proof -to-head): пакет доходит до неё.
	head := e.st.Status().HeadSeq
	q = window(now.Add(-3*time.Minute), now.Add(-2*time.Minute))
	q.Set("to_head", strconv.FormatUint(head, 10))
	code, data = get(q)
	if tb, err := proof.ParseWindow(data); code != 200 || err != nil || tb.Links[len(tb.Links)-1].Seq != head {
		t.Fatalf("до головы %d: %d %v %s", head, code, err, data)
	}
	q.Set("to_head", strconv.FormatUint(head+1000, 10))
	if code, data := get(q); code != 500 {
		t.Fatalf("голова, которой нет: %d %s", code, data)
	}
	q.Set("to_head", "x")
	if code, _ := get(q); code != 400 {
		t.Fatalf("to_head не число: %d", code)
	}

	for name, q := range map[string]url.Values{
		"время не RFC 3339":     {"from": {"вчера"}, "to": {now.Format(time.RFC3339)}},
		"конец раньше начала":   window(now.Add(-2*time.Minute), now.Add(-3*time.Minute)),
		"верхней метки ещё нет": window(now.Add(-time.Minute), now.Add(time.Hour)),
		"-source без -dek":      {"from": {now.Add(-3 * time.Minute).Format(time.RFC3339)}, "to": {now.Add(-2 * time.Minute).Format(time.RFC3339)}, "source": {"abs-core"}},
	} {
		if code, data := get(q); code != 400 {
			t.Fatalf("%s: %d %s", name, code, data)
		}
	}
	q = window(now.Add(-3*time.Minute), now.Add(-2*time.Minute))
	q.Set("source", "nobody")
	q.Set("dek", "1")
	if code, data := get(q); code != 404 {
		t.Fatalf("чужой источник: %d %s", code, data)
	}
}
