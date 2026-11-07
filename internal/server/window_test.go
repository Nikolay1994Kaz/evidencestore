package server

import (
	"bytes"
	"crypto/ed25519"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
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

	q := window(now.Add(-4*time.Minute), now.Add(-3*time.Minute))
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
	// Записи легли позже окна: на участке они есть, но ключи — только окну (P-46).
	r := proof.VerifyWindow(b, trust, time.Time{}, time.Time{})
	if !r.Valid() || !r.FromStart || r.Sources[0].Records != 2 || r.Attached != 0 || len(r.Bodies) != 0 {
		t.Fatalf("пакет за окно:\n%s", r.Text())
	}

	// До головы свидетеля (proof -to-head): пакет доходит до неё.
	head := e.st.Status().HeadSeq
	q = window(now.Add(-4*time.Minute), now.Add(-3*time.Minute))
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
		"конец раньше начала":   window(now.Add(-3*time.Minute), now.Add(-4*time.Minute)),
		"верхней метки ещё нет": window(now.Add(-time.Minute), now.Add(time.Hour)),
		"-source без -dek":      {"from": {now.Add(-4 * time.Minute).Format(time.RFC3339)}, "to": {now.Add(-3 * time.Minute).Format(time.RFC3339)}, "source": {"abs-core"}},
	} {
		if code, data := get(q); code != 400 {
			t.Fatalf("%s: %d %s", name, code, data)
		}
	}
	q = window(now.Add(-4*time.Minute), now.Add(-3*time.Minute))
	q.Set("source", "nobody")
	q.Set("dek", "1")
	if code, data := get(q); code != 404 {
		t.Fatalf("чужой источник: %d %s", code, data)
	}
}

// Пакет по источнику через админку (п. 28): окно разбирается так же, без
// источника — 400, чужой источник — 404. Верхний край — хвосты второй метки.
func TestAdminProofSource(t *testing.T) {
	e := setup(t)
	c := e.collector(t, "abs-core")
	post(t, c, e.url+"/v1/ingest", records(1, 2))
	for q := uint64(3); q <= 4; q++ {
		if resp, body := post(t, e.admin, "http://admin/admin/stamp", nil); resp == nil || resp.StatusCode != 200 {
			t.Fatalf("stamp: %v %s", resp, body)
		}
		post(t, c, e.url+"/v1/ingest", records(q, q))
	}
	now := time.Now().UTC()
	get := func(q url.Values) (int, []byte) {
		t.Helper()
		resp, err := e.admin.Get("http://admin/admin/proof-source?" + q.Encode())
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		data, _ := io.ReadAll(resp.Body)
		return resp.StatusCode, data
	}
	window := func(from, to time.Time) url.Values {
		return url.Values{"from": {from.Format(time.RFC3339Nano)}, "to": {to.Format(time.RFC3339Nano)}, "source": {"abs-core"}}
	}

	q := window(now.Add(-4*time.Minute), now.Add(-3*time.Minute))
	q.Set("dek", "1")
	code, data := get(q)
	if code != 200 {
		t.Fatalf("пакет по источнику: %d %s", code, data)
	}
	if bytes.Contains(data, []byte("\n ")) {
		t.Fatal("пакет по источнику с отступами")
	}
	b, err := proof.ParseSource(data)
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
	r := proof.VerifySource(b, trust, time.Time{}, time.Time{})
	// Запись 3 легла после закрывающей метки, до хвостов второй: она тоже в
	// пакете. Все записи легли позже окна: они идут листами, без улик (P-46).
	if !r.Valid() || !r.FromStart || r.Records != 3 || r.InWindow != 0 || r.Attached != 0 || len(r.Bodies) != 0 {
		t.Fatalf("пакет по источнику:\n%s", r.Text())
	}

	head := e.st.Status().HeadSeq
	q = window(now.Add(-4*time.Minute), now.Add(-3*time.Minute))
	q.Set("to_head", strconv.FormatUint(head, 10))
	code, data = get(q)
	if sb, err := proof.ParseSource(data); code != 200 || err != nil || sb.Links[len(sb.Links)-1].Seq != head {
		t.Fatalf("до головы %d: %d %v %s", head, code, err, data)
	}

	for name, q := range map[string]url.Values{
		"без источника":         {"from": {now.Add(-4 * time.Minute).Format(time.RFC3339)}, "to": {now.Add(-3 * time.Minute).Format(time.RFC3339)}},
		"время не RFC 3339":     {"from": {"вчера"}, "to": {now.Format(time.RFC3339)}, "source": {"abs-core"}},
		"верхней метки ещё нет": window(now.Add(-time.Minute), now.Add(time.Hour)),
	} {
		if code, data := get(q); code != 400 {
			t.Fatalf("%s: %d %s", name, code, data)
		}
	}
	q = window(now.Add(-4*time.Minute), now.Add(-3*time.Minute))
	q.Set("source", "nobody")
	if code, data := get(q); code != 404 {
		t.Fatalf("чужой источник: %d %s", code, data)
	}
}

// evidencestore stamp ставит метку и без новых листьев: в простое оператор
// так закрывает окно и даёт пакету по источнику верхний край.
func TestAdminStampForced(t *testing.T) {
	e := setup(t)
	c := e.collector(t, "abs-core")
	post(t, c, e.url+"/v1/ingest", records(1, 1))
	var last uint64
	for i := 0; i < 2; i++ {
		resp, body := post(t, e.admin, "http://admin/admin/stamp", nil)
		if resp == nil || resp.StatusCode != 200 {
			t.Fatalf("stamp: %v %s", resp, body)
		}
		var out map[string]uint64
		if err := json.Unmarshal(body, &out); err != nil {
			t.Fatal(err)
		}
		if out["stamped_head"] <= last {
			t.Fatalf("метка %d: голова %d после %d", i+1, out["stamped_head"], last)
		}
		last = out["stamped_head"]
	}
}

// Пакет по субъекту через админку (п. 32): значение уходит параметром, источник
// без subject_field — 400, чужой источник — 404. Журнал значений не видит.
func TestAdminProofSubject(t *testing.T) {
	e := setup(t)
	c := e.collector(t, "agent")
	post(t, c, e.url+"/v1/ingest", IngestRequest{Records: []IngestRecord{{Seq: 1, Body: []byte(`{"client":"c-1"}`)}}})
	for range 2 {
		if resp, body := post(t, e.admin, "http://admin/admin/stamp", nil); resp == nil || resp.StatusCode != 200 {
			t.Fatalf("stamp: %v %s", resp, body)
		}
	}
	now := time.Now().UTC()
	get := func(source, subject string) (int, []byte) {
		t.Helper()
		q := url.Values{"source": {source}, "subject": {subject},
			"from": {now.Add(-4 * time.Minute).Format(time.RFC3339Nano)}, "to": {now.Add(-3 * time.Minute).Format(time.RFC3339Nano)}}
		resp, err := e.admin.Get("http://admin/admin/proof-source?" + q.Encode())
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		data, _ := io.ReadAll(resp.Body)
		return resp.StatusCode, data
	}
	code, data := get("agent", "c-1")
	if code != 200 {
		t.Fatalf("пакет по субъекту: %d %s", code, data)
	}
	b, err := proof.ParseSource(data)
	if err != nil {
		t.Fatal(err)
	}
	if b.Subject == nil || b.Subject.Value != "c-1" || b.Subject.Field != "client" {
		t.Fatalf("субъект в пакете: %+v", b.Subject)
	}
	if code, data := get("abs-core", "c-1"); code != 400 || !bytes.Contains(data, []byte("subject_field")) {
		t.Fatalf("источник без subject_field: %d %s", code, data)
	}
	if code, data := get("nobody", "c-1"); code != 404 {
		t.Fatalf("чужой источник: %d %s", code, data)
	}
}
