package server

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"evidencestore/internal/config"
	"evidencestore/internal/pki"
	"evidencestore/internal/proof"
	"evidencestore/internal/store"
)

var quiet = slog.New(slog.NewTextHandler(io.Discard, nil))

type env struct {
	cfg    *config.Config
	st     *store.Store
	srv    *Server
	url    string
	ca     *pki.CA
	admin  *http.Client
	pinned *pki.Issued
}

func setup(t *testing.T) *env {
	t.Helper()
	dir := t.TempDir()
	ca, err := pki.NewCA("test collectors CA")
	if err != nil {
		t.Fatal(err)
	}
	srvCert, _ := ca.Server("127.0.0.1", "localhost")
	srvCert.Write(dir, "server")
	pki.WriteCert(filepath.Join(dir, "ca.crt"), ca.Cert)
	pinned, _ := ca.Client("pinned-src")

	cfg := &config.Config{
		DataDir:     filepath.Join(dir, "data"),
		RootsDir:    filepath.Join(dir, "roots"),
		AdminSocket: filepath.Join(dir, "admin.sock"),
		TLS:         config.TLS{Cert: filepath.Join(dir, "server.crt"), Key: filepath.Join(dir, "server.key"), ClientCA: filepath.Join(dir, "ca.crt")},
		TSA:         config.TSA{URL: "local"},
		Keys:        config.Keys{MinWait: config.Duration(time.Nanosecond)},
		Sources: []config.Source{
			{Name: "abs-core", ContentType: "syslog"},
			{Name: "pinned-src", ContentType: "syslog", CertSHA256: config.CertFingerprint(pinned.Cert.Raw)},
			{Name: "off", ContentType: "syslog", Disabled: true},
		},
	}
	cfg.Defaults()
	if err := cfg.Validate(); err != nil {
		t.Fatal(err)
	}
	if _, err := store.Init(cfg); err != nil {
		t.Fatal(err)
	}
	st, err := store.Open(cfg, store.Options{Logger: quiet, NoBackground: true})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	s := New(cfg, st, quiet)

	tlsCfg, err := TLSConfig(cfg)
	if err != nil {
		t.Fatal(err)
	}
	hs := httptest.NewUnstartedServer(s.IntakeHandler())
	hs.TLS = tlsCfg
	hs.StartTLS()
	t.Cleanup(hs.Close)

	ln, err := ListenAdmin(cfg.AdminSocket)
	if err != nil {
		t.Fatal(err)
	}
	as := &http.Server{Handler: s.AdminHandler()}
	go as.Serve(ln)
	t.Cleanup(func() { as.Close() })
	admin := &http.Client{Transport: &http.Transport{DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, "unix", cfg.AdminSocket)
	}}}
	return &env{cfg: cfg, st: st, srv: s, url: hs.URL, ca: ca, admin: admin, pinned: pinned}
}

func (e *env) client(t *testing.T, cert *pki.Issued) *http.Client {
	t.Helper()
	roots := x509.NewCertPool()
	roots.AddCert(e.ca.Cert)
	cfg := &tls.Config{RootCAs: roots}
	if cert != nil {
		cfg.Certificates = []tls.Certificate{{Certificate: [][]byte{cert.Cert.Raw}, PrivateKey: cert.Key}}
	}
	return &http.Client{Transport: &http.Transport{TLSClientConfig: cfg}, Timeout: 10 * time.Second}
}

func (e *env) collector(t *testing.T, source string) *http.Client {
	t.Helper()
	c, err := e.ca.Client(source)
	if err != nil {
		t.Fatal(err)
	}
	return e.client(t, c)
}

func post(t *testing.T, c *http.Client, url string, body any) (*http.Response, []byte) {
	t.Helper()
	data, _ := json.Marshal(body)
	resp, err := c.Post(url, "application/json", bytes.NewReader(data))
	if err != nil {
		return nil, []byte(err.Error())
	}
	defer resp.Body.Close()
	out, _ := io.ReadAll(resp.Body)
	return resp, out
}

func records(from, to uint64) IngestRequest {
	var r IngestRequest
	for q := from; q <= to; q++ {
		r.Records = append(r.Records, IngestRecord{Seq: q, Body: []byte(fmt.Sprintf("event %d", q))})
	}
	return r
}

// ⭐ Путь сборщика: mTLS → приём → обещание, подписанное хранилищем; повтор
// пачки отвечает «duplicate»; состояние источника для переустановки.
func TestIngestOverMTLS(t *testing.T) {
	e := setup(t)
	c := e.collector(t, "abs-core")
	resp, body := post(t, c, e.url+"/v1/ingest", records(1, 3))
	if resp == nil || resp.StatusCode != 200 {
		t.Fatalf("ingest: %v %s", resp, body)
	}
	var out IngestResponse
	if err := json.Unmarshal(body, &out); err != nil {
		t.Fatal(err)
	}
	pub, _ := base64.RawStdEncoding.DecodeString(e.st.PublicKey())
	for _, r := range out.Results {
		if r.Status != store.StatusAccepted || r.Promise == nil {
			t.Fatalf("результат: %+v", r)
		}
		if err := proof.VerifyPromise(*r.Promise, ed25519.PublicKey(pub)); err != nil {
			t.Fatal(err)
		}
	}
	_, body = post(t, c, e.url+"/v1/ingest", records(3, 4))
	json.Unmarshal(body, &out)
	if out.Results[0].Status != store.StatusDuplicate || out.Results[1].Status != store.StatusAccepted {
		t.Fatalf("повтор: %s", body)
	}
	r, err := c.Get(e.url + "/v1/state")
	if err != nil {
		t.Fatal(err)
	}
	var st StateResponse
	json.NewDecoder(r.Body).Decode(&st)
	r.Body.Close()
	if st.Source != "abs-core" || st.LastSeq != 4 || st.PublicKey != e.st.PublicKey() {
		t.Fatalf("state: %+v", st)
	}
}

// Источник — только из сертификата: без сертификата, с чужим УЦ, с
// неизвестным именем, с выведенным источником и с незакреплённым
// сертификатом закреплённого источника — отказ.
func TestSourceComesFromCertificate(t *testing.T) {
	e := setup(t)
	other, _ := pki.NewCA("rogue CA")
	rogue, _ := other.Client("abs-core")
	cases := map[string]struct {
		client *http.Client
		code   int // 0 — отказ на рукопожатии TLS
	}{
		"без сертификата":             {e.client(t, nil), 0},
		"чужой УЦ":                    {e.client(t, rogue), 0},
		"неизвестный источник":        {e.collector(t, "intruder"), 403},
		"выведенный источник":         {e.collector(t, "off"), 403},
		"закреплён другой сертификат": {e.collector(t, "pinned-src"), 403},
	}
	for name, c := range cases {
		resp, body := post(t, c.client, e.url+"/v1/ingest", records(1, 1))
		got := 0
		if resp != nil {
			got = resp.StatusCode
		}
		if got != c.code {
			t.Errorf("%s: код %d, ожидали %d (%s)", name, got, c.code, body)
		}
	}
	if resp, body := post(t, e.client(t, e.pinned), e.url+"/v1/ingest", records(1, 1)); resp == nil || resp.StatusCode != 200 {
		t.Fatalf("закреплённый сертификат: %v %s", resp, body)
	}
}

func TestBadRequests(t *testing.T) {
	e := setup(t)
	c := e.collector(t, "abs-core")
	for name, req := range map[string]any{
		"seq 0":      records(0, 0),
		"повтор seq": IngestRequest{Records: []IngestRecord{{Seq: 1}, {Seq: 1}}},
		"битый JSON": "not an object",
	} {
		if resp, body := post(t, c, e.url+"/v1/ingest", req); resp == nil || resp.StatusCode != 400 {
			t.Errorf("%s: %v %s", name, resp, body)
		}
	}
}

// Админка: метка, пакет доказательств, проверка пакета офлайн; ключи.
func TestAdminProofAndKeys(t *testing.T) {
	e := setup(t)
	c := e.collector(t, "abs-core")
	post(t, c, e.url+"/v1/ingest", records(1, 2))
	if resp, body := post(t, e.admin, "http://admin/admin/stamp", nil); resp == nil || resp.StatusCode != 200 {
		t.Fatalf("stamp: %v %s", resp, body)
	}
	resp, err := e.admin.Get("http://admin/admin/proof?source=abs-core&seq=2&dek=1")
	if err != nil {
		t.Fatal(err)
	}
	data, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	b, err := proof.Parse(data)
	if err != nil {
		t.Fatal(err, string(data))
	}
	resp, _ = e.admin.Get("http://admin/admin/tsa-root")
	rootDER, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	root, err := x509.ParseCertificate(rootDER)
	if err != nil {
		t.Fatal(err)
	}
	pool := x509.NewCertPool()
	pool.AddCert(root)
	pub, _ := base64.RawStdEncoding.DecodeString(e.st.PublicKey())
	trust := proof.Trust{StoreKey: ed25519.PublicKey(pub)}
	trust.TSA.Roots = pool
	r := proof.Verify(b, trust)
	if !r.Valid() || string(r.Body) != "event 2" {
		t.Fatalf("пакет:\n%s", r.Text())
	}

	if resp, err := e.admin.Get("http://admin/admin/proof?source=abs-core&seq=99"); err != nil || resp.StatusCode != 404 {
		t.Fatalf("нет такой улики: %v %v", resp, err)
	}
	scope := fmt.Sprintf("abs-core/%s", time.Now().UTC().Format("2006-01"))
	if resp, _ := post(t, e.admin, "http://admin/admin/keys/deactivate", map[string]any{"scopes": []string{scope}}); resp == nil || resp.StatusCode != 409 {
		t.Fatalf("текущий месяц без force: %v", resp)
	}
	if resp, body := post(t, e.admin, "http://admin/admin/keys/deactivate", map[string]any{"scopes": []string{scope}, "force": true}); resp == nil || resp.StatusCode != 200 {
		t.Fatalf("deactivate: %v %s", resp, body)
	}
	if resp, _ := post(t, e.admin, "http://admin/admin/keys/schedule", ScheduleRequest{Scope: scope, Approvals: []string{"operator"}}); resp == nil || resp.StatusCode != 409 {
		t.Fatalf("одно подтверждение: %v", resp)
	}
	if resp, body := post(t, e.admin, "http://admin/admin/keys/schedule", ScheduleRequest{Scope: scope, Approvals: []string{"operator", "security"}}); resp == nil || resp.StatusCode != 200 {
		t.Fatalf("schedule: %v %s", resp, body)
	}
	if resp, body := post(t, e.admin, "http://admin/admin/keys/complete", nil); resp == nil || resp.StatusCode != 200 {
		t.Fatalf("complete: %v %s", resp, body)
	}
	resp, _ = e.admin.Get("http://admin/admin/keys")
	var keys []KeyView
	json.NewDecoder(resp.Body).Decode(&keys)
	resp.Body.Close()
	found := false
	for _, k := range keys {
		if k.Scope == scope {
			found = k.State == "destroyed" && k.EffectiveAt != nil
		}
	}
	if !found {
		t.Fatalf("ключ не уничтожен: %+v", keys)
	}
	// Сборщик этого месяца теперь получает отказ: стёртый месяц не пишется.
	if resp, body := post(t, c, e.url+"/v1/ingest", records(3, 3)); resp == nil || resp.StatusCode != 409 {
		t.Fatalf("запись в стёртый месяц: %v %s", resp, body)
	}
}

func TestAdminSocketIsPrivate(t *testing.T) {
	e := setup(t)
	st, err := os.Stat(e.cfg.AdminSocket)
	if err != nil {
		t.Fatal(err)
	}
	if st.Mode().Perm() != 0o600 {
		t.Fatalf("права сокета %v", st.Mode().Perm())
	}
}
