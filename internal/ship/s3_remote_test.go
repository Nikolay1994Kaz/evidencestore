package ship

import (
	"context"
	"crypto/md5"
	"encoding/base64"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"sort"
	"strings"
	"sync"
	"testing"
)

// fakeS3 — in-memory S3-совместимый сервер для теста клиента: path-style
// PUT/GET объектов + ListObjectsV2. Подпись не проверяет (это тест
// клиента, не сервера), но требует её наличия и обязательных SigV4-заголовков.
type fakeS3 struct {
	mu      sync.Mutex
	objects map[string][]byte // ключ = "bucket/key"
	t       *testing.T
}

func (f *fakeS3) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	auth := r.Header.Get("Authorization")
	if !strings.HasPrefix(auth, "AWS4-HMAC-SHA256 Credential=") ||
		!strings.Contains(auth, "SignedHeaders=host;x-amz-content-sha256;x-amz-date") ||
		!strings.Contains(auth, "Signature=") {
		f.t.Errorf("bad Authorization header: %q", auth)
		http.Error(w, "bad auth", http.StatusForbidden)
		return
	}
	if r.Header.Get("x-amz-content-sha256") == "" || r.Header.Get("x-amz-date") == "" {
		f.t.Error("missing x-amz-content-sha256 / x-amz-date")
		http.Error(w, "bad headers", http.StatusForbidden)
		return
	}

	path := strings.TrimPrefix(r.URL.Path, "/")
	f.mu.Lock()
	defer f.mu.Unlock()

	// ListObjectsV2: GET /bucket?list-type=2&prefix=...
	if r.Method == http.MethodGet && r.URL.Query().Get("list-type") == "2" {
		bucket := path
		prefix := r.URL.Query().Get("prefix")
		type contents struct {
			Key string `xml:"Key"`
		}
		var result struct {
			XMLName     xml.Name   `xml:"ListBucketResult"`
			IsTruncated bool       `xml:"IsTruncated"`
			Contents    []contents `xml:"Contents"`
		}
		var keys []string
		for k := range f.objects {
			if strings.HasPrefix(k, bucket+"/"+prefix) {
				keys = append(keys, strings.TrimPrefix(k, bucket+"/"))
			}
		}
		sort.Strings(keys)
		for _, k := range keys {
			result.Contents = append(result.Contents, contents{Key: k})
		}
		w.Header().Set("Content-Type", "application/xml")
		xml.NewEncoder(w).Encode(result)
		return
	}

	switch r.Method {
	case http.MethodPut:
		body, _ := io.ReadAll(r.Body)
		// Бакет с Object Lock без контрольной суммы тела запись не принимает.
		sum := md5.Sum(body)
		if got := r.Header.Get("Content-MD5"); got != base64.StdEncoding.EncodeToString(sum[:]) {
			f.t.Errorf("PUT %s: Content-MD5 %q does not match the body", path, got)
			http.Error(w, "BadDigest", http.StatusBadRequest)
			return
		}
		f.objects[path] = body
		w.WriteHeader(http.StatusOK)
	case http.MethodGet:
		if data, ok := f.objects[path]; ok {
			w.Write(data)
		} else {
			http.Error(w, "NoSuchKey", http.StatusNotFound)
		}
	default:
		http.Error(w, "method", http.StatusMethodNotAllowed)
	}
}

func newS3TestRemote(t *testing.T) (*s3Remote, *fakeS3) {
	t.Helper()
	fake := &fakeS3{objects: map[string][]byte{}, t: t}
	srv := httptest.NewServer(fake)
	t.Cleanup(srv.Close)

	t.Setenv("AWS_ACCESS_KEY_ID", "test-access")
	t.Setenv("AWS_SECRET_ACCESS_KEY", "test-secret")

	u, err := url.Parse(fmt.Sprintf("s3://test-bucket/kv/prod?endpoint=%s&region=us-east-1", srv.URL))
	if err != nil {
		t.Fatal(err)
	}
	remote, err := newS3Remote(u)
	if err != nil {
		t.Fatal(err)
	}
	return remote, fake
}

func TestS3Remote_RoundTrip(t *testing.T) {
	remote, fake := newS3TestRemote(t)
	ctx := context.Background()

	// Put → Get байт-в-байт, ключ ложится под prefix из URL.
	payload := []byte("segment bytes \x00\x01\x02")
	if err := remote.Put(ctx, "evidence/seg_00000000000000000001.log/00000000000000000000-00000000000000000017", payload); err != nil {
		t.Fatal(err)
	}
	if _, ok := fake.objects["test-bucket/kv/prod/evidence/seg_00000000000000000001.log/00000000000000000000-00000000000000000017"]; !ok {
		t.Fatalf("объект не под ожидаемым ключом: %v", keysOf(fake.objects))
	}
	got, err := remote.Get(ctx, "evidence/seg_00000000000000000001.log/00000000000000000000-00000000000000000017")
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != string(payload) {
		t.Fatal("payload roundtrip mismatch")
	}

	// List возвращает ключи относительно prefix'а URL.
	if err := remote.Put(ctx, "heads/00000000000000000001.json", []byte("{}")); err != nil {
		t.Fatal(err)
	}
	keys, err := remote.List(ctx, "evidence/")
	if err != nil {
		t.Fatal(err)
	}
	if len(keys) != 1 || keys[0] != "evidence/seg_00000000000000000001.log/00000000000000000000-00000000000000000017" {
		t.Fatalf("list = %v", keys)
	}

	// Get отсутствующего → ErrNotExist.
	if _, err := remote.Get(ctx, "nope"); !errors.Is(err, ErrNotExist) {
		t.Fatalf("want ErrNotExist, got %v", err)
	}
}

// Ключи копии — только AWS_*: переменные старого проекта KVSTORE_S3_* их не
// дают (Q-86).
func TestS3Remote_CredentialsRequired(t *testing.T) {
	t.Setenv("KVSTORE_S3_ACCESS_KEY", "old-access")
	t.Setenv("KVSTORE_S3_SECRET_KEY", "old-secret")
	t.Setenv("AWS_ACCESS_KEY_ID", "")
	t.Setenv("AWS_SECRET_ACCESS_KEY", "")
	u, _ := url.Parse("s3://bucket/prefix")
	if _, err := newS3Remote(u); err == nil {
		t.Fatal("без AWS_* newS3Remote должен вернуть ошибку")
	}
}

// Свидетель голов берёт ключи только из своих переменных: ключи копии
// наружу (AWS_*) ему не подставляются.
func TestOpenRemoteEnv_OwnCredentials(t *testing.T) {
	fake := &fakeS3{objects: map[string][]byte{}, t: t}
	srv := httptest.NewServer(fake)
	t.Cleanup(srv.Close)
	t.Setenv("AWS_ACCESS_KEY_ID", "copy-access")
	t.Setenv("AWS_SECRET_ACCESS_KEY", "copy-secret")
	t.Setenv("ES_WITNESS_ACCESS_KEY_ID", "")
	t.Setenv("ES_WITNESS_SECRET_ACCESS_KEY", "")
	rawURL := fmt.Sprintf("s3://witness/heads?endpoint=%s&region=us-east-1", srv.URL)
	if _, err := OpenRemoteEnv(rawURL, "ES_WITNESS"); err == nil {
		t.Fatal("без своих ключей свидетель открылся с ключами копии")
	}
	t.Setenv("ES_WITNESS_ACCESS_KEY_ID", "witness-access")
	t.Setenv("ES_WITNESS_SECRET_ACCESS_KEY", "witness-secret")
	r, err := OpenRemoteEnv(rawURL, "ES_WITNESS")
	if err != nil {
		t.Fatal(err)
	}
	if got := r.(*s3Remote).accessKey; got != "witness-access" {
		t.Fatalf("ключ доступа свидетеля %q", got)
	}
	if err := r.Put(context.Background(), "heads/00000000000000000001.json", []byte("{}")); err != nil {
		t.Fatal(err)
	}
	if _, ok := fake.objects["witness/heads/heads/00000000000000000001.json"]; !ok {
		t.Fatalf("объекты: %v", keysOf(fake.objects))
	}
}

func TestOpenRemote_Schemes(t *testing.T) {
	// file://host/path (двойной слэш = host-часть) — ошибка формата: путь
	// обязан быть абсолютным (file:///abs/path).
	if _, err := OpenRemote("file://relative/path"); err == nil {
		t.Fatal("file:// с host-частью должен отклоняться")
	}
	if _, err := OpenRemote("file://" + t.TempDir()); err != nil {
		t.Fatalf("file:///abs: %v", err)
	}
	if _, err := OpenRemote("ftp://x"); err == nil {
		t.Fatal("неизвестная схема должна отклоняться")
	}
}

func keysOf(m map[string][]byte) []string {
	var ks []string
	for k := range m {
		ks = append(ks, k)
	}
	sort.Strings(ks)
	return ks
}
