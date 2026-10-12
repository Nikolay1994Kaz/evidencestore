package tsa

import (
	"bytes"
	"context"
	"crypto"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/asn1"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
	"time"
)

func authority(t *testing.T, rsaKey bool) (*Authority, string) {
	t.Helper()
	a, err := NewAuthority(rsaKey)
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewServer(a)
	t.Cleanup(srv.Close)
	return a, srv.URL
}

// Полный путь, как с НУЦ: запрос по HTTP → токен → офлайн-проверка по
// закреплённому корню. Оба типа ключей: RSA (как у НУЦ) и ECDSA.
func TestRequestVerify(t *testing.T) {
	for _, rsaKey := range []bool{true, false} {
		a, url := authority(t, rsaKey)
		imprint := Imprint("evidencestore/test/v1", []byte("head"))
		before := time.Now().Add(-time.Second)
		token, err := Request(context.Background(), http.DefaultClient, url, imprint)
		if err != nil {
			t.Fatal(err)
		}
		info, err := Verify(token, imprint, a.Trust())
		if err != nil {
			t.Fatalf("rsa=%v: %v", rsaKey, err)
		}
		if info.GenTime.Before(before.Truncate(time.Second)) || info.GenTime.After(time.Now()) {
			t.Fatalf("время метки %v", info.GenTime)
		}
		if gt, err := GenTime(token); err != nil || !gt.Equal(info.GenTime) {
			t.Fatalf("GenTime: %v, %v", gt, err)
		}
	}
}

// Токен над другим хэшем, токен чужой службы и токен без корня доверия не
// проходят.
func TestVerifyRejects(t *testing.T) {
	a, url := authority(t, false)
	other, _ := authority(t, false)
	imprint := Imprint("d", []byte("head"))
	token, err := Request(context.Background(), http.DefaultClient, url, imprint)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Verify(token, Imprint("d", []byte("other head")), a.Trust()); !errors.Is(err, ErrInvalid) {
		t.Fatalf("другой хэш: %v", err)
	}
	if _, err := Verify(token, imprint, other.Trust()); !errors.Is(err, ErrInvalid) {
		t.Fatalf("чужой корень: %v", err)
	}
	if _, err := Verify(token, imprint, Trust{Roots: x509.NewCertPool()}); !errors.Is(err, ErrInvalid) {
		t.Fatalf("пустое доверие: %v", err)
	}
}

// Любой изменённый байт токена — ошибка проверки. Для обоих типов ключей и
// для настоящего токена НУЦ.
func TestEveryByteOfTokenMatters(t *testing.T) {
	type sample struct {
		name    string
		token   []byte
		imprint [32]byte
		trust   Trust
	}
	var samples []sample
	for _, rsaKey := range []bool{false, true} {
		a, _ := authority(t, rsaKey)
		imprint := Imprint("d", []byte("head"))
		token, err := a.Sign(imprint[:], big.NewInt(7))
		if err != nil {
			t.Fatal(err)
		}
		samples = append(samples, sample{fmt.Sprintf("rsa=%v", rsaKey), token, imprint, a.Trust()})
	}
	nca, _ := os.ReadFile("testdata/nca_kz_token.der")
	ncaTrust, _ := LoadTrust("testdata/root_rsa_2020.cer,testdata/nca_rsa_2022.cer")
	samples = append(samples, sample{"НУЦ", nca, Imprint("evidencestore/testdata/v1", []byte("nca-kz golden token")), ncaTrust})
	for _, s := range samples {
		if _, err := Verify(s.token, s.imprint, s.trust); err != nil {
			t.Fatalf("%s: %v", s.name, err)
		}
		for i := range s.token {
			bad := bytes.Clone(s.token)
			bad[i] ^= 0x01
			if _, err := Verify(bad, s.imprint, s.trust); err == nil {
				t.Fatalf("%s: байт %d из %d изменён, а токен прошёл", s.name, i, len(s.token))
			}
		}
	}
}

// Сертификат без права ставить метки времени не годится, даже если цепочка
// до корня верна: и без назначения вовсе (Go считает такой годным для всего),
// и с чужим назначением.
func TestSignerNeedsTimestampingUsage(t *testing.T) {
	for name, eku := range map[string][]x509.ExtKeyUsage{
		"без назначения":     nil,
		"для TLS":            {x509.ExtKeyUsageServerAuth},
		"метки и ещё что-то": {x509.ExtKeyUsageTimeStamping, x509.ExtKeyUsageServerAuth},
	} {
		a, _ := authority(t, false)
		tmpl := *a.cert
		tmpl.ExtKeyUsage = eku
		tmpl.SerialNumber = big.NewInt(77)
		rootKey := a.rootKeyForTest(t)
		der, err := x509.CreateCertificate(rand.Reader, &tmpl, a.root, a.key.Public(), rootKey)
		if err != nil {
			t.Fatal(err)
		}
		a.cert, _ = x509.ParseCertificate(der)
		imprint := Imprint("d", []byte("head"))
		token, err := a.Sign(imprint[:], nil)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := Verify(token, imprint, a.Trust()); !errors.Is(err, ErrInvalid) {
			t.Fatalf("%s: токен принят: %v", name, err)
		}
	}
}

// Ответ с повтором чужого nonce отвергается: иначе можно подсунуть старый
// ответ TSA.
func TestReplayedResponseRejected(t *testing.T) {
	a, _ := authority(t, false)
	imprint := Imprint("d", []byte("head"))
	stale, _ := a.Sign(imprint[:], big.NewInt(42))
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		writeResp(w, timeStampResp{Status: pkiStatusInfo{Status: 0}, Token: rawToken(stale)})
	}))
	defer srv.Close()
	if _, err := Request(context.Background(), http.DefaultClient, srv.URL, imprint); !errors.Is(err, ErrInvalid) {
		t.Fatalf("повтор ответа: %v", err)
	}
}

// Отказ службы — отказ, даже если к нему приложен токен.
func TestRejectionStatus(t *testing.T) {
	a, _ := authority(t, false)
	for _, withToken := range []bool{false, true} {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			var req timeStampReq
			body, _ := io.ReadAll(r.Body)
			asn1.Unmarshal(body, &req)
			resp := timeStampResp{Status: pkiStatusInfo{Status: 2}}
			if withToken {
				token, _ := a.Sign(req.MessageImprint.HashedMessage, req.Nonce)
				resp.Token = rawToken(token)
			}
			writeResp(w, resp)
		}))
		_, err := Request(context.Background(), http.DefaultClient, srv.URL, Imprint("d", nil))
		srv.Close()
		if !errors.Is(err, ErrRejected) {
			t.Fatalf("отказ службы (токен приложен: %v): %v", withToken, err)
		}
	}
}

// Подписанный атрибут «тип содержимого» обязан называть TSTInfo: иначе
// подпись службы можно было бы предъявить над содержимым другого рода.
func TestContentTypeAttribute(t *testing.T) {
	a, _ := authority(t, false)
	a.ctype = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 7, 1} // id-data
	imprint := Imprint("d", []byte("head"))
	token, err := a.Sign(imprint[:], nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Verify(token, imprint, a.Trust()); !errors.Is(err, ErrInvalid) {
		t.Fatalf("чужой тип содержимого принят: %v", err)
	}
}

// Сохранённая служба поднимается той же: старые токены проверяются.
func TestSaveLoad(t *testing.T) {
	a, _ := authority(t, true)
	dir := t.TempDir()
	if err := a.Save(dir); err != nil {
		t.Fatal(err)
	}
	b, err := LoadAuthority(dir)
	if err != nil {
		t.Fatal(err)
	}
	imprint := sha256.Sum256([]byte("x"))
	token, _ := b.Sign(imprint[:], nil)
	if _, err := Verify(token, imprint, a.Trust()); err != nil {
		t.Fatal(err)
	}
}

// Живая проверка против настоящей службы (НУЦ РК). Запускается вручную:
//
//	ES_TSA_URL=http://tsp.pki.gov.kz ES_TSA_ROOTS=root_rsa_2020.cer,nca_rsa_2022.cer go test -run Live ./internal/tsa/
func TestLiveTSA(t *testing.T) {
	url := os.Getenv("ES_TSA_URL")
	if url == "" {
		t.Skip("ES_TSA_URL не задан")
	}
	imprint := Imprint("evidencestore/live-test/v1", []byte(time.Now().String()))
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	token, err := Request(ctx, http.DefaultClient, url, imprint)
	if err != nil {
		t.Fatal(err)
	}
	trust, err := LoadTrust(os.Getenv("ES_TSA_ROOTS"))
	if err != nil {
		t.Fatal(err)
	}
	info, err := Verify(token, imprint, trust)
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("метка %v, серийный %v, подписант %q, токен %d байт", info.GenTime, info.Serial, info.Signer.Subject, len(token))
}

func rawToken(token []byte) asn1.RawValue { return asn1.RawValue{FullBytes: token} }

func (a *Authority) rootKeyForTest(t *testing.T) crypto.Signer {
	t.Helper()
	if a.rootKey == nil {
		t.Fatal("у службы нет ключа корня")
	}
	return a.rootKey
}

// Настоящий токен TSA НУЦ РК, снятый 03.10.2026, проверяется офлайн по
// сертификатам НУЦ из testdata: формат настоящей службы разбирается всегда,
// без сети.
func TestRealNCAToken(t *testing.T) {
	token, err := os.ReadFile("testdata/nca_kz_token.der")
	if err != nil {
		t.Fatal(err)
	}
	trust, err := LoadTrust("testdata/root_rsa_2020.cer,testdata/nca_rsa_2022.cer")
	if err != nil {
		t.Fatal(err)
	}
	imprint := Imprint("evidencestore/testdata/v1", []byte("nca-kz golden token"))
	info, err := Verify(token, imprint, trust)
	if err != nil {
		t.Fatal(err)
	}
	if info.GenTime.Year() != 2026 || info.Signer.Subject.CommonName != "TIME-STAMPING AUTHORITY" {
		t.Fatalf("метка %v, подписант %q", info.GenTime, info.Signer.Subject.CommonName)
	}
	if _, err := Verify(token, Imprint("evidencestore/testdata/v1", []byte("другое")), trust); !errors.Is(err, ErrInvalid) {
		t.Fatalf("чужой хэш: %v", err)
	}
	other, _ := NewAuthority(false)
	if _, err := Verify(token, imprint, other.Trust()); !errors.Is(err, ErrInvalid) {
		t.Fatalf("без корня НУЦ: %v", err)
	}
}

// Подпись ключом службы, но предъявлен другой сертификат того же ключа:
// signingCertificateV2 называет настоящий, и проверка это ловит.
func TestSigningCertificateBinding(t *testing.T) {
	a, _ := authority(t, false)
	orig := a.cert
	tmpl := *a.cert
	tmpl.SerialNumber = big.NewInt(99)
	der, err := x509.CreateCertificate(rand.Reader, &tmpl, a.root, a.key.Public(), a.rootKeyForTest(t))
	if err != nil {
		t.Fatal(err)
	}
	twin, _ := x509.ParseCertificate(der)
	a.cert, a.essCert = twin, orig
	imprint := Imprint("d", []byte("head"))
	token, err := a.Sign(imprint[:], nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Verify(token, imprint, a.Trust()); !errors.Is(err, ErrInvalid) {
		t.Fatalf("сертификат-двойник принят: %v", err)
	}
	a.essCert = nil
	token, _ = a.Sign(imprint[:], nil)
	if _, err := Verify(token, imprint, a.Trust()); err != nil {
		t.Fatalf("согласованный токен: %v", err)
	}
}

// T-09: сертификат подписанта обязан быть назван подписанным атрибутом —
// signingCertificateV2 или signingCertificate (v1, SHA-1, как у НУЦ РК). v1
// сверяется так же строго; токен без обоих атрибутов не принимается
// (раньше проверялся только v2 и только если он был).
func TestSigningCertificateV1AndRequired(t *testing.T) {
	a, _ := authority(t, false)
	imprint := Imprint("d", []byte("head"))
	a.essV1 = 1
	token, err := a.Sign(imprint[:], nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Verify(token, imprint, a.Trust()); err != nil {
		t.Fatalf("токен с атрибутом v1: %v", err)
	}

	tmpl := *a.cert
	tmpl.SerialNumber = big.NewInt(99)
	der, err := x509.CreateCertificate(rand.Reader, &tmpl, a.root, a.key.Public(), a.rootKeyForTest(t))
	if err != nil {
		t.Fatal(err)
	}
	twin, _ := x509.ParseCertificate(der)
	orig := a.cert
	a.cert, a.essCert = twin, orig // v1 называет настоящий, предъявлен двойник
	token, _ = a.Sign(imprint[:], nil)
	if _, err := Verify(token, imprint, a.Trust()); !errors.Is(err, ErrInvalid) {
		t.Fatalf("двойник при атрибуте v1: %v", err)
	}
	a.cert, a.essCert = orig, nil

	a.essV1 = -1
	token, _ = a.Sign(imprint[:], nil)
	if _, err := Verify(token, imprint, a.Trust()); !errors.Is(err, ErrInvalid) {
		t.Fatalf("токен без атрибута сертификата: %v", err)
	}
}

// T-11: точность метки разбирается и проверяется: «плюс-минус час» не
// годится в границы времени улики.
func TestAccuracyBound(t *testing.T) {
	a, _ := authority(t, false)
	imprint := Imprint("d", []byte("head"))
	a.acc = accuracy{Seconds: 1}
	token, _ := a.Sign(imprint[:], nil)
	if _, err := Verify(token, imprint, a.Trust()); err != nil {
		t.Fatalf("точность 1 с: %v", err)
	}
	a.acc = accuracy{Seconds: 3600}
	token, _ = a.Sign(imprint[:], nil)
	if _, err := Verify(token, imprint, a.Trust()); !errors.Is(err, ErrInvalid) {
		t.Fatalf("точность час: %v", err)
	}
	// Отрицательная часть не вычитается из остальных: 120 с минус 60 000 мс
	// — не «минута», а негодная метка.
	a.acc = accuracy{Seconds: 120, Millis: -60000}
	token, _ = a.Sign(imprint[:], nil)
	if _, err := Verify(token, imprint, a.Trust()); !errors.Is(err, ErrInvalid) {
		t.Fatalf("отрицательная точность: %v", err)
	}
}

// Только для тестов: продукт зовёт встроенную службу напрямую (Sign), без
// HTTP. HTTP нужен, чтобы проверить Request на настоящем обмене RFC 3161.

// ServeHTTP отвечает на запросы RFC 3161, как настоящая служба.
func (a *Authority) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	body, err := io.ReadAll(io.LimitReader(r.Body, 1<<16))
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	var req timeStampReq
	if _, err := asn1.Unmarshal(body, &req); err != nil || !req.MessageImprint.HashAlgorithm.Algorithm.Equal(oidSHA256) {
		writeResp(w, timeStampResp{Status: pkiStatusInfo{Status: 2}}) // rejection
		return
	}
	token, err := a.Sign(req.MessageImprint.HashedMessage, req.Nonce)
	if err != nil {
		writeResp(w, timeStampResp{Status: pkiStatusInfo{Status: 2}})
		return
	}
	writeResp(w, timeStampResp{Status: pkiStatusInfo{Status: 0}, Token: asn1.RawValue{FullBytes: token}})
}

func writeResp(w http.ResponseWriter, resp timeStampResp) {
	der, err := asn1.Marshal(resp)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/timestamp-reply")
	w.Write(der)
}
