package pgwire

import (
	"crypto/hmac"
	"crypto/pbkdf2"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"strconv"
	"strings"
)

// scramClient — клиентская сторона SCRAM-SHA-256 (RFC 5802, RFC 7677) без
// привязки к каналу. Пароль берётся как есть: SASLprep не делается, пароль
// не из ASCII может не подойти.
type scramClient struct {
	user        string // в сообщении; PostgreSQL его не читает, непустое — только в тестах
	password    string
	nonce       string
	firstBare   string
	authMessage string
	salted      []byte
}

// newScram: nonce задаётся только в тестах (векторы RFC), иначе случаен.
func newScram(password string, nonce []byte) (*scramClient, error) {
	if nonce == nil {
		raw := make([]byte, 18)
		if _, err := rand.Read(raw); err != nil {
			return nil, err
		}
		nonce = []byte(base64.StdEncoding.EncodeToString(raw))
	}
	return &scramClient{password: password, nonce: string(nonce)}, nil
}

func (s *scramClient) first() []byte {
	// Имя в сообщении пустое: PostgreSQL берёт его из стартового пакета.
	s.firstBare = "n=" + s.user + ",r=" + s.nonce
	return []byte("n,," + s.firstBare)
}

func (s *scramClient) final(serverFirst []byte) ([]byte, error) {
	var nonce, salt64 string
	iter := 0
	for _, f := range strings.Split(string(serverFirst), ",") {
		switch {
		case strings.HasPrefix(f, "r="):
			nonce = f[2:]
		case strings.HasPrefix(f, "s="):
			salt64 = f[2:]
		case strings.HasPrefix(f, "i="):
			iter, _ = strconv.Atoi(f[2:])
		}
	}
	salt, err := base64.StdEncoding.DecodeString(salt64)
	if err != nil || len(salt) == 0 || iter <= 0 || !strings.HasPrefix(nonce, s.nonce) || nonce == s.nonce {
		return nil, errors.New("pgwire: bad SCRAM server-first message")
	}
	if s.salted, err = pbkdf2.Key(sha256.New, s.password, salt, iter, sha256.Size); err != nil {
		return nil, err
	}
	withoutProof := "c=biws,r=" + nonce
	s.authMessage = s.firstBare + "," + string(serverFirst) + "," + withoutProof
	clientKey := mac(s.salted, "Client Key")
	stored := sha256.Sum256(clientKey)
	sig := mac(stored[:], s.authMessage)
	proof := make([]byte, len(clientKey))
	for i := range proof {
		proof[i] = clientKey[i] ^ sig[i]
	}
	return []byte(withoutProof + ",p=" + base64.StdEncoding.EncodeToString(proof)), nil
}

func (s *scramClient) verify(serverFinal []byte) error {
	v, ok := strings.CutPrefix(string(serverFinal), "v=")
	if !ok {
		return fmt.Errorf("pgwire: SCRAM: server answered %q", serverFinal)
	}
	got, err := base64.StdEncoding.DecodeString(v)
	if err != nil {
		return errors.New("pgwire: SCRAM: bad server signature")
	}
	// Сервер, не знающий пароля, подпись не сложит: это проверка сервера.
	if !hmac.Equal(got, mac(mac(s.salted, "Server Key"), s.authMessage)) {
		return errors.New("pgwire: SCRAM: the server signature does not match: this server does not know the password")
	}
	return nil
}

func mac(key []byte, msg string) []byte {
	h := hmac.New(sha256.New, key)
	h.Write([]byte(msg))
	return h.Sum(nil)
}
