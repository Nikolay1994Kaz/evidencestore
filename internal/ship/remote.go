// Package ship — транспорт копии наружу: объектное хранилище за интерфейсом
// Remote, каталог (file://) или S3-совместимый бакет (s3://, подпись SigV4
// без aws-sdk). Что, когда и под какими ключами копировать, решает
// вызывающий (internal/store/replica.go).
package ship

import (
	"context"
	"fmt"
	"io"
	"net/url"
	"strings"
)

// Remote — минимальный контракт объектного хранилища. Ключи — относительные
// пути в POSIX-стиле ("evidence/seg_….log/<начало>-<конец>"). Реализации:
// файловая директория (file://) и S3-совместимый бакет (s3://). Удаления в
// контракте нет: из копии улик не удаляется ничего.
type Remote interface {
	// Put полностью записывает объект. Существующий ключ перезаписывается:
	// так повтор после сбоя не падает.
	Put(ctx context.Context, key string, data []byte) error
	// Get возвращает содержимое объекта. Отсутствующий ключ → ErrNotExist.
	Get(ctx context.Context, key string) ([]byte, error)
	// List возвращает все ключи с данным префиксом (рекурсивно).
	List(ctx context.Context, prefix string) ([]string, error)
}

// ErrNotExist сигнализирует об отсутствии объекта (аналог os.ErrNotExist).
var ErrNotExist = fmt.Errorf("ship: object does not exist")

// OpenRemote разбирает URL хранилища и возвращает бэкенд.
//
//	file:///abs/path            — директория (NFS/rclone-mount/локальные тесты)
//	s3://bucket/prefix?endpoint=https://minio:9000&region=us-east-1
//	                            — S3-совместимый бакет; креды из env
//	                              (KVSTORE_S3_ACCESS_KEY/SECRET_KEY или
//	                              AWS_ACCESS_KEY_ID/AWS_SECRET_ACCESS_KEY)
func OpenRemote(rawURL string) (Remote, error) {
	u, err := url.Parse(rawURL)
	if err != nil {
		return nil, fmt.Errorf("ship: bad url %q: %w", rawURL, err)
	}
	switch u.Scheme {
	case "file":
		// file:///abs/path → Host пуст, Path = /abs/path.
		if u.Host != "" || u.Path == "" {
			return nil, fmt.Errorf("ship: file URL must be file:///abs/path, got %q", rawURL)
		}
		return newFileRemote(u.Path)
	case "s3":
		return newS3Remote(u)
	default:
		return nil, fmt.Errorf("ship: unsupported scheme %q (want file:// or s3://)", u.Scheme)
	}
}

// joinKey склеивает сегменты ключа, отбрасывая пустые.
func joinKey(parts ...string) string {
	var b strings.Builder
	for _, p := range parts {
		p = strings.Trim(p, "/")
		if p == "" {
			continue
		}
		if b.Len() > 0 {
			b.WriteByte('/')
		}
		b.WriteString(p)
	}
	return b.String()
}

// readAll — io.ReadAll с оборачиванием ошибки ключом (диагностика оператору).
func readAll(r io.Reader, key string) ([]byte, error) {
	b, err := io.ReadAll(r)
	if err != nil {
		return nil, fmt.Errorf("ship: read %s: %w", key, err)
	}
	return b, nil
}
