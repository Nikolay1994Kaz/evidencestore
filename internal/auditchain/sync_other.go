//go:build !linux

package auditchain

import "os"

// fdatasync вне Linux — полный fsync. Хранилище работает только на Linux, а
// пакет нужен и проверяющему (esverify) на любой системе.
func fdatasync(f *os.File) error { return f.Sync() }
