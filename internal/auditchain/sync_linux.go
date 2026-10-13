package auditchain

import (
	"os"

	"golang.org/x/sys/unix"
)

// fdatasync сбрасывает данные файла без метаданных.
func fdatasync(f *os.File) error { return unix.Fdatasync(int(f.Fd())) }
