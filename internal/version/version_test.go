package version

import (
	"runtime"
	"strings"
	"testing"
)

func TestString(t *testing.T) {
	s := String("esverify")
	if !strings.HasPrefix(s, "esverify ") || !strings.Contains(s, runtime.Version()) || !strings.Contains(s, runtime.GOOS+"/"+runtime.GOARCH) {
		t.Fatalf("версия: %q", s)
	}
}
