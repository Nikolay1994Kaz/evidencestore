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

// Образ для сборщика называется по тегу выпуска: псевдоверсия, «+dirty» и
// «(devel)» выпуском не считаются — такого образа в реестре нет.
func TestReleaseTag(t *testing.T) {
	for v, want := range map[string]string{
		"v0.7.0":                               "v0.7.0",
		"v1.12.3":                              "v1.12.3",
		"(devel)":                              "",
		"":                                     "",
		"v0.7.0+dirty":                         "",
		"v0.7.1-0.20261124130000-52654c6b1fb8": "",
		"v0.7.0-rc1":                           "",
		"v0.7":                                 "",
		"v0..7":                                "",
		"0.7.0":                                "",
		"va.b.c":                               "",
	} {
		if got := releaseTag(v); got != want {
			t.Errorf("releaseTag(%q) = %q, а нужно %q", v, got, want)
		}
	}
}
