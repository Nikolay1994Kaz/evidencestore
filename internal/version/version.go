// Package version — версия программы из сведений о сборке. go build (Go
// 1.24+) сам кладёт в бинарник тег (или псевдоверсию, если коммит без тега)
// и коммит; флагов сборки не нужно.
package version

import (
	"fmt"
	"runtime"
	"runtime/debug"
	"strings"
)

// String — «имя версия (commit …, go…, ос/арх)».
func String(name string) string {
	v, rev, modified := "(devel)", "", false
	if info, ok := debug.ReadBuildInfo(); ok {
		if info.Main.Version != "" {
			v = info.Main.Version
		}
		for _, s := range info.Settings {
			switch s.Key {
			case "vcs.revision":
				rev = s.Value
			case "vcs.modified":
				modified = s.Value == "true"
			}
		}
	}
	var parts []string
	if rev != "" {
		c := "commit " + rev[:min(len(rev), 12)]
		if modified && !strings.HasSuffix(v, "+dirty") {
			c += ", modified"
		}
		parts = append(parts, c)
	}
	parts = append(parts, runtime.Version()+" "+runtime.GOOS+"/"+runtime.GOARCH)
	return fmt.Sprintf("%s %s (%s)", name, v, strings.Join(parts, ", "))
}

// Release — тег выпуска, из которого собран бинарник (vX.Y.Z), или "", если
// это не выпуск: псевдоверсия, изменённое дерево, сборка без сведений VCS.
// По нему docker add-source называет образ того же выпуска для сборщика.
func Release() string {
	info, ok := debug.ReadBuildInfo()
	if !ok {
		return ""
	}
	return releaseTag(info.Main.Version)
}

func releaseTag(v string) string {
	if !strings.HasPrefix(v, "v") || strings.ContainsAny(v, "-+") || strings.Count(v, ".") != 2 {
		return ""
	}
	for _, part := range strings.Split(v[1:], ".") {
		if part == "" || strings.Trim(part, "0123456789") != "" {
			return ""
		}
	}
	return v
}
