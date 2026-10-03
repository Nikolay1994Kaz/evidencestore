// Package metrics — показатели в текстовом формате Prometheus (exposition
// format 0.0.4) без зависимостей. Хранилище собирает их в момент запроса:
// счётчики живут в нём самом, остальное читается из его состояния.
package metrics

import (
	"fmt"
	"io"
	"math"
	"sort"
	"strconv"
	"strings"
)

// Type — тип показателя.
type Type string

const (
	Counter Type = "counter"
	Gauge   Type = "gauge"
)

// Sample — одно значение с метками.
type Sample struct {
	Labels [][2]string // пары имя–значение в порядке вывода
	Value  float64
}

// Family — показатель: имя, пояснение, тип и значения.
type Family struct {
	Name    string
	Help    string
	Type    Type
	Samples []Sample
}

// One — показатель с единственным значением без меток.
func One(name, help string, typ Type, v float64) Family {
	return Family{Name: name, Help: help, Type: typ, Samples: []Sample{{Value: v}}}
}

// Bool — 1 или 0.
func Bool(b bool) float64 {
	if b {
		return 1
	}
	return 0
}

// Write пишет показатели в порядке имён.
func Write(w io.Writer, fams []Family) error {
	sort.SliceStable(fams, func(i, j int) bool { return fams[i].Name < fams[j].Name })
	var b strings.Builder
	for _, f := range fams {
		fmt.Fprintf(&b, "# HELP %s %s\n# TYPE %s %s\n", f.Name, escapeHelp(f.Help), f.Name, f.Type)
		for _, s := range f.Samples {
			b.WriteString(f.Name)
			if len(s.Labels) > 0 {
				b.WriteByte('{')
				for i, l := range s.Labels {
					if i > 0 {
						b.WriteByte(',')
					}
					fmt.Fprintf(&b, "%s=\"%s\"", l[0], escapeLabel(l[1]))
				}
				b.WriteByte('}')
			}
			b.WriteByte(' ')
			b.WriteString(formatValue(s.Value))
			b.WriteByte('\n')
		}
	}
	_, err := io.WriteString(w, b.String())
	return err
}

func formatValue(v float64) string {
	switch {
	case math.IsInf(v, 1):
		return "+Inf"
	case math.IsInf(v, -1):
		return "-Inf"
	case math.IsNaN(v):
		return "NaN"
	}
	return strconv.FormatFloat(v, 'g', -1, 64)
}

func escapeHelp(s string) string {
	return strings.NewReplacer(`\`, `\\`, "\n", `\n`).Replace(s)
}

func escapeLabel(s string) string {
	return strings.NewReplacer(`\`, `\\`, "\n", `\n`, `"`, `\"`).Replace(s)
}
