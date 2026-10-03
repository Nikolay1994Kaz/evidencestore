package metrics

import (
	"math"
	"strings"
	"testing"
)

func TestWrite(t *testing.T) {
	var b strings.Builder
	err := Write(&b, []Family{
		{Name: "es_records_total", Help: "accepted records", Type: Counter, Samples: []Sample{
			{Labels: [][2]string{{"source", `ab"c\d`}}, Value: 3},
			{Labels: [][2]string{{"source", "x\ny"}}, Value: 0},
		}},
		One("es_failed", "line one\nline two", Gauge, Bool(true)),
		One("es_inf", "edge values", Gauge, math.Inf(1)),
	})
	if err != nil {
		t.Fatal(err)
	}
	want := `# HELP es_failed line one\nline two
# TYPE es_failed gauge
es_failed 1
# HELP es_inf edge values
# TYPE es_inf gauge
es_inf +Inf
# HELP es_records_total accepted records
# TYPE es_records_total counter
es_records_total{source="ab\"c\\d"} 3
es_records_total{source="x\ny"} 0
`
	if b.String() != want {
		t.Fatalf("got:\n%s\nwant:\n%s", b.String(), want)
	}
}
