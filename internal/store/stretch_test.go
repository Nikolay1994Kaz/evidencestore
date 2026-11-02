package store

import (
	"bytes"
	"encoding/json"
	"testing"
	"time"

	"github.com/Nikolay1994Kaz/evidencestore/internal/auditchain"
	"github.com/Nikolay1994Kaz/evidencestore/internal/config"
	"github.com/Nikolay1994Kaz/evidencestore/internal/proof"
)

// P-23: пакет одной улики не показывает чужих записей. Участок — листья от
// головы под T1 до звена улики — нужен сверке обещания, чтобы метку нельзя
// было спрятать; целиком в нём только метки, остальное — хешем. Два
// источника вперемешку, пакет по записи abs-core: имени hr-payroll в пакете
// нет, а обещание сверяется.
func TestBundleShowsNoOtherSources(t *testing.T) {
	c := newClock()
	s := openStore(t, testConfig(t, func(cfg *config.Config) {
		cfg.Sources = append(cfg.Sources, config.Source{Name: "hr-payroll", ContentType: "syslog"})
	}), c)
	mustStamp(t, s)
	var promise proof.Promise
	for q := uint64(1); q <= 5; q++ {
		c.add(time.Second)
		ingest(t, s, "hr-payroll", q, q)
		res := ingest(t, s, "abs-core", q, q)
		promise = *res[0].Promise
		if err := s.flush(); err != nil { // тик цепи
			t.Fatal(err)
		}
	}
	mustStamp(t, s)
	b, err := s.Proof("abs-core", 5, false)
	if err != nil {
		t.Fatal(err)
	}
	full := 0
	for _, l := range b.Stretch {
		if l.Leaf == nil {
			continue
		}
		full++
		if auditchain.EventType(l.Leaf.Type) != auditchain.EventTimestamp {
			t.Fatalf("в участке целиком лист, который не метка: %+v", *l.Leaf)
		}
	}
	data, err := json.Marshal(b)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(data, []byte("hr-payroll")) {
		t.Fatalf("пакет записи abs-core называет источник hr-payroll (листьев в участке %d)", len(b.Stretch))
	}
	r := proof.Verify(b, trustOf(t, s))
	if !r.Valid() {
		t.Fatalf("пакет не прошёл:\n%s", r.Text())
	}
	if err := proof.CheckPromise(promise, r, b, false); err != nil {
		t.Fatalf("обещание записи abs-core 5: %v", err)
	}
	if full == 0 || len(b.Stretch) <= full {
		t.Fatalf("участок: листьев %d, из них целиком %d — ждали метку целиком и записи хешем", len(b.Stretch), full)
	}
}
