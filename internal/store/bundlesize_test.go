package store

import (
	"encoding/json"
	"testing"
	"time"
)

// Размер пакета одной улики версии 3 (листья от головы под T1 до звена
// записи) против версии 2 — запись раз в секунду, метка раз в 10 минут,
// худший случай — запись перед самой меткой: не больше чем втрое.
func TestBundleSizeV3(t *testing.T) {
	c := newClock()
	s := openStore(t, testConfig(t), c)
	mustStamp(t, s)
	for q := uint64(1); q <= 600; q++ {
		c.add(time.Second)
		ingest(t, s, "abs-core", q, q)
		if err := s.flush(); err != nil { // тик цепи
			t.Fatal(err)
		}
	}
	mustStamp(t, s)
	for _, q := range []uint64{1, 300, 600} {
		b, err := s.Proof("abs-core", q, false)
		if err != nil {
			t.Fatal(err)
		}
		v3, _ := json.Marshal(b)
		b.Version, b.Stretch = 2, nil
		v2, _ := json.Marshal(b)
		t.Logf("запись %d: звеньев %d; версия 2 — %d КБ, версия 3 — %d КБ", q, len(b.Links), len(v2)/1024, len(v3)/1024)
		if len(v3) > 3*len(v2) {
			t.Errorf("запись %d: пакет версии 3 — %d байт, больше утроенного %d", q, len(v3), len(v2))
		}
	}
}
