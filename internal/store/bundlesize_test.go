package store

import (
	"encoding/json"
	"testing"
	"time"
)

// Размер пакета одной улики с участком (листья от головы под T1 до звена
// записи: метки целиком, остальное хешем) против пакета без участка — запись
// раз в секунду, метка раз в 10 минут, худший случай — запись перед самой
// меткой: не больше чем вдвое.
func TestBundleSizeStretch(t *testing.T) {
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
		with, _ := json.Marshal(b)
		served, _ := json.MarshalIndent(b, "", " ") // как отдаёт хранилище (server.go)
		n := len(b.Stretch)
		b.Stretch = nil
		without, _ := json.Marshal(b)
		servedWithout, _ := json.MarshalIndent(b, "", " ")
		t.Logf("запись %d: звеньев %d, листьев в участке %d; без участка — %d КБ, с участком — %d КБ; как отдаёт хранилище — %d КБ, ~%d Б на лист участка",
			q, len(b.Links), n, len(without)/1024, len(with)/1024, len(served)/1024, (len(served)-len(servedWithout))/max(n, 1))
		if len(with) > 2*len(without) {
			t.Errorf("запись %d: пакет с участком — %d байт, больше удвоенного %d", q, len(with), len(without))
		}
	}
}
