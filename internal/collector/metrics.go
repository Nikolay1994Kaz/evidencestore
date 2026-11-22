package collector

// Показатели сборщика для Prometheus (страница /metrics, настройка
// metrics_listen). Цикл сборщика однопоточный, и его поля ничем не защищены,
// поэтому показатели не читаются из них по запросу: в конце каждого прохода
// цикл сам складывает снимок (publish), а страница отдаёт последний снимок.
// Отсюда и escollect_loop_timestamp_seconds: время последнего прохода,
// которое перестало расти, — цикл завис.
//
// Чего показатели не скажут: упавший сборщик страницу не отдаёт. О нём
// говорит хранилище (источник замолчал) и сам Prometheus (страница
// недоступна).

import (
	"net/http"

	"github.com/Nikolay1994Kaz/evidencestore/internal/metrics"
)

// publish складывает снимок показателей: зовётся из цикла сборщика.
func (c *Collector) publish() {
	label := [][2]string{{"source", c.source}}
	one := func(name, help string, typ metrics.Type, v float64) metrics.Family {
		return metrics.Family{Name: name, Help: help, Type: typ, Samples: []metrics.Sample{{Labels: label, Value: v}}}
	}
	contact := 0.0
	if !c.contactAt.IsZero() {
		contact = float64(c.contactAt.Unix())
	}
	fams := []metrics.Family{
		one("escollect_up", "1 while the collector runs", metrics.Gauge, 1),
		one("escollect_loop_timestamp_seconds", "when the collector last finished a pass of its loop; a value that stops growing means the loop hangs", metrics.Gauge, float64(c.now().Unix())),
		one("escollect_spool_pending_records", "records in the spool the store has not acknowledged yet", metrics.Gauge, float64(c.pending)),
		one("escollect_issued_seq", "the last record number the collector issued", metrics.Gauge, float64(c.nextSeq-min(c.nextSeq, 1))),
		one("escollect_acked_seq", "the last record number the store acknowledged with a valid promise", metrics.Gauge, float64(c.acked)),
		one("escollect_store_last_contact_timestamp_seconds", "when the store last answered this collector; 0 before the first answer", metrics.Gauge, contact),
	}
	// Вход добавляет своё; метка источника — на каждом его значении.
	if in, ok := c.input.(interface{ Metrics() []metrics.Family }); ok {
		for _, f := range in.Metrics() {
			samples := make([]metrics.Sample, len(f.Samples))
			for i, s := range f.Samples {
				samples[i] = metrics.Sample{Labels: append(append([][2]string{}, label...), s.Labels...), Value: s.Value}
			}
			f.Samples = samples
			fams = append(fams, f)
		}
	}
	c.snap.Store(&fams)
}

// Metrics — показатели на конец последнего прохода цикла (nil — проходов ещё
// не было). Можно звать с любого потока.
func (c *Collector) Metrics() []metrics.Family {
	if p := c.snap.Load(); p != nil {
		return *p
	}
	return nil
}

// MetricsHandler — GET /metrics в текстовом формате Prometheus для всех
// источников процесса: одноимённые показатели разных источников — один
// показатель, значения различаются меткой source.
func MetricsHandler(cs ...*Collector) http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /metrics", func(w http.ResponseWriter, r *http.Request) {
		var merged []metrics.Family
		at := map[string]int{}
		for _, c := range cs {
			for _, f := range c.Metrics() {
				i, seen := at[f.Name]
				if !seen {
					at[f.Name] = len(merged)
					f.Samples = append([]metrics.Sample(nil), f.Samples...) // снимок не трогаем
					merged = append(merged, f)
					continue
				}
				merged[i].Samples = append(merged[i].Samples, f.Samples...)
			}
		}
		w.Header().Set("Content-Type", "text/plain; version=0.0.4; charset=utf-8")
		metrics.Write(w, merged)
	})
	return mux
}
