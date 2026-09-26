package monitoring

import "github.com/VictoriaMetrics/metrics"

var (
	// WalWriteDuration — время группового fsync WAL.
	WalWriteDuration = metrics.NewHistogram("evidencestore_wal_write_duration_seconds")

	// Шиппинг сегментов в удалённое хранилище идёт асинхронно, поэтому
	// ошибки видны только здесь.
	ShipErrors = metrics.NewCounter("evidencestore_ship_errors_total")
	ShipBytes  = metrics.NewCounter("evidencestore_ship_uploaded_bytes_total")
)
