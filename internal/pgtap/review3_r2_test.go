package pgtap

// Третий заход проверки (R2, 24.11): как сломать исправления второго захода
// (P-359, P-367). go test ./internal/pgtap -run R2Rev8 -count=1 -v

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/Nikolay1994Kaz/evidencestore/internal/pgoutput"
)

// R2-3. Справочник (index.jsonl) по README — «не улика, а удобство»: «растёт
// ... и не ротируется», «без него транзакцию находят по метке xid в
// хранилище». Оператор его очистил (место кончилось) или он лежит отдельно от
// буфера и пропал. После второго захода справочник решает, повтор ли
// транзакция ниже места входа: на первом же переподключении с повторами
// (сборщик убит -9, PostgreSQL до 17 после перезапуска забыл подтверждённое
// место слота, пачка отпечатков не подтверждена) loadSeen читает пустой
// справочник, loaded = true, floor = 0 — и каждый повтор того, что уже в
// буфере, — «новая транзакция»: Diverged (у pginput — ложная db-rewound и
// void всех намерений: PlaceTime не знает места), и транзакция пишется второй
// раз. Ожидание: повтор того, что в буфере, — повтор, без Diverged.
func TestR2Rev8ClearedIndexTurnsRepeatsIntoARewind(t *testing.T) {
	dir := t.TempDir()
	ins := pgoutput.Insert{RelID: 7, New: []pgoutput.Value{txt("1"), txt("x")}}
	t0 := time.Date(2026, 11, 24, 10, 0, 0, 0, time.UTC)
	h := open(t, dir, func(c *Config) { c.PackTx = 1 })
	h.tx(10, 2000, t0, who("agent"), accounts, ins)
	h.tx(11, 2100, t0.Add(time.Second), who("agent"), accounts, ins)
	h.tap.Close()
	spooled := len(h.sink.bodies)
	// Оператор очистил справочник: ': > index.jsonl'.
	if err := os.Truncate(filepath.Join(dir, IndexFile), 0); err != nil {
		t.Fatal(err)
	}
	var diverged []uint64
	h = openOn(t, dir, h.sink, func(c *Config) {
		c.PackTx = 1
		c.Diverged = func(xid uint32, final, place uint64) error {
			diverged = append(diverged, final, place)
			return nil
		}
	})
	// Слот подтверждён до 1500 (последние подтверждения не дошли): сервер
	// шлёт заново то, что уже в буфере.
	if err := h.tap.Resume(1500, false); err != nil {
		t.Fatal(err)
	}
	h.tx(10, 2000, t0, who("agent"), accounts, ins)
	h.tx(11, 2100, t0.Add(time.Second), who("agent"), accounts, ins)
	t.Logf("repeats of what is in the spool: %d records spooled again, Diverged %v, duplicates %d",
		len(h.sink.bodies)-spooled, diverged, h.tap.Stats().Duplicates)
	if len(diverged) != 0 || len(h.sink.bodies) != spooled {
		t.Errorf("a cleared index turns pure repeats into a 'database went back': Diverged %v, %d records written twice", diverged, len(h.sink.bodies)-spooled)
	}
}

// R2-3 (второе лицо). Справочник удалили на ходу (rm, ротация mv): Tap
// пишет в прежний дескриптор, а loadSeen открывает файл по пути — ENOENT, и
// Resume отдаёт ошибку. У pginput это ошибка identify → connect: каждое
// переподключение с повторами падает, вход стоит до перезапуска сборщика
// (после перезапуска — пустой справочник и первое лицо этой находки).
func TestR2Rev8RemovedIndexStopsTheReconnect(t *testing.T) {
	dir := t.TempDir()
	ins := pgoutput.Insert{RelID: 7, New: []pgoutput.Value{txt("1"), txt("x")}}
	t0 := time.Date(2026, 11, 24, 10, 0, 0, 0, time.UTC)
	h := open(t, dir, func(c *Config) { c.PackTx = 1 })
	h.tx(10, 2000, t0, who("agent"), accounts, ins)
	h.tx(11, 2100, t0.Add(time.Second), who("agent"), accounts, ins)
	if err := os.Remove(filepath.Join(dir, IndexFile)); err != nil {
		t.Fatal(err)
	}
	var errs []error
	for i := 0; i < 3; i++ { // три переподключения подряд
		errs = append(errs, h.tap.Resume(1500, false))
	}
	t.Logf("Resume after the index was removed: %v", errs)
	if errs[0] != nil || errs[2] != nil {
		t.Errorf("with the index removed every reconnect fails in Resume: %v", errs)
	}
}
