package pgwire

import (
	"context"
	"errors"
	"os"
	"testing"
	"time"
)

// TestLive — против настоящего PostgreSQL, по переменной окружения:
//
//	PGWIRE_TEST_DSN="host=127.0.0.1 port=5432 user=u password=p dbname=d" go test ./internal/pgwire -run Live
//
// Роли нужны REPLICATION и право создавать таблицы; wal_level = logical.
// Проверяет вход (каким его требует сервер: trust, пароль, SCRAM), запросы,
// ошибку сервера и поток репликации с подтверждением позиции.
func TestLive(t *testing.T) {
	dsn := os.Getenv("PGWIRE_TEST_DSN")
	if dsn == "" {
		t.Skip("PGWIRE_TEST_DSN is not set")
	}
	cfg, err := ParseDSN(dsn)
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	c, err := Dial(ctx, cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	if c.Param("server_version") == "" {
		t.Fatal("no server_version parameter")
	}
	res, err := c.Query("SELECT 1 AS a, NULL::text AS b, 'it''s' AS c; SELECT 2")
	if err != nil || len(res) != 2 || *res[0].Rows[0][0] != "1" || res[0].Rows[0][1] != nil || *res[0].Rows[0][2] != "it's" || res[0].Columns[2] != "c" || res[1].Tag != "SELECT 1" {
		t.Fatalf("%+v %v", res, err)
	}
	// Ошибка сервера — *PgError, и соединение после неё живо.
	var pg *PgError
	if _, err := c.Query("SELECT * FROM no_such_table_pgwire"); !errors.As(err, &pg) || pg.Code != "42P01" {
		t.Fatalf("%v", err)
	}
	if row, ok, err := c.QueryRow("SELECT " + Literal("still here")); err != nil || !ok || *row[0] != "still here" {
		t.Fatal(row, ok, err)
	}
	// Неверный пароль — отказ (если сервер его вообще спрашивает).
	bad := cfg
	bad.Password = "wrong-" + cfg.Password
	if bc, err := Dial(ctx, bad); err == nil {
		bc.Close()
		t.Log("the server did not ask for a password (trust): the wrong-password check is skipped")
	}

	slot := "pgwire_live_test"
	c.Query("SELECT pg_drop_replication_slot(" + Literal(slot) + ")")
	if _, err := c.Query("CREATE TABLE IF NOT EXISTS pgwire_live (id int PRIMARY KEY, v text); DROP PUBLICATION IF EXISTS pgwire_live_pub; CREATE PUBLICATION pgwire_live_pub FOR TABLE pgwire_live"); err != nil {
		t.Fatal(err)
	}
	if _, err := c.Query("SELECT pg_create_logical_replication_slot(" + Literal(slot) + ", 'pgoutput')"); err != nil {
		t.Fatal(err)
	}
	defer c.Query("SELECT pg_drop_replication_slot(" + Literal(slot) + ")")
	rcfg := cfg
	rcfg.Replication = true
	r, err := Dial(ctx, rcfg)
	if err != nil {
		t.Fatal(err)
	}
	if err := r.StartReplication(slot, "proto_version", "1", "publication_names", "pgwire_live_pub", "messages", "true"); err != nil {
		t.Fatal(err)
	}
	if _, err := r.Query("SELECT 1"); err == nil {
		t.Fatal("a query went through a streaming connection")
	}
	if _, err := c.Query("INSERT INTO pgwire_live VALUES (1, 'a') ON CONFLICT (id) DO UPDATE SET v = pgwire_live.v || 'a'"); err != nil {
		t.Fatal(err)
	}
	var kinds []byte
	var end LSN
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) && (len(kinds) == 0 || kinds[len(kinds)-1] != 'C') {
		m, err := r.ReadReplication(500 * time.Millisecond)
		if errors.Is(err, ErrTimeout) {
			continue
		}
		if err != nil {
			t.Fatal(err)
		}
		if m.Keepalive {
			continue
		}
		kinds = append(kinds, m.Data[0])
		end = m.WALEnd
	}
	if s := string(kinds); s != "BRIC" && s != "BRUC" {
		t.Fatalf("stream %q", s)
	}
	if err := r.SendStandbyStatus(end); err != nil {
		t.Fatal(err)
	}
	// Тишина: ожидание обрывается по времени, поток остаётся целым.
	if _, err := r.ReadReplication(300 * time.Millisecond); err != nil && !errors.Is(err, ErrTimeout) {
		t.Fatal(err)
	}
	r.Close()
	// Подтверждённая позиция дошла до слота.
	for i := 0; i < 50; i++ {
		row, _, err := c.QueryRow("SELECT confirmed_flush_lsn FROM pg_replication_slots WHERE slot_name = " + Literal(slot))
		if err != nil {
			t.Fatal(err)
		}
		if got, _ := ParseLSN(*row[0]); got >= end {
			return
		}
		time.Sleep(100 * time.Millisecond)
	}
	t.Fatalf("the slot did not move to %s", end)
}
