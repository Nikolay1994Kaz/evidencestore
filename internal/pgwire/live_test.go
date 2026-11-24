package pgwire

import (
	"context"
	"errors"
	"os"
	"strings"
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
	// Литерал читается базой как то же значение при любом
	// standard_conforming_strings, и соседний литерал остаётся значением, а
	// не текстом SQL. Раньше при off черта в конце съедала кавычку, и
	// следующее значение исполнялось (P-256).
	nasty := []string{`x\`, `)) v(a); SELECT 'injected'; --`, `a\'b`, `\\`, `\x41\n`, `it's`, "line\nbreak", ""}
	for _, mode := range []string{"off", "on"} {
		if _, err := c.Query("SET escape_string_warning = off; SET standard_conforming_strings = " + mode); err != nil {
			t.Fatal(err)
		}
		var lits []string
		for _, v := range nasty {
			lits = append(lits, Literal(v))
		}
		res, err := c.Query("SELECT * FROM (VALUES (" + strings.Join(lits, ", ") + ")) v")
		if err != nil || len(res) != 1 || len(res[0].Rows) != 1 || len(res[0].Rows[0]) != len(nasty) {
			t.Fatalf("standard_conforming_strings = %s: %+v %v", mode, res, err)
		}
		for i, v := range nasty {
			if got := res[0].Rows[0][i]; got == nil || *got != v {
				t.Fatalf("standard_conforming_strings = %s: %q came back as %v", mode, v, got)
			}
		}
	}
	c.Query("RESET standard_conforming_strings; RESET escape_string_warning")
	// Неверный пароль — отказ (если сервер его вообще спрашивает).
	bad := cfg
	bad.Password = "wrong-" + cfg.Password
	if bc, err := Dial(ctx, bad); err == nil {
		bc.Close()
		t.Log("the server did not ask for a password (trust): the wrong-password check is skipped")
	}

	// Отмена с другого потока: долгий запрос обрывается ошибкой 57014, а
	// соединение остаётся годным.
	started := time.Now()
	go func() {
		time.Sleep(300 * time.Millisecond)
		if err := c.Cancel(); err != nil {
			t.Error(err)
		}
	}()
	if _, err := c.Query("SELECT pg_sleep(30)"); !errors.As(err, &pg) || pg.Code != "57014" {
		t.Fatalf("a cancelled query: %v", err)
	}
	if took := time.Since(started); took > 10*time.Second {
		t.Fatalf("the cancel took %v", took)
	}
	if row, ok, err := c.QueryRow("SELECT 'alive'"); err != nil || !ok || *row[0] != "alive" {
		t.Fatal(row, ok, err)
	}
	// Отмена, когда запроса нет, ничего не ломает.
	if err := c.Cancel(); err != nil {
		t.Fatal(err)
	}
	if _, err := c.Query("SELECT 1"); err != nil {
		t.Fatal(err)
	}

	// Пачка расширенным протоколом: в тексте одна команда. COMMIT, склеенный с
	// изменением, сервер отвергает при разборе, и открытая транзакция не
	// фиксируется; PREPARE не берёт COMMIT вовсе; EXECUTE отдаёт колонки и
	// тег самой команды.
	if _, err := c.Query("CREATE TEMP TABLE pgwire_pipe (id int)"); err != nil {
		t.Fatal(err)
	}
	count := func() string {
		row, _, err := c.QueryRow("SELECT count(*) FROM pgwire_pipe")
		if err != nil {
			t.Fatal(err)
		}
		return *row[0]
	}
	if c.TxStatus() != TxIdle {
		t.Fatalf("outside a transaction: %c", c.TxStatus())
	}
	c.Query("BEGIN")
	res, err = c.Pipeline([]string{"INSERT INTO pgwire_pipe VALUES (1)", "COMMIT; INSERT INTO pgwire_pipe VALUES (2)", "INSERT INTO pgwire_pipe VALUES (3)"})
	if !errors.As(err, &pg) || pg.Code != "42601" || len(res) != 1 || res[0].Tag != "INSERT 0 1" || c.TxStatus() != TxFailed {
		t.Fatalf("COMMIT glued to a change: %+v %v %c", res, err, c.TxStatus())
	}
	c.Query("ROLLBACK")
	if n := count(); n != "0" {
		t.Fatalf("%s rows after the refused pipeline", n)
	}
	c.Query("BEGIN")
	res, err = c.Pipeline([]string{"PREPARE pw0 AS INSERT INTO pgwire_pipe VALUES (4)", "PREPARE pw1 AS COMMIT", "EXECUTE pw0", "EXECUTE pw1"})
	if !errors.As(err, &pg) || pg.Code != "42601" || len(res) != 1 || res[0].Tag != "PREPARE" || c.TxStatus() != TxFailed {
		t.Fatalf("PREPARE … AS COMMIT: %+v %v %c", res, err, c.TxStatus())
	}
	c.Query("ROLLBACK")
	c.Query("DISCARD ALL")
	c.Query("CREATE TEMP TABLE pgwire_pipe (id int)") // DISCARD ALL убрал и временную таблицу
	c.Query("BEGIN")
	res, err = c.Pipeline([]string{"PREPARE pw0 AS INSERT INTO pgwire_pipe VALUES (5), (6) RETURNING id", "PREPARE pw1 AS SELECT id, 'x' AS t FROM pgwire_pipe WHERE false",
		"EXECUTE pw0", "EXECUTE pw1"})
	if err != nil || len(res) != 4 || res[2].Tag != "INSERT 0 2" || len(res[2].Rows) != 2 || *res[2].Rows[1][0] != "6" ||
		strings.Join(res[3].Columns, ",") != "id,t" || len(res[3].Rows) != 0 || c.TxStatus() != TxOpen {
		t.Fatalf("PREPARE and EXECUTE: %+v %v %c", res, err, c.TxStatus())
	}
	c.Query("ROLLBACK")
	// Вне транзакции пачка — одна неявная транзакция: ошибка откатывает её целиком.
	res, err = c.Pipeline([]string{"INSERT INTO pgwire_pipe VALUES (7)", "SELECT 1/0"})
	if !errors.As(err, &pg) || pg.Code != "22012" || len(res) != 1 || c.TxStatus() != TxIdle || count() != "0" {
		t.Fatalf("an implicit transaction: %+v %v %c %s", res, err, c.TxStatus(), count())
	}
	c.Query("DISCARD ALL")

	slot := "pgwire_live_test"
	c.Query("SELECT pg_drop_replication_slot(" + Literal(slot) + ")")
	if _, err := c.Query("CREATE TABLE IF NOT EXISTS pgwire_live (id int PRIMARY KEY, v text); DROP PUBLICATION IF EXISTS pgwire_live_pub, \"pgwire\\live_pub\"; CREATE PUBLICATION \"pgwire\\live_pub\" FOR TABLE pgwire_live"); err != nil {
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
	// Черта в имени публикации: в команде репликации E'…' нет (R1 заход 2).
	if err := r.StartReplication(slot, 0, "proto_version", "1", "publication_names", `pgwire\live_pub`, "messages", "true"); err != nil {
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
