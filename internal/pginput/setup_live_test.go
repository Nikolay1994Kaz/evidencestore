package pginput

// Скрипт -setup-sql на установке, которая уже была (проверка R2 цикла
// 23.11): то, что прежние версии поставили в базу, снимается, а чужое — нет.

import (
	"context"
	"os"
	"strings"
	"testing"

	"github.com/Nikolay1994Kaz/evidencestore/internal/pgwire"
)

func setupAdmin(t *testing.T, db string) (*pgwire.Conn, string) {
	t.Helper()
	base := os.Getenv("PGINPUT_TEST_DSN")
	if base == "" {
		t.Skip("PGINPUT_TEST_DSN is not set")
	}
	dsn := base + " user=postgres"
	if db != "" {
		dsn = strings.Replace(base, "dbname=live", "dbname="+db, 1) + " user=postgres"
	}
	cfg, err := pgwire.ParseDSN(dsn)
	if err != nil {
		t.Fatal(err)
	}
	c, err := pgwire.Dial(context.Background(), cfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { c.Close() })
	return c, base
}

func setupExec(t *testing.T, c *pgwire.Conn, sqls ...string) {
	t.Helper()
	for _, q := range sqls {
		if _, err := c.Query(q); err != nil {
			t.Fatalf("%s: %v", q, err)
		}
	}
}

// -setup-sql снимал «схему отметок» как DROP SCHEMA IF EXISTS evidence
// CASCADE — любую схему с этим именем, чья бы она ни была. У приложения своя
// схема evidence (дела, улики, вложения — слово частое) — скрипт молча удалял
// её со всеми таблицами и строками при первой же установке (R2-5). Теперь
// снимается только то, чем владеет evidence_owner.
func TestLiveSetupSQLKeepsAnApplicationSchema(t *testing.T) {
	admin, base := setupAdmin(t, "")
	tidy := func() {
		admin.Query("ROLLBACK")
		admin.Query("SET client_min_messages = warning")
		admin.Query("DROP SCHEMA IF EXISTS evidence CASCADE")
		admin.Query("DROP PUBLICATION IF EXISTS r2_pub")
		admin.Query("DROP TABLE IF EXISTS public.r2_acc")
		admin.Query("DROP ROLE IF EXISTS r2_app")
	}
	tidy()
	t.Cleanup(tidy)
	setupExec(t, admin,
		"CREATE ROLE r2_app NOLOGIN",
		"CREATE TABLE public.r2_acc (id int PRIMARY KEY, note text)",
		// Схема приложения: не отметки evidencestore, а его собственные данные.
		"CREATE SCHEMA evidence AUTHORIZATION r2_app",
		"CREATE TABLE evidence.cases (id int PRIMARY KEY, title text)",
		"INSERT INTO evidence.cases SELECT g, 'case ' || g FROM generate_series(1, 1000) g",
		"ALTER TABLE evidence.cases OWNER TO r2_app",
	)
	cfg := Config{DSN: base + " user=r2_tap", Slot: "r2_slot", Publication: "r2_pub", Dir: t.TempDir(), MCPRoles: []string{"r2_mcp"},
		Tables: []string{"public.r2_acc"}}
	if err := cfg.Validate(); err != nil {
		t.Fatal(err)
	}
	setup, err := SetupSQL(&cfg)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := admin.Query(setup); err != nil {
		t.Fatalf("setup: %v", err)
	}
	row, _, err := admin.QueryRow("SELECT count(*)::text FROM pg_namespace WHERE nspname = 'evidence'")
	if err != nil {
		t.Fatal(err)
	}
	if *row[0] != "1" {
		t.Fatal("escollect -setup-sql dropped the application's schema evidence with its 1000 rows of evidence.cases (owner r2_app, not evidence_owner)")
	}
	if row, _, err := admin.QueryRow("SELECT count(*)::text FROM evidence.cases"); err != nil || *row[0] != "1000" {
		t.Fatalf("the rows of evidence.cases: %v %v", row, err)
	}
}

// Переход со старой установки, где отметки стояли в двух базах одного
// сервера (роль evidence_owner — общая на кластер, схема evidence — в каждой
// базе). DROP OWNED снимает объекты только своей базы, и DROP ROLE падал:
// роль владеет схемой во второй, скрипт откатывался весь — ни одну базу не
// перевести (R2-8). Теперь роль остаётся до последней базы.
func TestLiveMigrationOfTwoDatabases(t *testing.T) {
	admin, base := setupAdmin(t, "")
	admin.Query("SET client_min_messages = warning")
	admin.Query("DROP DATABASE IF EXISTS r2_other")
	setupExec(t, admin, "CREATE DATABASE r2_other")
	other, _ := setupAdmin(t, "r2_other")
	tidy := func() {
		admin.Query("ROLLBACK")
		other.Query("DROP SCHEMA IF EXISTS evidence CASCADE")
		admin.Query("DROP SCHEMA IF EXISTS evidence CASCADE")
		admin.Query("DROP PUBLICATION IF EXISTS r2_pub")
		admin.Query("DROP TABLE IF EXISTS public.r2_acc")
		other.Close()
		admin.Query("DROP DATABASE IF EXISTS r2_other")
		admin.Query("DROP OWNED BY evidence_owner")
		admin.Query("DROP ROLE IF EXISTS evidence_owner")
	}
	t.Cleanup(tidy)
	// Как оставила прежняя версия (ef9119a): роль без входа, схема с ключом —
	// в каждой базе, где стоял сборщик.
	setupExec(t, admin, "DO $$ BEGIN IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname = 'evidence_owner') THEN CREATE ROLE evidence_owner NOLOGIN; END IF; END $$",
		"CREATE TABLE public.r2_acc (id int PRIMARY KEY, note text)")
	for _, c := range []*pgwire.Conn{admin, other} {
		setupExec(t, c, "CREATE SCHEMA evidence AUTHORIZATION evidence_owner",
			"CREATE TABLE evidence.marker_key (k text NOT NULL, since pg_lsn NOT NULL)",
			"ALTER TABLE evidence.marker_key OWNER TO evidence_owner")
	}
	cfg := Config{DSN: base + " user=r2_tap", Slot: "r2_slot", Publication: "r2_pub", Dir: t.TempDir(), MCPRoles: []string{"r2_mcp"},
		Tables: []string{"public.r2_acc"}}
	if err := cfg.Validate(); err != nil {
		t.Fatal(err)
	}
	setup, _ := SetupSQL(&cfg)
	if _, err := admin.Query(setup); err != nil {
		t.Fatalf("the setup SQL of the new version fails on a cluster where the old one stood in two databases: %v", err)
	}
	count := func(c *pgwire.Conn, q string) string {
		t.Helper()
		row, _, err := c.QueryRow(q)
		if err != nil {
			t.Fatal(err)
		}
		return *row[0]
	}
	if n := count(admin, "SELECT count(*)::text FROM pg_namespace WHERE nspname = 'evidence'"); n != "0" {
		t.Fatalf("the first database keeps schema evidence: %s", n)
	}
	if n := count(admin, "SELECT count(*)::text FROM pg_roles WHERE rolname = 'evidence_owner'"); n != "1" {
		t.Fatalf("the role is dropped while the second database still has its schema: %s", n)
	}
	setupExec(t, other, "CREATE TABLE public.r2_acc (id int PRIMARY KEY, note text)")
	if _, err := other.Query(setup); err != nil {
		t.Fatalf("the setup SQL in the second database: %v", err)
	}
	if n := count(admin, "SELECT count(*)::text FROM pg_roles WHERE rolname = 'evidence_owner'"); n != "0" {
		t.Fatalf("the role stays after the last database: %s", n)
	}
}
