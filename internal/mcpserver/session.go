package mcpserver

// Сеанс базы для своих запросов сервера и для команд агента.
//
// Свои запросы сервера — отметка действия, номер транзакции, счёт строк,
// отметка об отказе — идут в том же сеансе и в той же транзакции, что и
// команды агента, а агент влияет на сеанс двумя путями: командами действия
// (SELECT set_config(…, true)) и настройками своей роли (ALTER ROLE … SET в
// своей сессии мимо сервера: к ним сеанс возвращают и DISCARD ALL, и
// SET … TO DEFAULT). Подменённый search_path отдавал счёт строк функциям
// агента (P-242), client_encoding ломал отметку об отказе (P-243). Поэтому
// вокруг своих запросов сервер ставит свои настройки (own), а командам агента
// возвращает его search_path (agentHead): таблицы агент называет так, как
// привык. Вне транзакции действия (отказ по частоте, откат) сеанс — сразу
// после DISCARD ALL: роль и client_encoding — те, с которыми сервер вошёл, а
// литералы pgwire.Literal читаются одинаково при любом
// standard_conforming_strings (P-256).

import (
	"errors"
	"fmt"

	"github.com/Nikolay1994Kaz/evidencestore/internal/pgwire"
)

// own — настройки для своих запросов сервера внутри транзакции (SET LOCAL:
// с её концом они уходят). search_path — только pg_catalog, и pg_temp
// последним: функции и операторы — системные, типы и таблицы pg_temp
// системных не заслонят. Текст — в UTF-8, роль — та, которой сервер вошёл
// (роль сервера может состоять в группе без права на отметки). Строковые
// литералы своих настроек не требуют: pgwire.Literal (P-256). Таймауты —
// те, с которыми сервер вошёл (sessionParams), а transaction_timeout
// (PostgreSQL 17+) — выключен: SQL агента ставил последней командой
// idle_in_transaction_session_timeout = 5 мс, и база рвала сеанс раньше, чем
// ложилась отметка об отказе, — тревоги не было (T заход 2). Запрос — через
// pg_settings: параметра, которого у версии нет, в нём нет и строки.
var own = []string{
	"SET LOCAL search_path = pg_catalog, pg_temp",
	"SET LOCAL client_encoding = 'UTF8'",
	"SET LOCAL ROLE NONE",
	ownTimeouts,
}

const ownTimeouts = "SELECT pg_catalog.set_config(s.name, CASE s.name WHEN 'transaction_timeout' THEN '0' ELSE s.reset_val END, true) " +
	"FROM pg_catalog.pg_settings s WHERE s.name IN ('statement_timeout', 'lock_timeout', 'idle_in_transaction_session_timeout', 'transaction_timeout')"

// agentHead — перед командами агента: его search_path (по умолчанию роли).
// Остальные настройки own командам агента не мешают: текст и так в UTF-8.
var agentHead = []string{"SET LOCAL search_path TO DEFAULT"}

// immediate — отложенные ограничения и триггеры срабатывают здесь, а не на
// COMMIT: их изменения входят в счёт строк (P-246). Идёт ещё с настройками
// агента — так, как сработали бы на COMMIT.
const immediate = "SET CONSTRAINTS ALL IMMEDIATE"

// batch — пачка одного вызова: agentHead, PREPARE каждой команды агента,
// EXECUTE каждой, затем свои команды сервера (хвост). Каждая — отдельным
// текстом расширенного протокола, ответ на каждую — свой Result.
type batch struct {
	sqls      []string
	head, n   int
	immediate bool // хвост начинается с immediate
}

// newBatch собирает пачку. Все PREPARE — раньше всех EXECUTE: отказ любой
// команды при разборе — и не исполнена ни одна. Склейка текста безопасна:
// «;» отвергнет Parse, а после AS грамматика пустит только SELECT, INSERT,
// UPDATE, DELETE, MERGE и VALUES.
func newBatch(stmts []string, write bool, guards []string) batch {
	b := batch{head: len(agentHead), n: len(stmts), immediate: write}
	b.sqls = append(b.sqls, agentHead...)
	for i, st := range stmts {
		b.sqls = append(b.sqls, "PREPARE "+agentStmt(i)+" AS "+st)
	}
	for i := range stmts {
		b.sqls = append(b.sqls, "EXECUTE "+agentStmt(i))
	}
	if write {
		b.sqls = append(b.sqls, immediate)
	}
	b.sqls = append(b.sqls, own...)
	b.sqls = append(b.sqls, guards...)
	return b
}

// agentStmt — имя подготовленной команды агента под номером i.
func agentStmt(i int) string { return fmt.Sprintf("es_agent_%d", i) }

// agent — ответы на команды агента среди ответов пачки.
func (b batch) agent(res []pgwire.Result) []pgwire.Result {
	lo := b.head + b.n
	if len(res) <= lo {
		return nil
	}
	return res[lo:min(len(res), lo+b.n)]
}

// refused объясняет ошибку пачки: на какой команде и почему. done — сколько
// команд пачки прошло. Отказ при подготовке с синтаксической ошибкой — почти
// всегда команда, которой нельзя (COMMIT, SET…), или две в одном тексте: об
// этом и сказано.
func (b batch) refused(err error, done int, read bool) error {
	var pg *pgwire.PgError
	if !errors.As(err, &pg) {
		return err
	}
	switch {
	case done < b.head:
		return fmt.Errorf("the session could not be set up for the statements: %w", err)
	case done < b.head+b.n:
		which := "the statement"
		if b.n > 1 {
			which = fmt.Sprintf("statement %d", done-b.head+1)
		}
		if pg.Code != "42601" {
			return fmt.Errorf("%s: %w", which, err)
		}
		if read {
			return fmt.Errorf("%s was not taken: %w. `query` takes one SELECT (or VALUES) and nothing else; several statements in one string are refused, and changes go through `execute`", which, err)
		}
		return fmt.Errorf("%s was not taken, nothing ran: %w. Each statement must be a single SELECT, INSERT, UPDATE, DELETE, MERGE or VALUES: "+
			"the server runs the transaction itself, so BEGIN, COMMIT, ROLLBACK, SET, DO, CALL and schema changes are not taken, "+
			"and several statements go as separate items of `statements`", which, err)
	case done < b.head+2*b.n:
		if b.n == 1 {
			return err
		}
		return fmt.Errorf("statement %d: %w", done-b.head-b.n+1, err)
	case b.immediate && done == b.head+2*b.n:
		return fmt.Errorf("a deferred constraint or trigger of the tables failed at the end of the action: %w", err)
	}
	return fmt.Errorf("the server could not restore its own session settings after the statements: %w", err)
}
