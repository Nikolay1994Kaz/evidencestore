// Package pgrole — проверка того, что роль агента или MCP-сервера может в
// PostgreSQL только выданное ей самой (DECISIONS, п. 40). Один источник для
// двух мест: escollect -setup-sql проверяет роли при настройке базы, esmcp —
// свою роль на каждом новом соединении. Раньше это были два разных запроса, и
// esmcp видел меньше, чем обещано (R1-6, R2-7, заход 2).
//
// SQL агента идёт ролью сервера, поэтому права роли сервера — это права
// агента. Права приходят не только членством и владением: через PUBLIC и
// прямые выдачи на функции SECURITY DEFINER (чужие права, P-276 снова),
// функции и таблицы, которые initdb или расширение оставили суперпользователям
// (dblink_connect_u, pg_authid), сторонние серверы (dblink и postgres_fdw:
// SQL ролью из сопоставления, мимо сборщика — R1-2), параметры уровня
// суперпользователя (track_counts выключает счёт строк — R1-6).
package pgrole

import "strings"

// as — «(as группа)», если право пришло через роль, которой r может стать.
const as = "CASE WHEN g.oid <> r.oid THEN format(' (as %I)', g.rolname) ELSE '' END"

// member — r и все роли g, которыми r может стать (сама r — тоже).
const member = "pg_roles r JOIN pg_roles g ON pg_has_role(r.oid, g.oid, 'MEMBER')"

// initOnly — объект, которому initdb или расширение не дали права priv для
// PUBLIC (запись в pg_init_privs есть, PUBLIC в ней нет).
func initOnly(class, obj, priv string) string {
	return "EXISTS (SELECT FROM pg_init_privs i WHERE i.classoid = '" + class + "'::regclass AND i.objoid = " + obj + " AND i.objsubid = 0\n" +
		"          AND NOT EXISTS (SELECT FROM aclexplode(i.initprivs) a WHERE a.grantee = 0 AND a.privilege_type = '" + priv + "'))"
}

// Rights — запрос строк x: что роли roles (SQL-список: 'a', 'b' или
// current_user) могут сверх выданного им самим. Пусто — ничего. Знаки
// процента в тексте не удвоены: в format строки Go его не передавать.
//
//   - суперпользователь, REPLICATION, CREATEROLE — сама или через роль;
//   - членство в любой роли (кроме неявного pg_database_owner: владение
//     базой называет проверка владения);
//   - EXECUTE на pg_terminate_backend, pg_cancel_backend (обрыв сеанса
//     сервера посреди действия); на функции, которые initdb или расширение
//     оставили суперпользователям; на чужие функции SECURITY DEFINER.
//     Сообщения журнала (pg_logical_emit_message) — не в счёт: «чья
//     транзакция» из базы больше не берётся (DECISIONS, п. 42);
//   - SELECT на колонки таблиц, которые initdb оставил суперпользователям
//     (pg_authid.rolpassword), — кроме колонок, открытых PUBLIC при initdb;
//   - USAGE на сторонний сервер.
func Rights(roles string) string {
	return "SELECT format('%I is a superuser, may replicate or create roles', r.rolname) || " + as + " AS x\n" +
		"      FROM " + member + " WHERE r.rolname IN (" + roles + ") AND (g.rolsuper OR g.rolreplication OR g.rolcreaterole)\n" +
		// Суперпользователь «член» любой роли: называть его по каждой — шум (R2-6).
		"        AND (g.oid = r.oid OR NOT r.rolsuper)\n" +
		"    UNION ALL SELECT format('%I is a member of %I', r.rolname, g.rolname)\n" +
		"      FROM " + member + " WHERE r.rolname IN (" + roles + ") AND g.oid <> r.oid AND g.rolname <> 'pg_database_owner' AND NOT r.rolsuper\n" +
		"    UNION ALL SELECT format('%I can call %s', r.rolname, f.oid::regprocedure) || " + as + "\n" +
		"      FROM " + member + " JOIN pg_proc f ON has_function_privilege(g.oid, f.oid, 'EXECUTE')\n" +
		"      WHERE r.rolname IN (" + roles + ") AND NOT g.rolsuper AND (\n" +
		"        f.pronamespace = 'pg_catalog'::regnamespace AND f.proname IN ('pg_terminate_backend', 'pg_cancel_backend')\n" +
		"        OR " + initOnly("pg_proc", "f.oid", "EXECUTE") + ")\n" +
		"    UNION ALL SELECT format('%I can call %s, a SECURITY DEFINER function of %I', r.rolname, f.oid::regprocedure, pg_get_userbyid(f.proowner)) || " + as + "\n" +
		// Функцию триггера SQL не позовёт: её зовёт только триггер.
		"      FROM " + member + " JOIN pg_proc f ON f.prosecdef AND f.proowner <> r.oid AND has_function_privilege(g.oid, f.oid, 'EXECUTE')\n" +
		"        AND f.prorettype NOT IN ('pg_catalog.trigger'::pg_catalog.regtype, 'pg_catalog.event_trigger'::pg_catalog.regtype)\n" +
		"      WHERE r.rolname IN (" + roles + ") AND NOT g.rolsuper\n" +
		"        AND f.pronamespace <> 'pg_catalog'::regnamespace\n" +
		"    UNION ALL SELECT format('%I can read %s.%I', r.rolname, c.oid::regclass, a.attname) || " + as + "\n" +
		"      FROM " + member + " JOIN pg_class c ON " + initOnly("pg_class", "c.oid", "SELECT") + "\n" +
		"      JOIN pg_attribute a ON a.attrelid = c.oid AND a.attnum > 0 AND NOT a.attisdropped\n" +
		"      WHERE r.rolname IN (" + roles + ") AND NOT g.rolsuper AND has_column_privilege(g.oid, c.oid, a.attnum, 'SELECT')\n" +
		"        AND NOT EXISTS (SELECT FROM pg_init_privs i CROSS JOIN LATERAL aclexplode(i.initprivs) p\n" +
		"          WHERE i.classoid = 'pg_class'::regclass AND i.objoid = c.oid AND i.objsubid = a.attnum AND p.grantee = 0 AND p.privilege_type = 'SELECT')\n" +
		"    UNION ALL SELECT format('%I can use foreign server %I', r.rolname, s.srvname) || " + as + "\n" +
		"      FROM " + member + " JOIN pg_foreign_server s ON has_server_privilege(g.oid, s.oid, 'USAGE')\n" +
		"      WHERE r.rolname IN (" + roles + ") AND NOT g.rolsuper"
}

// Params — запрос строк x: параметры уровня выше user, которые роли могут
// SET или ALTER SYSTEM (PostgreSQL 15+: pg_parameter_acl). Раньше в базе 15
// этой таблицы нет — запрос не звать.
func Params(roles string) string {
	return "SELECT format('%I can %s parameter %s', r.rolname, pr.p, a.parname) AS x\n" +
		"      FROM " + member + " CROSS JOIN pg_parameter_acl a\n" +
		"      LEFT JOIN pg_settings s ON s.name = a.parname CROSS JOIN (VALUES ('SET'), ('ALTER SYSTEM')) AS pr(p)\n" +
		"      WHERE r.rolname IN (" + roles + ") AND NOT g.rolsuper AND has_parameter_privilege(g.oid, a.parname, pr.p)\n" +
		"        AND (pr.p = 'ALTER SYSTEM' OR coalesce(s.context, 'superuser') <> 'user')"
}

// Hint — что сказать оператору на любую строку Rights и Params.
const Hint = "The SQL of the agent runs as the role of the MCP server, so these rights are the agent's: ending the sessions of the server " +
	"in the middle of an action, reading the files of the server (the settings of esmcp with its password) and the password hashes, SQL as another role " +
	"(a SECURITY DEFINER function, a foreign server of dblink or postgres_fdw), switching off the row count (track_counts). " +
	"Everything the role needs this script grants to the role itself: revoke the rest, from PUBLIC too, and the memberships."

// Escape удваивает знаки процента: текст запроса идёт внутрь format.
func Escape(sql string) string { return strings.ReplaceAll(sql, "%", "%%") }
