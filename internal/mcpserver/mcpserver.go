// Package mcpserver — MCP-сервер, через который ИИ-агент ходит в PostgreSQL.
//
// Агент получает инструменты: query (чтение), execute (изменение), actions
// (что он уже делал) и, если сервер настроен на хранилище, undo_preview и
// undo_apply (откат своего действия по до-образам из хранилища). Каждый вызов execute — одно действие: сервер
// открывает транзакцию, кладёт в неё отметку действия (evidence.mark_action —
// она уходит в журнал базы под тем же номером транзакции, что и изменения
// строк), исполняет запрос и пишет квитанцию: кто, что, какая транзакция, чем
// кончилось. Сборщик (escollect, источник "postgres") по отметке связывает до-образы с действием, а
// транзакция наблюдаемой роли без отметки значит, что в базу пришли в обход.
//
// Запреты держит не этот сервер, а база: он подключается своей ролью, и что
// этой роли не выдано, то SQL агента недоступно, каким бы ни был его текст.
// Роль сервера — только его (CheckRole): у агента для прямого доступа своя
// роль, только чтение, и стать ролью сервера он не может (DECISIONS, п. 39).
//
// ТРАНЗАКЦИЮ ВЕДЁТ СЕРВЕР. Отметка, предел строк и квитанция держатся на том,
// что до COMMIT сервера ничего не зафиксировано. Поэтому команда агента идёт
// в базу обёрнутой в PREPARE и расширенным протоколом (pgwire.Pipeline):
// разбор допускает ровно одну команду, а грамматика PREPARE — только SELECT,
// INSERT, UPDATE, DELETE, MERGE и VALUES. COMMIT, ROLLBACK, BEGIN, SET, DO,
// CALL и изменения схемы база отвергает ещё при разборе, ничего не исполнив;
// список разрешённого проверяет сама база, а не разбор текста здесь. Раньше
// текст шёл простым протоколом, и COMMIT в нём фиксировал транзакцию сервера
// до проверки предела (P-239). Каждый вызов начинается с DISCARD ALL: что
// SQL агента сменил на весь сеанс (set_config(…, false), рекомендательные
// замки), до следующего вызова не доживает.
//
// ПРОТОКОЛ. JSON-RPC 2.0 по stdio, сообщение на строку. Сервер двух эпох
// (спецификация MCP, «Versioning and Compatibility»): запрос с версией в _meta
// обслуживается без состояния по ревизии 2026-07-28 (server/discover,
// resultType, ошибка -32022 на чужую версию); запрос initialize включает
// прежний порядок с рукопожатием (ревизии 2024-11-05 … 2025-11-25).
package mcpserver

import (
	"bufio"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"maps"
	"os"
	"slices"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/Nikolay1994Kaz/evidencestore/internal/pgundo"
	"github.com/Nikolay1994Kaz/evidencestore/internal/pgwire"
)

// Версии протокола. Современная несёт версию в каждом запросе, прежние —
// договариваются один раз в initialize.
const (
	modernVersion = "2026-07-28"
	metaVersion   = "io.modelcontextprotocol/protocolVersion"
	metaClient    = "io.modelcontextprotocol/clientInfo"
	metaServer    = "io.modelcontextprotocol/serverInfo"
)

var legacyVersions = []string{"2025-11-25", "2025-06-18", "2025-03-26", "2024-11-05"}

const instructions = "Access to a PostgreSQL database for an AI agent. Use `query` to read and `execute` to change rows. " +
	"Every `execute` call is recorded as one action with the previous row values, so a human can undo it later; " +
	"the database role decides what is allowed."

// DB — соединение с базой (у *pgwire.Conn такие методы есть).
type DB interface {
	// Query — простой протокол: для своих запросов сервера, не для текста
	// агента (в нём можно склеить несколько команд).
	Query(sql string) ([]pgwire.Result, error)
	// Pipeline — расширенный протокол, ровно одна команда на текст: для
	// команд агента (pgwire.Pipeline).
	Pipeline(sqls []string) ([]pgwire.Result, error)
	// TxStatus — состояние транзакции после последнего ответа базы
	// (pgwire.TxIdle, TxOpen, TxFailed).
	TxStatus() byte
}

// Config — настройки сервера.
type Config struct {
	Agent   string // имя агента для отметок и квитанций
	MaxRows int    // сколько строк отдавать агенту из query; 0 — 200
	// RowLimit — предохранитель: сколько строк может изменить одно действие
	// execute. Больше — действие откатывается до фиксации, агент получает
	// отказ, а в журнале базы остаётся отметка, по которой сборщик поднимает
	// тревогу. 0 — без предела.
	RowLimit int
	// StatementTimeout — сколько может идти SQL агента (query и execute):
	// дольше — запрос отменяется на сервере базы, соединение закрывается,
	// действие откатывается. LockTimeout — сколько оператор агента ждёт чужую
	// блокировку (SET LOCAL lock_timeout в начале транзакции). 0 — не задано.
	StatementTimeout time.Duration
	LockTimeout      time.Duration
	// ActionsPerMinute — сколько действий execute агент может сделать за
	// минуту; WindowRows — сколько строк изменить за Window. Счёт — по файлу
	// квитанций, общий для всех сеансов агента. 0 — без предела.
	ActionsPerMinute int
	WindowRows       int
	Window           time.Duration
	// Dial открывает соединение ролью сервера с параметрами входа params
	// (pgwire.Config.Params) — их задаёт сервер (sessionParams), и Dial обязан
	// их передать. Зовётся при первом запросе и заново после обрыва.
	Dial func(params map[string]string) (DB, error)
	// Receipts — журнал квитанций (строки JSON, fsync на строку). ReceiptsPath —
	// он же для чтения: по нему действие находится и после перезапуска сервера.
	Receipts     *os.File
	ReceiptsPath string
	// Fetch отдаёт тела записей транзакции из хранилища, выписанные esverify из
	// проверенных пакетов. nil — инструментов отката у агента нет.
	Fetch   func(xid uint32) ([][]byte, error)
	Version string // версия программы для serverInfo
}

// Receipt — квитанция одного действия.
type Receipt struct {
	ActionID string `json:"action_id"`
	Time     string `json:"time"`
	Agent    string `json:"agent"`
	Tool     string `json:"tool"`
	// SQL — команды действия, через ";\n" для чтения; Statements — они же по
	// одной, когда их больше одной.
	SQL        string   `json:"sql"`
	Statements []string `json:"statements,omitempty"`
	Reason     string   `json:"reason,omitempty"`
	// XID — номер транзакции, 32 бита, как в журнале базы и хранилище;
	// FullXID — он же с эпохой (xid8): различает номера, занятые заново.
	XID     string `json:"xid,omitempty"`
	FullXID string `json:"xid8,omitempty"`
	// Outcome — committed, failed, refused (остановлено пределом), escaped
	// (SQL агента сам закрыл транзакцию сервера: что он изменил после этого,
	// могло зафиксироваться мимо пределов) или unknown (связь оборвалась на
	// COMMIT: зафиксировано ли, неизвестно).
	Outcome string   `json:"outcome"`
	Tags    []string `json:"tags,omitempty"`
	Rows    int      `json:"rows,omitempty"` // изменений строк (считается, когда задан предел)
	// Cause — почему действие остановлено сервером: row-limit, window-rows,
	// rate (отказы), timeout (запрос отменён по времени), escaped или unknown
	// (обрыв на COMMIT).
	Cause string `json:"cause,omitempty"`
	// Alerted — об этом отказе за частоту людям ушла тревога (об остальных в
	// ту же минуту — нет).
	Alerted bool            `json:"alerted,omitempty"`
	Error   string          `json:"error,omitempty"`
	Undoes  string          `json:"undoes,omitempty"` // у отката: какое действие он возвращает
	Client  json.RawMessage `json:"client,omitempty"`
}

// Server — один агент на одном потоке ввода-вывода.
type Server struct {
	cfg    Config
	log    *slog.Logger
	db     DB
	now    func() time.Time
	newID  func() string
	client json.RawMessage // clientInfo последнего запроса или initialize
	recent []Receipt
	// ledger — расход агента по файлу квитанций (limits.go).
	ledger *ledger
}

// New собирает сервер.
func New(cfg Config, log *slog.Logger) *Server {
	if cfg.MaxRows <= 0 {
		cfg.MaxRows = 200
	}
	if log == nil {
		log = slog.New(slog.DiscardHandler)
	}
	return &Server{cfg: cfg, log: log, now: time.Now, newID: func() string {
		var b [6]byte
		rand.Read(b[:])
		return time.Now().UTC().Format("20060102T150405Z") + "-" + hex.EncodeToString(b[:])
	}}
}

type request struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id"`
	Method  string          `json:"method"`
	Params  json.RawMessage `json:"params"`
}

type rpcError struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
	Data    any    `json:"data,omitempty"`
}

// Serve читает запросы из in и пишет ответы в out, пока in не закроют:
// закрытый ввод — сигнал клиента завершаться.
func (s *Server) Serve(in io.Reader, out io.Writer) error {
	r := bufio.NewReaderSize(in, 1<<20)
	for {
		line, err := r.ReadBytes('\n')
		if len(strings.TrimSpace(string(line))) > 0 {
			if resp := s.Handle(line); resp != nil {
				if _, werr := out.Write(append(resp, '\n')); werr != nil {
					return werr
				}
			}
		}
		if err == io.EOF {
			return nil
		}
		if err != nil {
			return err
		}
	}
}

// Handle отвечает на одно сообщение. nil — отвечать нечего (уведомление).
func (s *Server) Handle(line []byte) []byte {
	var req request
	if err := json.Unmarshal(line, &req); err != nil || req.JSONRPC != "2.0" || req.Method == "" {
		return reply(nil, nil, &rpcError{Code: -32700, Message: "parse error: expected one JSON-RPC 2.0 message per line"})
	}
	if len(req.ID) == 0 || string(req.ID) == "null" {
		return nil // уведомление: notifications/initialized, notifications/cancelled
	}
	var params struct {
		Meta map[string]json.RawMessage `json:"_meta"`
	}
	json.Unmarshal(req.Params, &params)
	modern := false
	if v, ok := params.Meta[metaVersion]; ok {
		var version string
		json.Unmarshal(v, &version)
		if version != modernVersion {
			return reply(req.ID, nil, &rpcError{Code: -32022, Message: "Unsupported protocol version",
				Data: map[string]any{"supported": append([]string{modernVersion}, legacyVersions...), "requested": version}})
		}
		modern = true
		if c, ok := params.Meta[metaClient]; ok {
			s.client = clientInfo(c)
		}
	}
	result, rerr := s.dispatch(req, modern)
	if rerr != nil {
		return reply(req.ID, nil, rerr)
	}
	if modern {
		// Результат современной ревизии: вид результата и кто отвечает.
		result["resultType"] = "complete"
		result["_meta"] = map[string]any{metaServer: s.serverInfo()}
	}
	return reply(req.ID, result, nil)
}

func reply(id json.RawMessage, result any, e *rpcError) []byte {
	if id == nil {
		id = json.RawMessage("null")
	}
	msg := map[string]any{"jsonrpc": "2.0", "id": id}
	if e != nil {
		msg["error"] = e
	} else {
		msg["result"] = result
	}
	out, _ := json.Marshal(msg)
	return out
}

func (s *Server) serverInfo() map[string]string {
	return map[string]string{"name": "evidencestore-esmcp", "version": s.cfg.Version}
}

func (s *Server) dispatch(req request, modern bool) (map[string]any, *rpcError) {
	switch req.Method {
	case "server/discover":
		return map[string]any{
			"supportedVersions": append([]string{modernVersion}, legacyVersions...),
			"capabilities":      map[string]any{"tools": map[string]any{}},
			"instructions":      instructions,
			"ttlMs":             3_600_000, "cacheScope": "public",
		}, nil
	case "initialize":
		var p struct {
			ProtocolVersion string          `json:"protocolVersion"`
			ClientInfo      json.RawMessage `json:"clientInfo"`
		}
		json.Unmarshal(req.Params, &p)
		version := legacyVersions[0]
		if slices.Contains(legacyVersions, p.ProtocolVersion) {
			version = p.ProtocolVersion // знакомую версию клиента повторяем, иначе предлагаем свою последнюю
		}
		if len(p.ClientInfo) > 0 {
			s.client = clientInfo(p.ClientInfo)
		}
		return map[string]any{"protocolVersion": version, "capabilities": map[string]any{"tools": map[string]any{}},
			"serverInfo": s.serverInfo(), "instructions": instructions}, nil
	case "ping":
		if modern {
			break // в ревизии 2026-07-28 ping убран
		}
		return map[string]any{}, nil
	case "tools/list":
		res := map[string]any{"tools": s.tools()}
		if modern {
			res["ttlMs"], res["cacheScope"] = 3_600_000, "public"
		}
		return res, nil
	case "tools/call":
		var p struct {
			Name      string          `json:"name"`
			Arguments json.RawMessage `json:"arguments"`
		}
		if err := json.Unmarshal(req.Params, &p); err != nil || p.Name == "" {
			return nil, &rpcError{Code: -32602, Message: "tools/call: params need a tool name"}
		}
		text, err := s.call(p.Name, p.Arguments)
		var unknown errUnknownTool
		if errors.As(err, &unknown) {
			return nil, &rpcError{Code: -32602, Message: err.Error()}
		}
		// Ошибка исполнения — результат с isError: её видит модель и может поправиться.
		if err != nil {
			return map[string]any{"content": []map[string]string{{"type": "text", "text": err.Error()}}, "isError": true}, nil
		}
		return map[string]any{"content": []map[string]string{{"type": "text", "text": text}}, "isError": false}, nil
	}
	return nil, &rpcError{Code: -32601, Message: "method not found: " + req.Method}
}

type errUnknownTool string

func (e errUnknownTool) Error() string { return "unknown tool: " + string(e) }

var tools = []map[string]any{
	{
		"name":  "query",
		"title": "Read from the database",
		"description": "Run one read-only SQL statement (SELECT) and get the rows back as JSON. The transaction is read-only: a statement that writes fails. " +
			"One statement only: several in one string are refused.",
		"inputSchema": map[string]any{"type": "object", "required": []string{"sql"}, "additionalProperties": false,
			"properties": map[string]any{"sql": map[string]any{"type": "string", "description": "A SELECT statement."}}},
	},
	{
		"name":  "execute",
		"title": "Change rows in the database",
		"description": "Run SQL that changes rows (INSERT, UPDATE, DELETE, MERGE) as one transaction and one recorded action. " +
			"Give one statement in `sql`, or several in `statements`: they run in that order, in one transaction. " +
			"Each statement is a single SELECT, INSERT, UPDATE, DELETE, MERGE or VALUES. The server runs the transaction itself, " +
			"so BEGIN, COMMIT, ROLLBACK, SET, DO, CALL and schema changes are refused before anything runs. " +
			"Returns the action id, the transaction id and what each statement did. The previous values of every changed row are kept, so the action can be undone by a human.",
		"inputSchema": map[string]any{"type": "object", "additionalProperties": false,
			"properties": map[string]any{
				"sql": map[string]any{"type": "string", "description": "One statement. Use `statements` for several."},
				"statements": map[string]any{"type": "array", "minItems": 1, "maxItems": maxStatements, "items": map[string]any{"type": "string"},
					"description": "Several statements, one per item; they run in order, in a single transaction."},
				"reason": map[string]any{"type": "string", "description": "Why this change is being made, in a sentence. Kept with the action."},
			}},
	},
	{
		"name":        "actions",
		"title":       "List recent actions",
		"description": "List the latest `execute` actions of this session: action id, transaction id, SQL, outcome.",
		"inputSchema": map[string]any{"type": "object", "additionalProperties": false,
			"properties": map[string]any{"limit": map[string]any{"type": "integer", "minimum": 1, "maximum": 50}}},
	},
}

// tools — список инструментов: откат есть, только если сервер умеет достать до-образы.
func (s *Server) tools() []map[string]any {
	list := slices.Clone(tools)
	// Агент должен знать о пределах заранее, а не из отказа.
	var limits string
	if s.cfg.RowLimit > 0 {
		limits += fmt.Sprintf(" One action may change at most %d rows: a larger one is rolled back, nothing changes, "+
			"and the operators are alerted. Do not split such a change into smaller actions; ask a person.", s.cfg.RowLimit)
	}
	if s.cfg.WindowRows > 0 {
		limits += fmt.Sprintf(" All actions together may change at most %d rows in %s.", s.cfg.WindowRows, s.cfg.Window)
	}
	if s.cfg.ActionsPerMinute > 0 {
		limits += fmt.Sprintf(" At most %d actions a minute: do not retry a refused action in a loop.", s.cfg.ActionsPerMinute)
	}
	if s.cfg.StatementTimeout > 0 {
		limits += fmt.Sprintf(" A statement that runs longer than %s is cancelled and the action is rolled back.", s.cfg.StatementTimeout)
	}
	if limits != "" {
		for i, t := range list {
			if t["name"] == "execute" {
				t = maps.Clone(t)
				t["description"] = t["description"].(string) + limits
				list[i] = t
			}
		}
	}
	if s.cfg.Fetch == nil {
		return list
	}
	return append(list, undoTools...)
}

var undoTools = []map[string]any{
	{
		"name":  "undo_preview",
		"title": "Preview the undo of an action",
		"description": "Show what undoing one `execute` action would do: how many rows would get their previous values back, " +
			"and which rows were changed by someone after the action (conflicts — the undo leaves those alone). Changes nothing.",
		"inputSchema": map[string]any{"type": "object", "required": []string{"action_id"}, "additionalProperties": false,
			"properties": map[string]any{"action_id": map[string]any{"type": "string", "description": "The action id returned by `execute`."}}},
	},
	{
		"name":  "undo_apply",
		"title": "Undo an action",
		"description": "Put back the previous values of the rows one `execute` action changed, in a single transaction, using the row images kept in the evidence store. " +
			"Rows changed by someone after the action are left alone and listed. The undo is itself recorded as an action.",
		"inputSchema": map[string]any{"type": "object", "required": []string{"action_id"}, "additionalProperties": false,
			"properties": map[string]any{
				"action_id": map[string]any{"type": "string", "description": "The action id returned by `execute`."},
				"reason":    map[string]any{"type": "string", "description": "Why the action is undone, in a sentence. Kept with the undo."},
			}},
	},
}

func (s *Server) call(name string, args json.RawMessage) (string, error) {
	var a struct {
		SQL        string   `json:"sql"`
		Statements []string `json:"statements"`
		Reason     string   `json:"reason"`
		Limit      int      `json:"limit"`
		ActionID   string   `json:"action_id"`
	}
	if len(args) > 0 {
		if err := json.Unmarshal(args, &a); err != nil {
			return "", fmt.Errorf("arguments: %w", err)
		}
	}
	// Причина — в отметке, квитанции и тексте тревоги людям: в мегабайты она
	// там не нужна, а длиной агент добивался своего — тревога «слишком
	// длинная» (dropped) вместо настоящей, отметка не успевала лечь (T, заходы
	// 1 и 2).
	if len(a.Reason) > maxReason {
		return "", fmt.Errorf("the reason is %d bytes, and at most %d are taken: say it in a sentence", len(a.Reason), maxReason)
	}
	switch name {
	case "query":
		if len(a.Statements) > 0 {
			return "", errors.New("`query` takes one statement in `sql`")
		}
		stmts, err := statements(a.SQL, nil)
		if err != nil {
			return "", err
		}
		return s.query(stmts[0])
	case "execute":
		stmts, err := statements(a.SQL, a.Statements)
		if err != nil {
			return "", err
		}
		return s.execute(stmts, a.Reason)
	case "actions":
		n := a.Limit
		if n <= 0 || n > 50 {
			n = 10
		}
		list := s.history()
		if len(list) > n {
			list = list[len(list)-n:]
		}
		out, _ := json.Marshal(map[string]any{"actions": list})
		return string(out), nil
	case "undo_preview", "undo_apply":
		if s.cfg.Fetch == nil {
			break
		}
		if a.ActionID == "" {
			return "", errors.New("action_id is empty")
		}
		return s.undo(a.ActionID, a.Reason, name == "undo_apply")
	}
	return "", errUnknownTool(name)
}

// history — квитанции из журнала (или из памяти, если журнала на чтение нет).
func (s *Server) history() []Receipt {
	if s.cfg.ReceiptsPath == "" {
		return s.recent
	}
	data, err := os.ReadFile(s.cfg.ReceiptsPath)
	if err != nil {
		return s.recent
	}
	// Файл квитанций может быть общим у нескольких агентов: свои — только
	// этого (P-247). Чужое действие агент не видит и не откатывает.
	var out []Receipt
	for _, line := range strings.Split(string(data), "\n") {
		var rc Receipt
		if line != "" && json.Unmarshal([]byte(line), &rc) == nil && rc.Agent == s.cfg.Agent {
			out = append(out, rc)
		}
	}
	return out
}

// marks — несёт ли транзакция плана отметку действия actionID.
func marks(p *pgundo.Plan, actionID string) bool {
	for _, a := range p.Actions {
		var m struct {
			Info struct {
				ActionID string `json:"action_id"`
			} `json:"info"`
		}
		if json.Unmarshal(a, &m) == nil && m.Info.ActionID == actionID {
			return true
		}
	}
	return false
}

// undoLimit — откат перешёл предел строк по статистике своей транзакции.
type undoLimit struct {
	cause string
	info  map[string]any
	why   error
}

func (e *undoLimit) Error() string { return e.why.Error() }

// undo показывает или применяет откат действия. До-образы — только из
// хранилища (Fetch): локальной копии журнала сервер не верит.
func (s *Server) undo(actionID, reason string, apply bool) (string, error) {
	var target *Receipt
	for _, rc := range s.history() {
		if rc.ActionID == actionID {
			target = &rc
		}
	}
	switch {
	case target == nil:
		return "", fmt.Errorf("action %s is not in this server's receipts", actionID)
	case target.Outcome != "committed" && target.Outcome != "unknown":
		// unknown — COMMIT оборвался, и действие могло зафиксироваться: если
		// хранилище знает транзакцию с его отметкой (marks ниже), откат есть
		// (T заход 2).
		return "", fmt.Errorf("action %s did not commit (%s): there is nothing to undo", actionID, target.Outcome)
	case target.Tool == "undo_apply":
		// Откат отката повторил бы то изменение, которое откат вернул (P-249).
		return "", fmt.Errorf("action %s is itself an undo (of %s): undoing it would make that change again. Ask a person", actionID, target.Undoes)
	}
	// Откат — тоже действие агента: под тем же замком и пределами, что
	// execute (P-249). Частота — раньше базы.
	var rc Receipt
	if apply {
		unlock, err := s.actionLock()
		if err != nil {
			return "", fmt.Errorf("the undo of action %s did not run: %w", actionID, err)
		}
		defer unlock()
		rc = Receipt{ActionID: s.newID(), Time: s.now().UTC().Format(time.RFC3339Nano), Agent: s.cfg.Agent, Tool: "undo_apply",
			Reason: reason, Undoes: actionID, Client: s.client, Outcome: "failed"}
		if err := s.throttle(&rc); err != nil {
			rc.Error = err.Error()
			s.keep(rc)
			return "", fmt.Errorf("undo %s was refused: %w", rc.ActionID, err)
		}
	}
	// В квитанциях до 22.11 номер — с эпохой (xid8); журнал базы и хранилище
	// знают его младшие 32 бита.
	full, err := strconv.ParseUint(target.XID, 10, 64)
	if err != nil {
		return "", fmt.Errorf("action %s has no transaction id in its receipt", actionID)
	}
	xid := uint32(full)
	lines, err := s.cfg.Fetch(xid)
	if err != nil {
		return "", fmt.Errorf("the row images of action %s could not be taken from the evidence store: %w", actionID, err)
	}
	plan, err := pgundo.Build(xid, lines)
	if err != nil {
		return "", err
	}
	// Транзакция с этим номером — та, что несёт отметку действия: номер
	// бывает занят заново (база восстановлена из копии, счётчик обошёл
	// 32 бита), и откат чужой транзакции вышел бы откатом этого действия.
	if !marks(plan, actionID) {
		return "", fmt.Errorf("transaction %d in the evidence store carries no marker of action %s: the transaction id was taken again "+
			"(the database was restored from a backup, or the counter wrapped). This action is not undone here: ask a person", xid, actionID)
	}
	// Сверка и откат — с чистого сеанса; путь поиска ставит pgundo (Path),
	// таймауты — параметры входа (sessionParams).
	if err := s.fresh(); err != nil {
		return "", err
	}
	statuses, err := plan.Check(s.db)
	if err != nil {
		return "", err
	}
	ok, done, bad := pgundo.Tally(statuses)
	conflicts := plan.Conflicts(statuses)
	if len(conflicts) > 20 {
		conflicts = conflicts[:20]
	}
	out := map[string]any{"action_id": actionID, "xid": target.XID, "row_changes": plan.Changes, "undo_steps": len(plan.Steps),
		"to_apply": ok, "already_as_before": done, "conflicts_total": bad, "conflicts": conflicts}
	if !apply {
		text, _ := json.Marshal(out)
		return string(text), nil
	}
	if ok == 0 {
		return "", fmt.Errorf("nothing to apply for action %s: %d steps are already as before, %d are conflicts", actionID, done, bad)
	}
	// Пределы строк — заранее по шагам отката (меньше он не изменит), и перед
	// фиксацией — по статистике его транзакции, с триггерами и каскадами
	// (LimitRows).
	refuse := func(cause string, info map[string]any, why error) (string, error) {
		rc.Outcome, rc.Cause, rc.Rows, rc.Error = "refused", cause, info["rows"].(int), why.Error()
		s.markRefused(&rc, info)
		if werr := s.keep(rc); werr != nil {
			s.log.Error("receipt not written", "action", rc.ActionID, "outcome", rc.Outcome, "err", werr)
		}
		return "", fmt.Errorf("undo %s was refused, nothing changed: %w", rc.ActionID, why)
	}
	if s.cfg.RowLimit > 0 && ok > s.cfg.RowLimit {
		return refuse(CauseRowLimit, map[string]any{"rows": ok, "limit": s.cfg.RowLimit},
			fmt.Errorf("it would change %d rows, and one action may change at most %d: ask a person to undo it", ok, s.cfg.RowLimit))
	}
	if s.cfg.WindowRows > 0 {
		_, before, _, err := s.usage(s.now())
		if err != nil {
			return "", fmt.Errorf("the receipts journal could not be read, so the limit of %d rows in %s cannot be checked: %w", s.cfg.WindowRows, s.cfg.Window, err)
		}
		if before+ok > s.cfg.WindowRows {
			return refuse(CauseWindowRows, map[string]any{"rows": ok, "window_rows": before, "limit": s.cfg.WindowRows, "window": s.cfg.Window.String()},
				fmt.Errorf("with its %d rows the agent would have changed %d rows in the last %s, and the limit is %d: ask a person to undo it",
					ok, before+ok, s.cfg.Window, s.cfg.WindowRows))
		}
	}
	plan.LimitRows(func(rows int) error {
		if s.cfg.RowLimit > 0 && rows > s.cfg.RowLimit {
			return &undoLimit{CauseRowLimit, map[string]any{"rows": rows, "limit": s.cfg.RowLimit},
				fmt.Errorf("it changed %d rows (with what triggers and cascades changed), and one action may change at most %d: ask a person to undo it", rows, s.cfg.RowLimit)}
		}
		if s.cfg.WindowRows > 0 {
			_, before, _, err := s.usage(s.now())
			if err != nil {
				return err
			}
			if before+rows > s.cfg.WindowRows {
				return &undoLimit{CauseWindowRows, map[string]any{"rows": rows, "window_rows": before, "limit": s.cfg.WindowRows, "window": s.cfg.Window.String()},
					fmt.Errorf("with its %d rows the agent would have changed %d rows in the last %s, and the limit is %d: ask a person to undo it",
						rows, before+rows, s.cfg.Window, s.cfg.WindowRows)}
			}
		}
		return nil
	})
	// Откат — тоже действие: его отметка несёт и номер действия, и что он возвращает.
	applied, err := plan.Apply(s.db, map[string]any{"action_id": rc.ActionID, "agent": rc.Agent, "tool": rc.Tool, "reason": reason,
		"undoes_action": actionID, "undoes_xid": target.XID, "steps_applied": ok, "conflicts_left": bad})
	var lim *undoLimit
	if errors.As(err, &lim) {
		return refuse(lim.cause, lim.info, lim.why)
	}
	if errors.Is(err, pgundo.ErrCommitUnknown) {
		// Как у execute (P-258): откат мог зафиксироваться — строки в окно,
		// людям — отметка, агенту — не повторять (R1, R2 заход 3).
		s.drop()
		rc.XID, rc.Outcome, rc.Cause, rc.Rows, rc.Error = applied.XID, "unknown", CauseUnknown, applied.Rows, err.Error()
		s.markRefused(&rc, map[string]any{"xid": rc.XID, "rows": rc.Rows, "tool": rc.Tool})
		if werr := s.keep(rc); werr != nil {
			s.log.Error("receipt not written", "action", rc.ActionID, "outcome", rc.Outcome, "err", werr)
		}
		return "", fmt.Errorf("undo %s: lost the connection to the database during COMMIT: the undo may have been committed (transaction %s). "+
			"Do not repeat it: the operators are alerted to check the transaction", rc.ActionID, rc.XID)
	}
	if err == nil {
		rc.XID, rc.Outcome, rc.Rows = applied.XID, "committed", applied.Rows
	} else {
		rc.Error = err.Error()
	}
	if werr := s.keep(rc); werr != nil {
		s.log.Error("receipt not written", "action", rc.ActionID, "outcome", rc.Outcome, "err", werr)
		return "", fmt.Errorf("undo %s is %s, but its receipt could not be written: %v", rc.ActionID, rc.Outcome, werr)
	}
	if errors.Is(err, pgundo.ErrChanged) {
		return "", fmt.Errorf("%w. Preview the undo again", err)
	}
	if err != nil {
		return "", err
	}
	out["undo_action_id"], out["undo_xid"], out["applied"] = rc.ActionID, applied.XID, applied.Steps
	if len(applied.Differ) > 0 {
		// Строки вернулись, но триггеры таблиц переписали часть значений: агент
		// должен знать, что «как было» получилось не во всём.
		out["differs_from_before"] = applied.Differ
	}
	delete(out, "to_apply")
	text, _ := json.Marshal(out)
	return string(text), nil
}

// run исполняет запрос; соединение, сломавшееся не по вине запроса, бросает,
// чтобы следующий вызов открыл новое.
func (s *Server) run(sql string) ([]pgwire.Result, error) {
	if err := s.connect(); err != nil {
		return nil, err
	}
	res, err := s.db.Query(sql)
	var pg *pgwire.PgError
	if err != nil && !errors.As(err, &pg) {
		s.drop()
	}
	return res, err
}

// pipe исполняет пачку команд расширенным протоколом (pgwire.Pipeline);
// соединение — как у run.
func (s *Server) pipe(sqls []string) ([]pgwire.Result, error) {
	if err := s.connect(); err != nil {
		return nil, err
	}
	res, err := s.db.Pipeline(sqls)
	var pg *pgwire.PgError
	if err != nil && !errors.As(err, &pg) {
		s.drop()
	}
	return res, err
}

// fresh начинает вызов с чистого сеанса. DISCARD ALL сбрасывает то, что SQL
// агента мог оставить сеансу прошлым вызовом: настройки на весь сеанс
// (SELECT set_config(…, false) — роль, search_path, DateStyle…),
// рекомендательные замки, временные таблицы, подготовленные команды. Не
// вышло (сеанс, например, внутри транзакции) — соединение бросается и
// открывается новое: новый сеанс чист сам.
func (s *Server) fresh() error {
	if err := s.connect(); err != nil {
		return err
	}
	if _, err := s.run("DISCARD ALL"); err == nil {
		return nil
	}
	s.drop()
	return s.connect()
}

// maxStatements — сколько команд может быть в одном действии.
const maxStatements = 100

// maxReason — предел длины причины действия или отката, в байтах.
const maxReason = 2000

// clientInfo — сведения о клиенте MCP для отметки и квитанции: имя и версия,
// каждое не длиннее 200 байт. Их шлёт сам агент, и в мегабайты они делали
// строку тревоги «слишком длинной» (dropped) вместо настоящей — как причина
// до предела maxReason (R1, R2, T заход 3).
func clientInfo(raw json.RawMessage) json.RawMessage {
	var c struct {
		Name    string `json:"name"`
		Version string `json:"version"`
	}
	if json.Unmarshal(raw, &c) != nil {
		return nil
	}
	cut := func(s string) string {
		for len(s) > 200 {
			_, n := utf8.DecodeLastRuneInString(s)
			s = s[:len(s)-n]
		}
		return s
	}
	out, _ := json.Marshal(map[string]string{"name": cut(c.Name), "version": cut(c.Version)})
	return out
}

// statements — команды вызова: одна в sql или несколько в list, ни одной
// пустой. Режет на команды не сервер: разбор оставлен базе (prepared).
func statements(sql string, list []string) ([]string, error) {
	switch {
	case sql != "" && len(list) > 0:
		return nil, errors.New("give one statement in `sql` or several in `statements`, not both")
	case len(list) > maxStatements:
		return nil, fmt.Errorf("%d statements, and one action takes at most %d", len(list), maxStatements)
	case len(list) == 0:
		list = []string{sql}
	}
	for i, st := range list {
		if strings.TrimSpace(st) == "" {
			if len(list) == 1 {
				return nil, errors.New("sql is empty")
			}
			return nil, fmt.Errorf("statement %d is empty", i+1)
		}
		if strings.IndexByte(st, 0) >= 0 {
			return nil, fmt.Errorf("statement %d holds a zero byte", i+1)
		}
	}
	return list, nil
}

func (s *Server) query(sql string) (string, error) {
	if err := s.fresh(); err != nil {
		return "", err
	}
	if _, err := s.run("BEGIN TRANSACTION READ ONLY"); err != nil {
		return "", err
	}
	if _, err := s.run(strings.Join(append(slices.Clone(own), s.guards()...), "; ")); err != nil {
		s.run("ROLLBACK")
		return "", err
	}
	b := newBatch([]string{sql}, false, s.guards())
	all, err := s.timed(func() ([]pgwire.Result, error) { return s.pipe(b.sqls) })
	res := b.agent(all)
	if s.db != nil && s.leftReadOnly(res) {
		// Чтение закрыло свою транзакцию «только для чтения»: всё, что шло
		// после этого, исполнялось с правами роли и могло зафиксироваться. С
		// PREPARE так не выйти; проверка — страховка.
		return "", s.escapedQuery(sql)
	}
	if s.db != nil { // по таймауту соединение уже закрыто
		s.run("ROLLBACK")
	}
	if err != nil {
		return "", b.refused(err, len(all), true)
	}
	type set struct {
		Columns   []string    `json:"columns"`
		Rows      [][]*string `json:"rows"`
		Truncated bool        `json:"truncated,omitempty"`
	}
	var out []set
	for _, r := range res {
		if r.Columns == nil {
			continue
		}
		rows := r.Rows
		if rows == nil {
			rows = [][]*string{}
		}
		st := set{Columns: r.Columns, Rows: rows}
		if len(st.Rows) > s.cfg.MaxRows {
			st.Rows, st.Truncated = st.Rows[:s.cfg.MaxRows], true
		}
		out = append(out, st)
	}
	if len(out) == 0 {
		return "", errors.New("the statement returned no rows: `query` is for SELECT; use `execute` to change rows")
	}
	text, _ := json.Marshal(out[len(out)-1])
	return string(text), nil
}

func (s *Server) execute(stmts []string, reason string) (string, error) {
	rc := Receipt{ActionID: s.newID(), Agent: s.cfg.Agent, Tool: "execute",
		SQL: strings.Join(stmts, ";\n"), Reason: reason, Client: s.client, Outcome: "failed"}
	if len(stmts) > 1 {
		rc.Statements = stmts
	}
	unlock, err := s.actionLock()
	if err != nil {
		return "", fmt.Errorf("action %s did not run: %w", rc.ActionID, err)
	}
	defer unlock()
	// Время — после замка: частота считается по нему. Раньше оно ставилось до
	// ожидания, а ждать можно дольше минуты (до statement_timeout + 15 с), и
	// действия, прождавшие в очереди за долгим, были записаны в прошлое — счёт
	// их не видел, и проходили все подряд (R2 заход 2).
	rc.Time = s.now().UTC().Format(time.RFC3339Nano)
	err = s.throttle(&rc)
	if err == nil {
		err = s.transaction(&rc, stmts)
	}
	if err != nil {
		rc.Error = err.Error()
	}
	if werr := s.keep(rc); werr != nil {
		// Действие без квитанции — дыра в учёте: о ней должен узнать и агент, и оператор.
		s.log.Error("receipt not written", "action", rc.ActionID, "outcome", rc.Outcome, "err", werr)
		return "", fmt.Errorf("action %s is %s, but its receipt could not be written: %v", rc.ActionID, rc.Outcome, werr)
	}
	if err != nil && rc.Cause == CauseRate {
		return "", fmt.Errorf("action %s was refused: %w", rc.ActionID, err)
	}
	if err != nil && rc.Outcome == "escaped" {
		return "", fmt.Errorf("action %s %w", rc.ActionID, err)
	}
	if err != nil && rc.Outcome == "unknown" {
		return "", fmt.Errorf("action %s: %w", rc.ActionID, err)
	}
	if err != nil && rc.Outcome == "refused" {
		return "", fmt.Errorf("action %s was refused and rolled back, nothing changed: %w", rc.ActionID, err)
	}
	if err != nil {
		return "", fmt.Errorf("action %s failed and was rolled back: %w", rc.ActionID, err)
	}
	out, _ := json.Marshal(map[string]any{"action_id": rc.ActionID, "xid": rc.XID, "outcome": rc.Outcome, "statements": rc.Tags})
	return string(out), nil
}

// throttle — предел действий в минуту: отказ раньше, чем действие пойдёт в
// базу.
func (s *Server) throttle(rc *Receipt) error {
	if s.cfg.ActionsPerMinute <= 0 {
		return nil
	}
	now := s.now()
	actions, _, alerted, err := s.usage(now)
	if err != nil {
		// Не сосчитать — не пускать: предел, который молча не работает, хуже
		// его отсутствия.
		return fmt.Errorf("the receipts journal could not be read, so the limit of %d actions a minute cannot be checked: %w", s.cfg.ActionsPerMinute, err)
	}
	if actions < s.cfg.ActionsPerMinute {
		return nil
	}
	rc.Outcome, rc.Cause = "refused", CauseRate
	// Тревога людям — на первый отказ и потом не чаще раза в минуту: агент в
	// цикле не должен завалить их сообщениями. В квитанциях — каждый отказ, и
	// по ним же видно, когда тревога уже была: сеансов у агента много.
	if now.Sub(alerted) >= time.Minute {
		// С чистого сеанса: отказ раньше базы идёт до транзакции, а сеанс
		// остался от прошлого вызова (P-243). В квитанции «тревога ушла» —
		// только если отметка легла.
		rc.Alerted = s.fresh() == nil && s.markRefused(rc, map[string]any{"actions": actions, "limit": s.cfg.ActionsPerMinute})
	}
	return fmt.Errorf("%d actions in the last minute, and the limit is %d. Wait before the next one and do not retry in a loop; if this pace is needed, ask a person to raise the limit",
		actions, s.cfg.ActionsPerMinute)
}

func (s *Server) transaction(rc *Receipt, stmts []string) error {
	if err := s.fresh(); err != nil {
		return err
	}
	if _, err := s.run("BEGIN"); err != nil {
		return err
	}
	fail := func(err error) error {
		if s.db != nil { // по таймауту соединение уже закрыто, транзакция откатилась с ним
			s.run("ROLLBACK")
		}
		return err
	}
	// Свои настройки — раньше своих запросов: сеанс после DISCARD ALL несёт
	// умолчания роли, а их мог сменить и не сервер (P-242).
	if _, err := s.run(strings.Join(append(slices.Clone(own), s.guards()...), "; ")); err != nil {
		return fail(err)
	}
	mark, _ := json.Marshal(map[string]any{"action_id": rc.ActionID, "agent": rc.Agent, "tool": rc.Tool, "reason": rc.Reason, "client": rc.Client})
	// Отметка — первой: в журнале базы она встанет перед изменениями строк.
	if _, err := s.run("SELECT evidence.mark_action(" + pgwire.Literal(string(mark)) + "::json)"); err != nil {
		return fail(fmt.Errorf("the action marker could not be set%s: %w", setupHint(err), err))
	}
	// Номер транзакции, а при пределах строк — и счёт строк до SQL агента
	// (changed): тем же запросом, без лишнего обмена с базой. Номер — 32
	// бита, как в журнале базы, справочнике, хранилище и тревогах; полный
	// (с эпохой) — рядом (P-247).
	counting := s.cfg.RowLimit > 0 || s.cfg.WindowRows > 0
	ask := "SELECT pg_current_xact_id()::xid::text, pg_current_xact_id()::text"
	if counting {
		ask += ", " + xactRows
	}
	res, err := s.run(ask)
	if err != nil {
		if counting {
			return fail(fmt.Errorf("the transaction id and its row count could not be read, so the rows the action changes could not be counted and the row limits cannot be checked: %w", err))
		}
		return fail(err)
	}
	if len(res) == 1 && len(res[0].Rows) == 1 && len(res[0].Rows[0]) >= 2 && res[0].Rows[0][0] != nil && res[0].Rows[0][1] != nil {
		rc.XID, rc.FullXID = *res[0].Rows[0][0], *res[0].Rows[0][1]
	}
	before := 0
	if counting {
		if before, err = countIn(res, 2); err != nil {
			return fail(fmt.Errorf("the rows the action changes could not be counted, so the row limits cannot be checked: %w", err))
		}
	}
	b := newBatch(stmts, true, s.guards())
	all, err := s.timed(func() ([]pgwire.Result, error) { return s.pipe(b.sqls) })
	for _, r := range b.agent(all) {
		rc.Tags = append(rc.Tags, r.Tag)
	}
	if errors.Is(err, errTimeout) {
		// Соединение закрыто, транзакция откатилась вместе с ним. Отметка для
		// тревоги — по новому соединению.
		rc.Cause = CauseTimeout
		s.markRefused(rc, map[string]any{"timeout": s.cfg.StatementTimeout.String()})
		return err
	}
	// Транзакция всё ещё та, что открыл сервер? COMMIT или ROLLBACK в тексте
	// агента закрывают её, не спрашивая сервера, а всё, что идёт в тексте
	// после них, база исполняет само по себе: без отметки действия, мимо
	// пределов строк и с фиксацией раньше, чем сервер что-то проверит.
	if left, lerr := s.left(rc.XID, rc.Tags); lerr != nil {
		return fail(lerr)
	} else if left {
		return s.escaped(rc)
	}
	if err != nil {
		return fail(b.refused(err, len(all), false))
	}
	if s.cfg.RowLimit > 0 || s.cfg.WindowRows > 0 {
		// Предохранитель: до фиксации известно, сколько строк действие изменило.
		// Не сосчитать — не фиксировать: предел, который молча не работает, хуже
		// его отсутствия.
		rows, err := s.changed(before, rc.Tags)
		if err != nil {
			return fail(fmt.Errorf("the rows the action changed could not be counted, so the row limits cannot be checked: %w", err))
		}
		rc.Rows = rows
		// refuse: отметка об отказе — не транзакционное сообщение журнала базы,
		// откат её не стирает, и сборщик поднимет тревогу для людей.
		refuse := func(cause string, info map[string]any, why error) error {
			rc.Cause = cause
			s.markRefused(rc, info)
			s.run("ROLLBACK")
			rc.Outcome = "refused"
			return why
		}
		if s.cfg.RowLimit > 0 && rows > s.cfg.RowLimit {
			return refuse(CauseRowLimit, map[string]any{"rows": rows, "limit": s.cfg.RowLimit},
				fmt.Errorf("it would change %d rows, and one action may change at most %d. Do not split it into smaller actions: ask a person to do it or to raise the limit",
					rows, s.cfg.RowLimit))
		}
		if s.cfg.WindowRows > 0 {
			_, before, _, err := s.usage(s.now())
			if err != nil {
				return fail(fmt.Errorf("the receipts journal could not be read, so the limit of %d rows in %s cannot be checked: %w", s.cfg.WindowRows, s.cfg.Window, err))
			}
			if before+rows > s.cfg.WindowRows {
				return refuse(CauseWindowRows, map[string]any{"rows": rows, "window_rows": before, "limit": s.cfg.WindowRows, "window": s.cfg.Window.String()},
					fmt.Errorf("with its %d rows the agent would have changed %d rows in the last %s, and the limit is %d. Do not go on in smaller actions: ask a person to do it or to raise the limit",
						rows, before+rows, s.cfg.Window, s.cfg.WindowRows))
			}
		}
	}
	if _, err := s.run("COMMIT"); err != nil {
		var pg *pgwire.PgError
		if !errors.As(err, &pg) || pg.Severity == "FATAL" || pg.Severity == "PANIC" {
			// Связь оборвалась на COMMIT (или база закрыла сеанс — FATAL):
			// зафиксировала ли она, отсюда не узнать. При синхронной реплике
			// сеанс, прерванный в её ожидании, уже зафиксирован у себя.
			// «Откатилось» сказать нельзя — агент повторил бы действие
			// (P-250); строки идут в счёт окна, а людям — тревога: «спроси
			// человека» без человека не работало (P-258).
			s.drop()
			rc.Outcome, rc.Cause = "unknown", CauseUnknown
			s.markRefused(rc, map[string]any{"xid": rc.XID, "rows": rc.Rows})
			return fmt.Errorf("lost the connection to the database during COMMIT: the action may have been committed (transaction %s). "+
				"Do not repeat it: the operators are alerted to check the transaction", rc.XID)
		}
		return fail(err)
	}
	rc.Outcome = "committed"
	return nil
}

// closing — теги ответа на команды, которые закрывают транзакцию: COMMIT и END
// (тег COMMIT), ROLLBACK и ABORT (тег ROLLBACK), PREPARE TRANSACTION и
// завершение подготовленной. ROLLBACK TO SAVEPOINT тоже даёт тег ROLLBACK, но
// транзакцию не закрывает: это видно по её номеру (left).
var closing = []string{"COMMIT", "ROLLBACK", "PREPARE TRANSACTION", "COMMIT PREPARED", "ROLLBACK PREPARED"}

func closes(tags []string) bool {
	return slices.ContainsFunc(tags, func(tag string) bool { return slices.Contains(closing, tag) })
}

// left — вышел ли SQL агента из транзакции действия xid. Транзакции нет —
// вышел. Транзакция открыта, а среди ответов есть COMMIT или ROLLBACK —
// вышел, если номер у открытой уже не тот (агент закрыл нашу и открыл свою
// BEGIN), и не вышел, если тот же (ROLLBACK TO SAVEPOINT). Транзакция сломана
// ошибкой, соединения нет — номер не спросить: вышел, если в ответах есть
// закрывающая команда. Без закрывающей команды из транзакции не выйти, и
// лишнего вопроса базе нет.
func (s *Server) left(xid string, tags []string) (bool, error) {
	if s.db == nil {
		return closes(tags), nil
	}
	switch s.db.TxStatus() {
	case pgwire.TxIdle:
		return true, nil
	case pgwire.TxFailed:
		return closes(tags), nil
	}
	if !closes(tags) {
		return false, nil
	}
	res, err := s.run("SELECT pg_current_xact_id_if_assigned()::xid::text")
	if err != nil {
		return false, err
	}
	if len(res) != 1 || len(res[0].Rows) != 1 {
		return false, errors.New("the server did not say which transaction is open")
	}
	now := res[0].Rows[0][0]
	return now == nil || *now != xid, nil
}

// escaped завершает действие, чей SQL закрыл транзакцию сервера. Что он
// изменил до своего COMMIT, база уже зафиксировала вместе с отметкой, без
// проверки пределов; что после — отдельными транзакциями без отметки (их
// сборщик назовёт no-action). Сказать агенту «ничего не изменилось» нельзя:
// исход escaped, людям — тревога. Открытое сейчас (транзакция, которую агент
// начал сам, или сломанная) откатывается, сеанс бросается: в нём остались
// настройки, которые текст агента мог сменить.
func (s *Server) escaped(rc *Receipt) error {
	if s.db != nil && s.db.TxStatus() != pgwire.TxIdle {
		s.run("ROLLBACK")
	}
	rc.Outcome, rc.Cause = "escaped", CauseEscaped
	s.markRefused(rc, map[string]any{"xid": rc.XID, "tool": rc.Tool})
	s.drop()
	return errEscaped
}

var errEscaped = errors.New("left the server's transaction: its SQL ended it (COMMIT, ROLLBACK or the like), " +
	"so what it changed may be committed without the row limits being checked. The operators are alerted; do not repeat it. " +
	"The server runs the transaction itself: send the statements without BEGIN, COMMIT or ROLLBACK")

// leftReadOnly — закрыло ли чтение свою транзакцию «только для чтения».
// Номера у неё нет, поэтому признаков два: транзакции нет, или среди ответов
// есть закрывающая команда.
func (s *Server) leftReadOnly(res []pgwire.Result) bool {
	if s.db.TxStatus() == pgwire.TxIdle {
		return true
	}
	tags := make([]string, len(res))
	for i, r := range res {
		tags[i] = r.Tag
	}
	return closes(tags)
}

// escapedQuery — чтение вышло из своей транзакции: квитанция (это уже не
// чтение) и тревога, как у действия.
func (s *Server) escapedQuery(sql string) error {
	rc := Receipt{ActionID: s.newID(), Time: s.now().UTC().Format(time.RFC3339Nano), Agent: s.cfg.Agent, Tool: "query",
		SQL: sql, Client: s.client}
	err := s.escaped(&rc)
	rc.Error = err.Error()
	if werr := s.keep(rc); werr != nil {
		s.log.Error("receipt not written", "action", rc.ActionID, "outcome", rc.Outcome, "err", werr)
	}
	return fmt.Errorf("the read %s %w", rc.ActionID, err)
}

// xactRows — сколько строк, по статистике базы, изменили транзакции этого
// сеанса, ещё не сброшенные в общую статистику. Это сумма n_tup_ins, n_tup_upd
// и n_tup_del вида pg_stat_xact_user_tables, взятая прямо из функций: вид
// соединяет pg_class с индексами и namespace и на каждом вызове обходился
// примерно в 0,5–0,7 мс, а счёт берётся дважды за действие (до и после SQL
// агента). Таблицы те же: всё, что создано после initdb (oid от
// FirstNormalObjectId, 16384), — обычные, секционированные и материализованные;
// системные и TOAST вид отбрасывает так же.
// Тот же запрос считает строки отката (pgundo.XactRows).
const xactRows = pgundo.XactRows

// countIn — число из колонки col единственной строки ответа.
func countIn(res []pgwire.Result, col int) (int, error) {
	if len(res) != 1 || len(res[0].Rows) != 1 || len(res[0].Rows[0]) <= col || res[0].Rows[0][col] == nil {
		return 0, errors.New("the server did not answer the question about the transaction's statistics")
	}
	return strconv.Atoi(*res[0].Rows[0][col])
}

// changed — сколько строк изменила текущая транзакция. Счёт ведёт сама база
// (статистика транзакции): в него входят и строки, изменённые внутри WITH,
// триггерами и каскадом, чего по ответам на операторы не видно. Ответы
// операторов — второе мнение на случай, если статистика в базе выключена
// (track_counts = off): берётся большее.
//
// Счёт — разность: before взят в начале транзакции, до SQL агента.
// Статистика транзакции (pg_stat_xact_*) показывает не одну текущую, а всё, что
// сеанс ещё не сбросил в общую статистику: база сбрасывает её не чаще раза в
// секунду, иначе — примерно через 10 с простоя. Действие вслед за другим
// получало строки соседа к своим: правка одной строки — «would change 101
// rows» (P-240). Внутри транзакции база статистику не сбрасывает, поэтому
// разность — ровно строки этой транзакции.
func (s *Server) changed(before int, tags []string) (int, error) {
	res, err := s.run("SELECT " + xactRows)
	if err != nil {
		return 0, err
	}
	after, err := countIn(res, 0)
	if err != nil {
		return 0, err
	}
	rows := max(after-before, 0)
	byTags := 0
	for _, tag := range tags {
		f := strings.Fields(tag)
		if len(f) < 2 {
			continue
		}
		switch f[0] {
		case "INSERT", "UPDATE", "DELETE", "MERGE":
			n, _ := strconv.Atoi(f[len(f)-1])
			byTags += n
		}
	}
	return max(rows, byTags), nil
}

func (s *Server) keep(rc Receipt) error {
	s.recent = append(s.recent, rc)
	if len(s.recent) > 50 {
		s.recent = s.recent[len(s.recent)-50:]
	}
	if s.cfg.Receipts == nil {
		return nil
	}
	line, err := json.Marshal(rc)
	if err != nil {
		return err
	}
	line = append(line, '\n')
	// Прошлая запись оборвалась на полуслове (сбой процесса, нет места):
	// своя квитанция — с новой строки, иначе она приклеится к обрывку, и её
	// не разберёт ни счёт пределов, ни actions (R1 заход 2).
	if s.cfg.ReceiptsPath != "" && !endsLine(s.cfg.ReceiptsPath) {
		line = append([]byte{'\n'}, line...)
	}
	if _, err := s.cfg.Receipts.Write(line); err != nil {
		return err
	}
	return s.cfg.Receipts.Sync()
}

// endsLine — файл пуст или кончается переводом строки. Не прочесть — да:
// лишний перевод строки безвреден, а не дописать его — тоже не хуже, чем было.
func endsLine(path string) bool {
	f, err := os.Open(path)
	if err != nil {
		return true
	}
	defer f.Close()
	fi, err := f.Stat()
	if err != nil || fi.Size() == 0 {
		return true
	}
	var b [1]byte
	if _, err := f.ReadAt(b[:], fi.Size()-1); err != nil {
		return true
	}
	return b[0] == '\n'
}
