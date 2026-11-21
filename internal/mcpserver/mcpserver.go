// Package mcpserver — MCP-сервер, через который ИИ-агент ходит в PostgreSQL.
//
// Агент получает три инструмента: query (чтение), execute (изменение) и
// actions (что он уже делал). Каждый вызов execute — одно действие: сервер
// открывает транзакцию, кладёт в неё отметку действия (evidence.mark_action —
// она уходит в журнал базы под тем же номером транзакции, что и изменения
// строк), исполняет запрос и пишет квитанцию: кто, что, какая транзакция, чем
// кончилось. Сборщик espgtap по отметке связывает до-образы с действием, а
// транзакция роли агента без отметки значит, что агент пришёл в базу в обход.
//
// Запреты держит не этот сервер, а база: он подключается ролью агента, и что
// этой роли не выдано, то агенту недоступно, каким бы ни был текст запроса.
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
	"os"
	"slices"
	"strings"
	"time"

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

// DB — соединение с базой (у *pgwire.Conn такой метод есть).
type DB interface {
	Query(sql string) ([]pgwire.Result, error)
}

// Config — настройки сервера.
type Config struct {
	Agent   string // имя агента для отметок и квитанций
	MaxRows int    // сколько строк отдавать агенту из query; 0 — 200
	// Dial открывает соединение ролью агента. Зовётся при первом запросе и
	// заново после обрыва.
	Dial func() (DB, error)
	// Receipts — журнал квитанций (строки JSON, fsync на строку).
	Receipts *os.File
	Version  string // версия программы для serverInfo
}

// Receipt — квитанция одного действия.
type Receipt struct {
	ActionID string          `json:"action_id"`
	Time     string          `json:"time"`
	Agent    string          `json:"agent"`
	Tool     string          `json:"tool"`
	SQL      string          `json:"sql"`
	Reason   string          `json:"reason,omitempty"`
	XID      string          `json:"xid,omitempty"`
	Outcome  string          `json:"outcome"` // committed или failed
	Tags     []string        `json:"tags,omitempty"`
	Error    string          `json:"error,omitempty"`
	Client   json.RawMessage `json:"client,omitempty"`
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
			s.client = c
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
			s.client = p.ClientInfo
		}
		return map[string]any{"protocolVersion": version, "capabilities": map[string]any{"tools": map[string]any{}},
			"serverInfo": s.serverInfo(), "instructions": instructions}, nil
	case "ping":
		if modern {
			break // в ревизии 2026-07-28 ping убран
		}
		return map[string]any{}, nil
	case "tools/list":
		res := map[string]any{"tools": tools}
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
		"name":        "query",
		"title":       "Read from the database",
		"description": "Run one read-only SQL statement (SELECT) and get the rows back as JSON. The transaction is read-only: a statement that writes fails.",
		"inputSchema": map[string]any{"type": "object", "required": []string{"sql"}, "additionalProperties": false,
			"properties": map[string]any{"sql": map[string]any{"type": "string", "description": "A SELECT statement."}}},
	},
	{
		"name":  "execute",
		"title": "Change rows in the database",
		"description": "Run SQL that changes rows (INSERT, UPDATE, DELETE) as one transaction and one recorded action. " +
			"Returns the action id, the transaction id and what each statement did. The previous values of every changed row are kept, so the action can be undone by a human.",
		"inputSchema": map[string]any{"type": "object", "required": []string{"sql"}, "additionalProperties": false,
			"properties": map[string]any{
				"sql":    map[string]any{"type": "string", "description": "One or more statements; they run in a single transaction."},
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

func (s *Server) call(name string, args json.RawMessage) (string, error) {
	var a struct {
		SQL    string `json:"sql"`
		Reason string `json:"reason"`
		Limit  int    `json:"limit"`
	}
	if len(args) > 0 {
		if err := json.Unmarshal(args, &a); err != nil {
			return "", fmt.Errorf("arguments: %w", err)
		}
	}
	switch name {
	case "query", "execute":
		if strings.TrimSpace(a.SQL) == "" {
			return "", errors.New("sql is empty")
		}
		if strings.IndexByte(a.SQL, 0) >= 0 {
			return "", errors.New("sql holds a zero byte")
		}
		if name == "query" {
			return s.query(a.SQL)
		}
		return s.execute(a.SQL, a.Reason)
	case "actions":
		n := a.Limit
		if n <= 0 || n > 50 {
			n = 10
		}
		list := s.recent
		if len(list) > n {
			list = list[len(list)-n:]
		}
		out, _ := json.Marshal(map[string]any{"actions": list})
		return string(out), nil
	}
	return "", errUnknownTool(name)
}

// run исполняет запрос; соединение, сломавшееся не по вине запроса, бросает,
// чтобы следующий вызов открыл новое.
func (s *Server) run(sql string) ([]pgwire.Result, error) {
	if s.db == nil {
		db, err := s.cfg.Dial()
		if err != nil {
			return nil, fmt.Errorf("the database is unreachable: %w", err)
		}
		s.db = db
	}
	res, err := s.db.Query(sql)
	var pg *pgwire.PgError
	if err != nil && !errors.As(err, &pg) {
		if c, ok := s.db.(io.Closer); ok {
			c.Close()
		}
		s.db = nil
	}
	return res, err
}

func (s *Server) query(sql string) (string, error) {
	if _, err := s.run("BEGIN TRANSACTION READ ONLY"); err != nil {
		return "", err
	}
	res, err := s.run(sql)
	s.run("ROLLBACK")
	if err != nil {
		return "", err
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

func (s *Server) execute(sql, reason string) (string, error) {
	rc := Receipt{ActionID: s.newID(), Time: s.now().UTC().Format(time.RFC3339Nano), Agent: s.cfg.Agent, Tool: "execute",
		SQL: sql, Reason: reason, Client: s.client, Outcome: "failed"}
	err := s.transaction(&rc)
	if err != nil {
		rc.Error = err.Error()
	}
	if werr := s.keep(rc); werr != nil {
		// Действие без квитанции — дыра в учёте: о ней должен узнать и агент, и оператор.
		s.log.Error("receipt not written", "action", rc.ActionID, "outcome", rc.Outcome, "err", werr)
		return "", fmt.Errorf("action %s is %s, but its receipt could not be written: %v", rc.ActionID, rc.Outcome, werr)
	}
	if err != nil {
		return "", fmt.Errorf("action %s failed and was rolled back: %w", rc.ActionID, err)
	}
	out, _ := json.Marshal(map[string]any{"action_id": rc.ActionID, "xid": rc.XID, "outcome": rc.Outcome, "statements": rc.Tags})
	return string(out), nil
}

func (s *Server) transaction(rc *Receipt) error {
	if _, err := s.run("BEGIN"); err != nil {
		return err
	}
	fail := func(err error) error {
		s.run("ROLLBACK")
		return err
	}
	mark, _ := json.Marshal(map[string]any{"action_id": rc.ActionID, "agent": rc.Agent, "tool": rc.Tool, "reason": rc.Reason, "client": rc.Client})
	// Отметка — первой: в журнале базы она встанет перед изменениями строк.
	if _, err := s.run("SELECT evidence.mark_action(" + pgwire.Literal(string(mark)) + "::json)"); err != nil {
		return fail(fmt.Errorf("the action marker could not be set (is the database prepared with espgtap -setup-sql?): %w", err))
	}
	res, err := s.run("SELECT pg_current_xact_id()::text")
	if err != nil {
		return fail(err)
	}
	if len(res) == 1 && len(res[0].Rows) == 1 && res[0].Rows[0][0] != nil {
		rc.XID = *res[0].Rows[0][0]
	}
	res, err = s.run(rc.SQL)
	for _, r := range res {
		rc.Tags = append(rc.Tags, r.Tag)
	}
	if err != nil {
		return fail(err)
	}
	if _, err := s.run("COMMIT"); err != nil {
		return fail(err)
	}
	rc.Outcome = "committed"
	return nil
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
	if _, err := s.cfg.Receipts.Write(append(line, '\n')); err != nil {
		return err
	}
	return s.cfg.Receipts.Sync()
}
