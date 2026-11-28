package pginput

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/Nikolay1994Kaz/evidencestore/internal/alert"
	"github.com/Nikolay1994Kaz/evidencestore/internal/gateway"
	"github.com/Nikolay1994Kaz/evidencestore/internal/mcpserver"
	"github.com/Nikolay1994Kaz/evidencestore/internal/pgundo"
	"github.com/Nikolay1994Kaz/evidencestore/internal/pgwire"
)

// liveGateway — шлюз в живых тестах: свой ключ и свой файл квитанций,
// намерения действий и откатов — как их пишут esmcp и esundo (DECISIONS,
// п. 42): до COMMIT, со ссылкой на транзакцию.
type liveGateway struct {
	t    *testing.T
	name string
	path string
	key  ed25519.PrivateKey
	n    int
}

func newLiveGateway(t *testing.T, name string) *liveGateway {
	_, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return &liveGateway{t: t, name: name, path: filepath.Join(t.TempDir(), name+"-receipts.jsonl"), key: key}
}

// liveReceipts — раздел receipts входа над файлами шлюзов gws.
func liveReceipts(gws ...*liveGateway) *ReceiptsConfig {
	r := &ReceiptsConfig{}
	for _, g := range gws {
		r.Files = append(r.Files, g.path)
		r.GatewayKeys = append(r.GatewayKeys, hex.EncodeToString(g.key.Public().(ed25519.PublicKey)))
	}
	return r
}

// server — настройки MCP-сервера с квитанциями этого шлюза.
func (g *liveGateway) server(c mcpserver.Config) mcpserver.Config {
	c.ReceiptsPath, c.Key, c.Gateway, c.PGSource = g.path, g.key, g.name, "postgres"
	return c
}

func (g *liveGateway) append(d gateway.Draft) {
	g.t.Helper()
	if _, err := gateway.Append(g.path, g.key, g.name, d); err != nil {
		g.t.Fatal(err)
	}
}

// intent — намерение нового действия о транзакции, открытой на c: номер
// транзакции — из неё, как его берёт esmcp. Отдаёт xid и номер действия.
func (g *liveGateway) intent(c *pgwire.Conn) (uint32, string) {
	g.t.Helper()
	// Как esmcp: номер (32 бита и с эпохой) и запуск базы — в намерении.
	row, ok, err := c.QueryRow("SELECT pg_current_xact_id()::xid::text, pg_current_xact_id()::text, " + pgundo.StartedSQL)
	if err != nil || !ok || row[0] == nil || row[1] == nil || row[2] == nil {
		g.t.Fatalf("the transaction id: %v", err)
	}
	var xid uint32
	fmt.Sscan(*row[0], &xid)
	g.n++
	id := fmt.Sprintf("%s-%d", g.name, g.n)
	g.append(gateway.Draft{Action: id, Step: alert.StepIntent, Refs: []gateway.Ref{{Source: "postgres", Subject: *row[0]}},
		Body: json.RawMessage(fmt.Sprintf(`{"agent":"live-bot","tool":"execute","reason":"test","xid8":%q,"db_started":%q}`, *row[1], *row[2]))})
	return xid, id
}

// act — транзакция sql соединением c через шлюз: BEGIN, sql, намерение,
// COMMIT. Отдаёт её xid.
func (g *liveGateway) act(c *pgwire.Conn, sql string) uint32 {
	g.t.Helper()
	if _, err := c.Query("BEGIN; " + sql); err != nil {
		c.Query("ROLLBACK")
		g.t.Fatalf("%s: %v", sql, err)
	}
	xid, _ := g.intent(c)
	if _, err := c.Query("COMMIT"); err != nil {
		g.t.Fatalf("COMMIT of %s: %v", sql, err)
	}
	return xid
}

// outcome — квитанция исхода действия id с телом body.
func (g *liveGateway) outcome(id, body string) {
	g.t.Helper()
	g.append(gateway.Draft{Action: id, Step: alert.StepOutcome, Body: json.RawMessage(body)})
}

// undo — намерение отката транзакции undoes, как его пишет esundo.
func (g *liveGateway) undo(undoes uint32) pgundo.IntentFunc {
	return func(xid, xid8, started, timeline string) error {
		g.n++
		_, err := gateway.Append(g.path, g.key, g.name, gateway.Draft{Action: fmt.Sprintf("undo-%d-%d", undoes, g.n), Step: alert.StepUndo,
			Refs: []gateway.Ref{{Source: "postgres", Subject: xid}}, Body: json.RawMessage(fmt.Sprintf(`{"agent":"test","tool":"esundo","undoes_xid":"%d","xid8":%q,"db_started":%q,"db_timeline":%q}`, undoes, xid8, started, timeline))})
		return err
	}
}

// outcomes — тела квитанций исхода из файла шлюза по порядку, начиная со
// строки from (с нуля).
func (g *liveGateway) outcomes(from int) []map[string]any {
	g.t.Helper()
	data, _ := os.ReadFile(g.path)
	var out []map[string]any
	for i, line := range bytes.Split(bytes.TrimSpace(data), []byte("\n")) {
		r, err := gateway.ParseReceipt(line)
		if i < from || err != nil || r.Step != alert.StepOutcome {
			continue
		}
		var m map[string]any
		json.Unmarshal(r.Body, &m)
		out = append(out, m)
	}
	return out
}

// lines — сколько строк в файле квитанций.
func (g *liveGateway) lines() int {
	data, _ := os.ReadFile(g.path)
	return bytes.Count(data, []byte("\n"))
}
