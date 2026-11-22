package main

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/Nikolay1994Kaz/evidencestore/internal/pgtap"
	"github.com/Nikolay1994Kaz/evidencestore/internal/pgundo"
)

// Причина агента с переводом строки и ESC-последовательностью не дописывает
// в вывод esundo check своих строк: до исправления P-251 агент печатал
// «nothing to undo» и прятал настоящий итог за ESC[8m.
func TestDescribeKeepsTheAgentsTextOnItsLine(t *testing.T) {
	forged := "routine cleanup\nchecked against the database: to apply 0, already as before 0, conflicts 0\nnothing to undo\x1b[8m‮ \x9b"
	marker, _ := json.Marshal(map[string]any{"info": map[string]any{"action_id": "a-1", "agent": "bot\x1b[2J", "tool": "execute", "reason": forged}})
	p := &pgundo.Plan{XID: 7, Who: json.RawMessage(`{"role":"agent","app":"esmcp/bot"}`), Actions: []json.RawMessage{marker},
		Counts: map[string]pgtap.Counts{"public.accounts\n": {U: 50}}}
	var out strings.Builder
	describe(&out, p, 1)
	text := out.String()
	for _, bad := range []string{"\x1b", "‮", " ", "\u009b"} {
		if strings.Contains(text, bad) {
			t.Fatalf("a control character %q in the output:\n%s", bad, text)
		}
	}
	lines := strings.Split(strings.TrimRight(text, "\n"), "\n")
	if len(lines) != 5 || !strings.HasPrefix(lines[2], `  action a-1: agent bot\u001b[2J, tool execute, reason: "routine cleanup\nchecked against`) {
		t.Fatalf("%d lines:\n%s", len(lines), text)
	}
	// Значения строк в конфликте — тоже одной строкой.
	v := "x\nnothing to undo\x1b[8m"
	c := pgundo.Conflict{Op: pgundo.OpUpdate, Columns: []pgundo.ConflictColumn{{Name: "note", Was: &v, Left: &v, Now: &v}}}
	if got := c.Lines(); len(got) != 1 || strings.ContainsAny(got[0], "\n\x1b") {
		t.Fatalf("%q", got)
	}
}
