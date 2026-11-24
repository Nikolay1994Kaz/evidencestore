#!/usr/bin/env python3
"""mcp_call.py — один вызов инструмента MCP-сервера esmcp, как его сделал бы агент.

    mcp_call.py ESMCP CONFIG TOOL '{"sql": "..."}'

Запускает сервер подпроцессом и говорит с ним по stdio по ревизии 2026-07-28:
server/discover, затем tools/call с версией протокола в _meta. Печатает текст
результата; код выхода 1 — инструмент ответил ошибкой (isError), 2 — протокол.
"""
import json
import subprocess
import sys

VERSION = "2026-07-28"
META = {"io.modelcontextprotocol/protocolVersion": VERSION,
        "io.modelcontextprotocol/clientInfo": {"name": "pg-undo-demo-agent", "version": "0"},
        "io.modelcontextprotocol/clientCapabilities": {}}


def main():
    binary, config, tool, args = sys.argv[1:5]
    reqs = [{"jsonrpc": "2.0", "id": "d", "method": "server/discover", "params": {"_meta": META}},
            {"jsonrpc": "2.0", "id": "c", "method": "tools/call", "params": {"name": tool, "arguments": json.loads(args), "_meta": META}}]
    p = subprocess.run([binary, "-config", config], input="".join(json.dumps(r) + "\n" for r in reqs),
                       capture_output=True, text=True)
    answers = {}
    for line in p.stdout.splitlines():
        m = json.loads(line)  # сервер не пишет в stdout ничего, кроме сообщений
        answers[m.get("id")] = m
    d, c = answers.get("d", {}).get("result"), answers.get("c", {})
    if not d or VERSION not in d.get("supportedVersions", []) or d.get("resultType") != "complete":
        print(f"mcp_call: server/discover: {answers.get('d')} {p.stderr}", file=sys.stderr)
        sys.exit(2)
    if "result" not in c:
        print(f"mcp_call: tools/call: {c} {p.stderr}", file=sys.stderr)
        sys.exit(2)
    print(c["result"]["content"][0]["text"])
    sys.exit(1 if c["result"].get("isError") else 0)


if __name__ == "__main__":
    main()
