#!/usr/bin/env python3
"""mcp_session.py — сеанс агента с MCP-сервером esmcp: один процесс сервера,
много вызовов подряд (как у настоящего клиента MCP; mcp_call.py соседнего
опыта запускает сервер заново на каждый вызов, и пулеру тогда нечего делить).

    from mcp_session import Session
    s = Session(esmcp, config); ok, text = s.call("execute", {"sql": "..."}); s.close()

Из оболочки: строки «ИНСТРУМЕНТ JSON» со стандартного ввода, на каждую —
строка «ok ТЕКСТ» или «err ТЕКСТ».
"""
import json
import subprocess
import sys

VERSION = "2026-07-28"
META = {"io.modelcontextprotocol/protocolVersion": VERSION,
        "io.modelcontextprotocol/clientInfo": {"name": "pg-ha-stand", "version": "0"},
        "io.modelcontextprotocol/clientCapabilities": {}}


class Session:
    def __init__(self, binary, config, log=None):
        self.log = open(log, "a") if log else subprocess.DEVNULL
        self.p = subprocess.Popen([binary, "-config", config], stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                  stderr=self.log, text=True, bufsize=1)
        self.n = 0
        d = self._ask("server/discover", {"_meta": META})
        if VERSION not in d.get("result", {}).get("supportedVersions", []):
            raise RuntimeError(f"server/discover: {d}")

    def _ask(self, method, params):
        self.n += 1
        self.p.stdin.write(json.dumps({"jsonrpc": "2.0", "id": self.n, "method": method, "params": params}) + "\n")
        self.p.stdin.flush()
        line = self.p.stdout.readline()
        if not line:
            raise RuntimeError("the server closed its output")
        return json.loads(line)

    def call(self, tool, args):
        """(ok, текст ответа инструмента)."""
        m = self._ask("tools/call", {"name": tool, "arguments": args, "_meta": META})
        if "result" not in m:
            raise RuntimeError(f"tools/call: {m}")
        return not m["result"].get("isError"), m["result"]["content"][0]["text"]

    def close(self):
        self.p.stdin.close()
        self.p.wait(timeout=30)
        if self.log is not subprocess.DEVNULL:
            self.log.close()


if __name__ == "__main__":
    s = Session(sys.argv[1], sys.argv[2], sys.argv[3] if len(sys.argv) > 3 else None)
    for line in sys.stdin:
        tool, _, args = line.strip().partition(" ")
        if tool:
            ok, text = s.call(tool, json.loads(args))
            print("ok" if ok else "err", text, flush=True)
    s.close()
