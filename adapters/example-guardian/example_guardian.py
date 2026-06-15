#!/usr/bin/env python3
"""
Minimal local Guardian for testing the Claude Code adapter.

Implements just enough of the ACS Instrument surface to round-trip with
the adapter. Policy is deliberately simple: deny destructive Bash
commands, allow everything else. Production Guardians plug in OPA/Rego,
Cedar, or whatever policy engine the deployment uses.

Usage:
  python3 example_guardian.py [--port 8787]

The server logs every received request to stderr in a single line so
the round-trip is debuggable.
"""
from __future__ import annotations

import argparse
import hashlib
import http.server
import json
import re
import socketserver
import sys
from typing import Any


DESTRUCTIVE_BASH = re.compile(
    r"\b(rm\s+-rf?\s+/|mkfs|dd\s+if=|:\(\)\{|>\s*/dev/sda)",
    re.IGNORECASE,
)


def evaluate(method: str, params: dict[str, Any]) -> dict[str, Any]:
    """Deterministic policy evaluation. Returns an ACS decision result."""
    session_id = params.get("session_id", "")
    chain_hash = hashlib.sha256(
        (session_id + method + str(params.get("step_id", ""))).encode()
    ).hexdigest()

    if method == "steps/toolCallRequest":
        tool = params.get("tool", {})
        tool_name = tool.get("name", "")
        args = tool.get("arguments", {})

        if tool_name in ("Bash", "Shell"):
            cmd = args.get("command", "")
            if DESTRUCTIVE_BASH.search(cmd):
                return {
                    "decision": "deny",
                    "reasoning": f"destructive Bash pattern in: {cmd[:80]}",
                    "reason_codes": ["destructive_command"],
                    "chain_hash": chain_hash,
                }

        if tool_name == "Write":
            path = args.get("file_path", "")
            if path.startswith("/etc/") or path.startswith("/usr/"):
                return {
                    "decision": "deny",
                    "reasoning": f"write to protected system path: {path}",
                    "reason_codes": ["protected_path"],
                    "chain_hash": chain_hash,
                }

        return {"decision": "allow", "chain_hash": chain_hash}

    if method in (
        "steps/sessionStart",
        "steps/sessionEnd",
        "steps/userMessage",
        "steps/toolCallResult",
        "steps/agentResponse",
        "steps/preCompact",
        "steps/postCompact",
        "steps/subagentStart",
        "steps/subagentStop",
        "steps/knowledgeRetrieval",
        "steps/memoryStore",
        "steps/memoryContextRetrieval",
    ):
        return {"decision": "allow", "chain_hash": chain_hash}

    return {
        "decision": "deny",
        "reasoning": f"unknown method: {method}",
        "chain_hash": chain_hash,
    }


class GuardianHandler(http.server.BaseHTTPRequestHandler):
    def do_POST(self) -> None:  # noqa: N802
        length = int(self.headers.get("Content-Length", "0"))
        body = self.rfile.read(length).decode("utf-8")
        try:
            request = json.loads(body)
        except json.JSONDecodeError:
            self._respond(400, {"jsonrpc": "2.0", "error": {"code": -32700, "message": "Parse error"}})
            return

        method = request.get("method", "")
        params = request.get("params", {})
        request_id = request.get("id")

        sys.stderr.write(
            f"[guardian] {method} session={params.get('session_id', '?')} "
            f"step={params.get('step_id', '?')[:8]}\n"
        )
        sys.stderr.flush()

        result = evaluate(method, params)
        self._respond(200, {"jsonrpc": "2.0", "id": request_id, "result": result})

    def _respond(self, status: int, body: dict[str, Any]) -> None:
        payload = json.dumps(body).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    def log_message(self, fmt: str, *args: Any) -> None:  # silence default logs
        return


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--port", type=int, default=8787)
    parser.add_argument("--host", default="127.0.0.1")
    args = parser.parse_args()

    class ReusableServer(socketserver.TCPServer):
        allow_reuse_address = True

    with ReusableServer((args.host, args.port), GuardianHandler) as httpd:
        sys.stderr.write(f"[guardian] listening on {args.host}:{args.port}\n")
        sys.stderr.flush()
        try:
            httpd.serve_forever()
        except KeyboardInterrupt:
            pass
    return 0


if __name__ == "__main__":
    sys.exit(main())
