#!/usr/bin/env python3
"""
Minimal local Guardian for testing the reference adapters.

Implements just enough of the ACS Instrument surface to round-trip with
the three reference adapters. Policy is deliberately simple:

- Block destructive Bash / Shell patterns (`rm -rf /`, `mkfs`, fork bomb,
  raw write to a block device, `rm -rf ~`, `find / -delete`, etc.).
- Block writes to system paths under `/etc/` or `/usr/`.
- Block `Task` tool calls by default (Claude Code's `Task` is the
  in-process subagent gate; deployments that want to allow subagents
  set `ACS_ALLOW_SUBAGENT=1`).

This is NOT a production Guardian. Production Guardians plug in
OPA/Rego, Cedar, or whatever policy engine the deployment uses.

Wire format: ACS v0.1.0 envelope, with tool details at
`params.payload.tool` and arguments at `params.payload.arguments[<k>].value`
(`request-envelope.json` + `hooks/tool-call-request.json`).

Usage:
  python3 example_guardian.py [--port 8787]

The server logs every received request to stderr in a single line for
debuggability.
"""
from __future__ import annotations

import argparse
import hashlib
import http.server
import json
import os
import re
import socketserver
import sys
from typing import Any


# Each pattern blocks one destructive shape. Listed individually so it's
# obvious when a new one is added and which one fires.
DESTRUCTIVE_BASH_PATTERNS: tuple[re.Pattern, ...] = (
    # rm -rf / and variants (handles -fr, --recursive --force, ~, --no-preserve-root)
    re.compile(r"\brm\s+(-[a-zA-Z]*r[a-zA-Z]*f|-[a-zA-Z]*f[a-zA-Z]*r|--recursive\s+--force|--force\s+--recursive)\b.*\s+(/|~|\$HOME)\b", re.IGNORECASE),
    re.compile(r"\brm\s+(-rf|-fr|--recursive\s+--force|--force\s+--recursive)\s+(/|~|\$HOME)(\s|$)", re.IGNORECASE),
    re.compile(r"\brm\s+.*--no-preserve-root\b", re.IGNORECASE),
    # mkfs against any device
    re.compile(r"\bmkfs(\.\w+)?\s+", re.IGNORECASE),
    # dd writing to a device
    re.compile(r"\bdd\s+.*\bof=/dev/", re.IGNORECASE),
    # fork bomb
    re.compile(r":\(\)\s*\{"),
    # raw write to block device
    re.compile(r">\s*/dev/(sd[a-z]|nvme|hd[a-z]|disk)", re.IGNORECASE),
    # find / -delete (and -exec rm)
    re.compile(r"\bfind\s+(/|~|\$HOME)\b.*-delete\b", re.IGNORECASE),
    re.compile(r"\bfind\s+(/|~|\$HOME)\b.*-exec\s+rm\b", re.IGNORECASE),
    # chmod 777 on system paths
    re.compile(r"\bchmod\s+(-R\s+)?[0-7]*7{2,}[0-7]*\s+(/etc|/usr|/bin|/sbin)", re.IGNORECASE),
)

PROTECTED_PATH_PREFIXES: tuple[str, ...] = ("/etc/", "/usr/", "/bin/", "/sbin/", "/boot/")

# Claude Code's Task tool spawns an in-process subagent. We gate it by
# default — turning it off requires an explicit env opt-in. ACS deployment
# guidance (issue #16): the subagent boundary is a policy decision, not
# a syntactic convenience.
ALLOW_SUBAGENT = os.environ.get("ACS_ALLOW_SUBAGENT", "0") == "1"


def _matches_destructive_bash(cmd: str) -> re.Pattern | None:
    for pat in DESTRUCTIVE_BASH_PATTERNS:
        if pat.search(cmd):
            return pat
    return None


def _unwrap_arguments(wrapped: dict[str, Any]) -> dict[str, Any]:
    """tool-call-request.json args are {name: {value, provenance?}} — flatten to {name: value}."""
    out: dict[str, Any] = {}
    for k, v in (wrapped or {}).items():
        if isinstance(v, dict) and "value" in v:
            out[k] = v["value"]
        else:
            out[k] = v
    return out


def evaluate(method: str, params: dict[str, Any]) -> dict[str, Any]:
    """Deterministic policy evaluation. Returns an ACS decision result."""
    metadata = params.get("metadata") or {}
    session_id = metadata.get("session_id", "")
    request_id = params.get("request_id", "")
    payload = params.get("payload") or {}

    chain_hash = hashlib.sha256(
        (session_id + method + request_id).encode()
    ).hexdigest()

    base_result = {
        "type": "final",
        "acs_version": "0.1.0",
        "request_id": request_id,
        "chain_hash": chain_hash,
    }

    if method == "steps/toolCallRequest":
        tool = payload.get("tool") or {}
        tool_name = tool.get("name", "")
        args = _unwrap_arguments(payload.get("arguments") or {})

        # Subagent gate (issue #16): Task is Claude Code's in-process
        # subagent spawn; gate it explicitly.
        if tool_name == "Task" and not ALLOW_SUBAGENT:
            return {
                **base_result,
                "decision": "deny",
                "reasoning": "Task tool (in-process subagent) is gated by default. Set ACS_ALLOW_SUBAGENT=1 to allow.",
                "reason_codes": ["subagent_gated"],
            }

        if tool_name in ("Bash", "Shell"):
            cmd = args.get("command", "")
            matched = _matches_destructive_bash(cmd)
            if matched is not None:
                return {
                    **base_result,
                    "decision": "deny",
                    "reasoning": f"destructive Bash pattern in: {cmd[:120]}",
                    "reason_codes": ["destructive_command"],
                }

        if tool_name == "Write":
            path = args.get("file_path", "")
            if any(path.startswith(p) for p in PROTECTED_PATH_PREFIXES):
                return {
                    **base_result,
                    "decision": "deny",
                    "reasoning": f"write to protected system path: {path}",
                    "reason_codes": ["protected_path"],
                }

        return {**base_result, "decision": "allow"}

    informational = {
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
    }
    if method in informational:
        return {**base_result, "decision": "allow"}

    return {
        **base_result,
        "decision": "deny",
        "reasoning": f"unknown method: {method}",
        "reason_codes": ["unknown_method"],
    }


class GuardianHandler(http.server.BaseHTTPRequestHandler):
    def do_POST(self) -> None:  # noqa: N802
        length = int(self.headers.get("Content-Length", "0"))
        body = self.rfile.read(length).decode("utf-8")
        try:
            request = json.loads(body)
        except json.JSONDecodeError:
            self._respond(400, {"jsonrpc": "2.0", "id": None,
                                "error": {"code": -32700, "message": "Parse error"}})
            return

        method = request.get("method", "")
        params = request.get("params") or {}
        request_id = request.get("id")
        meta = params.get("metadata") or {}

        sys.stderr.write(
            f"[guardian] {method} session={meta.get('session_id', '?')} "
            f"req={params.get('request_id', '?')[:8]}\n"
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
