"""Bounded stdio MCP subset, protocol 2025-06-18. No shell or network tools."""
from __future__ import annotations
import argparse
import json
import sys
from .core import MAX_BYTES, canonical, run_suite, verify
from .fixtures import Fixture, suite

PROTOCOL = "2025-06-18"


def tool(name, description, properties=None, required=None):
    return {"name": name, "description": description,
            "inputSchema": {"type": "object", "properties": properties or {},
                            "required": required or [], "additionalProperties": False},
            "annotations": {"destructiveHint": False, "openWorldHint": False}}


class Server:
    def __init__(self, fixture: Fixture | None = None):
        self.fixture = fixture
        self.initialized = False
        self.ready = False
        if fixture:
            self.tools = [
                tool("observe", "Read complete state of the synthetic in-memory fixture."),
                tool("read_record", "Read a synthetic tenant record.",
                     {"tenant": {"type": "string"}, "actor": {"type": "string"}}),
                tool("send_message", "Append to an in-memory sink. Never sends email.",
                     {k: {"type": "string"} for k in ("to", "body", "approval")}),
                tool("hash_artifact", "Hash synthetic text; no filesystem access.", {"text": {"type": "string"}})]
        else:
            self.tools = [
                tool("case_catalog", "List synthetic boundary cases. Not a live-model benchmark."),
                tool("lab_run", "Run synthetic fixtures and return tamper-evident evidence.",
                     {"mode": {"type": "string", "enum": ["guarded", "vulnerable", "deny_all"]}}),
                tool("bundle_verify", "Check integrity; not identity, authority, or certification.",
                     {"bundle": {"type": "object"}, "expected_head": {"type": "string"}}, ["bundle"])]

    @staticmethod
    def error(ident, code, message):
        return {"jsonrpc": "2.0", "id": ident, "error": {"code": code, "message": message}}

    def handle(self, request):
        if not isinstance(request, dict) or request.get("jsonrpc") != "2.0":
            return self.error(None, -32600, "Invalid Request")
        method, params = request.get("method"), request.get("params", {})
        if not isinstance(method, str) or not isinstance(params, dict):
            return self.error(request.get("id"), -32600, "Invalid Request")
        if "id" not in request:
            if method == "notifications/initialized" and self.initialized:
                self.ready = True
            return None
        ident = request["id"]
        if type(ident) not in {str, int}:
            return self.error(None, -32600, "Invalid request ID")
        if method == "initialize":
            if self.initialized:
                return self.error(ident, -32600, "Already initialized")
            if not isinstance(params.get("protocolVersion"), str):
                return self.error(ident, -32602, "protocolVersion is required")
            self.initialized = True
            result = {"protocolVersion": PROTOCOL, "capabilities": {"tools": {"listChanged": False}},
                      "serverInfo": {"name": "boundary-evidence-lab", "version": "0.1.0"}}
        elif method == "ping":
            result = {}
        elif not self.ready:
            return self.error(ident, -32002, "Initialize the session first")
        elif method == "tools/list":
            if params.get("cursor") is not None:
                return self.error(ident, -32602, "Unknown cursor")
            result = {"tools": self.tools}
        elif method == "tools/call":
            name, args = params.get("name"), params.get("arguments", {})
            definition = next((t for t in self.tools if t["name"] == name), None)
            if definition is None:
                return self.error(ident, -32602, "Unknown tool")
            schema = definition["inputSchema"]
            if not isinstance(args, dict) or set(args) - set(schema["properties"]):
                return self.error(ident, -32602, "Unexpected arguments")
            if any(k not in args for k in schema["required"]):
                return self.error(ident, -32602, "Missing arguments")
            for key, value in args.items():
                rule = schema["properties"][key]
                expected = str if rule["type"] == "string" else dict
                if not isinstance(value, expected) or ("enum" in rule and value not in rule["enum"]):
                    return self.error(ident, -32602, "Invalid argument type or value")
            try:
                if self.fixture:
                    payload = self.fixture.call(name, args)
                elif name == "case_catalog":
                    payload = {"cases": [{k: c[k] for k in ("id", "title", "kind")} for c in suite()["cases"]]}
                elif name == "lab_run":
                    mode = args.get("mode", "guarded")
                    payload = run_suite(suite(), lambda c: Fixture(mode, c.get("setup")), target="synthetic:" + mode)
                else:
                    payload = {"integrity_valid": verify(args["bundle"], args.get("expected_head")),
                               "external_head_supplied": "expected_head" in args,
                               "auditor_identity_verified": False}
                result = {"content": [{"type": "text", "text": canonical(payload).decode()}],
                          "structuredContent": payload, "isError": False}
            except Exception:
                result = {"content": [{"type": "text", "text": "Tool execution failed; no security verdict."}], "isError": True}
        else:
            return self.error(ident, -32601, "Method not found")
        return {"jsonrpc": "2.0", "id": ident, "result": result}


def serve(server: Server) -> None:
    while True:
        raw = sys.stdin.buffer.readline(MAX_BYTES + 1)
        if not raw:
            break
        if len(raw) > MAX_BYTES:
            response = server.error(None, -32700, "Message exceeds limit")
            sys.stdout.buffer.write(canonical(response) + b"\n")
            sys.stdout.buffer.flush()
            break
        try:
            request = json.loads(raw)
            response = server.handle(request)
        except (ValueError, UnicodeError, RecursionError):
            response = server.error(None, -32700, "Parse error")
        if response is not None:
            encoded = canonical(response)
            if len(encoded) > MAX_BYTES:
                encoded = canonical(server.error(response.get("id"), -32603, "Response exceeds limit"))
            sys.stdout.buffer.write(encoded + b"\n")
            sys.stdout.buffer.flush()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--fixture", choices=["guarded", "vulnerable", "deny_all"])
    parser.add_argument("--setup", default="{}")
    args = parser.parse_args()
    setup = json.loads(args.setup)
    if not isinstance(setup, dict):
        parser.error("setup must be an object")
    serve(Server(Fixture(args.fixture, setup) if args.fixture else None))


if __name__ == "__main__":
    main()
