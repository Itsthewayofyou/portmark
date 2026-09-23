"""A fake MCP server for the PR 2 tests: one protocol era per mode, plus deliberate misbehaviour.

Run as `python mcp_fake_server.py <mode>`; it speaks newline-delimited JSON-RPC on stdin/stdout, exactly as
the stdio binding prescribes. Every mode is a case some real server could put on the wire.
"""

import json
import os
import sys
import time

MODERN = "2026-07-28"
LEGACY = "2025-06-18"

TOOLS = {
    "read_file": {
        "name": "read_file",
        "description": "Read a file",
        "inputSchema": {"type": "object", "properties": {"path": {"type": "string"}}, "required": ["path"]},
    },
    "write_file": {
        "name": "write_file",
        "description": "Write a file",
        "inputSchema": {"type": "object", "properties": {"path": {"type": "string"}, "text": {"type": "string"}}},
    },
}


def send(message):
    sys.stdout.write(json.dumps(message) + "\n")
    sys.stdout.flush()


def result(request_id, body, modern=True):
    payload = dict(body)
    if modern:
        payload["resultType"] = "complete"
    send({"jsonrpc": "2.0", "id": request_id, "result": payload})


def error(request_id, code, message, data=None):
    body = {"code": code, "message": message}
    if data is not None:
        body["data"] = data
    send({"jsonrpc": "2.0", "id": request_id, "error": body})


def tool_list(mode):
    definitions = [dict(definition) for definition in TOOLS.values()]
    if mode == "drift":
        definitions[0] = {**definitions[0], "description": "Read a file (now with extra powers)"}
    if mode == "gone":
        definitions = [definition for definition in definitions if definition["name"] != "read_file"]
    return definitions


def main():
    mode = sys.argv[1] if len(sys.argv) > 1 else "modern"
    modern = mode not in ("legacy", "legacy_new")
    marker = os.environ.get("FAKE_MCP_MARKER_FILE")
    if marker:  # proves which environment variables reached the server process
        with open(marker, "w", encoding="utf-8") as handle:
            json.dump({key: os.environ.get(key, "") for key in ("FAKE_MCP_SECRET", "PORTMARK_MCP_PIN", "HOME")}, handle)
    while True:
        # readline(), not `for line in sys.stdin`: the iterator reads ahead, so a server that answers one
        # request at a time would wait for input that the client is waiting for the answer to.
        line = sys.stdin.readline()
        if not line:
            return
        line = line.strip()
        if not line:
            continue
        request = json.loads(line)
        method = request.get("method")
        request_id = request.get("id")
        if method is None or request_id is None:
            continue  # a notification: notifications/initialized
        if mode == "hang":
            time.sleep(3600)
        if mode == "server_request" and method == "tools/call":
            # Forbidden by the stdio binding: a server request written to stdout.
            send({"jsonrpc": "2.0", "id": 9001, "method": "elicitation/create", "params": {}})
            continue
        if mode == "big" and method == "tools/list":
            sys.stdout.write(json.dumps({"jsonrpc": "2.0", "id": request_id, "result": {"x": "y" * (2 << 20)}}) + "\n")
            sys.stdout.flush()
            continue
        if mode == "flood" and method == "tools/list":
            # Bytes forever, with no newline: a frame that never ends.
            while True:
                sys.stdout.write("x" * 65536)
                sys.stdout.flush()
        if mode == "wrong_id" and method == "tools/list":
            send({"jsonrpc": "2.0", "id": (request_id or 0) + 100, "result": {"resultType": "complete", "tools": []}})
            continue
        if mode == "not_json" and method == "tools/list":
            sys.stdout.write("this is not json\n")
            sys.stdout.flush()
            continue
        if method == "server/discover":
            if mode in ("legacy", "legacy_new"):
                error(request_id, -32601, "Method not found")  # a legacy server's answer to an unknown method
            elif mode == "unsupported":
                error(request_id, -32022, "Unsupported protocol version", {"supported": [LEGACY], "requested": MODERN})
            else:
                result(request_id, {"supportedVersions": [MODERN], "capabilities": {"tools": {}}})
            continue
        if method == "initialize":
            if mode == "modern":
                error(request_id, -32601, "Method not found")
                continue
            if mode == "unsupported":
                # This server advertised 2025-06-18 in its UnsupportedProtocolVersionError, and accepts only
                # that revision: a client that asks for another one is asking for something it was told about.
                asked = (request.get("params") or {}).get("protocolVersion")
                if asked != LEGACY:
                    error(request_id, -32602, f"this server speaks {LEGACY}, not {asked}")
                    continue
            if mode == "legacy_new":
                asked = (request.get("params") or {}).get("protocolVersion")
                if asked != "2025-11-25":
                    error(request_id, -32602, f"this server speaks 2025-11-25, not {asked}")
                    continue
                send({"jsonrpc": "2.0", "id": request_id, "result": {
                    "protocolVersion": "2025-11-25", "capabilities": {"tools": {}},
                    "serverInfo": {"name": "fake", "version": "1"},
                }})
                continue
            send({"jsonrpc": "2.0", "id": request_id, "result": {
                "protocolVersion": LEGACY, "capabilities": {"tools": {}},
                "serverInfo": {"name": "fake", "version": "1"},
            }})  # a legacy result has no resultType
            continue
        if method == "tools/list":
            result(request_id, {"tools": tool_list(mode)}, modern=modern and mode != "unsupported")
            continue
        if method == "tools/call":
            name = (request.get("params") or {}).get("name")
            arguments = (request.get("params") or {}).get("arguments") or {}
            if mode == "input_required":
                send({"jsonrpc": "2.0", "id": request_id, "result": {
                    "resultType": "input_required",
                    "inputRequests": {"who": {"method": "elicitation/create", "params": {}}},
                }})
                continue
            if mode == "tool_error":
                result(request_id, {"content": [{"type": "text", "text": "no such file"}], "isError": True}, modern=modern)
                continue
            if mode == "blocks":
                result(request_id, {"content": [
                    {"type": "text", "text": "ok"},
                    {"type": "image", "data": "A" * 4096, "mimeType": "image/png"},
                ], "structuredContent": {"read": True}}, modern=modern)
                continue
            result(request_id, {"content": [{"type": "text", "text": f"{name}:{json.dumps(arguments, sort_keys=True)}"}]}, modern=modern)
            continue
        error(request_id, -32601, f"Method not found: {method}")


if __name__ == "__main__":
    main()
