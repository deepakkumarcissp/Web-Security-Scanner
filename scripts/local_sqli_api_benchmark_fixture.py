#!/usr/bin/env python3
"""Intentionally vulnerable, loopback-only SQLite JSON API for DKCISSP SQLi benchmarks.

Never bind this fixture to a non-loopback interface or expose it to an untrusted network.
The vulnerable query is deliberate and must not be copied into production applications.
"""
from __future__ import annotations

import argparse
import json
import sqlite3
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path


OPENAPI = {
    "openapi": "3.0.0",
    "info": {"title": "DKCISSP Local SQLi Benchmark", "version": "1.0.0"},
    "servers": [{"url": "http://127.0.0.1:18081"}],
    "paths": {
        "/rest/user/login": {
            "post": {
                "summary": "Intentionally vulnerable local training login",
                "requestBody": {
                    "required": True,
                    "content": {
                        "application/json": {
                            "schema": {
                                "type": "object",
                                "properties": {
                                    "email": {"type": "string"},
                                    "password": {"type": "string"},
                                },
                                "required": ["email", "password"],
                            }
                        }
                    },
                },
                "responses": {
                    "200": {"description": "Authentication response"},
                    "401": {"description": "Invalid credentials"},
                },
            }
        }
    },
}


def init_database(path: str) -> None:
    with sqlite3.connect(path) as conn:
        conn.execute("CREATE TABLE IF NOT EXISTS users (email TEXT NOT NULL, password TEXT NOT NULL)")
        conn.execute("DELETE FROM users")
        conn.execute("INSERT INTO users(email,password) VALUES(?,?)",
                     ("benchmark-admin@local.test", "benchmark-password"))
        conn.commit()


def handler_for(db_path: str):
    class Handler(BaseHTTPRequestHandler):
        server_version = "DKCISSP-SQLi-Benchmark/1.0"

        def _send(self, status: int, payload: dict) -> None:
            raw = json.dumps(payload).encode("utf-8")
            self.send_response(status)
            self.send_header("Content-Type", "application/json; charset=utf-8")
            self.send_header("Content-Length", str(len(raw)))
            self.send_header("Cache-Control", "no-store")
            self.end_headers()
            self.wfile.write(raw)

        def log_message(self, format, *args):
            return

        def do_GET(self):
            if self.path == "/openapi.json":
                self._send(200, OPENAPI)
            elif self.path == "/health":
                self._send(200, {"status": "ok", "fixture": "intentionally-vulnerable"})
            else:
                self._send(404, {"error": "not found"})

        def do_POST(self):
            if self.path != "/rest/user/login":
                self._send(404, {"error": "not found"})
                return
            try:
                length = int(self.headers.get("Content-Length", "0"))
                if length < 1 or length > 8192:
                    self._send(400, {"error": "invalid request size"})
                    return
                payload = json.loads(self.rfile.read(length).decode("utf-8"))
                email = str(payload.get("email", ""))[:512]
                password = str(payload.get("password", ""))[:512]
            except (ValueError, UnicodeDecodeError, AttributeError):
                self._send(400, {"error": "invalid JSON"})
                return

            # INTENTIONALLY VULNERABLE: string interpolation into SQL is the benchmark signal.
            # Do not use this pattern outside this isolated training fixture.
            query = "SELECT email FROM users WHERE email = '%s' AND password = '%s'" % (email, password)
            try:
                with sqlite3.connect(db_path, timeout=1) as conn:
                    row = conn.execute(query).fetchone()
            except sqlite3.Error:
                self._send(500, {"error": "database query failed"})
                return
            if row:
                self._send(200, {"authentication": {"token": "local-benchmark-token"},
                                 "user": {"email": row[0]}})
            else:
                self._send(401, {"error": "Invalid email or password"})

    return Handler


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=18081)
    parser.add_argument("--database", default="/tmp/dkcissp-sqli-benchmark.sqlite3")
    args = parser.parse_args()
    if args.host not in ("127.0.0.1", "::1", "localhost"):
        parser.error("Safety guard: this intentionally vulnerable fixture may bind only to loopback.")
    if not 1024 <= args.port <= 65535:
        parser.error("Port must be between 1024 and 65535.")
    Path(args.database).parent.mkdir(parents=True, exist_ok=True)
    init_database(args.database)
    server = ThreadingHTTPServer((args.host, args.port), handler_for(args.database))
    print(f"Local SQLi benchmark fixture listening on http://{args.host}:{args.port} (loopback only)", flush=True)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()


if __name__ == "__main__":
    main()
