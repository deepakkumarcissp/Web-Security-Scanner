#!/usr/bin/env python3
"""Deliberately vulnerable HTTP fixture for local DKCISSP scanner testing only.

Binds exclusively to 127.0.0.1. Do not expose this service to a network.
"""
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from html import escape
from urllib.parse import parse_qs, urlparse
import argparse


class VulnerableFixtureHandler(BaseHTTPRequestHandler):
    server_version = "DKCISSPBenchmarkFixture/1.0"

    def do_GET(self):
        parsed = urlparse(self.path)
        params = parse_qs(parsed.query, keep_blank_values=True)
        if parsed.path == "/":
            body = ("<!doctype html><html><head><title>Local benchmark</title></head><body>"
                    "<h1>DKCISSP local-only vulnerable fixture</h1>"
                    "<a href='/search?q=hello'>Reflected XSS case</a>"
                    "<a href='/product?id=1'>SQL injection case</a></body></html>")
            self._send(200, body)
            return
        if parsed.path == "/search":
            query = params.get("q", [""])[0]
            # Intentionally unsafe: raw input is reflected into HTML for XSS detection tests.
            self._send(200, "<!doctype html><html><head><title>Search</title></head><body>Results for: " + query + "</body></html>")
            return
        if parsed.path == "/product":
            product_id = params.get("id", ["1"])[0]
            # Simulate a classic SQL error response for quote-containing input.
            # This is a deterministic detector fixture, not a real database or data store.
            if "'" in product_id or '"' in product_id:
                self._send(500, "<!doctype html><html><title>Database error</title><body>SQL syntax error near '" + escape(product_id) + "'</body></html>")
                return
            if " or " in product_id.lower() or "%27" in product_id.lower():
                self._send(200, "<!doctype html><html><title>Product</title><body>Product 1; Product 2; Product 3</body></html>")
                return
            self._send(200, "<!doctype html><html><title>Product</title><body>Product " + escape(product_id) + "</body></html>")
            return
        self._send(404, "<!doctype html><html><title>Not found</title><body>Not found</body></html>")

    def _send(self, status, body):
        payload = body.encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(payload)))
        self.send_header("Connection", "close")
        self.end_headers()
        self.wfile.write(payload)

    def log_message(self, fmt, *args):
        # Keep test output quiet; do not log query payloads.
        return


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--port", type=int, default=18080)
    args = parser.parse_args()
    if not 1 <= args.port <= 65535:
        parser.error("port must be between 1 and 65535")
    server = ThreadingHTTPServer(("127.0.0.1", args.port), VulnerableFixtureHandler)
    print(f"Local-only benchmark fixture listening at http://127.0.0.1:{args.port}/", flush=True)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()


if __name__ == "__main__":
    main()
