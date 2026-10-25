import importlib.util
from pathlib import Path
from threading import Thread
from urllib.request import urlopen
from urllib.error import HTTPError
from http.server import ThreadingHTTPServer


ROOT = Path(__file__).resolve().parents[1]
FIXTURE_PATH = ROOT / "scripts" / "local_vuln_benchmark_fixture.py"
spec = importlib.util.spec_from_file_location("local_vuln_benchmark_fixture", FIXTURE_PATH)
fixture = importlib.util.module_from_spec(spec)
spec.loader.exec_module(fixture)


def run_fixture():
    server = ThreadingHTTPServer(("127.0.0.1", 0), fixture.VulnerableFixtureHandler)
    thread = Thread(target=server.serve_forever, daemon=True)
    thread.start()
    return server, thread, f"http://127.0.0.1:{server.server_port}"


def test_fixture_is_bound_to_loopback_and_homepage_exposes_only_test_routes():
    server, thread, base = run_fixture()
    try:
        assert server.server_address[0] == "127.0.0.1"
        body = urlopen(base + "/", timeout=2).read().decode()
        assert "/search?q=hello" in body
        assert "/product?id=1" in body
        assert "DKCISSP local-only vulnerable fixture" in body
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)


def test_fixture_has_deterministic_reflected_xss_signal():
    server, thread, base = run_fixture()
    try:
        body = urlopen(base + "/search?q=%3Cscript%3Ealert(1)%3C%2Fscript%3E", timeout=2).read().decode()
        assert "<script>alert(1)</script>" in body
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)


def test_fixture_has_deterministic_sql_error_signal():
    server, thread, base = run_fixture()
    try:
        try:
            urlopen(base + "/product?id=1%27", timeout=2)
            assert False, "Expected fixture to return a simulated SQL error"
        except HTTPError as exc:
            body = exc.read().decode()
            assert exc.code == 500
            assert "SQL syntax error" in body
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)


def test_fixture_normal_product_response_is_not_a_sql_error():
    server, thread, base = run_fixture()
    try:
        response = urlopen(base + "/product?id=1", timeout=2)
        assert response.status == 200
        body = response.read().decode()
        assert "Product 1" in body
        assert "SQL syntax error" not in body
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)
