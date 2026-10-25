import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
import app


def test_sensitive_file_path_requires_successful_response_and_uses_metadata_only():
    headers = {"content-type": "application/octet-stream", "content-length": "37"}
    signal = app.exposed_file_observation(
        "http://127.0.0.1:12345/backup.zip", 200, headers
    )
    assert signal is not None
    assert signal["title"] == "Potentially exposed backup or configuration artifact"
    assert signal["severity"] == "Low"
    assert signal["confidence"] == "Low"
    assert "path=/backup.zip" in signal["evidence"]
    assert "content-type=application/octet-stream" in signal["evidence"]
    assert "File contents were not included" in signal["evidence"]
    assert "does not confirm that secrets are present" in signal["remediation"]

    assert app.exposed_file_observation(
        "http://127.0.0.1:12345/backup.zip", 404, headers
    ) is None


def test_example_templates_and_ordinary_downloads_are_not_flagged():
    headers = {"content-type": "text/plain", "content-length": "20"}
    benign_urls = [
        "http://127.0.0.1:12345/.env.example",
        "http://127.0.0.1:12345/downloads/product.zip",
        "http://127.0.0.1:12345/robots.txt",
        "http://127.0.0.1:12345/.well-known/security.txt",
    ]
    for url in benign_urls:
        assert app.exposed_file_observation(url, 200, headers) is None


def test_repository_metadata_and_private_key_names_are_cautious_observations():
    headers = {"content-type": "text/plain", "content-length": "100"}
    for path in ("/.git/config", "/app/.git/config", "/id_rsa", "/app/.env.production", "/db.sql"):
        signal = app.exposed_file_observation(
            f"http://127.0.0.1:12345{path}", 200, headers
        )
        assert signal is not None, path
        assert signal["severity"] == "Low"
        assert signal["confidence"] == "Low"
        assert "File contents were not included" in signal["evidence"]
