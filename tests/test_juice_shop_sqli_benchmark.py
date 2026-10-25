import importlib.util
from pathlib import Path
from unittest.mock import patch


ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "benchmark_juice_shop_sqli.py"
spec = importlib.util.spec_from_file_location("benchmark_juice_shop_sqli", SCRIPT)
benchmark = importlib.util.module_from_spec(spec)
spec.loader.exec_module(benchmark)


def test_benchmark_rejects_non_loopback_targets():
    for target in (
        "https://127.0.0.1:1003",
        "http://example.com",
        "http://127.0.0.1:1003/rest/user/login",
        "http://user:pass@127.0.0.1:1003",
    ):
        try:
            benchmark.validate_base_url(target)
        except ValueError:
            pass
        else:
            raise AssertionError(f"Target should have been rejected: {target}")


def test_benchmark_marks_expected_positive_only_when_control_and_test_match():
    responses = iter([
        (401, "Invalid email or password."),
        (200, '{"authentication":{"token":"test-token"}}'),
    ])
    with patch.object(benchmark, "post_json", side_effect=lambda *args, **kwargs: next(responses)):
        result = benchmark.run_benchmark("http://127.0.0.1:1003")
    assert result["expected_positive_pass"] is True
    assert result["control"]["rejected_as_invalid_credentials"] is True
    assert result["test"]["authentication_response_observed"] is True
    assert "test-token" not in str(result)
    assert result["secrets_suppressed"] is True


def test_benchmark_does_not_count_http_error_alone_as_positive():
    responses = iter([
        (401, "Invalid email or password."),
        (500, "Internal Server Error"),
    ])
    with patch.object(benchmark, "post_json", side_effect=lambda *args, **kwargs: next(responses)):
        result = benchmark.run_benchmark("http://127.0.0.1:1003")
    assert result["expected_positive_pass"] is False
