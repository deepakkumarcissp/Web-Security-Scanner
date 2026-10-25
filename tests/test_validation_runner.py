import importlib.util
from pathlib import Path


SCRIPT = Path(__file__).resolve().parents[1] / "scripts" / "validate_juice_shop.py"
SPEC = importlib.util.spec_from_file_location("validate_juice_shop", SCRIPT)
runner = importlib.util.module_from_spec(SPEC)
assert SPEC.loader is not None
SPEC.loader.exec_module(runner)


def test_validation_passes_when_scan_and_required_nuclei_check_complete():
    passed, failures = runner.assess_validation("completed", {
        "Nuclei": {"status": "completed"},
        "OWASP ZAP passive": {"status": "api_mismatch"},
    })
    assert passed is True
    assert failures == []


def test_validation_fails_if_nuclei_times_out_even_when_scan_completed():
    passed, failures = runner.assess_validation("completed", {
        "Nuclei": {"status": "timeout"},
    })
    assert passed is False
    assert any("Nuclei" in failure for failure in failures)


def test_validation_fails_if_required_nuclei_status_is_missing():
    passed, failures = runner.assess_validation("completed", {})
    assert passed is False
    assert any("missing" in failure for failure in failures)


def test_validation_fails_if_scan_did_not_complete():
    passed, failures = runner.assess_validation("failed", {
        "Nuclei": {"status": "completed"},
    })
    assert passed is False
    assert any("Scanner did not complete" in failure for failure in failures)
