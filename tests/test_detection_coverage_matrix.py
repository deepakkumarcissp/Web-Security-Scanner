import json
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
MATRIX_PATH = ROOT / "tests" / "fixtures" / "detection_coverage_matrix.json"


def test_detection_coverage_matrix_has_unique_ids_and_supported_statuses():
    matrix = json.loads(MATRIX_PATH.read_text(encoding="utf-8"))
    categories = matrix["categories"]
    assert categories
    ids = [item["id"] for item in categories]
    assert len(ids) == len(set(ids))
    allowed_statuses = {"validated", "implemented", "unverified", "planned"}
    allowed_profiles = {"quick", "standard", "deep", "active", "all"}

    for item in categories:
        assert item["status"] in allowed_statuses, item["id"]
        assert item["name"].strip()
        assert item["next_action"].strip()
        assert isinstance(item["evidence"], list)
        assert isinstance(item["known_gaps"], list)
        assert item["profiles"]
        assert set(item["profiles"]) <= allowed_profiles
        if item["status"] in {"validated", "implemented"}:
            assert item["evidence"], f"Implemented category needs evidence: {item['id']}"


def test_validated_categories_reference_existing_test_or_fixture_evidence():
    matrix = json.loads(MATRIX_PATH.read_text(encoding="utf-8"))
    for item in matrix["categories"]:
        if item["status"] != "validated":
            continue
        for evidence in item["evidence"]:
            assert (ROOT / evidence).is_file(), (item["id"], evidence)


def test_coverage_document_warns_against_unjustified_overall_claims():
    doc = (ROOT / "DETECTION_COVERAGE.md").read_text(encoding="utf-8")
    matrix = json.loads(MATRIX_PATH.read_text(encoding="utf-8"))
    assert "Do not combine unrelated categories into a single headline coverage percentage." in doc
    assert "not comprehensive vulnerability coverage estimates" in doc
    assert matrix["coverage_policy"]["unmatched_findings_policy"].startswith(
        "Unmatched findings remain for human triage"
    )
