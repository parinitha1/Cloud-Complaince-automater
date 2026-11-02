import json

import pytest

from ccaudit.checks import REGISTRY
from ccaudit.engine import (SnapshotError, evaluate_framework, load_frameworks, load_snapshot,
                            scan, validate_snapshot)
from ccaudit.models import CheckResult, Context, Finding, Status

INDIA = Context(allowed_regions=["ap-south-1", "ap-south-2"])


def test_frameworks_reference_only_real_checks():
    load_frameworks()  # raises on unknown ids


def test_framework_control_ids_unique_and_nonempty():
    for fw in load_frameworks():
        ids = [c["id"] for c in fw["controls"]]
        assert len(ids) == len(set(ids)), fw["id"]
        assert all(c["checks"] for c in fw["controls"])


def test_every_check_is_mapped_by_at_least_one_framework():
    mapped = {cid for fw in load_frameworks() for c in fw["controls"] for cid in c["checks"]}
    assert mapped == set(REGISTRY)


def test_unknown_framework_rejected():
    with pytest.raises(ValueError):
        load_frameworks(["nope"])


def test_framework_filter():
    assert [fw["id"] for fw in load_frameworks(["soc2"])] == ["soc2"]


def test_secure_sample_scores_100(secure):
    _results, fws = scan(secure, INDIA)
    for f in fws:
        assert f.failed == 0, f.framework_id
        assert f.score == 100.0, f.framework_id


def test_insecure_sample_scores_zero_and_fails_many(insecure):
    results, fws = scan(insecure, INDIA)
    assert all(f.score == 0.0 for f in fws)
    failed = {r.check_id for r in results.values() if r.status == Status.FAIL}
    assert {"S3-001", "SG-001", "RDS-001", "IAM-001", "IAM-002", "LOG-001", "RES-001"} <= failed


def test_residency_check_off_without_regions(insecure):
    results, _ = scan(insecure)
    assert results["RES-001"].status == Status.NA


def _result(check_id, status):
    findings = [] if status == Status.NA else [Finding("r", status)]
    return CheckResult(check_id, "t", "low", "d", "r", findings)


def test_control_rollup_rules():
    fw = {"id": "x", "name": "X", "controls": [
        {"id": "C1", "title": "t", "checks": ["A", "B"]},
        {"id": "C2", "title": "t", "checks": ["A", "C"]},
        {"id": "C3", "title": "t", "checks": ["C"]},
    ]}
    results = {"A": _result("A", Status.PASS), "B": _result("B", Status.FAIL), "C": _result("C", Status.NA)}
    res = evaluate_framework(fw, results)
    statuses = {c.control_id: c.status for c in res.controls}
    assert statuses == {"C1": Status.FAIL, "C2": Status.PASS, "C3": Status.NA}
    assert (res.passed, res.failed, res.not_applicable) == (1, 1, 1)
    assert res.score == 50.0


def test_score_none_when_nothing_evaluated():
    fw = {"id": "x", "name": "X", "controls": [{"id": "C", "title": "t", "checks": ["C"]}]}
    assert evaluate_framework(fw, {"C": _result("C", Status.NA)}).score is None


def test_empty_snapshot_is_all_not_applicable():
    results, fws = scan({}, INDIA)
    # only LOG-001 distinguishes "not collected" from "collected but empty": missing means N/A
    assert all(r.status == Status.NA for r in results.values())
    assert all(f.score is None for f in fws)


class TestSnapshotValidation:
    def test_rejects_non_object(self):
        with pytest.raises(SnapshotError):
            validate_snapshot([])

    def test_rejects_wrong_section_type(self):
        with pytest.raises(SnapshotError):
            validate_snapshot({"s3_buckets": {"name": "x"}})

    def test_rejects_bad_iam(self):
        with pytest.raises(SnapshotError):
            validate_snapshot({"iam": []})

    def test_bad_json_file(self, tmp_path):
        p = tmp_path / "s.json"
        p.write_text("{not json")
        with pytest.raises(SnapshotError):
            load_snapshot(p)

    def test_loads_sample(self, tmp_path, secure):
        p = tmp_path / "s.json"
        p.write_text(json.dumps(secure))
        assert load_snapshot(p)["account_id"] == secure["account_id"]
