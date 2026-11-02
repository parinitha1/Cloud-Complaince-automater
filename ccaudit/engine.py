"""Loads snapshots and frameworks, runs checks and rolls results up to controls."""
from __future__ import annotations

import json
from pathlib import Path

from .checks import REGISTRY
from .models import (CheckResult, Context, ControlResult, FrameworkResult, Status)

FRAMEWORK_DIR = Path(__file__).parent / "frameworks"

LIST_SECTIONS = ("s3_buckets", "security_groups", "cloudtrail", "log_groups",
                 "ebs_volumes", "rds_instances", "kms_keys")


class SnapshotError(ValueError):
    """Raised when a snapshot file is malformed."""


def load_snapshot(path: str | Path) -> dict:
    try:
        data = json.loads(Path(path).read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise SnapshotError(f"{path} is not valid JSON: {exc}") from exc
    return validate_snapshot(data)


def validate_snapshot(data: object) -> dict:
    if not isinstance(data, dict):
        raise SnapshotError("snapshot must be a JSON object")
    for key in LIST_SECTIONS:
        if key in data and data[key] is not None and not isinstance(data[key], list):
            raise SnapshotError(f"'{key}' must be a list")
    if "iam" in data and data["iam"] is not None and not isinstance(data["iam"], dict):
        raise SnapshotError("'iam' must be an object")
    return data


def load_frameworks(only: list[str] | None = None) -> list[dict]:
    frameworks = []
    for p in sorted(FRAMEWORK_DIR.glob("*.json")):
        fw = json.loads(p.read_text(encoding="utf-8"))
        for control in fw["controls"]:
            unknown = [c for c in control["checks"] if c not in REGISTRY]
            if unknown:
                raise ValueError(f'{fw["id"]} {control["id"]} references unknown checks: {unknown}')
        frameworks.append(fw)
    if only:
        ids = {fw["id"] for fw in frameworks}
        bad = [f for f in only if f not in ids]
        if bad:
            raise ValueError(f"unknown framework(s) {bad}; available: {sorted(ids)}")
        frameworks = [fw for fw in frameworks if fw["id"] in only]
    return frameworks


def run_checks(snapshot: dict, ctx: Context | None = None) -> dict[str, CheckResult]:
    ctx = ctx or Context()
    results = {}
    for check_id, (meta, fn) in REGISTRY.items():
        results[check_id] = CheckResult(
            check_id=meta.check_id, title=meta.title, severity=meta.severity,
            description=meta.description, remediation=meta.remediation,
            findings=fn(snapshot, ctx),
        )
    return results


def evaluate_framework(fw: dict, results: dict[str, CheckResult]) -> FrameworkResult:
    controls = []
    for c in fw["controls"]:
        statuses = {cid: results[cid].status for cid in c["checks"]}
        values = set(statuses.values())
        if Status.FAIL in values:
            status = Status.FAIL
        elif Status.PASS in values:
            status = Status.PASS
        else:
            status = Status.NA
        controls.append(ControlResult(c["id"], c["title"], list(c["checks"]), status, statuses))
    return FrameworkResult(fw["id"], fw["name"], fw.get("disclaimer", ""), controls)


def scan(snapshot: dict, ctx: Context | None = None,
         frameworks: list[str] | None = None) -> tuple[dict[str, CheckResult], list[FrameworkResult]]:
    results = run_checks(snapshot, ctx)
    fws = [evaluate_framework(fw, results) for fw in load_frameworks(frameworks)]
    return results, fws
