"""Core data models for the compliance scanner."""
from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum


class Status(str, Enum):
    PASS = "PASS"
    FAIL = "FAIL"
    NA = "N/A"


SEVERITY_RANK = {"low": 1, "medium": 2, "high": 3, "critical": 4}


@dataclass
class Finding:
    """Result for one resource evaluated by one check."""
    resource: str
    status: Status
    detail: str = ""


@dataclass
class CheckResult:
    check_id: str
    title: str
    severity: str
    description: str
    remediation: str
    findings: list[Finding] = field(default_factory=list)

    @property
    def status(self) -> Status:
        if any(f.status == Status.FAIL for f in self.findings):
            return Status.FAIL
        if any(f.status == Status.PASS for f in self.findings):
            return Status.PASS
        return Status.NA

    @property
    def failed(self) -> list[Finding]:
        return [f for f in self.findings if f.status == Status.FAIL]


@dataclass
class ControlResult:
    control_id: str
    title: str
    check_ids: list[str]
    status: Status
    check_statuses: dict[str, Status]


@dataclass
class FrameworkResult:
    framework_id: str
    name: str
    disclaimer: str
    controls: list[ControlResult]

    @property
    def passed(self) -> int:
        return sum(1 for c in self.controls if c.status == Status.PASS)

    @property
    def failed(self) -> int:
        return sum(1 for c in self.controls if c.status == Status.FAIL)

    @property
    def not_applicable(self) -> int:
        return sum(1 for c in self.controls if c.status == Status.NA)

    @property
    def score(self) -> float | None:
        """Percentage of evaluated controls that pass; None if nothing was evaluated."""
        evaluated = self.passed + self.failed
        if evaluated == 0:
            return None
        return round(100.0 * self.passed / evaluated, 1)


@dataclass
class Context:
    """Tunable policy thresholds passed to every check."""
    allowed_regions: list[str] | None = None  # None means: do not enforce residency
    max_key_age_days: int = 90
    min_password_length: int = 14
    min_backup_days: int = 7
    min_log_retention_days: int = 365
