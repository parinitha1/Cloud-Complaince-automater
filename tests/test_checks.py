import pytest

from ccaudit.checks import REGISTRY
from ccaudit.models import Context, Status


def run(check_id, snapshot, ctx=None):
    _meta, fn = REGISTRY[check_id]
    findings = fn(snapshot, ctx or Context())
    statuses = {f.status for f in findings}
    if Status.FAIL in statuses:
        return Status.FAIL, findings
    if Status.PASS in statuses:
        return Status.PASS, findings
    return Status.NA, findings


GOOD_PAB = {"block_public_acls": True, "ignore_public_acls": True,
            "block_public_policy": True, "restrict_public_buckets": True}


def sg(*rules):
    return {"security_groups": [{"id": "sg-1", "name": "t", "rules": list(rules)}]}


def rule(port_from, port_to, cidr="0.0.0.0/0", protocol="tcp"):
    return {"protocol": protocol, "port_from": port_from, "port_to": port_to, "cidr": cidr}


CASES = [
    # (check id, snapshot, expected status)
    ("S3-001", {"s3_buckets": [{"name": "b", "public_access_block": GOOD_PAB}]}, Status.PASS),
    ("S3-001", {"s3_buckets": [{"name": "b", "public_access_block": None}]}, Status.FAIL),
    ("S3-001", {"s3_buckets": [{"name": "b", "public_access_block": {**GOOD_PAB, "restrict_public_buckets": False}}]}, Status.FAIL),
    ("S3-001", {}, Status.NA),
    ("S3-002", {"s3_buckets": [{"name": "b", "encryption": True}]}, Status.PASS),
    ("S3-002", {"s3_buckets": [{"name": "b", "encryption": False}]}, Status.FAIL),
    ("S3-003", {"s3_buckets": [{"name": "b", "versioning": True}]}, Status.PASS),
    ("S3-003", {"s3_buckets": [{"name": "b"}]}, Status.FAIL),
    ("S3-004", {"s3_buckets": [{"name": "b", "logging": True}]}, Status.PASS),
    ("S3-004", {"s3_buckets": [{"name": "b", "logging": False}]}, Status.FAIL),
    ("S3-005", {"s3_buckets": [{"name": "b", "enforces_tls": True}]}, Status.PASS),
    ("S3-005", {"s3_buckets": [{"name": "b", "enforces_tls": False}]}, Status.FAIL),
    ("SG-001", sg(rule(22, 22)), Status.FAIL),
    ("SG-001", sg(rule(3389, 3389, "::/0")), Status.FAIL),
    ("SG-001", sg(rule(20, 30)), Status.FAIL),                       # range covers 22
    ("SG-001", sg(rule(None, None, protocol="-1")), Status.FAIL),    # all traffic
    ("SG-001", sg(rule(22, 22, "10.0.0.0/8")), Status.PASS),
    ("SG-001", sg(rule(443, 443)), Status.PASS),
    ("SG-001", {}, Status.NA),
    ("SG-002", sg(rule(443, 443), rule(80, 80)), Status.PASS),
    ("SG-002", sg(rule(5432, 5432)), Status.FAIL),
    ("SG-002", sg(rule(8000, 9000)), Status.FAIL),
    ("SG-002", sg(rule(80, 443)), Status.FAIL),                      # a range is not just 80/443
    ("SG-002", sg(rule(22, 22)), Status.PASS),                       # reported by SG-001, not here
    ("SG-002", sg(rule(5432, 5432, "10.0.0.0/16")), Status.PASS),
    ("IAM-001", {"iam": {"root_mfa": True}}, Status.PASS),
    ("IAM-001", {"iam": {"root_mfa": False}}, Status.FAIL),
    ("IAM-001", {"iam": {}}, Status.NA),
    ("IAM-001", {}, Status.NA),
    ("IAM-002", {"iam": {"root_access_keys": False}}, Status.PASS),
    ("IAM-002", {"iam": {"root_access_keys": True}}, Status.FAIL),
    ("IAM-003", {"iam": {"password_policy": {"min_length": 14}}}, Status.PASS),
    ("IAM-003", {"iam": {"password_policy": {"min_length": 13}}}, Status.FAIL),
    ("IAM-003", {"iam": {"password_policy": None}}, Status.FAIL),
    ("IAM-003", {"iam": {}}, Status.NA),
    ("IAM-004", {"iam": {"users": [{"name": "a", "console_access": True, "mfa": True}]}}, Status.PASS),
    ("IAM-004", {"iam": {"users": [{"name": "a", "console_access": True, "mfa": False}]}}, Status.FAIL),
    ("IAM-004", {"iam": {"users": [{"name": "a", "console_access": False, "mfa": False}]}}, Status.NA),
    ("IAM-005", {"iam": {"users": [{"name": "a", "access_keys": [{"id": "k", "active": True, "age_days": 90}]}]}}, Status.PASS),
    ("IAM-005", {"iam": {"users": [{"name": "a", "access_keys": [{"id": "k", "active": True, "age_days": 91}]}]}}, Status.FAIL),
    ("IAM-005", {"iam": {"users": [{"name": "a", "access_keys": [{"id": "k", "active": False, "age_days": 999}]}]}}, Status.NA),
    ("IAM-006", {"iam": {"users": [{"name": "a", "attached_admin": True}]}}, Status.FAIL),
    ("IAM-006", {"iam": {"users": [{"name": "a", "attached_admin": False}]}}, Status.PASS),
    ("LOG-001", {"cloudtrail": [{"name": "t", "multi_region": True, "logging": True}]}, Status.PASS),
    ("LOG-001", {"cloudtrail": [{"name": "t", "multi_region": True, "logging": False}]}, Status.FAIL),
    ("LOG-001", {"cloudtrail": [{"name": "t", "multi_region": False, "logging": True}]}, Status.FAIL),
    ("LOG-001", {"cloudtrail": []}, Status.FAIL),                    # collected, none exist
    ("LOG-001", {}, Status.NA),                                      # not collected
    ("LOG-002", {"cloudtrail": [{"name": "t", "log_validation": True}]}, Status.PASS),
    ("LOG-002", {"cloudtrail": [{"name": "t", "log_validation": False}]}, Status.FAIL),
    ("LOG-003", {"cloudtrail": [{"name": "t", "kms_encrypted": True}]}, Status.PASS),
    ("LOG-003", {"cloudtrail": [{"name": "t", "kms_encrypted": False}]}, Status.FAIL),
    ("LOG-004", {"log_groups": [{"name": "g", "retention_days": 365}]}, Status.PASS),
    ("LOG-004", {"log_groups": [{"name": "g", "retention_days": None}]}, Status.PASS),
    ("LOG-004", {"log_groups": [{"name": "g", "retention_days": 30}]}, Status.FAIL),
    ("ENC-001", {"ebs_volumes": [{"id": "v", "encrypted": True}]}, Status.PASS),
    ("ENC-001", {"ebs_volumes": [{"id": "v", "encrypted": False}]}, Status.FAIL),
    ("ENC-002", {"rds_instances": [{"id": "d", "encrypted": True}]}, Status.PASS),
    ("ENC-002", {"rds_instances": [{"id": "d", "encrypted": False}]}, Status.FAIL),
    ("ENC-003", {"kms_keys": [{"id": "k", "rotation_enabled": True}]}, Status.PASS),
    ("ENC-003", {"kms_keys": [{"id": "k", "rotation_enabled": False}]}, Status.FAIL),
    ("RDS-001", {"rds_instances": [{"id": "d", "publicly_accessible": False}]}, Status.PASS),
    ("RDS-001", {"rds_instances": [{"id": "d", "publicly_accessible": True}]}, Status.FAIL),
    ("BCK-001", {"rds_instances": [{"id": "d", "backup_retention_days": 7}]}, Status.PASS),
    ("BCK-001", {"rds_instances": [{"id": "d", "backup_retention_days": 6}]}, Status.FAIL),
    ("BCK-001", {"rds_instances": [{"id": "d"}]}, Status.FAIL),
]


@pytest.mark.parametrize("check_id,snapshot,expected", CASES)
def test_check(check_id, snapshot, expected):
    status, _ = run(check_id, snapshot)
    assert status == expected


def test_every_check_has_a_case():
    assert {c[0] for c in CASES} | {"RES-001"} == set(REGISTRY)


def test_every_check_can_pass_and_fail():
    for check_id in REGISTRY:
        if check_id == "RES-001":
            continue
        outcomes = {c[2] for c in CASES if c[0] == check_id}
        assert Status.PASS in outcomes and Status.FAIL in outcomes, check_id


def test_thresholds_are_configurable():
    snap = {"iam": {"password_policy": {"min_length": 10}}}
    assert run("IAM-003", snap, Context(min_password_length=10))[0] == Status.PASS
    snap = {"iam": {"users": [{"name": "a", "access_keys": [{"id": "k", "active": True, "age_days": 200}]}]}}
    assert run("IAM-005", snap, Context(max_key_age_days=365))[0] == Status.PASS
    snap = {"log_groups": [{"name": "g", "retention_days": 90}]}
    assert run("LOG-004", snap, Context(min_log_retention_days=90))[0] == Status.PASS


def test_admin_ports_not_double_reported():
    snap = sg(rule(22, 22))
    assert run("SG-001", snap)[0] == Status.FAIL
    assert run("SG-002", snap)[0] == Status.PASS


class TestResidency:
    SNAP = {"s3_buckets": [{"name": "in", "region": "ap-south-1"}, {"name": "out", "region": "us-east-1"}],
            "ebs_volumes": [{"id": "v", "region": "ap-south-2"}]}

    def test_disabled_by_default(self):
        assert run("RES-001", self.SNAP)[0] == Status.NA

    def test_flags_outside_allowed(self):
        status, findings = run("RES-001", self.SNAP, Context(allowed_regions=["ap-south-1", "ap-south-2"]))
        assert status == Status.FAIL
        assert [f.resource for f in findings if f.status == Status.FAIL] == ["out"]

    def test_all_in_region_passes(self):
        assert run("RES-001", self.SNAP, Context(allowed_regions=["ap-south-1", "ap-south-2", "us-east-1"]))[0] == Status.PASS
