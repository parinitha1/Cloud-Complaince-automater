"""Read-only AWS collector that builds a snapshot dict for the checks.

Only Describe/Get/List API calls are made. Nothing is modified.
boto3 is imported lazily so the scanner works offline on saved snapshots.
"""
from __future__ import annotations

import datetime as dt
import json
from typing import Callable

from botocore.exceptions import ClientError

ClientFactory = Callable[[str, str | None], object]

ABSENT_CODES = {
    "NoSuchPublicAccessBlockConfiguration",
    "ServerSideEncryptionConfigurationNotFoundError",
    "NoSuchBucketPolicy",
    "NoSuchEntity",
}


def make_client_factory(profile: str | None = None, default_region: str | None = None) -> ClientFactory:
    import boto3  # lazy import
    session = boto3.Session(profile_name=profile, region_name=default_region)
    cache: dict[tuple[str, str | None], object] = {}

    def factory(service: str, region: str | None = None):
        key = (service, region)
        if key not in cache:
            cache[key] = session.client(service, region_name=region) if region else session.client(service)
        return cache[key]
    return factory


def _code(exc: ClientError) -> str:
    return exc.response.get("Error", {}).get("Code", "")


def policy_enforces_tls(policy_json: str | dict | None) -> bool:
    """True if a bucket policy has a Deny statement conditioned on aws:SecureTransport being false."""
    if not policy_json:
        return False
    policy = json.loads(policy_json) if isinstance(policy_json, str) else policy_json
    statements = policy.get("Statement", [])
    if isinstance(statements, dict):
        statements = [statements]
    for st in statements:
        if st.get("Effect") != "Deny":
            continue
        cond = st.get("Condition", {})
        for op in ("Bool", "BoolIfExists"):
            val = cond.get(op, {}).get("aws:SecureTransport")
            if val is not None and str(val).lower() == "false":
                return True
    return False


def _tag_name(tags: list[dict] | None) -> str:
    for t in tags or []:
        if t.get("Key") == "Name":
            return t.get("Value", "")
    return ""


def collect_s3(cf: ClientFactory) -> list[dict]:
    s3 = cf("s3", None)
    buckets = []
    for b in s3.list_buckets().get("Buckets", []):
        name = b["Name"]
        loc = s3.get_bucket_location(Bucket=name).get("LocationConstraint")
        region = loc or "us-east-1"
        if region == "EU":
            region = "eu-west-1"
        item = {"name": name, "region": region, "public_access_block": None,
                "encryption": False, "versioning": False, "logging": False, "enforces_tls": False}
        try:
            cfg = s3.get_public_access_block(Bucket=name)["PublicAccessBlockConfiguration"]
            item["public_access_block"] = {
                "block_public_acls": cfg.get("BlockPublicAcls", False),
                "ignore_public_acls": cfg.get("IgnorePublicAcls", False),
                "block_public_policy": cfg.get("BlockPublicPolicy", False),
                "restrict_public_buckets": cfg.get("RestrictPublicBuckets", False),
            }
        except ClientError as exc:
            if _code(exc) not in ABSENT_CODES:
                raise
        try:
            rules = s3.get_bucket_encryption(Bucket=name)["ServerSideEncryptionConfiguration"]["Rules"]
            if rules:
                item["encryption"] = True
                item["encryption_type"] = rules[0]["ApplyServerSideEncryptionByDefault"]["SSEAlgorithm"]
        except ClientError as exc:
            if _code(exc) not in ABSENT_CODES:
                raise
        item["versioning"] = s3.get_bucket_versioning(Bucket=name).get("Status") == "Enabled"
        item["logging"] = "LoggingEnabled" in s3.get_bucket_logging(Bucket=name)
        try:
            item["enforces_tls"] = policy_enforces_tls(s3.get_bucket_policy(Bucket=name)["Policy"])
        except ClientError as exc:
            if _code(exc) not in ABSENT_CODES:
                raise
        buckets.append(item)
    return buckets


def collect_security_groups(cf: ClientFactory, region: str) -> list[dict]:
    ec2 = cf("ec2", region)
    groups = []
    for page in ec2.get_paginator("describe_security_groups").paginate():
        for sg in page["SecurityGroups"]:
            rules = []
            for perm in sg.get("IpPermissions", []):
                proto = perm.get("IpProtocol", "-1")
                lo, hi = perm.get("FromPort"), perm.get("ToPort")
                for r in perm.get("IpRanges", []):
                    rules.append({"protocol": proto, "port_from": lo, "port_to": hi, "cidr": r["CidrIp"]})
                for r in perm.get("Ipv6Ranges", []):
                    rules.append({"protocol": proto, "port_from": lo, "port_to": hi, "cidr": r["CidrIpv6"]})
            groups.append({"id": f'{region}:{sg["GroupId"]}', "name": sg.get("GroupName", ""), "rules": rules})
    return groups


def collect_ebs(cf: ClientFactory, region: str) -> list[dict]:
    ec2 = cf("ec2", region)
    out = []
    for page in ec2.get_paginator("describe_volumes").paginate():
        for v in page["Volumes"]:
            out.append({"id": v["VolumeId"], "region": region, "encrypted": bool(v.get("Encrypted"))})
    return out


def collect_rds(cf: ClientFactory, region: str) -> list[dict]:
    rds = cf("rds", region)
    out = []
    for page in rds.get_paginator("describe_db_instances").paginate():
        for d in page["DBInstances"]:
            out.append({
                "id": d["DBInstanceIdentifier"], "region": region,
                "encrypted": bool(d.get("StorageEncrypted")),
                "publicly_accessible": bool(d.get("PubliclyAccessible")),
                "backup_retention_days": d.get("BackupRetentionPeriod", 0),
                "multi_az": bool(d.get("MultiAZ")),
            })
    return out


def collect_kms(cf: ClientFactory, region: str) -> list[dict]:
    kms = cf("kms", region)
    out = []
    for page in kms.get_paginator("list_keys").paginate():
        for k in page["Keys"]:
            meta = kms.describe_key(KeyId=k["KeyId"])["KeyMetadata"]
            if meta.get("KeyManager") != "CUSTOMER" or meta.get("KeyState") != "Enabled":
                continue
            if meta.get("KeySpec", "SYMMETRIC_DEFAULT") != "SYMMETRIC_DEFAULT":
                continue  # automatic rotation applies to symmetric keys
            if meta.get("Origin", "AWS_KMS") != "AWS_KMS":
                continue
            rot = kms.get_key_rotation_status(KeyId=k["KeyId"])["KeyRotationEnabled"]
            out.append({"id": f'{region}:{k["KeyId"]}', "region": region, "rotation_enabled": bool(rot)})
    return out


def collect_log_groups(cf: ClientFactory, region: str) -> list[dict]:
    logs = cf("logs", region)
    out = []
    for page in logs.get_paginator("describe_log_groups").paginate():
        for g in page["logGroups"]:
            out.append({"name": f'{region}:{g["logGroupName"]}', "retention_days": g.get("retentionInDays")})
    return out


def collect_cloudtrail(cf: ClientFactory, region: str) -> list[dict]:
    ct = cf("cloudtrail", region)
    out = []
    for t in ct.describe_trails(includeShadowTrails=False).get("trailList", []):
        status = ct.get_trail_status(Name=t["TrailARN"])
        out.append({
            "name": t["Name"],
            "multi_region": bool(t.get("IsMultiRegionTrail")),
            "log_validation": bool(t.get("LogFileValidationEnabled")),
            "kms_encrypted": bool(t.get("KmsKeyId")),
            "logging": bool(status.get("IsLogging")),
        })
    return out


def collect_iam(cf: ClientFactory) -> dict:
    iam = cf("iam", None)
    summary = iam.get_account_summary()["SummaryMap"]
    try:
        pol = iam.get_account_password_policy()["PasswordPolicy"]
        policy = {"min_length": pol.get("MinimumPasswordLength", 0)}
    except ClientError as exc:
        if _code(exc) != "NoSuchEntity":
            raise
        policy = None

    now = dt.datetime.now(dt.timezone.utc)
    users = []
    for page in iam.get_paginator("list_users").paginate():
        for u in page["Users"]:
            name = u["UserName"]
            try:
                iam.get_login_profile(UserName=name)
                console = True
            except ClientError as exc:
                if _code(exc) != "NoSuchEntity":
                    raise
                console = False
            mfa = bool(iam.list_mfa_devices(UserName=name).get("MFADevices"))
            keys = []
            for k in iam.list_access_keys(UserName=name).get("AccessKeyMetadata", []):
                keys.append({"id": k["AccessKeyId"], "active": k["Status"] == "Active",
                             "age_days": (now - k["CreateDate"]).days})
            attached = iam.list_attached_user_policies(UserName=name).get("AttachedPolicies", [])
            admin = any(p["PolicyName"] == "AdministratorAccess" for p in attached)
            users.append({"name": name, "console_access": console, "mfa": mfa,
                          "access_keys": keys, "attached_admin": admin})
    return {
        "root_mfa": bool(summary.get("AccountMFAEnabled")),
        "root_access_keys": bool(summary.get("AccountAccessKeysPresent")),
        "password_policy": policy,
        "users": users,
    }


def collect_snapshot(cf: ClientFactory, regions: list[str], account_id: str = "unknown") -> dict:
    """Collect everything. Global services (S3, IAM) are read once; regional ones per region."""
    snap: dict = {
        "schema_version": 1, "provider": "aws", "account_id": account_id,
        "collected_at": dt.datetime.now(dt.timezone.utc).isoformat(timespec="seconds"),
        "regions": regions,
        "s3_buckets": collect_s3(cf),
        "iam": collect_iam(cf),
        "security_groups": [], "ebs_volumes": [], "rds_instances": [],
        "kms_keys": [], "log_groups": [], "cloudtrail": [],
    }
    seen_trails: set[str] = set()
    for region in regions:
        snap["security_groups"] += collect_security_groups(cf, region)
        snap["ebs_volumes"] += collect_ebs(cf, region)
        snap["rds_instances"] += collect_rds(cf, region)
        snap["kms_keys"] += collect_kms(cf, region)
        snap["log_groups"] += collect_log_groups(cf, region)
        for t in collect_cloudtrail(cf, region):
            if t["name"] not in seen_trails:  # multi-region trails appear in every region
                seen_trails.add(t["name"])
                snap["cloudtrail"].append(t)
    return snap
