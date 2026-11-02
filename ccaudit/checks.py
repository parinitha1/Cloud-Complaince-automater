"""Automated checks. Each check inspects a snapshot dict and returns Findings.

A check returns an empty list when the relevant section is missing or has no
resources; the engine reports that as N/A rather than as a pass.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Callable

from .models import Context, Finding, Status

WORLD_CIDRS = {"0.0.0.0/0", "::/0"}
ADMIN_PORTS = (22, 3389)
WEB_PORTS = {80, 443}


@dataclass(frozen=True)
class CheckMeta:
    check_id: str
    title: str
    severity: str
    description: str
    remediation: str


CheckFn = Callable[[dict, Context], list[Finding]]
REGISTRY: dict[str, tuple[CheckMeta, CheckFn]] = {}


def check(check_id: str, title: str, severity: str, description: str, remediation: str):
    def wrap(fn: CheckFn) -> CheckFn:
        if check_id in REGISTRY:
            raise ValueError(f"duplicate check id {check_id}")
        REGISTRY[check_id] = (CheckMeta(check_id, title, severity, description, remediation), fn)
        return fn
    return wrap


def _ok(resource: str, detail: str = "") -> Finding:
    return Finding(resource, Status.PASS, detail)


def _bad(resource: str, detail: str) -> Finding:
    return Finding(resource, Status.FAIL, detail)


def _covers_port(rule: dict, port: int) -> bool:
    if str(rule.get("protocol", "")) == "-1":
        return True
    lo, hi = rule.get("port_from"), rule.get("port_to")
    if lo is None or hi is None:
        return True
    return lo <= port <= hi


def _world_open(rule: dict) -> bool:
    return rule.get("cidr") in WORLD_CIDRS


# ----------------------------------------------------------------- S3

@check("S3-001", "S3 buckets block public access", "critical",
       "All four S3 Block Public Access settings should be enabled so objects cannot be exposed by ACLs or policies.",
       "Enable Block Public Access on the bucket (or the whole account): BlockPublicAcls, IgnorePublicAcls, BlockPublicPolicy, RestrictPublicBuckets.")
def s3_public_access(snap: dict, ctx: Context) -> list[Finding]:
    out = []
    required = ("block_public_acls", "ignore_public_acls", "block_public_policy", "restrict_public_buckets")
    for b in snap.get("s3_buckets", []):
        pab = b.get("public_access_block") or {}
        missing = [k for k in required if not pab.get(k)]
        if missing:
            out.append(_bad(b["name"], "Block Public Access not fully enabled; missing: " + ", ".join(missing)))
        else:
            out.append(_ok(b["name"]))
    return out


@check("S3-002", "S3 buckets use default encryption", "high",
       "Buckets should encrypt objects at rest by default (SSE-S3 or SSE-KMS).",
       "Enable default bucket encryption, preferably SSE-KMS with a customer-managed key for sensitive data.")
def s3_encryption(snap: dict, ctx: Context) -> list[Finding]:
    return [_ok(b["name"], b.get("encryption_type", "")) if b.get("encryption")
            else _bad(b["name"], "No default encryption configured")
            for b in snap.get("s3_buckets", [])]


@check("S3-003", "S3 bucket versioning enabled", "medium",
       "Versioning protects against accidental deletion and overwrite, supporting recovery.",
       "Enable versioning, and add lifecycle rules to expire old versions according to your retention policy.")
def s3_versioning(snap: dict, ctx: Context) -> list[Finding]:
    return [_ok(b["name"]) if b.get("versioning")
            else _bad(b["name"], "Versioning is not enabled")
            for b in snap.get("s3_buckets", [])]


@check("S3-004", "S3 server access logging enabled", "low",
       "Access logs give an audit trail of requests to each bucket.",
       "Enable server access logging to a dedicated log bucket, or use CloudTrail data events for sensitive buckets.")
def s3_logging(snap: dict, ctx: Context) -> list[Finding]:
    return [_ok(b["name"]) if b.get("logging")
            else _bad(b["name"], "Server access logging is not enabled")
            for b in snap.get("s3_buckets", [])]


@check("S3-005", "S3 bucket policy enforces TLS", "medium",
       "Bucket policies should deny requests that do not use HTTPS (aws:SecureTransport = false).",
       "Add a Deny statement for Principal * with condition Bool aws:SecureTransport = false.")
def s3_tls(snap: dict, ctx: Context) -> list[Finding]:
    return [_ok(b["name"]) if b.get("enforces_tls")
            else _bad(b["name"], "No policy statement denying non-TLS requests")
            for b in snap.get("s3_buckets", [])]


# ------------------------------------------------------ Security groups

@check("SG-001", "No world-open SSH/RDP", "critical",
       "Security groups must not allow 0.0.0.0/0 or ::/0 to reach SSH (22) or RDP (3389), including via all-traffic rules.",
       "Restrict the source to a VPN or bastion CIDR, or use SSM Session Manager and remove the rule.")
def sg_admin_ports(snap: dict, ctx: Context) -> list[Finding]:
    out = []
    for sg in snap.get("security_groups", []):
        hits = []
        for r in sg.get("rules", []):
            if not _world_open(r):
                continue
            for p in ADMIN_PORTS:
                if _covers_port(r, p):
                    hits.append(p)
        label = f'{sg["id"]} ({sg.get("name", "")})'
        if hits:
            out.append(_bad(label, "World-open admin port(s): " + ", ".join(str(p) for p in sorted(set(hits)))))
        else:
            out.append(_ok(label))
    return out


@check("SG-002", "No world-open ports other than 80/443", "high",
       "Only public web ports should be reachable from the whole internet. Admin ports are reported by SG-001.",
       "Narrow the source CIDR to known ranges or place the service behind a load balancer or private network.")
def sg_other_ports(snap: dict, ctx: Context) -> list[Finding]:
    out = []
    for sg in snap.get("security_groups", []):
        bad_ranges = []
        for r in sg.get("rules", []):
            if not _world_open(r):
                continue
            if any(_covers_port(r, p) for p in ADMIN_PORTS):
                continue  # reported by SG-001
            lo, hi = r.get("port_from"), r.get("port_to")
            if lo is not None and hi is not None and lo == hi and lo in WEB_PORTS:
                continue
            bad_ranges.append(f'{r.get("protocol")}/{lo}-{hi}')
        label = f'{sg["id"]} ({sg.get("name", "")})'
        if bad_ranges:
            out.append(_bad(label, "World-open: " + ", ".join(bad_ranges)))
        else:
            out.append(_ok(label))
    return out


# ------------------------------------------------------------------ IAM

def _iam(snap: dict) -> dict | None:
    return snap.get("iam")


@check("IAM-001", "Root account has MFA", "critical",
       "The root user has unrestricted access, so it must be protected with MFA (hardware MFA preferred).",
       "Register an MFA device for the root user and store break-glass access securely.")
def iam_root_mfa(snap: dict, ctx: Context) -> list[Finding]:
    iam = _iam(snap)
    if not iam or iam.get("root_mfa") is None:
        return []
    return [_ok("root") if iam["root_mfa"] else _bad("root", "Root account has no MFA device")]


@check("IAM-002", "Root account has no access keys", "critical",
       "Root access keys cannot be scoped down and should not exist.",
       "Delete root access keys and use IAM roles or Identity Center users for programmatic access.")
def iam_root_keys(snap: dict, ctx: Context) -> list[Finding]:
    iam = _iam(snap)
    if not iam or iam.get("root_access_keys") is None:
        return []
    return [_bad("root", "Root account has active access keys") if iam["root_access_keys"] else _ok("root")]


@check("IAM-003", "Strong password policy", "medium",
       "The account password policy should require a minimum length that meets your standard (default 14).",
       "Update the IAM account password policy to meet the minimum length and require varied character types.")
def iam_password_policy(snap: dict, ctx: Context) -> list[Finding]:
    iam = _iam(snap)
    if not iam or "password_policy" not in iam:
        return []
    pol = iam["password_policy"]
    if not pol:
        return [_bad("account", "No custom password policy is set")]
    length = pol.get("min_length", 0)
    if length < ctx.min_password_length:
        return [_bad("account", f"Minimum length is {length}, expected at least {ctx.min_password_length}")]
    return [_ok("account", f"Minimum length {length}")]


@check("IAM-004", "Console users have MFA", "high",
       "Every IAM user with console access should authenticate with MFA.",
       "Require MFA for all console users, or move to federated sign-in with enforced MFA.")
def iam_user_mfa(snap: dict, ctx: Context) -> list[Finding]:
    iam = _iam(snap) or {}
    out = []
    for u in iam.get("users", []):
        if not u.get("console_access"):
            continue
        out.append(_ok(u["name"]) if u.get("mfa") else _bad(u["name"], "Console access without MFA"))
    return out


@check("IAM-005", "Access keys rotated", "medium",
       "Active access keys should be rotated at least every 90 days (configurable).",
       "Rotate or delete stale keys; prefer short-lived credentials from roles.")
def iam_key_age(snap: dict, ctx: Context) -> list[Finding]:
    iam = _iam(snap) or {}
    out = []
    for u in iam.get("users", []):
        for k in u.get("access_keys", []):
            if not k.get("active", True):
                continue
            label = f'{u["name"]}/{k.get("id", "key")}'
            age = k.get("age_days", 0)
            if age > ctx.max_key_age_days:
                out.append(_bad(label, f"Key is {age} days old (limit {ctx.max_key_age_days})"))
            else:
                out.append(_ok(label, f"{age} days old"))
    return out


@check("IAM-006", "No directly attached admin policy on users", "medium",
       "Users should receive privileges through roles or groups, not by attaching AdministratorAccess to the user.",
       "Detach AdministratorAccess from the user and grant least-privilege access through reviewed roles or groups.")
def iam_admin_users(snap: dict, ctx: Context) -> list[Finding]:
    iam = _iam(snap) or {}
    return [_bad(u["name"], "AdministratorAccess attached directly to user") if u.get("attached_admin")
            else _ok(u["name"]) for u in iam.get("users", [])]


# -------------------------------------------------------------- Logging

@check("LOG-001", "CloudTrail multi-region trail is logging", "critical",
       "At least one multi-region CloudTrail trail should be actively logging management events.",
       "Create a multi-region trail delivering to a protected S3 bucket and make sure logging is started.")
def trail_enabled(snap: dict, ctx: Context) -> list[Finding]:
    trails = snap.get("cloudtrail")
    if trails is None:
        return []
    if not trails:
        return [_bad("account", "No CloudTrail trails exist")]
    if any(t.get("multi_region") and t.get("logging") for t in trails):
        return [_ok("account")]
    return [_bad("account", "No trail is both multi-region and actively logging")]


@check("LOG-002", "CloudTrail log file validation", "medium",
       "Log file integrity validation lets you detect tampering with delivered logs.",
       "Enable log file validation on every trail.")
def trail_validation(snap: dict, ctx: Context) -> list[Finding]:
    return [_ok(t["name"]) if t.get("log_validation")
            else _bad(t["name"], "Log file validation disabled")
            for t in snap.get("cloudtrail") or []]


@check("LOG-003", "CloudTrail logs encrypted with KMS", "medium",
       "Trail logs should be encrypted with a KMS key rather than only default S3 encryption.",
       "Set a KMS key on the trail and grant CloudTrail permission to use it.")
def trail_encryption(snap: dict, ctx: Context) -> list[Finding]:
    return [_ok(t["name"]) if t.get("kms_encrypted")
            else _bad(t["name"], "Trail is not encrypted with a KMS key")
            for t in snap.get("cloudtrail") or []]


@check("LOG-004", "Log groups retain logs long enough", "medium",
       "CloudWatch log groups should keep logs for the period your policy requires (default 365 days). 'Never expire' passes.",
       "Set the log group retention to at least the required number of days or export logs to long-term storage.")
def log_retention(snap: dict, ctx: Context) -> list[Finding]:
    out = []
    for g in snap.get("log_groups", []):
        days = g.get("retention_days")
        if days is None:
            out.append(_ok(g["name"], "Never expires"))
        elif days < ctx.min_log_retention_days:
            out.append(_bad(g["name"], f"Retention {days} days, expected at least {ctx.min_log_retention_days}"))
        else:
            out.append(_ok(g["name"], f"{days} days"))
    return out


# ----------------------------------------------- Encryption and data stores

@check("ENC-001", "EBS volumes encrypted", "high",
       "EBS volumes should be encrypted at rest.",
       "Create encrypted snapshots/copies and replace unencrypted volumes; enable EBS encryption by default per region.")
def ebs_encrypted(snap: dict, ctx: Context) -> list[Finding]:
    return [_ok(v["id"]) if v.get("encrypted") else _bad(v["id"], "Volume is not encrypted")
            for v in snap.get("ebs_volumes", [])]


@check("ENC-002", "RDS storage encrypted", "high",
       "RDS instances should have storage encryption enabled.",
       "Encryption cannot be turned on in place: restore from an encrypted snapshot copy and cut over.")
def rds_encrypted(snap: dict, ctx: Context) -> list[Finding]:
    return [_ok(d["id"]) if d.get("encrypted") else _bad(d["id"], "Storage is not encrypted")
            for d in snap.get("rds_instances", [])]


@check("ENC-003", "KMS customer keys rotate", "medium",
       "Customer-managed symmetric KMS keys should have automatic rotation enabled.",
       "Enable automatic key rotation on each customer-managed key.")
def kms_rotation(snap: dict, ctx: Context) -> list[Finding]:
    return [_ok(k["id"]) if k.get("rotation_enabled") else _bad(k["id"], "Automatic rotation disabled")
            for k in snap.get("kms_keys", [])]


@check("RDS-001", "RDS not publicly accessible", "critical",
       "Database instances should not be directly reachable from the internet.",
       "Disable public accessibility and use private subnets with access through application tiers or a bastion.")
def rds_public(snap: dict, ctx: Context) -> list[Finding]:
    return [_bad(d["id"], "Instance is publicly accessible") if d.get("publicly_accessible") else _ok(d["id"])
            for d in snap.get("rds_instances", [])]


@check("BCK-001", "RDS automated backups retained", "medium",
       "Automated backups should be kept for at least the configured number of days (default 7).",
       "Raise the backup retention period on the instance.")
def rds_backups(snap: dict, ctx: Context) -> list[Finding]:
    out = []
    for d in snap.get("rds_instances", []):
        days = d.get("backup_retention_days", 0)
        if days < ctx.min_backup_days:
            out.append(_bad(d["id"], f"Backup retention {days} days, expected at least {ctx.min_backup_days}"))
        else:
            out.append(_ok(d["id"], f"{days} days"))
    return out


@check("RES-001", "Data stores are in approved regions", "medium",
       "Storage and databases should sit in regions your data residency policy allows. This is a visibility check: "
       "the DPDP Act does not by itself bar storing data outside India, but sector regulators or contracts may. "
       "Skipped unless allowed regions are configured.",
       "Move data to an approved region, or document the legal basis for keeping it elsewhere.")
def data_residency(snap: dict, ctx: Context) -> list[Finding]:
    if not ctx.allowed_regions:
        return []
    out = []
    for section, key in (("s3_buckets", "name"), ("ebs_volumes", "id"),
                         ("rds_instances", "id"), ("kms_keys", "id")):
        for res in snap.get(section, []):
            region = res.get("region")
            if region is None:
                continue
            if region in ctx.allowed_regions:
                out.append(_ok(res[key], region))
            else:
                out.append(_bad(res[key], f"In {region}; allowed: {', '.join(ctx.allowed_regions)}"))
    return out
