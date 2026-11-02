"""Collector tests use botocore's Stubber, so no AWS account or network is needed."""
import datetime as dt
import json

import pytest

boto3 = pytest.importorskip("boto3")
from botocore.stub import Stubber  # noqa: E402

from ccaudit import collector  # noqa: E402
from ccaudit.engine import scan, validate_snapshot  # noqa: E402

NOW = dt.datetime.now(dt.timezone.utc)
REGION = "ap-south-1"


class Env:
    """Hands out real boto3 clients wrapped in Stubbers."""

    def __init__(self):
        self.clients = {}
        self.stubbers = {}

    def add(self, service, region=None):
        key = (service, region)
        client = boto3.client(service, region_name=region or REGION,
                              aws_access_key_id="test", aws_secret_access_key="test")
        self.clients[key] = client
        self.stubbers[key] = Stubber(client)
        return self.stubbers[key]

    def factory(self, service, region=None):
        return self.clients[(service, region)]

    def activate(self):
        for s in self.stubbers.values():
            s.activate()

    def assert_done(self):
        for s in self.stubbers.values():
            s.assert_no_pending_responses()


def test_policy_enforces_tls():
    good = {"Statement": [{"Effect": "Deny", "Principal": "*", "Action": "s3:*", "Resource": "*",
                           "Condition": {"Bool": {"aws:SecureTransport": "false"}}}]}
    assert collector.policy_enforces_tls(json.dumps(good))
    assert collector.policy_enforces_tls(good)
    allow = {"Statement": [{"Effect": "Allow", "Principal": "*", "Action": "s3:*", "Resource": "*",
                            "Condition": {"Bool": {"aws:SecureTransport": "false"}}}]}
    assert not collector.policy_enforces_tls(allow)
    assert not collector.policy_enforces_tls({"Statement": {"Effect": "Deny", "Action": "*"}})
    assert not collector.policy_enforces_tls(None)


def test_collect_s3_handles_configured_and_bare_buckets():
    env = Env()
    s3 = env.add("s3")
    s3.add_response("list_buckets", {"Buckets": [{"Name": "good", "CreationDate": NOW},
                                                 {"Name": "bare", "CreationDate": NOW}]})
    # "good": everything configured
    s3.add_response("get_bucket_location", {"LocationConstraint": REGION})
    s3.add_response("get_public_access_block", {"PublicAccessBlockConfiguration": {
        "BlockPublicAcls": True, "IgnorePublicAcls": True, "BlockPublicPolicy": True, "RestrictPublicBuckets": True}})
    s3.add_response("get_bucket_encryption", {"ServerSideEncryptionConfiguration": {"Rules": [
        {"ApplyServerSideEncryptionByDefault": {"SSEAlgorithm": "aws:kms"}}]}})
    s3.add_response("get_bucket_versioning", {"Status": "Enabled"})
    s3.add_response("get_bucket_logging", {"LoggingEnabled": {"TargetBucket": "logs", "TargetPrefix": "p/"}})
    s3.add_response("get_bucket_policy", {"Policy": json.dumps({"Statement": [{
        "Effect": "Deny", "Principal": "*", "Action": "s3:*", "Resource": "*",
        "Condition": {"Bool": {"aws:SecureTransport": "false"}}}]})})
    # "bare": us-east-1 (no location constraint), nothing configured
    s3.add_response("get_bucket_location", {})
    s3.add_client_error("get_public_access_block", "NoSuchPublicAccessBlockConfiguration")
    s3.add_client_error("get_bucket_encryption", "ServerSideEncryptionConfigurationNotFoundError")
    s3.add_response("get_bucket_versioning", {})
    s3.add_response("get_bucket_logging", {})
    s3.add_client_error("get_bucket_policy", "NoSuchBucketPolicy")
    env.activate()

    good, bare = collector.collect_s3(env.factory)
    assert good["region"] == REGION and good["encryption"] and good["encryption_type"] == "aws:kms"
    assert good["versioning"] and good["logging"] and good["enforces_tls"]
    assert all(good["public_access_block"].values())
    assert bare["region"] == "us-east-1" and bare["public_access_block"] is None
    assert not (bare["encryption"] or bare["versioning"] or bare["logging"] or bare["enforces_tls"])
    env.assert_done()


def test_collect_s3_reraises_unexpected_errors():
    env = Env()
    s3 = env.add("s3")
    s3.add_response("list_buckets", {"Buckets": [{"Name": "b", "CreationDate": NOW}]})
    s3.add_response("get_bucket_location", {"LocationConstraint": REGION})
    s3.add_client_error("get_public_access_block", "AccessDenied")
    env.activate()
    from botocore.exceptions import ClientError
    with pytest.raises(ClientError):
        collector.collect_s3(env.factory)


def test_collect_security_groups_flattens_rules():
    env = Env()
    ec2 = env.add("ec2", REGION)
    ec2.add_response("describe_security_groups", {"SecurityGroups": [{
        "GroupId": "sg-1", "GroupName": "web", "IpPermissions": [
            {"IpProtocol": "tcp", "FromPort": 22, "ToPort": 22,
             "IpRanges": [{"CidrIp": "0.0.0.0/0"}], "Ipv6Ranges": [{"CidrIpv6": "::/0"}]},
            {"IpProtocol": "-1", "IpRanges": [{"CidrIp": "10.0.0.0/8"}]}]}]})
    env.activate()
    groups = collector.collect_security_groups(env.factory, REGION)
    rules = groups[0]["rules"]
    assert groups[0]["id"] == f"{REGION}:sg-1"
    assert {r["cidr"] for r in rules} == {"0.0.0.0/0", "::/0", "10.0.0.0/8"}
    assert [r for r in rules if r["protocol"] == "-1"][0]["port_from"] is None


def test_collect_kms_only_customer_symmetric_keys():
    env = Env()
    kms = env.add("kms", REGION)
    arn = "arn:aws:kms:ap-south-1:123456789012:key/"
    kms.add_response("list_keys", {"Keys": [{"KeyId": "cust", "KeyArn": arn + "cust"},
                                            {"KeyId": "aws", "KeyArn": arn + "aws"},
                                            {"KeyId": "asym", "KeyArn": arn + "asym"}], "Truncated": False})
    kms.add_response("describe_key", {"KeyMetadata": {"KeyId": "cust", "KeyManager": "CUSTOMER", "KeyState": "Enabled",
                                                      "KeySpec": "SYMMETRIC_DEFAULT", "Origin": "AWS_KMS"}})
    kms.add_response("get_key_rotation_status", {"KeyRotationEnabled": False})
    kms.add_response("describe_key", {"KeyMetadata": {"KeyId": "aws", "KeyManager": "AWS", "KeyState": "Enabled"}})
    kms.add_response("describe_key", {"KeyMetadata": {"KeyId": "asym", "KeyManager": "CUSTOMER", "KeyState": "Enabled",
                                                      "KeySpec": "RSA_2048", "Origin": "AWS_KMS"}})
    env.activate()
    keys = collector.collect_kms(env.factory, REGION)
    assert keys == [{"id": f"{REGION}:cust", "region": REGION, "rotation_enabled": False}]
    env.assert_done()


def test_collect_iam():
    env = Env()
    iam = env.add("iam")
    iam.add_response("get_account_summary", {"SummaryMap": {"AccountMFAEnabled": 1, "AccountAccessKeysPresent": 0}})
    iam.add_client_error("get_account_password_policy", "NoSuchEntity")
    iam.add_response("list_users", {"Users": [
        {"Path": "/", "UserName": "bob", "UserId": "AIDAIOSFODNN7EXAMPLE", "Arn": "arn:aws:iam::123456789012:user/bob",
         "CreateDate": NOW}], "IsTruncated": False})
    iam.add_response("get_login_profile", {"LoginProfile": {"UserName": "bob", "CreateDate": NOW}})
    iam.add_response("list_mfa_devices", {"MFADevices": []})
    iam.add_response("list_access_keys", {"AccessKeyMetadata": [
        {"UserName": "bob", "AccessKeyId": "AKIAIOSFODNN7EXAMPLE", "Status": "Active",
         "CreateDate": NOW - dt.timedelta(days=120)}]})
    iam.add_response("list_attached_user_policies", {"AttachedPolicies": [
        {"PolicyName": "AdministratorAccess", "PolicyArn": "arn:aws:iam::aws:policy/AdministratorAccess"}]})
    env.activate()
    data = collector.collect_iam(env.factory)
    assert data["root_mfa"] is True and data["root_access_keys"] is False
    assert data["password_policy"] is None
    bob = data["users"][0]
    assert bob["console_access"] and not bob["mfa"] and bob["attached_admin"]
    assert bob["access_keys"][0]["age_days"] in (119, 120)
    env.assert_done()


def test_collect_snapshot_end_to_end_feeds_the_scanner():
    env = Env()
    arn = "arn:aws:cloudtrail:ap-south-1:123456789012:trail/t"

    env.add("s3").add_response("list_buckets", {"Buckets": []})
    iam = env.add("iam")
    iam.add_response("get_account_summary", {"SummaryMap": {"AccountMFAEnabled": 0, "AccountAccessKeysPresent": 1}})
    iam.add_response("get_account_password_policy", {"PasswordPolicy": {"MinimumPasswordLength": 8}})
    iam.add_response("list_users", {"Users": [], "IsTruncated": False})

    ec2 = env.add("ec2", REGION)
    ec2.add_response("describe_security_groups", {"SecurityGroups": []})
    ec2.add_response("describe_volumes", {"Volumes": [{"VolumeId": "vol-1", "Encrypted": False}]})
    env.add("rds", REGION).add_response("describe_db_instances", {"DBInstances": [{
        "DBInstanceIdentifier": "db", "DBInstanceClass": "db.t3.micro", "Engine": "postgres",
        "StorageEncrypted": True, "PubliclyAccessible": True, "BackupRetentionPeriod": 1, "MultiAZ": False}]})
    env.add("kms", REGION).add_response("list_keys", {"Keys": [], "Truncated": False})
    env.add("logs", REGION).add_response("describe_log_groups", {"logGroups": [
        {"logGroupName": "/a", "retentionInDays": 30}, {"logGroupName": "/b"}]})
    ct = env.add("cloudtrail", REGION)
    ct.add_response("describe_trails", {"trailList": [{
        "Name": "t", "TrailARN": arn, "IsMultiRegionTrail": True, "LogFileValidationEnabled": True}]},
        expected_params={"includeShadowTrails": False})
    ct.add_response("get_trail_status", {"IsLogging": True})
    env.activate()

    snap = collector.collect_snapshot(env.factory, [REGION], "123456789012")
    validate_snapshot(snap)
    json.dumps(snap)  # must be serialisable for `ccaudit collect`
    assert snap["ebs_volumes"][0] == {"id": "vol-1", "region": REGION, "encrypted": False}
    assert snap["rds_instances"][0]["publicly_accessible"] is True
    assert snap["log_groups"][1]["retention_days"] is None
    assert snap["cloudtrail"][0]["kms_encrypted"] is False

    results, _ = scan(snap)
    failed = {r.check_id for r in results.values() if r.status.value == "FAIL"}
    assert {"IAM-001", "IAM-002", "IAM-003", "ENC-001", "RDS-001", "BCK-001", "LOG-003", "LOG-004"} <= failed
    assert "LOG-001" not in failed and "LOG-002" not in failed
    env.assert_done()
