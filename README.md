# Cloud Compliance Automator (`ccaudit`)

Compliance-as-code for cloud accounts. It maps technical controls from **ISO/IEC 27001:2022**, **SOC 2** and
India's **DPDP Act, 2023** onto 23 automated checks, then scores each framework and produces console, JSON and
HTML reports with remediation steps.

```
AWS account ──collect (read-only)──> snapshot.json ──checks──> controls ──> framework scores + reports
                                        ^ also works offline on saved snapshots
```

## Quick start (no AWS account needed)

```bash
pip install -e ".[dev]"
python -m ccaudit scan --snapshot samples/insecure_account.json --allowed-regions india --format console,html,json
open reports/report.html            # or xdg-open on Linux
python -m ccaudit scan --snapshot samples/secure_account.json --allowed-regions india   # 100% on all frameworks
pytest -q
```

## Web UI

```bash
python -m ccaudit serve          # opens http://127.0.0.1:8000 in your browser
python -m ccaudit serve --port 8001 --no-browser
```

Pick a sample or upload a snapshot, choose frameworks, regions and thresholds, and click **Run scan**.
It listens on localhost only and uses the standard library (no extra install). Stop it with Ctrl+C.
The UI scans snapshot files; use `collect` or `scan --live` on the command line to read a real account.

## Scanning a real AWS account

```bash
# 1. Create a read-only identity using policies/ccaudit-readonly.json, configure an AWS profile for it.
# 2. Collect a snapshot (read-only API calls only), or scan live in one step:
python -m ccaudit collect --profile audit --regions ap-south-1,ap-south-2 --out snapshot.json
python -m ccaudit scan --snapshot snapshot.json --allowed-regions india --format console,html
python -m ccaudit scan --live --profile audit --regions ap-south-1 --format html
```

Keep snapshots private: they describe your security posture.

## CI gate

`--fail-on critical|high|medium|low` makes the process exit with code 1 when any failed check has at least
that severity. Exit code 2 means a usage or input error (bad file, unknown framework, AWS auth failure).
`.github/workflows/ci.yml` shows the pattern.

## Checks

| ID | Severity | What it verifies |
|----|----------|------------------|
| S3-001 | critical | All four S3 Block Public Access settings on |
| S3-002 | high | Default bucket encryption |
| S3-003 | medium | Bucket versioning |
| S3-004 | low | Server access logging |
| S3-005 | medium | Bucket policy denies non-TLS requests |
| SG-001 | critical | No world-open SSH/RDP (including all-traffic rules) |
| SG-002 | high | No other world-open ports besides 80/443 |
| IAM-001 | critical | Root MFA |
| IAM-002 | critical | No root access keys |
| IAM-003 | medium | Password policy minimum length (default 14) |
| IAM-004 | high | MFA for console users |
| IAM-005 | medium | Access keys rotated (default 90 days) |
| IAM-006 | medium | No AdministratorAccess attached directly to users |
| LOG-001 | critical | Multi-region CloudTrail trail actively logging |
| LOG-002 | medium | CloudTrail log file validation |
| LOG-003 | medium | CloudTrail encrypted with KMS |
| LOG-004 | medium | CloudWatch log retention (default 365 days; never-expire passes) |
| ENC-001 | high | EBS volumes encrypted |
| ENC-002 | high | RDS storage encrypted |
| ENC-003 | medium | Customer-managed KMS key rotation |
| RDS-001 | critical | RDS not publicly accessible |
| BCK-001 | medium | RDS backup retention (default 7 days) |
| RES-001 | medium | Data stores in approved regions (only runs with `--allowed-regions`) |

`python -m ccaudit list-checks` prints each check with the framework controls it maps to.

## How scoring works

- A **check** is FAIL if any resource fails, PASS if resources exist and all pass, and **N/A** if there is
  nothing to evaluate or the section was not collected. N/A is never counted as a pass.
- A **control** FAILs if any mapped check fails, PASSes if at least one mapped check passes and none fail,
  and is N/A otherwise.
- A **framework score** is passing controls divided by evaluated (pass + fail) controls.

Because one failing resource fails its whole control, scores are deliberately strict.

## Extending

- **New check:** add a function with the `@check(...)` decorator in `ccaudit/checks.py`, add test cases to
  `tests/test_checks.py`, and reference its ID from a control in `ccaudit/frameworks/*.json`.
  `tests/test_engine.py` fails if a check is unmapped or a mapping points to a missing check.
- **New framework:** drop a JSON file in `ccaudit/frameworks/` using the same shape (for example CIS AWS
  Foundations or PCI DSS).
- **Another cloud:** write a collector that emits the same snapshot sections; the checks and reports are
  provider-neutral.

## Limitations (read before relying on results)

- **Mappings are indicative.** They are an engineering interpretation of what each framework asks for, not an
  auditor's or lawyer's opinion. ISO 27001, SOC 2 and the DPDP Act all contain organisational, legal and
  process requirements (policies, consent, notices, breach reporting duties, vendor management, data
  principal rights) that no cloud scan can verify. Confirm the DPDP Act, the DPDP Rules and any sector
  regulator requirements with counsel.
- **RES-001 is a visibility check.** The DPDP Act does not by itself forbid storing data outside India, but
  sector regulations or contracts might. Set `--allowed-regions` to match your own policy.
- **Point-in-time.** A snapshot is not evidence of continuous control operation, which SOC 2 Type II and ISO
  surveillance audits look for.
- **AWS only, partial coverage.** Checks look at S3, EC2 security groups, EBS, RDS, KMS, IAM users, CloudTrail
  and CloudWatch Logs. They do not evaluate IAM policy contents beyond the admin-policy check, organisation
  SCPs, Lambda, EKS, WAF, or resources outside the regions you pass.
- **Collector tested with stubbed API responses**, not against a live account. Run it against a sandbox
  account first. Large accounts may need pagination and throttling tuning.
- Key rotation (ENC-003) only covers customer-managed symmetric KMS keys with AWS-generated key material.

## Layout

```
ccaudit/
  checks.py        23 checks (registry + decorator)
  engine.py        snapshot loading, check execution, control roll-up
  frameworks/      iso27001.json, soc2.json, dpdp.json (control -> check mappings)
  collector.py     read-only AWS collector (boto3, lazy import)
  report.py        console / JSON / HTML writers
  web.py           local web UI (python -m ccaudit serve)
  cli.py           collect, scan, list-checks, serve
samples/           insecure and secure example snapshots
policies/          least-privilege IAM policy for the collector
tests/             126 tests (checks, roll-up, reports, CLI, web UI, collector with botocore Stubber)
```
