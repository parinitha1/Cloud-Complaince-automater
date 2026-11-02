import json
import re
import shutil
from pathlib import Path

from ccaudit import report
from ccaudit.cli import main
from ccaudit.engine import scan
from ccaudit.models import Context

ROOT = Path(__file__).resolve().parents[1]
INSECURE = str(ROOT / "samples" / "insecure_account.json")
SECURE = str(ROOT / "samples" / "secure_account.json")


def test_json_report_structure(insecure):
    results, fws = scan(insecure, Context(allowed_regions=["ap-south-1"]))
    data = json.loads(report.to_json(results, fws, {"account_id": "1"}))
    assert {f["id"] for f in data["frameworks"]} == {"iso27001", "soc2", "dpdp"}
    assert len(data["checks"]) == len(results)
    severities = [c["severity"] for c in data["checks"]]
    rank = {"critical": 4, "high": 3, "medium": 2, "low": 1}
    assert [rank[s] for s in severities] == sorted((rank[s] for s in severities), reverse=True)


def test_html_escapes_resource_names(insecure):
    insecure["s3_buckets"][0]["name"] = "<script>alert(1)</script>"
    results, fws = scan(insecure)
    out = report.to_html(results, fws, {"account_id": "<b>x</b>"})
    assert "<script>alert(1)</script>" not in out
    assert "&lt;script&gt;alert(1)&lt;/script&gt;" in out
    assert "<b>x</b>" not in out


def test_html_is_self_contained(secure):
    results, fws = scan(secure)
    out = report.to_html(results, fws)
    assert not re.search(r"(src|href)=['\"]https?://", out)
    assert out.startswith("<!doctype html>")


def test_console_report_mentions_failures(insecure):
    results, fws = scan(insecure)
    text = report.to_console(results, fws)
    assert "SG-001" in text and "FRAMEWORK SCORES" in text


def test_console_report_clean_account(secure):
    results, fws = scan(secure)
    assert "None." in report.to_console(results, fws)


class TestCli:
    def test_scan_secure_passes_with_fail_on(self, capsys):
        assert main(["scan", "--snapshot", SECURE, "--fail-on", "low", "--allowed-regions", "india"]) == 0

    def test_scan_insecure_fails_with_fail_on_critical(self):
        assert main(["scan", "--snapshot", INSECURE, "--fail-on", "critical"]) == 1

    def test_scan_insecure_default_exit_zero(self):
        assert main(["scan", "--snapshot", INSECURE]) == 0

    def test_fail_on_threshold_respected(self, tmp_path):
        # only low/medium findings remain after fixing criticals and highs
        data = json.loads(Path(SECURE).read_text())
        data["s3_buckets"][0]["logging"] = False  # low severity failure
        p = tmp_path / "s.json"
        p.write_text(json.dumps(data))
        assert main(["scan", "--snapshot", str(p), "--fail-on", "medium"]) == 0
        assert main(["scan", "--snapshot", str(p), "--fail-on", "low"]) == 1

    def test_writes_report_files(self, tmp_path):
        out = tmp_path / "out"
        code = main(["scan", "--snapshot", INSECURE, "--format", "json,html", "--out-dir", str(out)])
        assert code == 0
        assert json.loads((out / "report.json").read_text())["frameworks"]
        assert (out / "report.html").read_text().startswith("<!doctype html>")

    def test_framework_filter(self, tmp_path):
        out = tmp_path / "o"
        main(["scan", "--snapshot", INSECURE, "--framework", "dpdp", "--format", "json", "--out-dir", str(out)])
        data = json.loads((out / "report.json").read_text())
        assert [f["id"] for f in data["frameworks"]] == ["dpdp"]

    def test_missing_file_returns_2(self, capsys):
        assert main(["scan", "--snapshot", "/nonexistent.json"]) == 2

    def test_bad_snapshot_returns_2(self, tmp_path, capsys):
        p = tmp_path / "bad.json"
        p.write_text("[]")
        assert main(["scan", "--snapshot", str(p)]) == 2
        assert "error" in capsys.readouterr().err

    def test_unknown_framework_returns_2(self):
        assert main(["scan", "--snapshot", SECURE, "--framework", "hipaa"]) == 2

    def test_unknown_format_returns_2(self):
        assert main(["scan", "--snapshot", SECURE, "--format", "pdf"]) == 2

    def test_list_checks(self, capsys):
        assert main(["list-checks"]) == 0
        assert "S3-001" in capsys.readouterr().out

    def test_residency_flag(self, tmp_path):
        out = tmp_path / "o"
        main(["scan", "--snapshot", INSECURE, "--allowed-regions", "india", "--format", "json", "--out-dir", str(out)])
        checks = {c["id"]: c for c in json.loads((out / "report.json").read_text())["checks"]}
        assert checks["RES-001"]["status"] == "FAIL"
        main(["scan", "--snapshot", INSECURE, "--format", "json", "--out-dir", str(out)])
        checks = {c["id"]: c for c in json.loads((out / "report.json").read_text())["checks"]}
        assert checks["RES-001"]["status"] == "N/A"
