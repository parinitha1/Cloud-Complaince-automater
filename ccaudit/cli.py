"""Command line interface: collect, scan, list-checks."""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from . import __version__
from .checks import REGISTRY
from .engine import SnapshotError, load_frameworks, load_snapshot, scan
from .models import Context, SEVERITY_RANK, Status
from . import report

INDIA_REGIONS = ["ap-south-1", "ap-south-2"]


def _csv(value: str) -> list[str]:
    return [v.strip() for v in value.split(",") if v.strip()]


def _regions_arg(value: str | None) -> list[str] | None:
    if value is None or value.lower() == "any":
        return None
    if value.lower() == "india":
        return INDIA_REGIONS
    return _csv(value)


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="ccaudit", description=__doc__)
    p.add_argument("--version", action="version", version=f"ccaudit {__version__}")
    sub = p.add_subparsers(dest="command", required=True)

    c = sub.add_parser("collect", help="read-only collection from AWS into a snapshot JSON file")
    c.add_argument("--profile", help="AWS profile name")
    c.add_argument("--regions", default="ap-south-1", help="comma separated regions (default ap-south-1)")
    c.add_argument("--out", default="snapshot.json")

    s = sub.add_parser("scan", help="evaluate a snapshot (or live account) against frameworks")
    src = s.add_mutually_exclusive_group(required=True)
    src.add_argument("--snapshot", help="path to a snapshot JSON file")
    src.add_argument("--live", action="store_true", help="collect from AWS first (read-only)")
    s.add_argument("--profile")
    s.add_argument("--regions", default="ap-south-1", help="regions to collect when using --live")
    s.add_argument("--framework", action="append", help="iso27001, soc2, dpdp (repeatable; default all)")
    s.add_argument("--format", default="console", help="comma list of console,json,html")
    s.add_argument("--out-dir", default="reports")
    s.add_argument("--fail-on", default="none", choices=["none", "low", "medium", "high", "critical"],
                   help="exit 1 if a failed check has at least this severity")
    s.add_argument("--allowed-regions", default=None,
                   help="'india', 'any' or comma list; enables the RES-001 residency check")
    s.add_argument("--max-key-age", type=int, default=90)
    s.add_argument("--min-password-length", type=int, default=14)
    s.add_argument("--min-backup-days", type=int, default=7)
    s.add_argument("--min-log-retention", type=int, default=365)

    sub.add_parser("list-checks", help="print all checks and framework mappings")

    w = sub.add_parser("serve", help="open the local web UI in your browser")
    w.add_argument("--port", type=int, default=8000)
    w.add_argument("--no-browser", action="store_true", help="do not open a browser tab automatically")
    return p


def cmd_serve(args) -> int:
    from .web import serve
    try:
        serve(port=args.port, open_browser=not args.no_browser)
    except OSError as exc:
        print(f"error: could not start server on port {args.port}: {exc}. Try --port 8001.", file=sys.stderr)
        return 2
    return 0


def _live_snapshot(profile: str | None, regions: list[str]) -> dict:
    from .collector import collect_snapshot, make_client_factory
    cf = make_client_factory(profile, regions[0])
    account = cf("sts", None).get_caller_identity()["Account"]
    return collect_snapshot(cf, regions, account)


def cmd_collect(args) -> int:
    snap = _live_snapshot(args.profile, _csv(args.regions))
    Path(args.out).write_text(json.dumps(snap, indent=2, default=str), encoding="utf-8")
    print(f"Snapshot written to {args.out}")
    return 0


def cmd_list(_args) -> int:
    fws = load_frameworks()
    usage: dict[str, list[str]] = {cid: [] for cid in REGISTRY}
    for fw in fws:
        for c in fw["controls"]:
            for cid in c["checks"]:
                usage[cid].append(f'{fw["id"]}:{c["id"]}')
    for cid, (meta, _fn) in REGISTRY.items():
        print(f"{cid:<8} {meta.severity:<9} {meta.title}")
        print(f"{'':<18} maps to: {', '.join(usage[cid]) or '-'}")
    return 0


def cmd_scan(args) -> int:
    formats = _csv(args.format)
    bad = [f for f in formats if f not in ("console", "json", "html")]
    if bad:
        print(f"unknown format(s): {bad}", file=sys.stderr)
        return 2

    if args.live:
        snapshot = _live_snapshot(args.profile, _csv(args.regions))
        source = "live AWS scan"
    else:
        snapshot = load_snapshot(args.snapshot)
        source = Path(args.snapshot).name

    ctx = Context(allowed_regions=_regions_arg(args.allowed_regions), max_key_age_days=args.max_key_age,
                  min_password_length=args.min_password_length, min_backup_days=args.min_backup_days,
                  min_log_retention_days=args.min_log_retention)
    results, fws = scan(snapshot, ctx, args.framework)
    meta = {"account_id": snapshot.get("account_id"), "source": source,
            "collected_at": snapshot.get("collected_at")}

    out_dir = Path(args.out_dir)
    if "console" in formats:
        print(report.to_console(results, fws))
    if "json" in formats or "html" in formats:
        out_dir.mkdir(parents=True, exist_ok=True)
    if "json" in formats:
        (out_dir / "report.json").write_text(report.to_json(results, fws, meta), encoding="utf-8")
        print(f"Wrote {out_dir / 'report.json'}")
    if "html" in formats:
        (out_dir / "report.html").write_text(report.to_html(results, fws, meta), encoding="utf-8")
        print(f"Wrote {out_dir / 'report.html'}")

    if args.fail_on != "none":
        threshold = SEVERITY_RANK[args.fail_on]
        if any(r.status == Status.FAIL and SEVERITY_RANK[r.severity] >= threshold for r in results.values()):
            return 1
    return 0


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        return {"collect": cmd_collect, "scan": cmd_scan, "list-checks": cmd_list,
                "serve": cmd_serve}[args.command](args)
    except (SnapshotError, ValueError, FileNotFoundError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    except Exception as exc:  # AWS auth / network problems surface here
        if exc.__class__.__module__.startswith(("botocore", "boto3")):
            print(f"AWS error: {exc}", file=sys.stderr)
            return 2
        raise


if __name__ == "__main__":
    sys.exit(main())
