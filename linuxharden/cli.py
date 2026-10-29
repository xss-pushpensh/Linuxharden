import argparse
import json
import os
import sys
from pathlib import Path

from .checks.base import Status
from .remediator.backup import backup_paths, list_backups, restore_backup
from .reporter.html import write_html_report
from .reporter.scoring import weighted_score
from .scanner import run_audit, run_remediation


def _require_root() -> None:
    if os.geteuid() != 0:
        print("ERROR: this command requires root. Use sudo.")
        sys.exit(1)


def _print_plain_table(results) -> None:
    print()
    print(f"{'Control':<10} {'Status':<8} {'Severity':<10} Title")
    print("-" * 80)
    for r in results:
        print(f"{r.control_id:<10} {r.status.value:<8} {r.severity.value:<10} {r.title}")
    print("-" * 80)


def cmd_audit(args) -> None:
    results = run_audit()
    _print_plain_table(results)

    score = weighted_score(results)
    passed = sum(1 for r in results if r.status == Status.PASS)
    print(f"\nCompliance score: {score:.1f}%   ({passed}/{len(results)} passed)")

    if args.json:
        Path(args.json).write_text(
            json.dumps([r.to_dict() for r in results], indent=2)
        )
        print(f"JSON written to {args.json}")

    if args.html:
        write_html_report(results, Path(args.html))
        print(f"HTML written to {args.html}")


def cmd_harden(args) -> None:
    _require_root()

    results = run_audit()
    failing = [r for r in results if r.status == Status.FAIL]

    if not failing:
        print("Nothing to remediate — already compliant.")
        return

    print(f"\n{len(failing)} control(s) failing:")
    for r in failing:
        print(f"  - {r.control_id}  {r.title}")

    if args.dry_run:
        print("\nDry-run actions:")
        for cid, ok, msg in run_remediation(results, dry_run=True):
            print(f"  {cid}: {msg}")
        return

    if not args.yes:
        print("\nBackup of /etc and /boot will be created, then changes applied.")
        if input("Type 'yes' to continue: ").strip().lower() != "yes":
            print("Aborted.")
            return

    archive = backup_paths(["/etc", "/boot"], label="pre-harden")
    print(f"Backup: {archive}")

    actions = run_remediation(results, dry_run=False)
    for cid, ok, msg in actions:
        tag = "OK  " if ok else "FAIL"
        print(f"  [{tag}] {cid}: {msg}")


def cmd_rollback(args) -> None:
    _require_root()
    backups = list_backups()
    if not backups:
        print("No backups found.")
        return

    if args.list:
        for i, b in enumerate(backups):
            print(f"  [{i}] {b}")
        return

    target = Path(args.to) if args.to else backups[0]
    print(f"Restoring from: {target}")
    if input("Type 'yes' to confirm: ").strip().lower() != "yes":
        print("Aborted.")
        return

    if restore_backup(target):
        print(f"Restored from {target}")
    else:
        print(f"Restore FAILED for {target}")


def main() -> None:
    p = argparse.ArgumentParser(prog="linuxharden")
    sub = p.add_subparsers(dest="cmd", required=True)

    audit = sub.add_parser("audit", help="Audit system against CIS controls")
    audit.add_argument("--json", help="Write JSON report to this path")
    audit.add_argument("--html", help="Write HTML report to this path")
    audit.set_defaults(func=cmd_audit)

    harden = sub.add_parser("harden", help="Apply remediations")
    harden.add_argument("--dry-run", action="store_true")
    harden.add_argument("--yes", action="store_true")
    harden.set_defaults(func=cmd_harden)

    rollback = sub.add_parser("rollback", help="Restore from a backup")
    rollback.add_argument("--to", help="Specific backup archive")
    rollback.add_argument("--list", action="store_true")
    rollback.set_defaults(func=cmd_rollback)

    args = p.parse_args()
    args.func(args)


if __name__ == "__main__":
    main()
