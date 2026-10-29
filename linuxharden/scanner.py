from .checks.base import Check, CheckResult, Status
from .checks import (
    filesystem, services, network, logging_audit, access_auth, system_maint,
)


def all_checks() -> list[Check]:
    return (
        filesystem.CHECKS
        + services.CHECKS
        + network.CHECKS
        + logging_audit.CHECKS
        + access_auth.CHECKS
        + system_maint.CHECKS
    )


def run_audit() -> list[CheckResult]:
    results: list[CheckResult] = []
    for check in all_checks():
        try:
            results.append(check.run())
        except Exception as e:
            results.append(CheckResult(
                control_id=check.control_id,
                title=check.title,
                status=Status.ERROR,
                severity=check.severity,
                detail=f"Check crashed: {e}",
                remediation="Investigate crash",
                cis_section=check.cis_section,
            ))
    return results


def run_remediation(results: list[CheckResult], dry_run: bool = False):
    checks_by_id = {c.control_id: c for c in all_checks()}
    actions: list[tuple[str, bool, str]] = []
    for r in results:
        if r.status != Status.FAIL:
            continue
        check = checks_by_id.get(r.control_id)
        if not check:
            continue
        if dry_run:
            actions.append((r.control_id, True, f"[dry-run] {r.remediation}"))
        else:
            ok, msg = check.remediate()
            actions.append((r.control_id, ok, msg))
    return actions
