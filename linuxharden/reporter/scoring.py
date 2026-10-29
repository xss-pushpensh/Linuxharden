from ..checks.base import CheckResult, Severity, Status


WEIGHTS = {
    Severity.CRITICAL: 4,
    Severity.HIGH: 3,
    Severity.MEDIUM: 2,
    Severity.LOW: 1,
}


def weighted_score(results: list[CheckResult]) -> float:
    total = 0
    passed = 0
    for r in results:
        if r.status == Status.SKIP:
            continue
        w = WEIGHTS.get(r.severity, 1)
        total += w
        if r.status == Status.PASS:
            passed += w
    return (passed / total * 100) if total else 0.0
