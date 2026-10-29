from linuxharden.scanner import all_checks
from linuxharden.checks.base import Status


def test_all_checks_load():
    checks = all_checks()
    assert len(checks) == 20, f"expected 20 checks, got {len(checks)}"
    for c in checks:
        assert c.control_id, f"missing control_id on {type(c).__name__}"
        assert c.title, f"missing title on {type(c).__name__}"
        assert c.cis_section, f"missing cis_section on {type(c).__name__}"


def test_each_check_runs():
    valid = {Status.PASS, Status.FAIL, Status.SKIP, Status.ERROR}
    for c in all_checks():
        result = c.run()
        assert result.status in valid, f"{c.control_id} returned {result.status}"


def test_control_ids_unique():
    ids = [c.control_id for c in all_checks()]
    assert len(ids) == len(set(ids)), f"duplicate control IDs: {ids}"
