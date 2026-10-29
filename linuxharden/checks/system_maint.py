from .base import Check, FilePermCheck, Severity


class PasswdPermsCheck(FilePermCheck):
    control_id = "6.1.2"
    title = "Ensure /etc/passwd has mode 644"
    severity = Severity.HIGH
    cis_section = "6.1.2"
    target = "/etc/passwd"
    expected_mode = 0o644


class ShadowPermsCheck(FilePermCheck):
    control_id = "6.1.3"
    title = "Ensure /etc/shadow has mode 640"
    severity = Severity.CRITICAL
    cis_section = "6.1.3"
    target = "/etc/shadow"
    expected_mode = 0o640


CHECKS: list[Check] = [
    PasswdPermsCheck(),
    ShadowPermsCheck(),
]
