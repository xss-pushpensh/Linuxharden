from .base import Check, FilePermCheck, SSHConfigCheck, Severity


class SSHRootLoginCheck(SSHConfigCheck):
    control_id = "5.2.1"
    title = "Ensure SSH root login is disabled"
    severity = Severity.CRITICAL
    cis_section = "5.2.1"
    directive = "PermitRootLogin"
    expected = "no"


class SSHS11ForwardCheck(SSHConfigCheck):
    control_id = "5.2.4"
    title = "Ensure SSH X11 forwarding is disabled"
    severity = Severity.LOW
    cis_section = "5.2.4"
    directive = "X11Forwarding"
    expected = "no"


class SudoersPermsCheck(FilePermCheck):
    control_id = "5.3.1"
    title = "Ensure /etc/sudoers has mode 440"
    severity = Severity.HIGH
    cis_section = "5.3.1"
    target = "/etc/sudoers"
    expected_mode = 0o440


CHECKS: list[Check] = [
    SSHRootLoginCheck(),
    SSHS11ForwardCheck(),
    SudoersPermsCheck(),
]
