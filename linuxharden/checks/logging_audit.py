from .base import Check, FilePermCheck, ServiceCheck, Severity


class AuditdActiveCheck(ServiceCheck):
    control_id = "4.1.1"
    title = "Ensure auditd is installed and running"
    severity = Severity.HIGH
    cis_section = "4.1.1"
    service = "auditd"
    should_be_active = True


class RsyslogActiveCheck(ServiceCheck):
    control_id = "4.2.1"
    title = "Ensure rsyslog is installed and running"
    severity = Severity.HIGH
    cis_section = "4.2.1"
    service = "rsyslog"
    should_be_active = True


class SyslogPermsCheck(FilePermCheck):
    control_id = "4.2.3"
    title = "Ensure /var/log/syslog has mode 640"
    severity = Severity.MEDIUM
    cis_section = "4.2.3"
    target = "/var/log/syslog"
    expected_mode = 0o640


CHECKS: list[Check] = [
    AuditdActiveCheck(),
    RsyslogActiveCheck(),
    SyslogPermsCheck(),
]
