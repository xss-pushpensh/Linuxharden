from .base import Check, PackageAbsentCheck, ServiceCheck, Severity


class TelnetAbsentCheck(PackageAbsentCheck):
    control_id = "2.1.1"
    title = "Ensure telnet server is not installed"
    severity = Severity.HIGH
    cis_section = "2.1.1"
    package = "telnetd"


class AvahiDisabledCheck(ServiceCheck):
    control_id = "2.2.2"
    title = "Ensure avahi-daemon is disabled"
    severity = Severity.MEDIUM
    cis_section = "2.2.2"
    service = "avahi-daemon"
    should_be_active = False


class CupsDisabledCheck(ServiceCheck):
    control_id = "2.2.4"
    title = "Ensure CUPS is disabled"
    severity = Severity.LOW
    cis_section = "2.2.4"
    service = "cups"
    should_be_active = False


class RshClientAbsentCheck(PackageAbsentCheck):
    control_id = "2.3.1"
    title = "Ensure rsh client is not installed"
    severity = Severity.MEDIUM
    cis_section = "2.3.1"
    package = "rsh-client"


CHECKS: list[Check] = [
    TelnetAbsentCheck(),
    AvahiDisabledCheck(),
    CupsDisabledCheck(),
    RshClientAbsentCheck(),
]
