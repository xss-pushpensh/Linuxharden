from .base import Check, Severity, SysctlCheck


class IPForwardCheck(SysctlCheck):
    control_id = "3.1.1"
    title = "Ensure IP forwarding is disabled"
    severity = Severity.MEDIUM
    cis_section = "3.1.1"
    sysctl_key = "net.ipv4.ip_forward"
    expected = "0"


class SourceRouteCheck(SysctlCheck):
    control_id = "3.2.1"
    title = "Ensure source-routed packets are not accepted"
    severity = Severity.HIGH
    cis_section = "3.2.1"
    sysctl_key = "net.ipv4.conf.all.accept_source_route"
    expected = "0"


class SynCookiesCheck(SysctlCheck):
    control_id = "3.2.8"
    title = "Ensure TCP SYN cookies are enabled"
    severity = Severity.MEDIUM
    cis_section = "3.2.8"
    sysctl_key = "net.ipv4.tcp_syncookies"
    expected = "1"


class IPv6RACheck(SysctlCheck):
    control_id = "3.3.1"
    title = "Ensure IPv6 router advertisements are not accepted"
    severity = Severity.MEDIUM
    cis_section = "3.3.1"
    sysctl_key = "net.ipv6.conf.all.accept_ra"
    expected = "0"


CHECKS: list[Check] = [
    IPForwardCheck(),
    SourceRouteCheck(),
    SynCookiesCheck(),
    IPv6RACheck(),
]
