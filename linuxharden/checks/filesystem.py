from .base import Check, Severity, SysctlCheck


class ASLRCheck(SysctlCheck):
    control_id = "1.5.1"
    title = "Ensure ASLR is enabled"
    severity = Severity.HIGH
    cis_section = "1.5.1"
    sysctl_key = "kernel.randomize_va_space"
    expected = "2"


class DmesgRestrictCheck(SysctlCheck):
    control_id = "1.5.2"
    title = "Ensure dmesg is restricted to root"
    severity = Severity.MEDIUM
    cis_section = "1.5.2"
    sysctl_key = "kernel.dmesg_restrict"
    expected = "1"


class KptrRestrictCheck(SysctlCheck):
    control_id = "1.5.3"
    title = "Ensure kernel pointer leaks are restricted"
    severity = Severity.MEDIUM
    cis_section = "1.5.3"
    sysctl_key = "kernel.kptr_restrict"
    expected = "2"


class SuidDumpableCheck(SysctlCheck):
    control_id = "1.6.1"
    title = "Ensure core dumps of SUID programs are disabled"
    severity = Severity.MEDIUM
    cis_section = "1.6.1"
    sysctl_key = "fs.suid_dumpable"
    expected = "0"


CHECKS: list[Check] = [
    ASLRCheck(),
    DmesgRestrictCheck(),
    KptrRestrictCheck(),
    SuidDumpableCheck(),
]
