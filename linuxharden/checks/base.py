import os
import stat as stat_mod
import subprocess
from abc import ABC, abstractmethod
from dataclasses import dataclass
from enum import Enum


class Severity(str, Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class Status(str, Enum):
    PASS = "pass"
    FAIL = "fail"
    SKIP = "skip"
    ERROR = "error"


@dataclass
class CheckResult:
    control_id: str
    title: str
    status: Status
    severity: Severity
    detail: str
    remediation: str
    cis_section: str = ""

    def to_dict(self) -> dict:
        return {
            "control_id": self.control_id,
            "title": self.title,
            "status": self.status.value,
            "severity": self.severity.value,
            "detail": self.detail,
            "remediation": self.remediation,
            "cis_section": self.cis_section,
        }


class Check(ABC):
    control_id: str = ""
    title: str = ""
    severity: Severity = Severity.MEDIUM
    cis_section: str = ""

    @abstractmethod
    def run(self) -> CheckResult:
        ...

    def remediate(self) -> tuple[bool, str]:
        return False, "No remediation implemented"


def _run(cmd: list[str], timeout: int = 10):
    try:
        return subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
    except (subprocess.SubprocessError, FileNotFoundError):
        return None


class SysctlCheck(Check):
    sysctl_key: str = ""
    expected: str = ""

    def run(self) -> CheckResult:
        r = _run(["sysctl", "-n", self.sysctl_key])
        if r is None or r.returncode != 0:
            return CheckResult(
                self.control_id, self.title, Status.ERROR, self.severity,
                f"Cannot read {self.sysctl_key}",
                f"sysctl -w {self.sysctl_key}={self.expected}",
                self.cis_section,
            )
        actual = r.stdout.strip()
        status = Status.PASS if actual == self.expected else Status.FAIL
        return CheckResult(
            self.control_id, self.title, status, self.severity,
            f"{self.sysctl_key} = {actual!r} (expected {self.expected!r})",
            f"sysctl -w {self.sysctl_key}={self.expected}",
            self.cis_section,
        )

    def remediate(self) -> tuple[bool, str]:
        try:
            subprocess.run(
                ["sysctl", "-w", f"{self.sysctl_key}={self.expected}"],
                check=True, capture_output=True, timeout=10,
            )
            with open("/etc/sysctl.d/99-linuxharden.conf", "a") as f:
                f.write(f"{self.sysctl_key} = {self.expected}\n")
            return True, f"Set {self.sysctl_key}={self.expected}"
        except (subprocess.SubprocessError, PermissionError, OSError) as e:
            return False, f"Failed: {e}"


class FilePermCheck(Check):
    target: str = ""
    expected_mode: int = 0o644

    def run(self) -> CheckResult:
        try:
            s = os.stat(self.target)
            actual = stat_mod.S_IMODE(s.st_mode)
            status = Status.PASS if actual == self.expected_mode else Status.FAIL
            return CheckResult(
                self.control_id, self.title, status, self.severity,
                f"mode {oct(actual)} (expected {oct(self.expected_mode)})",
                f"chmod {oct(self.expected_mode)[2:]} {self.target}",
                self.cis_section,
            )
        except FileNotFoundError:
            return CheckResult(
                self.control_id, self.title, Status.ERROR, self.severity,
                f"{self.target} not found", "Investigate missing file",
                self.cis_section,
            )

    def remediate(self) -> tuple[bool, str]:
        try:
            os.chmod(self.target, self.expected_mode)
            return True, f"chmod {oct(self.expected_mode)[2:]} {self.target}"
        except (PermissionError, OSError) as e:
            return False, f"Failed: {e}"


class ServiceCheck(Check):
    service: str = ""
    should_be_active: bool = False

    def run(self) -> CheckResult:
        active_r = _run(["systemctl", "is-active", self.service])
        enabled_r = _run(["systemctl", "is-enabled", self.service])
        is_active = active_r is not None and active_r.stdout.strip() == "active"
        is_enabled = enabled_r is not None and enabled_r.stdout.strip() == "enabled"
        ok = (is_active == self.should_be_active) and (is_enabled == self.should_be_active)
        status = Status.PASS if ok else Status.FAIL
        return CheckResult(
            self.control_id, self.title, status, self.severity,
            f"active={is_active} enabled={is_enabled}",
            self._remediation_str(), self.cis_section,
        )

    def _remediation_str(self) -> str:
        verb = "enable --now" if self.should_be_active else "disable --now"
        return f"systemctl {verb} {self.service}"

    def remediate(self) -> tuple[bool, str]:
        try:
            verb = "enable" if self.should_be_active else "disable"
            subprocess.run(
                ["systemctl", verb, "--now", self.service],
                check=True, capture_output=True, timeout=30,
            )
            state = "enabled" if self.should_be_active else "disabled"
            return True, f"{state} {self.service}"
        except subprocess.SubprocessError as e:
            return False, f"Failed: {e}"


class PackageAbsentCheck(Check):
    package: str = ""

    def run(self) -> CheckResult:
        r = _run(["dpkg-query", "-W", "-f=${Status}", self.package])
        installed = r is not None and r.returncode == 0 and "install ok installed" in r.stdout
        status = Status.FAIL if installed else Status.PASS
        state = "installed" if installed else "not installed"
        return CheckResult(
            self.control_id, self.title, status, self.severity,
            f"{self.package}: {state}",
            f"apt purge -y {self.package}", self.cis_section,
        )

    def remediate(self) -> tuple[bool, str]:
        env = {**os.environ, "DEBIAN_FRONTEND": "noninteractive"}
        try:
            subprocess.run(
                ["apt", "purge", "-y", self.package],
                check=True, capture_output=True, timeout=120, env=env,
            )
            return True, f"Purged {self.package}"
        except subprocess.SubprocessError as e:
            return False, f"Failed: {e}"


class SSHConfigCheck(Check):
    directive: str = ""
    expected: str = ""
    config_path: str = "/etc/ssh/sshd_config"

    def _parse_current(self) -> str | None:
        if not os.path.exists(self.config_path):
            return None
        with open(self.config_path) as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                parts = line.split(None, 1)
                if len(parts) == 2 and parts[0].lower() == self.directive.lower():
                    return parts[1].strip()
        return ""

    def run(self) -> CheckResult:
        actual = self._parse_current()
        if actual is None:
            return CheckResult(
                self.control_id, self.title, Status.ERROR, self.severity,
                f"{self.config_path} not found", "Install openssh-server",
                self.cis_section,
            )
        status = Status.PASS if actual.lower() == self.expected.lower() else Status.FAIL
        return CheckResult(
            self.control_id, self.title, status, self.severity,
            f"{self.directive} = {actual!r} (expected {self.expected!r})",
            f"Set '{self.directive} {self.expected}' in sshd_config",
            self.cis_section,
        )

    def remediate(self) -> tuple[bool, str]:
        try:
            with open(self.config_path) as f:
                lines = f.readlines()
            new_lines: list[str] = []
            found = False
            for line in lines:
                stripped = line.strip()
                if not stripped or stripped.startswith("#"):
                    new_lines.append(line)
                    continue
                parts = stripped.split(None, 1)
                if parts and parts[0].lower() == self.directive.lower():
                    new_lines.append(f"{self.directive} {self.expected}\n")
                    found = True
                else:
                    new_lines.append(line)
            if not found:
                new_lines.append(f"\n{self.directive} {self.expected}\n")
            with open(self.config_path, "w") as f:
                f.writelines(new_lines)
            subprocess.run(
                ["systemctl", "reload", "ssh"],
                capture_output=True, timeout=10,
            )
            return True, f"Set {self.directive} {self.expected}, reloaded ssh"
        except (PermissionError, OSError) as e:
            return False, f"Failed: {e}"
