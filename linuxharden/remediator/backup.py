import hashlib
import tarfile
import time
from pathlib import Path


BACKUP_ROOT = Path("/var/backups/linuxharden")


def backup_paths(paths: list[str], label: str = "pre-harden") -> Path:
    BACKUP_ROOT.mkdir(parents=True, exist_ok=True)
    ts = time.strftime("%Y%m%d_%H%M%S")
    archive = BACKUP_ROOT / f"{label}_{ts}.tar.gz"

    with tarfile.open(archive, "w:gz") as tar:
        for p in paths:
            if Path(p).exists():
                tar.add(p, arcname=p.lstrip("/"))

    digest = hashlib.sha256(archive.read_bytes()).hexdigest()
    checksum_file = archive.with_suffix(".tar.gz.sha256")
    checksum_file.write_text(f"{digest}  {archive.name}\n")
    return archive


def list_backups() -> list[Path]:
    if not BACKUP_ROOT.exists():
        return []
    return sorted(BACKUP_ROOT.glob("*.tar.gz"), reverse=True)


def restore_backup(archive: Path) -> bool:
    if not archive.exists():
        return False
    try:
        with tarfile.open(archive, "r:gz") as tar:
            tar.extractall(path="/")
        return True
    except (tarfile.TarError, PermissionError, OSError):
        return False
