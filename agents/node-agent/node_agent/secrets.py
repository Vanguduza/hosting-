"""Versioned node-local secret delivery. Never returns secret values in receipts."""
import os
import json
import re
import tempfile
import uuid
from pathlib import Path

from .core import OperationError


def install(directory, resource_id, version, values):
    root = Path(directory)
    if not root.is_dir() or root.is_symlink() or root.stat().st_mode & 0o077:
        raise OperationError("Node secret root must be owner-only")
    ident = str(uuid.UUID(str(resource_id)))
    if type(version) is not int or version < 1:
        raise ValueError("Invalid secret revision")
    if not isinstance(values, dict) or not values or len(values) > 16 or not all(
        isinstance(key, str) and re.fullmatch(r"[a-z][a-z0-9_]{0,63}", key)
        and isinstance(value, str) and 1 <= len(value) <= 8192 for key, value in values.items()
    ):
        raise ValueError("Invalid node secret values")
    if len(json.dumps(values).encode()) > 60000:
        raise ValueError("Secret payload too large")
    target = root / ident
    target.mkdir(mode=0o700, exist_ok=True)
    if target.is_symlink() or target.stat().st_mode & 0o077:
        raise OperationError("Node secret resource directory unsafe")
    revision = target / str(version)
    if revision.exists():
        if revision.is_symlink() or not revision.is_dir():
            raise OperationError("Secret revision path unsafe")
        existing = {p.name: p.read_text() for p in revision.iterdir() if p.is_file() and not p.is_symlink()}
        if existing != values or len(list(revision.iterdir())) != len(values):
            raise OperationError("Secret revision replay differs")
        return revision
    temporary = Path(tempfile.mkdtemp(prefix=".revision-", dir=target))
    try:
        os.chmod(temporary, 0o700)
        for key, value in values.items():
            fd = os.open(temporary / key, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            with os.fdopen(fd, "w", encoding="utf-8") as file:
                file.write(value)
                file.flush()
                os.fsync(file.fileno())
        os.rename(temporary, revision)
    except Exception:
        for path in temporary.iterdir():
            path.unlink()
        temporary.rmdir()
        raise
    return revision
