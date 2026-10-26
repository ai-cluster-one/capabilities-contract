"""Stored executable script bodies, run through one shared piece.

A body is the text of an executable script kept in the store - an automation's
`script_body`, a stored tasks hook - starting with a `#!` line. `materialise` puts it
on disk as an executable file named by its content's sha256, so the same body is
written once and run from the same path by every process that runs it.
"""

from __future__ import annotations

import contextlib
import hashlib
import os
import stat
import tempfile
from pathlib import Path

__all__ = ["body_digest", "check_body", "materialise"]

_MODE = 0o700


def body_digest(body: str) -> str:
    """The sha256 hex digest of the body's UTF-8 bytes."""
    return hashlib.sha256(body.encode("utf-8")).hexdigest()


def check_body(body: str) -> None:
    """Raise ValueError unless the body is a non-empty str starting with "#!"."""
    if not isinstance(body, str):
        raise ValueError(f"a script body is a str, not {type(body).__name__}")
    if not body.startswith("#!"):
        raise ValueError("a script body starts with a #! line")


def _is_current(path: Path, data: bytes) -> bool:
    """Whether `path` is a regular file, mode 0700, holding exactly `data`."""
    try:
        info = os.lstat(path)
    except FileNotFoundError:
        return False
    if not stat.S_ISREG(info.st_mode) or stat.S_IMODE(info.st_mode) != _MODE:
        return False
    if info.st_size != len(data):
        return False
    try:
        with open(path, "rb") as handle:
            return handle.read() == data
    except OSError:
        return False


def materialise(body: str, directory: os.PathLike | str) -> Path:
    """Return `<directory>/<body_digest(body)>`, an executable file holding the body.

    The directory is made (mode 0700, with its parents) when missing. A file already
    there with the same content and mode 0700 is reused; anything else at that path is
    replaced atomically by a file written beside it, so a process running it never
    sees a partial file and two processes materialising at once both return a whole one.
    """
    check_body(body)
    data = body.encode("utf-8")
    folder = Path(directory)
    folder.mkdir(mode=_MODE, parents=True, exist_ok=True)
    path = folder / body_digest(body)
    if _is_current(path, data):
        return path
    fd, temp = tempfile.mkstemp(dir=folder, prefix=f".{path.name}.", suffix=".tmp")
    try:
        with os.fdopen(fd, "wb") as handle:
            handle.write(data)
            handle.flush()
            os.fsync(handle.fileno())
        os.chmod(temp, _MODE)
        os.replace(temp, path)
    except BaseException:
        with contextlib.suppress(FileNotFoundError):
            os.unlink(temp)
        raise
    return path
