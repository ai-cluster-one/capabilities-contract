"""Stored executable script bodies: a body is put on disk once, by its digest, as an
executable file, whoever and however many at once ask for it."""

from __future__ import annotations

import hashlib
import os
import stat
import subprocess
import sys
import threading
from pathlib import Path

import pytest

from capabilities_contract.bodies import body_digest, check_body, materialise

BODY = "#!/bin/sh\necho 'héllo'\n"


def _mode(path: Path) -> int:
    return stat.S_IMODE(os.lstat(path).st_mode)


def test_digest_is_sha256_of_utf8():
    assert body_digest(BODY) == hashlib.sha256(BODY.encode("utf-8")).hexdigest()
    assert body_digest(BODY) != body_digest(BODY + "\n")


@pytest.mark.parametrize("body", ["", "echo hi\n", " #!/bin/sh\n", "\n#!/bin/sh\n", b"#!/bin/sh\n",
                                  None])
def test_refuses_a_body_without_shebang(tmp_path, body):
    with pytest.raises(ValueError):
        check_body(body)
    with pytest.raises(ValueError):
        materialise(body, tmp_path / "bodies")
    assert not (tmp_path / "bodies").exists()


def test_writes_executable_file_named_by_digest(tmp_path):
    directory = tmp_path / "a" / "b" / "bodies"
    path = materialise(BODY, directory)
    assert path == directory / body_digest(BODY)
    assert path.read_bytes() == BODY.encode("utf-8")
    assert _mode(path) == 0o700
    assert _mode(directory) & 0o077 == 0
    out = subprocess.run([str(path)], capture_output=True, text=True, check=True).stdout
    assert out == "héllo\n"


def test_accepts_a_str_directory(tmp_path):
    assert materialise(BODY, str(tmp_path)) == tmp_path / body_digest(BODY)


def test_idempotent_reuses_the_file(tmp_path):
    first = materialise(BODY, tmp_path)
    inode = os.stat(first).st_ino
    second = materialise(BODY, tmp_path)
    assert second == first
    assert os.stat(second).st_ino == inode
    assert sorted(p.name for p in tmp_path.iterdir()) == [first.name]


@pytest.mark.parametrize("damage", ["content", "truncated", "mode", "symlink"])
def test_rewrites_a_damaged_existing_file(tmp_path, damage):
    path = materialise(BODY, tmp_path)
    if damage == "content":
        path.write_text("#!/bin/sh\necho 'hellx'\n")
    elif damage == "truncated":
        path.write_text("#!/bin")
    elif damage == "mode":
        os.chmod(path, 0o755)
    else:
        target = tmp_path / "elsewhere"
        target.write_bytes(BODY.encode("utf-8"))
        os.chmod(target, 0o700)
        path.unlink()
        path.symlink_to(target)
    again = materialise(BODY, tmp_path)
    assert again == path
    assert not again.is_symlink()
    assert again.read_bytes() == BODY.encode("utf-8")
    assert _mode(again) == 0o700
    assert not [p for p in tmp_path.iterdir() if p.name.endswith(".tmp")]


def test_concurrent_threads(tmp_path):
    results: list[Path] = []
    errors: list[BaseException] = []
    barrier = threading.Barrier(16)

    def run():
        try:
            barrier.wait()
            for _ in range(20):
                results.append(materialise(BODY, tmp_path / "bodies"))
        except BaseException as exc:
            errors.append(exc)

    threads = [threading.Thread(target=run) for _ in range(16)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()
    assert not errors
    assert set(results) == {tmp_path / "bodies" / body_digest(BODY)}
    assert [p.name for p in (tmp_path / "bodies").iterdir()] == [body_digest(BODY)]


_CHILD = """
import sys
from capabilities_contract.bodies import materialise
directory, body = sys.argv[1], sys.argv[2]
for i in range(200):
    # Each round is a new body, so every round is a fresh race to write it.
    text = f"{body}# {i}\\n"
    path = materialise(text, directory)
    with open(path, "rb") as handle:
        assert handle.read() == text.encode("utf-8"), "partial or wrong file"
"""


def test_concurrent_processes(tmp_path):
    directory = tmp_path / "bodies"
    procs = [subprocess.Popen([sys.executable, "-c", _CHILD, str(directory), BODY],
                              stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
             for _ in range(8)]
    for proc in procs:
        _, err = proc.communicate(timeout=120)
        assert proc.returncode == 0, err
    names = sorted(p.name for p in directory.iterdir())
    assert names == sorted(body_digest(f"{BODY}# {i}\n") for i in range(200))
    for name in names:
        assert _mode(directory / name) == 0o700
