"""One stuck or dead session on the store's locks stops nobody for long.

Each case runs the caller in its own process, as a tool would, so a caller that
waits without bound fails the case by its timeout instead of hanging the suite.
"""

from __future__ import annotations

import json
import os
import signal
import subprocess
import sys
import textwrap
import time

import pytest

from capabilities_contract.db import connect, migrate

STEPS = [("0001", "CREATE TABLE lockd_items (id int)")]

CALLER = textwrap.dedent("""
    import json, sys, time
    from capabilities_contract.db import DbError, _migrate, connect, migrate
    args = json.loads(sys.argv[1])
    for name, value in args.get("set", {}).items():
        setattr(_migrate, name, value)
    if args.get("stall_after_lock"):
        def _stall(conn):
            time.sleep(600)
        _migrate._snapshot = _stall
    conn = connect(application_name=args["app"])
    started = time.monotonic()
    try:
        result = migrate(conn, "lockd", args["steps"], major=1, minor=0)
        out = {"ok": True, "applied": result.applied, "skipped": result.skipped}
    except DbError as exc:
        out = {"ok": False, "slug": exc.slug, "message": exc.message, "hint": exc.hint}
    out["seconds"] = time.monotonic() - started
    print(json.dumps(out))
""")


@pytest.fixture()
def caller(store, tmp_path):
    script = tmp_path / "caller.py"
    script.write_text(CALLER)
    env = {**os.environ, "XDG_CONFIG_HOME": str(store.config_home)}
    env.pop("CAPABILITIES_STORE_URL", None)
    env.pop("AGENTKIT_STORE_URL", None)

    def start(app: str, steps=STEPS, **args) -> subprocess.Popen:
        payload = json.dumps({"app": app, "steps": steps, **args})
        return subprocess.Popen([sys.executable, str(script), payload], env=env,
                                stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)

    procs: list[subprocess.Popen] = []

    def tracked(*a, **kw):
        proc = start(*a, **kw)
        procs.append(proc)
        return proc

    yield tracked
    for proc in procs:
        if proc.poll() is None:
            proc.kill()
            proc.wait()


def _finish(proc: subprocess.Popen, timeout: float) -> dict:
    try:
        out, err = proc.communicate(timeout=timeout)
    except subprocess.TimeoutExpired:
        proc.kill()
        proc.communicate()
        pytest.fail(f"the caller was still waiting after {timeout}s")
    assert proc.returncode == 0, err
    return json.loads(out)


def _holder(server, *keys: str):
    """An admin session holding each key's transaction lock and then going idle,
    as a session left `idle in transaction` does."""
    conn = server.admin()
    conn.autocommit = False
    for key in keys:
        conn.execute("SELECT pg_advisory_xact_lock(hashtextextended(%s, 0))", (key,))
    return conn


def _backends(server, app: str) -> list[tuple]:
    with server.admin() as admin:
        return admin.execute(
            "SELECT a.pid, a.state, l.granted FROM pg_stat_activity a "
            "LEFT JOIN pg_locks l ON l.pid = a.pid AND l.locktype = 'advisory' "
            "WHERE a.application_name = %s", (app,)).fetchall()


def _wait_until(predicate, timeout: float) -> bool:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if predicate():
            return True
        time.sleep(0.05)
    return predicate()


def test_a_stuck_holder_stops_no_caller_whose_tables_are_in_place(store, caller):
    with connect(application_name="setup") as conn:
        migrate(conn, "lockd", STEPS, major=1, minor=0)
    holder = _holder(store.server, f"capabilities_contract:{store.schema}",
                     f"capabilities_contract:{store.schema}:lockd")
    try:
        result = _finish(caller("settled"), timeout=20)
    finally:
        holder.close()
    assert result["ok"], result
    assert result["applied"] == [] and result["skipped"] == ["0001"]


def test_a_lock_wait_is_bounded_and_reported_as_store_busy(store, caller):
    holder = _holder(store.server, f"capabilities_contract:{store.schema}")
    try:
        result = _finish(caller("bounded", set={"LOCK_WAIT_SECONDS": 1.0}), timeout=20)
    finally:
        holder.close()
    assert not result["ok"] and result["slug"] == "store_busy", result
    assert result["seconds"] < 5
    assert f"capabilities_contract:{store.schema}" in result["message"]
    assert result["hint"]


def test_a_caller_killed_while_waiting_leaves_nothing_queued(store, caller):
    holder = _holder(store.server, f"capabilities_contract:{store.schema}")
    try:
        proc = caller("killed", set={"LOCK_WAIT_SECONDS": 60.0})
        assert _wait_until(lambda: _backends(store.server, "killed"), 20)
        time.sleep(1)
        proc.send_signal(signal.SIGKILL)
        proc.wait()
        assert _wait_until(lambda: not _backends(store.server, "killed"), 5), \
            _backends(store.server, "killed")
        with store.server.admin() as admin:
            queued = admin.execute("SELECT count(*) FROM pg_locks "
                                   "WHERE locktype = 'advisory' AND NOT granted").fetchone()[0]
        assert queued == 0
    finally:
        holder.close()


def test_a_caller_that_stalls_holding_a_lock_is_ended_by_the_server(store, caller):
    with connect(application_name="setup") as conn:
        migrate(conn, "lockd", STEPS, major=1, minor=0)
    steps = [*STEPS, ("0002", "CREATE TABLE lockd_more (id int)")]
    proc = caller("stalled", steps=steps, stall_after_lock=True,
                  set={"LOCK_IDLE_SECONDS": 1})

    def holding():
        return any(granted for _pid, _state, granted in _backends(store.server, "stalled"))

    assert _wait_until(holding, 20), _backends(store.server, "stalled")
    assert _wait_until(lambda: not holding(), 10), _backends(store.server, "stalled")
    assert proc.poll() is None
    with connect(application_name="after") as conn:
        assert migrate(conn, "lockd", steps, major=1, minor=0).applied == ["0002"]
