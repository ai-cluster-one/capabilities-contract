"""Transaction connections through a real transaction-mode pooler: PgBouncer with
pool_mode=transaction and one server connection, so every client's transactions run on
the same server session in turn. Runs when CAPABILITIES_CONTRACT_TEST_PGBOUNCER names a
pgbouncer executable; otherwise it skips."""

from __future__ import annotations

import os
import socket
import subprocess
import time
from pathlib import Path

import psycopg
import pytest

from capabilities_contract.db import DbError, connect, disconnect, migrate

PGBOUNCER_ENV = "CAPABILITIES_CONTRACT_TEST_PGBOUNCER"


def _free_port() -> int:
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


@pytest.fixture()
def pooler(server, tmp_path):
    binary = os.environ.get(PGBOUNCER_ENV)
    if not binary or not Path(binary).is_file():
        pytest.skip(f"{PGBOUNCER_ENV} does not name a pgbouncer executable")
    if not server.rootcert:
        pytest.skip("the pooler needs the test cluster's own certificate")
    cert = Path(server.rootcert)
    port = _free_port()
    users = tmp_path / "users.txt"
    users.write_text(f'"{server.user}" "{server.password}"\n')
    ini = tmp_path / "pgbouncer.ini"
    ini.write_text(
        "[databases]\n"
        f"{server.database} = host={server.host} port={server.port} dbname={server.database}\n"
        "[pgbouncer]\n"
        f"listen_addr = 127.0.0.1\nlisten_port = {port}\nunix_socket_dir =\n"
        f"auth_type = plain\nauth_file = {users}\n"
        "pool_mode = transaction\ndefault_pool_size = 1\nmin_pool_size = 0\n"
        "max_prepared_statements = 0\nserver_reset_query =\n"
        "server_tls_sslmode = require\n"
        f"client_tls_sslmode = require\nclient_tls_cert_file = {cert}\n"
        f"client_tls_key_file = {cert.parent / 'server.key'}\n"
        f"logfile = {tmp_path / 'pgbouncer.log'}\npidfile = {tmp_path / 'pgbouncer.pid'}\n")
    proc = subprocess.Popen([binary, str(ini)], stdout=subprocess.DEVNULL,
                            stderr=subprocess.DEVNULL)
    deadline = time.monotonic() + 15
    while True:
        try:
            socket.create_connection(("127.0.0.1", port), timeout=1).close()
            break
        except OSError:
            if time.monotonic() > deadline or proc.poll() is not None:
                proc.kill()
                pytest.fail("pgbouncer did not start")
            time.sleep(0.1)
    yield port
    # PgBouncer shuts down once its clients are gone: close this process's.
    disconnect(every=True)
    proc.terminate()
    proc.wait(timeout=10)


def test_transaction_connections_share_one_server_session_cleanly(store, pooler):
    store.write(transaction_host="127.0.0.1", transaction_port=pooler)
    with connect(application_name="pooled", transaction=True) as first, \
            connect(application_name="pooled", transaction=True) as second:
        migrate(first, "demo", [("0001", "CREATE TABLE demo_rows (id int, who text)")],
                major=1, minor=0)
        pids = set()
        for round_ in range(8):
            for name, conn in (("first", first), ("second", second)):
                conn.execute("INSERT INTO demo_rows VALUES (%s, %s)", (round_, name))
                pids.add(conn.execute("SELECT pg_backend_pid()").fetchone()[0])
                assert conn.execute("SHOW search_path").fetchone() == (store.schema,)
                conn.commit()
        assert len(pids) == 1  # one server session served both clients
        second.autocommit = True
        for _ in range(8):
            assert second.execute("SELECT count(*) FROM demo_rows").fetchone() == (16,)
        assert first.execute("SELECT count(*) FROM pg_prepared_statements").fetchone() == (0,)
        assert first.execute("SELECT count(*) FROM pg_listening_channels()").fetchone() == (0,)
        first.commit()


def test_a_session_binding_through_the_pooler_would_leak(store, pooler):
    """Why the transaction path binds per transaction: a session SET made by one client
    is what the next client finds on the shared server session."""
    from dataclasses import replace

    from capabilities_contract.db import resolve_setting
    setting = replace(resolve_setting(None), host="127.0.0.1", port=pooler)
    kwargs = setting.connect_kwargs()
    with psycopg.connect(**kwargs, autocommit=True) as one, \
            psycopg.connect(**kwargs, autocommit=True) as two:
        one.execute("SET search_path TO leaked_schema")
        assert two.execute("SHOW search_path").fetchone() == ("leaked_schema",)
        one.execute("RESET search_path")


def test_a_read_only_default_works_through_the_pooler(store, pooler, monkeypatch):
    """A pooler in transaction mode refuses startup options; the read-only
    default reaches each transaction instead."""
    store.write(transaction_host="127.0.0.1", transaction_port=pooler)
    monkeypatch.setenv("PGOPTIONS", "-c default_transaction_read_only=on")
    with connect(application_name="pooled", transaction=True) as conn:
        assert conn.execute("SHOW transaction_read_only").fetchone() == ("on",)
        with pytest.raises(psycopg.errors.ReadOnlySqlTransaction):
            conn.execute("CREATE TABLE demo_written (id int)")


def test_a_store_that_does_not_answer_behind_the_pooler_is_refused_in_time(
        store, server, tmp_path):
    """The pooler accepts the client and holds it while the store behind it
    does not answer; the client gives up within its connect timeout."""
    binary = os.environ.get(PGBOUNCER_ENV)
    if not binary or not Path(binary).is_file():
        pytest.skip(f"{PGBOUNCER_ENV} does not name a pgbouncer executable")
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        dead = sock.getsockname()[1]
    port = _free_port()
    cert = Path(server.rootcert)
    (tmp_path / "users.txt").write_text(f'"{server.user}" "{server.password}"\n')
    (tmp_path / "pgbouncer.ini").write_text(
        "[databases]\n"
        f"{server.database} = host=127.0.0.1 port={dead} dbname={server.database}\n"
        "[pgbouncer]\n"
        f"listen_addr = 127.0.0.1\nlisten_port = {port}\nunix_socket_dir =\n"
        f"auth_type = plain\nauth_file = {tmp_path / 'users.txt'}\n"
        "pool_mode = transaction\ndefault_pool_size = 1\n"
        f"client_tls_sslmode = require\nclient_tls_cert_file = {cert}\n"
        f"client_tls_key_file = {cert.parent / 'server.key'}\n"
        f"logfile = {tmp_path / 'pgbouncer.log'}\n")
    proc = subprocess.Popen([binary, str(tmp_path / "pgbouncer.ini")],
                            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    try:
        deadline = time.monotonic() + 15
        while True:
            try:
                socket.create_connection(("127.0.0.1", port), timeout=1).close()
                break
            except OSError:
                assert time.monotonic() < deadline and proc.poll() is None
                time.sleep(0.1)
        store.write(transaction_host="127.0.0.1", transaction_port=port)
        started = time.monotonic()
        with pytest.raises(DbError) as caught:
            connect(application_name="pooled", transaction=True, connect_timeout=3)
        took = time.monotonic() - started
        assert caught.value.slug == "store_unreachable"
        assert took < 8, took
    finally:
        proc.kill()
        proc.wait(timeout=10)
