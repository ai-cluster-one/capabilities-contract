"""A throwaway PostgreSQL with TLS, and a machine store setting that points at it.

By default the suite runs `initdb` in a temporary directory, turns TLS on with a
self-signed certificate made here, refuses plain text in pg_hba.conf, and starts the
cluster on a random port. With CAPABILITIES_CONTRACT_TEST_URL set (CI), it uses that
TLS-enabled server instead; CAPABILITIES_CONTRACT_TEST_ROOTCERT then names the
certificate that verifies it, if any.
"""

from __future__ import annotations

import json
import os
import shutil
import socket
import subprocess
import tempfile
import time
import uuid
from dataclasses import dataclass
from pathlib import Path
from urllib.parse import unquote, urlparse

import pytest

ADMIN = "admin"
AGENT = "agent"
PASSWORD = "s3cret pass/word%"  # a value that needs quoting; never a real secret
DATABASE = "app"

ENFORCED_HBA = (f"hostssl all {ADMIN} 127.0.0.1/32 trust\n"
                "hostssl all all 127.0.0.1/32 scram-sha-256\n"
                "hostnossl all all 127.0.0.1/32 reject\n")


def _free_port() -> int:
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


def _pg_tool(name: str) -> str | None:
    base = os.environ.get("PG_BIN")
    if base and (Path(base) / name).exists():
        return str(Path(base) / name)
    return shutil.which(name)


@dataclass
class Server:
    host: str
    port: int
    database: str
    user: str
    password: str | None
    rootcert: str | None
    admin_kwargs: dict

    def admin(self):
        import psycopg
        conn = psycopg.connect(**self.admin_kwargs, connect_timeout=10)
        conn.autocommit = True
        return conn


class Cluster:
    def __init__(self, root: Path):
        self.root = root
        self.data = root / "data"
        self.port = _free_port()
        self.cert = root / "server.crt"
        self.env = {**os.environ, "LC_ALL": "en_US.UTF-8", "LANG": "en_US.UTF-8"}

    def run(self, *argv: str) -> None:
        result = subprocess.run(argv, env=self.env, text=True, capture_output=True,
                                timeout=120)
        assert result.returncode == 0, (argv, result.stdout + result.stderr)

    def start(self) -> None:
        self.run(_pg_tool("initdb"), "-D", str(self.data), "-U", ADMIN, "-E", "UTF8",
                 "--locale=en_US.UTF-8", "--auth=trust")
        key = self.root / "server.key"
        self.run("openssl", "req", "-new", "-x509", "-days", "2", "-nodes",
                 "-subj", "/CN=localhost",
                 "-addext", "subjectAltName=DNS:localhost,IP:127.0.0.1",
                 "-keyout", str(key), "-out", str(self.cert))
        key.chmod(0o600)
        with (self.data / "postgresql.conf").open("a") as conf:
            conf.write(f"\nlisten_addresses = '127.0.0.1'\nport = {self.port}\n"
                       "unix_socket_directories = ''\nssl = on\n"
                       f"ssl_cert_file = '{self.cert}'\nssl_key_file = '{key}'\n"
                       "password_encryption = 'scram-sha-256'\n")
        (self.data / "pg_hba.conf").write_text(ENFORCED_HBA)
        self.run(_pg_tool("pg_ctl"), "-D", str(self.data), "-l", str(self.root / "pg.log"),
                 "-w", "-t", "60", "start")

    def stop(self) -> None:
        subprocess.run([_pg_tool("pg_ctl"), "-D", str(self.data), "-m", "immediate", "stop"],
                       env=self.env, capture_output=True, timeout=60)


@pytest.fixture(scope="session")
def server():
    url = os.environ.get("CAPABILITIES_CONTRACT_TEST_URL")
    if url:
        parsed = urlparse(url)
        yield Server(host=parsed.hostname or "127.0.0.1", port=parsed.port or 5432,
                     database=parsed.path.lstrip("/") or "postgres",
                     user=unquote(parsed.username or "postgres"),
                     password=unquote(parsed.password) if parsed.password else None,
                     rootcert=os.environ.get("CAPABILITIES_CONTRACT_TEST_ROOTCERT"),
                     admin_kwargs={"conninfo": url})
        return
    for tool in ("initdb", "pg_ctl"):
        if _pg_tool(tool) is None:
            pytest.skip(f"{tool} is not on PATH or in $PG_BIN")
    if shutil.which("openssl") is None:
        pytest.skip("openssl is not on PATH")
    root = Path(tempfile.mkdtemp(prefix="capabilities-contract-pg-"))
    cluster = Cluster(root)
    try:
        cluster.start()
        admin_kwargs = {"host": "127.0.0.1", "port": cluster.port, "user": ADMIN,
                        "dbname": "postgres", "sslmode": "require"}
        import psycopg
        with psycopg.connect(**admin_kwargs, autocommit=True) as admin:
            admin.execute(f"CREATE ROLE {AGENT} LOGIN PASSWORD '{PASSWORD}'")
            admin.execute(f"CREATE DATABASE {DATABASE} OWNER {AGENT} ENCODING 'UTF8' "
                          "TEMPLATE template0")
        yield Server(host="127.0.0.1", port=cluster.port, database=DATABASE, user=AGENT,
                     password=PASSWORD, rootcert=str(cluster.cert),
                     admin_kwargs={**admin_kwargs, "dbname": DATABASE})
    finally:
        cluster.stop()
        shutil.rmtree(root, ignore_errors=True)


def write_family_setting(config_home: Path, document) -> Path:
    folder = config_home / "agentkit"
    folder.mkdir(parents=True, exist_ok=True)
    path = folder / "store.json"
    path.write_text(document if isinstance(document, str) else json.dumps(document))
    return path


def write_setting(config_home: Path, document: dict, password: str | None = None) -> None:
    folder = config_home / "capabilities"
    folder.mkdir(parents=True, exist_ok=True)
    (folder / "store.json").write_text(json.dumps(document))
    if password is not None:
        (folder / "credentials.env").write_text(f"CAPABILITIES_STORE_PASSWORD={password}\n")


@dataclass
class Store:
    config_home: Path
    schema: str
    server: Server

    def document(self, **overrides) -> dict:
        doc = {"schema": "capabilities.store.v2", "host": self.server.host,
               "port": self.server.port, "database": self.server.database,
               "user": self.server.user, "sslmode": "require", "db_schema": self.schema}
        doc.update(overrides)
        return {k: v for k, v in doc.items() if v is not None}

    def write(self, **overrides) -> None:
        write_setting(self.config_home, self.document(**overrides), self.server.password)


@pytest.fixture()
def clean_env(tmp_path, monkeypatch):
    """An empty XDG_CONFIG_HOME and no URL override."""
    home = tmp_path / "config"
    home.mkdir()
    monkeypatch.setenv("XDG_CONFIG_HOME", str(home))
    monkeypatch.delenv("CAPABILITIES_STORE_URL", raising=False)
    monkeypatch.delenv("AGENTKIT_STORE_URL", raising=False)
    return home


@pytest.fixture()
def store(server, clean_env):
    """A machine setting pointing at the test server, bound to a fresh schema."""
    found = Store(config_home=clean_env, schema=f"t_{uuid.uuid4().hex[:12]}", server=server)
    found.write()
    yield found
    try:
        with server.admin() as admin:
            admin.execute(f'DROP SCHEMA IF EXISTS "{found.schema}" CASCADE')
    except Exception:
        pass


def wait_for(path: Path, timeout: float = 30.0) -> None:
    deadline = time.monotonic() + timeout
    while not path.exists():
        if time.monotonic() > deadline:
            raise TimeoutError(path)
        time.sleep(0.01)
