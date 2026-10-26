"""An agent's vault: secrets sealed with the agent's own key, kept in the store, read by
a process through a reader that opens only the names asked for and sees a change through
the vault's channel."""

from __future__ import annotations

import time

import pytest

from capabilities_contract import vault
from capabilities_contract.capability import store as store_tier
from capabilities_contract.db import connect, disconnect, migrate

AGENT = "prj_000000000001"


def test_a_sealed_value_opens_only_under_its_key_agent_and_name():
    key = vault.parse_key(vault.generate_key())
    blob = vault.seal(key, AGENT, "API_TOKEN", "tok-1")
    assert b"tok-1" not in blob
    assert vault.unseal(key, AGENT, "API_TOKEN", blob) == "tok-1"
    assert vault.unseal(key, "prj_000000000002", "API_TOKEN", blob) is None
    assert vault.unseal(key, AGENT, "OTHER", blob) is None
    other = vault.parse_key(vault.generate_key())
    assert vault.unseal(other, AGENT, "API_TOKEN", blob) is None
    assert vault.seal(key, AGENT, "API_TOKEN", "tok-1") != blob  # a fresh nonce each time


def test_a_key_is_32_bytes_of_url_safe_base64_and_its_fingerprint_is_not_the_key():
    text = vault.generate_key()
    key = vault.parse_key(text)
    assert len(text) == 43 and len(key) == 32
    assert vault.fingerprint(key) != text and len(vault.fingerprint(key)) == 64
    for bad in ("", "short", text[:-1], text + "AA", "!" * 43):
        with pytest.raises(vault.VaultError) as raised:
            vault.parse_key(bad)
        assert raised.value.slug == "bad_key"
        assert bad == "" or bad not in raised.value.message


def test_the_key_resolves_from_the_folder_then_the_machine_then_the_environment(
        tmp_path, monkeypatch):
    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path / "config"))
    monkeypatch.delenv(vault.KEY_ENV, raising=False)
    root = tmp_path / "agent"
    root.mkdir()
    assert vault.key_source(root) == (None, None)
    monkeypatch.setenv(vault.KEY_ENV, "from-env")
    assert vault.key_source(root) == ("from-env", "env")
    shared = vault.shared_env_path()
    shared.parent.mkdir(parents=True)
    shared.write_text(f"{vault.KEY_ENV}=from-machine\n")
    assert vault.key_source(root) == ("from-machine", str(shared))
    (root / ".env").write_text(f"{vault.KEY_ENV}=from-env-file\n")
    assert vault.key_source(root)[0] == "from-env-file"
    (root / ".env.local").write_text(f"{vault.KEY_ENV}='from-local'\n")
    assert vault.key_source(root) == ("from-local", str(root / ".env.local"))


def test_key_value_text_carries_every_value_back_whole():
    values = {"PLAIN": "abc", "SPACED": " x ", "LINES": "a\nb", "QUOTED": "it's \"q\"",
              "HASH": "a#b", "EMPTY": ""}
    assert vault.parse_text(vault.render_text(values)) == values
    assert vault.parse_text("# c\n\nexport A=1\nB='two'\n") == {"A": "1", "B": "two"}
    for bad, slug in (("nope\n", "bad_text"), ("1A=x\n", "bad_text"),
                      ("A=1\nA=2\n", "bad_text"), ('A="\\q"\n', "bad_text")):
        with pytest.raises(vault.VaultError) as raised:
            vault.parse_text(bad)
        assert raised.value.slug == slug


@pytest.fixture()
def vaulted(store):
    with connect(application_name="setup", transaction=True) as conn:
        major, minor = store_tier.STORE_TABLES_VERSION
        migrate(conn, store_tier.STORE_OWNER, store_tier.record_table_steps(),
                major=major, minor=minor)
        conn.execute("INSERT INTO capabilities_agents (id) VALUES (%s)", (AGENT,))
        conn.commit()
    disconnect()
    vault._READERS.clear()
    return store


def _put(key: bytes, name: str, value: str) -> None:
    with connect(application_name="writer", transaction=True) as conn:
        with conn.transaction():
            vault.put(conn, key, AGENT, name, value, updated_by="me@node")


def _version() -> int:
    with connect(application_name="reader", transaction=True) as conn:
        found = conn.execute(vault.VERSION_QUERY, (vault.VAULT_CHANNEL, AGENT)).fetchall()
    return found[0][0] if found else 0


def test_the_store_keeps_ciphertext_and_the_key_fingerprint_never_the_key(vaulted):
    text = vault.generate_key()
    key = vault.parse_key(text)
    _put(key, "API_TOKEN", "tok-1")
    with connect(application_name="reader", transaction=True) as conn:
        with conn.transaction():
            vault.record_key(conn, AGENT, vault.fingerprint(key))
        rows = vault.rows(conn, AGENT)
        dump = repr(conn.execute("SELECT * FROM capabilities_vault").fetchall()) \
            + repr(conn.execute("SELECT * FROM capabilities_agents").fetchall())
        assert vault.recorded_key(conn, AGENT) == (True, vault.fingerprint(key))
    assert [r["name"] for r in rows] == ["API_TOKEN"]
    assert rows[0]["key_fingerprint"] == vault.fingerprint(key)
    assert rows[0]["updated_by"] == "me@node"
    assert "tok-1" not in dump and text not in dump


def test_every_change_raises_the_channel_version_for_the_agent(vaulted):
    key = vault.parse_key(vault.generate_key())
    before = _version()
    _put(key, "A", "1")
    _put(key, "A", "2")
    with connect(application_name="writer", transaction=True) as conn:
        with conn.transaction():
            assert vault.remove(conn, AGENT, ["A", "MISSING"]) == ["A"]
        with conn.transaction():
            vault.record_key(conn, AGENT, vault.fingerprint(key))
    assert _version() == before + 4


def test_a_reader_opens_what_it_is_asked_and_sees_a_change_through_the_channel(
        vaulted, tmp_path, monkeypatch):
    text = vault.generate_key()
    key = vault.parse_key(text)
    root = tmp_path / "agent"
    root.mkdir()
    (root / ".env.local").write_text(f"{vault.KEY_ENV}={text}\n")
    _put(key, "API_TOKEN", "tok-1")
    _put(key, "OTHER", "x")
    reader = vault.reader(root, AGENT)
    assert reader is vault.reader(root, AGENT)
    opened = []
    real = vault.unseal
    monkeypatch.setattr(vault, "unseal", lambda *a: opened.append(a[2]) or real(*a))
    assert reader.get("API_TOKEN") == "tok-1"
    assert reader.get("MISSING") is None
    assert opened == ["API_TOKEN"]
    _put(key, "API_TOKEN", "tok-2")
    assert reader.get("API_TOKEN") == "tok-1"  # trusted for CHECK_SECONDS
    deadline = time.monotonic() + vault.CHECK_SECONDS + 1.0
    while reader.get("API_TOKEN") != "tok-2":
        assert time.monotonic() < deadline, "the change did not reach the reader"
        time.sleep(0.05)


def test_a_reader_seeded_by_another_round_trip_asks_the_store_nothing_more(
        vaulted, tmp_path, monkeypatch):
    text = vault.generate_key()
    key = vault.parse_key(text)
    _put(key, "API_TOKEN", "tok-1")
    root = tmp_path / "agent"
    root.mkdir()
    (root / ".env.local").write_text(f"{vault.KEY_ENV}={text}\n")
    reader = vault.reader(root, AGENT)
    with connect(application_name="reader", transaction=True) as conn:
        from capabilities_contract.db import batch
        found = batch(conn, [("SELECT 1", None), *vault.round_trip(AGENT)])
    reader.seed(found[1], found[2])
    monkeypatch.setattr(vault.Reader, "_connect",
                        lambda self: pytest.fail("the reader reached the store"))
    assert reader.get("API_TOKEN") == "tok-1"


def test_a_row_sealed_under_another_key_is_unreadable(vaulted, tmp_path):
    old = vault.parse_key(vault.generate_key())
    _put(old, "API_TOKEN", "tok-1")
    text = vault.generate_key()
    root = tmp_path / "agent"
    root.mkdir()
    (root / ".env.local").write_text(f"{vault.KEY_ENV}={text}\n")
    assert vault.reader(root, AGENT).get("API_TOKEN") is None
    with connect(application_name="reader", transaction=True) as conn:
        assert vault.sealed_under_other(conn, AGENT, vault.fingerprint(vault.parse_key(text))) == 1


def test_no_key_means_no_reader_and_an_unreachable_store_says_the_vault_was_not_read(
        tmp_path, clean_env, monkeypatch):
    monkeypatch.delenv(vault.KEY_ENV, raising=False)
    root = tmp_path / "agent"
    root.mkdir()
    assert vault.reader(root, AGENT) is None
    (root / ".env.local").write_text(
        f"{vault.KEY_ENV}={vault.generate_key()}\n"
        "AGENTKIT_DB_HOST=127.0.0.1\nAGENTKIT_DB_PORT=1\nAGENTKIT_DB_NAME=x\n"
        "AGENTKIT_DB_USER=x\nAGENTKIT_DB_SSLMODE=disable\n")
    reader = vault.reader(root, AGENT)
    with pytest.raises(vault.VaultError) as raised:
        reader.get("API_TOKEN")
    assert raised.value.slug == "vault_unreadable"
    assert raised.value.message.startswith("the vault could not be read")
    started = time.monotonic()
    with pytest.raises(vault.VaultError):
        reader.get("OTHER")  # the refusal stands for RETRY_SECONDS
    assert time.monotonic() - started < 0.5


def test_a_reader_keeps_what_it_read_through_a_store_that_goes_away(
        vaulted, tmp_path, monkeypatch):
    text = vault.generate_key()
    _put(vault.parse_key(text), "API_TOKEN", "tok-1")
    root = tmp_path / "agent"
    root.mkdir()
    (root / ".env.local").write_text(f"{vault.KEY_ENV}={text}\n")
    reader = vault.reader(root, AGENT)
    assert reader.get("API_TOKEN") == "tok-1"

    def gone(self):
        raise vault.DbError("store_unreachable", "cannot reach the store: gone")
    monkeypatch.setattr(vault.Reader, "_connect", gone)
    monkeypatch.setattr(vault, "CHECK_SECONDS", 0.0)
    assert reader.get("API_TOKEN") == "tok-1"
    assert reader.problem.startswith("the vault could not be read")
