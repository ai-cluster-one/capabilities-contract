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
        conn.execute("INSERT INTO agents (id) VALUES (%s)", (AGENT,))
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
        dump = repr(conn.execute("SELECT * FROM secrets").fetchall()) \
            + repr(conn.execute("SELECT * FROM agents").fetchall())
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


def _agent_root(tmp_path, text: str, store):
    root = tmp_path / "agent"
    root.mkdir(exist_ok=True)
    (root / ".env.local").write_text(f"{vault.KEY_ENV}={text}\n")
    return root


def test_write_seals_values_records_the_key_and_a_reader_reads_them_back_at_once(
        vaulted, tmp_path):
    text = vault.generate_key()
    root = _agent_root(tmp_path, text, vaulted)
    reader = vault.reader(root, AGENT)
    assert reader.get("API_TOKEN") is None
    assert vault.write(root, AGENT, {"API_TOKEN": "tok-1", "OTHER": "x"},
                       updated_by="me@node") == {"API_TOKEN": "created", "OTHER": "created"}
    assert reader.get("API_TOKEN") == "tok-1"  # not held for CHECK_SECONDS
    assert vault.write(root, AGENT, {"API_TOKEN": "tok-2"}) == {"API_TOKEN": "replaced"}
    assert reader.get("API_TOKEN") == "tok-2"
    with connect(application_name="reader", transaction=True) as conn:
        assert vault.recorded_key(conn, AGENT) == (True, vault.fingerprint(vault.parse_key(text)))
    assert vault.delete(root, AGENT, ["API_TOKEN", "MISSING"]) == ["API_TOKEN"]
    assert reader.get("API_TOKEN") is None and reader.get("OTHER") == "x"


def test_write_refuses_and_writes_nothing_without_the_agents_key(vaulted, tmp_path,
                                                                  monkeypatch):
    monkeypatch.delenv(vault.KEY_ENV, raising=False)
    root = tmp_path / "agent"
    root.mkdir()
    with pytest.raises(vault.VaultError) as raised:
        vault.write(root, AGENT, {"API_TOKEN": "tok-1"})
    assert raised.value.slug == "key_missing"
    first = vault.generate_key()
    _agent_root(tmp_path, first, vaulted)
    vault.write(root, AGENT, {"API_TOKEN": "tok-1"})
    _agent_root(tmp_path, vault.generate_key(), vaulted)
    with pytest.raises(vault.VaultError) as raised:
        vault.write(root, AGENT, {"API_TOKEN": "tok-2"})
    assert raised.value.slug == "key_mismatch"
    with pytest.raises(vault.VaultError) as raised:
        vault.write(root, "prj_0000000000ff", {"API_TOKEN": "tok-2"})
    assert raised.value.slug == "agent_unregistered"
    _agent_root(tmp_path, first, vaulted)
    assert vault.reader(root, AGENT).get("API_TOKEN") == "tok-1"


def test_write_to_a_store_it_cannot_reach_is_refused_as_unwritable(tmp_path, clean_env,
                                                                   monkeypatch):
    monkeypatch.delenv(vault.KEY_ENV, raising=False)
    root = tmp_path / "agent"
    root.mkdir()
    (root / ".env.local").write_text(
        f"{vault.KEY_ENV}={vault.generate_key()}\n"
        "AGENTKIT_DB_HOST=127.0.0.1\nAGENTKIT_DB_PORT=1\nAGENTKIT_DB_NAME=x\n"
        "AGENTKIT_DB_USER=x\nAGENTKIT_DB_SSLMODE=disable\n")
    with pytest.raises(vault.VaultError) as raised:
        vault.write(root, AGENT, {"API_TOKEN": "tok-1"})
    assert raised.value.slug == "vault_unwritable"
    assert "tok-1" not in raised.value.message


def test_a_value_sealed_for_the_public_key_opens_only_under_the_agents_key():
    key = vault.parse_key(vault.generate_key())
    public = vault.parse_public(vault.public_text(key))
    assert public == vault.public_key(key) and len(public) == 32
    assert vault.public_text(key) != vault.encode_key(key)
    blob = vault.seal_for(public, AGENT, "API_TOKEN", "tok-1")
    assert blob[0] == vault.SEALED_FORMAT_PUBLIC and b"tok-1" not in blob
    assert vault.unseal(key, AGENT, "API_TOKEN", blob, None) == "tok-1"
    assert vault.unseal(key, "prj_000000000002", "API_TOKEN", blob, None) is None
    assert vault.unseal(key, AGENT, "OTHER", blob, None) is None
    assert vault.unseal(vault.parse_key(vault.generate_key()), AGENT, "API_TOKEN", blob,
                        None) is None
    assert vault.parse_public("short") is None
    # Anyone may have written it, so it opens only while the agent pins no platform key.
    assert vault.unseal(key, AGENT, "API_TOKEN", blob, b"\x01" * 32) is None
    assert vault.unseal(key, AGENT, "API_TOKEN", blob) is None


PEER = "prj_000000000002"
LATE = "prj_000000000003"


def test_share_seals_the_writers_own_and_refuses_another_agents_vault(vaulted, tmp_path):
    with connect(application_name="setup", transaction=True) as conn, conn.transaction():
        conn.execute("INSERT INTO agents (id) VALUES (%s)", (PEER,))
    root = _agent_root(tmp_path, vault.generate_key(), vaulted)
    with pytest.raises(vault.VaultError) as refused:
        vault.share(root, AGENT, {"API_TOKEN": "tok-1"}, [AGENT, PEER])
    assert refused.value.slug == "shared_by_platform" and refused.value.hint
    with connect(application_name="reader", transaction=True) as conn:
        assert vault.rows(conn, PEER) == [] and vault.rows(conn, AGENT) == []
    done = vault.share(root, AGENT, {"API_TOKEN": "tok-1"}, [AGENT], replace=False)
    assert done["sealed"] == {AGENT: {"API_TOKEN": "created"}}
    assert vault.reader(root, AGENT).get("API_TOKEN") == "tok-1"


# --- The platform -----------------------------------------------------------------

CID = "0a0b0c0d0e0f"


def _agent(tmp_path, agent_id: str) -> tuple:
    """An agent registered with its key published, and its folder holding the key."""
    text = vault.generate_key()
    key = vault.parse_key(text)
    root = tmp_path / agent_id
    root.mkdir()
    (root / ".env.local").write_text(f"{vault.KEY_ENV}={text}\n")
    with connect(application_name="setup", transaction=True) as conn, conn.transaction():
        conn.execute("INSERT INTO agents (id) VALUES (%s) ON CONFLICT DO NOTHING", (agent_id,))
        vault.record_key(conn, agent_id, vault.fingerprint(key))
        vault.publish(conn, agent_id, key)
    return root, key


def _shared(grantees: list) -> None:
    with connect(application_name="setup", transaction=True) as conn, conn.transaction():
        conn.execute("INSERT INTO connections (id, capability, label, spec) "
                     "VALUES (%s, 'demo', 'primary', '{}')", (CID,))
        for agent in grantees:
            conn.execute("INSERT INTO grants (agent_id, capability, connection_id, enabled) "
                         "VALUES (%s, 'demo', %s, true)", (agent, CID))


def _platform():
    from capabilities_contract import platform
    with connect(application_name="setup", transaction=True) as conn, conn.transaction():
        return platform.ensure(conn, create_missing=True)


def _settles(root, agent: str, name: str, wanted) -> None:
    deadline = time.monotonic() + vault.CHECK_SECONDS + 2.0
    while vault.reader(root, agent).get(name) != wanted:
        assert time.monotonic() < deadline, f"{agent} did not come to read {wanted!r}"
        time.sleep(0.05)


def test_a_shared_value_entered_once_reaches_both_grantees_its_change_too_and_a_revoke_one(
        vaulted, tmp_path):
    from capabilities_contract import platform
    a_root, _a = _agent(tmp_path, AGENT)
    p_root, _p = _agent(tmp_path, PEER)
    _shared([AGENT, PEER])
    with pytest.raises(vault.VaultError) as refused:
        platform.share_connection(a_root, CID, {"DEMO_TOKEN": "tok-1"})
    assert refused.value.slug == "platform_key_missing" and refused.value.hint
    made = _platform()
    assert (platform.home() / platform.KEY_FILE).stat().st_mode & 0o077 == 0
    done = platform.share_connection(a_root, CID, {"DEMO_TOKEN": "tok-1"}, updated_by="me@node")
    assert done["copies"] == {"DEMO_TOKEN": "created"} and done["refused"] == []
    assert done["sealed"] == {AGENT: {"DEMO_TOKEN": "created"}, PEER: {"DEMO_TOKEN": "created"}}
    assert vault.reader(a_root, AGENT).get("DEMO_TOKEN") == "tok-1"
    assert vault.reader(p_root, PEER).get("DEMO_TOKEN") == "tok-1"
    again = platform.share_connection(a_root, CID, {"DEMO_TOKEN": "tok-1"})
    assert again["copies"] == {"DEMO_TOKEN": "unchanged"}
    assert again["sealed"] == {AGENT: {"DEMO_TOKEN": "unchanged"},
                               PEER: {"DEMO_TOKEN": "unchanged"}}
    platform.share_connection(a_root, CID, {"DEMO_TOKEN": "tok-2"})
    _settles(a_root, AGENT, "DEMO_TOKEN", "tok-2")
    _settles(p_root, PEER, "DEMO_TOKEN", "tok-2")
    with connect(application_name="writer", transaction=True) as conn, conn.transaction():
        conn.execute("UPDATE grants SET enabled = false WHERE agent_id = %s", (PEER,))
        assert platform.revoke(conn, CID, PEER) == ["DEMO_TOKEN"]
        assert platform.connection_values(conn, made, CID) == {"DEMO_TOKEN": "tok-2"}
    _settles(p_root, PEER, "DEMO_TOKEN", None)
    assert vault.reader(a_root, AGENT).get("DEMO_TOKEN") == "tok-2"


def test_an_entry_another_agent_writes_into_a_vault_is_refused(vaulted, tmp_path):
    from capabilities_contract import platform
    a_root, a_key = _agent(tmp_path, AGENT)
    _p_root, p_key = _agent(tmp_path, PEER)
    made = _platform()
    a_public, fp = vault.public_key(a_key), vault.fingerprint(a_key)
    forged = vault.seal_box(vault._public_secret(p_key), a_public, AGENT, "FORGED", "evil")
    with connect(application_name="peer", transaction=True) as conn, conn.transaction():
        vault.put_row(conn, AGENT, "FORGED", forged, fp)
    # Sent by another agent's key: refused.
    assert vault.reader(a_root, AGENT).get("FORGED") is None
    with connect(application_name="platform", transaction=True) as conn, conn.transaction():
        assert platform.write_agent_pin(conn, made, AGENT, a_key)
    platform.record_vault_pins([AGENT])
    with connect(application_name="reader", transaction=True) as conn:
        assert vault.pin_of(a_key, AGENT, vault.rows(conn, AGENT)) == made.public
    # Sealed anonymously once the pin exists: refused.
    with connect(application_name="peer", transaction=True) as conn, conn.transaction():
        vault.put_row(conn, AGENT, "ANON", vault.seal_for(a_public, AGENT, "ANON", "evil"), fp)
    vault._READERS.clear()
    assert vault.reader(a_root, AGENT).get("ANON") is None
    # A pin another wrote opens nothing: the agent's key alone writes one.
    fake = vault.seal_box(vault._public_secret(p_key), a_public, AGENT, vault.PIN_NAME,
                          vault.public_text(p_key))
    with connect(application_name="peer", transaction=True) as conn, conn.transaction():
        vault.put_row(conn, AGENT, vault.PIN_NAME, fake, fp)
    vault._READERS.clear()
    assert vault.reader(a_root, AGENT).get("FORGED") is None
    # What the platform sends opens.
    with connect(application_name="platform", transaction=True) as conn, conn.transaction():
        assert platform.deliver(conn, made, AGENT, {"GRANTED": "ok"}) == {"GRANTED": "created"}
    vault._READERS.clear()
    assert vault.reader(a_root, AGENT).get("GRANTED") == "ok"


def test_the_platform_seals_nothing_for_an_agent_whose_published_key_moved(vaulted, tmp_path):
    from capabilities_contract import platform
    _agent(tmp_path, AGENT)
    made = _platform()
    with connect(application_name="platform", transaction=True) as conn, conn.transaction():
        platform.deliver(conn, made, AGENT, {"GRANTED": "ok"})
    swapped = vault.parse_key(vault.generate_key())
    with connect(application_name="peer", transaction=True) as conn, conn.transaction():
        vault.record_key(conn, AGENT, vault.fingerprint(swapped))
        vault.publish(conn, AGENT, swapped)
    with connect(application_name="platform", transaction=True) as conn, \
            pytest.raises(vault.VaultError) as refused:
        platform.deliver(conn, made, AGENT, {"GRANTED": "ok"})
    assert refused.value.slug == "agent_key_changed" and "recover" in refused.value.hint


def test_reseal_turns_format_2_entries_into_format_1_and_loses_none(vaulted, tmp_path):
    from capabilities_contract import platform
    root, key = _agent(tmp_path, AGENT)
    fp = vault.fingerprint(key)
    with connect(application_name="old", transaction=True) as conn, conn.transaction():
        vault.put_row(conn, AGENT, "OLD_OWN", vault.seal_symmetric(key, AGENT, "OLD_OWN", "one"),
                      fp)
        vault.put_row(conn, AGENT, "OLD_GRANTED", vault.seal_for(
            vault.public_key(key), AGENT, "OLD_GRANTED", "two"), fp)
    with connect(application_name="migrate", transaction=True) as conn, conn.transaction():
        done = vault.reseal(conn, key, AGENT)
        again = vault.reseal(conn, key, AGENT)
        held = {r["name"]: r["ciphertext"][0] for r in vault.rows(conn, AGENT)}
    assert done == {"resealed": ["OLD_GRANTED"], "unreadable": []}
    assert again == {"resealed": [], "unreadable": []}
    assert held == {"OLD_GRANTED": vault.SEALED_FORMAT, "OLD_OWN": vault.SEALED_FORMAT}
    reader = vault.reader(root, AGENT)
    assert (reader.get("OLD_OWN"), reader.get("OLD_GRANTED")) == ("one", "two")
    # What the platform delivers is its own, and is left as it is.
    made = _platform()
    with connect(application_name="platform", transaction=True) as conn, conn.transaction():
        platform.deliver(conn, made, AGENT, {"GRANTED": "three"})
        assert vault.reseal(conn, key, AGENT) == {"resealed": [], "unreadable": []}


def test_own_entries_are_format_1_and_a_delivery_format_2_beside_the_platforms_copy(
        vaulted, tmp_path):
    """What this release writes opens under a release that reads only `ciphertext`."""
    from capabilities_contract import platform
    root, key = _agent(tmp_path, AGENT)
    made = _platform()
    vault.write(root, AGENT, {"OWN": "mine"})
    with connect(application_name="platform", transaction=True) as conn, conn.transaction():
        assert platform.write_agent_pin(conn, made, AGENT, key)
        assert platform.deliver(conn, made, AGENT, {"GRANTED": "ok"}) == {"GRANTED": "created"}
        assert platform.deliver(conn, made, AGENT, {"GRANTED": "ok"}) == {
            "GRANTED": "unchanged"}
    with connect(application_name="reader", transaction=True) as conn:
        held = {r["name"]: r for r in vault.rows(conn, AGENT)}
    assert set(held) == {"GRANTED", "OWN", vault.PIN_NAME}
    assert [held[n]["ciphertext"][0] for n in ("OWN", vault.PIN_NAME)] == [vault.SEALED_FORMAT] * 2
    assert held["OWN"]["box"] is None
    assert held["GRANTED"]["ciphertext"][0] == vault.SEALED_FORMAT_PUBLIC
    assert vault.box_sender(held["GRANTED"]["box"]) == made.public
    # A reader of `ciphertext` alone, as an older release is, opens both.
    assert vault._unseal_symmetric(key, AGENT, "OWN", held["OWN"]["ciphertext"]) == "mine"
    assert vault._unseal_public(key, AGENT, "GRANTED", held["GRANTED"]["ciphertext"]) == "ok"
    reader = vault.reader(root, AGENT)
    assert (reader.get("OWN"), reader.get("GRANTED")) == ("mine", "ok")
    # The agent's own write of the name clears the platform's copy beside it.
    vault.write(root, AGENT, {"GRANTED": "mine-now"})
    with connect(application_name="reader", transaction=True) as conn:
        [row] = [r for r in vault.rows(conn, AGENT) if r["name"] == "GRANTED"]
    assert (row["ciphertext"][0], row["box"]) == (vault.SEALED_FORMAT, None)
    assert vault.reader(root, AGENT).get("GRANTED") == "mine-now"


def _attack(agent: str, attacker: bytes, pin: bool = True) -> None:
    """Another agent, holding the store's login and its own key alone: the
    agent's pin taken out, and its own public key published as the platform's."""
    with connect(application_name="peer", transaction=True) as conn, conn.transaction():
        if pin:
            conn.execute("DELETE FROM secrets WHERE agent_id = %s AND name = %s",
                         (agent, vault.PIN_NAME))
        conn.execute("UPDATE store_state SET platform_public_key = %s",
                     (vault.public_text(attacker),))


def _forge(agent: str, key: bytes, attacker: bytes, name: str, value: str) -> None:
    with connect(application_name="peer", transaction=True) as conn, conn.transaction():
        vault.put_row(conn, agent, name, vault.seal_box(
            vault._public_secret(attacker), vault.public_key(key), agent, name, value),
            vault.fingerprint(key))


def _attacker_opens(agent: str, key: bytes, attacker: bytes) -> list:
    with connect(application_name="peer", transaction=True) as conn:
        found = conn.execute("SELECT name, ciphertext FROM platform_secrets "
                             "WHERE agent_id = %s", (agent,)).fetchall()
    opened = [vault.open_box(vault._public_secret(attacker), vault.copy_scope(agent_id=agent),
                             name, bytes(blob), [vault.public_key(key)]) for name, blob in found]
    return [value for value in opened if value is not None]


def test_the_platform_key_the_store_publishes_is_never_pinned_or_trusted(vaulted, tmp_path):
    from capabilities_contract import platform
    root, key = _agent(tmp_path, AGENT)
    _peer_root, attacker = _agent(tmp_path, PEER)
    made = _platform()
    with connect(application_name="platform", transaction=True) as conn, conn.transaction():
        platform.write_agent_pin(conn, made, AGENT, key)
        platform.deliver(conn, made, AGENT, {"GRANTED": "ok"})
    platform.record_vault_pins([AGENT])
    held = platform.home() / platform.KEY_FILE
    for machine, own in (("platform", "OWN_HERE"), ("node", "OWN_ON_NODE")):
        if machine == "node":
            held.rename(held.with_suffix(".away"))
        _attack(AGENT, attacker)
        _forge(AGENT, key, attacker, "FORGED", "evil")
        vault._READERS.clear()
        reader = vault.reader(root, AGENT)
        assert reader.get("FORGED") is None, machine
        vault.write(root, AGENT, {own: "mine"})
        with connect(application_name="writer", transaction=True) as conn, conn.transaction():
            vault.put(conn, key, AGENT, own + "_TOO", "mine-too")
            trusted = vault.take_pin(conn, key, AGENT)
            pin = vault.pin_of(key, AGENT, vault.rows(conn, AGENT))
        vault._READERS.clear()
        reader = vault.reader(root, AGENT)
        assert (reader.get("FORGED"), reader.get(own)) == (None, "mine"), machine
        # Where the key file is the pin is written from it; where it is not none is taken.
        assert (pin, trusted) == ((made.public, made.public) if machine == "platform"
                                  else (None, None)), machine
        assert _attacker_opens(AGENT, key, attacker) == [], machine
    # On the node, a missing pin stays missing: no copy of an own entry is written.
    with connect(application_name="reader", transaction=True) as conn:
        copied = {n for (n,) in conn.execute(
            "SELECT name FROM platform_secrets WHERE agent_id = %s", (AGENT,)).fetchall()}
    assert copied == {"OWN_HERE", "OWN_HERE_TOO"}


def test_a_key_published_before_the_platform_exists_is_never_pinned(vaulted, tmp_path):
    root, key = _agent(tmp_path, AGENT)
    _peer_root, attacker = _agent(tmp_path, PEER)
    _attack(AGENT, attacker, pin=False)
    _forge(AGENT, key, attacker, "FORGED", "evil")
    assert vault.reader(root, AGENT).get("FORGED") is None
    vault.write(root, AGENT, {"OWN": "mine"})
    with connect(application_name="reader", transaction=True) as conn:
        found = vault.rows(conn, AGENT)
        copies = conn.execute("SELECT count(*) FROM platform_secrets").fetchone()[0]
    assert vault.pin_of(key, AGENT, found) is None and copies == 0
    vault._READERS.clear()
    assert vault.reader(root, AGENT).get("FORGED") is None


def test_a_store_older_than_core_4_4_keeps_the_vault_as_before(store, tmp_path):
    from capabilities_contract.db import _migrate
    with connect(application_name="setup", transaction=True) as conn:
        migrate(conn, "core", _migrate.CORE_STEPS[:6], major=4, minor=3)
        conn.execute("INSERT INTO agents (id) VALUES (%s)", (AGENT,))
        conn.commit()
    disconnect()
    vault._READERS.clear()
    text = vault.generate_key()
    root = tmp_path / "agent"
    root.mkdir()
    (root / ".env.local").write_text(f"{vault.KEY_ENV}={text}\n")
    vault.write(root, AGENT, {"OWN": "mine"})
    vault.write(root, AGENT, {"OWN": "mine-2"})
    with connect(application_name="reader", transaction=True) as conn:
        [row] = vault.rows(conn, AGENT)
    assert (row["ciphertext"][0], row["box"]) == (vault.SEALED_FORMAT, None)
    assert vault.reader(root, AGENT).get("OWN") == "mine-2"


def test_a_dump_of_the_store_holds_no_key_and_no_value(vaulted, tmp_path):
    from capabilities_contract import platform
    a_root, a_key = _agent(tmp_path, AGENT)
    _p_root, p_key = _agent(tmp_path, PEER)
    _shared([AGENT, PEER])
    _platform()
    platform.share_connection(a_root, CID, {"DEMO_TOKEN": "shared-value-1"})
    vault.write(a_root, AGENT, {"OWN_TOKEN": "own-value-1"})
    platform_text = (platform.home() / platform.KEY_FILE).read_text().strip()
    with connect(application_name="dump", transaction=True) as conn:
        tables = [t for (t,) in conn.execute(
            "SELECT table_name FROM information_schema.tables WHERE table_schema = "
            "current_schema() AND table_type = 'BASE TABLE'").fetchall()]
        dump = b"".join(repr(conn.execute(f'SELECT * FROM "{t}"').fetchall()).encode()
                        for t in tables)
        copies = conn.execute("SELECT count(*) FROM platform_secrets").fetchone()[0]
    assert copies == 2  # the shared connection's, and the agent's own
    for secret in (vault.encode_key(a_key), vault.encode_key(p_key), platform_text):
        assert secret.encode() not in dump
    for raw in (a_key, p_key, vault.parse_key(platform_text)):
        assert repr(raw).encode()[2:-1] not in dump
    assert b"shared-value-1" not in dump and b"own-value-1" not in dump


def test_a_first_pin_keeps_an_older_release_s_entries_and_a_pin_taken_away_launders_none(
        vaulted, tmp_path):
    """The platform's first pin of an agent closes format 2 for it, so it seals the
    agent's format 2 entries again as its own first; a reader on the platform's
    machine does not pin an agent the platform never pinned. A pin taken away after
    that is written again with nothing sealed again: a format 2 entry planted
    meanwhile never opens and never becomes the agent's own."""
    from capabilities_contract import platform
    root, key = _agent(tmp_path, AGENT)
    _peer_root, attacker = _agent(tmp_path, PEER)
    public, fp = vault.public_key(key), vault.fingerprint(key)
    with connect(application_name="old", transaction=True) as conn, conn.transaction():
        vault.put_row(conn, AGENT, "OLD_GRANTED", vault.seal_for(public, AGENT, "OLD_GRANTED",
                                                                 "kept"), fp)
    made = _platform()
    # On the platform's machine, before the platform pinned the agent, every
    # reader and writer leaves it unpinned and the older entry opens.
    vault._READERS.clear()
    assert vault.reader(root, AGENT).get("OLD_GRANTED") == "kept"
    vault.write(root, AGENT, {"OWN": "mine"})
    with connect(application_name="reader", transaction=True) as conn, conn.transaction():
        assert vault.take_pin(conn, key, AGENT) is None
        assert vault.pin_of(key, AGENT, vault.rows(conn, AGENT)) is None
    # The platform's first pin seals it again as the agent's own, then pins.
    with connect(application_name="platform", transaction=True) as conn, conn.transaction():
        assert platform.write_agent_pin(conn, made, AGENT, key)
        held = {r["name"]: r for r in vault.rows(conn, AGENT)}
    platform.record_vault_pins([AGENT])
    assert held["OLD_GRANTED"]["ciphertext"][0] == vault.SEALED_FORMAT
    assert vault.pin_of(key, AGENT, held.values()) == made.public
    vault._READERS.clear()
    assert vault.reader(root, AGENT).get("OLD_GRANTED") == "kept"
    # The pin taken away, a format 2 entry planted over the agent's own.
    with connect(application_name="peer", transaction=True) as conn, conn.transaction():
        conn.execute("DELETE FROM secrets WHERE agent_id = %s AND name = %s",
                     (AGENT, vault.PIN_NAME))
        vault.put_row(conn, AGENT, "OLD_GRANTED", vault.seal_for(public, AGENT, "OLD_GRANTED",
                                                                 "evil"), fp)
    with connect(application_name="migrate", transaction=True) as conn, conn.transaction():
        assert vault.reseal(conn, key, AGENT) == {"resealed": [], "unreadable": ["OLD_GRANTED"]}
    # A reader on the platform's machine writes the pin again at once, sealing nothing.
    vault._READERS.clear()
    assert vault.reader(root, AGENT).get("OLD_GRANTED") is None
    with connect(application_name="reader", transaction=True) as conn:
        held = {r["name"]: r for r in vault.rows(conn, AGENT)}
    assert vault.pin_of(key, AGENT, held.values()) == made.public
    assert held["OLD_GRANTED"]["ciphertext"][0] == vault.SEALED_FORMAT_PUBLIC
    # Taken away again, the platform writes it again, sealing nothing either.
    with connect(application_name="peer", transaction=True) as conn, conn.transaction():
        conn.execute("DELETE FROM secrets WHERE agent_id = %s AND name = %s",
                     (AGENT, vault.PIN_NAME))
    with connect(application_name="platform", transaction=True) as conn, conn.transaction():
        assert platform.write_agent_pin(conn, made, AGENT, key)
        held = {r["name"]: r for r in vault.rows(conn, AGENT)}
    assert held["OLD_GRANTED"]["ciphertext"][0] == vault.SEALED_FORMAT_PUBLIC
    vault._READERS.clear()
    assert vault.reader(root, AGENT).get("OLD_GRANTED") is None
