"""A store reached through Supabase's transaction pooler is refused before anything is
sent to it; every other endpoint is connected to as before. No server is needed: the
driver's connect is replaced by one that records it was reached."""

from __future__ import annotations

import psycopg
import pytest

from capabilities_contract.db import DbError, Setting, connect

POOLER = "aws-0-region.pooler.supabase.com"
PASSWORD = "not-a-real-secret"


@pytest.fixture
def reached(monkeypatch):
    calls = []

    def fake_connect(*args, **kwargs):
        calls.append(kwargs)
        raise psycopg.OperationalError("reached the driver")

    monkeypatch.setattr(psycopg, "connect", fake_connect)
    return calls


def _fields(host, port):
    return Setting(level="environment", host=host, port=port, database="postgres",
                   user="postgres.ref", sslmode="require", password=PASSWORD)


def _url(url):
    return Setting(level="environment", url=url)


@pytest.mark.parametrize("setting", [
    _fields(POOLER, 6543),
    _fields(POOLER.upper(), 6543),
    _url(f"postgresql://postgres.ref:{PASSWORD}@{POOLER}:6543/postgres"),
    _url(f"postgresql:///postgres?host={POOLER}&port=6543&password={PASSWORD}"),
    _url(f"postgresql://postgres.ref:{PASSWORD}@db.example.com:5432,{POOLER}:6543/postgres"),
], ids=["fields", "fields-upper-case", "url", "url-query-host", "url-second-host"])
def test_the_transaction_pooler_is_refused_before_it_is_reached(reached, setting):
    with pytest.raises(DbError) as caught:
        connect(application_name="test", setting=setting)
    error = caught.value
    assert error.slug == "transaction_pooler"
    assert reached == []
    assert f"{POOLER}:6543" in error.message.lower()
    assert "5432" in error.hint
    assert PASSWORD not in error.message + error.hint


@pytest.mark.parametrize("setting", [
    _fields(POOLER, 5432),
    _url(f"postgresql://postgres.ref:{PASSWORD}@{POOLER}:5432/postgres"),
    _url(f"postgresql://postgres.ref:{PASSWORD}@{POOLER}/postgres"),
    _fields("db.example.com", 6543),
    _fields("db.example.com", 5432),
    _url("postgresql://agent@127.0.0.1:6543/app?sslmode=disable"),
], ids=["session-pooler-fields", "session-pooler-url", "session-pooler-default-port",
        "other-host-6543", "direct-host", "local-6543"])
def test_every_other_endpoint_is_connected_to(reached, setting):
    with pytest.raises(DbError) as caught:
        connect(application_name="test", setting=setting)
    assert caught.value.slug == "store_unreachable"
    assert len(reached) == 1
