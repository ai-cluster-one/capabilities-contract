"""An inventory metric says what it counts for a reader drawing a tile."""

from __future__ import annotations

import json
import sys

import pytest
from test_capability import _declarations

from capabilities_contract.capability import bind


@pytest.fixture
def excepthook():
    """The core tier installs its own excepthook; the test leaves none behind."""
    saved = sys.excepthook
    yield
    sys.excepthook = saved


def _inventory(monkeypatch, tmp_path, metrics) -> tuple[int | None, dict | None]:
    namespace = _declarations(INVENTORY={"network": "none"},
                              _inventory=lambda network: {"metrics": metrics})
    bind(namespace, "core")
    monkeypatch.chdir(tmp_path)
    try:
        namespace["_cmd_inventory"]([])
    except SystemExit as stop:
        return stop.code, None
    return None, namespace


def test_a_tile_metric_carries_its_kind_and_the_kinds_own_glyph(excepthook):
    namespace = _declarations()
    bind(namespace, "core")
    tile = namespace["_tile"]
    assert tile("waiting", 3) == {"label": "waiting", "value": 3,
                                  "kind": "waiting", "glyph": "hand"}
    assert tile("in_progress", 1, "in progress") == {
        "label": "in progress", "value": 1, "kind": "in_progress", "glyph": "pulse"}
    assert tile("servers", 2, glyph="server", note="from files")["note"] == "from files"
    assert {kind: tile(kind, 0)["glyph"] for kind in namespace["TILE_KINDS"]} == {
        "active": "pulse", "total": "page", "in_progress": "pulse", "waiting": "hand",
        "documents": "page", "servers": "server", "connections": "plug"}


@pytest.mark.parametrize("kind,glyph", [("teams", None), ("documents", "star")])
def test_a_kind_or_glyph_outside_its_set_is_refused(kind, glyph, excepthook, capsys):
    namespace = _declarations()
    bind(namespace, "core")
    with pytest.raises(SystemExit) as stop:
        namespace["_tile"](kind, 1, glyph=glyph)
    assert stop.value.code == 6 and "bad_tile" in capsys.readouterr().err


def test_the_envelope_passes_tile_metrics_and_plain_metrics_through(
        tmp_path, monkeypatch, excepthook, capsys):
    metrics = [{"label": "documents", "value": 4, "kind": "documents", "glyph": "page"},
               {"label": "profile", "value": "generic"}]
    code, _ = _inventory(monkeypatch, tmp_path, metrics)
    assert code is None
    assert json.loads(capsys.readouterr().out)["metrics"] == metrics


def test_the_envelope_refuses_a_metric_with_a_kind_outside_the_set(
        tmp_path, monkeypatch, excepthook, capsys):
    code, _ = _inventory(monkeypatch, tmp_path,
                         [{"label": "x", "value": 1, "kind": "everything"}])
    assert code == 6 and "bad_tile" in capsys.readouterr().err
