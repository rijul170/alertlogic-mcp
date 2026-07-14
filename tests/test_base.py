"""Unit tests for the base module: gating, classification, auth helpers."""
import sys
import time
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parent.parent))

from alertlogic_mcp.modules.base import (  # noqa: E402
    ALLOW_DESTRUCTIVE_ENV,
    READONLY_ENV,
    BaseModule,
    classify_tool,
    url_quote,
)


# ------------------------------------------------------------------ #
#  classify_tool                                                      #
# ------------------------------------------------------------------ #

@pytest.mark.parametrize("name,expected", [
    ("incidents_list", "read"),
    ("incidents_get_elaborations", "read"),
    ("assets_topology", "read"),
    ("scan_result_get_latest", "read"),
    ("incidents_complete", "write"),
    ("user_create", "write"),
    ("scan_scheduler_create_schedule", "write"),
    ("user_delete", "destructive"),
    ("playbook_execute", "destructive"),
    ("environments_trigger_scan", "write"),
    # overrides
    ("inquisitor_submit_search", "read"),
    ("aims_authenticate", "read"),
    ("soc_ir_start", "read"),
    ("responder_list_triggers", "read"),
    ("aefr_create_trigger", "write"),
])
def test_classify_tool(name, expected):
    assert classify_tool(name) == expected


def test_unknown_names_fail_safe_to_write():
    """A name with no recognizable verb must not be exposed in read-only mode."""
    assert classify_tool("mystery_operation_xyz") == "write"


# ------------------------------------------------------------------ #
#  _add_tool gating                                                   #
# ------------------------------------------------------------------ #

class FakeServer:
    """Captures tool registrations without a real FastMCP instance."""

    def __init__(self):
        self.registered = {}

    def tool(self, **kwargs):
        def decorator(fn):
            self.registered[kwargs["name"]] = kwargs
            return fn
        return decorator


class DummyModule(BaseModule):
    def register_tools(self, server):
        self._add_tool(server, self._noop, "widgets_list", "List widgets")
        self._add_tool(server, self._noop, "widgets_create", "Create a widget")
        self._add_tool(server, self._noop, "widgets_delete", "Delete a widget")

    def _noop(self):
        return {}


def test_default_mode_suppresses_destructive(monkeypatch):
    monkeypatch.delenv(READONLY_ENV, raising=False)
    monkeypatch.delenv(ALLOW_DESTRUCTIVE_ENV, raising=False)
    server = FakeServer()
    DummyModule().register_tools(server)
    assert set(server.registered) == {"widgets_list", "widgets_create"}


def test_readonly_mode_exposes_only_reads(monkeypatch):
    monkeypatch.setenv(READONLY_ENV, "true")
    monkeypatch.delenv(ALLOW_DESTRUCTIVE_ENV, raising=False)
    server = FakeServer()
    DummyModule().register_tools(server)
    assert set(server.registered) == {"widgets_list"}


def test_allow_destructive_all(monkeypatch):
    monkeypatch.delenv(READONLY_ENV, raising=False)
    monkeypatch.setenv(ALLOW_DESTRUCTIVE_ENV, "true")
    server = FakeServer()
    DummyModule().register_tools(server)
    assert set(server.registered) == {"widgets_list", "widgets_create", "widgets_delete"}


def test_allow_destructive_specific_names(monkeypatch):
    monkeypatch.delenv(READONLY_ENV, raising=False)
    monkeypatch.setenv(ALLOW_DESTRUCTIVE_ENV, "widgets_delete,other_tool")
    server = FakeServer()
    DummyModule().register_tools(server)
    assert "widgets_delete" in server.registered


def test_readonly_beats_allow_destructive(monkeypatch):
    monkeypatch.setenv(READONLY_ENV, "true")
    monkeypatch.setenv(ALLOW_DESTRUCTIVE_ENV, "true")
    server = FakeServer()
    DummyModule().register_tools(server)
    assert set(server.registered) == {"widgets_list"}


def test_annotations_set_from_tier(monkeypatch):
    monkeypatch.delenv(READONLY_ENV, raising=False)
    monkeypatch.setenv(ALLOW_DESTRUCTIVE_ENV, "true")
    server = FakeServer()
    DummyModule().register_tools(server)
    assert server.registered["widgets_list"]["annotations"].readOnlyHint is True
    assert server.registered["widgets_create"]["annotations"].readOnlyHint is False
    assert server.registered["widgets_create"]["annotations"].destructiveHint is False
    assert server.registered["widgets_delete"]["annotations"].destructiveHint is True


# ------------------------------------------------------------------ #
#  Auth / HTTP helpers                                                 #
# ------------------------------------------------------------------ #

def test_url_quote_encodes_slashes():
    assert url_quote("/aws/us-west-2/host/i-123") == "%2Faws%2Fus-west-2%2Fhost%2Fi-123"
    assert url_quote("") == ""
    assert url_quote(None) == ""


class ConcreteModule(BaseModule):
    def register_tools(self, server):
        pass


def test_token_validity_with_leeway():
    mod = ConcreteModule()
    mod._token = "tok"
    mod._token_expires_at = time.time() + 3600
    assert mod._token_is_valid() is True
    # Inside the refresh leeway window the token counts as expired
    mod._token_expires_at = time.time() + 30
    assert mod._token_is_valid() is False
    # No expiry info: assume valid for the session
    mod._token_expires_at = 0.0
    assert mod._token_is_valid() is True
    mod._token = None
    assert mod._token_is_valid() is False


def test_authenticate_requires_key_format(monkeypatch):
    monkeypatch.setenv("ALERTLOGIC_API_KEY", "missing-colon-separator")
    mod = ConcreteModule()
    mod.api_key = "missing-colon-separator"
    result = mod.authenticate()
    assert "error" in result


def test_request_reports_auth_failure(monkeypatch):
    mod = ConcreteModule()
    mod.api_key = ""  # no credentials at all
    result = mod._get("/aims/v1/{account_id}/users", account_id="12345")
    assert "error" in result
