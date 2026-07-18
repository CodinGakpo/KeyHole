"""Unit tests for the egress proxy's pure decision logic.

The proxy image is standalone (no mark1 dependency), so we load its module by path and test the
deny-by-default parsing/allowlist logic without needing Docker or a socket.
"""

import importlib.util
from pathlib import Path

import pytest

_PROXY_PATH = Path(__file__).resolve().parents[2] / "images" / "egress-proxy" / "proxy.py"


@pytest.fixture(scope="module")
def proxy():
    spec = importlib.util.spec_from_file_location("mark1_egress_proxy", _PROXY_PATH)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_parse_connect_with_port(proxy):
    assert proxy.parse_connect("CONNECT example.com:443 HTTP/1.1") == ("example.com", 443)


def test_parse_connect_defaults_port(proxy):
    assert proxy.parse_connect("CONNECT example.com HTTP/1.1") == ("example.com", 443)


def test_parse_connect_rejects_non_connect(proxy):
    assert proxy.parse_connect("GET http://example.com/ HTTP/1.1") is None
    assert proxy.parse_connect("garbage") is None


def test_deny_by_default(proxy):
    allowed = proxy.load_allowlist("")
    assert not proxy.is_allowed("example.com", allowed)


def test_allowlist_permits_only_listed_hosts(proxy):
    allowed = proxy.load_allowlist("example.com, api.github.com")
    assert proxy.is_allowed("example.com", allowed)
    assert proxy.is_allowed("api.github.com", allowed)
    assert not proxy.is_allowed("evil.example", allowed)
    assert not proxy.is_allowed("sub.example.com", allowed)  # exact match only
