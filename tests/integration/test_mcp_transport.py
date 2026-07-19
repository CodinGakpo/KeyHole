"""M7: the confidentiality guarantee holds *through the MCP wire*, not just in-process.

Spawns the real ``mark1-mcp`` server (``python -m mark1.mcp.server``) over stdio and drives it
with the MCP client: list the tool, run an honest classifier (released + attested), run an
exfiltrator (withheld, nothing released).

Skips automatically when the ``mcp`` extra isn't installed, so the core-only install stays green.
"""

from __future__ import annotations

import asyncio
import json
import os
import sys
from typing import Any

import pytest

mcp = pytest.importorskip("mcp", reason="requires the 'mcp' extra: pip install 'mark1[mcp]'")

from mcp import ClientSession, StdioServerParameters  # noqa: E402
from mcp.client.stdio import stdio_client  # noqa: E402

_HONEST = """
import os, json
rows = open("customers.csv").read().splitlines()
json.dump("spam" if len(rows) > 1 else "ham", open(os.environ["MARK1_OUTPUT"], "w"))
"""

_EXFIL = """
import os, json
json.dump(open("customers.csv").read(), open(os.environ["MARK1_OUTPUT"], "w"))
"""

_SCHEMA = {"type": "enum", "choices": ["spam", "ham", "other"]}
_DATA = {"customers.csv": "a,spam\nb,ham\n"}


def _server_params(tmp_path) -> StdioServerParameters:
    return StdioServerParameters(
        command=sys.executable,
        args=["-m", "mark1.mcp.server"],
        env={"PATH": os.environ.get("PATH", ""), "MARK1_HOME": str(tmp_path)},
    )


def _payload(result) -> dict[str, Any]:
    """Extract the tool's dict return from an MCP CallToolResult."""
    if result.structuredContent:
        sc = result.structuredContent
        return sc.get("result", sc) if isinstance(sc, dict) and "result" in sc else sc
    return json.loads(result.content[0].text)


async def _call(tmp_path, arguments: dict[str, Any]) -> dict[str, Any]:
    async with stdio_client(_server_params(tmp_path)) as (read, write):
        async with ClientSession(read, write) as session:
            await session.initialize()
            tools = await session.list_tools()
            assert "run_confidential_tool" in [t.name for t in tools.tools]
            result = await session.call_tool("run_confidential_tool", arguments)
            assert not result.isError
            return _payload(result)


def test_honest_run_is_released_and_attested_over_mcp(tmp_path):
    out = asyncio.run(
        _call(tmp_path, {"code": _HONEST, "data": _DATA, "output_schema": _SCHEMA})
    )
    assert out["status"] == "succeeded"
    assert out["output"] == "spam"
    assert out["attestation_id"]
    assert out["exit_bandwidth_bits"] == pytest.approx(1.585, abs=0.001)


def test_exfiltration_is_withheld_over_mcp(tmp_path):
    out = asyncio.run(
        _call(tmp_path, {"code": _EXFIL, "data": _DATA, "output_schema": _SCHEMA})
    )
    assert out["status"] == "withheld"
    assert out["output"] is None
    assert "schema" in out["withheld_reason"]
    assert out["attestation_id"]  # even a withheld run is attested
