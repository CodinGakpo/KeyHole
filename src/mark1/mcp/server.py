"""MCP server: let an AI agent run code on private data with a structural no-exfiltration guarantee.

Exposes ``run_confidential`` (and read-backs) as MCP tools. An agent supplies untrusted code, the
data, and a narrow output schema; it gets back only the schema-conforming value plus an
attestation id. Requires the ``mcp`` extra.

Business logic is intentionally thin here — it delegates to the same runner/exit-gate used
everywhere else, so the guarantee is identical across CLI, API, and MCP.
"""

from __future__ import annotations

from typing import Any

from mark1.attest.keys import load_or_create_dev_signer
from mark1.common.models import Limits, RunRequest
from mark1.controlplane.runner import run_local
from mark1.schema.spec import OutputSchema


def run_confidential(
    code: str,
    data: dict[str, str],
    output_schema: dict[str, Any],
    timeout_seconds: int = 60,
) -> dict[str, Any]:
    """Core tool implementation, independent of the MCP transport (so it's directly testable)."""
    request = RunRequest(
        code=code,
        data=data,
        output_schema=OutputSchema.from_dict(output_schema),
        limits=Limits(timeout_seconds=timeout_seconds),
    )
    signer = load_or_create_dev_signer()
    outcome = run_local(request, signer)
    return {
        "status": outcome.result.status.value,
        "output": outcome.result.output,
        "withheld_reason": outcome.result.withheld_reason,
        "exit_bandwidth_bits": outcome.result.exit_bandwidth_bits,
        "attestation_id": outcome.result.attestation_id,
    }


def main() -> int:
    """Entry point for the ``mark1-mcp`` script. Requires the ``mcp`` extra."""
    try:
        from mcp.server.fastmcp import FastMCP
    except ImportError:
        print("The MCP server requires the 'mcp' extra: pip install 'mark1[mcp]'")
        return 1

    server = FastMCP("mark1")

    @server.tool()
    def run_confidential_tool(
        code: str,
        data: dict[str, str],
        output_schema: dict[str, Any],
        timeout_seconds: int = 60,
    ) -> dict[str, Any]:
        """Run untrusted code on supplied data; return only a schema-conforming, attested value."""
        return run_confidential(code, data, output_schema, timeout_seconds)

    server.run()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
