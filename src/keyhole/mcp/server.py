"""MCP server: let an AI agent answer questions about private data it never gets to see.

The server runs on the data owner's side, next to the dataset registry. The agent is the
code-provider ``KEYHOLE_PRINCIPAL`` (default ``agent``) and sees only datasets the owner granted
it. Tools:

* ``list_datasets`` — what each dataset is, its mock rows, and how much exit budget is left.
* ``run`` — run code on a dataset's mock (full debug output) or real data (bounded answer only).
* ``run_confidential_tool`` — the inline mode: the *caller* supplies the data. It protects
  nothing from the caller, who already has the data; its use is bounding what comes back from
  processing content the agent does not trust (a 2-bit label cannot carry a prompt injection).

Requires the ``mcp`` extra.

Business logic is intentionally thin here — it delegates to the same runner/exit-gate used
everywhere else, so the guarantee is identical across CLI, API, and MCP.
"""

from __future__ import annotations

import os
from typing import Any

from keyhole import api
from keyhole.attest.keys import load_or_create_dev_signer
from keyhole.common.models import Limits, RunRequest
from keyhole.controlplane.runner import run_local
from keyhole.schema.spec import OutputSchema


def run_confidential(
    code: str,
    data: dict[str, str],
    output_schema: dict[str, Any],
    timeout_seconds: int = 60,
    principal: str = "default",
) -> dict[str, Any]:
    """Core tool implementation, independent of the MCP transport (so it's directly testable)."""
    request = RunRequest(
        code=code,
        data=data,
        output_schema=OutputSchema.from_dict(output_schema),
        limits=Limits(timeout_seconds=timeout_seconds),
        principal=principal,
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
    """Entry point for the ``keyhole-mcp`` script. Requires the ``mcp`` extra."""
    try:
        from mcp.server.fastmcp import FastMCP
    except ImportError:
        print("The MCP server requires the 'mcp' extra: pip install 'keyhole[mcp]'")
        return 1

    server = FastMCP("keyhole")
    principal_id = os.environ.get("KEYHOLE_PRINCIPAL", "agent")

    @server.tool()
    def list_datasets() -> list[dict[str, Any]]:
        """Private datasets you may compute on. You never receive the real rows — each entry has
        a description, mock rows of the same shape, and the exit policy: the most bits one run
        may return and how much of the total budget is left."""
        return api.list_datasets(principal_id)

    @server.tool()
    def run(
        dataset_id: str,
        code: str,
        output_schema: dict[str, Any],
        on: str = "mock",
        timeout_seconds: int = 60,
    ) -> dict[str, Any]:
        """Run Python on a dataset. The code reads the dataset's files by name from the working
        directory and writes ONE JSON value to the path in $KEYHOLE_OUTPUT. output_schema declares
        that value narrowly, e.g. {"type":"enum","choices":[...]}, {"type":"integer","minimum":0,
        "maximum":100}, {"type":"boolean"}; narrower schemas spend less budget.

        on="mock": runs on mock rows and returns stdout, stderr and validation errors. Free; use
        it until the code works. on="real": runs on the real data and returns only the answer.
        Failures there are deliberately unexplained and still spend budget, so debug on mock."""
        if on not in ("mock", "real"):
            return {"status": "refused", "reason": "on must be 'mock' or 'real'"}
        from keyhole.controlplane.store import FileStore

        return api.run(dataset_id, code, output_schema, principal=principal_id,
                       on=on, timeout_seconds=timeout_seconds,  # type: ignore[arg-type]
                       audit=FileStore())

    @server.tool()
    def run_confidential_tool(
        code: str,
        data: dict[str, str],
        output_schema: dict[str, Any],
        timeout_seconds: int = 60,
        principal: str = "default",
    ) -> dict[str, Any]:
        """Run code on data YOU supply; return only a schema-conforming, attested value. Use this
        to process content you do not trust and get back a bounded answer. For private datasets
        use `run` instead — there the data never reaches you."""
        return run_confidential(code, data, output_schema, timeout_seconds, principal)

    server.run()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
