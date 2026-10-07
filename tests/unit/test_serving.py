"""The MCP tool and control-plane handler reuse the same guarantee."""

from keyhole.attest.keys import load_or_create_dev_signer
from keyhole.common.models import Limits, RunRequest
from keyhole.controlplane.app import handle_create_run_local, handle_get_run
from keyhole.controlplane.store import InMemoryStore
from keyhole.mcp.server import run_confidential
from keyhole.schema.spec import OutputSchema, SchemaType

_CLASSIFY = """
import os, json
json.dump("spam", open(os.environ["KEYHOLE_OUTPUT"], "w"))
"""

_EXFIL = """
import os, json
json.dump(open("d.txt").read(), open(os.environ["KEYHOLE_OUTPUT"], "w"))
"""


def test_mcp_tool_releases_conforming_output():
    out = run_confidential(
        code=_CLASSIFY,
        data={},
        output_schema={"type": "enum", "choices": ["spam", "ham"]},
    )
    assert out["status"] == "succeeded"
    assert out["output"] == "spam"
    assert out["attestation_id"]


def test_mcp_tool_withholds_exfiltration():
    out = run_confidential(
        code=_EXFIL,
        data={"d.txt": "top secret dataset"},
        output_schema={"type": "enum", "choices": ["spam", "ham"]},
    )
    assert out["status"] == "withheld"
    assert out["output"] is None


def test_handler_persists_result_and_audit():
    store = InMemoryStore()
    signer = load_or_create_dev_signer()
    req = RunRequest(
        code=_CLASSIFY,
        data={},
        output_schema=OutputSchema(type=SchemaType.ENUM, choices=["spam", "ham"]),
        limits=Limits(),
    )
    result = handle_create_run_local(req, store, signer)
    assert handle_get_run(result.run_id, store) is result
    assert store.get_audit(result.run_id) is not None
    assert store.get_attestation(result.attestation_id) is not None
