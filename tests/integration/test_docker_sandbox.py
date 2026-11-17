"""The docker backend: the same escape attempts as the bubblewrap tests, in a container.

Gated behind KEYHOLE_DOCKER=1 (needs a Docker daemon and the python:3.12-slim image).
"""

from __future__ import annotations

import os
import shutil
import subprocess
import time

import pytest

from keyhole.attest.sign import Ed25519Signer
from keyhole.common.models import Limits, RunRequest, RunStatus
from keyhole.controlplane.runner import run_local
from keyhole.schema.spec import OutputSchema, SchemaType

pytestmark = pytest.mark.skipif(
    not os.environ.get("KEYHOLE_DOCKER") or shutil.which("docker") is None,
    reason="requires Docker; set KEYHOLE_DOCKER=1 to run",
)
BOOL = OutputSchema(type=SchemaType.BOOLEAN)


@pytest.fixture(autouse=True)
def _docker_backend(monkeypatch):
    monkeypatch.setenv("KEYHOLE_SANDBOX", "docker")


def _run(code: str, timeout: int = 20, **kw):
    req = RunRequest(code=code, data={"customers.csv": "secret,row"}, output_schema=BOOL,
                     limits=Limits(timeout_seconds=timeout, **kw))
    return run_local(req, Ed25519Signer.generate())


def _probe(body: str) -> str:
    return ("import os, json\ngot = False\ntry:\n" +
            "\n".join("    " + line for line in body.splitlines()) +
            "\nexcept Exception:\n    pass\n"
            "json.dump(got, open(os.environ['KEYHOLE_OUTPUT'], 'w'))")


def test_honest_code_runs_and_is_attested_as_docker():
    out = _run("import os, json\njson.dump(len(open('customers.csv').read()) > 0, "
               "open(os.environ['KEYHOLE_OUTPUT'], 'w'))")
    assert out.result.status is RunStatus.SUCCEEDED and out.result.output is True
    assert out.attestation.isolation == "docker"


def test_no_network():
    out = _run(_probe("import socket\nsocket.create_connection(('1.1.1.1', 53), timeout=2)\n"
                      "got = True"))
    assert out.result.output is False


def test_host_home_and_signing_key_are_not_visible():
    target = os.path.expanduser("~")
    out = _run(_probe(f"import os\ngot = os.path.exists({target!r}) and "
                      f"len(os.listdir({target!r})) > 0"))
    assert out.result.output is False


def test_root_filesystem_is_read_only():
    out = _run(_probe("open('/usr/local/planted', 'w').write('x')\ngot = True"))
    assert out.result.output is False


def test_timeout_removes_the_container():
    started = time.monotonic()
    out = _run("import time\ntime.sleep(60)", timeout=3)
    assert out.audit.status is RunStatus.TIMEOUT
    assert time.monotonic() - started < 30
    left = subprocess.run(["docker", "ps", "-q", "--filter", "name=keyhole-"],
                          capture_output=True, text=True).stdout.strip()
    assert left == ""


def test_fork_bomb_is_contained():
    code = "import os\nwhile True:\n    try:\n        os.fork()\n    except OSError:\n        pass"
    out = _run(code, timeout=5)
    assert out.result.status is not RunStatus.SUCCEEDED
