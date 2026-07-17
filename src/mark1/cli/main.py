"""`sbx` — the Mark-1 command-line interface.

Uses only the standard library (argparse) so it runs with the core install. The ``run --local``
path exercises the full executor + exit-gate pipeline on your machine, no AWS required.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from mark1.attest.keys import load_or_create_dev_signer
from mark1.attest.record import Attestation
from mark1.attest.verify import verify_attestation
from mark1.common.config import dev_pubkey_path
from mark1.common.models import Limits, RunRequest
from mark1.controlplane.runner import run_local
from mark1.schema.bandwidth import bandwidth_bits
from mark1.schema.spec import OutputSchema


def main(argv: list[str] | None = None) -> int:
    parser = _build_parser()
    args = parser.parse_args(argv)
    if not getattr(args, "func", None):
        parser.print_help()
        return 1
    return args.func(args)


def _build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="sbx", description="Mark-1 confidential code execution")
    sub = p.add_subparsers(dest="command")

    run = sub.add_parser("run", help="run code on supplied data under a declared exit schema")
    run.add_argument("code", help="path to the Python file to run")
    run.add_argument("--data", action="append", default=[], metavar="NAME=PATH",
                     help="supply a data file into the sandbox (repeatable)")
    run.add_argument("--schema", required=True, help="path to the output-schema JSON")
    run.add_argument("--local", action="store_true", help="run locally (no AWS)")
    run.add_argument("--timeout", type=int, default=60, help="wall-clock timeout (seconds)")
    run.add_argument("--save-attestation", metavar="PATH", help="write the attestation JSON here")
    run.set_defaults(func=_cmd_run)

    verify = sub.add_parser("verify", help="verify an attestation file")
    verify.add_argument("attestation", help="path to an attestation JSON")
    verify.add_argument("--pubkey", help="signer public-key PEM (defaults to local dev pubkey)")
    verify.set_defaults(func=_cmd_verify)

    keygen = sub.add_parser("keygen", help="create the local dev signing key if absent")
    keygen.set_defaults(func=_cmd_keygen)

    doctor = sub.add_parser("doctor", help="check the local environment")
    doctor.set_defaults(func=_cmd_doctor)

    return p


def _cmd_run(args: argparse.Namespace) -> int:
    code = Path(args.code).read_text()
    schema = OutputSchema.from_dict(json.loads(Path(args.schema).read_text()))
    data = {}
    for spec in args.data:
        if "=" not in spec:
            print(f"error: --data expects NAME=PATH, got {spec!r}", file=sys.stderr)
            return 2
        name, path = spec.split("=", 1)
        data[name] = Path(path).read_text()

    request = RunRequest(
        code=code, data=data, output_schema=schema, limits=Limits(timeout_seconds=args.timeout)
    )

    if not args.local:
        print("error: only --local is supported in this build; pass --local", file=sys.stderr)
        return 2

    signer = load_or_create_dev_signer()
    outcome = run_local(request, signer)
    r = outcome.result

    print(f"run:        {r.run_id}")
    print(f"status:     {r.status.value}")
    print(f"bandwidth:  {bandwidth_bits(schema):.2f} bits (max that could leave)")
    if r.status.value == "succeeded":
        print(f"output:     {json.dumps(r.output)}")
    else:
        print(f"withheld:   {r.withheld_reason}")
    print(f"attestation:{r.attestation_id}")

    if args.save_attestation:
        Path(args.save_attestation).write_text(outcome.attestation.model_dump_json(indent=2))
        print(f"saved attestation -> {args.save_attestation}")

    return 0 if r.status.value == "succeeded" else 3


def _cmd_verify(args: argparse.Namespace) -> int:
    att = Attestation.model_validate_json(Path(args.attestation).read_text())
    pubkey_path = Path(args.pubkey) if args.pubkey else dev_pubkey_path()
    if not pubkey_path.exists():
        print(f"error: no public key at {pubkey_path}", file=sys.stderr)
        return 2
    ok = verify_attestation(att, pubkey_path.read_bytes())
    print("VALID" if ok else "INVALID", f"attestation {att.attestation_id}")
    print(f"  released:   {att.released}")
    print(f"  bandwidth:  {att.exit_bandwidth_bits:.2f} bits")
    print(f"  egress:     {att.egress_denied}/{att.egress_attempts} denied")
    return 0 if ok else 1


def _cmd_keygen(args: argparse.Namespace) -> int:
    signer = load_or_create_dev_signer()
    print(f"dev signing key id: {signer.key_id}")
    print(f"public key:         {dev_pubkey_path()}")
    return 0


def _cmd_doctor(args: argparse.Namespace) -> int:
    import shutil

    print("Mark-1 environment check")
    print(f"  python:     {sys.version.split()[0]}")
    print(f"  docker:     {'found' if shutil.which('docker') else 'MISSING (needed for M1 image runs)'}")
    print(f"  terraform:  {'found' if shutil.which('terraform') else 'missing (needed to deploy)'}")
    try:
        import cryptography  # noqa: F401
        print("  crypto:     ok")
    except ImportError:
        print("  crypto:     MISSING (pip install cryptography)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
