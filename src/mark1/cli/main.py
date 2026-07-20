"""`sbx` — the Mark-1 command-line interface.

Uses only the standard library (argparse) so it runs with the core install. The ``run --local``
path exercises the full executor + exit-gate pipeline on your machine, no AWS required.
"""

from __future__ import annotations

import argparse
import json
import sys
import time
from pathlib import Path

from mark1.attest.keys import load_or_create_dev_signer
from mark1.attest.record import Attestation
from mark1.attest.verify import verify_attestation
from mark1.common.api_client import ApiClient
from mark1.common.config import api_endpoint, dev_pubkey_path, home_dir
from mark1.common.models import Limits, RunRequest
from mark1.controlplane.budget import BudgetPolicy, FileLedger
from mark1.controlplane.runner import run_local
from mark1.controlplane.store import FileStore
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
    run.add_argument("--principal", default="default",
                     help="caller identity the cumulative exit-bandwidth budget is keyed on")
    run.add_argument("--budget-bits", type=float, metavar="BITS",
                     help="cap total released exit-bits for --principal (enables the ledger)")
    run.add_argument("--budget-window", type=float, metavar="SECONDS",
                     help="rolling window for --budget-bits (default: cumulative for all time)")
    run.add_argument("--dataset", metavar="DATASET_ID",
                     help="clean room: run against a registered dataset instead of --data")
    run.add_argument("--grant", metavar="TOKEN",
                     help="clean room: the grant token authorizing --principal on --dataset")
    run.set_defaults(func=_cmd_run)

    ds = sub.add_parser("dataset", help="clean room: register datasets and grant access")
    dssub = ds.add_subparsers(dest="dataset_command")
    ds_add = dssub.add_parser("add", help="register a dataset you own")
    ds_add.add_argument("files", nargs="+", metavar="NAME=PATH",
                        help="dataset file(s), NAME=PATH (NAME is how code reads it)")
    ds_add.add_argument("--owner", required=True, help="the data-owner identity")
    ds_add.set_defaults(func=_cmd_dataset_add)
    ds_ls = dssub.add_parser("ls", help="list registered datasets")
    ds_ls.set_defaults(func=_cmd_dataset_ls)
    ds_grant = dssub.add_parser("grant", help="issue a grant token for a dataset")
    ds_grant.add_argument("dataset_id")
    ds_grant.add_argument("--to", required=True, metavar="PROVIDER",
                          help="code-provider to authorize, or 'any'")
    ds_grant.set_defaults(func=_cmd_dataset_grant)
    ds.set_defaults(func=lambda a: (ds.print_help() or 1))

    verify = sub.add_parser("verify", help="verify an attestation file")
    verify.add_argument("attestation", help="path to an attestation JSON")
    verify.add_argument("--pubkey",
                        help="signer public-key PEM: local dev pubkey (default), or a KMS-exported "
                             "PEM for cloud ecdsa-p256 attestations")
    verify.set_defaults(func=_cmd_verify)

    keygen = sub.add_parser("keygen", help="create the local dev signing key if absent")
    keygen.set_defaults(func=_cmd_keygen)

    doctor = sub.add_parser("doctor", help="check the local environment")
    doctor.set_defaults(func=_cmd_doctor)

    dash = sub.add_parser("dashboard", help="serve the local run/audit/attestation dashboard")
    dash.add_argument("--port", type=int, default=8787, help="port to serve on (default 8787)")
    dash.add_argument("--pubkey", help="verifier public-key PEM (defaults to the local dev pubkey)")
    dash.set_defaults(func=_cmd_dashboard)

    return p


def _cmd_run(args: argparse.Namespace) -> int:
    code = Path(args.code).read_text()
    schema = OutputSchema.from_dict(json.loads(Path(args.schema).read_text()))

    if args.dataset:
        return _run_cleanroom_cmd(args, code, schema)

    data = {}
    for spec in args.data:
        if "=" not in spec:
            print(f"error: --data expects NAME=PATH, got {spec!r}", file=sys.stderr)
            return 2
        name, path = spec.split("=", 1)
        data[name] = Path(path).read_text()

    request = RunRequest(
        code=code, data=data, output_schema=schema, limits=Limits(timeout_seconds=args.timeout),
        principal=args.principal,
    )

    if args.local:
        return _run_local_cmd(args, request, schema)
    return _run_cloud_cmd(args, request, schema)


def _run_cleanroom_cmd(args: argparse.Namespace, code: str, schema: OutputSchema) -> int:
    from mark1.controlplane.cleanroom import DatasetStore, Refusal, run_in_cleanroom

    if not args.grant:
        print("error: --dataset requires --grant <token>", file=sys.stderr)
        return 2

    signer = load_or_create_dev_signer()
    outcome = run_in_cleanroom(
        DatasetStore(), args.dataset, args.grant, args.principal, code, schema, signer,
        limits=Limits(timeout_seconds=args.timeout),
    )
    if isinstance(outcome, Refusal):
        print(f"refused:    {outcome.reason} (nothing ran; the data was never materialized)")
        return 4

    store = FileStore()
    store.put_result(outcome.result)
    store.put_audit(outcome.audit)
    store.put_attestation(outcome.attestation)

    print(f"dataset:    {args.dataset}  (owner {outcome.attestation.data_owner})")
    print(f"provider:   {args.principal}")
    _print_result(outcome.result, schema, None, args.principal)
    if args.save_attestation:
        Path(args.save_attestation).write_text(outcome.attestation.model_dump_json(indent=2))
        print(f"saved attestation -> {args.save_attestation}")
    return 0 if outcome.result.status.value == "succeeded" else 3


def _run_local_cmd(args: argparse.Namespace, request: RunRequest, schema: OutputSchema) -> int:
    ledger = budget = None
    if args.budget_bits is not None:
        ledger = FileLedger(home_dir() / "ledger.json")
        budget = BudgetPolicy(max_exit_bits=args.budget_bits, window_seconds=args.budget_window)

    signer = load_or_create_dev_signer()
    outcome = run_local(request, signer, ledger=ledger, budget=budget)

    # Persist to the local store so `sbx dashboard` has a history to show.
    store = FileStore()
    store.put_result(outcome.result)
    store.put_audit(outcome.audit)
    store.put_attestation(outcome.attestation)

    _print_result(outcome.result, schema, budget, args.principal)

    if args.save_attestation:
        Path(args.save_attestation).write_text(outcome.attestation.model_dump_json(indent=2))
        print(f"saved attestation -> {args.save_attestation}")

    return 0 if outcome.result.status.value == "succeeded" else 3


def _run_cloud_cmd(args: argparse.Namespace, request: RunRequest, schema: OutputSchema) -> int:
    endpoint = api_endpoint()
    if not endpoint:
        print("error: set MARK1_API_ENDPOINT to the control-plane URL, or pass --local",
              file=sys.stderr)
        return 2

    client = ApiClient(endpoint)
    pending = client.create_run(request)
    print(f"run:        {pending.run_id}  (submitted; polling…)")

    deadline = time.time() + args.timeout + 180  # run time + cold start/queue headroom
    result = pending
    while result.status.value in ("pending", "running") and time.time() < deadline:
        time.sleep(4)
        result = client.get_run(pending.run_id)

    _print_result(result, schema, None, args.principal)

    if args.save_attestation and result.attestation_id:
        att = client.get_attestation(result.run_id)
        Path(args.save_attestation).write_text(json.dumps(att, indent=2))
        print(f"saved attestation -> {args.save_attestation}")

    return 0 if result.status.value == "succeeded" else 3


def _print_result(r, schema: OutputSchema, budget, principal: str) -> None:
    print(f"run:        {r.run_id}")
    print(f"status:     {r.status.value}")
    print(f"bandwidth:  {bandwidth_bits(schema):.2f} bits (max that could leave)")
    if r.status.value == "succeeded":
        print(f"output:     {json.dumps(r.output)}")
    else:
        print(f"withheld:   {r.withheld_reason}")
    if budget is not None and r.cumulative_exit_bits is not None:
        print(f"budget:     {r.cumulative_exit_bits:.2f}/{budget.max_exit_bits:.2f} bits used"
              f" (principal '{principal}')")
    print(f"attestation:{r.attestation_id}")


def _cmd_verify(args: argparse.Namespace) -> int:
    att = Attestation.model_validate_json(Path(args.attestation).read_text())
    pubkey_path = Path(args.pubkey) if args.pubkey else dev_pubkey_path()
    if not pubkey_path.exists():
        print(f"error: no public key at {pubkey_path}", file=sys.stderr)
        return 2
    ok = verify_attestation(att, pubkey_path.read_bytes())
    print("VALID" if ok else "INVALID", f"attestation {att.attestation_id}")
    print(f"  algorithm:  {att.algorithm}")
    print(f"  released:   {att.released}")
    print(f"  bandwidth:  {att.exit_bandwidth_bits:.2f} bits")
    print(f"  egress:     {att.egress_denied}/{att.egress_attempts} denied")
    return 0 if ok else 1


def _cmd_dashboard(args: argparse.Namespace) -> int:
    from mark1.dashboard.server import serve

    pubkey_path = Path(args.pubkey) if args.pubkey else dev_pubkey_path()
    pubkey_pem = pubkey_path.read_bytes() if pubkey_path.exists() else None

    store = FileStore()
    url = f"http://127.0.0.1:{args.port}"
    print(f"Mark-1 dashboard on {url}  (reading ~/.mark1/store; Ctrl-C to stop)")
    if pubkey_pem is None:
        print("  note: no public key found — signatures will show as unverified")
    serve(store, pubkey_pem, port=args.port)
    return 0


def _cmd_dataset_add(args: argparse.Namespace) -> int:
    from mark1.controlplane.cleanroom import DatasetStore

    files = {}
    for spec in args.files:
        if "=" not in spec:
            print(f"error: expected NAME=PATH, got {spec!r}", file=sys.stderr)
            return 2
        name, path = spec.split("=", 1)
        files[name] = Path(path).read_text()

    ds = DatasetStore().add(args.owner, files)
    print(f"dataset:    {ds.dataset_id}")
    print(f"owner:      {ds.owner}")
    print(f"data hash:  {ds.data_sha256}")
    print(f"files:      {', '.join(ds.filenames)}")
    print(f"\nGrant a code-provider access:\n  sbx dataset grant {ds.dataset_id} --to <provider>")
    return 0


def _cmd_dataset_ls(args: argparse.Namespace) -> int:
    from mark1.controlplane.cleanroom import DatasetStore

    datasets = DatasetStore().list()
    if not datasets:
        print("no datasets registered (try: sbx dataset add NAME=PATH --owner you)")
        return 0
    for d in datasets:
        print(f"{d.dataset_id}  owner={d.owner}  {d.data_sha256[:12]}…  {', '.join(d.filenames)}")
    return 0


def _cmd_dataset_grant(args: argparse.Namespace) -> int:
    from mark1.controlplane.cleanroom import DatasetStore

    store = DatasetStore()
    if store.get(args.dataset_id) is None:
        print(f"error: no such dataset {args.dataset_id}", file=sys.stderr)
        return 2
    grantee = "*" if args.to == "any" else args.to
    grant = store.grant(args.dataset_id, grantee)
    print(f"grant token: {grant.grant_id}")
    print(f"authorizes:  {grant.grantee}  on  {grant.dataset_id}")
    print(f"\nThe code-provider runs:\n  sbx run code.py --dataset {args.dataset_id}"
          f" --grant {grant.grant_id} --principal {grantee if grantee != '*' else '<provider>'}"
          f" --schema schema.json")
    return 0


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
    try:
        import mcp  # noqa: F401
        print("  mcp:        ok (mark1-mcp serves AI agents over stdio)")
    except ImportError:
        print("  mcp:        missing (pip install 'mark1[mcp]' to serve AI agents)")
    try:
        import boto3  # noqa: F401
        print("  boto3:      ok (cloud runs available)")
    except ImportError:
        print("  boto3:      missing (pip install 'mark1[cloud]' for cloud runs)")
    from mark1.common.config import dev_key_path
    if dev_key_path().exists():
        print("  dev key:    ok")
    else:
        print("  dev key:    absent (created on first run, or `sbx keygen`)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
