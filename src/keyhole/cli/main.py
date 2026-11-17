"""`sbx` — the Keyhole command-line interface.

Uses only the standard library (argparse) so it runs with the core install. The ``run --local``
path exercises the full executor + exit-gate pipeline on your machine, no AWS required.
"""

from __future__ import annotations

import argparse
import json
import sys
import time
from pathlib import Path

from keyhole.attest.keys import load_or_create_dev_signer
from keyhole.attest.record import Attestation
from keyhole.attest.verify import verify_attestation
from keyhole.common.api_client import ApiClient
from keyhole.common.config import api_endpoint, dev_pubkey_path, home_dir
from keyhole.common.models import Limits, RunRequest
from keyhole.controlplane.budget import BudgetPolicy, FileLedger
from keyhole.controlplane.runner import run_local
from keyhole.controlplane.store import FileStore
from keyhole.schema.bandwidth import bandwidth_bits, run_channel_bits
from keyhole.schema.spec import OutputSchema


def main(argv: list[str] | None = None) -> int:
    parser = _build_parser()
    args = parser.parse_args(argv)
    if not getattr(args, "func", None):
        parser.print_help()
        return 1
    return args.func(args)


def _build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="sbx", description="Keyhole confidential code execution")
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
    run.add_argument("--on", choices=["real", "mock"], default="real",
                     help="clean room: 'mock' runs on the owner's mock data with full debug "
                          "output (free); 'real' returns only the bounded answer (default)")
    run.set_defaults(func=_cmd_run)

    ds = sub.add_parser("dataset", help="clean room: register datasets and grant access")
    dssub = ds.add_subparsers(dest="dataset_command")
    ds_add = dssub.add_parser("add", help="register a dataset you own")
    ds_add.add_argument("files", nargs="+", metavar="NAME=PATH",
                        help="dataset file(s), NAME=PATH (NAME is how code reads it)")
    ds_add.add_argument("--owner", required=True, help="the data-owner identity")
    ds_add.add_argument("--max-bits-per-run", type=float, required=True, metavar="BITS",
                        help="exit policy: the widest answer one run may carry")
    ds_add.add_argument("--budget-bits", type=float, required=True, metavar="BITS",
                        help="exit policy: total bits that may ever leave this dataset")
    ds_add.add_argument("--budget-window", type=float, metavar="SECONDS",
                        help="make --budget-bits a rolling window (default: for all time)")
    ds_add.add_argument("--describe", default="", metavar="TEXT",
                        help="what the data is and how it is laid out (shown to code providers)")
    ds_add.add_argument("--mock", action="append", default=[], metavar="NAME=PATH",
                        help="non-sensitive stand-in file of the same shape (repeatable)")
    ds_add.add_argument("--cloud", action="store_true",
                        help="register on the cloud control plane (KEYHOLE_API_ENDPOINT, "
                             "KEYHOLE_OWNER_KEY) instead of the local registry")
    ds_add.set_defaults(func=_cmd_dataset_add)
    ds_ls = dssub.add_parser("ls", help="list registered datasets")
    ds_ls.set_defaults(func=_cmd_dataset_ls)
    ds_grant = dssub.add_parser("grant", help="issue a grant token for a dataset")
    ds_grant.add_argument("dataset_id")
    ds_grant.add_argument("--to", required=True, metavar="PROVIDER",
                          help="code-provider to authorize, or 'any'")
    ds_grant.add_argument("--cloud", action="store_true",
                          help="grant on the cloud control plane (KEYHOLE_OWNER_KEY)")
    ds_grant.set_defaults(func=_cmd_dataset_grant)
    def _ds_help(_args: argparse.Namespace) -> int:
        ds.print_help()
        return 1

    ds.set_defaults(func=_ds_help)

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
        if api_endpoint() and not args.local:
            if not args.grant:
                print("error: --dataset requires --grant <token>", file=sys.stderr)
                return 2
            request = RunRequest(code=code, output_schema=schema, principal=args.principal,
                                 limits=Limits(timeout_seconds=args.timeout),
                                 dataset_id=args.dataset)
            return _run_cloud_cmd(args, request, schema, grant=args.grant)
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
    from keyhole.controlplane.cleanroom import (
        DatasetStore,
        Refusal,
        run_in_cleanroom,
        run_on_mock,
    )

    if not args.grant:
        print("error: --dataset requires --grant <token>", file=sys.stderr)
        return 2
    if args.budget_bits is not None:
        print("note: --budget-bits is ignored with --dataset; the data owner set the budget")

    dstore = DatasetStore()
    limits = Limits(timeout_seconds=args.timeout)
    if args.on == "mock":
        mock = run_on_mock(dstore, args.dataset, args.grant, args.principal, code, schema, limits)
        if isinstance(mock, Refusal):
            print(f"refused:    {mock.reason}")
            return 4
        print(f"mock run:   {'output conforms' if mock.conforms else 'needs fixing'}"
              f"  (exit {mock.exit_code}{', timed out' if mock.timed_out else ''})")
        for err in mock.errors:
            print(f"  - {err}")
        print(f"output:     {mock.output_raw}")
        if mock.stdout:
            print(f"--- stdout\n{mock.stdout.rstrip()}")
        if mock.stderr:
            print(f"--- stderr\n{mock.stderr.rstrip()}")
        return 0 if mock.conforms else 3

    signer = load_or_create_dev_signer()
    outcome = run_in_cleanroom(
        dstore, args.dataset, args.grant, args.principal, code, schema, signer, limits=limits,
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
    ds = dstore.get(args.dataset)
    if ds is not None:
        print(f"budget:     {dstore.bits_spent(ds):.2f}/{ds.budget_bits:.2f} bits of this dataset"
              " (all providers)")
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
    # With --data, whoever runs this supplied the data, so they are its owner and may see the audit.
    owner_reason = outcome.audit.withheld_reason
    if owner_reason and owner_reason != outcome.result.withheld_reason:
        print(f"owner view: {outcome.audit.status.value}: {owner_reason}")

    if args.save_attestation:
        Path(args.save_attestation).write_text(outcome.attestation.model_dump_json(indent=2))
        print(f"saved attestation -> {args.save_attestation}")

    return 0 if outcome.result.status.value == "succeeded" else 3


def _client(owner: bool = False) -> ApiClient | None:
    import os

    endpoint = api_endpoint()
    if not endpoint:
        print("error: set KEYHOLE_API_ENDPOINT to the control-plane URL, or pass --local",
              file=sys.stderr)
        return None
    key = os.environ.get("KEYHOLE_OWNER_KEY" if owner else "KEYHOLE_API_KEY")
    if not key:
        print(f"error: set {'KEYHOLE_OWNER_KEY' if owner else 'KEYHOLE_API_KEY'}",
              file=sys.stderr)
        return None
    return ApiClient(endpoint, api_key=key)


def _http_error(exc: Exception) -> int:
    """Print an API refusal (403: the reason never depends on the data) or error, and its code."""
    import urllib.error

    if isinstance(exc, urllib.error.HTTPError):
        try:
            reason = json.loads(exc.read().decode("utf-8")).get("error", "")
        except ValueError:
            reason = ""
        label = "refused:" if exc.code == 403 else f"error {exc.code}:"
        print(f"{label:11} {reason}")
        return 4 if exc.code == 403 else 2
    raise exc


def _run_cloud_cmd(args: argparse.Namespace, request: RunRequest, schema: OutputSchema,
                   grant: str | None = None) -> int:
    import urllib.error

    client = _client()
    if client is None:
        return 2
    try:
        pending = (client.run_dataset(request, grant) if grant is not None
                   else client.create_run(request))
    except urllib.error.HTTPError as exc:
        return _http_error(exc)
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
    print(f"bandwidth:  {bandwidth_bits(schema):.2f} bits per answer, "
          f"{run_channel_bits(schema):.2f} per run (max that could leave)")
    if r.status.value == "succeeded":
        print(f"output:     {json.dumps(r.output)}")
    else:
        print(f"withheld:   {r.withheld_reason}")
    if budget is not None and r.cumulative_exit_bits is not None:
        print(f"budget:     {r.cumulative_exit_bits:.2f}/{budget.max_exit_bits:.2f} bits charged"
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
    print(f"  sandbox:    {att.isolation}"
          + ("  (exit gate only: the code had network and file access)"
             if att.isolation == "none" else ""))
    print(f"  bandwidth:  {att.exit_bandwidth_bits:.2f} bits")
    print(f"  charged:    {att.run_channel_bits:.2f} bits for this run")
    if att.cumulative_exit_bits is not None:
        print(f"  cumulative: {att.cumulative_exit_bits:.2f} bits against this budget")
    return 0 if ok else 1


def _cmd_dashboard(args: argparse.Namespace) -> int:
    from keyhole.dashboard.server import serve

    pubkey_path = Path(args.pubkey) if args.pubkey else dev_pubkey_path()
    pubkey_pem = pubkey_path.read_bytes() if pubkey_path.exists() else None

    store = FileStore()
    url = f"http://127.0.0.1:{args.port}"
    print(f"Keyhole dashboard on {url}  (reading ~/.keyhole/store; Ctrl-C to stop)")
    if pubkey_pem is None:
        print("  note: no public key found — signatures will show as unverified")
    serve(store, pubkey_pem, port=args.port)
    return 0


def _cmd_dataset_add_cloud(args: argparse.Namespace, files: dict[str, str],
                           mock: dict[str, str]) -> int:
    import urllib.error

    client = _client(owner=True)
    if client is None:
        return 2
    try:
        ds = client.create_dataset({
            "owner": args.owner, "files": files, "mock": mock, "description": args.describe,
            "max_bits_per_run": args.max_bits_per_run, "budget_bits": args.budget_bits,
        })
    except urllib.error.HTTPError as exc:
        return _http_error(exc)
    print(f"dataset:    {ds['dataset_id']}  (cloud)")
    print(f"owner:      {ds['owner']}")
    print(f"exit policy: at most {ds['max_bits_per_run']:g} bits per run, "
          f"{ds['budget_bits']:g} in total")
    print(f"\nGrant a code-provider access:\n  sbx dataset grant {ds['dataset_id']} --to <provider>"
          " --cloud")
    return 0


def _cmd_dataset_add(args: argparse.Namespace) -> int:
    from keyhole.controlplane.cleanroom import DatasetStore

    files = {}
    for spec in args.files:
        if "=" not in spec:
            print(f"error: expected NAME=PATH, got {spec!r}", file=sys.stderr)
            return 2
        name, path = spec.split("=", 1)
        files[name] = Path(path).read_text()
    mock = {}
    for spec in args.mock:
        if "=" not in spec:
            print(f"error: --mock expects NAME=PATH, got {spec!r}", file=sys.stderr)
            return 2
        name, path = spec.split("=", 1)
        mock[name] = Path(path).read_text()

    if args.cloud:
        if args.budget_window is not None:
            print("error: cloud budgets are cumulative; drop --budget-window", file=sys.stderr)
            return 2
        return _cmd_dataset_add_cloud(args, files, mock)
    ds = DatasetStore().add(
        args.owner, files, max_bits_per_run=args.max_bits_per_run, budget_bits=args.budget_bits,
        budget_window_seconds=args.budget_window, description=args.describe, mock=mock,
    )
    print(f"dataset:    {ds.dataset_id}")
    print(f"owner:      {ds.owner}")
    print(f"exit policy: at most {ds.max_bits_per_run:g} bits per run, {ds.budget_bits:g} in total")
    print(f"data hash:  {ds.data_sha256}")
    print(f"files:      {', '.join(ds.filenames)}")
    print(f"\nGrant a code-provider access:\n  sbx dataset grant {ds.dataset_id} --to <provider>")
    return 0


def _cmd_dataset_ls(args: argparse.Namespace) -> int:
    from keyhole.controlplane.cleanroom import DatasetStore

    datasets = DatasetStore().list()
    if not datasets:
        print("no datasets registered (try: sbx dataset add NAME=PATH --owner you)")
        return 0
    for d in datasets:
        print(f"{d.dataset_id}  owner={d.owner}  {d.data_sha256[:12]}…  {', '.join(d.filenames)}")
    return 0


def _cmd_dataset_grant(args: argparse.Namespace) -> int:
    from keyhole.controlplane.cleanroom import DatasetStore

    grantee = "*" if args.to == "any" else args.to
    if args.cloud:
        import urllib.error

        client = _client(owner=True)
        if client is None:
            return 2
        try:
            g = client.create_grant(args.dataset_id, grantee)
        except urllib.error.HTTPError as exc:
            return _http_error(exc)
        print(f"grant token: {g['grant_id']}  (cloud)")
        print(f"authorizes:  {g['grantee']}  on  {g['dataset_id']}")
        return 0

    store = DatasetStore()
    if store.get(args.dataset_id) is None:
        print(f"error: no such dataset {args.dataset_id}", file=sys.stderr)
        return 2
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

    print("Keyhole environment check")
    print(f"  python:     {sys.version.split()[0]}")
    docker = "found" if shutil.which("docker") else "MISSING (needed for M1 image runs)"
    print(f"  docker:     {docker}")
    print(f"  terraform:  {'found' if shutil.which('terraform') else 'missing (needed to deploy)'}")
    try:
        import cryptography  # noqa: F401
        print("  crypto:     ok")
    except ImportError:
        print("  crypto:     MISSING (pip install cryptography)")
    try:
        import mcp  # noqa: F401
        print("  mcp:        ok (keyhole-mcp serves AI agents over stdio)")
    except ImportError:
        print("  mcp:        missing (pip install 'keyhole[mcp]' to serve AI agents)")
    try:
        import boto3  # noqa: F401
        print("  boto3:      ok (cloud runs available)")
    except ImportError:
        print("  boto3:      missing (pip install 'keyhole[cloud]' for cloud runs)")
    from keyhole.common.config import dev_key_path
    if dev_key_path().exists():
        print("  dev key:    ok")
    else:
        print("  dev key:    absent (created on first run, or `sbx keygen`)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
