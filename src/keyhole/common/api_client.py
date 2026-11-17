"""Thin REST client for the control plane, shared by the CLI and the MCP server.

Standard-library only (urllib) to avoid a heavy dependency. Used on the cloud path when
``KEYHOLE_API_ENDPOINT`` is set; the local path calls the runner in-process instead.
"""

from __future__ import annotations

import json
import urllib.request
from typing import Any

from keyhole.common.models import RunRequest, RunResult


class ApiClient:
    def __init__(self, endpoint: str, api_key: str | None = None, timeout: float = 30.0) -> None:
        self.endpoint = endpoint.rstrip("/")
        self.api_key = api_key
        self.timeout = timeout

    def create_run(self, request: RunRequest) -> RunResult:
        data = self._post("/runs", request.model_dump(mode="json"))
        return RunResult.model_validate(data)

    def get_run(self, run_id: str) -> RunResult:
        return RunResult.model_validate(self._get(f"/runs/{run_id}"))

    def get_audit(self, run_id: str) -> dict[str, Any]:
        return self._get(f"/runs/{run_id}/audit")

    def get_attestation(self, run_id: str) -> dict[str, Any]:
        return self._get(f"/runs/{run_id}/attestation")

    def run_dataset(self, request: RunRequest, grant: str) -> RunResult:
        """Run against a registered dataset; ``request.data`` is ignored (the owner supplies it)."""
        body = request.model_dump(mode="json", exclude={"data", "data_owner"})
        return RunResult.model_validate(self._post("/runs", {**body, "grant": grant}))

    def get_dataset(self, dataset_id: str) -> dict[str, Any]:
        return self._get(f"/datasets/{dataset_id}")

    # Owner routes: construct the client with the owner key.
    def create_dataset(self, body: dict[str, Any]) -> dict[str, Any]:
        return self._post("/datasets", body)

    def create_grant(self, dataset_id: str, grantee: str) -> dict[str, Any]:
        return self._post(f"/datasets/{dataset_id}/grants", {"grantee": grantee})

    def _headers(self) -> dict[str, str]:
        headers = {"Content-Type": "application/json"}
        if self.api_key:
            headers["Authorization"] = f"Bearer {self.api_key}"
        return headers

    def _post(self, path: str, body: dict[str, Any]) -> dict[str, Any]:
        req = urllib.request.Request(
            self.endpoint + path,
            data=json.dumps(body).encode("utf-8"),
            headers=self._headers(),
            method="POST",
        )
        with urllib.request.urlopen(req, timeout=self.timeout) as resp:  # noqa: S310
            return json.loads(resp.read().decode("utf-8"))

    def _get(self, path: str) -> dict[str, Any]:
        req = urllib.request.Request(self.endpoint + path, headers=self._headers(), method="GET")
        with urllib.request.urlopen(req, timeout=self.timeout) as resp:  # noqa: S310
            return json.loads(resp.read().decode("utf-8"))
