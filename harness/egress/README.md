# Egress Containment Harness (M3)

Proves, structurally, that the sandbox has **no side exit** — mirroring the Fargate sandbox +
egress-proxy sidecar layout locally with Docker.

## Topology

```
        ┌─────────────── edge (internet) ───────────────┐
        │                                                │
   [ egress-proxy ]  ── deny-by-default, logs attempts ──┘
        │  (also on internal)
        │
  ── internal (internal: true, NO internet) ──
        │
   [ probe ]   ← the sandbox's network posture: internal-only
```

The probe can reach the internet **only** through the proxy. It asserts three things:

1. **`direct_egress_blocked`** — a raw connection from the probe to a public IP fails (no route).
2. **`proxy_denies_unlisted`** — `CONNECT 9.9.9.9:443` → `403 Forbidden`.
3. **`proxy_allows_listed`** — `CONNECT 1.1.1.1:443` → `200 Connection Established` (real tunnel).

Literal IPs are used so the probe needs no DNS (the internal net has none); the proxy — reachable
by service name — does the upstream resolution.

## Run

```bash
docker compose -f harness/egress/docker-compose.yml up --build \
    --abort-on-container-exit --exit-code-from probe
# expect: CONTAINMENT: PROVEN  (probe exits 0)

# or via pytest:
MARK1_DOCKER=1 python -m pytest tests/integration -q
```

The proxy prints one structured JSON line per attempt (allowed or denied) — this is the network
flight recorder that the control plane folds into a run's data-flow record and attestation.
