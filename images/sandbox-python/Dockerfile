# Minimal, non-root, read-only-root-FS sandbox image.
# Runs a single untrusted Python program and captures its typed output at $KEYHOLE_OUTPUT.
# The strong isolation (no egress, empty task role, read-only FS) comes from the Fargate task
# definition + network; this image just keeps the attack surface small.

FROM python:3.12-slim AS base

# Drop to a non-root, unprivileged user. The task definition also sets readonlyRootFilesystem.
RUN groupadd --gid 10001 sandbox \
 && useradd  --uid 10001 --gid 10001 --no-create-home --shell /usr/sbin/nologin sandbox

# Scratch dir owned by the sandbox user. At runtime the root FS is read-only and a writable
# ephemeral volume is mounted at /sandbox/work; an empty volume inherits this mount point's
# ownership (10001), so the non-root user can write there without weakening the read-only root.
RUN mkdir -p /sandbox/work && chown -R 10001:10001 /sandbox

WORKDIR /sandbox
USER 10001:10001

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    KEYHOLE_OUTPUT=/sandbox/__keyhole_output__.json

# The in-container runner fetches code/data/schema (from S3 in the cloud) and executes them under
# the same contract as the local executor. Copied last so image layers stay cache-friendly.
COPY --chown=10001:10001 run_in_sandbox.py /opt/keyhole/run_in_sandbox.py

ENTRYPOINT ["python", "-I", "/opt/keyhole/run_in_sandbox.py"]
