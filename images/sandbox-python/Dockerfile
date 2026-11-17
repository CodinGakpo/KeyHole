# Minimal, non-root, read-only-root-FS sandbox image.
# Runs a single untrusted Python program and captures its typed output at $KEYHOLE_OUTPUT.
# The strong isolation (no egress, empty task role, read-only FS) comes from the Fargate task
# definition + network; this image just keeps the attack surface small.

FROM python:3.12-slim AS base

# Drop to a non-root, unprivileged user. The task definition also sets readonlyRootFilesystem.
# Two users: the runner (10001) holds the presigned I/O URLs; the untrusted code runs as 10002 and
# so cannot read the runner's environment through /proc, signal it, or write its result envelope.
RUN groupadd --gid 10001 sandbox \
 && useradd  --uid 10001 --gid 10001 --no-create-home --shell /usr/sbin/nologin sandbox \
 && groupadd --gid 10002 untrusted \
 && useradd  --uid 10002 --gid 10002 --no-create-home --shell /usr/sbin/nologin untrusted

# Scratch dir owned by the sandbox user. At runtime the root FS is read-only and a writable
# ephemeral volume is mounted at /sandbox/work; an empty volume inherits this mount point's
# ownership (10001), so the non-root user can write there without weakening the read-only root.
RUN mkdir -p /sandbox/work && chown -R 10001:10001 /sandbox

WORKDIR /sandbox
# The runner starts as root so it can start the code as 10002 (setuid) and kill it at the deadline;
# the task definition drops every other capability. See run_in_sandbox.py.
USER 0:0

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    KEYHOLE_OUTPUT=/sandbox/__keyhole_output__.json

# The in-container runner fetches code/data/schema (from S3 in the cloud) and executes them under
# the same contract as the local executor. Copied last so image layers stay cache-friendly.
COPY --chown=10001:10001 run_in_sandbox.py /opt/keyhole/run_in_sandbox.py

ENTRYPOINT ["python", "-I", "/opt/keyhole/run_in_sandbox.py"]
