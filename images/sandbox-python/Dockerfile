# Minimal, non-root, read-only-root-FS sandbox image.
# Runs a single untrusted Python program and captures its typed output at $MARK1_OUTPUT.
# The strong isolation (no egress, empty task role, read-only FS) comes from the Fargate task
# definition + network; this image just keeps the attack surface small.

FROM python:3.12-slim AS base

# Drop to a non-root, unprivileged user. The task definition also sets readonlyRootFilesystem.
RUN groupadd --gid 10001 sandbox \
 && useradd  --uid 10001 --gid 10001 --no-create-home --shell /usr/sbin/nologin sandbox

# A world-writable scratch dir is the ONLY place code may write (root FS is read-only at runtime).
RUN mkdir -p /sandbox && chown 10001:10001 /sandbox

WORKDIR /sandbox
USER 10001:10001

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    MARK1_OUTPUT=/sandbox/__mark1_output__.json

# The in-container runner fetches code/data/schema (from S3 in the cloud) and executes them under
# the same contract as the local executor. Copied last so image layers stay cache-friendly.
COPY --chown=10001:10001 run_in_sandbox.py /opt/mark1/run_in_sandbox.py

ENTRYPOINT ["python", "-I", "/opt/mark1/run_in_sandbox.py"]
