# Egress-proxy sidecar: the sandbox's ONLY intended network path. Deny-by-default; logs every
# connection attempt (allowed or denied) as the network flight recorder. For default (no-egress)
# runs the sandbox has no route at all and this proxy simply records that nothing was attempted;
# for allowlisted runs it permits only the declared hostnames.

FROM python:3.12-slim

RUN groupadd --gid 10002 proxy \
 && useradd  --uid 10002 --gid 10002 --no-create-home --shell /usr/sbin/nologin proxy

COPY proxy.py /opt/mark1/proxy.py

USER 10002:10002
# MARK1_ALLOWED_HOSTS is a comma-separated allowlist (empty => deny all).
ENV MARK1_ALLOWED_HOSTS="" \
    MARK1_PROXY_PORT=8080

EXPOSE 8080
ENTRYPOINT ["python", "-I", "/opt/mark1/proxy.py"]
