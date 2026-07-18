# The containment probe as an image (avoids bind-mount/SELinux issues; runs as an unprivileged user).
FROM python:3.12-slim
COPY probe.py /probe.py
USER 65534:65534
ENTRYPOINT ["python", "-I", "/probe.py"]
