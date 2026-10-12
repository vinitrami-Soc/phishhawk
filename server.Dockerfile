# The PhishHawk web app: phishhawk server run (web app and one worker).
# The database and the encrypted blobs live in /data; the two keys come from
# Docker secrets (compose.yaml) or PHISHHAWK_* variables. See docs/SERVER.md.
ARG BASE=python:3.12-slim
FROM ${BASE}

LABEL org.opencontainers.image.title="phishhawk-server" \
      org.opencontainers.image.description="PhishHawk web app: phishing triage for a small SOC team" \
      org.opencontainers.image.licenses="MIT"

WORKDIR /opt/phishhawk
COPY pyproject.toml README.md LICENSE ./
COPY src ./src
RUN pip install --no-cache-dir ".[server,qr]" \
 && useradd --create-home --uid 10001 phishhawk \
 && install -d -o phishhawk -m 700 /data

USER phishhawk
ENV PHISHHAWK_DATA_DIR=/data PHISHHAWK_HOST=0.0.0.0 PHISHHAWK_PORT=8000 PYTHONDONTWRITEBYTECODE=1
VOLUME /data
EXPOSE 8000
HEALTHCHECK --interval=30s --timeout=5s --start-period=20s \
  CMD ["python", "-c", "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8000/healthz', timeout=4)"]
ENTRYPOINT ["phishhawk", "server"]
CMD ["run"]
