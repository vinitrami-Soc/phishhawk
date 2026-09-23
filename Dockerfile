# phishtriage in a box: parses hostile input, so it runs as an unprivileged user
# and needs nothing mounted read-write except where you want reports written.
# Override if Docker Hub rate-limits you, e.g.
#   --build-arg BASE=public.ecr.aws/docker/library/python:3.12-slim
ARG BASE=python:3.12-slim
FROM ${BASE}

LABEL org.opencontainers.image.title="phishtriage" \
      org.opencontainers.image.description="Automated phishing IOC extraction, enrichment and triage" \
      org.opencontainers.image.licenses="MIT"

WORKDIR /opt/phishtriage
COPY pyproject.toml README.md LICENSE ./
COPY src ./src
RUN pip install --no-cache-dir . \
 && useradd --create-home --uid 10001 triage

USER triage
WORKDIR /mail
ENTRYPOINT ["phish-triage"]
CMD ["--help"]
