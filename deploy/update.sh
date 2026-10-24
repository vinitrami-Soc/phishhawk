#!/bin/sh
# Brings this server to a version of PhishHawk (docs/DEPLOY.md): a backup, the code at REF (a branch, a tag or a
# commit; main when none is given), a new build, then the health check and the audit log's verification. The
# GitHub "Deploy" workflow runs it over SSH; it can be run here by hand too: sh deploy/update.sh v3.0.0
set -eu
cd "$(dirname "$0")/.."
ref=${1:-main}
case "$ref" in
  "" | -* | *[!A-Za-z0-9._/-]*) echo "not a branch, tag or commit: $ref" >&2; exit 2 ;;
esac
sh deploy/backup.sh
git fetch --quiet --tags origin
if git rev-parse --verify --quiet "origin/$ref^{commit}" >/dev/null; then
  git checkout --quiet --detach "origin/$ref"
else
  git checkout --quiet --detach "$ref^{commit}"
fi
echo "deploying $(git log -1 --format='%h %s')"
docker compose -f deploy/compose.yaml pull --quiet db tunnel  # their security fixes
docker compose -f deploy/compose.yaml build --pull            # and the base images
docker compose -f deploy/compose.yaml up -d --wait
docker compose -f deploy/compose.yaml exec -T phishhawk phishhawk server audit verify
echo "PhishHawk is up at $(sed -n 's/^PHISHHAWK_PUBLIC_URL=//p' deploy/.env)"
