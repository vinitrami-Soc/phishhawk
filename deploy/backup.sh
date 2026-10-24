#!/bin/sh
# A backup of PhishHawk (docs/DEPLOY.md): the database and the encrypted files, at the same moment, into
# deploy/backups/, keeping the last 14 days. Run it daily from cron, and copy deploy/backups/ off this server.
# The files are encrypted with deploy/secrets/phishhawk_encryption_key: keep that key apart from the backups.
set -eu
cd "$(dirname "$0")"
if [ -z "$(docker compose ps --status running -q db)" ]; then
  echo "PhishHawk is not running here yet: nothing to back up"
  exit 0
fi
stamp=$(date -u +%Y%m%d-%H%M%S)
umask 077
mkdir -p backups
docker compose exec -T db pg_dump -U phishhawk -d phishhawk --format=custom > "backups/db-$stamp.dump"
docker compose exec -T phishhawk tar -C /data -czf - . > "backups/data-$stamp.tgz"
find backups -type f -mtime +14 -delete
echo "backed up: deploy/backups/db-$stamp.dump deploy/backups/data-$stamp.tgz"
