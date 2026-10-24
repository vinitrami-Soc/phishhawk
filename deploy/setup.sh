#!/bin/sh
# First setup of PhishHawk on this server (docs/DEPLOY.md). Makes the two keys and the database password, asks for
# the site's address, the Cloudflare Tunnel token, who runs it and the mail settings, and writes deploy/secrets/ and
# deploy/.env. Run it again to change an answer: an empty answer keeps the one already given, and keys already made
# are never replaced (a new encryption key would leave every stored file unreadable).
set -eu
cd "$(dirname "$0")"
umask 077
mkdir -p secrets
chmod 700 secrets  # the folder keeps other users out; the files are readable by the containers' users

made() { echo "  made secrets/$1"; }
[ -s secrets/phishhawk_secret_key ] || { openssl rand -base64 32 > secrets/phishhawk_secret_key; made phishhawk_secret_key; }
[ -s secrets/phishhawk_encryption_key ] || { openssl rand -base64 32 > secrets/phishhawk_encryption_key; made phishhawk_encryption_key; }
if [ ! -s secrets/postgres_password ]; then
  openssl rand -hex 24 > secrets/postgres_password
  printf 'postgresql://phishhawk:%s@db:5432/phishhawk\n' "$(cat secrets/postgres_password)" > secrets/phishhawk_database_url
  made postgres_password
fi

# the answers so far, from deploy/.env
current() { sed -n "s/^$1=//p" .env 2>/dev/null | head -n 1; }
ask() {  # ask NAME QUESTION: the answer, or the current value when the answer is empty
  now=$(current "$1")
  printf '%s%s: ' "$2" "${now:+ [$now]}" >&2
  read -r answer || answer=""
  printf '%s' "${answer:-$now}"
}
ask_secret() {  # ask_secret FILE QUESTION: written to secrets/FILE; empty keeps the file as it is
  printf '%s%s: ' "$2" "$([ -s "secrets/$1" ] && echo ' [kept]')" >&2
  stty -echo 2>/dev/null || true
  read -r answer || answer=""
  stty echo 2>/dev/null || true
  echo >&2
  if [ -n "$answer" ]; then printf '%s\n' "$answer" > "secrets/$1"; fi
  [ -e "secrets/$1" ] || : > "secrets/$1"
}

echo "The site" >&2
public_url=$(ask PHISHHAWK_PUBLIC_URL "  Its address, such as https://phishhawk.example.org")
ask_secret cloudflare_tunnel_token "  The Cloudflare Tunnel token (docs/DEPLOY.md, step 2)"
operator_name=$(ask PHISHHAWK_OPERATOR_NAME "  Who runs it, for the privacy page, such as Example Security Ltd, United Kingdom")
operator_email=$(ask PHISHHAWK_OPERATOR_EMAIL "  Where people write about their data, such as privacy@example.org")
indexed=$(ask PHISHHAWK_INDEX_PUBLIC_PAGES "  Let search engines list its product, privacy and help pages? (true or false)")
echo "Mail, for password reset links (leave empty for none; docs/SERVER.md, \"Email and password reset\")" >&2
smtp_host=$(ask PHISHHAWK_SMTP_HOST "  SMTP server, such as smtp-relay.brevo.com")
smtp_port=$(ask PHISHHAWK_SMTP_PORT "  SMTP port (587 for STARTTLS)")
smtp_username=$(ask PHISHHAWK_SMTP_USERNAME "  SMTP login")
smtp_from=$(ask PHISHHAWK_SMTP_FROM "  From, such as PhishHawk <no-reply@example.org>")
ask_secret phishhawk_smtp_password "  SMTP password or key"

{
  echo "# written by deploy/setup.sh: run it again to change an answer"
  echo "PHISHHAWK_PUBLIC_URL=$public_url"
  echo "PHISHHAWK_OPERATOR_NAME=$operator_name"
  echo "PHISHHAWK_OPERATOR_EMAIL=$operator_email"
  echo "PHISHHAWK_INDEX_PUBLIC_PAGES=${indexed:-false}"
  echo "PHISHHAWK_SMTP_HOST=$smtp_host"
  echo "PHISHHAWK_SMTP_PORT=${smtp_port:-587}"
  echo "PHISHHAWK_SMTP_USERNAME=$smtp_username"
  echo "PHISHHAWK_SMTP_FROM=$smtp_from"
} > .env
chmod 644 secrets/* .env
echo "Ready. Next: docker compose -f deploy/compose.yaml up -d --build --wait" >&2
echo "Keep a copy of deploy/secrets/phishhawk_encryption_key somewhere safe: without it no backup can be read." >&2
