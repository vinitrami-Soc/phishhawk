# Running PhishHawk on the internet

This is the runbook for one public PhishHawk server: a small Linux server, the
web app on Postgres, and a [Cloudflare Tunnel](https://developers.cloudflare.com/cloudflare-one/connections/connect-networks/)
that brings visitors in. The server publishes no web port; only SSH is open.
Everything for it is in [`deploy/`](../deploy):

| File | What it does |
|---|---|
| `deploy/compose.yaml` | the web app and its worker, Postgres, and the tunnel |
| `deploy/setup.sh` | makes the keys and the database password, asks for the rest |
| `deploy/backup.sh` | backs up the database and the stored files, keeps 14 days |
| `deploy/update.sh` | backs up, then moves the server to a branch, tag or commit |
| `.github/workflows/deploy.yml` | runs `update.sh` from GitHub, over SSH |

The examples use `phishhawk.example.org`; use your own name.

- [1. A server](#1-a-server)
- [2. A Cloudflare Tunnel](#2-a-cloudflare-tunnel)
- [3. Mail](#3-mail)
- [4. First start](#4-first-start)
- [5. Deploys from GitHub](#5-deploys-from-github)
- [6. Backups and restore](#6-backups-and-restore)
- [Day to day](#day-to-day)

## 1. A server

Any Linux server with 2 GB of memory, 20 GB of disk and Docker will do: a
Hetzner CX23, or an Oracle Cloud "Always Free" Ampere machine (the images build
on ARM as well). On Ubuntu 24.04, as root:

```bash
curl -fsSL https://get.docker.com | sh
adduser --disabled-password --gecos "" phishhawk
usermod -aG docker phishhawk          # docker is root on this machine: keep this user's key safe
install -d -o phishhawk -m 700 /home/phishhawk/.ssh
cp ~/.ssh/authorized_keys /home/phishhawk/.ssh/ && chown phishhawk: /home/phishhawk/.ssh/authorized_keys
ufw allow OpenSSH && ufw --force enable
```

Turn on the provider's automatic security updates (`unattended-upgrades` is on
by default on Ubuntu) and log in with SSH keys only.

## 2. A Cloudflare Tunnel

The domain's DNS must be on Cloudflare. In the Cloudflare dashboard, open
**Zero Trust → Networks → Tunnels → Create a tunnel**, choose **Cloudflared**
and name it `phishhawk`. Cloudflare shows an install command with a long
token after `--token`: copy only the token, `setup.sh` asks for it. Skip the
install step: the tunnel runs in `compose.yaml`.

Add a **public hostname**: subdomain `phishhawk`, your domain, service type
**HTTP**, URL `phishhawk:8000`. Cloudflare creates the DNS record and the
certificate. Then, under the domain's **SSL/TLS → Edge Certificates**, turn on
**Always Use HTTPS**.

Keep that DNS record **Proxied** (the orange cloud), also when you change
other records in bulk. Set to DNS only, the name points at an address that
answers nothing: the tunnel stays healthy, yet every visitor and uptime check
gets a connection timeout.

The tunnel passes each visitor's address in `X-Forwarded-For`, and
`compose.yaml` trusts it from the project's own network only, so the login and
reset throttles slow down each visitor, not the tunnel.

## 3. Mail

For password reset links, PhishHawk sends mail through an SMTP provider (Brevo,
Resend, Amazon SES, Zoho ZeptoMail; Cloudflare Email Routing receives mail but
does not send it). Add the sender domain at the provider and the SPF and DKIM
records it gives you in Cloudflare's DNS, then keep its SMTP server, login and
key at hand for `setup.sh`. Without mail, everything else works; see
[Email and password reset](SERVER.md#email-and-password-reset).

## 4. First start

As the `phishhawk` user on the server:

```bash
git clone https://github.com/vinitrami-Soc/phishhawk.git ~/phishhawk
cd ~/phishhawk
sh deploy/setup.sh
docker compose -f deploy/compose.yaml up -d --build --wait
docker compose -f deploy/compose.yaml exec phishhawk phishhawk server setup-code
```

`setup.sh` asks for the site's address (`https://phishhawk.example.org`), the
tunnel token, who runs the site and where people write about their data (the
privacy page shows both), whether search engines may list the product, privacy
and help pages, and the mail settings. It writes them to `deploy/.env` and
`deploy/secrets/` (git ignores both). Run it again to change an answer.

Open `https://phishhawk.example.org/setup`, enter the setup code and make your
account: you own this server.

**Keep a copy of `deploy/secrets/phishhawk_encryption_key` in a password
manager.** Every stored message is encrypted with it; without it no backup can
be read, by you or anyone else.

## 5. Deploys from GitHub

Make a key for GitHub on your own computer:

```bash
ssh-keygen -t ed25519 -N "" -C github-deploy -f phishhawk-deploy
ssh-keyscan -t ed25519 <server address>      # the server's key, for DEPLOY_KNOWN_HOSTS
```

On the server, add one line to `/home/phishhawk/.ssh/authorized_keys`, with the
contents of `phishhawk-deploy.pub` at the end. It lets the key run
`update.sh` and nothing else, even if the key leaks:

```
command="sh ~/phishhawk/deploy/update.sh \"$SSH_ORIGINAL_COMMAND\"",restrict ssh-ed25519 AAAA... github-deploy
```

In the repository on GitHub, **Settings → Secrets and variables → Actions**:

| Kind | Name | Value |
|---|---|---|
| Secret | `DEPLOY_SSH_KEY` | the contents of `phishhawk-deploy` (the private key) |
| Variable | `DEPLOY_HOST` | the server's address |
| Variable | `DEPLOY_USER` | `phishhawk` |
| Variable | `DEPLOY_KNOWN_HOSTS` | the `ssh-keyscan` line |
| Variable | `DEPLOY_URL` | `https://phishhawk.example.org` |

Then delete `phishhawk-deploy` from your computer. From now on:

- **publishing a release** deploys its tag (the Release workflow also builds the
  package);
- **Actions → Deploy → Run workflow** deploys any branch, tag or commit: an
  older tag rolls back the code.

Each deploy backs up first, rebuilds, waits for the health check and verifies
the audit log. Under **Settings → Environments → production** you can require
your own approval before each deploy runs.

## 6. Backups and restore

Back up every night, as the `phishhawk` user (`crontab -e`):

```
17 3 * * * sh ~/phishhawk/deploy/backup.sh >/dev/null
```

Backups land in `deploy/backups/` and are kept 14 days. Copy that folder off
the server too (`rclone` to cloud storage, or `scp` to your computer): a backup
on the same disk does not survive the server. Keep the encryption key apart from
the backups.

To restore one (the stamp is in the file names), with the site stopped:

```bash
cd ~/phishhawk
docker compose -f deploy/compose.yaml stop phishhawk tunnel
docker compose -f deploy/compose.yaml exec -T db \
  pg_restore -U phishhawk -d phishhawk --clean --if-exists < deploy/backups/db-STAMP.dump
docker compose -f deploy/compose.yaml run --rm -T --no-deps --entrypoint tar phishhawk \
  -C /data -xzf - < deploy/backups/data-STAMP.tgz
docker compose -f deploy/compose.yaml up -d --wait
docker compose -f deploy/compose.yaml exec phishhawk phishhawk server audit verify
```

A rollback to an older tag does not undo database migrations: to go back past
one, restore the backup the deploy made before it.

## Search engines

With `PHISHHAWK_INDEX_PUBLIC_PAGES=true` and `PHISHHAWK_PUBLIC_URL` set in
`deploy/.env` (`setup.sh` asks for both), search engines may list the product
page at the site's address, the privacy page and the help page; see
[SERVER.md](SERVER.md#https-through-a-reverse-proxy). After a deploy, check:

```bash
curl -sI https://phishhawk.example.org/ | grep -i x-robots-tag   # all
curl -s https://phishhawk.example.org/robots.txt                 # ends with the Sitemap line
curl -s https://phishhawk.example.org/sitemap.xml                # three addresses
```

Then add the site to Google Search Console (a Domain property, verified with a
TXT record in Cloudflare's DNS) and Bing Webmaster Tools, and submit
`/sitemap.xml` to both. In Cloudflare, leave verified bots (Googlebot, Bingbot)
unchallenged, and keep Rocket Loader, Email Address Obfuscation and the Web
Analytics script turned off for this hostname: they add scripts to the page,
and PhishHawk's content security policy blocks them.

To keep AI training crawlers out, open **Security → Settings → Configure AI bot
policies**, keep **Search** on Allow and set **Training** to **Disallow**, not
Block. Since 15 September 2026, Block (and Block on pages with ads) also stops
crawlers that index for search and training alike, Googlebot, Bingbot and
Applebot among them: Search Console then reports the sitemap as a 403 and
Cloudflare's security events name the rule "Block AI training crawlers".

## Day to day

```bash
cd ~/phishhawk
docker compose -f deploy/compose.yaml ps                  # what runs, and its health
docker compose -f deploy/compose.yaml logs -f phishhawk   # the web app and the worker
sh deploy/update.sh v3.1.0                                # deploy by hand
```

Dependabot opens monthly pull requests for the Python, frontend, Docker and
Actions dependencies; once one is merged, a release (or **Run workflow**) puts
it on the server. Everything else about running the web app (settings, users,
retention, key rotation) is in [SERVER.md](SERVER.md).
