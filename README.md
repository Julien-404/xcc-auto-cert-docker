# xcc-cert-renewer

Automates Let's Encrypt certificate renewal on infrastructure that has no built-in ACME client. Runs as a Docker container on any host with LAN access to the targets; checks weekly and renews each certificate when it is within 30 days of expiry.

Deploys certs **directly on each device** — no reverse proxy. Two backends today:

- **Lenovo XClarity Controller (XCC) BMCs** — drives the internal Web UI JSON API (Redfish is too restrictive on firmware 9.98; see `CLAUDE.md` for the autopsy).
- **Cisco Small Business SG500 / SG500XG stacks** — pushes the PEM over SSH into `crypto certificate N import`, then binds HTTPS to it.

Both backends share the same acme.sh installation, Cloudflare credentials, weekly cron, and `/data` volume.

## Requirements

- A Docker host on the same LAN as your targets (e.g., Unraid, Proxmox, any VM).
- Target FQDNs must live under a zone you control on **Cloudflare** (needed for DNS-01 challenge).
- Python/OpenSSL/networking internals are handled inside the container — host just needs Docker.

## Quick start

```bash
git clone git@github.com:Julien-404/xcc-cert-renewer.git
cd xcc-cert-renewer

# 1. Secrets
cp .env.example .env && $EDITOR .env

# 2a. XCC FQDNs (skip if you don't have any)
cp config/xcc-hosts.conf.example config/xcc-hosts.conf && $EDITOR config/xcc-hosts.conf

# 2b. SG500 FQDNs + SSH key (skip if you don't have any)
cp config/sg500-hosts.conf.example config/sg500-hosts.conf && $EDITOR config/sg500-hosts.conf
mkdir -p config/ssh
cp ~/.ssh/id_rsa_sg500 config/ssh/sg500-key
chmod 600 config/ssh/sg500-key
chown 1000:1000 config/ssh/sg500-key   # uid inside the container

# 3. Build + start (weekly cron, Mon 04:00 TZ by default)
docker compose build
docker compose up -d
```

Either host list can be empty or absent — the renewer just skips the missing backend.

## XCC prerequisites (one-time per BMC)

Before running the renewer against a BMC, prepare its Web UI once:

1. **Create the service user** — Web UI → *BMC Configuration → Users* → add `acme-api` with **Supervisor** role and a strong password.
2. **Clear the forced-password-change** — log into the Web UI with `acme-api` at least once. Lenovo forces a password change on first login; pick the value that will go in `XCC_PASS`.
3. **Disable password expiration** (recommended) — otherwise the service account silently expires after 90 days and the renewer breaks.
4. **First cert activation is manual** — the very first time you hand a BMC over to the renewer, upload any LE-signed cert via the Web UI's *SSL Certificate Management → Import Certificate* once. The renewer itself can generate/sign the cert — run it with `--force`, then upload the generated fullchain via the UI. After that one-time activation, future renewals are fully automated. (This is a Lenovo firmware quirk: `cert_upload` via API silently no-ops on a factory-fresh BMC until it has accepted its first UI-driven external cert upload.)

## SG500 prerequisites (one-time per stack)

1. **Create a CLI service user** — Web UI → *Administration → User Accounts → Add* → name e.g. `claude`, **Level 15 (Read/Write CLI)**, pick any password (only needed if SSH pubkey auth gets disabled).
2. **Install the service user's SSH public key** — Web UI → *Security → SSH User Authentication* → enable **By Public Key**, add the public key (RSA only — SG500 1.4.x does not accept ECDSA/ed25519 user-keys). Mount the corresponding **private** key into the container at `/config/ssh/sg500-key`.
3. **Enable pubkey auto-login** — in the CLI or Web UI, set `ip ssh pubkey-auth auto-login` so the switch skips the second CLI password prompt after SSH pubkey auth succeeds.
4. **Enable SSH server** — `ip ssh server` (usually already on).

No "first manual activation" dance needed — the renewer populates slot 2 and binds HTTPS atomically on the very first run.

**What the backend actually does on the switch**

1. `crypto certificate 2 import` and paste a three-block PEM (private key + derived public key + leaf cert — full chains are rejected by firmware 1.4.x; browsers recover via AIA).
2. `show crypto certificate 2` to positively confirm the expected `CN=` landed in the slot (no unbinding of the currently active cert until this passes).
3. `ip https certificate 2` to bind HTTPS to the new slot.
4. `write` + `Y` to persist to startup-config.
5. Reconnect over TLS and assert the fingerprint actually changed.

Environment overrides: `SG500_SSH_USER` (default `claude`), `SG500_SSH_KEY` (default `/config/ssh/sg500-key`), `SG500_SLOT` (default 2 — only 1 and 2 exist on SG500).

## Telegram alerts (optional)

Set `TG_BOT_TOKEN` and `TG_CHAT_ID` in `.env` to be notified on any run where at least one host fails. Messages are only sent on failure by default; set `TG_NOTIFY_ALWAYS=1` to also receive a success heartbeat — handy to catch silent cron misfires. `NOTIFY_SUBJECT` prefixes the message (default: `cert-renewer`).

To get the credentials: create a bot with [@BotFather](https://t.me/BotFather), DM your new bot once from the account you want to alert, then:

```bash
curl -s "https://api.telegram.org/bot<TOKEN>/getUpdates" | jq '.result[0].message.chat.id'
```

The bot posts failures as plain text (no markdown escaping issues) with a compact summary:

```
🚨 cert-renewer FAILED
Run: 2026-04-23T22:30:00+02:00
Failed: 2 / 4

xcc:
  • xcc-pve-01.int.example.com (rc=1)
sg500:
  • sw-core.int.example.com (rc=3)

xcc: 2 host(s) OK
Logs: docker logs xcc-cert-renewer
```

If the curl to Telegram itself fails (network, wrong token), the renewer logs a line but never fails the run because of it.

## DNS requirements

- FQDNs can resolve via **internal DNS only** — they don't need to be in the public zone.
- The parent zone (`example.com`) **must** be on Cloudflare and your `CF_Token` must have `Zone:DNS:Edit` on it.
- `_acme-challenge.*` TXT records are written transiently in the Cloudflare zone during issuance and auto-cleaned after. They don't require you to change your A records.

## Commands

| Command | Purpose |
|---|---|
| `docker compose up -d` | Start scheduled renewal (weekly per `CRON_SCHEDULE`, default Mon 04:00) |
| `docker compose run --rm xcc-cert-renewer once` | Run one pass over every host in both `xcc-hosts.conf` and `sg500-hosts.conf` |
| `docker exec xcc-cert-renewer /app/xcc-deploy-cert.py --host <FQDN> [--force]` | Run XCC backend against one host |
| `docker exec xcc-cert-renewer /app/sg500-deploy-cert.py --host <FQDN> [--force]` | Run SG500 backend against one host |
| `docker exec xcc-cert-renewer /app/notify.sh "hello"` | Send a one-shot Telegram message (validates creds) |
| `docker compose run --rm xcc-cert-renewer test-notify` | Same as above, via entrypoint dispatch |
| `docker compose run --rm xcc-cert-renewer shell` | Drop into a debug shell |
| `docker compose logs -f` | Follow scheduler / renewal logs (supercronic streams to stdout) |

Per-host log files live in the `xcc-cert-data` volume at `/data/logs/<type>-<FQDN>.log`; cert backups at `/data/backups/`.

## What a renewal does (XCC backend)

1. **Pre-check** — TLS-handshake the BMC on port 443, read the certificate. If `> RENEWAL_THRESHOLD_DAYS` (30) remain, skip.
2. **Backup** — save the currently-served cert to `/data/backups/<host>-<timestamp>.pem`.
3. **Web UI login** — `get_nonce` → `login` → extract `access_token` JWT and `_csrf_token` cookie.
4. **Generate CSR** — drive the XCC through `Sec_GenKeyAndCSR` → `CSR_Format=1` → `Sec_DownloadCSRANDCert`, then `GET /download/download_csr_0.pem`. The CSR has `SAN = [DNS:<FQDN>]` only (critical — see `CLAUDE.md`).
5. **Fail-fast** if the CSR contains any SAN other than the expected FQDN (defense against firmware regression).
6. **Sign with Let's Encrypt** via `acme.sh --signcsr --dns dns_cf`.
7. **Upload + activate** the signed fullchain: `POST /upload` → `POST /api/providers/cert_upload` → **`POST /api/function Sec_ImportCert`**. The third call is the one that actually activates the cert; skipping it leaves the XCC serving the old cert while APIs still return success.
8. **Post-deploy validation** — wait 45 s for the XCC to reload its HTTPS service, then confirm the live cert is LE-issued, covers the FQDN, and — critically — has the exact public key we just signed. Retries 6× / 20 s.

## What a renewal does (SG500 backend)

1. **Pre-check** — TLS-handshake the switch on port 443 (using a permissive `SECLEVEL=0` context to accept the legacy ciphers SG500 firmware 1.4.x speaks). Skip if the cert has > `RENEWAL_THRESHOLD_DAYS` remaining.
2. **Issue / renew** via `acme.sh --issue --dns dns_cf --keylength 2048 --server letsencrypt`. RSA is required — the switch rejects ECDSA keys.
3. **Build payload** — three PEM blocks concatenated in order: PKCS#1 private key, PKCS#1 public key (derived via `openssl rsa -RSAPublicKey_out`), leaf cert only.
4. **SSH + paste** — line-by-line into `crypto certificate 2 import`, with a 0.22 s drain between lines to keep the switch's paste buffer in step. Terminator is `.` on its own line.
5. **Positive slot verification** — `show crypto certificate 2` and assert `CN=<FQDN>` is present. Only then does the script proceed; if the slot is empty or wrong, it aborts **before** issuing `ip https certificate 2` (which would otherwise unbind the currently active slot 1).
6. **Bind + save** — `ip https certificate 2`, `end`, `write`, `Y`. Expect a `COPY-I-FILECPY` syslog trap to confirm persistence.
7. **Post-verify** — reconnect over TLS after 4 s, confirm both the fingerprint changed and `notAfter` moved forward.

## Troubleshooting

### XCC

- **Login fails with HTTP 401 `{"return":507,"description":"Invalid credentials"}`** → the `acme-api` user has never had its forced-password-change cleared. Log in once via the browser and set the password you put in `XCC_PASS`.
- **CSR has unexpected SAN entries** → `Sec_DownloadCSRANDCert` didn't materialize a fresh CSR, or the XCC firmware regressed on the SAN-filtering behaviour. Run with `-v` and inspect the decoded CSR; abort before submitting to LE.
- **Tool reports SUCCESS but cert didn't change** → the pubkey-fingerprint check is meant to catch this, but if it passes and the browser still shows the old cert, see prerequisite #4 (first upload must be via Web UI).
- **Post-deploy validation times out** → the XCC web service occasionally takes > 2 min to reload. Check the XCC event log (Web UI → Events) for cert-service messages.

### SG500

- **"did not get paste prompt for slot N"** → either `crypto certificate N import` is not a valid command on your firmware (should work on 1.4.x), or the slot number is outside `[1,2]`. SG500 has no slot 3+.
- **"SG500 rejected cert import: Inconsistent value"** → you tried to push a full chain (leaf + intermediate). SG500 1.4.x accepts only the leaf; the script does this automatically, so this error implies a local modification.
- **"SG500 rejected cert import: saved private key did not match"** → the three-block PEM format is off. Every block matters, in this order: `-----BEGIN RSA PRIVATE KEY-----` (PKCS#1), `-----BEGIN RSA PUBLIC KEY-----` (PKCS#1), `-----BEGIN CERTIFICATE-----`.
- **"post-paste verification failed: expected CN=... not found"** → the paste completed silently but the slot content is wrong. Most commonly an RX-buffer corruption (the switch dropped chars); increase the per-line drain from 0.22 to 0.4 s in `ssh_install`.
- **HTTPS inaccessible after a run** → the script is designed to abort **before** unbinding the active cert if the new slot isn't verified. If you see this anyway, reconnect via SSH and `configure` → `ip https certificate 1` to restore factory binding.
- **`acme.sh` exits non-zero with `rateLimited`** → you've hit LE's "5 certificates per exact identifier / 7 d" limit. Wait; normal cron cadence doesn't trigger this, but `--force` loops during debug do.

See [`CLAUDE.md`](./CLAUDE.md) for the XCC reverse-engineered Web UI protocol and the reasoning behind every design decision.
