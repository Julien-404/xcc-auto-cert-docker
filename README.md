# xcc-auto-cert-docker

Automates Let's Encrypt certificate renewal on Lenovo XClarity Controller (XCC) BMCs. Runs as a Docker container on any host with LAN access to the BMCs; checks weekly and renews each certificate when it is within 30 days of expiry.

Deploys certs **directly on each XCC** — no reverse proxy. Works around Lenovo firmware limitations by driving the XCC's internal Web UI JSON API rather than Redfish (see `CLAUDE.md` for the autopsy).

## Requirements

- A Docker host on the same LAN as your BMCs (e.g., Unraid, Proxmox, any VM).
- Your BMC FQDNs must live under a zone you control on **Cloudflare** (needed for DNS-01 challenge).
- Python/OpenSSL/networking internals are handled inside the container — host just needs Docker.

## Quick start

```bash
git clone git@github.com:Julien-404/xcc-auto-cert-docker.git
cd xcc-auto-cert-docker

# 1. Secrets (see XCC prerequisites below for what XCC_PASS is)
cp .env.example .env && $EDITOR .env

# 2. Your BMC FQDNs, one per line
cp config/xcc-hosts.conf.example config/xcc-hosts.conf && $EDITOR config/xcc-hosts.conf

# 3. Build + start (weekly cron, Mon 04:00 TZ by default)
docker compose build
docker compose up -d
```

## XCC prerequisites (one-time per BMC)

Before running the renewer against a BMC, prepare its Web UI once:

1. **Create the service user** — Web UI → *BMC Configuration → Users* → add `acme-api` with **Supervisor** role and a strong password.
2. **Clear the forced-password-change** — log into the Web UI with `acme-api` at least once. Lenovo forces a password change on first login; pick the value that will go in `XCC_PASS`.
3. **Disable password expiration** (recommended) — otherwise the service account silently expires after 90 days and the renewer breaks.
4. **First cert activation is manual** — the very first time you hand a BMC over to the renewer, upload any LE-signed cert via the Web UI's *SSL Certificate Management → Import Certificate* once. The renewer itself can generate/sign the cert — run it with `--force`, then upload the generated fullchain via the UI. After that one-time activation, future renewals are fully automated. (This is a Lenovo firmware quirk: `cert_upload` via API silently no-ops on a factory-fresh BMC until it has accepted its first UI-driven external cert upload.)

Add the FQDN to `config/xcc-hosts.conf`, then:

```bash
docker compose run --rm xcc-cert-renewer host your-bmc.example.com --force --verbose
```

On a BMC that already has an LE cert (bootstrapped), the tool will renew end-to-end autonomously.

## DNS requirements

- Your BMC FQDNs (e.g., `bmc.int.example.com`) can resolve via **internal DNS only** — they don't need to be in the public zone.
- The parent zone (`example.com`) **must** be on Cloudflare and your `CF_Token` must have `Zone:DNS:Edit` on it.
- `_acme-challenge.*` TXT records are written transiently in the Cloudflare zone during issuance and auto-cleaned after. They don't require you to change your A records.

## Commands

| Command | Purpose |
|---|---|
| `docker compose up -d` | Start scheduled renewal (weekly per `CRON_SCHEDULE`, default Mon 04:00) |
| `docker compose run --rm xcc-cert-renewer once` | Run one pass over every host in `config/xcc-hosts.conf` |
| `docker compose run --rm xcc-cert-renewer host <FQDN> [--dry-run\|--force\|-v]` | Run against a single host |
| `docker compose run --rm xcc-cert-renewer shell` | Drop into a debug shell |
| `docker compose logs -f` | Follow scheduler / renewal logs (supercronic streams to stdout) |

Per-host log files live in the `xcc-cert-data` volume at `/data/logs/<FQDN>.log`; cert backups are at `/data/backups/`.

## What a renewal does

1. **Pre-check** — TLS-handshake the BMC on port 443, read the certificate. If `> RENEWAL_THRESHOLD_DAYS` (30) remain, skip.
2. **Backup** — save the currently-served cert to `/data/backups/<host>-<timestamp>.pem`.
3. **Web UI login** — `get_nonce` → `login` → extract `access_token` JWT and `_csrf_token` cookie.
4. **Generate CSR** — drive the XCC through `Sec_GenKeyAndCSR` → `CSR_Format=1` → `Sec_DownloadCSRANDCert`, then `GET /download/download_csr_0.pem`. The CSR has `SAN = [DNS:<FQDN>]` only (critical — see `CLAUDE.md`).
5. **Fail-fast** if the CSR contains any SAN other than the expected FQDN (defense against firmware regression).
6. **Sign with Let's Encrypt** via `acme.sh --signcsr --dns dns_cf`.
7. **Upload + activate** the signed fullchain: `POST /upload` → `POST /api/providers/cert_upload` → **`POST /api/function Sec_ImportCert`**. The third call is the one that actually activates the cert; skipping it leaves the XCC serving the old cert while APIs still return success.
8. **Post-deploy validation** — wait 45 s for the XCC to reload its HTTPS service, then confirm the live cert is LE-issued, covers the FQDN, and — critically — has the exact public key we just signed. Retries 6× / 20 s.

## Troubleshooting

- **Login fails with HTTP 401 `{"return":507,"description":"Invalid credentials"}`** → the `acme-api` user has never had its forced-password-change cleared. Log in once via the browser and set the password you put in `XCC_PASS`.
- **CSR has unexpected SAN entries** → `Sec_DownloadCSRANDCert` didn't materialize a fresh CSR, or the XCC firmware regressed on the SAN-filtering behaviour. Run with `-v` and inspect the decoded CSR; abort before submitting to LE.
- **`acme.sh` exits non-zero with `rateLimited`** → you've hit LE's "5 certificates per exact identifier / 7 d" limit. Wait; normal cron cadence doesn't trigger this, but `--force` loops during debug do.
- **Tool reports SUCCESS but cert didn't change** → the pubkey-fingerprint check is meant to catch this, but if it passes and the browser still shows the old cert, see prerequisite #4 (first upload must be via Web UI).
- **Post-deploy validation times out** → the XCC web service occasionally takes > 2 min to reload. Check the XCC event log (Web UI → Events) for cert-service messages.

See [`CLAUDE.md`](./CLAUDE.md) for the full reverse-engineered Web UI protocol and the reasoning behind every design decision.
