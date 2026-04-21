# CLAUDE.md — Context for Claude Code

## Project

**xcc-cert-renewer** — Automates Let's Encrypt certificate deployment to Lenovo XClarity Controller (XCC) BMCs, packaged as a Docker container. DNS-01 via Cloudflare; cert deployment via the **XCC Web UI's internal JSON API** (reverse-engineered — not Redfish). Runs on any Docker host on the same LAN as the BMCs.

## Why Web UI API and not Redfish

Recent XCC firmware (validated on `CDI3B4E 9.98`) has a hard constraint: `CertificateService.GenerateCSR` and `Certificate.Renew` both **auto-inject private-IP and short-hostname SANs** (the BMC's current mgmt IPv4, its short hostname, an IPv6 link-local literal `<addr>.ipv6-literal.net`, etc.) into every generated CSR. LE rejects those. The Redfish `AlternativeNames` parameter is additive, not restrictive. `CertificateService.ReplaceCertificate` does not accept external private keys.

The **Web UI path honours a restrictive SAN list**, but only if you follow its exact sequence: set the `CSR_Format` dataset flag and call `Sec_DownloadCSRANDCert` to materialize the file. Without that materialize step, `/download/download_csr_0.pem` returns a stale copy regardless of what `Sec_GenKeyAndCSR` was just called with. This was discovered by HAR-capturing an interactive Web UI session.

See "Reverse-engineered Web UI auth flow" below for the full protocol.

## Architecture

```
Docker container (any host on the BMC mgmt LAN)
  │
  ├─ supercronic (in-container cron, default Mon 04:00 local TZ)
  │     └─ renew-all.sh
  │           └─ xcc-deploy-cert.py --host <FQDN>   (per host in xcc-hosts.conf)
  │                 1. fetch_live_cert() → skip if expiry > RENEWAL_THRESHOLD_DAYS
  │                 2. backup_current_cert() → /data/backups/<host>-<ts>.pem
  │                 3. XCCWebUI.login()
  │                       - POST /api/providers/get_nonce
  │                       - POST /api/login (lowercase {username,password} + CSP nonce header)
  │                 4. XCCWebUI.generate_csr()
  │                       - POST /api/function  {Sec_GenKeyAndCSR:"<csv>"}
  │                       - POST /api/dataset   {CSR_Format:"1"}
  │                       - POST /api/function  {Sec_DownloadCSRANDCert:"0,4,0"}   ← materialize
  │                       - GET  /download/download_csr_0.pem
  │                 5. validate_csr_matches_host() — fail if SAN ≠ exactly [DNS:<fqdn>]
  │                 6. acme.sh --signcsr --dns dns_cf → LE-signed fullchain PEM
  │                 7. XCCWebUI.upload_cert()
  │                       - POST /upload (multipart with fullchain.pem)
  │                       - POST /api/providers/cert_upload  {FileName, ServiceType:0, CertType:"cert", Index:0}
  │                       - POST /api/function  {Sec_ImportCert:"0,1,0,0,<original-filename>,"}   ← activation
  │                 8. sleep 45s, then validate_deployed_cert() — issuer + SAN + pubkey fingerprint (6× retry × 20s)
  │
  └─ acme.sh installed into /data/acme on first run
```

## Reverse-engineered Web UI auth flow

All state was derived from HAR captures of an interactive browser session against a Lenovo XCC Web UI. The Web UI is a Vue SPA. Under the hood:

- **Login** requires a short-lived nonce fetched from `POST /api/providers/get_nonce` (empty `{}` body), replayed as a request header `Content-Security-Policy: nonce=<uuid>` on the `POST /api/login`. Request body uses **lowercase** keys: `{"username":"...","password":"..."}` (PascalCase is rejected with 507 "Invalid credentials").
- **Auth tokens**: login response gives `{"access_token": "<JWT>"}` in the body and sets `_csrf_token=<value>` cookie. Subsequent requests need `Authorization: Bearer <JWT>` **and** `X-XSRF-TOKEN: <csrf>` (CSRF double-submit).
- **Generate CSR** is 3 calls, in order, under the same session: `Sec_GenKeyAndCSR` (params) → `CSR_Format=1` (format flag) → `Sec_DownloadCSRANDCert` (materialize file on disk). Skipping the materialize call leaves the download URL serving whatever was last materialized.
- **Upload signed cert** is a 3-step dance. Skipping any step leaves the XCC serving the previous cert while APIs return success:
  1. `POST /upload` (multipart, form field `file`) — stages the file, returns `{"items":[{"path":"<handle>"}]}`
  2. `POST /api/providers/cert_upload` with `{FileName:<handle>, ServiceType:0, CertType:"cert", Index:0}` — stages the cert internally
  3. `POST /api/function` with `{"Sec_ImportCert":"0,1,0,0,<original_filename>,"}` — **actually activates the cert**. The last arg is the filename sent in step 1's multipart (not the handle from step 1's response).
- **Session is tied to the user, not the client IP**: concurrent calls from different source IPs share session state. `sessioninfo.remoteip` reflects whichever client first authenticated. Harmless for automation, confusing when debugging while a browser session is open.

The `Sec_GenKeyAndCSR` body is a CSV-packed string. Field layout (0-indexed, discovered empirically):
- 0: cert type (0 = HTTPS server)
- 1-4: Country, State, City, Organization
- 5: Common Name
- 6-14: optional subject fields (OU, email, etc. — left empty)
- 15: unknown (always 0 in browser-generated calls)
- 16: key-strength hint (256 → ECDSA P-384 in practice)
- 17-24: SAN slots, each prefixed with type (`DNS:...`, `IP Address:...`). Up to 8 entries, max 512 chars total.

## Key design decisions (don't undo)

1. **Web UI path, not Redfish.** See "Why Web UI API and not Redfish" above. Don't "simplify" back to Redfish — it's broken for our use case on current firmware.
2. **CSR generated on the XCC, key never leaves.** The code never sees the private key. It drives the XCC through its own keypair-generation + upload lifecycle.
3. **No reverse proxy.** An earlier design used a Traefik reverse proxy to sidestep the XCC cert limitations; once direct deploy proved workable (after cracking the Web UI flow), that path was dropped.
4. **Fail-fast on CSR pollution.** `validate_csr_matches_host` rejects any SAN that isn't exactly `[DNS:<fqdn>]`. If a firmware update regresses the Web UI behaviour, we abort before burning an LE rate-limit slot.
5. **Pubkey-fingerprint check post-deploy.** `validate_deployed_cert` compares the CSR's pubkey against the served cert's pubkey to catch silent upload-didn't-activate regressions (the exact failure mode we hit before finding `Sec_ImportCert`).
6. **DNS-01 via Cloudflare.** BMC mgmt LANs are typically not internet-reachable, so HTTP-01 is impossible. The CF token writes TXT under the public parent zone; even if the FQDNs are only resolved by internal DNS (no public A record), LE only needs the `_acme-challenge.*` TXT and that's served from the parent CF zone.
7. **Supercronic, not host cron.** Runs in container, logs to stdout (Docker-friendly), TZ-aware.

## Layout

```
.
├── Dockerfile                       multi-stage; fetches acme.sh + supercronic at build
├── docker-compose.yml
├── requirements.txt                 pinned Python deps
├── .env.example                     template for secrets
├── .gitignore
├── config/
│   └── xcc-hosts.conf.example       one FQDN per line (copy to xcc-hosts.conf)
├── scripts/
│   ├── xcc-deploy-cert.py           main logic (Web UI client + acme.sh + pre/post validation)
│   ├── renew-all.sh                 orchestrates all hosts, aggregates failures
│   └── entrypoint.sh                installs acme.sh on first run, dispatches commands
├── README.md                        public-facing docs
└── CLAUDE.md                        this file
```

## Environment variables

| Name | Required | Default | Notes |
|---|---|---|---|
| `ACME_EMAIL` | on first run | — | LE account registration |
| `ACME_SERVER` | no | `letsencrypt` | Set to `letsencrypt_test` for staging |
| `XCC_USER` | yes | — | Web UI username (Supervisor role, WebUI account type) |
| `XCC_PASS` | yes | — | Web UI password. **Must not be in password-change-required state** (log in once via UI to clear it) |
| `CF_Token` | yes | — | Cloudflare API token with `Zone:DNS:Edit` on the public parent zone |
| `CRON_SCHEDULE` | no | `0 4 * * 1` | Mon 04:00 in `TZ` zone |
| `TZ` | no | `UTC` | e.g. `Europe/Zurich` |
| `RENEWAL_THRESHOLD_DAYS` | no | `30` | Renew when fewer days remain |
| `CSR_COUNTRY` / `CSR_STATE` / `CSR_CITY` / `CSR_ORG` | no | `XX` / `State` / `City` / `Organization` | Cosmetic Subject fields. LE ignores them; XCC just requires non-empty. |

## Commands

```bash
# Iterate on one host (interactive, verbose)
docker compose run --rm xcc-cert-renewer host <fqdn> --force --verbose

# Run one pass over every host in config/xcc-hosts.conf
docker compose run --rm xcc-cert-renewer once

# Start scheduled cron mode
docker compose up -d

# Follow scheduler logs
docker compose logs -f

# Persisted per-host log / cert backup inside the volume
docker compose exec xcc-cert-renewer ls -lh /data/logs/
docker compose exec xcc-cert-renewer ls -lh /data/backups/
```

## XCC manual prerequisites (one-time per BMC)

1. **Create the Web UI user** — *BMC Configuration → Users* → create the service account (e.g. `acme-api`) with **Supervisor** role.
2. **Force-change the password** — log in once via the Web UI with the service account. The XCC prompts for a new password (first-login requirement). Without this, all API calls return 403 "PasswordChangeRequired" except `/redfish/v1/` itself.
3. **(Optional) Disable PasswordExpiration** on the account so the service doesn't silently break after 90 days.
4. **First cert activation is manual.** Generate + LE-sign a cert once via this tool with `--force`, then upload the generated fullchain via the Web UI's *Import Certificate* form. After that one-time UI upload, the tool's API-driven renewals work fully. Factory-fresh BMCs silently no-op on API cert_upload until they've accepted one UI-driven external cert.

Internal DNS: each BMC FQDN A-records directly to that BMC's mgmt IP. The public parent zone (on Cloudflare) needs no A record for the BMC — only the transient `_acme-challenge.*` TXT records are written there during issuance.

## Known gotchas

- **Web UI session is user-scoped, not connection-scoped.** `sessioninfo.remoteip` stays at whichever client first logged in.
- **XCC web service reload is async (~30-60s)** after `cert_upload` + `Sec_ImportCert`. Validation loop retries 6×20s, up to ~2 min total.
- **Factory-fresh BMC silent no-op**: see prerequisite #4 above. The `Sec_ImportCert` call returns `{"return": 0}` but the active cert isn't swapped until the BMC has accepted one UI-driven external cert.
- **`PasswordExpiration` default 90 days** on Lenovo XCC accounts. For a service user, disable it via the Web UI to avoid silent break.
- **Rate limits**: LE prod is 50 certs/week/registered-domain; 5 duplicates/week per FQDN. Weekly cron × 90-day cert × threshold 30d means one renewal per ~60d in steady state — well within limits. Don't hammer with `--force` during debug; use `ACME_SERVER=letsencrypt_test`.
- **CSR materialize step**: if `Sec_GenKeyAndCSR` isn't followed by `CSR_Format` + `Sec_DownloadCSRANDCert`, `/download/download_csr_0.pem` keeps serving the previous CSR. Downstream validation catches the pubkey mismatch but the error message would be misleading — always run all three.
- **Cloudflare zone handling**: if your BMC FQDNs live under a subdomain of your public CF zone (e.g. `*.int.example.com` in an `example.com` CF zone that has no delegation for `int`), CF serves the `_acme-challenge.*.int.example.com` TXT records you write directly, even though the A records are internal-only. This is the most common setup and just works.

## Useful references

- acme.sh `--signcsr`: https://github.com/acmesh-official/acme.sh/wiki
- acme.sh Cloudflare DNS API: https://github.com/acmesh-official/acme.sh/wiki/dnsapi#dns_cf
- supercronic: https://github.com/aptible/supercronic
- Lenovo XCC Redfish cert endpoints (documented behaviour that doesn't work for external CAs): https://pubs.lenovo.com/xcc-restapi/certmgt_replace_certificate_post

## Style / conventions

- Python: type hints, `from __future__ import annotations`, stdlib logging, f-strings.
- Bash: `set -euo pipefail`, quote every variable, shellcheck-clean.
- Errors: fail-fast over silent fallback. Only "continue on error" is in `renew-all.sh` at the per-host boundary.
- Secrets never logged. Never `LOG.debug` anything with `XCC_PASS`, `CF_Token`, or the JWT.
