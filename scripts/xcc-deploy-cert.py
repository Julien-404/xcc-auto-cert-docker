#!/usr/bin/env python3
"""
xcc-deploy-cert.py - Deploy a Let's Encrypt certificate to a Lenovo XClarity Controller.

Uses the XCC Web UI's internal REST API (reverse-engineered) because Redfish
`Certificate.Renew`/`GenerateCSR` auto-inject private-IP / short-hostname SANs
that LE refuses to sign. The Web UI path honours a restrictive SAN list.

Workflow per host:
  1. Pre-check: read current HTTPS cert, skip if expiry > RENEWAL_THRESHOLD_DAYS.
  2. Backup the currently-deployed cert to /data/backups/.
  3. Web UI login: get_nonce -> login -> extract JWT + CSRF token.
  4. Generate CSR: Sec_GenKeyAndCSR -> dataset CSR_Format=1 -> Sec_DownloadCSRANDCert -> download.
  5. Validate CSR contains only the expected FQDN (defense in depth).
  6. Sign with Let's Encrypt via acme.sh (DNS-01 Cloudflare).
  7. Upload signed cert: POST /upload -> POST /api/providers/cert_upload -> Sec_ImportCert (activate).
  8. Wait for web-server reload and validate the live cert on port 443, with
     pubkey-fingerprint check to catch silent upload failures (retried).
"""

from __future__ import annotations

import argparse
import logging
import os
import socket
import ssl
import subprocess
import sys
import tempfile
import time
from datetime import datetime, timezone
from pathlib import Path

import requests
import urllib3
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.x509.oid import ExtensionOID, NameOID

# The XCC serves a factory self-signed cert (or our deployed LE cert). We do
# the TLS verification of the deployed cert separately after rollout.
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

LOG = logging.getLogger("xcc-deploy")

# ---- Constants -------------------------------------------------------------
DEFAULT_RENEWAL_THRESHOLD_DAYS = 30
XCC_POST_DEPLOY_WAIT = 45
VALIDATION_RETRIES = 6
VALIDATION_RETRY_DELAY = 20
HTTP_TIMEOUT = 30
ACME_TIMEOUT = 600


def _cert_not_after(cert: x509.Certificate) -> datetime:
    getter = getattr(cert, "not_valid_after_utc", None)
    if getter is not None:
        return getter
    return cert.not_valid_after.replace(tzinfo=timezone.utc)


def require_env(name: str) -> str:
    value = os.environ.get(name)
    if not value:
        raise RuntimeError(f"Required environment variable {name} is not set")
    return value


# ============================================================================
# XCC Web UI client (reverse-engineered from browser HAR captures)
# ============================================================================
class XCCWebUI:
    """Authenticated session against the XCC Web UI's internal JSON API.

    The flow is non-Redfish; endpoints live under /api/providers, /api/function,
    /api/dataset, /upload, /download. Auth is a JWT in localStorage +
    a `_csrf_token` cookie echoed back via the X-XSRF-TOKEN header.
    """

    def __init__(self, host: str, user: str, password: str) -> None:
        self.host = host
        self.base_url = f"https://{host}"
        self.user = user
        self.password = password
        self.session = requests.Session()
        self.session.verify = False
        self.session.headers.update({
            "Accept": "application/json, text/plain, */*",
            "Origin": self.base_url,
            "Referer": f"{self.base_url}/",
        })

    def _url(self, path: str) -> str:
        return f"{self.base_url}{path}"

    def login(self) -> None:
        # Step 1 - fetch a fresh nonce (server expects POST with empty JSON body)
        r = self.session.post(self._url("/api/providers/get_nonce"),
                              json={}, timeout=HTTP_TIMEOUT)
        r.raise_for_status()
        nonce = r.json().get("nonce")
        if not nonce:
            raise RuntimeError(f"get_nonce returned no nonce: {r.text[:200]}")

        # Step 2 - login. Note: keys are lowercase. The server rejects PascalCase.
        # The Content-Security-Policy request header is required (yes, really -
        # it's used as a nonce channel by the XCC, not in its standard meaning).
        r = self.session.post(
            self._url("/api/login"),
            json={"username": self.user, "password": self.password},
            headers={"Content-Security-Policy": f"nonce={nonce}"},
            timeout=HTTP_TIMEOUT,
        )
        if r.status_code != 200:
            raise RuntimeError(f"Login failed: HTTP {r.status_code} - {r.text[:200]}")
        token = r.json().get("access_token")
        if not token:
            raise RuntimeError(f"Login returned no access_token: {r.text[:200]}")

        # The login response sets a `_csrf_token` cookie. We echo it back via
        # X-XSRF-TOKEN on every subsequent request.
        csrf = self.session.cookies.get("_csrf_token")
        if not csrf:
            raise RuntimeError("Login did not set _csrf_token cookie")

        self.session.headers.update({
            "Authorization": f"Bearer {token}",
            "X-XSRF-TOKEN": csrf,
        })
        LOG.info("Web UI login OK (user=%s)", self.user)

    def logout(self) -> None:
        try:
            self.session.post(self._url("/api/logout"), timeout=HTTP_TIMEOUT)
        except Exception:
            pass

    def generate_csr(self, fqdn: str) -> str:
        """Run the full Generate CSR flow and return the PEM CSR.

        The CSR is produced with SAN = [fqdn] only; no IP / short-hostname
        injection (unlike the Redfish path).
        """
        # Subject/SAN CSV - the Web UI sends a packed CSV string. Field positions:
        #   0: csr type (0 = HTTPS server cert)
        #   1..4: C, ST, L, O
        #   5: CN
        #   6..14: optional fields (OU, email, etc. - left empty)
        #   15: unknown (always 0 in browser-generated calls)
        #   16: key bit length hint (256 -> ECDSA P-384 in practice)
        #   17..24: SAN slots, each prefixed with type (DNS:, IP Address:, ...)
        # Subject fields must be non-empty or the XCC rejects the request.
        # The values are cosmetic from LE's perspective (LE only signs based on SAN),
        # so sensible generic defaults are fine. Override via CSR_* env vars if needed.
        country = os.environ.get("CSR_COUNTRY", "XX")
        state = os.environ.get("CSR_STATE", "State")
        city = os.environ.get("CSR_CITY", "City")
        org = os.environ.get("CSR_ORG", "Organization")
        subject_csv = (
            f"0,{country},{state},{city},{org},{fqdn},"
            ",,,,,,,,,"
            "0,256,"
            f"DNS:{fqdn},,,,,,,"
        )

        LOG.info("Requesting fresh keypair + CSR on %s (CN=%s, SAN=[%s])",
                 self.host, fqdn, fqdn)
        r = self.session.post(self._url("/api/function"),
                              json={"Sec_GenKeyAndCSR": subject_csv},
                              timeout=HTTP_TIMEOUT)
        r.raise_for_status()
        if r.json().get("return") != 0:
            raise RuntimeError(f"Sec_GenKeyAndCSR failed: {r.text[:300]}")

        # Set the format flag so the next download is in PEM with the SAN honored.
        r = self.session.post(self._url("/api/dataset"),
                              json={"CSR_Format": "1"}, timeout=HTTP_TIMEOUT)
        r.raise_for_status()
        if r.json().get("return") != 0:
            raise RuntimeError(f"CSR_Format set failed: {r.text[:300]}")

        # Materialize the file. Without this step, /download/* returns a stale
        # cached CSR. Args meaning: 0 = cert type (HTTPS), 4 = CSR download,
        # 0 = index. Confirmed by HAR from an interactive session.
        r = self.session.post(self._url("/api/function"),
                              json={"Sec_DownloadCSRANDCert": "0,4,0"},
                              timeout=HTTP_TIMEOUT)
        r.raise_for_status()
        fname = r.json().get("FileName")
        if not fname:
            raise RuntimeError(f"Sec_DownloadCSRANDCert returned no FileName: {r.text[:300]}")

        r = self.session.get(self._url(f"/download/{fname}"), timeout=HTTP_TIMEOUT)
        r.raise_for_status()
        csr_pem = r.text.strip()
        if "BEGIN CERTIFICATE REQUEST" not in csr_pem:
            raise RuntimeError(f"Downloaded file is not a CSR: {csr_pem[:200]}")
        return csr_pem + "\n"

    def upload_cert(self, fullchain_pem: str) -> None:
        """Upload a signed fullchain PEM (leaf + intermediates) to the XCC.

        Three-step dance, matching what the Web UI does internally:
          1. POST /upload (multipart) -> stages the file, returns a handle
          2. POST /api/providers/cert_upload -> stages the cert (no-op on its own)
          3. POST /api/function Sec_ImportCert -> actually activates the cert

        Without step 3, cert_upload appears to succeed (`{"return":0}`) but
        the XCC silently keeps serving the previous cert. Sec_ImportCert takes
        the ORIGINAL upload filename (not the internal handle) as its argument.
        """
        upload_filename = f"{self.host}-fullchain.pem"
        LOG.info("Uploading signed cert bundle to %s", self.host)
        files = {"file": (upload_filename, fullchain_pem.encode(), "application/octet-stream")}
        r = self.session.post(self._url("/upload"), files=files, timeout=HTTP_TIMEOUT)
        r.raise_for_status()
        items = r.json().get("items") or []
        if not items or not items[0].get("path"):
            raise RuntimeError(f"/upload returned no file handle: {r.text[:300]}")
        handle = items[0]["path"]

        r = self.session.post(
            self._url("/api/providers/cert_upload"),
            json={"FileName": handle, "ServiceType": 0, "CertType": "cert", "Index": 0},
            timeout=HTTP_TIMEOUT,
        )
        r.raise_for_status()
        if r.json().get("return") != 0:
            raise RuntimeError(f"cert_upload staging failed: {r.text[:300]}")

        # Args: 0=HTTPS cert type, 1=import mode, 0=?, 0=?, <filename>, (trailing empty)
        r = self.session.post(
            self._url("/api/function"),
            json={"Sec_ImportCert": f"0,1,0,0,{upload_filename},"},
            timeout=HTTP_TIMEOUT,
        )
        r.raise_for_status()
        if r.json().get("return") != 0:
            raise RuntimeError(f"Sec_ImportCert failed: {r.text[:300]}")
        LOG.info("Cert activated on %s", self.host)


# ============================================================================
# acme.sh wrapper
# ============================================================================
def acme_sign_csr(csr_pem: str, domain: str, workdir: Path) -> str:
    """Sign a CSR with Let's Encrypt via acme.sh (--signcsr, DNS-01 Cloudflare).

    Returns the fullchain PEM (leaf + intermediates).
    """
    acme_home = Path(os.environ.get("ACME_HOME", "/data/acme"))
    acme_bin = acme_home / "acme.sh"
    if not acme_bin.exists():
        raise FileNotFoundError(
            f"acme.sh not found at {acme_bin}. "
            f"First-run install is done by the container entrypoint."
        )

    csr_path = workdir / f"{domain}.csr"
    cert_path = workdir / f"{domain}.cer"
    ca_path = workdir / f"{domain}.ca.cer"
    fullchain_path = workdir / f"{domain}.fullchain.cer"
    csr_path.write_text(csr_pem)

    env = os.environ.copy()
    require_env("CF_Token")
    server = os.environ.get("ACME_SERVER", "letsencrypt")

    cmd = [
        str(acme_bin),
        "--home", str(acme_home),
        "--signcsr",
        "--csr", str(csr_path),
        "--dns", "dns_cf",
        "--server", server,
        "--cert-file", str(cert_path),
        "--ca-file", str(ca_path),
        "--fullchain-file", str(fullchain_path),
        "--force",
    ]
    LOG.info("Running acme.sh --signcsr for %s (server=%s)", domain, server)
    result = subprocess.run(
        cmd, env=env, capture_output=True, text=True, timeout=ACME_TIMEOUT
    )
    if result.returncode != 0:
        LOG.error("acme.sh stdout:\n%s", result.stdout)
        LOG.error("acme.sh stderr:\n%s", result.stderr)
        raise RuntimeError(f"acme.sh exited with code {result.returncode}")
    if not fullchain_path.exists() or fullchain_path.stat().st_size == 0:
        raise RuntimeError("acme.sh succeeded but fullchain file is missing/empty")
    return fullchain_path.read_text()


# ============================================================================
# Certificate inspection & validation
# ============================================================================
def fetch_live_cert(host: str, port: int = 443, timeout: int = 10) -> str:
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    with socket.create_connection((host, port), timeout=timeout) as sock:
        with ctx.wrap_socket(sock, server_hostname=host) as ssock:
            der = ssock.getpeercert(binary_form=True)
    return ssl.DER_cert_to_PEM_cert(der)


def cert_needs_renewal(pem: str, threshold_days: int) -> tuple[bool, str]:
    try:
        cert = x509.load_pem_x509_certificate(pem.encode(), default_backend())
    except Exception as e:
        return True, f"Could not parse current cert ({e}); assuming renewal needed"
    not_after = _cert_not_after(cert)
    days_left = (not_after - datetime.now(timezone.utc)).days
    issuer = cert.issuer.rfc4514_string()
    if days_left < threshold_days:
        return True, f"Expires in {days_left}d (issuer: {issuer})"
    return False, f"Still valid for {days_left}d (issuer: {issuer})"


def validate_csr_matches_host(csr_pem: str, host: str) -> None:
    """Fail-fast if the CSR's SAN list is polluted or doesn't include the FQDN.

    The whole point of the Web UI path is to get a clean SAN = [FQDN] list.
    If something regressed and the CSR contains extra entries LE can't validate,
    abort before submitting to LE (and burning rate-limit budget).
    """
    try:
        csr = x509.load_pem_x509_csr(csr_pem.encode(), default_backend())
    except Exception as e:
        raise RuntimeError(f"Could not parse CSR: {e}") from e
    dns_names: list[str] = []
    ip_names: list[str] = []
    try:
        san_ext = csr.extensions.get_extension_for_oid(
            ExtensionOID.SUBJECT_ALTERNATIVE_NAME
        )
        dns_names = list(san_ext.value.get_values_for_type(x509.DNSName))
        ip_names = [str(ip) for ip in san_ext.value.get_values_for_type(x509.IPAddress)]
    except x509.ExtensionNotFound:
        pass
    if host not in dns_names:
        raise RuntimeError(f"CSR missing expected DNS:{host}. DNS={dns_names} IP={ip_names}")
    bad = [d for d in dns_names if d != host] + ip_names
    if bad:
        raise RuntimeError(
            f"CSR has unexpected SAN entries {bad}; LE will reject. "
            f"Check that Sec_DownloadCSRANDCert materialized the new CSR."
        )
    LOG.info("CSR clean: SAN=[DNS:%s]", host)


def _pubkey_fingerprint(cert_or_csr) -> str:
    """SHA-256 of DER SubjectPublicKeyInfo, hex-encoded. Works on x509 Certificate or CSR."""
    from cryptography.hazmat.primitives import hashes, serialization
    der = cert_or_csr.public_key().public_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    d = hashes.Hash(hashes.SHA256(), backend=default_backend())
    d.update(der)
    return d.finalize().hex()


def validate_deployed_cert(host: str, staging: bool, expected_pubkey: str | None = None) -> None:
    LOG.info("Validating deployed certificate on %s:443", host)
    pem = fetch_live_cert(host)
    cert = x509.load_pem_x509_certificate(pem.encode(), default_backend())
    issuer = cert.issuer.rfc4514_string()
    days_left = (_cert_not_after(cert) - datetime.now(timezone.utc)).days

    issuer_ok = ("let's encrypt" in issuer.lower() or "letsencrypt" in issuer.lower())
    if staging:
        issuer_ok = issuer_ok and "staging" in issuer.lower()
    if not issuer_ok:
        raise RuntimeError(f"Unexpected issuer on deployed cert: {issuer}")

    try:
        san = cert.extensions.get_extension_for_oid(
            ExtensionOID.SUBJECT_ALTERNATIVE_NAME
        ).value.get_values_for_type(x509.DNSName)
    except x509.ExtensionNotFound:
        san = []
    if host not in san:
        raise RuntimeError(f"Deployed cert SAN missing {host}: got {san}")

    # Defense in depth: if caller supplied the expected pubkey (from the CSR we
    # just signed), make sure the XCC is actually serving a cert bound to that
    # keypair. Catches silent cert_upload/Sec_ImportCert regressions.
    if expected_pubkey is not None:
        actual = _pubkey_fingerprint(cert)
        if actual != expected_pubkey:
            raise RuntimeError(
                f"Deployed cert pubkey mismatch: expected {expected_pubkey[:16]}…, "
                f"got {actual[:16]}…. The XCC is still serving the previous cert."
            )

    LOG.info("Deployed cert OK: issuer=%s, expires in %dd, SAN=%s",
             issuer, days_left, san)


def backup_current_cert(host: str, backup_dir: Path) -> Path | None:
    backup_dir.mkdir(parents=True, exist_ok=True)
    timestamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    path = backup_dir / f"{host}-{timestamp}.pem"
    try:
        pem = fetch_live_cert(host)
    except Exception as e:
        LOG.warning("Could not fetch current cert on %s for backup: %s", host, e)
        return None
    path.write_text(pem)
    path.chmod(0o600)
    LOG.info("Backed up current cert to %s", path)
    return path


# ============================================================================
# Main flow
# ============================================================================
def deploy_to_xcc(host: str, dry_run: bool, force: bool,
                  skip_validate: bool) -> int:
    xcc_user = require_env("XCC_USER")
    xcc_pass = require_env("XCC_PASS")
    threshold = int(os.environ.get("RENEWAL_THRESHOLD_DAYS", DEFAULT_RENEWAL_THRESHOLD_DAYS))
    backup_dir = Path(os.environ.get("BACKUP_DIR", "/data/backups"))
    staging = os.environ.get("ACME_SERVER", "letsencrypt") != "letsencrypt"

    # 1. Pre-check
    try:
        live_pem = fetch_live_cert(host)
        needs, msg = cert_needs_renewal(live_pem, threshold)
        LOG.info("Pre-check [%s]: %s", host, msg)
        if not needs and not force:
            LOG.info("Skipping %s: renewal not needed (use --force to override)", host)
            return 0
    except Exception as e:
        LOG.warning("Pre-check failed for %s: %s (proceeding)", host, e)

    if dry_run:
        LOG.info("[dry-run] Would renew cert on %s", host)
        return 0

    # 2. Backup
    backup_current_cert(host, backup_dir)

    # 3. Web UI login
    xcc = XCCWebUI(host, xcc_user, xcc_pass)
    try:
        xcc.login()
    except Exception as e:
        LOG.error("Login failed on %s: %s", host, e)
        return 2

    expected_pubkey: str | None = None
    try:
        # 4. Generate clean CSR
        csr_pem = xcc.generate_csr(host)
        LOG.debug("CSR:\n%s", csr_pem)

        # 5. Validate
        validate_csr_matches_host(csr_pem, host)

        # Record the CSR's pubkey so post-deploy validation can confirm the
        # XCC swapped to serving this specific keypair.
        csr_obj = x509.load_pem_x509_csr(csr_pem.encode(), default_backend())
        expected_pubkey = _pubkey_fingerprint(csr_obj)

        # 6. Sign with LE
        with tempfile.TemporaryDirectory(prefix="xcc-cert-") as tmp:
            fullchain_pem = acme_sign_csr(csr_pem, host, Path(tmp))

        # 7. Upload
        xcc.upload_cert(fullchain_pem)
    finally:
        xcc.logout()

    # 8. Wait for web service reload
    LOG.info("Waiting %ds for XCC to reload its web service", XCC_POST_DEPLOY_WAIT)
    time.sleep(XCC_POST_DEPLOY_WAIT)

    # 9. Validate post-deploy
    if not skip_validate:
        last_err = None
        for attempt in range(1, VALIDATION_RETRIES + 1):
            try:
                validate_deployed_cert(host, staging=staging, expected_pubkey=expected_pubkey)
                break
            except Exception as e:
                last_err = e
                LOG.warning("Validation attempt %d/%d failed: %s",
                            attempt, VALIDATION_RETRIES, e)
                if attempt < VALIDATION_RETRIES:
                    time.sleep(VALIDATION_RETRY_DELAY)
        else:
            LOG.error("Post-deployment validation failed for %s: %s", host, last_err)
            return 3

    LOG.info("SUCCESS: cert renewed on %s", host)
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Renew Let's Encrypt cert on a Lenovo XCC BMC via its Web UI API"
    )
    parser.add_argument("--host", required=True, help="XCC FQDN")
    parser.add_argument("--dry-run", action="store_true")
    parser.add_argument("--force", action="store_true",
                        help="Renew even if not near expiry")
    parser.add_argument("--skip-validate", action="store_true")
    parser.add_argument("-v", "--verbose", action="store_true")
    args = parser.parse_args()

    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format="%(asctime)s [%(levelname)s] %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )
    try:
        return deploy_to_xcc(
            host=args.host,
            dry_run=args.dry_run,
            force=args.force,
            skip_validate=args.skip_validate,
        )
    except Exception as e:
        LOG.exception("Fatal error on %s: %s", args.host, e)
        return 1


if __name__ == "__main__":
    sys.exit(main())
