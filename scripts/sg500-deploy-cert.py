#!/usr/bin/env python3
"""sg500-deploy-cert.py — issue/renew a Let's Encrypt certificate and install it
on a Cisco Small Business SG500-series HTTPS admin interface.

Works around SG500 firmware 1.4.x quirks:
  - Only 2 cert slots (1 and 2). We install in slot 2, leaving slot 1 as a
    factory rollback.
  - `crypto certificate N import` expects a three-block PEM payload in this
    exact order: RSA PRIVATE KEY (PKCS#1), RSA PUBLIC KEY (PKCS#1 derived),
    leaf X.509 CERTIFICATE. Full chain is rejected ("Inconsistent value").
  - TTY paste buffer is fragile: blasting the PEM straight via `chan.sendall`
    drops characters. We send one line at a time and drain the echo (~0.22s)
    between lines before the next one.
  - HTTPS ciphers are legacy (AES-CBC, TLSv1.2 max). Python SSL defaults reject
    them, so probes use SECLEVEL=0.
  - SSH auth only accepts rsa-sha1 signatures from user keys (firmware 1.4.x
    predates the rsa-sha2 RFC). We explicitly disable rsa-sha2 in paramiko.

Usage:
    sg500-deploy-cert.py --host sw-backbone.int.dataplex.ch [--ip 172.16.27.20]
        [--ssh-user claude] [--ssh-key /config/ssh/sg500-key] [--slot 2] [--force]

Env vars:
    ACME_HOME               acme.sh home dir (default /data/acme)
    ACME_SERVER             default "letsencrypt"
    RENEWAL_THRESHOLD_DAYS  skip if cert has more than this many days left (default 30)
    SG500_SSH_USER          default "claude"
    SG500_SSH_KEY           default "/config/ssh/sg500-key"
    SG500_SLOT              default 2

Exit codes:
    0 success (or SKIP, still valid)
    1 fatal / aborted before install
    2 install reported success but post-install TLS probe failed
    3 post-install cert fingerprint did not change vs pre-install
"""
import argparse, datetime, os, pathlib, re, socket, ssl, subprocess, sys, time
import paramiko

ACME_HOME = pathlib.Path(os.environ.get("ACME_HOME", "/data/acme"))
ACME_SERVER = os.environ.get("ACME_SERVER", "letsencrypt")
THRESHOLD = int(os.environ.get("RENEWAL_THRESHOLD_DAYS", "30"))


def log(msg: str) -> None:
    print(f"[{datetime.datetime.now(datetime.timezone.utc).isoformat(timespec='seconds')}] {msg}", flush=True)


# ---------------------------------------------------------------------------
# TLS probe (pre + post check)
# ---------------------------------------------------------------------------
def peek_cert(fqdn: str, ip: str | None = None):
    # SG500 firmware 1.4.x speaks TLSv1.2 with legacy ciphers (AES-CBC, 3DES).
    # Python's default SECLEVEL=2 rejects them, so force a permissive context
    # only for this probe (verify_mode is NONE — we're reading, not trusting).
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    try:
        ctx.set_ciphers("ALL:@SECLEVEL=0")
    except ssl.SSLError:
        ctx.set_ciphers("DEFAULT:@SECLEVEL=0")
    target = ip or fqdn
    try:
        with socket.create_connection((target, 443), timeout=8) as s, \
             ctx.wrap_socket(s, server_hostname=fqdn) as tls:
            der = tls.getpeercert(binary_form=True)
    except Exception as exc:
        log(f"probe {target}:443 failed: {exc}")
        return None
    out = subprocess.run(
        ["openssl", "x509", "-inform", "DER", "-noout",
         "-enddate", "-subject", "-fingerprint", "-sha1"],
        input=der, capture_output=True, check=True, timeout=10,
    ).stdout.decode()
    m_end = re.search(r"notAfter=(.+)", out)
    m_sub = re.search(r"subject=(.+)", out)
    m_fp  = re.search(r"Fingerprint=(.+)", out)
    notafter = datetime.datetime.strptime(m_end.group(1).strip(), "%b %d %H:%M:%S %Y %Z")
    return (notafter.replace(tzinfo=datetime.timezone.utc),
            m_sub.group(1).strip(), m_fp.group(1).strip())


# ---------------------------------------------------------------------------
# acme.sh wrapper
# ---------------------------------------------------------------------------
def acme_issue(fqdn: str) -> tuple[pathlib.Path, pathlib.Path]:
    """Run acme.sh issue/renew for fqdn, return (key_path, cert_path).

    acme.sh returns 0 on fresh issue, 2 when the cert is still valid and no
    renewal is needed — both are normal outcomes.
    """
    acme_sh = ACME_HOME / "acme.sh"
    if not acme_sh.exists():
        raise FileNotFoundError(f"acme.sh not found at {acme_sh}")
    cmd = [str(acme_sh), "--issue", "--dns", "dns_cf", "-d", fqdn,
           "--keylength", "2048", "--server", ACME_SERVER]
    log(f"running {' '.join(cmd)}")
    r = subprocess.run(cmd, capture_output=True, text=True)
    if r.returncode not in (0, 2):
        log("acme.sh stdout:\n" + r.stdout)
        log("acme.sh stderr:\n" + r.stderr)
        raise RuntimeError(f"acme.sh failed rc={r.returncode}")
    # acme.sh writes to $HOME/.acme.sh by default. When running as uid 1000
    # (user "acme" with HOME=/data in the container image), this is
    # /data/.acme.sh. Other paths listed as defensive fallbacks.
    for d in (pathlib.Path.home() / ".acme.sh" / fqdn,
              ACME_HOME / fqdn):
        if (d / f"{fqdn}.key").exists():
            return d / f"{fqdn}.key", d / f"{fqdn}.cer"
    raise FileNotFoundError(f"cannot locate issued cert dir for {fqdn}")


def build_payload(key_path: pathlib.Path, cert_path: pathlib.Path) -> tuple[str, str, str]:
    """Return (private_key_pkcs1_pem, public_key_pkcs1_pem, leaf_cert_pem).

    The leaf is extracted from fullchain.cer; the intermediate is dropped because
    SG500 1.4.x rejects multi-cert bundles ("Inconsistent value"). Browsers
    recover via AIA from the leaf's "CA Issuers" extension.
    """
    key_pem = key_path.read_text().strip()
    cert_text = cert_path.read_text().strip()
    m = re.match(r"(-----BEGIN CERTIFICATE-----.*?-----END CERTIFICATE-----)",
                 cert_text, re.S)
    if not m:
        raise RuntimeError(f"no certificate found in {cert_path}")
    leaf = m.group(1)
    pub_pem = subprocess.run(
        ["openssl", "rsa", "-in", "/dev/stdin", "-RSAPublicKey_out"],
        input=key_pem.encode(), capture_output=True, check=True, timeout=10,
    ).stdout.decode().strip()
    return key_pem, pub_pem, leaf


# ---------------------------------------------------------------------------
# SG500 SSH install
# ---------------------------------------------------------------------------
# Patterns that indicate a CLI-level error in SG500 1.4.x. Covers both "% ..."
# style error echoes and the few plain-text SSL-related ones we have observed.
SG500_ERROR_PATTERNS = (
    re.compile(r"^\s*%"),                                  # "% bad parameter", "% Unrecognized command"
    re.compile(r"SSL can't import certificate"),
    re.compile(r"saved private key did not match"),
    re.compile(r"Inconsistent value"),
    re.compile(r"Private key instance \d+ does not exist"),
    re.compile(r"Invalid .*$", re.IGNORECASE),
)


def _scan_for_errors(tail: str) -> list[str]:
    """Return a list of error-looking lines from a CLI response tail."""
    errors: list[str] = []
    for raw_line in tail.splitlines():
        line = raw_line.strip()
        if not line:
            continue
        for pat in SG500_ERROR_PATTERNS:
            if pat.search(line):
                errors.append(line)
                break
    return errors


def _response_after_terminator(post: str) -> str:
    """Slice response to keep only what comes after the paste terminator "."

    Critical: `post` contains the switch's echo of our paste, which includes
    the private key PEM. We must never log `post` directly — only this slice.
    """
    # The terminator we sent is "\n.\n". Some firmwares echo it as ".\r\n" or
    # similar; match a bare "." line.
    m = re.search(r"(^|\n)\s*\.\s*(\r?\n|$)", post)
    if m:
        return post[m.end():]
    return "<terminator not found in response>"


def ssh_install(host: str, user: str, key_path: str, slot: int, fqdn: str,
                key_pem: str, pub_pem: str, leaf: str) -> None:
    """Paste the cert onto the switch, verify it took, then bind HTTPS.

    Raises RuntimeError with a sanitized error message (no PEM content) on any
    detectable failure BEFORE the HTTPS rebind — so we never unbind the active
    slot 1 unless slot 2 was successfully populated.
    """
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    # SG500 1.4.x SSH server only verifies rsa-sha1 signatures on user keys,
    # not rsa-sha2-256/512 (predates RFC 8332). paramiko 4.0+ prefers rsa-sha2
    # by default — force it down to rsa-sha1 for compatibility.
    pkey = paramiko.RSAKey.from_private_key_file(key_path)
    client.connect(
        host, username=user, pkey=pkey,
        look_for_keys=False, allow_agent=False,
        timeout=15, auth_timeout=15, banner_timeout=15,
        disabled_algorithms={"pubkeys": ["rsa-sha2-256", "rsa-sha2-512"]},
    )
    chan = None
    try:
        chan = client.invoke_shell(width=300, height=10000)
        chan.settimeout(12)

        def drain(wait: float) -> str:
            buf, last = b"", time.time()
            while time.time() - last < wait:
                if chan.recv_ready():
                    buf += chan.recv(65535)
                    last = time.time()
                else:
                    time.sleep(0.05)
            return buf.decode(errors="replace")

        drain(2.0)
        chan.sendall("terminal datadump\n"); drain(1.0)
        # If a previous session left us mid-paste, this bare "." clears it.
        chan.sendall(".\n"); drain(0.5)
        chan.sendall("end\n"); drain(0.5)
        chan.sendall("configure\n"); drain(0.5)
        chan.sendall(f"crypto certificate {slot} import\n")
        prompt = drain(3.0)
        if "Please paste" not in prompt:
            raise RuntimeError(
                f"did not get paste prompt for slot {slot} "
                f"(is the slot valid, 1 or 2 only on SG500?)"
            )

        lines = (key_pem + "\n" + pub_pem + "\n" + leaf).splitlines()
        log(f"pasting {len(lines)} lines (0.22s drain between lines)")
        for line in lines:
            chan.sendall(line + "\n")
            drain(0.22)
        # Let the switch settle before sending the terminator; otherwise the
        # final cert lines can still be in its input buffer.
        time.sleep(1.0)
        chan.sendall(".\n")
        post = drain(8.0)

        tail = _response_after_terminator(post)
        errors = _scan_for_errors(tail)
        if errors:
            raise RuntimeError(
                f"SG500 rejected cert import: {'; '.join(errors)}"
            )

        # Positive verification: read back the slot and confirm the expected
        # CN. Without this, a silent-but-bogus import would slip through to
        # `ip https certificate N`, which — critically — DETACHES the currently
        # active cert 1 if slot N is empty, breaking HTTPS.
        # `show crypto certificate` is EXEC-level on SG500 1.4.x, not config —
        # must leave config mode to run it.
        chan.sendall("end\n"); drain(0.8)
        chan.sendall(f"show crypto certificate {slot}\n")
        show_out = drain(4.0)
        if f"CN={fqdn}" not in show_out and f"CN = {fqdn}" not in show_out:
            slot_errors = _scan_for_errors(show_out)
            detail = "; ".join(slot_errors) if slot_errors else f"expected CN={fqdn} not found"
            raise RuntimeError(f"post-paste verification failed: {detail}")

        # Safe to rebind now — slot {slot} is known-good.
        chan.sendall("configure\n"); drain(0.5)
        chan.sendall(f"ip https certificate {slot}\n"); drain(2.0)
        chan.sendall("end\n"); drain(1.0)
        chan.sendall("write\n"); drain(1.5)
        chan.sendall("Y\n")
        save = drain(8.0)
        # "COPY-I-FILECPY" is the syslog trap the switch emits on successful
        # startup-config write; we see it mirrored in the interactive session.
        if "COPY-I-FILECPY" not in save and "successfully" not in save.lower():
            log("WARNING: `write` did not emit the expected COPY-I-FILECPY trap")
        log("config saved to startup-config")
    finally:
        if chan is not None:
            try: chan.close()
            except Exception: pass
        client.close()


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------
def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--host", required=True, help="FQDN of the switch (must match cert CN)")
    ap.add_argument("--ip", help="Switch IP (default: resolve --host)")
    ap.add_argument("--ssh-user", default=os.environ.get("SG500_SSH_USER", "claude"))
    ap.add_argument("--ssh-key",  default=os.environ.get("SG500_SSH_KEY", "/config/ssh/sg500-key"))
    ap.add_argument("--slot", type=int, default=int(os.environ.get("SG500_SLOT", "2")),
                    help="Cert slot 1 or 2 (SG500 has no slot 3+)")
    ap.add_argument("--force", action="store_true",
                    help="Skip the pre-check expiry threshold and reinstall even if unchanged")
    args = ap.parse_args()

    if args.slot not in (1, 2):
        log(f"FATAL: --slot must be 1 or 2 (got {args.slot})")
        return 1

    target = args.ip or args.host
    log(f"=== sg500-deploy-cert host={args.host} ip={target} slot={args.slot} ===")

    pre = peek_cert(args.host, args.ip)
    if pre and not args.force:
        notafter, subj, fp = pre
        days = (notafter - datetime.datetime.now(datetime.timezone.utc)).days
        log(f"current cert: subj={subj} fp={fp} notAfter={notafter.isoformat()} days_left={days}")
        if days > THRESHOLD:
            log(f"SKIP — {days} days left (threshold {THRESHOLD})")
            return 0
    elif pre is None:
        log("pre-check probe failed — will attempt renewal anyway")

    key_path, cert_path = acme_issue(args.host)
    log(f"issued key={key_path} cert={cert_path}")
    key_pem, pub_pem, leaf = build_payload(key_path, cert_path)

    ssh_install(target, args.ssh_user, args.ssh_key, args.slot,
                args.host, key_pem, pub_pem, leaf)

    # Give the HTTPS server a few seconds to pick up the new cert.
    time.sleep(4)
    post = peek_cert(args.host, args.ip)
    if not post:
        log("ERROR: post-verify TLS probe failed — install may not have taken")
        return 2
    notafter, subj, fp = post
    log(f"post-install: subj={subj} fp={fp} notAfter={notafter.isoformat()}")
    if pre and not args.force:
        if pre[2] == fp:
            log("ERROR: fingerprint unchanged after install — unexpected, failing")
            return 3
        if pre[0] >= post[0]:
            log("ERROR: notAfter did not move forward — failing")
            return 3
    log("SUCCESS")
    return 0


if __name__ == "__main__":
    sys.exit(main())
