"""End-to-end checks of squid-auth-oidc and proxy-relay-oidc.

Checks a running lab (see README.md): the helper with tokens minted at Dex,
the relay with its README's run command, and a certificate reload. Run from
the repository root on the Docker host: python3 e2e/e2e.py
"""

import base64
import hashlib
import json
import re
import shlex
import ssl
import subprocess
import sys
import time
from pathlib import Path

LAB = Path(__file__).resolve().parent.parent
NEEDED = (
    "bin/squid-auth-oidc",
    "bin/proxy-relay-oidc",
    "bin/ephemeral-ca",
    "certs/ca.crt",
    "certs/server/dex.example.com.crt",
    "certs/server/squid.example.com.crt",
)
SQUID = "https://squid.example.com:3129"
# --proxy-cacert, not only CURL_CA_BUNDLE: curl checks an HTTPS proxy against
# its own CA setting, apart from the one for the server behind it.
VIA_SQUID = ("--proxy", SQUID, "--proxy-cacert", "/certs/ca.crt")
SQUID_PUBLISHED = ("127.0.0.1", 3129)
RELAY = "http://127.0.0.1:3128"
DEX = "https://dex.example.com/dex"
ALLOWED = "http://app.internal.example.com/"
DENIED = "http://public.example.com/"
RELAY_LOG = "/tmp/relay.log"
RELAY_PID = "/tmp/relay.pid"
# Past Dex's 2m ID token lifetime, so the relay must refresh to keep passing.
TOKEN_LIFETIME_RUN = 150

# The run command of the proxy-relay-oidc README, as written.
RELAY_RUN = """
proxy-relay-oidc \\
  -listen 127.0.0.1:3128 \\
  -proxy squid.example.com:3129 \\
  -issuer https://dex.example.com/dex \\
  -client-id squid-relay \\
  -redirect-url http://127.0.0.1:8085/callback \\
  -username-claim preferred_username
"""

failures = []


def main():
    missing = [path for path in NEEDED if not (LAB / path).is_file()]
    if missing:
        sys.exit("missing " + ", ".join(missing) + ": see README.md")
    wait_for("Dex", lambda: status(f"{DEX}/.well-known/openid-configuration"), "200")
    # 407 without credentials: Squid is up and asks for them.
    wait_for("Squid", lambda: status(*VIA_SQUID, ALLOWED), "407")
    print_versions()

    check_helper()
    check_relay()
    check_relay_refuses_oversized_token()
    check_certificate_reload()

    print()
    if failures:
        print(f"{len(failures)} check(s) failed: " + ", ".join(failures))
        sys.exit(1)
    print("all checks passed")


# --- running things ----------------------------------------------------------


def run(*cmd):
    return subprocess.run(cmd, cwd=LAB, capture_output=True, text=True).stdout


def compose(*args):
    return run("docker", "compose", *args)


def in_tools(*cmd):
    return compose("exec", "-T", "tools", *cmd)


def in_squid(*cmd):
    return compose("exec", "-T", "squid", *cmd)


def status(*curl_args):
    """HTTP status of one curl request from the tools container."""
    return in_tools(
        "curl",
        "-s",
        "--max-time",
        "15",
        "-o",
        "/dev/null",
        "-w",
        "%{http_code}",
        *curl_args,
    )


def body(*curl_args):
    return in_tools("curl", "-s", "--max-time", "15", *curl_args)


def via_squid(login, token, url):
    return status(*VIA_SQUID, "--proxy-user", f"{login}:{token}", url)


def via_relay(*curl_args):
    return status("--proxy", RELAY, *curl_args)


def check(name, got, want):
    mark = "ok  " if got == want else "FAIL"
    print(f"{mark} {name}: {got}" + ("" if got == want else f" (want {want})"))
    if got != want:
        failures.append(name)


def wait_for(what, probe, want, timeout=60):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if probe() == want:
            return
        time.sleep(1)
    sys.exit(f"timed out waiting for {what}")


def print_versions():
    for tool, version in (
        ("squid-auth-oidc", in_squid("/usr/local/libexec/squid-auth-oidc", "-version")),
        ("proxy-relay-oidc", in_tools("proxy-relay-oidc", "-version")),
    ):
        if not version:
            sys.exit(
                f"bin/{tool} does not run in its container: a build with cgo? see README.md"
            )
        print(version.strip())
    print(in_squid("squid-gnutls", "-v").splitlines()[0])


# --- helper ------------------------------------------------------------------


def mint(
    login, client="squid-relay", scope="openid profile email groups offline_access"
):
    """An ID token from Dex's password grant, enabled for this lab only."""
    out = in_tools(
        "curl",
        "-sf",
        f"{DEX}/token",
        "-d",
        "grant_type=password",
        "-d",
        f"client_id={client}",
        "--data-urlencode",
        f"scope={scope}",
        "-d",
        f"username={login}",
        "-d",
        "password=password",
    )
    if not out:
        sys.exit(f"Dex issued no token for {login} ({client})")
    return json.loads(out)["id_token"]


def with_groups(token, groups):
    """token with its groups claim replaced and the signature kept."""
    header, payload, signature = token.split(".")
    claims = json.loads(base64.urlsafe_b64decode(payload + "=" * (-len(payload) % 4)))
    claims["groups"] = groups
    forged = base64.urlsafe_b64encode(json.dumps(claims).encode()).rstrip(b"=").decode()
    return ".".join([header, forged, signature])


def check_helper():
    print("== helper, with tokens minted at Dex (alice: admins, staff / bob: staff)")
    alice, bob = mint("alice"), mint("bob")
    check("alice to an internal host", via_squid("alice", alice, ALLOWED), "200")
    check("alice outside the internal domain", via_squid("alice", alice, DENIED), "403")
    check(
        "bob, not in admins, to an internal host", via_squid("bob", bob, ALLOWED), "403"
    )
    check("alice with bob's token", via_squid("alice", bob, ALLOWED), "407")
    check(
        "bob's token edited to carry admins",
        via_squid("bob", with_groups(bob, ["admins"]), ALLOWED),
        "407",
    )
    check(
        "token for another audience",
        via_squid("alice", mint("alice", client="other-app"), ALLOWED),
        "407",
    )
    # After an answer with groups, so a helper that leaves the key out would
    # keep admins cached for alice.
    no_groups = mint("alice", scope="openid profile email")
    check(
        "alice without groups, after with",
        via_squid("alice", no_groups, ALLOWED),
        "403",
    )
    check(
        "heavy100 is verified (not in admins)",
        via_squid("heavy100", mint("heavy100"), ALLOWED),
        "403",
    )
    check(
        "heavy150 is over Squid's helper line",
        via_squid("heavy150", mint("heavy150"), ALLOWED),
        "407",
    )
    log = in_squid("cat", "/var/log/squid/access.log")
    check(
        "access.log names alice and her groups",
        bool(re.search(r" alice admins,staff$", log, re.M)),
        True,
    )


# --- relay -------------------------------------------------------------------


def start_relay():
    argv = shlex.split(RELAY_RUN.replace("\\\n", " "))
    in_tools("rm", "-f", RELAY_LOG)
    compose(
        "exec",
        "-d",
        "tools",
        "sh",
        "-c",
        f"echo $$ >{RELAY_PID}; exec {shlex.join(argv)} >{RELAY_LOG} 2>&1",
    )
    wait_for("the relay's login URL", lambda: bool(login_url()), True, timeout=20)


# By PID, not by name: the kernel cuts process names to 15 characters, so
# "proxy-relay-oidc" matches nothing in pkill -x.
def stop_relay():
    in_tools("sh", "-c", f"kill $(cat {RELAY_PID})")
    wait_for(
        "the relay to stop",
        lambda: in_tools(
            "sh", "-c", f"kill -0 $(cat {RELAY_PID}) 2>/dev/null || echo gone"
        ).strip(),
        "gone",
    )


def relay_log():
    return in_tools("cat", RELAY_LOG)


def login_url():
    found = re.search(r'msg="log in to continue" url="([^"]*)"', relay_log())
    return found.group(1) if found else ""


def log_in(login):
    """Drive Dex's login form as a browser would, ending at the relay's callback."""
    jar = f"/tmp/jar-{login}"
    form = in_tools(
        "curl",
        "-s",
        "-c",
        jar,
        "-b",
        jar,
        "-L",
        "-o",
        "/dev/null",
        "-w",
        "%{url_effective}",
        login_url(),
    )
    return in_tools(
        "curl",
        "-s",
        "-c",
        jar,
        "-b",
        jar,
        "-L",
        "--data-urlencode",
        f"login={login}",
        "--data-urlencode",
        "password=password",
        form,
    )


def check_relay():
    print("== relay, started with its README's run command")
    start_relay()
    check("before login", via_relay(ALLOWED), "502")
    check(
        "the 502 names the login URL",
        "dex.example.com/dex/auth" in body("--proxy", RELAY, ALLOWED),
        True,
    )
    check(
        "login through Dex's form",
        log_in("alice").strip(),
        "Logged in as alice. You can close this tab.",
    )
    check("HTTP to an internal host", via_relay(ALLOWED), "200")
    check("HTTP outside the internal domain", via_relay(DENIED), "403")
    check("CONNECT to an internal host", via_relay("-p", ALLOWED), "200")
    check(
        "client's own proxy credentials replaced",
        via_relay("--proxy-user", "mallory:x", ALLOWED),
        "200",
    )
    check(
        "plain-HTTP upgrade",
        via_relay("-H", "Connection: Upgrade", "-H", "Upgrade: websocket", ALLOWED),
        "502",
    )

    print(f"   using it for {TOKEN_LIFETIME_RUN}s, past the 2m token lifetime")
    answers = set()
    deadline = time.monotonic() + TOKEN_LIFETIME_RUN
    while time.monotonic() < deadline:
        answers.add(("HTTP", via_relay(ALLOWED)))
        answers.add(("CONNECT", via_relay("-p", ALLOWED)))
        time.sleep(15)
    check(
        "every answer past the token lifetime",
        sorted(answers),
        [("CONNECT", "200"), ("HTTP", "200")],
    )
    # One from the login, then one refresh per minute.
    check(
        "refreshed at least twice", relay_log().count('msg="token stored"') >= 3, True
    )
    stop_relay()


def check_relay_refuses_oversized_token():
    print("== relay, logged in as heavy150")
    start_relay()
    log_in("heavy150")
    check("oversized token is not sent", via_relay(ALLOWED), "502")
    check(
        "the 502 names the limit",
        "over the 8000" in body("--proxy", RELAY, ALLOWED),
        True,
    )
    stop_relay()


# --- certificate reload ------------------------------------------------------


# A refused or reset handshake reads as no certificate yet, not a failure:
# Squid reopens its listening socket while it reconfigures.
def served_fingerprint():
    try:
        pem = ssl.get_server_certificate(SQUID_PUBLISHED)
    except OSError:
        return ""
    return hashlib.sha256(ssl.PEM_cert_to_DER_cert(pem)).hexdigest()


def file_fingerprint(path):
    return hashlib.sha256(
        ssl.PEM_cert_to_DER_cert((LAB / path).read_text())
    ).hexdigest()


def check_certificate_reload():
    print(
        "== certificate reload: reissue Squid's certificate, then squid -k reconfigure"
    )
    before = served_fingerprint()
    run("bin/ephemeral-ca", "-out", "certs", "-server", "squid.example.com")
    reissued = file_fingerprint("certs/server/squid.example.com.crt")
    in_squid("squid-gnutls", "-k", "reconfigure")
    wait_for(
        "Squid to serve the new certificate", served_fingerprint, reissued, timeout=20
    )
    check("new certificate served without a restart", reissued != before, True)
    check(
        "requests pass after the reload",
        via_squid("alice", mint("alice"), ALLOWED),
        "200",
    )


if __name__ == "__main__":
    main()
