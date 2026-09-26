"""ADR-0025 -- behavioral verification of the production proxy's route
ownership and provider-cookie boundary, for both identity deployment
profiles (deploy/caddy/identity-profile-{fresh,existing}.caddyfile).

The real ./Caddyfile and profile files are adapted by a real Caddy binary;
only the deployment-specific *endpoints* are swapped for local test doubles
(listener address, upstream dial addresses, the identity CA file path, and
Caddy's own ACME automation, which cannot run here). Routing, header and
cookie handling, and upstream TLS verification are the unmodified adapted
configuration. Each upstream double answers with its own name plus the
request it received, so assertions are about which service actually served
a request and what it actually saw -- not about configuration text.

Requires a Caddy binary of the version docker-compose.prod.yml pins
(`SAAS_OS_CADDY_BIN`, or `caddy` on PATH) and the `openssl` CLI; skipped,
not failed, when either is unavailable -- the same posture as this
directory's other Docker/tooling-dependent checks.
"""

from __future__ import annotations

import http.client
import json
import os
import shutil
import socket
import ssl
import subprocess
import threading
import time
from collections.abc import Iterator
from dataclasses import dataclass
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[2]
PINNED_CADDY_VERSION = "v2.11.4"
PROFILE_IMPORT_DIR = "/etc/caddy/identity-profiles"
IDENTITY_CA_PATH = "/identity-ca/tls.crt"

PUBLIC = "app.test.invalid"
IDENTITY = "id.test.invalid"

# ZITADEL v4.19.0 and Login V2 cookies (see ./Caddyfile's
# `strip_provider_cookies`) plus SaaS-OS's own session cookies.
PROVIDER_COOKIES = [
    ("__Host-zitadel.useragent", "ua"),
    ("__Host-zitadel.login.csrf", "csrf"),
    ("zitadel.login.lang", "en"),
    ("__Secure-zitadel.quota.exhausted", "q"),
    ("sessions", "s"),
    ("fingerprintId", "f"),
    ("verificationCheck", "v"),
    ("NEXT_LOCALE", "de"),
]
SAAS_COOKIES = [("saas_os_session", "abc"), ("saas_os_session_login", "def")]


def _caddy_binary() -> str | None:
    candidate = os.environ.get("SAAS_OS_CADDY_BIN") or shutil.which("caddy")
    if not candidate:
        return None
    try:
        version = subprocess.run(
            [candidate, "version"], capture_output=True, text=True, timeout=10
        ).stdout
    except OSError:
        return None
    return candidate if version.startswith(PINNED_CADDY_VERSION + " ") else None


CADDY = _caddy_binary()


def _caddy() -> str:
    """CADDY narrowed for callers that only run when the module is not skipped."""
    assert CADDY is not None
    return CADDY


pytestmark = pytest.mark.skipif(
    CADDY is None or shutil.which("openssl") is None,
    reason=f"Caddy {PINNED_CADDY_VERSION} (SAAS_OS_CADDY_BIN or PATH) and openssl required",
)


def _free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def _self_signed(tmp: Path, name: str, cn: str) -> tuple[Path, Path]:
    cert, key = tmp / f"{name}.crt", tmp / f"{name}.key"
    subprocess.run(
        [
            "openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "1",
            "-keyout", str(key), "-out", str(cert),
            "-subj", f"/CN={cn}", "-addext", f"subjectAltName=DNS:{cn}",
        ],
        check=True,
        capture_output=True,
    )  # fmt: skip
    return cert, key


class _Upstream(BaseHTTPRequestHandler):
    upstream_name = "?"

    def _reply(self) -> None:
        self.server.seen.append(self.path)  # type: ignore[attr-defined]
        body = json.dumps(
            {
                "upstream": self.upstream_name,
                "path": self.path,
                "host": self.headers.get("Host"),
                "cookie": self.headers.get_all("Cookie") or [],
                "headers": {k.lower(): v for k, v in self.headers.items()},
            }
        ).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    do_GET = do_POST = _reply

    def log_message(self, *args: object) -> None:
        pass


class _RecordingServer(ThreadingHTTPServer):
    """An upstream double that records every request path it served."""

    seen: list[str]


def _serve(name: str, context: ssl.SSLContext | None = None) -> tuple[_RecordingServer, int]:
    handler = type(f"Upstream_{name}", (_Upstream,), {"upstream_name": name})
    server = _RecordingServer(("127.0.0.1", 0), handler)
    server.seen = []
    if context is not None:
        server.socket = context.wrap_socket(server.socket, server_side=True)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    return server, server.server_address[1]


def _adapt(profile: str, identity_domain: str, tmp: Path) -> dict:
    """Adapt the REAL ./Caddyfile + profile file. The one textual change is
    the profile import directory, which Compose bind-mounts at
    /etc/caddy/identity-profiles (asserted by the topology test)."""
    caddyfile = (REPO_ROOT / "Caddyfile").read_text()
    assert caddyfile.count(PROFILE_IMPORT_DIR) == 1
    local = tmp / "Caddyfile"
    local.write_text(caddyfile.replace(PROFILE_IMPORT_DIR, str(REPO_ROOT / "deploy" / "caddy")))
    env = {
        **os.environ,
        "IDENTITY_PROFILE": profile,
        "PUBLIC_DOMAIN": PUBLIC,
        "IDENTITY_PUBLIC_DOMAIN": identity_domain,
    }
    result = subprocess.run(
        [_caddy(), "adapt", "--config", str(local), "--adapter", "caddyfile"],
        env=env,
        capture_output=True,
        text=True,
        timeout=30,
        check=False,
    )
    assert result.returncode == 0, result.stderr
    return json.loads(result.stdout)


@dataclass
class Proxy:
    port: int
    seen: dict[str, list[str]]

    def request(
        self,
        host: str,
        path: str,
        cookie: str | list[str] | None = None,
        headers: dict | None = None,
    ) -> tuple[int, dict | None]:
        """`cookie` as a list sends one `Cookie` header field per item."""
        conn = http.client.HTTPConnection("127.0.0.1", self.port, timeout=10)
        conn.putrequest("GET", path, skip_host=True, skip_accept_encoding=True)
        for name, value in {"Host": host, **(headers or {})}.items():
            conn.putheader(name, value)
        for value in [cookie] if isinstance(cookie, str) else cookie or []:
            conn.putheader("Cookie", value)
        conn.endheaders()
        response = conn.getresponse()
        raw = response.read()
        conn.close()
        try:
            return response.status, json.loads(raw)
        except ValueError:
            return response.status, None

    def body(
        self,
        host: str,
        path: str,
        cookie: str | list[str] | None = None,
        headers: dict | None = None,
    ) -> dict:
        """The upstream double's JSON reply; fails if the proxy answered itself."""
        status, parsed = self.request(host, path, cookie=cookie, headers=headers)
        assert parsed is not None, (status, host, path)
        return parsed


def _start(
    profile: str,
    identity_domain: str,
    tmp: Path,
    *,
    trusted_ca: Path | None = None,
) -> Iterator[Proxy]:
    zitadel_cert, zitadel_key = _self_signed(tmp, "zitadel", identity_domain)
    tls = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    tls.load_cert_chain(zitadel_cert, zitadel_key)
    servers = {
        "zitadel:443": _serve("zitadel", tls),
        "zitadel-login:3000": _serve("zitadel-login"),
        "backend:8000": _serve("backend"),
        "frontend:3000": _serve("frontend"),
    }
    config = _adapt(profile, identity_domain, tmp)
    port = _free_port()
    text = json.dumps(config)
    for dial, (_, upstream_port) in servers.items():
        text = text.replace(f'"dial": "{dial}"', f'"dial": "127.0.0.1:{upstream_port}"')
    text = text.replace(json.dumps(IDENTITY_CA_PATH), json.dumps(str(trusted_ca or zitadel_cert)))
    config = json.loads(text)
    # Test-harness endpoints only: plain-HTTP loopback listener, no ACME,
    # no redirect server, private storage, no admin endpoint.
    http_app = config["apps"]["http"]
    main = next(s for s in http_app["servers"].values() if ":443" in s["listen"])
    main["listen"] = [f"127.0.0.1:{port}"]
    main.pop("tls_connection_policies", None)
    main["automatic_https"] = {"disable": True}
    http_app["servers"] = {"main": main}
    config.pop("apps", {}).pop("tls", None)
    config["apps"] = {"http": http_app}
    config["admin"] = {"disabled": True}
    config["storage"] = {"module": "file_system", "root": str(tmp / "caddy-storage")}
    (tmp / "caddy.json").write_text(json.dumps(config))

    process = subprocess.Popen(
        [_caddy(), "run", "--config", str(tmp / "caddy.json")],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.PIPE,
        env={
            **os.environ,
            "HOME": str(tmp),
            "XDG_DATA_HOME": str(tmp),
            "XDG_CONFIG_HOME": str(tmp),
        },
    )
    try:
        deadline = time.monotonic() + 15
        while True:
            try:
                socket.create_connection(("127.0.0.1", port), timeout=0.5).close()
                break
            except OSError:
                assert process.poll() is None, (
                    process.stderr.read().decode() if process.stderr else ""
                )
                assert time.monotonic() < deadline, "caddy did not start"
                time.sleep(0.1)
        yield Proxy(port, {dial.split(":")[0]: srv.seen for dial, (srv, _) in servers.items()})
    finally:
        process.terminate()
        process.wait(timeout=10)
        for server, _ in servers.values():
            server.shutdown()


@pytest.fixture(scope="module")
def fresh(tmp_path_factory: pytest.TempPathFactory) -> Iterator[Proxy]:
    yield from _start("fresh", PUBLIC, tmp_path_factory.mktemp("fresh"))


@pytest.fixture(scope="module")
def existing(tmp_path_factory: pytest.TempPathFactory) -> Iterator[Proxy]:
    yield from _start("existing", IDENTITY, tmp_path_factory.mktemp("existing"))


def _cookie_header(pairs: list[tuple[str, str]]) -> str:
    return "; ".join(f"{k}={v}" for k, v in pairs)


# --- fresh profile (Topology A): route ownership on PUBLIC_DOMAIN -----------

ZITADEL_PATHS = [
    "/auth/v1/users/me",
    "/v2/users",
    "/v2beta/sessions",
    "/zitadel.session.v2.SessionService/CreateSession",
    "/zitadel.admin.v1.AdminService/Healthz",
    "/admin/v1/orgs",
    "/management/v1/orgs/me",
    "/system/v1/instances",
    "/assets/v1/org/policy/label/logo",
    "/oidc/v1/userinfo",
    "/saml/v2/metadata",
    "/oauth/v2/authorize?client_id=x",
    "/oauth/v2/token",
    "/oauth/v2/keys",
    "/device",
    "/device/login",
    "/.well-known/openid-configuration",
    "/.well-known/apple-app-site-association",
    "/.well-known/assetlinks.json",
    "/openapi/v2/swagger",
    "/idps/callback",
    "/idps/callback/x",
    "/ui/console",
    "/ui/console/users",
    "/ui/login",
    "/ui/login/login",
]
BACKEND_PATHS = [
    "/auth/login",
    "/auth/callback?code=c&state=s",
    "/auth/logout",
    "/auth/me",
    "/v1/x",
]
LOGIN_V2_PATHS = ["/ui/v2/login", "/ui/v2/login/loginname", "/ui/v2/login/_next/static/x.js"]
FRONTEND_PATHS = ["/", "/dashboard", "/healthz", "/readyz", "/ui/v2/loginx", "/v2", "/auth"]


@pytest.mark.parametrize("path", ZITADEL_PATHS)
def test_fresh_zitadel_routes_reach_zitadel(fresh: Proxy, path: str) -> None:
    status, body = fresh.request(PUBLIC, path)
    assert status == 200 and body is not None
    assert body["upstream"] == "zitadel"
    assert body["path"] == path
    # ZITADEL resolves its instance from the forwarded public Host.
    assert body["host"] == PUBLIC


def test_fresh_auth_v1_is_zitadel_but_saas_auth_is_backend(fresh: Proxy) -> None:
    """The one prefix both own: ZITADEL's /auth/v1/* wins over SaaS-OS
    /auth/*, without taking any SaaS-OS /auth route."""
    assert fresh.body(PUBLIC, "/auth/v1/users/me")["upstream"] == "zitadel"
    assert fresh.body(PUBLIC, "/auth/v1")["upstream"] == "backend"
    for path in ("/auth/login", "/auth/callback", "/auth/logout", "/auth/me"):
        assert fresh.body(PUBLIC, path)["upstream"] == "backend", path


@pytest.mark.parametrize("path", BACKEND_PATHS)
def test_fresh_saas_os_api_routes_reach_backend(fresh: Proxy, path: str) -> None:
    status, body = fresh.request(PUBLIC, path)
    assert body is not None, (status, path)
    assert status == 200 and body["upstream"] == "backend" and body["path"] == path


@pytest.mark.parametrize("path", LOGIN_V2_PATHS)
def test_fresh_login_v2_routes_reach_login_v2(fresh: Proxy, path: str) -> None:
    status, body = fresh.request(PUBLIC, path)
    assert body is not None, (status, path)
    assert status == 200 and body["upstream"] == "zitadel-login" and body["path"] == path
    assert body["host"] == PUBLIC


@pytest.mark.parametrize("path", FRONTEND_PATHS)
def test_fresh_everything_else_reaches_the_frontend(fresh: Proxy, path: str) -> None:
    status, body = fresh.request(PUBLIC, path)
    assert body is not None, (status, path)
    assert status == 200 and body["upstream"] == "frontend"


@pytest.mark.parametrize("path", ["/debug/ready", "/debug/healthz", "/debug/metrics", "/debug"])
def test_fresh_debug_is_not_exposed(fresh: Proxy, path: str) -> None:
    """ZITADEL's undocumented /debug/* never reaches ZITADEL via the public
    site (it falls through to the frontend's ordinary 404)."""
    status, body = fresh.request(PUBLIC, path)
    assert body is not None and body["upstream"] == "frontend"


def test_fresh_has_no_separate_identity_site(fresh: Proxy) -> None:
    status, body = fresh.request(IDENTITY, "/.well-known/openid-configuration")
    assert body is None or body.get("upstream") != "zitadel"


def test_fresh_strips_provider_cookies_from_saas_os_upstreams(fresh: Proxy) -> None:
    cases = [
        # interleaved, provider first, provider last, provider only
        SAAS_COOKIES[:1] + PROVIDER_COOKIES + SAAS_COOKIES[1:],
        PROVIDER_COOKIES + SAAS_COOKIES,
        SAAS_COOKIES + PROVIDER_COOKIES,
    ]
    for pairs in cases:
        for path in ("/auth/me", "/v1/x", "/", "/healthz"):
            body = fresh.body(PUBLIC, path, cookie=_cookie_header(pairs))
            assert body["upstream"] in ("backend", "frontend")
            assert body["cookie"] == [_cookie_header(SAAS_COOKIES)], (path, body["cookie"])


# The exact provider cookies the live fresh-profile login left in the browser.
LIVE_PROVIDER_COOKIES = [
    ("__Host-zitadel.useragent", "ua"),
    ("fingerprintId", "f"),
    ("sessions", "s"),
]


@pytest.mark.parametrize(
    "path", ["/auth/me", "/auth/callback?code=c&state=s", "/v1/x", "/", "/healthz"]
)
@pytest.mark.parametrize("provider", [LIVE_PROVIDER_COOKIES, PROVIDER_COOKIES])
def test_fresh_provider_only_cookie_header_is_removed_entirely(
    fresh: Proxy, path: str, provider: list[tuple[str, str]]
) -> None:
    """A request carrying ONLY provider cookies reaches SaaS-OS with no
    `Cookie` header at all -- not an empty one."""
    body = fresh.body(PUBLIC, path, cookie=_cookie_header(provider))
    assert body["upstream"] in ("backend", "frontend")
    assert body["cookie"] == []
    assert "cookie" not in body["headers"]


def test_fresh_saas_os_cookies_survive_alongside_provider_only_fields(fresh: Proxy) -> None:
    """With several `Cookie` header fields, one emptied by the filter must not
    cause the SaaS-OS cookies in another field to be dropped."""
    fields = [_cookie_header(LIVE_PROVIDER_COOKIES), _cookie_header(SAAS_COOKIES)]
    body = fresh.body(PUBLIC, "/auth/me", cookie=fields)
    assert _cookie_header(SAAS_COOKIES) in body["cookie"]
    assert not any(name in "".join(body["cookie"]) for name, _ in LIVE_PROVIDER_COOKIES)


def test_fresh_request_without_cookies_stays_without_cookies(fresh: Proxy) -> None:
    body = fresh.body(PUBLIC, "/auth/me")
    assert body["cookie"] == [] and "cookie" not in body["headers"]


def test_fresh_saas_os_only_cookies_pass_unchanged(fresh: Proxy) -> None:
    cookie = _cookie_header(SAAS_COOKIES)
    for path in ("/auth/me", "/auth/login", "/auth/callback", "/auth/logout", "/v1/x", "/"):
        assert fresh.body(PUBLIC, path, cookie=cookie)["cookie"] == [cookie], path


def test_fresh_cookie_stripping_is_exact_by_name(fresh: Proxy) -> None:
    """Similar-looking SaaS-OS/application cookie names are not stripped."""
    keep = [("mysessions", "1"), ("sessions_x", "2"), ("xzitadel.a", "3"), ("NEXT_LOCALE2", "4")]
    body = fresh.body(PUBLIC, "/auth/me", cookie=_cookie_header(keep + [("sessions", "s")]))
    assert body["cookie"] == [_cookie_header(keep)]


@pytest.mark.parametrize("path", ["/ui/v2/login/loginname", "/oauth/v2/authorize", "/auth/v1/x"])
def test_fresh_provider_routes_keep_all_cookies(fresh: Proxy, path: str) -> None:
    cookie = _cookie_header(SAAS_COOKIES + PROVIDER_COOKIES)
    body = fresh.body(PUBLIC, path, cookie=cookie)
    assert body["upstream"] in ("zitadel", "zitadel-login")
    assert body["cookie"] == [cookie]


@pytest.mark.parametrize("path", ["/ui/v2/login/loginname", "/oauth/v2/authorize"])
def test_fresh_client_cannot_choose_zitadel_host(fresh: Proxy, path: str) -> None:
    spoof = {
        "X-Zitadel-Instance-Host": "evil.test.invalid",
        "X-Zitadel-Public-Host": "evil.test.invalid",
        "X-Zitadel-Forward-Host": "evil.test.invalid",
    }
    body = fresh.body(PUBLIC, path, headers=spoof)
    assert not {h.lower() for h in spoof} & set(body["headers"])
    assert body["host"] == PUBLIC


def test_fresh_zitadel_upstream_tls_is_verified(tmp_path: Path) -> None:
    """The fresh profile verifies ZITADEL's certificate: trusting a
    different certificate than the one ZITADEL serves makes Caddy refuse
    the upstream instead of connecting anyway."""
    other_cert, _ = _self_signed(tmp_path, "other", PUBLIC)
    for proxy in _start("fresh", PUBLIC, tmp_path, trusted_ca=other_cert):
        status, body = proxy.request(PUBLIC, "/.well-known/openid-configuration")
        # 502 (handshake refused) or 503 (already marked unhealthy by the
        # equally-verified active health check) -- never a response.
        assert status in (502, 503) and body is None
        assert proxy.seen["zitadel"] == []
        assert proxy.body(PUBLIC, "/auth/me")["upstream"] == "backend"


# --- existing profile: unchanged SaaS-OS routing + identity domain -----------


@pytest.mark.parametrize(
    ("path", "upstream"),
    [
        ("/auth/login", "backend"),
        ("/auth/callback", "backend"),
        ("/auth/me", "backend"),
        ("/auth/v1/users/me", "backend"),  # no ZITADEL on PUBLIC_DOMAIN in this profile
        ("/v1/x", "backend"),
        ("/", "frontend"),
        ("/healthz", "frontend"),
        ("/ui/v2/login", "frontend"),
        ("/oauth/v2/authorize", "frontend"),
        ("/.well-known/openid-configuration", "frontend"),
    ],
)
def test_existing_public_domain_routing_is_unchanged(
    existing: Proxy, path: str, upstream: str
) -> None:
    assert existing.body(PUBLIC, path)["upstream"] == upstream


@pytest.mark.parametrize(
    ("path", "upstream"),
    [
        ("/.well-known/openid-configuration", "zitadel"),
        ("/oauth/v2/authorize", "zitadel"),
        ("/auth/v1/users/me", "zitadel"),
        ("/ui/login/login", "zitadel"),
        ("/ui/console", "zitadel"),
        ("/ui/v2/login", "zitadel-login"),
        ("/ui/v2/login/loginname", "zitadel-login"),
    ],
)
def test_existing_identity_domain_serves_zitadel_and_login_v2(
    existing: Proxy, path: str, upstream: str
) -> None:
    body = existing.body(IDENTITY, path)
    assert body["upstream"] == upstream
    assert body["host"] == IDENTITY


@pytest.mark.parametrize("path", ["/ui/v2/login/password", "/oauth/v2/authorize"])
def test_existing_identity_domain_keeps_provider_cookies(existing: Proxy, path: str) -> None:
    cookie = _cookie_header(PROVIDER_COOKIES)
    body = existing.body(IDENTITY, path, cookie=cookie)
    assert body["upstream"] in ("zitadel", "zitadel-login")
    assert body["cookie"] == [cookie]


def test_existing_saas_os_cookies_pass_unchanged(existing: Proxy) -> None:
    """Existing profile: provider cookies are host-only on the identity
    domain, so the PUBLIC_DOMAIN site forwards Cookie exactly as before."""
    cookie = _cookie_header(SAAS_COOKIES)
    assert existing.body(PUBLIC, "/auth/me", cookie=cookie)["cookie"] == [cookie]
