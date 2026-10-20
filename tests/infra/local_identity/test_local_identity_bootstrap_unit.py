"""`saas-os-local-identity` (saas_os/infra/local_identity/zitadel_bootstrap.py) --
configuration and idempotency, against an in-memory fake of the three
ZITADEL Management API calls it makes. No real ZITADEL needed; the live
stack is exercised by `docker compose up` (docs/LOCAL-IDENTITY.md).
"""

from __future__ import annotations

import json
from pathlib import Path

import httpx
import pytest

from saas_os.infra.local_identity import zitadel_bootstrap as zb

REPO_ROOT = Path(__file__).resolve().parents[3]


class FakeZitadel:
    """Just enough of ZITADEL's Management API: one org, list/create of
    projects and applications. Records every create call."""

    def __init__(self) -> None:
        self.projects: list[dict] = []
        self.applications: list[dict] = []
        self.create_requests: list[tuple[str, dict]] = []
        self.update_requests: list[dict] = []
        self.auth_headers: set[str] = set()
        self.list_requests: list[tuple[str, dict]] = []

    @staticmethod
    def _page(items_key: str, items: list[dict], body: dict) -> httpx.Response:
        """ZITADEL v4.19.5 list semantics (advisory A10018): `limit` defaults
        to 100, more than 1000 is an error, and the response carries the
        total as a uint64 JSON string."""
        pagination = body.get("pagination") or {}
        offset = int(pagination.get("offset", 0))
        limit = int(pagination.get("limit") or 100)
        if limit > 1000:
            return httpx.Response(400, json={"message": "Limit exceeded"})
        return httpx.Response(
            200,
            json={
                items_key: items[offset : offset + limit],
                "pagination": {"totalResult": str(len(items)), "appliedLimit": str(limit)},
            },
        )

    def handle(self, request: httpx.Request) -> httpx.Response:
        self.auth_headers.add(request.headers.get("Authorization", ""))
        path = request.url.path
        body = json.loads(request.content) if request.content else {}
        if path == "/management/v1/orgs/me":
            return httpx.Response(200, json={"org": {"id": "org-1"}})
        if path.endswith("/ListProjects"):
            self.list_requests.append(("projects", body))
            return self._page("projects", list(self.projects), body)
        if path.endswith("/CreateProject"):
            self.create_requests.append(("project", body))
            project = {"projectId": f"proj-{len(self.projects) + 1}", "name": body["name"]}
            self.projects.append(project)
            return httpx.Response(200, json={"projectId": project["projectId"]})
        if path.endswith("/ListApplications"):
            project_id = body["filters"][0]["projectIdFilter"]["projectId"]
            apps = [a for a in self.applications if a["projectId"] == project_id]
            self.list_requests.append(("applications", body))
            return self._page("applications", apps, body)
        if path.endswith("/CreateApplication"):
            self.create_requests.append(("application", body))
            client_id = f"client-{len(self.applications) + 1}"
            self.applications.append(
                {
                    "applicationId": f"app-{len(self.applications) + 1}",
                    "projectId": body["projectId"],
                    "name": body["name"],
                    "oidcConfiguration": {
                        "clockSkew": "0s",
                        **body["oidcConfiguration"],
                        "clientId": client_id,
                    },
                }
            )
            return httpx.Response(200, json={"oidcConfiguration": {"clientId": client_id}})
        if path.endswith("/UpdateApplication"):
            # ZITADEL v4.19.0-v4.19.5 semantics (convert/oidc_app.go): omitted fields
            # are unchanged, EXCEPT empty response/grant types (reset to their
            # defaults) and an omitted clock skew (reset to zero).
            self.update_requests.append(body)
            app = next(a for a in self.applications if a["applicationId"] == body["applicationId"])
            update = body["oidcConfiguration"]
            oidc = app["oidcConfiguration"]
            oidc.update(update)
            if "responseTypes" not in update:
                oidc["responseTypes"] = ["OIDC_RESPONSE_TYPE_CODE"]
            if "grantTypes" not in update:
                oidc["grantTypes"] = ["OIDC_GRANT_TYPE_AUTHORIZATION_CODE"]
            if "clockSkew" not in update:
                oidc["clockSkew"] = "0s"
            return httpx.Response(200, json={})
        return httpx.Response(404)

    def transport(self) -> httpx.MockTransport:
        return httpx.MockTransport(self.handle)


@pytest.fixture
def pat_file(tmp_path: Path) -> Path:
    path = tmp_path / "bootstrap.pat"
    path.write_text("test-pat\n", encoding="utf-8")
    return path


def test_defaults_preserve_saas_os_names() -> None:
    config = zb.load_config([], {"ZITADEL_INTERNAL_URL": "http://zitadel.localhost:8081"})
    assert config.project_name == "saas-os"
    assert config.application_name == "saas-os-backend"
    assert config.pat_path == "/bootstrap/bootstrap.pat"
    assert config.redirect_uri == "http://localhost:8000/auth/callback"


def test_empty_values_fall_back_to_defaults() -> None:
    # docker-compose.yml passes `${OIDC_LOCAL_PROJECT_NAME:-}` through.
    config = zb.load_config(
        [],
        {
            "ZITADEL_INTERNAL_URL": "http://z",
            "OIDC_LOCAL_PROJECT_NAME": "",
            "OIDC_LOCAL_APPLICATION_NAME": "  ",
        },
    )
    assert (config.project_name, config.application_name) == ("saas-os", "saas-os-backend")


def test_consumer_names_and_redirect_uri_come_from_configuration() -> None:
    env = {
        "ZITADEL_INTERNAL_URL": "http://zitadel.localhost:8081",
        "OIDC_LOCAL_PROJECT_NAME": "example-product",
        "OIDC_LOCAL_APPLICATION_NAME": "example-product-backend",
        "OIDC_REDIRECT_URI": "http://localhost:9000/auth/callback",
        "ZITADEL_BOOTSTRAP_PAT_PATH": "/elsewhere/pat",
    }
    config = zb.load_config([], env)
    assert config == zb.BootstrapConfig(
        zitadel_url="http://zitadel.localhost:8081",
        redirect_uri="http://localhost:9000/auth/callback",
        project_name="example-product",
        application_name="example-product-backend",
        pat_path="/elsewhere/pat",
    )


def test_cli_flags_take_precedence_over_environment() -> None:
    config = zb.load_config(
        ["--project-name", "flag-project", "--redirect-uri", "http://flag/cb"],
        {"ZITADEL_INTERNAL_URL": "http://z", "OIDC_LOCAL_PROJECT_NAME": "env-project"},
    )
    assert config.project_name == "flag-project"
    assert config.redirect_uri == "http://flag/cb"


def test_missing_zitadel_url_fails_loudly() -> None:
    # SystemExit, not a return code: the production wrapper ignores main()'s
    # return value, so a silent "exit 0" would hide the failure.
    with pytest.raises(SystemExit) as excinfo:
        zb.load_config([], {})
    assert excinfo.value.code != 0


def test_application_is_a_public_pkce_client() -> None:
    body = zb.application_request("proj-1", "app", "http://localhost:8000/auth/callback")
    oidc = body["oidcConfiguration"]
    assert oidc["authMethodType"] == "OIDC_AUTH_METHOD_TYPE_NONE"
    assert oidc["grantTypes"] == ["OIDC_GRANT_TYPE_AUTHORIZATION_CODE"]
    assert oidc["responseTypes"] == ["OIDC_RESPONSE_TYPE_CODE"]
    assert oidc["redirectUris"] == ["http://localhost:8000/auth/callback"]
    assert "clientSecret" not in json.dumps(body)
    # ADR-0046: the email claims are in the ID token, which is all SaaS OS reads.
    assert oidc["idTokenUserinfoAssertion"] is True


def test_an_existing_application_without_the_email_claims_is_updated_once(
    pat_file: Path,
) -> None:
    """An application created before ADR-0046 gets `idTokenUserinfoAssertion`
    by one in-place update: same client id, every other setting preserved,
    and no further update once it is set."""
    fake = FakeZitadel()
    config = zb.BootstrapConfig(zitadel_url="http://z", pat_path=str(pat_file))
    client_id = zb.bootstrap(config, transport=fake.transport())
    oidc = fake.applications[0]["oidcConfiguration"]
    del oidc["idTokenUserinfoAssertion"]
    oidc["clockSkew"] = "2s"
    oidc["loginVersion"] = {"loginV1": {}}
    before = json.loads(json.dumps(oidc))

    assert zb.bootstrap(config, transport=fake.transport()) == client_id
    assert zb.bootstrap(config, transport=fake.transport()) == client_id

    (update,) = fake.update_requests
    assert update["oidcConfiguration"]["idTokenUserinfoAssertion"] is True
    assert "loginVersion" not in update["oidcConfiguration"]  # unchanged
    after = fake.applications[0]["oidcConfiguration"]
    assert after.pop("idTokenUserinfoAssertion") is True
    assert after == before


def test_bootstrap_uses_configured_names_and_redirect_uri(pat_file: Path) -> None:
    fake = FakeZitadel()
    config = zb.BootstrapConfig(
        zitadel_url="http://zitadel.localhost:8081",
        redirect_uri="http://localhost:9000/auth/callback",
        project_name="example-product",
        application_name="example-product-backend",
        pat_path=str(pat_file),
    )
    client_id = zb.bootstrap(config, transport=fake.transport())

    assert client_id == "client-1"
    assert fake.auth_headers == {"Bearer test-pat"}
    (_, project_req), (_, app_req) = fake.create_requests
    assert project_req == {"organizationId": "org-1", "name": "example-product"}
    assert app_req["name"] == "example-product-backend"
    assert app_req["oidcConfiguration"]["redirectUris"] == ["http://localhost:9000/auth/callback"]


def test_bootstrap_is_idempotent(pat_file: Path) -> None:
    fake = FakeZitadel()
    config = zb.BootstrapConfig(zitadel_url="http://z", pat_path=str(pat_file))

    first = zb.bootstrap(config, transport=fake.transport())
    second = zb.bootstrap(config, transport=fake.transport())

    assert first == second
    assert len(fake.projects) == 1
    assert len(fake.applications) == 1
    assert [kind for kind, _ in fake.create_requests] == ["project", "application"]
    assert fake.projects[0]["name"] == "saas-os"
    assert fake.applications[0]["name"] == "saas-os-backend"


def test_two_consumers_share_an_instance_without_colliding(pat_file: Path) -> None:
    fake = FakeZitadel()
    a = zb.BootstrapConfig(zitadel_url="http://z", pat_path=str(pat_file))
    b = zb.BootstrapConfig(
        zitadel_url="http://z",
        pat_path=str(pat_file),
        project_name="other",
        application_name="other-backend",
    )
    assert zb.bootstrap(a, transport=fake.transport()) != zb.bootstrap(
        b, transport=fake.transport()
    )
    assert sorted(p["name"] for p in fake.projects) == ["other", "saas-os"]


def test_no_product_specific_name_is_hardcoded() -> None:
    """ADR-0015 rule 5: the reusable tooling stays product-neutral."""
    files = [
        REPO_ROOT / "saas_os" / "infra" / "local_identity" / "__init__.py",
        REPO_ROOT / "saas_os" / "infra" / "local_identity" / "zitadel_bootstrap.py",
        REPO_ROOT / "local-dev" / "bootstrap_zitadel.py",
    ]
    for path in files:
        text = path.read_text(encoding="utf-8").lower()
        assert "marketstack" not in text, path


def test_local_dev_entrypoint_delegates_to_the_packaged_implementation() -> None:
    """deploy/bootstrap_zitadel_production.py loads local-dev/bootstrap_zitadel.py
    by path and calls `main()` -- it must be the packaged one, not a copy."""
    import importlib.util

    spec = importlib.util.spec_from_file_location(
        "bootstrap_zitadel_shim", REPO_ROOT / "local-dev" / "bootstrap_zitadel.py"
    )
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    assert module.main is zb.main


def test_console_script_is_declared() -> None:
    import tomllib

    pyproject = tomllib.loads((REPO_ROOT / "pyproject.toml").read_text(encoding="utf-8"))
    scripts = pyproject["project"]["scripts"]
    assert (
        scripts["saas-os-local-identity"] == "saas_os.infra.local_identity.zitadel_bootstrap:main"
    )
    assert "saas_os.infra.local_identity" in pyproject["tool"]["setuptools"]["packages"]


# --- ADR-0025: per-application Login V2 base URI ------------------------------

LOGIN_V2 = "https://app.example.test/ui/v2/login"


def test_login_v2_base_uri_is_optional_and_configurable() -> None:
    assert zb.load_config([], {"ZITADEL_INTERNAL_URL": "http://z"}).login_v2_base_uri is None
    env = {"ZITADEL_INTERNAL_URL": "http://z", "ZITADEL_LOGIN_V2_BASE_URI": LOGIN_V2}
    assert zb.load_config([], env).login_v2_base_uri == LOGIN_V2
    flag = zb.load_config(["--login-v2-base-uri", "https://f/ui/v2/login"], env)
    assert flag.login_v2_base_uri == "https://f/ui/v2/login"


def test_new_application_is_created_with_login_v2(pat_file: Path) -> None:
    fake = FakeZitadel()
    config = zb.BootstrapConfig(
        zitadel_url="http://z", pat_path=str(pat_file), login_v2_base_uri=LOGIN_V2
    )
    zb.bootstrap(config, transport=fake.transport())
    (_, app_req) = fake.create_requests[1]
    assert app_req["oidcConfiguration"]["loginVersion"] == {"loginV2": {"baseUri": LOGIN_V2}}
    assert fake.update_requests == []


def test_without_a_base_uri_the_login_version_is_never_touched(pat_file: Path) -> None:
    fake = FakeZitadel()
    config = zb.BootstrapConfig(zitadel_url="http://z", pat_path=str(pat_file))
    zb.bootstrap(config, transport=fake.transport())
    assert "loginVersion" not in fake.create_requests[1][1]["oidcConfiguration"]
    fake.applications[0]["oidcConfiguration"]["loginVersion"] = {"loginV1": {}}
    zb.bootstrap(config, transport=fake.transport())
    assert fake.update_requests == []
    assert fake.applications[0]["oidcConfiguration"]["loginVersion"] == {"loginV1": {}}


def test_existing_application_is_updated_in_place_once(pat_file: Path) -> None:
    """An existing application (created before ADR-0025) gets Login V2 by an
    in-place update: no second application, same client id, every other
    OIDC setting preserved, and no further update once it matches."""
    fake = FakeZitadel()
    legacy = zb.BootstrapConfig(zitadel_url="http://z", pat_path=str(pat_file))
    client_id = zb.bootstrap(legacy, transport=fake.transport())
    oidc = fake.applications[0]["oidcConfiguration"]
    oidc["clockSkew"] = "2s"
    oidc["postLogoutRedirectUris"] = ["https://app.example.test/"]
    before = json.loads(json.dumps(oidc))

    upgraded = zb.BootstrapConfig(
        zitadel_url="http://z", pat_path=str(pat_file), login_v2_base_uri=LOGIN_V2
    )
    assert zb.bootstrap(upgraded, transport=fake.transport()) == client_id
    assert zb.bootstrap(upgraded, transport=fake.transport()) == client_id

    assert len(fake.applications) == 1
    assert len(fake.update_requests) == 1
    (update,) = fake.update_requests
    assert update["applicationId"] == "app-1"
    assert update["oidcConfiguration"]["loginVersion"] == {"loginV2": {"baseUri": LOGIN_V2}}
    after = fake.applications[0]["oidcConfiguration"]
    assert after.pop("loginVersion") == {"loginV2": {"baseUri": LOGIN_V2}}
    assert after == before


def test_changed_base_uri_updates_the_same_application(pat_file: Path) -> None:
    fake = FakeZitadel()
    for base_uri in (LOGIN_V2, "https://id.example.test/ui/v2/login"):
        config = zb.BootstrapConfig(
            zitadel_url="http://z", pat_path=str(pat_file), login_v2_base_uri=base_uri
        )
        zb.bootstrap(config, transport=fake.transport())
    assert len(fake.applications) == 1
    assert fake.applications[0]["oidcConfiguration"]["loginVersion"] == {
        "loginV2": {"baseUri": "https://id.example.test/ui/v2/login"}
    }


# --- deploy/bootstrap_zitadel_production.py: profile -> base URI ------------


def _production_wrapper():
    import importlib.util

    spec = importlib.util.spec_from_file_location(
        "bootstrap_zitadel_production", REPO_ROOT / "deploy" / "bootstrap_zitadel_production.py"
    )
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_fresh_profile_uses_login_v2_on_public_domain() -> None:
    env = {
        "IDENTITY_PROFILE": "fresh",
        "PUBLIC_DOMAIN": "app.example.test",
        "IDENTITY_PUBLIC_DOMAIN": "app.example.test",
    }
    assert _production_wrapper().login_v2_base_uri(env) == LOGIN_V2


@pytest.mark.parametrize("enabled", [None, "", "false", "FALSE"])
def test_existing_profile_leaves_login_version_alone_by_default(enabled: str | None) -> None:
    env = {"PUBLIC_DOMAIN": "app.example.test", "IDENTITY_PUBLIC_DOMAIN": "id.example.test"}
    if enabled is not None:
        env["ZITADEL_LOGIN_V2_ENABLED"] = enabled
    # Also the default when IDENTITY_PROFILE is unset (pre-ADR-0025 .env).
    assert _production_wrapper().login_v2_base_uri(env) is None
    assert _production_wrapper().login_v2_base_uri({**env, "IDENTITY_PROFILE": "existing"}) is None


def test_existing_profile_opt_in_keeps_the_identity_domain() -> None:
    env = {
        "IDENTITY_PROFILE": "existing",
        "PUBLIC_DOMAIN": "app.example.test",
        "IDENTITY_PUBLIC_DOMAIN": "id.example.test",
        "ZITADEL_LOGIN_V2_ENABLED": "true",
    }
    assert _production_wrapper().login_v2_base_uri(env) == "https://id.example.test/ui/v2/login"


@pytest.mark.parametrize(
    "env",
    [
        # fresh with a separate identity domain would be a second issuer
        {
            "IDENTITY_PROFILE": "fresh",
            "PUBLIC_DOMAIN": "a.test",
            "IDENTITY_PUBLIC_DOMAIN": "b.test",
        },
        # existing collapsed onto PUBLIC_DOMAIN would silently migrate issuer/RP ID
        {
            "IDENTITY_PROFILE": "existing",
            "PUBLIC_DOMAIN": "a.test",
            "IDENTITY_PUBLIC_DOMAIN": "a.test",
        },
        {
            "IDENTITY_PROFILE": "bogus",
            "PUBLIC_DOMAIN": "a.test",
            "IDENTITY_PUBLIC_DOMAIN": "b.test",
        },
        {"IDENTITY_PROFILE": "fresh", "PUBLIC_DOMAIN": "", "IDENTITY_PUBLIC_DOMAIN": ""},
        {
            "PUBLIC_DOMAIN": "a.test",
            "IDENTITY_PUBLIC_DOMAIN": "b.test",
            "ZITADEL_LOGIN_V2_ENABLED": "yes",
        },
    ],
)
def test_inconsistent_profiles_fail_closed(env: dict[str, str]) -> None:
    with pytest.raises(ValueError):
        _production_wrapper().login_v2_base_uri(env)


@pytest.mark.parametrize(
    ("content", "revoked"),
    [("", True), ("  \n", True), ("a-token", False), (None, False)],
)
def test_an_emptied_bootstrap_token_file_means_revoked(
    tmp_path: Path, content: str | None, revoked: bool
) -> None:
    """docs/RUNBOOKS.md, "Bootstrap token": after the token is revoked and its
    file emptied, the production wrapper skips cleanly instead of failing
    every routine `up -d`. A missing file is not revocation."""
    path = tmp_path / "bootstrap.pat"
    if content is not None:
        path.write_text(content, encoding="utf-8")
    wrapper = _production_wrapper()
    assert wrapper.bootstrap_token_revoked({"ZITADEL_BOOTSTRAP_PAT_PATH": str(path)}) is revoked


def test_the_production_wrapper_exits_cleanly_on_a_revoked_token(tmp_path: Path) -> None:
    import subprocess
    import sys

    path = tmp_path / "bootstrap.pat"
    path.write_text("", encoding="utf-8")
    env = {
        **__import__("os").environ,
        "ZITADEL_BOOTSTRAP_PAT_PATH": str(path),
        "IDENTITY_PROFILE": "existing",
        "ZITADEL_LOGIN_V2_ENABLED": "false",
    }
    result = subprocess.run(
        [sys.executable, str(REPO_ROOT / "deploy" / "bootstrap_zitadel_production.py")],
        env=env,
        capture_output=True,
        text=True,
        timeout=60,
    )
    assert result.returncode == 0, result.stderr
    assert "revoked" in result.stdout


# --- Pagination (ZITADEL v4.19.5 list limits, advisory A10018) --------------


def _seed_projects(fake: FakeZitadel, count: int) -> None:
    for i in range(count):
        fake.projects.append({"projectId": f"seed-{i}", "name": f"other-{i}"})


def _config(pat_file: Path) -> zb.BootstrapConfig:
    return zb.BootstrapConfig(zitadel_url="http://z", pat_path=str(pat_file))


def test_a_match_on_the_first_page_needs_one_request(pat_file: Path) -> None:
    fake = FakeZitadel()
    _seed_projects(fake, 3)
    fake.projects.append({"projectId": "existing", "name": "saas-os"})

    zb.bootstrap(_config(pat_file), transport=fake.transport())

    project_lists = [body for kind, body in fake.list_requests if kind == "projects"]
    assert len(project_lists) == 1
    assert [kind for kind, _ in fake.create_requests] == ["application"]
    assert fake.applications[0]["projectId"] == "existing"


def test_a_match_on_a_later_page_is_found_and_not_duplicated(pat_file: Path) -> None:
    """Without pagination the server's default limit of 100 hides this
    project and the bootstrap would create a second one."""
    fake = FakeZitadel()
    _seed_projects(fake, 250)
    fake.projects.insert(230, {"projectId": "existing", "name": "saas-os"})

    zb.bootstrap(_config(pat_file), transport=fake.transport())

    assert [kind for kind, _ in fake.create_requests] == ["application"]
    assert fake.applications[0]["projectId"] == "existing"


def test_requests_follow_the_offset_contract_and_keep_the_filters(pat_file: Path) -> None:
    fake = FakeZitadel()
    _seed_projects(fake, 250)

    zb.bootstrap(_config(pat_file), transport=fake.transport())

    project_lists = [body for kind, body in fake.list_requests if kind == "projects"]
    assert [b["pagination"] for b in project_lists] == [
        {"offset": 0, "limit": 100, "asc": True},
        {"offset": 100, "limit": 100, "asc": True},
        {"offset": 200, "limit": 100, "asc": True},
    ]
    assert all(
        b["filters"] == [{"organizationIdFilter": {"organizationId": "org-1"}}]
        for b in project_lists
    )
    (app_list,) = [body for kind, body in fake.list_requests if kind == "applications"]
    assert app_list["filters"] == [{"projectIdFilter": {"projectId": "proj-251"}}]
    assert app_list["pagination"] == {"offset": 0, "limit": 100, "asc": True}


def test_an_empty_listing_creates_once(pat_file: Path) -> None:
    fake = FakeZitadel()

    zb.bootstrap(_config(pat_file), transport=fake.transport())

    assert [kind for kind, _ in fake.create_requests] == ["project", "application"]


def test_repeated_runs_across_pages_never_duplicate(pat_file: Path) -> None:
    fake = FakeZitadel()
    _seed_projects(fake, 250)

    first = zb.bootstrap(_config(pat_file), transport=fake.transport())
    second = zb.bootstrap(_config(pat_file), transport=fake.transport())

    assert first == second
    assert [kind for kind, _ in fake.create_requests] == ["project", "application"]
    assert [p["name"] for p in fake.projects].count("saas-os") == 1


def test_an_application_on_a_later_page_is_found(pat_file: Path) -> None:
    fake = FakeZitadel()
    fake.projects.append({"projectId": "p", "name": "saas-os"})
    for i in range(150):
        fake.applications.append(
            {
                "applicationId": f"seed-{i}",
                "projectId": "p",
                "name": f"other-{i}",
                "oidcConfiguration": {"clientId": f"seed-client-{i}"},
            }
        )
    fake.applications.append(
        {
            "applicationId": "existing",
            "projectId": "p",
            "name": "saas-os-backend",
            "oidcConfiguration": {"clientId": "existing-client", "idTokenUserinfoAssertion": True},
        }
    )

    assert zb.bootstrap(_config(pat_file), transport=fake.transport()) == "existing-client"
    assert fake.create_requests == []


def test_an_api_failure_mid_listing_creates_nothing(
    pat_file: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(zb, "_RETRIES", 2)
    monkeypatch.setattr(zb, "_RETRY_DELAY_SECONDS", 0)
    fake = FakeZitadel()
    _seed_projects(fake, 150)

    def handle(request: httpx.Request) -> httpx.Response:
        body = json.loads(request.content) if request.content else {}
        if request.url.path.endswith("/ListProjects") and body["pagination"]["offset"] > 0:
            return httpx.Response(503)
        return fake.handle(request)

    with pytest.raises(httpx.HTTPStatusError):
        zb.bootstrap(_config(pat_file), transport=httpx.MockTransport(handle))
    assert fake.create_requests == []


def test_an_empty_page_short_of_the_total_fails_closed(pat_file: Path) -> None:
    fake = FakeZitadel()

    def handle(request: httpx.Request) -> httpx.Response:
        if request.url.path.endswith("/ListProjects"):
            return httpx.Response(200, json={"projects": [], "pagination": {"totalResult": "5"}})
        return fake.handle(request)

    with pytest.raises(zb.IncompleteListingError):
        zb.bootstrap(_config(pat_file), transport=httpx.MockTransport(handle))
    assert fake.create_requests == []


def test_pagination_is_bounded(pat_file: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """A server that always reports more items cannot loop forever."""
    monkeypatch.setattr(zb, "_MAX_LIST_PAGES", 3)
    fake = FakeZitadel()
    calls = 0

    def handle(request: httpx.Request) -> httpx.Response:
        nonlocal calls
        if request.url.path.endswith("/ListProjects"):
            calls += 1
            page = [{"projectId": f"x-{calls}", "name": "other"}] * 100
            return httpx.Response(
                200, json={"projects": page, "pagination": {"totalResult": "1000000"}}
            )
        return fake.handle(request)

    with pytest.raises(zb.IncompleteListingError):
        zb.bootstrap(_config(pat_file), transport=httpx.MockTransport(handle))
    assert calls == 3
    assert fake.create_requests == []


def test_a_response_without_totals_stops_on_a_short_page(pat_file: Path) -> None:
    fake = FakeZitadel()
    seen: list[int] = []

    def handle(request: httpx.Request) -> httpx.Response:
        if request.url.path.endswith("/ListProjects"):
            offset = json.loads(request.content)["pagination"]["offset"]
            seen.append(offset)
            count = 100 if offset == 0 else 7
            page = [{"projectId": f"n-{offset + i}", "name": "other"} for i in range(count)]
            return httpx.Response(200, json={"projects": page})
        return fake.handle(request)

    zb.bootstrap(_config(pat_file), transport=httpx.MockTransport(handle))
    assert seen == [0, 100]
