"""`saas-os-local-identity` (infra/local_identity/zitadel_bootstrap.py) --
configuration and idempotency, against an in-memory fake of the three
ZITADEL Management API calls it makes. No real ZITADEL needed; the live
stack is exercised by `docker compose up` (docs/LOCAL-IDENTITY.md).
"""

from __future__ import annotations

import json
from pathlib import Path

import httpx
import pytest

from infra.local_identity import zitadel_bootstrap as zb

REPO_ROOT = Path(__file__).resolve().parents[3]


class FakeZitadel:
    """Just enough of ZITADEL's Management API: one org, list/create of
    projects and applications. Records every create call."""

    def __init__(self) -> None:
        self.projects: list[dict] = []
        self.applications: list[dict] = []
        self.create_requests: list[tuple[str, dict]] = []
        self.auth_headers: set[str] = set()

    def handle(self, request: httpx.Request) -> httpx.Response:
        self.auth_headers.add(request.headers.get("Authorization", ""))
        path = request.url.path
        body = json.loads(request.content) if request.content else {}
        if path == "/management/v1/orgs/me":
            return httpx.Response(200, json={"org": {"id": "org-1"}})
        if path.endswith("/ListProjects"):
            return httpx.Response(200, json={"projects": list(self.projects)})
        if path.endswith("/CreateProject"):
            self.create_requests.append(("project", body))
            project = {"projectId": f"proj-{len(self.projects) + 1}", "name": body["name"]}
            self.projects.append(project)
            return httpx.Response(200, json={"projectId": project["projectId"]})
        if path.endswith("/ListApplications"):
            project_id = body["filters"][0]["projectIdFilter"]["projectId"]
            apps = [a for a in self.applications if a["projectId"] == project_id]
            return httpx.Response(200, json={"applications": apps})
        if path.endswith("/CreateApplication"):
            self.create_requests.append(("application", body))
            client_id = f"client-{len(self.applications) + 1}"
            self.applications.append(
                {
                    "projectId": body["projectId"],
                    "name": body["name"],
                    "oidcConfiguration": {"clientId": client_id},
                }
            )
            return httpx.Response(200, json={"oidcConfiguration": {"clientId": client_id}})
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
        REPO_ROOT / "infra" / "local_identity" / "__init__.py",
        REPO_ROOT / "infra" / "local_identity" / "zitadel_bootstrap.py",
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
    assert scripts["saas-os-local-identity"] == "infra.local_identity.zitadel_bootstrap:main"
    assert "infra.local_identity" in pyproject["tool"]["setuptools"]["packages"]
