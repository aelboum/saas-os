"""`saas-os-local-identity` -- idempotent bootstrap of a local-development
OIDC application in a self-hosted ZITADEL instance (ADR-0023 Phase 1,
docs/LOCAL-IDENTITY.md).

Local-development tooling. It is run as a one-shot Compose service (SaaS-OS's
own `zitadel-bootstrap`, or the equivalent service in a consuming project's
Compose file) and is never imported by application code. It lives in the
installed package only so a consuming project can run it from its SaaS-OS
dependency rather than copying this repository's files (ADR-0015).
`local-dev/bootstrap_zitadel.py` is a thin compatibility entrypoint that
delegates here (docker-compose.prod.yml's production wrapper loads that
path).

What it does, using only ZITADEL's own supported Management API (no custom
provisioning system):

1. Reads the bootstrap machine user's Personal Access Token that ZITADEL
   itself wrote to `ZITADEL_FIRSTINSTANCE_PATPATH` during `start-from-init`
   (a file on a volume shared with the `zitadel` service). This PAT is never
   printed, logged, or persisted anywhere else.
2. Resolves the instance's default organization id
   (`GET /management/v1/orgs/me`).
3. Finds or creates a project named `project_name` in that org
   (`ProjectService.ListProjects` / `.CreateProject`).
4. Finds or creates a public (PKCE, no client secret), authorization-code
   OIDC web application named `application_name` in that project
   (`ApplicationService.ListApplications` / `.CreateApplication`), with its
   redirect URI set to the same `OIDC_REDIRECT_URI` the application's own
   backend reads (api/auth/config.py) -- one source of truth, so the
   bootstrap and the application it provisions never drift apart.
5. Prints the resulting `client_id` so a developer can copy it into their
   own `.env` as `OIDC_CLIENT_ID`. No secret is written anywhere; the
   application is a public client, so there is no client secret at all.

Re-running is safe (e.g. on every `docker compose up`): steps 3 and 4 always
list-before-create, by exact name, so nothing is duplicated.

Configuration (environment variables; each has an equivalent CLI flag that
takes precedence):

- `ZITADEL_INTERNAL_URL` (required) -- ZITADEL's URL as reachable from this
  process. ZITADEL resolves which instance a request belongs to by matching
  the `Host` header against its ExternalDomain(:ExternalPort), so this must
  be the same host:port the browser uses (see docs/LOCAL-IDENTITY.md, "Why
  `zitadel.localhost`").
- `OIDC_REDIRECT_URI` -- the application's own callback URL.
- `OIDC_LOCAL_PROJECT_NAME` -- ZITADEL project name (default `saas-os`).
- `OIDC_LOCAL_APPLICATION_NAME` -- ZITADEL application name (default
  `saas-os-backend`).
- `ZITADEL_BOOTSTRAP_PAT_PATH` -- PAT file path (default
  `/bootstrap/bootstrap.pat`).

An empty value is treated as unset, so a Compose file can pass
`${OIDC_LOCAL_PROJECT_NAME:-}` through unconditionally.
"""

from __future__ import annotations

import argparse
import os
import sys
import time
from collections.abc import Mapping, Sequence
from dataclasses import dataclass

import httpx

DEFAULT_PAT_PATH = "/bootstrap/bootstrap.pat"
DEFAULT_PROJECT_NAME = "saas-os"
DEFAULT_APPLICATION_NAME = "saas-os-backend"
DEFAULT_REDIRECT_URI = "http://localhost:8000/auth/callback"

_RETRIES = 15
_RETRY_DELAY_SECONDS = 2.0


@dataclass(frozen=True)
class BootstrapConfig:
    zitadel_url: str
    redirect_uri: str = DEFAULT_REDIRECT_URI
    project_name: str = DEFAULT_PROJECT_NAME
    application_name: str = DEFAULT_APPLICATION_NAME
    pat_path: str = DEFAULT_PAT_PATH


def _non_empty(value: str | None) -> str | None:
    if value is None:
        return None
    value = value.strip()
    return value or None


def load_config(
    argv: Sequence[str] | None = None, environ: Mapping[str, str] | None = None
) -> BootstrapConfig:
    """Build the configuration from CLI flags, falling back to environment
    variables, falling back to SaaS-OS's own defaults."""
    env = os.environ if environ is None else environ
    parser = argparse.ArgumentParser(
        prog="saas-os-local-identity",
        description="Idempotently create a local-development ZITADEL project and public "
        "(PKCE) OIDC application, and print its OIDC_CLIENT_ID. Development tooling "
        "only -- see docs/LOCAL-IDENTITY.md.",
    )
    parser.add_argument("--zitadel-url", help="Overrides ZITADEL_INTERNAL_URL.")
    parser.add_argument("--redirect-uri", help="Overrides OIDC_REDIRECT_URI.")
    parser.add_argument("--project-name", help="Overrides OIDC_LOCAL_PROJECT_NAME.")
    parser.add_argument("--application-name", help="Overrides OIDC_LOCAL_APPLICATION_NAME.")
    parser.add_argument("--pat-path", help="Overrides ZITADEL_BOOTSTRAP_PAT_PATH.")
    args = parser.parse_args(argv)

    def pick(flag: str | None, env_name: str) -> str | None:
        return _non_empty(flag) or _non_empty(env.get(env_name))

    zitadel_url = pick(args.zitadel_url, "ZITADEL_INTERNAL_URL")
    if zitadel_url is None:
        parser.error("ZITADEL_INTERNAL_URL (or --zitadel-url) is required.")
    return BootstrapConfig(
        zitadel_url=zitadel_url,
        redirect_uri=pick(args.redirect_uri, "OIDC_REDIRECT_URI") or DEFAULT_REDIRECT_URI,
        project_name=pick(args.project_name, "OIDC_LOCAL_PROJECT_NAME") or DEFAULT_PROJECT_NAME,
        application_name=pick(args.application_name, "OIDC_LOCAL_APPLICATION_NAME")
        or DEFAULT_APPLICATION_NAME,
        pat_path=pick(args.pat_path, "ZITADEL_BOOTSTRAP_PAT_PATH") or DEFAULT_PAT_PATH,
    )


def read_pat(path: str) -> str:
    # ZITADEL writes this file once `start-from-init`'s setup step completes;
    # `zitadel: condition: service_healthy` in the Compose file already
    # guarantees the file exists by the time this container starts, but
    # projections can still lag briefly behind -- retried in `_call`, not here.
    with open(path, encoding="utf-8") as f:
        return f.read().strip()


def _call(client: httpx.Client, method: str, path: str, json: dict | None = None) -> dict:
    last_error: Exception | None = None
    for attempt in range(1, _RETRIES + 1):
        try:
            response = client.request(method, path, json=json)
            response.raise_for_status()
            return response.json()
        except httpx.HTTPError as exc:
            last_error = exc
            print(
                f"[bootstrap] {method} {path} failed (attempt {attempt}/{_RETRIES}): {exc}",
                file=sys.stderr,
            )
            time.sleep(_RETRY_DELAY_SECONDS)
    assert last_error is not None
    raise last_error


def get_org_id(client: httpx.Client) -> str:
    body = _call(client, "GET", "/management/v1/orgs/me")
    return body["org"]["id"]


def find_or_create_project(client: httpx.Client, org_id: str, project_name: str) -> str:
    listing = _call(
        client,
        "POST",
        "/zitadel.project.v2.ProjectService/ListProjects",
        json={"filters": [{"organizationIdFilter": {"organizationId": org_id}}]},
    )
    for project in listing.get("projects", []):
        if project["name"] == project_name:
            print(f"[bootstrap] project {project_name!r} already exists: {project['projectId']}")
            return project["projectId"]

    created = _call(
        client,
        "POST",
        "/zitadel.project.v2.ProjectService/CreateProject",
        json={"organizationId": org_id, "name": project_name},
    )
    print(f"[bootstrap] created project {project_name!r}: {created['projectId']}")
    return created["projectId"]


def application_request(project_id: str, application_name: str, redirect_uri: str) -> dict:
    """The `CreateApplication` request body: a public PKCE client."""
    return {
        "projectId": project_id,
        "name": application_name,
        "oidcConfiguration": {
            "redirectUris": [redirect_uri],
            # Authorization Code + PKCE only -- no refresh-token grant
            # (SaaS-OS's own OIDC code never requests offline_access or
            # persists a refresh token; core/identity/oidc.py).
            "responseTypes": ["OIDC_RESPONSE_TYPE_CODE"],
            "grantTypes": ["OIDC_GRANT_TYPE_AUTHORIZATION_CODE"],
            "applicationType": "OIDC_APP_TYPE_WEB",
            # Public client: no client secret, PKCE S256 is always
            # mandatory in core/identity/oidc.py regardless -- matches the
            # OIDC_CLIENT_SECRET="" default in .env.example for exactly the
            # same reason.
            "authMethodType": "OIDC_AUTH_METHOD_TYPE_NONE",
        },
    }


def find_or_create_application(
    client: httpx.Client, project_id: str, application_name: str, redirect_uri: str
) -> str:
    listing = _call(
        client,
        "POST",
        "/zitadel.application.v2.ApplicationService/ListApplications",
        json={"filters": [{"projectIdFilter": {"projectId": project_id}}]},
    )
    for app in listing.get("applications", []):
        if app["name"] == application_name:
            client_id = app["oidcConfiguration"]["clientId"]
            print(
                f"[bootstrap] application {application_name!r} already exists: "
                f"client_id={client_id}"
            )
            return client_id

    created = _call(
        client,
        "POST",
        "/zitadel.application.v2.ApplicationService/CreateApplication",
        json=application_request(project_id, application_name, redirect_uri),
    )
    client_id = created["oidcConfiguration"]["clientId"]
    print(f"[bootstrap] created application {application_name!r}: client_id={client_id}")
    return client_id


def bootstrap(config: BootstrapConfig, transport: httpx.BaseTransport | None = None) -> str:
    """Ensure the project and application exist; return the OIDC client id.

    `transport` exists only so tests can substitute an in-memory ZITADEL."""
    headers = {"Authorization": f"Bearer {read_pat(config.pat_path)}"}
    with httpx.Client(
        base_url=config.zitadel_url, headers=headers, timeout=10.0, transport=transport
    ) as client:
        org_id = get_org_id(client)
        project_id = find_or_create_project(client, org_id, config.project_name)
        return find_or_create_application(
            client, project_id, config.application_name, config.redirect_uri
        )


def main(argv: Sequence[str] | None = None) -> None:
    # Returns None / raises rather than returning an exit code:
    # deploy/bootstrap_zitadel_production.py calls `main()` and ignores its
    # return value, so every failure must surface as an exception/SystemExit.
    config = load_config(argv)
    client_id = bootstrap(config)

    print("")
    print("=" * 72)
    print(
        f"Local ZITADEL OIDC application ready "
        f"(project {config.project_name!r}, application {config.application_name!r})."
    )
    print(f"Redirect URI: {config.redirect_uri}")
    print(f"Set this in your .env (only if it changed):  OIDC_CLIENT_ID={client_id}")
    print("Leave OIDC_CLIENT_SECRET empty -- this is a public PKCE client.")
    print("=" * 72)


if __name__ == "__main__":
    main()
