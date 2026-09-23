"""Idempotent local-only bootstrap of the SaaS-OS OIDC application in the
self-hosted local ZITADEL instance (ADR-0023 Phase 1).

Not part of the `saas-os` package (not under `core/`, `infra/`, `api/`,
`control-plane/`) -- this is Docker Compose tooling for the local
development topology only, run as the `zitadel-bootstrap` one-shot service
via `docker compose up`. It is never imported by application code and
carries no production role.

What it does, using only ZITADEL's own supported Management API (no custom
provisioning system):

1. Reads the bootstrap machine user's Personal Access Token that ZITADEL
   itself wrote to `ZITADEL_FIRSTINSTANCE_PATPATH` during `start-from-init`
   (a file on the shared `zitadel-bootstrap` volume -- see
   docker-compose.yml). This PAT is never printed, logged, or persisted
   anywhere else.
2. Resolves the local instance's default organization id
   (`GET /management/v1/orgs/me`).
3. Finds or creates a project named PROJECT_NAME in that org
   (`ProjectService.ListProjects` / `.CreateProject`).
4. Finds or creates a public (PKCE, no client secret), authorization-code
   OIDC web application named APP_NAME in that project
   (`ApplicationService.ListApplications` / `.CreateApplication`), with its
   redirect URI set to whatever `OIDC_REDIRECT_URI` SaaS-OS's own backend is
   already configured with (api/auth/config.py) -- so this script and the
   application it provisions never drift from each other.
5. Prints the resulting `client_id` so a developer can copy it into their
   own `.env` as `ZITADEL_CLIENT_ID` (`docker compose logs zitadel-bootstrap`).
   No secret is written to any tracked file; the application is a public
   client, so there is no client secret to handle at all.

Re-running this script (e.g. on every `docker compose up`) is safe: steps 3
and 4 always list-before-create, by exact name, so nothing is duplicated.
"""

from __future__ import annotations

import os
import sys
import time

import httpx

PAT_PATH = "/bootstrap/bootstrap.pat"
ORG_NAME = "saas-os-local"
PROJECT_NAME = "saas-os"
APP_NAME = "saas-os-backend"

# ZITADEL resolves which instance a request belongs to by matching the
# `Host` header against ZITADEL_EXTERNALDOMAIN(:ZITADEL_EXTERNALPORT) --
# verified empirically: calling it via a network address that does not
# match ExternalDomain 404s with no matching instance found, even with a
# valid PAT. docker-compose.yml gives the `zitadel` service a network alias
# equal to ZITADEL_EXTERNALDOMAIN (`zitadel.localhost`) and keeps
# ZITADEL_PORT/ZITADEL_EXTERNALPORT/the host-published port identical
# (ZITADEL_LOCAL_PORT, .env) specifically so ZITADEL_INTERNAL_URL below can
# be the exact same URL a browser on the host uses -- no separate
# Host-header override needed.
ZITADEL_URL = os.environ["ZITADEL_INTERNAL_URL"]
REDIRECT_URI = os.environ.get("OIDC_REDIRECT_URI", "http://localhost:8000/auth/callback")

_RETRIES = 15
_RETRY_DELAY_SECONDS = 2.0


def _read_pat() -> str:
    # ZITADEL writes this file once `start-from-init`'s setup step completes;
    # `zitadel: condition: service_healthy` in docker-compose.yml already
    # guarantees the file exists by the time this container starts, but
    # projections can still lag briefly behind -- retried below, not here.
    with open(PAT_PATH, encoding="utf-8") as f:
        return f.read().strip()


def _call(client: httpx.Client, method: str, path: str, json: dict | None = None) -> dict:
    last_error: Exception | None = None
    for attempt in range(1, _RETRIES + 1):
        try:
            response = client.request(method, path, json=json)
            response.raise_for_status()
            return response.json()
        except (httpx.HTTPError, httpx.HTTPStatusError) as exc:
            last_error = exc
            print(
                f"[bootstrap] {method} {path} failed (attempt {attempt}/{_RETRIES}): {exc}",
                file=sys.stderr,
            )
            time.sleep(_RETRY_DELAY_SECONDS)
    assert last_error is not None
    raise last_error


def _get_org_id(client: httpx.Client) -> str:
    body = _call(client, "GET", "/management/v1/orgs/me")
    return body["org"]["id"]


def _find_or_create_project(client: httpx.Client, org_id: str) -> str:
    listing = _call(
        client,
        "POST",
        "/zitadel.project.v2.ProjectService/ListProjects",
        json={"filters": [{"organizationIdFilter": {"organizationId": org_id}}]},
    )
    for project in listing.get("projects", []):
        if project["name"] == PROJECT_NAME:
            print(f"[bootstrap] project {PROJECT_NAME!r} already exists: {project['projectId']}")
            return project["projectId"]

    created = _call(
        client,
        "POST",
        "/zitadel.project.v2.ProjectService/CreateProject",
        json={"organizationId": org_id, "name": PROJECT_NAME},
    )
    print(f"[bootstrap] created project {PROJECT_NAME!r}: {created['projectId']}")
    return created["projectId"]


def _find_or_create_application(client: httpx.Client, project_id: str) -> str:
    listing = _call(
        client,
        "POST",
        "/zitadel.application.v2.ApplicationService/ListApplications",
        json={"filters": [{"projectIdFilter": {"projectId": project_id}}]},
    )
    for app in listing.get("applications", []):
        if app["name"] == APP_NAME:
            client_id = app["oidcConfiguration"]["clientId"]
            print(f"[bootstrap] application {APP_NAME!r} already exists: client_id={client_id}")
            return client_id

    created = _call(
        client,
        "POST",
        "/zitadel.application.v2.ApplicationService/CreateApplication",
        json={
            "projectId": project_id,
            "name": APP_NAME,
            "oidcConfiguration": {
                "redirectUris": [REDIRECT_URI],
                # Authorization Code + PKCE only -- no refresh-token grant
                # (SaaS-OS's own OIDC code never requests offline_access or
                # persists a refresh token; core/identity/oidc.py is
                # unchanged by this phase).
                "responseTypes": ["OIDC_RESPONSE_TYPE_CODE"],
                "grantTypes": ["OIDC_GRANT_TYPE_AUTHORIZATION_CODE"],
                "applicationType": "OIDC_APP_TYPE_WEB",
                # Public client: no client secret, PKCE S256 is always
                # mandatory in core/identity/oidc.py regardless -- matches
                # the existing ZITADEL_CLIENT_SECRET="" default in
                # .env.example for exactly the same reason.
                "authMethodType": "OIDC_AUTH_METHOD_TYPE_NONE",
            },
        },
    )
    client_id = created["oidcConfiguration"]["clientId"]
    print(f"[bootstrap] created application {APP_NAME!r}: client_id={client_id}")
    return client_id


def main() -> None:
    pat = _read_pat()
    headers = {"Authorization": f"Bearer {pat}"}
    with httpx.Client(base_url=ZITADEL_URL, headers=headers, timeout=10.0) as client:
        org_id = _get_org_id(client)
        project_id = _find_or_create_project(client, org_id)
        client_id = _find_or_create_application(client, project_id)

    print("")
    print("=" * 72)
    print("Local ZITADEL OIDC application ready.")
    print(f"Set this in your .env (only if it changed):  ZITADEL_CLIENT_ID={client_id}")
    print("Leave ZITADEL_CLIENT_SECRET empty -- this is a public PKCE client.")
    print("=" * 72)


if __name__ == "__main__":
    main()
