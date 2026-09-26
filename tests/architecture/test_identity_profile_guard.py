"""ADR-0025 §1a -- behavioral tests of deploy/check-identity-profile.sh, the
fail-closed guard that keeps an existing deployment's issuer and
WebAuthn/passkey/U2F RP ID from ever being switched by a configuration edit.

The real script is executed with `sh`; only its three fixed container paths
(the state volume, ZITADEL's TLS volume and ZITADEL's database volume) are
pointed at a temporary directory. Requires `sh` and `openssl`; skipped otherwise.
"""

from __future__ import annotations

import os
import shutil
import subprocess
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[2]
SCRIPT = REPO_ROOT / "deploy" / "check-identity-profile.sh"

pytestmark = pytest.mark.skipif(
    shutil.which("sh") is None or shutil.which("openssl") is None,
    reason="sh and openssl required",
)


@pytest.fixture
def guard(tmp_path: Path):
    text = SCRIPT.read_text()
    for fixed in (
        'STATE_DIR="/identity-profile-state"',
        'EXISTING_CERT="/identity-tls-server/',
        'EXISTING_ZITADEL_DB="/zitadel-db-data/',
    ):
        assert text.count(fixed) == 1
    state, tls, db = tmp_path / "state", tmp_path / "tls", tmp_path / "zitadel-db"
    tls.mkdir()
    db.mkdir()
    local = tmp_path / "check-identity-profile.sh"
    local.write_text(
        text.replace('"/identity-profile-state"', f'"{state}"')
        .replace('"/identity-tls-server/', f'"{tls}/')
        .replace('"/zitadel-db-data/', f'"{db}/')
    )

    def run(profile: str | None, public: str, identity: str) -> subprocess.CompletedProcess:
        env = {"PATH": os.environ["PATH"], "PUBLIC_DOMAIN": public}
        env["IDENTITY_PUBLIC_DOMAIN"] = identity
        if profile is not None:
            env["IDENTITY_PROFILE"] = profile
        return subprocess.run(
            ["sh", str(local)], env=env, capture_output=True, text=True, timeout=30
        )

    def existing_cert(cn: str) -> None:
        subprocess.run(
            [
                "openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "1",
                "-keyout", str(tls / "tls.key"), "-out", str(tls / "tls.crt"),
                "-subj", f"/CN={cn}", "-addext", f"subjectAltName=DNS:{cn}",
            ],
            check=True,
            capture_output=True,
        )  # fmt: skip

    def existing_zitadel_db() -> None:
        # What PostgreSQL's initdb leaves in an initialized data directory.
        (db / "PG_VERSION").write_text("16\n")

    run.existing_cert = existing_cert  # type: ignore[attr-defined]
    run.existing_zitadel_db = existing_zitadel_db  # type: ignore[attr-defined]
    run.state_file = state / "profile"  # type: ignore[attr-defined]
    return run


def test_fresh_deployment_is_pinned(guard) -> None:
    result = guard("fresh", "app.example.test", "app.example.test")
    assert result.returncode == 0, result.stderr
    assert guard.state_file.read_text() == (
        "profile=fresh public_domain=app.example.test identity_public_domain=app.example.test"
    )
    assert guard("fresh", "app.example.test", "app.example.test").returncode == 0


def test_existing_deployment_is_recognized_and_pinned(guard) -> None:
    guard.existing_cert("id.example.test")
    result = guard("existing", "app.example.test", "id.example.test")
    assert result.returncode == 0, result.stderr


@pytest.mark.parametrize(
    ("profile", "public", "identity"),
    [
        ("fresh", "app.example.test", "id.example.test"),
        ("existing", "app.example.test", "app.example.test"),
        ("bogus", "app.example.test", "id.example.test"),
        (None, "app.example.test", "id.example.test"),
    ],
)
def test_invalid_profiles_refuse_to_start(guard, profile, public, identity) -> None:
    result = guard(profile, public, identity)
    assert result.returncode != 0
    assert not guard.state_file.exists()


def test_existing_deployment_cannot_be_switched_to_fresh(guard) -> None:
    """The ABSOLUTELY-DO-NOT case: an existing (pre-ADR-0025) identity
    deployment re-configured as fresh on PUBLIC_DOMAIN -- which would move its
    issuer and RP ID -- is refused before any identity service starts."""
    guard.existing_cert("id.example.test")
    result = guard("fresh", "app.example.test", "app.example.test")
    assert result.returncode != 0
    assert "different domain" in result.stderr
    assert not guard.state_file.exists()


def test_pinned_profile_and_domains_cannot_change(guard) -> None:
    guard.existing_cert("id.example.test")
    assert guard("existing", "app.example.test", "id.example.test").returncode == 0
    for args in [
        ("fresh", "app.example.test", "app.example.test"),
        ("existing", "app.example.test", "login.example.test"),
        ("existing", "www.example.test", "id.example.test"),
    ]:
        result = guard(*args)
        assert result.returncode != 0, args
        assert "pinned" in result.stderr
    assert guard("existing", "app.example.test", "id.example.test").returncode == 0


def test_pinned_fresh_deployment_cannot_move_either(guard) -> None:
    assert guard("fresh", "app.example.test", "app.example.test").returncode == 0
    assert guard("fresh", "new.example.test", "new.example.test").returncode != 0
    assert guard("existing", "app.example.test", "id.example.test").returncode != 0


# --- identity data present, but its domains can no longer be confirmed -------


@pytest.mark.parametrize(
    ("profile", "public", "identity"),
    [
        ("fresh", "app.example.test", "app.example.test"),
        ("existing", "app.example.test", "id.example.test"),
    ],
)
def test_existing_zitadel_database_without_pin_or_certificate_fails_closed(
    guard, profile, public, identity
) -> None:
    """An existing deployment whose identity TLS volume was deleted before
    this guard ever pinned it: ZITADEL's database (issuer, passkeys, U2F)
    still exists, but nothing can confirm which domains it was created for.
    The guard refuses rather than guessing -- for the fresh profile in
    particular, which would move the issuer and RP ID to PUBLIC_DOMAIN."""
    guard.existing_zitadel_db()
    result = guard(profile, public, identity)
    assert result.returncode != 0
    assert "existing ZITADEL database" in result.stderr
    assert not guard.state_file.exists()


def test_existing_deployment_with_database_and_certificate_is_still_recognized(guard) -> None:
    guard.existing_zitadel_db()
    guard.existing_cert("id.example.test")
    assert guard("existing", "app.example.test", "id.example.test").returncode == 0
    fresh = guard("fresh", "app.example.test", "app.example.test")
    assert fresh.returncode != 0


def test_fresh_deployment_initialized_as_fresh_keeps_starting(guard) -> None:
    """Explicitly initialized fresh: pinned before ZITADEL's database exists
    (`zitadel-db` depends on the guard), then allowed on every later start."""
    assert guard("fresh", "app.example.test", "app.example.test").returncode == 0
    guard.existing_zitadel_db()
    guard.existing_cert("app.example.test")
    assert guard("fresh", "app.example.test", "app.example.test").returncode == 0
    assert guard("existing", "app.example.test", "id.example.test").returncode != 0


def test_brand_new_deployment_with_no_identity_data_is_pinned(guard) -> None:
    """No pin, no certificate, no ZITADEL database: nothing exists that an
    issuer or RP-ID change could strand, so the first run is pinned."""
    assert guard("fresh", "app.example.test", "app.example.test").returncode == 0
    assert guard.state_file.exists()
