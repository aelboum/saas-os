"""The whole public import surface is pinned (production-readiness gate 1).

Every `saas_os` package with `__all__` and, for each exported name, its
signature (functions), bases, fields and public method signatures (classes)
are recorded in `public_api_snapshot.txt` by `scripts/public_api_snapshot.py`.
A change fails here until the snapshot is rewritten with `--write`, which is
the moment to decide whether it is a `0.Y.0` change (ADR-0015, "release
labels": a removed or changed public signature) and to write the changelog
entry."""

from __future__ import annotations

import importlib.util
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
SCRIPT_PATH = REPO_ROOT / "scripts" / "public_api_snapshot.py"


def _script():
    spec = importlib.util.spec_from_file_location("public_api_snapshot", SCRIPT_PATH)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _differences(committed: dict, current: dict) -> list[str]:
    lines = []
    for module in sorted(committed.keys() | current.keys()):
        old, new = committed.get(module), current.get(module)
        if old is None or new is None:
            lines.append(f"{module}: package {'added' if old is None else 'removed'}")
            continue
        for name in sorted(old.keys() | new.keys()):
            if old.get(name) != new.get(name):
                state = "added" if name not in old else "removed" if name not in new else "changed"
                lines.append(f"{module}.{name}: {state}")
    return lines


def test_the_public_api_matches_the_reviewed_snapshot() -> None:
    script = _script()
    current = script.parse(script.render(script.build_snapshot()))
    committed = script.parse(script.SNAPSHOT.read_text(encoding="utf-8"))
    differences = _differences(committed, current)
    assert not differences, (
        "The public API changed. Review each entry (a changed or removed signature "
        "is a 0.Y.0 change, ADR-0015), then run `python scripts/public_api_snapshot.py "
        "--write`:\n  " + "\n  ".join(differences)
    )


def test_the_snapshot_covers_the_packages_products_import() -> None:
    """Not vacuous: the packages the consumer guide tells products to import
    from are in the snapshot, with real signatures."""
    script = _script()
    snapshot = script.parse(script.SNAPSHOT.read_text(encoding="utf-8"))
    for module in (
        "saas_os.core.tenancy",
        "saas_os.core.billing",
        "saas_os.core.rbac",
        "saas_os.infra.jobs",
        "saas_os.infra.db",
    ):
        assert module in snapshot, module
    assert snapshot["saas_os.core.tenancy"]["register_purge_participant"].startswith(
        "def register_purge_participant("
    )
