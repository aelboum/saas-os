"""P1.7 -- migration *graph* correctness (docs/IMPLEMENTATION-ROADMAP.md
P1.7: "migration graph validity is tested"). Pure `alembic.script.ScriptDirectory`
inspection of `infra/db/migrations/versions/` -- no database connection,
no `env.py` execution (Alembic does not invoke `env.py` for pure
script-directory introspection), so this runs in the default suite and
protects every future migration, not just the ones that exist today.

Distinct from `test_migration_gate_integration.py`'s *real* clean-database-
to-head proof: this file only proves the revision *chain itself* is
internally consistent (one head, one base, no orphaned/duplicate
revisions, every revision has both a real `upgrade()` and `downgrade()`).
It says nothing about whether the migrations actually apply successfully
against real PostgreSQL, or what schema they produce -- that is the
integration file's job.
"""

from __future__ import annotations

from pathlib import Path

from alembic.config import Config
from alembic.script import ScriptDirectory

_REPO_ROOT = Path(__file__).resolve().parents[3]
_VERSIONS_DIR = _REPO_ROOT / "infra" / "db" / "migrations" / "versions"

# A literal pin, not a computed value -- an accidental extra, reordered,
# or rebased migration changes this and the test fails, forcing a
# deliberate update rather than a silent drift.
_EXPECTED_HEAD = "4c1e9a7b2d55"


def _script_directory() -> ScriptDirectory:
    cfg = Config(str(_REPO_ROOT / "alembic.ini"))
    cfg.set_main_option("script_location", str(_REPO_ROOT / "infra" / "db" / "migrations"))
    return ScriptDirectory.from_config(cfg)


def _version_file_count() -> int:
    return len([p for p in _VERSIONS_DIR.glob("*.py") if p.name != "__init__.py"])


def test_exactly_one_head_exists() -> None:
    """No unresolved branch point -- `alembic upgrade head` (singular) is
    always unambiguous."""
    heads = _script_directory().get_heads()
    assert len(heads) == 1, f"expected exactly one head, found {len(heads)}: {heads}"


def test_the_one_head_matches_the_documented_revision() -> None:
    (head,) = _script_directory().get_heads()
    assert head == _EXPECTED_HEAD, (
        f"migration head changed to {head!r} (expected {_EXPECTED_HEAD!r}) -- "
        "if this is deliberate (a genuinely new migration was added), update "
        "_EXPECTED_HEAD; if not, an unexpected migration change was introduced."
    )


def test_exactly_one_base_exists() -> None:
    """No unresolved second migration lineage with no shared ancestor."""
    bases = _script_directory().get_bases()
    assert len(bases) == 1, f"expected exactly one base, found {len(bases)}: {bases}"


def test_revision_chain_length_matches_the_number_of_migration_files() -> None:
    """Non-vacuous proof the chain isn't silently missing/duplicating a
    revision: `walk_revisions()` must visit exactly one `Script` per
    `versions/*.py` file on disk."""
    revisions = list(_script_directory().walk_revisions())
    assert len(revisions) == _version_file_count()


def test_no_duplicate_revision_ids() -> None:
    revisions = list(_script_directory().walk_revisions())
    revision_ids = [r.revision for r in revisions]
    assert len(revision_ids) == len(set(revision_ids)), "duplicate revision id detected"


def test_every_revision_has_a_real_upgrade_and_downgrade_function() -> None:
    """Every migration must define *both* directions -- an
    irreversible-by-omission migration is exactly the kind of thing this
    gate exists to catch before it reaches `main`."""
    for revision in _script_directory().walk_revisions():
        module = revision.module
        upgrade_fn = getattr(module, "upgrade", None)
        downgrade_fn = getattr(module, "downgrade", None)
        assert callable(upgrade_fn), f"{revision.revision} has no upgrade() function"
        assert callable(downgrade_fn), f"{revision.revision} has no downgrade() function"


def test_chain_is_a_single_linear_sequence_no_branch_points() -> None:
    """Every non-head revision must have exactly one direct child --
    a branch point (two migrations sharing a `down_revision`) would
    otherwise only surface as a confusing multi-head error at
    `alembic upgrade head` time."""
    revisions = list(_script_directory().walk_revisions())
    down_revisions: list[str] = []
    for r in revisions:
        if r.down_revision is not None:
            # down_revision can technically be a tuple for merge points;
            # this repository's chain is linear, so a bare str is expected.
            assert isinstance(r.down_revision, str), (
                f"{r.revision} has a non-linear (tuple) down_revision -- "
                "this repository's migration chain is expected to stay linear"
            )
            down_revisions.append(r.down_revision)
    assert len(down_revisions) == len(set(down_revisions)), (
        "two migrations share the same down_revision -- a branch point exists"
    )
