"""Preserves `python -m infra.db.backup {create,restore,prune}` after P2.4
converted this module into a package (`infra/db/backup/__init__.py` plus
new sibling submodules) -- `python -m <package>` runs `<package>/__main__.py`,
not `<package>/__init__.py`'s own `if __name__ == "__main__"` block, which
no longer executes automatically once a flat module becomes a package.

P2.4's own production pipeline (locking, encryption, off-site upload,
retention) is `python -m infra.db.backup.orchestrator {run,restore,status}`
-- a separate entrypoint, not this one; this file's sole purpose is
backward compatibility for the P1.3 CLI's existing three subcommands.
"""

from infra.db.backup import _cli

if __name__ == "__main__":  # pragma: no cover
    _cli()
