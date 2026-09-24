"""ADR-0024 -- `saas-os-edge-config` (`infra/edge/cli.py`): the way a
consuming project obtains the reusable local edge configuration from its
installed dependency instead of copying this repository (ADR-0015). No
network, no environment reads, no secret."""

from __future__ import annotations

from pathlib import Path

import pytest
from infra.edge.cli import main

from infra.edge import read_local_edge_caddyfile


def test_emits_the_packaged_configuration_to_stdout(capsys: pytest.CaptureFixture[str]) -> None:
    assert main([]) == 0
    assert capsys.readouterr().out == read_local_edge_caddyfile()


def test_writes_the_packaged_configuration_to_a_path(tmp_path: Path) -> None:
    destination = tmp_path / "local-dev" / "Caddyfile"
    assert main(["--output", str(destination)]) == 0
    assert destination.read_text(encoding="utf-8") == read_local_edge_caddyfile()


def test_refuses_to_overwrite_a_project_owned_file_without_force(tmp_path: Path) -> None:
    """The emitted file becomes the project's own (ADR-0015 rules 9/10) --
    re-running the tool must not silently discard its edits."""
    destination = tmp_path / "Caddyfile"
    destination.write_text("# the project's own edits\n", encoding="utf-8")
    with pytest.raises(SystemExit):
        main(["--output", str(destination)])
    assert destination.read_text(encoding="utf-8") == "# the project's own edits\n"

    assert main(["--output", str(destination), "--force"]) == 0
    assert destination.read_text(encoding="utf-8") == read_local_edge_caddyfile()


def test_the_packaged_asset_is_readable_as_package_data() -> None:
    """Guards the `[tool.setuptools.package-data]` entry from the source
    side; `tests/test_wheel_contents.py` guards the built wheel."""
    content = read_local_edge_caddyfile()
    assert content.strip()
    assert "reverse_proxy" in content
