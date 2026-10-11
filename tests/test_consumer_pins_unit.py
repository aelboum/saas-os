"""Every consumer manifest shipped as an example pins `saas-os` the way
ADR-0015 rules 7-8 require of a real consumer: one Git/VCS dependency on
an exact 40-character commit SHA (docs/P-ROADMAP.md, P2).

Parsed with `saas_os.infra.update.pins.find_pin` -- the same parser
`saas-os-update` uses on a real consumer -- so an example manifest that
the update tooling could not handle fails here too. Hermetic: no network,
no Git; whether the SHA is reachable on the remote is proven by the
recorded clean-install run, not by this test.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from saas_os.infra.update.git import is_full_sha
from saas_os.infra.update.pins import PinError, find_pin

_EXAMPLES = Path(__file__).resolve().parents[1] / "examples"
_CONSUMERS = sorted(p.parent for p in _EXAMPLES.glob("*/pyproject.toml"))


def test_both_example_consumers_are_covered() -> None:
    assert [p.name for p in _CONSUMERS] == ["consumer-scaffold", "reference-consumer"]


@pytest.mark.parametrize("consumer", _CONSUMERS, ids=lambda p: p.name)
def test_example_consumer_pins_an_exact_commit_sha(consumer: Path) -> None:
    pin = find_pin(consumer)
    assert pin.relative_file == "pyproject.toml"
    assert pin.url == "https://github.com/aelboum/saas-os"
    assert is_full_sha(pin.ref), f"{consumer.name} pins {pin.ref!r}, not a 40-character SHA"


@pytest.mark.parametrize("ref", ["<pin-to-a-released-commit-sha>", "main", "v0.1.0", "4fccc93"])
def test_a_placeholder_tag_branch_or_short_sha_would_be_rejected(tmp_path: Path, ref: str) -> None:
    """The check above is not vacuous: each of the refs it exists to keep
    out is refused by the same two calls."""
    (tmp_path / "pyproject.toml").write_text(
        '[project]\nname = "x"\ndependencies = [\n'
        f'    "saas-os @ git+https://github.com/aelboum/saas-os@{ref}",\n]\n',
        encoding="utf-8",
    )
    try:
        pin = find_pin(tmp_path)
    except PinError:
        return
    assert not is_full_sha(pin.ref)
