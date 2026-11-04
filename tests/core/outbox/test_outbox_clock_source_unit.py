"""The outbox's schedule code never reads the application host's clock
(`saas_os/core/outbox/dispatch.py`, "One clock: the database's").

`test_outbox_database_clock_integration.py` makes the host clock disagree
with PostgreSQL by replacing `dispatch.datetime`; a host-clock read through
any other name (`time.time()`, `date.today()`, a re-imported `datetime`)
would escape it. This guard reads the two modules' source and refuses every
call that reads the host's wall clock, however it is spelled.
"""

from __future__ import annotations

import ast
from pathlib import Path

import pytest

import saas_os.core.outbox.dispatch as dispatch
import saas_os.core.outbox.replay as replay

# Wall-clock readers, by the last two parts of the called name: covers
# `datetime.now()`, `datetime.datetime.now()`, `dt.datetime.utcnow()`,
# `date.today()`, `time.time()`, ...
_HOST_CLOCK_CALLS = {
    ("datetime", "now"),
    ("datetime", "utcnow"),
    ("datetime", "today"),
    ("date", "today"),
    ("time", "time"),
    ("time", "time_ns"),
    ("time", "localtime"),
    ("time", "gmtime"),
    ("time", "ctime"),
}
# Names that are host-clock readers on their own once imported
# (`from time import time`, `from datetime import ... as` aside).
_HOST_CLOCK_IMPORTS = {
    ("time", "time"),
    ("time", "time_ns"),
    ("time", "localtime"),
    ("time", "gmtime"),
    ("time", "ctime"),
}


def _dotted(node: ast.expr) -> tuple[str, ...]:
    parts: list[str] = []
    while isinstance(node, ast.Attribute):
        parts.append(node.attr)
        node = node.value
    if isinstance(node, ast.Name):
        parts.append(node.id)
    return tuple(reversed(parts))


def host_clock_reads(source: str) -> list[str]:
    """Every host-clock read in `source`, as `line: name`."""
    found: list[str] = []
    for node in ast.walk(ast.parse(source)):
        if isinstance(node, ast.Call):
            name = _dotted(node.func)
            if len(name) >= 2 and name[-2:] in _HOST_CLOCK_CALLS:
                found.append(f"{node.lineno}: {'.'.join(name)}()")
        elif isinstance(node, ast.ImportFrom) and node.module is not None:
            for alias in node.names:
                if (node.module, alias.name) in _HOST_CLOCK_IMPORTS:
                    found.append(f"{node.lineno}: from {node.module} import {alias.name}")
        elif isinstance(node, ast.Import):
            for alias in node.names:
                if alias.name == "time":
                    found.append(f"{node.lineno}: import time")
    return found


@pytest.mark.parametrize("module", [dispatch, replay], ids=["dispatch", "replay"])
def test_the_outbox_schedule_code_never_reads_the_host_clock(module: object) -> None:
    path = Path(str(getattr(module, "__file__", "")))
    assert host_clock_reads(path.read_text(encoding="utf-8")) == []


@pytest.mark.parametrize(
    "source",
    [
        "from datetime import UTC, datetime\nat = datetime.now(UTC)\n",
        "import datetime\nat = datetime.datetime.utcnow()\n",
        "from datetime import date\nd = date.today()\n",
        "import time\nt = time.time()\n",
        "from time import time\nt = time()\n",
        "import datetime as dt\nat = dt.datetime.now()\n",
    ],
)
def test_the_guard_finds_each_spelling_of_a_host_clock_read(source: str) -> None:
    assert host_clock_reads(source) != []


def test_the_guard_accepts_the_database_clock_and_explicit_instants() -> None:
    source = (
        "from datetime import datetime, timedelta\n"
        "from saas_os.infra.db import now as database_now\n"
        "def f(now: datetime | None):\n"
        "    at = now if now is not None else database_now()\n"
        "    return at + timedelta(seconds=1)\n"
    )
    assert host_clock_reads(source) == []
