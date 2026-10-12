"""The consumer's SaaS-OS dependency pin (ADR-0015 rules 7-8:
`saas-os @ git+<url>@<exact commit SHA>`).

The updater changes exactly one thing in a consumer: the ref of its single
SaaS-OS pin, from one exact SHA to another. Discovery is deliberately
strict -- one pin, in one file, already an exact SHA -- and anything else
(no pin, several pins, a mutable ref, a lock file that also records the
pinned SHA) is refused rather than guessed at.
"""

from __future__ import annotations

import hashlib
import os
import re
import tempfile
from dataclasses import dataclass
from pathlib import Path

# `saas-os`, `saas_os`, `SaaS-OS`, with optional extras, then a direct Git
# reference. The URL runs to whitespace, a quote, a comma, a `;` (an
# environment marker) or a `#` fragment.
_PIN = re.compile(
    r"(?i)(?<![A-Za-z0-9_.\-])saas[-_.]os(?:\[[^\]]*\])?\s*@\s*(?P<target>git\+[^\s\"',;#]+)"
)
_CREDENTIALS = re.compile(r"(?P<scheme>[A-Za-z][A-Za-z0-9+.\-]*://)[^/@\s]+@")
DEFAULT_PIN_FILES = ("pyproject.toml", "requirements*.txt", "requirements/*.txt")
LOCK_FILES = ("uv.lock", "poetry.lock", "pdm.lock", "Pipfile.lock", "requirements*.lock")


class PinError(ValueError):
    """The consumer's pin cannot be determined unambiguously."""

    def __init__(self, code: str, detail: str) -> None:
        self.code = code
        self.detail = detail
        super().__init__(detail)


@dataclass(frozen=True)
class Pin:
    file: Path  # absolute
    relative_file: str  # POSIX, relative to the consumer root
    line_number: int  # 1-based
    url: str  # without the `git+` prefix and the ref
    ref: str
    ref_start: int  # offset of the ref within the file's text
    ref_end: int


def redact(text: str) -> str:
    """Remove credentials embedded in a URL's user-info part (everything
    between `scheme://` and the `@` before the host)."""
    return _CREDENTIALS.sub(r"\g<scheme>***@", text)


def _split_ref(target: str) -> tuple[str, str | None, int]:
    """Split `git+<url>[@<ref>]` into url, ref and the ref's offset. Only an
    `@` after the host part separates a ref: `git+ssh://git@host/...` has an
    `@` in its user info that is not one."""
    body = target[len("git+") :]
    scheme_end = body.find("://")
    path_start = body.find("/", scheme_end + 3 if scheme_end >= 0 else 0)
    at = body.rfind("@")
    if at < 0 or path_start < 0 or at < path_start:
        return body, None, -1
    return body[:at], body[at + 1 :], len("git+") + at + 1


def _candidate_files(root: Path, patterns: tuple[str, ...]) -> list[Path]:
    """Regular files matching `patterns` that resolve inside `root`. A
    symlink (of the file or of a directory on its path) that resolves
    outside the consumer is never a pin file, so the updater can never
    write outside the consumer it was pointed at."""
    resolved_root = root.resolve()
    files: set[Path] = set()
    for pattern in patterns:
        try:
            matches = list(root.glob(pattern))
        except (ValueError, NotImplementedError) as exc:
            raise PinError("pin_files_invalid", f"pin file pattern {pattern!r} is invalid") from exc
        for path in matches:
            if path.is_file() and path.resolve().is_relative_to(resolved_root):
                files.add(path)
    return sorted(files)


def find_pin(root: Path, pin_files: tuple[str, ...] = DEFAULT_PIN_FILES) -> Pin:
    """The single SaaS-OS pin in the consumer's dependency files. Raises
    `PinError` when there is none, more than one, or it has no ref."""
    found: list[Pin] = []
    for file in _candidate_files(root, pin_files):
        # Raw bytes, decoded without newline translation: the offsets must
        # address exactly the bytes `write_pin()` rewrites (CRLF files too).
        try:
            text = file.read_bytes().decode("utf-8")
        except (OSError, UnicodeDecodeError) as exc:
            raise PinError(
                "pin_unreadable", f"{file.relative_to(root).as_posix()} cannot be read as UTF-8"
            ) from exc
        offset = 0
        for number, line in enumerate(text.splitlines(keepends=True), start=1):
            if not line.lstrip().startswith("#"):
                for match in _PIN.finditer(line):
                    url, ref, ref_offset = _split_ref(match.group("target"))
                    if ref is None:
                        raise PinError(
                            "pin_not_exact_sha",
                            f"{file.relative_to(root).as_posix()}:{number} pins saas-os "
                            "without a commit reference",
                        )
                    start = offset + match.start("target") + ref_offset
                    found.append(
                        Pin(
                            file=file,
                            relative_file=file.relative_to(root).as_posix(),
                            line_number=number,
                            url=url,
                            ref=ref,
                            ref_start=start,
                            ref_end=start + len(ref),
                        )
                    )
            offset += len(line)
    if not found:
        raise PinError("pin_missing", "no saas-os Git dependency pin was found")
    if len(found) > 1:
        places = ", ".join(f"{pin.relative_file}:{pin.line_number}" for pin in found)
        raise PinError("pin_ambiguous", f"saas-os is pinned in more than one place ({places})")
    return found[0]


def lock_files_mentioning(root: Path, sha: str) -> list[str]:
    """Lock files that also record `sha`: updating only the pin would leave
    them inconsistent, and the updater does not rewrite lock files."""
    return [
        path.relative_to(root).as_posix()
        for path in _candidate_files(root, LOCK_FILES)
        if sha in path.read_text(encoding="utf-8", errors="replace")
    ]


def file_digest(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _write_atomically(path: Path, content: bytes) -> None:
    descriptor, temporary = tempfile.mkstemp(dir=path.parent, prefix=f".{path.name}.")
    try:
        with os.fdopen(descriptor, "wb") as handle:
            handle.write(content)
        os.replace(temporary, path)
    except BaseException:
        if os.path.exists(temporary):
            os.unlink(temporary)
        raise


def write_pin(pin: Pin, new_sha: str) -> bytes:
    """Replace exactly the pin's ref with `new_sha`, byte for byte elsewhere,
    and return the file's original bytes (for rollback)."""
    original = pin.file.read_bytes()
    text = original.decode("utf-8")
    if text[pin.ref_start : pin.ref_end] != pin.ref:
        raise PinError("stale_state", f"{pin.relative_file} changed since it was analyzed")
    updated = text[: pin.ref_start] + new_sha + text[pin.ref_end :]
    _write_atomically(pin.file, updated.encode("utf-8"))
    return original


def restore(path: Path, original: bytes) -> bool:
    """Write `original` back and verify it byte for byte."""
    _write_atomically(path, original)
    return hashlib.sha256(path.read_bytes()).digest() == hashlib.sha256(original).digest()
