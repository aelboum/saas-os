"""Validation and rendering of the four optional list/threading headers
(issue 224, ADR-0057 and ADR-0058 amendments of 2026-11-07).

`EmailMessage.list_unsubscribe`, `list_unsubscribe_post`, `in_reply_to` and
`references` are the only caller path to `List-Unsubscribe`,
`List-Unsubscribe-Post`, `In-Reply-To` and `References`. There is no generic
header mapping and no header name is ever taken from a caller, so `Bcc`,
`Return-Path`, `Received`, `Date` and the MIME headers stay unreachable by
construction. This module is provider-neutral: `service.py` calls
`validate_list_headers()` before any provider call, and each adapter calls
`refuse_unsafe_header_values()` again (defence in depth: `provider.send()` is
public and validates nothing about the message) and takes the names and
values to emit from `message_headers()`, so both adapters emit exactly the
same set.

Every refusal raises `InvalidEmailHeaderError` with a fixed message: the
value is never echoed (an unsubscribe URI identifies the recipient).

What this checks is syntax and shape only. It does not make a message
RFC 8058 compliant: the DKIM signature that must cover these headers is
applied by the relay or provider, and the unsubscribe endpoint belongs to the
product. Rules (the numbers 2048 and 20 are owner decisions of 2026-11-06):

- `list_unsubscribe`: a tuple of at most two URIs without angle brackets,
  one `https://` and/or one plain `mailto:addr` (lower-case scheme, no query,
  no userinfo, no port above 65535); printable ASCII, no space, none of
  `< > " \\ ,`; at most 2048 characters each, and short enough that its
  header line stays within RFC 5322's 998 characters. The message must have
  exactly one recipient.
- `list_unsubscribe_post`: a real `bool`; true only with an `https` URI.
- `in_reply_to`, `references`: tuples of strict RFC 5322 `msg-id`
  (`<dot-atom@dot-atom-or-[literal]>`, ASCII, no obsolete forms), no
  duplicates, at most 20 each.
"""

from __future__ import annotations

import re
from collections.abc import Callable

from saas_os.core.email.errors import InvalidEmailAddressError, InvalidEmailHeaderError
from saas_os.core.email.provider import EmailMessage

MAX_URI_LENGTH = 2048
MAX_MESSAGE_IDS = 20
# RFC 5322 section 2.1.1: a line is at most 998 characters (before the CRLF).
# A URI or a message id cannot be folded, so it travels alone on a line, led
# by one folding space; `<uri>,` is the longest form it takes.
_MAX_UNFOLDABLE_TOKEN = 997

LIST_UNSUBSCRIBE = "List-Unsubscribe"
LIST_UNSUBSCRIBE_POST = "List-Unsubscribe-Post"
IN_REPLY_TO = "In-Reply-To"
REFERENCES = "References"
# The complete set of header names this module can ever emit.
HEADER_NAMES = (LIST_UNSUBSCRIBE, LIST_UNSUBSCRIBE_POST, IN_REPLY_TO, REFERENCES)
ONE_CLICK_VALUE = "List-Unsubscribe=One-Click"

_URI_CHARACTERS = re.compile(r"[!-~]+")  # printable ASCII, no space; used with fullmatch()
_URI_FORBIDDEN = ("<", ">", '"', "\\", ",")
_HTTPS_URI = re.compile(
    r"https://(?P<host>[A-Za-z0-9](?:[A-Za-z0-9.-]*[A-Za-z0-9])?)"
    r"(?::(?P<port>[0-9]{1,5}))?(?P<rest>[/?#].*)?"
)  # used with fullmatch(): a host and nothing before it, so no userinfo
_MAILTO_PREFIX = "mailto:"
_ATEXT = r"[A-Za-z0-9!#$%&'*+/=?^_`{|}~-]"
_DOT_ATOM = rf"{_ATEXT}+(?:\.{_ATEXT}+)*"
_NO_FOLD_LITERAL = r"\[[\x21-\x5a\x5e-\x7e]*\]"
# RFC 5322 section 3.6.4 `msg-id` without CFWS or the obsolete forms.
_MESSAGE_ID = re.compile(rf"<{_DOT_ATOM}@(?:{_DOT_ATOM}|{_NO_FOLD_LITERAL})>")  # fullmatch()

AddressValidator = Callable[[str], None]


def _refuse(message: str) -> InvalidEmailHeaderError:
    return InvalidEmailHeaderError(message)


def _has_control_character(value: str) -> bool:
    """CR, LF, NUL and every other C0 control and DEL (the issue asks for CR,
    LF and NUL; a vertical tab or form feed is a line break to some parsers)."""
    return any(ord(character) < 0x20 or ord(character) == 0x7F for character in value)


def _check_tuple(name: str, value: object) -> tuple[str, ...]:
    if not isinstance(value, tuple) or not all(isinstance(item, str) for item in value):
        raise _refuse(f"{name} must be a tuple of strings.")
    return value


def _check_uri(uri: str, validate_address: AddressValidator) -> str:
    """Return the URI's scheme (`https` or `mailto`) or raise."""
    if not uri:
        raise _refuse("List-Unsubscribe URI must not be empty.")
    if _has_control_character(uri):
        raise _refuse("List-Unsubscribe URI contains a forbidden control character.")
    if not _URI_CHARACTERS.fullmatch(uri):
        raise _refuse("List-Unsubscribe URI must be printable ASCII without spaces.")
    if len(uri) > MAX_URI_LENGTH:
        raise _refuse(f"List-Unsubscribe URI is longer than {MAX_URI_LENGTH} characters.")
    if len(f"<{uri}>,") > _MAX_UNFOLDABLE_TOKEN:
        raise _refuse("List-Unsubscribe URI does not fit in one header line (998 characters).")
    if any(forbidden in uri for forbidden in _URI_FORBIDDEN):
        raise _refuse("List-Unsubscribe URI contains a character that is not allowed in it.")
    if uri.startswith(_MAILTO_PREFIX):
        address = uri[len(_MAILTO_PREFIX) :]
        if "?" in address or "%" in address:
            raise _refuse("List-Unsubscribe mailto URI must be the plain form mailto:address.")
        try:
            validate_address(address)
        except InvalidEmailAddressError:
            raise _refuse("List-Unsubscribe mailto URI does not hold a valid address.") from None
        return "mailto"
    match = _HTTPS_URI.fullmatch(uri)
    if match is None:
        raise _refuse("List-Unsubscribe URI must be an https:// URI or a mailto: URI.")
    port = match.group("port")
    if port is not None and not 0 < int(port) <= 65535:
        raise _refuse("List-Unsubscribe URI has an invalid port.")
    return "https"


def _check_message_ids(name: str, ids: tuple[str, ...]) -> None:
    if len(ids) > MAX_MESSAGE_IDS:
        raise _refuse(f"{name} holds more than {MAX_MESSAGE_IDS} message ids.")
    for item in ids:
        if _has_control_character(item):
            raise _refuse(f"{name} contains a forbidden control character.")
        if not _MESSAGE_ID.fullmatch(item) or not item.isascii():
            raise _refuse(f"{name} holds a value that is not a valid <id@host> message id.")
        if len(item) > _MAX_UNFOLDABLE_TOKEN:
            raise _refuse(f"{name} holds a message id that does not fit in one header line.")
    if len(set(ids)) != len(ids):
        raise _refuse(f"{name} holds a duplicate message id.")


def validate_list_headers(message: EmailMessage, *, validate_address: AddressValidator) -> None:
    """Raise `InvalidEmailHeaderError` unless the four header fields of
    `message` are well formed (module docstring). `validate_address` checks a
    `mailto:` address (injected: `service.py` owns the address rules)."""
    uris = _check_tuple("list_unsubscribe", message.list_unsubscribe)
    in_reply_to = _check_tuple("in_reply_to", message.in_reply_to)
    references = _check_tuple("references", message.references)
    if not isinstance(message.list_unsubscribe_post, bool):
        raise _refuse("list_unsubscribe_post must be a bool.")

    if uris:
        if len(message.to) != 1:
            raise _refuse("list_unsubscribe requires exactly one recipient.")
        schemes = [_check_uri(uri, validate_address) for uri in uris]
        if len(set(schemes)) != len(schemes):
            raise _refuse("list_unsubscribe takes at most one https and one mailto URI.")
        if message.list_unsubscribe_post and "https" not in schemes:
            raise _refuse("list_unsubscribe_post requires an https List-Unsubscribe URI.")
    elif message.list_unsubscribe_post:
        raise _refuse("list_unsubscribe_post requires an https List-Unsubscribe URI.")

    _check_message_ids("in_reply_to", in_reply_to)
    _check_message_ids("references", references)


def refuse_unsafe_header_values(message: EmailMessage) -> None:
    """The adapters' own check, run before any I/O: CR, LF and NUL (and non-ASCII) in any
    of the four fields, and the shape that makes the emitted headers
    unambiguous (a tuple of strings, a `bool`, one-click only with an `https`
    URI). Not the full validation of `validate_list_headers()`: the service
    owns that; this is the backstop for a caller of `provider.send()`."""
    for name, value in (
        ("list_unsubscribe", message.list_unsubscribe),
        ("in_reply_to", message.in_reply_to),
        ("references", message.references),
    ):
        for item in _check_tuple(name, value):
            if _has_control_character(item):
                raise _refuse(f"{name} contains a forbidden control character.")
            if not item.isascii():
                # Headers are written as ASCII; refuse here rather than fail
                # with a raw encoding error mid-send.
                raise _refuse(f"{name} must be ASCII.")
    if not isinstance(message.list_unsubscribe_post, bool):
        raise _refuse("list_unsubscribe_post must be a bool.")
    if message.list_unsubscribe_post and not _has_https(message.list_unsubscribe):
        raise _refuse("list_unsubscribe_post requires an https List-Unsubscribe URI.")


def _has_https(uris: tuple[str, ...]) -> bool:
    return any(uri.startswith("https://") for uri in uris)


def message_headers(message: EmailMessage) -> dict[str, str]:
    """The headers to emit for `message`, name to single-line value: the
    complete, closed result both adapters use. Empty when no field is set.
    A function of the message alone (the Resend body and its idempotency key
    depend on that)."""
    headers: dict[str, str] = {}
    if message.list_unsubscribe:
        headers[LIST_UNSUBSCRIBE] = ", ".join(f"<{uri}>" for uri in message.list_unsubscribe)
        if message.list_unsubscribe_post and _has_https(message.list_unsubscribe):
            headers[LIST_UNSUBSCRIBE_POST] = ONE_CLICK_VALUE
    if message.in_reply_to:
        headers[IN_REPLY_TO] = " ".join(message.in_reply_to)
    if message.references:
        headers[REFERENCES] = " ".join(message.references)
    return headers
