"""Issue 224 (ADR-0057 amendment of 2026-11-07) -- the typed
`List-Unsubscribe`, `List-Unsubscribe-Post`, `In-Reply-To` and `References`
fields of `EmailMessage`: validation in `send_email()` and the adapters'
own backstop. Pure unit tests against `FakeEmailProvider`; the wire formats
are asserted in `test_smtp_provider_unit.py` and `test_resend_provider_unit.py`.
"""

from __future__ import annotations

import dataclasses

import pytest

from saas_os.core.email import InvalidEmailHeaderError as PublicInvalidEmailHeaderError
from saas_os.core.email.errors import InvalidEmailAddressError, InvalidEmailHeaderError
from saas_os.core.email.headers import (
    HEADER_NAMES,
    MAX_MESSAGE_IDS,
    MAX_URI_LENGTH,
    message_headers,
    refuse_unsafe_header_values,
)
from saas_os.core.email.provider import EmailMessage, FakeEmailProvider
from saas_os.core.email.service import send_email

HTTPS = "https://app.example.com/unsubscribe/opaque-token"
MAILTO = "mailto:unsubscribe@example.com"
MSG_ID = "<parent.1@mail.example.com>"
CANARY = "CANARYVALUE"


def _message(**overrides: object) -> EmailMessage:
    defaults: dict[str, object] = {
        "sender": "sender@example.com",
        "to": ("recipient@example.com",),
        "subject": "Test subject",
        "text_body": "Hello, world.",
    }
    defaults.update(overrides)
    return EmailMessage(**defaults)  # type: ignore[arg-type]


def _refused(**overrides: object) -> InvalidEmailHeaderError:
    provider = FakeEmailProvider()
    with pytest.raises(InvalidEmailHeaderError) as excinfo:
        send_email(_message(**overrides), provider=provider)
    assert provider.sent == []  # refused before any provider call
    return excinfo.value


def _assert_no_canary(error: BaseException) -> None:
    assert CANARY not in str(error)
    assert CANARY not in repr(error)
    assert error.__cause__ is None


# --- Shape of the public surface ----------------------------------------------


def test_the_fields_are_appended_with_inert_defaults() -> None:
    names = [f.name for f in dataclasses.fields(EmailMessage)]
    assert names[-4:] == ["list_unsubscribe", "list_unsubscribe_post", "in_reply_to", "references"]
    message = _message()
    assert message.list_unsubscribe == ()
    assert message.list_unsubscribe_post is False
    assert message.in_reply_to == ()
    assert message.references == ()
    assert message_headers(message) == {}


def test_positional_construction_of_the_existing_fields_still_works() -> None:
    message = EmailMessage("a@example.com", ("b@example.com",), "s", "t", None, None, {}, "<i@d>")
    assert message.message_id == "<i@d>"
    assert message.list_unsubscribe == ()


def test_the_message_stays_frozen() -> None:
    with pytest.raises(dataclasses.FrozenInstanceError):
        _message().list_unsubscribe = (HTTPS,)  # type: ignore[misc]


def test_the_error_is_an_additive_subclass_exported_publicly() -> None:
    assert PublicInvalidEmailHeaderError is InvalidEmailHeaderError
    assert issubclass(InvalidEmailHeaderError, InvalidEmailAddressError)


def test_the_new_values_are_not_in_repr() -> None:
    message = _message(
        list_unsubscribe=(f"https://example.com/{CANARY}",),
        list_unsubscribe_post=True,
        in_reply_to=(f"<{CANARY}@example.com>",),
        references=(f"<{CANARY}@example.com>",),
    )
    assert CANARY not in repr(message)
    assert "list_unsubscribe" not in repr(message)


# --- Acceptance ----------------------------------------------------------------


@pytest.mark.parametrize(
    ("overrides", "expected"),
    [
        ({"list_unsubscribe": (HTTPS,)}, {"List-Unsubscribe": f"<{HTTPS}>"}),
        ({"list_unsubscribe": (MAILTO,)}, {"List-Unsubscribe": f"<{MAILTO}>"}),
        (
            {"list_unsubscribe": (HTTPS, MAILTO)},
            {"List-Unsubscribe": f"<{HTTPS}>, <{MAILTO}>"},
        ),
        (
            {"list_unsubscribe": (MAILTO, HTTPS), "list_unsubscribe_post": True},
            {
                "List-Unsubscribe": f"<{MAILTO}>, <{HTTPS}>",
                "List-Unsubscribe-Post": "List-Unsubscribe=One-Click",
            },
        ),
        ({"in_reply_to": (MSG_ID,)}, {"In-Reply-To": MSG_ID}),
        (
            {"references": (MSG_ID, "<parent.2@mail.example.com>")},
            {"References": f"{MSG_ID} <parent.2@mail.example.com>"},
        ),
        ({"in_reply_to": ("<a@[192.0.2.1]>",)}, {"In-Reply-To": "<a@[192.0.2.1]>"}),
    ],
)
def test_valid_headers_are_accepted_and_rendered(
    overrides: dict[str, object], expected: dict[str, str]
) -> None:
    provider = FakeEmailProvider()
    message = _message(**overrides)
    send_email(message, provider=provider)
    assert provider.sent == [message]  # the Fake records the new fields
    assert message_headers(message) == expected


def test_all_four_headers_together_render_exactly_the_closed_set() -> None:
    message = _message(
        list_unsubscribe=(HTTPS,),
        list_unsubscribe_post=True,
        in_reply_to=(MSG_ID,),
        references=(MSG_ID,),
    )
    send_email(message, provider=FakeEmailProvider())
    assert tuple(sorted(message_headers(message))) == tuple(sorted(HEADER_NAMES))


def test_one_click_is_never_rendered_unless_asked_for() -> None:
    assert "List-Unsubscribe-Post" not in message_headers(_message(list_unsubscribe=(HTTPS,)))


def test_the_boundary_values_are_accepted() -> None:
    long_path = "/" + "a" * (900 - len("https://example.com/"))
    send_email(
        _message(
            list_unsubscribe=("https://example.com" + long_path,),
            references=tuple(f"<id{i}@example.com>" for i in range(MAX_MESSAGE_IDS)),
        ),
        provider=FakeEmailProvider(),
    )


# --- Refusals: list_unsubscribe --------------------------------------------------

_BAD_URIS = {
    "empty": "",
    "cr": f"https://example.com/{CANARY}\r",
    "lf": f"https://example.com/{CANARY}\n",
    "crlf-injection": f"https://example.com/{CANARY}\r\nBcc: attacker@evil.example",
    "nul": f"https://example.com/{CANARY}\x00",
    "control": f"https://example.com/{CANARY}\x01",
    "del": f"https://example.com/{CANARY}\x7f",
    "space": f"https://example.com/{CANARY} x",
    "tab": f"https://example.com/{CANARY}\tx",
    "non-ascii": f"https://example.com/{CANARY}é",
    "angle-open": f"https://example.com/{CANARY}<",
    "angle-close": f"https://example.com/{CANARY}>",
    "bracketed": f"<https://example.com/{CANARY}>",
    "double-quote": f'https://example.com/{CANARY}"',
    "backslash": f"https://example.com/{CANARY}\\",
    "comma": f"https://example.com/{CANARY},https://evil.example/x",
    "javascript": f"javascript:alert('{CANARY}')",
    "data": f"data:text/plain,{CANARY}",
    "file": f"file:///etc/{CANARY}",
    "http": f"http://example.com/{CANARY}",
    "ftp": f"ftp://example.com/{CANARY}",
    "upper-scheme": f"HTTPS://example.com/{CANARY}",
    "no-scheme": f"example.com/{CANARY}",
    "userinfo": f"https://user:{CANARY}@example.com/",
    "userinfo-lookalike": f"https://example.com@evil.example/{CANARY}",
    "no-host": f"https:///{CANARY}",
    "host-only-scheme": "https://",
    "bad-port": f"https://example.com:99999/{CANARY}",
    "zero-port": f"https://example.com:0/{CANARY}",
    "ipv6": f"https://[::1]/{CANARY}",
    "mailto-query": f"mailto:unsubscribe@example.com?subject={CANARY}",
    "mailto-percent": f"mailto:unsub%40example.com{CANARY}",
    "mailto-two-addresses": f"mailto:a@example.com,{CANARY}@example.com",
    "mailto-invalid": f"mailto:{CANARY}",
    "mailto-empty": "mailto:",
    "mailto-upper": f"MAILTO:{CANARY}@example.com",
    "too-long": f"https://example.com/{CANARY}" + "a" * MAX_URI_LENGTH,
    # Short of 2048 but too long for one RFC 5322 line (998 characters).
    "over-one-line": "https://example.com/" + "a" * 980 + CANARY,
}


@pytest.mark.parametrize("uri", list(_BAD_URIS.values()), ids=list(_BAD_URIS))
def test_bad_list_unsubscribe_uris_are_refused_without_echo(uri: str) -> None:
    _assert_no_canary(_refused(list_unsubscribe=(uri,)))


def test_a_string_instead_of_a_tuple_is_refused() -> None:
    # Iterating a str would yield characters; the type is checked first.
    _assert_no_canary(_refused(list_unsubscribe=f"https://example.com/{CANARY}"))
    _assert_no_canary(_refused(in_reply_to=f"<{CANARY}@example.com>"))
    _assert_no_canary(_refused(references=f"<{CANARY}@example.com>"))


def test_a_list_instead_of_a_tuple_is_refused() -> None:
    # A list is mutable after validation; the fields are tuples by contract.
    _refused(list_unsubscribe=[HTTPS])
    _refused(references=[MSG_ID])


def test_a_non_string_element_is_refused() -> None:
    _refused(list_unsubscribe=(b"https://example.com/x",))
    _refused(references=(None,))


def test_two_uris_of_the_same_scheme_are_refused() -> None:
    _refused(list_unsubscribe=(HTTPS, "https://other.example.com/u/1"))
    _refused(list_unsubscribe=(MAILTO, "mailto:other@example.com"))
    _refused(list_unsubscribe=(HTTPS, HTTPS))


def test_more_than_two_uris_are_refused() -> None:
    _refused(list_unsubscribe=(HTTPS, MAILTO, "mailto:third@example.com"))


@pytest.mark.parametrize(
    "recipients",
    [("a@example.com", "b@example.com"), ("a@example.com", "a@example.com")],
)
def test_list_unsubscribe_with_several_recipients_is_refused(recipients: tuple[str, ...]) -> None:
    error = _refused(to=recipients, list_unsubscribe=(HTTPS,))
    assert "recipient" in str(error)


def test_several_recipients_are_fine_without_list_unsubscribe() -> None:
    send_email(
        _message(to=("a@example.com", "b@example.com"), references=(MSG_ID,)),
        provider=FakeEmailProvider(),
    )


# --- Refusals: one-click ---------------------------------------------------------


def test_one_click_without_an_https_uri_is_refused() -> None:
    _refused(list_unsubscribe=(MAILTO,), list_unsubscribe_post=True)


def test_one_click_without_any_list_unsubscribe_is_refused() -> None:
    _refused(list_unsubscribe_post=True)


@pytest.mark.parametrize("value", ["List-Unsubscribe=One-Click", 1, "yes", None])
def test_one_click_must_be_a_real_bool(value: object) -> None:
    _refused(list_unsubscribe=(HTTPS,), list_unsubscribe_post=value)


# --- Refusals: In-Reply-To and References -------------------------------------------

_BAD_IDS = {
    "empty": "",
    "no-brackets": f"{CANARY}@example.com",
    "no-at": f"<{CANARY}>",
    "two-ats": f"<{CANARY}@a@example.com>",
    "empty-left": "<@example.com>",
    "empty-right": f"<{CANARY}@>",
    "cr": f"<{CANARY}@example.com>\r",
    "lf": f"<{CANARY}@example.com>\nBcc: attacker@evil.example",
    "nul": f"<{CANARY}\x00@example.com>",
    "control": f"<{CANARY}\x01@example.com>",
    "space": f"<{CANARY} x@example.com>",
    "two-ids-in-one": f"<{CANARY}@example.com> <b@example.com>",
    "comment": f"(c) <{CANARY}@example.com>",
    "non-ascii": f"<{CANARY}é@example.com>",
    "quote": f'<"{CANARY}"@example.com>',
    "leading-dot": f"<.{CANARY}@example.com>",
    "double-dot": f"<{CANARY}..x@example.com>",
    "trailing-dot": f"<{CANARY}.@example.com>",
    "bad-literal": f"<{CANARY}@[a b]>",
    "comma": f"<{CANARY},x@example.com>",
    "angle-nested": f"<<{CANARY}@example.com>>",
    "too-long": f"<{CANARY}@" + "a" * 1000 + ".example>",
}


@pytest.mark.parametrize("field", ["in_reply_to", "references"])
@pytest.mark.parametrize("identifier", list(_BAD_IDS.values()), ids=list(_BAD_IDS))
def test_bad_message_ids_are_refused_without_echo(field: str, identifier: str) -> None:
    _assert_no_canary(_refused(**{field: (identifier,)}))


@pytest.mark.parametrize("field", ["in_reply_to", "references"])
def test_too_many_message_ids_are_refused(field: str) -> None:
    ids = tuple(f"<id{i}@example.com>" for i in range(MAX_MESSAGE_IDS + 1))
    _refused(**{field: ids})


@pytest.mark.parametrize("field", ["in_reply_to", "references"])
def test_duplicate_message_ids_are_refused(field: str) -> None:
    _refused(**{field: (MSG_ID, MSG_ID)})


# --- Adapter backstop ----------------------------------------------------------


@pytest.mark.parametrize(
    "overrides",
    [
        {"list_unsubscribe": (f"https://example.com/{CANARY}\r\nBcc: x@evil.example",)},
        {"list_unsubscribe": (f"https://example.com/{CANARY}\n",)},
        {"list_unsubscribe": (f"https://example.com/{CANARY}\x00",)},
        {"in_reply_to": (f"<{CANARY}@example.com>\r\nBcc: x@evil.example",)},
        {"in_reply_to": (f"<{CANARY}\x00@example.com>",)},
        {"references": (f"<{CANARY}@example.com>\n",)},
        {"references": (f"<{CANARY}\x00@example.com>",)},
        {"references": (f"<{CANARY}é@example.com>",)},
        {"references": (f"<{CANARY}\x0b@example.com>",)},
        {"list_unsubscribe": (f"https://example.com/{CANARY}\x1b[2J",)},
    ],
)
def test_the_adapter_check_refuses_cr_lf_and_nul(overrides: dict[str, object]) -> None:
    with pytest.raises(InvalidEmailHeaderError) as excinfo:
        refuse_unsafe_header_values(_message(**overrides))
    _assert_no_canary(excinfo.value)


def test_the_adapter_check_refuses_one_click_without_an_https_uri() -> None:
    with pytest.raises(InvalidEmailHeaderError):
        refuse_unsafe_header_values(
            _message(list_unsubscribe=(MAILTO,), list_unsubscribe_post=True)
        )
    with pytest.raises(InvalidEmailHeaderError):
        refuse_unsafe_header_values(_message(list_unsubscribe_post=True))


def test_the_adapter_check_accepts_a_valid_message() -> None:
    refuse_unsafe_header_values(
        _message(list_unsubscribe=(HTTPS,), list_unsubscribe_post=True, references=(MSG_ID,))
    )


def test_one_click_is_emitted_only_with_an_https_uri_and_the_flag() -> None:
    """The rendering guard, independent of the validation above."""
    assert "List-Unsubscribe-Post" not in message_headers(
        _message(list_unsubscribe=(MAILTO,), list_unsubscribe_post=False)
    )
    assert "List-Unsubscribe-Post" not in message_headers(
        _message(list_unsubscribe=(MAILTO,), list_unsubscribe_post=True)
    )
    assert "List-Unsubscribe-Post" not in message_headers(_message(list_unsubscribe_post=True))
    assert (
        message_headers(_message(list_unsubscribe=(HTTPS,), list_unsubscribe_post=True))[
            "List-Unsubscribe-Post"
        ]
        == "List-Unsubscribe=One-Click"
    )


def test_metadata_is_not_a_header_channel() -> None:
    message = _message(metadata={"List-Unsubscribe": "<https://evil.example/>", "Bcc": "x@y.z"})
    assert message_headers(message) == {}
