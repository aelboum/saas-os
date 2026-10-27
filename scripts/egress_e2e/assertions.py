"""ADR-0059 end-to-end assertions over the driver's three phases, the
destination's connection log and the proxy's access log.

`python assertions.py <results-dir>`; exits non-zero with every failure listed.
"""

from __future__ import annotations

import json
import sys
from collections.abc import Callable
from pathlib import Path

PATH_SECRETS = ("PATH-TOKEN", "QUERY-TOKEN")


def main(directory: Path) -> int:
    normal = json.loads((directory / "normal.json").read_text())
    resolver_down = json.loads((directory / "resolver_down.json").read_text())
    proxy_down = json.loads((directory / "proxy_down.json").read_text())
    dest = (directory / "dest-good.log").read_text().splitlines()
    dest_after_normal = int((directory / "dest-good.count").read_text())
    proxy_log = (directory / "proxy-access.log").read_text()
    failures: list[str] = []

    def expect(label: str, actual: object, expected: object) -> None:
        ok = expected(actual) if callable(expected) else actual == expected
        if not ok:
            failures.append(f"{label}: got {actual!r}")

    starts = lambda prefix: lambda value: str(value).startswith(prefix)  # noqa: E731

    # Normal: legitimate HTTPS through the proxy; every refusal by the application.
    expect("resolve good", normal["resolve"]["good"], "11.22.33.10")
    expect("resolve mixed", normal["resolve"]["mixed"], "10.0.0.5,11.22.33.10")
    expect("resolve missing", normal["resolve"]["missing"], starts("error:"))
    expect("resolve outside zone", normal["resolve"]["outside_zone"], starts("error:"))
    expect("direct connection", normal["direct"], starts("error:"))
    strict, hook = normal["strict"], normal["webhook"]
    expect("strict good", strict["good"], "status:204")
    expect("webhook good", hook["good"], "status:204")
    for key in ("mixed", "metadata", "ula6"):
        expect(f"strict {key}", strict[key], starts("EgressDestinationError:"))
        expect(f"webhook {key}", hook[key], "WebhookDestinationRejectedError")
    for key in ("missing", "outside_zone"):
        expect(f"strict {key}", strict[key], "EgressResolutionError:unresolved")
        expect(f"webhook {key}", hook[key], "WebhookDestinationUnresolvedError")
    expect("strict wrong cert", strict["wrong_cert"], starts("EgressTLSError:"))
    expect("webhook wrong cert", hook["wrong_cert"], starts("WebhookDeliveryError"))
    # The application opt-in for http:// cannot get past the proxy (port 443 only).
    expect(
        "http opt-in is refused by the proxy",
        normal["http_opt_in"],
        "WebhookDestinationRejectedError",
    )
    policy = normal["proxy_policy"]
    expect("proxy allows the fixture", policy["11.22.33.10:443"], starts("HTTP/1.1 200"))
    for target, answer in policy.items():
        if target != "11.22.33.10:443":
            expect(f"proxy refuses {target}", answer, starts("HTTP/1.1 403"))

    # The destination saw exactly the two legitimate requests, on the hostname.
    requests = [line for line in dest if line.startswith("request ")]
    expect(
        "destination requests",
        sorted(requests),
        [
            "request POST /hook/PATH-TOKEN?token=QUERY-TOKEN HTTP/1.1",
            "request POST /strict/PATH-TOKEN?token=QUERY-TOKEN HTTP/1.1",
        ],
    )
    expect(
        "destination SNI",
        sorted({line for line in dest if line.startswith("sni ")}),
        ["sni hooks.e2e.test"],
    )
    expect(
        "destination Host",
        sorted({line for line in dest if line.startswith("host ")}),
        ["host hooks.e2e.test"],
    )

    # Resolver down, then proxy down: every delivery fails closed and nothing
    # reaches the destination by any other path. A stopped resolver shows as
    # a failed lookup or, where queries time out instead of being refused
    # (Linux), as the delivery's deadline expiring: both are transient.
    def one_of(*options: str) -> Callable[[object], bool]:
        return lambda value: any(str(value).startswith(option) for option in options)

    for _phase, results, strict_expected, hook_expected in (
        (
            resolver_down,
            resolver_down,
            one_of("EgressResolutionError:unresolved", "EgressTimeoutError:deadline_expired"),
            one_of("WebhookDestinationUnresolvedError", "WebhookDeliveryError"),
        ),
        (
            proxy_down,
            proxy_down,
            one_of("EgressProxyUnavailableError:proxy_unavailable"),
            one_of("WebhookDeliveryError"),
        ),
    ):
        name = results["phase"]
        expect(f"{name} strict good", results["strict"]["good"], strict_expected)
        expect(f"{name} webhook good", results["webhook"]["good"], hook_expected)
        expect(f"{name} direct connection", results["direct"], starts("error:"))
    expect("resolver down: no answers", resolver_down["resolve"]["good"], starts("error:"))
    expect("proxy down: names still resolve", proxy_down["resolve"]["good"], "11.22.33.10")
    expect(
        "no connection after the normal phase",
        sum(line == "connection" for line in dest),
        dest_after_normal,
    )

    # No URL path or query in the proxy's log.
    for secret in PATH_SECRETS:
        expect(f"proxy log has no {secret}", secret in proxy_log, False)
    expect("proxy log records tunnels by IP", "CONNECT 11.22.33.10:443 200" in proxy_log, True)

    for failure in failures:
        print(f"FAIL: {failure}")
    print(f"{'FAILED' if failures else 'PASSED'}: {len(failures)} failure(s)")
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main(Path(sys.argv[1])))
