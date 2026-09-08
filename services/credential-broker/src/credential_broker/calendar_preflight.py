"""Explicit read-only Google access check; not a delegated Gate execution proof."""

from __future__ import annotations

import argparse
import json
import re
from pathlib import Path

import httpx

from .client import read_secret

URL = "https://www.googleapis.com/calendar/v3/calendars/primary/events"
PARAMS = {"maxResults": "1", "fields": "kind"}


def check(token_file: Path, *, transport: httpx.BaseTransport | None = None) -> dict[str, object]:
    """Return only status, never event data, credentials or provider error text.

    The supplied token remains owned by its source. This function neither revokes
    it nor claims that deleting a Python reference annihilates it.
    """
    token = read_secret(token_file)
    if re.fullmatch(r"[A-Za-z0-9._~+/-]{1,8192}=*", token) is None:
        raise ValueError("invalid token file")
    with httpx.Client(
        transport=transport, trust_env=False, follow_redirects=False, timeout=10
    ) as client:
        with client.stream(
            "GET", URL, params=PARAMS, headers={"Authorization": "Bearer " + token}
        ) as response:
            status = response.status_code
            valid = False
            if status == 200:
                raw = bytearray()
                for chunk in response.iter_bytes():
                    raw.extend(chunk)
                    if len(raw) > 4096:
                        raise ValueError("unexpected response size")
                try:
                    valid = json.loads(raw) == {"kind": "calendar#events"}
                except (ValueError, UnicodeError):
                    pass
    return {
        "test": "google-calendar-read-only-access-preflight",
        "status": "PASS" if status == 200 and valid else "FAIL",
        "http_status": status,
        "delegated_flow_verified": False,
        "provider_write_attempted": False,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--token-file", type=Path, required=True)
    args = parser.parse_args()
    try:
        result = check(args.token_file)
    except (OSError, ValueError, httpx.HTTPError):
        result = {"test": "google-calendar-read-only-access-preflight", "status": "ERROR"}
    print(json.dumps(result))
    return 0 if result["status"] == "PASS" else 1


if __name__ == "__main__":
    raise SystemExit(main())
