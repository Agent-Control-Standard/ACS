#!/usr/bin/env python3
"""Assert that the deployed site serves each schema at the URI its $id declares.

A status code is not the property worth checking. A traversal that overwrites the root
schema still returns 200, and so does a truncated or stale document.
"""
from __future__ import annotations

import json
import sys
import time
import urllib.error
import urllib.request

# Pages fronts content through a CDN, so a fresh deployment can 404 briefly. curl's
# --retry does not cover a 404, which is why this polls explicitly.
ATTEMPTS = 6
DELAY_SECONDS = 10


def fetch(url: str) -> dict:
    request = urllib.request.Request(url, headers={"Cache-Control": "no-cache"})
    with urllib.request.urlopen(request, timeout=20) as response:
        return json.loads(response.read().decode("utf-8"))


def check(base: str, path: str) -> None:
    url = f"{base.rstrip('/')}/{path}"
    last: Exception | None = None
    for attempt in range(1, ATTEMPTS + 1):
        try:
            doc = fetch(url)
        except (urllib.error.URLError, json.JSONDecodeError) as error:
            last = error
            print(f"attempt {attempt}/{ATTEMPTS}: {url} not ready ({error})")
            time.sleep(DELAY_SECONDS)
            continue
        served = doc.get("$id")
        if served != url:
            raise SystemExit(f"::error::{url} serves $id {served!r}, expected its own URL")
        print(f"ok: {url} serves its own $id")
        return
    raise SystemExit(f"::error::{url} never became available: {last}")


def main(argv: list[str]) -> int:
    if len(argv) < 3:
        print("usage: verify_published.py <base-url> <path> [<path> ...]", file=sys.stderr)
        return 2
    for path in argv[2:]:
        check(argv[1], path)
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
