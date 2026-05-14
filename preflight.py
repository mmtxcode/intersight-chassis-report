#!/usr/bin/env python3
"""Preflight check for the Intersight report launcher.

Validates that the API key in .env can authenticate against Intersight,
and on success prints the account display Name on stdout. On failure,
prints a specific diagnostic to stderr and exits non-zero so the
launcher can surface the error to the user.

Exit codes:
  0  success — account name is on stdout
  2  .env / key-file configuration issue
  3  private-key loader failure
  4  network error reaching Intersight
  5  Intersight rejected the request (auth / role / URL)
  6  authenticated but no account Name returned
"""

import os
import sys
from pathlib import Path

import requests
from dotenv import load_dotenv

from chassis_report import DEFAULT_BASE_URL, load_private_key, sign_headers


def fail(code: int, msg: str) -> None:
    print(msg, file=sys.stderr)
    sys.exit(code)


def main() -> None:
    load_dotenv()
    key_id = os.environ.get("INTERSIGHT_API_KEY_ID", "").strip()
    key_file = os.environ.get("INTERSIGHT_API_KEY_FILE", "").strip()
    base_url = os.environ.get("INTERSIGHT_BASE_URL", DEFAULT_BASE_URL).rstrip("/")

    if not key_id or not key_file:
        fail(2, "INTERSIGHT_API_KEY_ID and INTERSIGHT_API_KEY_FILE must be set in .env")
    if not Path(key_file).is_file():
        fail(2, f"API key file not found at: {key_file}")

    try:
        private_key = load_private_key(key_file)
    except Exception as e:
        fail(3, f"Could not load API key from {key_file}: {e}")

    # The account Moid is the first segment of the API key ID; direct read
    # by Moid is the lowest-privilege call that confirms auth and returns
    # the account display name in one round trip.
    account_moid = key_id.split("/", 1)[0]
    url = f"{base_url}/api/v1/iam/Accounts/{account_moid}"
    headers = sign_headers("GET", url, b"", key_id, private_key)

    try:
        resp = requests.get(url, headers=headers, timeout=15)
    except requests.RequestException as e:
        fail(4, f"Network error contacting {base_url}: {e}")

    if resp.status_code != 200:
        try:
            body = resp.json()
            msg = body.get("message") or resp.text[:200]
        except ValueError:
            msg = resp.text[:200]
        fail(5, f"Intersight rejected the request: HTTP {resp.status_code} — {msg}")

    try:
        name = (resp.json().get("Name") or "").strip()
    except ValueError:
        fail(6, "Authenticated, but Intersight returned an unparseable response.")

    if not name:
        fail(6, "Authenticated, but Intersight returned no account Name.")

    print(name)


if __name__ == "__main__":
    main()
