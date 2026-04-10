#!/usr/bin/env python3

import argparse
import base64
import json
import subprocess
import sys
import time


MAX_RETRIES = 3
BACKOFF_SECONDS = [5, 15, 30]


def upload(profile_path: str, api_url: str) -> str | None:
    """Upload a profile and return the JWT response, or None on failure."""
    result = subprocess.run(
        [
            "curl",
            "--silent",
            "--show-error",
            "--fail",
            "--max-time", "60",
            api_url,
            "-X", "POST",
            "-H", "Accept: application/vnd.firefox-profiler+json;version=1.0",
            "--data-binary", f"@{profile_path}",
        ],
        capture_output=True,
        text=True,
    )
    if result.returncode != 0:
        print(f"curl failed (exit {result.returncode}): {result.stderr.strip()}", file=sys.stderr)
        return None
    resp = result.stdout.strip()
    if not resp:
        print("empty response from Firefox Profiler API", file=sys.stderr)
        return None
    return resp


def parse_token(resp: str) -> str:
    parts = resp.split(".")
    if len(parts) != 3:
        raise SystemExit(f"unexpected Firefox Profiler response: {resp!r}")

    payload = parts[1]
    if len(payload) % 4:
        payload += "=" * (4 - len(payload) % 4)

    decoded = json.loads(base64.urlsafe_b64decode(payload))
    token = decoded.get("profileToken")
    if not token:
        raise SystemExit(f"missing profileToken in Firefox response: {decoded!r}")
    return token


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Upload a samply profile to Firefox Profiler and print the public URL."
    )
    parser.add_argument("profile_path")
    parser.add_argument(
        "--api-url",
        default="https://api.profiler.firefox.com/compressed-store",
    )
    args = parser.parse_args()

    for attempt in range(MAX_RETRIES):
        resp = upload(args.profile_path, args.api_url)
        if resp is not None:
            token = parse_token(resp)
            print(f"https://profiler.firefox.com/public/{token}")
            return 0

        if attempt < MAX_RETRIES - 1:
            wait = BACKOFF_SECONDS[attempt]
            print(f"Retrying in {wait}s (attempt {attempt + 2}/{MAX_RETRIES})...", file=sys.stderr)
            time.sleep(wait)

    print("Failed to upload after all retries", file=sys.stderr)
    return 1


if __name__ == "__main__":
    sys.exit(main())
