"""Forward newline-delimited Falco JSON alerts from stdin to CloudGuard.

Example: falco --json-output | python tools/falco_forwarder.py
"""
import json
import os
import sys
import time
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen


def main() -> int:
    api_key = os.environ.get("CLOUDGUARD_API_KEY")
    endpoint = os.environ.get("CLOUDGUARD_FALCO_ENDPOINT", "http://127.0.0.1:8000/api/falco/events")
    if not api_key:
        print("CLOUDGUARD_API_KEY is required", file=sys.stderr)
        return 2
    for line in sys.stdin:
        try:
            payload = json.loads(line)
            request = Request(
                endpoint,
                data=json.dumps(payload).encode("utf-8"),
                headers={"Content-Type": "application/json", "X-API-Key": api_key},
                method="POST",
            )
            with urlopen(request, timeout=10) as response:
                response.read()
        except (json.JSONDecodeError, HTTPError, URLError, TimeoutError) as exc:
            print(f"Falco forward failed: {exc}", file=sys.stderr)
            time.sleep(1)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
