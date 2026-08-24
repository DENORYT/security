"""Command-line interface for the local WAF risk scorer."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any

from .engine import HTTPRequest, build_default_policy


def _request_from_mapping(payload: dict[str, Any]) -> HTTPRequest:
    method = payload.get("method")
    path = payload.get("path")
    if not isinstance(method, str) or not isinstance(path, str):
        raise ValueError("Request JSON requires string fields 'method' and 'path'")
    headers = payload.get("headers", {})
    if not isinstance(headers, dict) or not all(isinstance(key, str) and isinstance(value, str) for key, value in headers.items()):
        raise ValueError("'headers' must be an object with string keys and values")
    return HTTPRequest(
        method=method,
        path=path,
        query=str(payload.get("query", "")),
        headers=headers,
        body=str(payload.get("body", "")),
    )


def main() -> int:
    parser = argparse.ArgumentParser(description="Score a local HTTP request using the defensive WAF lab policy.")
    parser.add_argument("--request", required=True, type=Path, help="Path to a JSON request fixture")
    args = parser.parse_args()
    try:
        payload = json.loads(args.request.read_text(encoding="utf-8"))
        if not isinstance(payload, dict):
            raise ValueError("Request JSON must be an object")
        decision = build_default_policy().evaluate(_request_from_mapping(payload))
    except (OSError, ValueError, json.JSONDecodeError) as error:
        parser.error(str(error))
    print(json.dumps(decision.to_dict(), indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
