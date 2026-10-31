"""``python -m agentic_auth.gateway`` / ``agentic-auth-gateway`` — run the shared gateway.

Mirrors ``agentic_auth/sidecar/__main__.py``: load, validate, run. A configuration error exits
non-zero before the socket is bound, because a gateway that comes up unable to enforce
looks healthy while forwarding everything — for every agent at once.
"""

from __future__ import annotations

import logging
import sys

from agentic_auth.gateway.app import build_app
from agentic_auth.gateway.config import GatewayConfigError, load


def main(argv: list[str] | None = None) -> int:
    logging.basicConfig(level=logging.INFO)
    args = sys.argv[1:] if argv is None else argv
    path = args[0] if args else None

    try:
        config = load(path)
    except GatewayConfigError as exc:
        print(f"agentic-auth-gateway: {exc}", file=sys.stderr)
        return 2

    import uvicorn

    uvicorn.run(build_app(config), host=config.host, port=config.port, log_level="info")
    return 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
