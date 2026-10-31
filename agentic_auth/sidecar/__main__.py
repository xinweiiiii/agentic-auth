"""``agentic-auth-sidecar`` entrypoint.

Exits non-zero rather than starting when it cannot enforce. A sidecar that comes up
without a PDP or an upstream map looks healthy while doing nothing useful, which is the
worst of the available failure modes.
"""

from __future__ import annotations

import argparse
import logging
import socket
import sys

import uvicorn

from agentic_auth.observability import logs
from agentic_auth.sidecar.app import build_app
from agentic_auth.sidecar.config import SidecarConfigError, load


def main() -> int:
    parser = argparse.ArgumentParser(prog="agentic-auth-sidecar", description="Sidecar PEP")
    parser.add_argument(
        "--config", default=None, help="YAML/JSON config file; omit to read AGENTIC_AUTH_SIDECAR_*"
    )
    parser.add_argument("--log-level", default="info")
    args = parser.parse_args()

    logging.basicConfig(level=args.log_level.upper())
    # Structured, machine-parsable records with correlation fields.
    # Added after basicConfig so the JSON handler sits alongside the default stream handler
    # rather than replacing it, and a developer watching a terminal still sees plain lines.
    logs.configure()

    try:
        config = load(args.config)
    except SidecarConfigError as exc:
        print(f"sidecar: refusing to start: {exc}", file=sys.stderr)
        return 2
    except OSError as exc:
        print(f"sidecar: cannot read config: {exc}", file=sys.stderr)
        return 2

    # Bind-check before uvicorn so the failure is one clear line, not a traceback.
    probe = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    probe.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    try:
        probe.bind((config.host, config.port))
    except OSError as exc:
        print(f"sidecar: cannot bind {config.listen_addr}: {exc}", file=sys.stderr)
        return 2
    finally:
        probe.close()

    if config.observe_mode:
        logging.getLogger(__name__).warning(
            "OBSERVE MODE: denials are recorded but NOT enforced. Not a security posture."
        )

    uvicorn.run(build_app(config), host=config.host, port=config.port, log_level=args.log_level)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
