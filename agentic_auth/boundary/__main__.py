"""``agentic-auth-boundary`` — run a boundary adapter, or emit the egress CA.

Three subcommands, one per FR-14 rung that needs a process:

    agentic-auth-boundary mcp-proxy [config.yaml]   # connector mode
    agentic-auth-boundary egress-proxy [config.yaml]  # network mode (not available yet)
    agentic-auth-boundary egress-ca [--out DIR]     # the operator's trust material

The resource-side guard has no subcommand: it is middleware the integrator adds to their
own app, not a process we run.
"""

from __future__ import annotations

import logging
import sys
from pathlib import Path


def _usage() -> int:
    print(__doc__, file=sys.stderr)
    return 2


def _egress_ca(args: list[str]) -> int:
    from cryptography.hazmat.primitives import serialization

    from agentic_auth.boundary.egress import CertificateAuthority, install_snippet

    out = Path(args[1]) if len(args) > 1 else Path.cwd()
    out.mkdir(parents=True, exist_ok=True)
    ca = CertificateAuthority.generate()

    cert_path = out / "egress-ca.pem"
    key_path = out / "egress-ca-key.pem"
    cert_path.write_bytes(ca.certificate_pem())
    key_path.write_bytes(
        ca.private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        )
    )
    key_path.chmod(0o600)

    print(f"wrote {cert_path}")
    print(f"wrote {key_path}  (keep this private)")
    print()
    print(install_snippet(ca))
    return 0


def main(argv: list[str] | None = None) -> int:
    logging.basicConfig(level=logging.INFO)
    args = sys.argv[1:] if argv is None else argv
    if not args:
        return _usage()

    command, *rest = args
    if command == "egress-ca":
        return _egress_ca(args)

    if command in {"mcp-proxy", "egress-proxy"}:
        from agentic_auth.gateway.config import GatewayConfigError, load

        try:
            config = load(rest[0] if rest else None)
        except GatewayConfigError as exc:
            print(f"agentic-auth-boundary {command}: {exc}", file=sys.stderr)
            return 2

        if command == "mcp-proxy":
            from agentic_auth.boundary.mcp import build_app
        else:  # pragma: no cover - the transport needs a real socket
            print(
                "egress-proxy is not available yet: it needs a CONNECT-capable listener. "
                "`egress-ca` generates the CA it will use. Until then, use mcp-proxy, or "
                "the resource-side guard where you own the tool.",
                file=sys.stderr,
            )
            return 2

        import uvicorn

        uvicorn.run(build_app(config), host=config.host, port=config.port, log_level="info")
        return 0

    return _usage()


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
