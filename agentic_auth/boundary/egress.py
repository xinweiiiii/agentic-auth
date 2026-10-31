"""The injected egress proxy — when the runtime is all you control (FR-013, FR-014).

**Use this when you own neither the agent, nor its tools, nor its connector
configuration, but you do own the runtime it executes in.** Inject this proxy, point the
runtime's egress at it, and the agent's only route out is through policy.

This is the one mode that cannot reuse the sidecar's transport, and the reason is worth
reading. ``agentic_auth/sidecar/app.py`` opens with: *"A reverse proxy rather than a
forward/CONNECT proxy: no TLS interception, no CA to trust in the agent runtime, no root
privileges."* That was the right Phase 2 call and still is — for a sidecar. FR-013
addresses the case where the agent's egress cannot be repointed at a reverse proxy at
all, which requires exactly the thing Phase 2 declined to build (research.md R10).

So it costs more, and the cost is stated rather than hidden:

- **A CA certificate must be installed in the agent's runtime trust store.** Distributing
  it is the operator's job; ``agentic-auth-boundary egress-ca`` emits one and an install
  snippet, and that is as far as automation goes.
- **The guarantee level is ``network``, not ``full``**, because the enforcement depends on
  trust material sitting in a runtime the integrator does not fully own.

Once a connection is intercepted the request is an ordinary HTTP request and
``enforce()`` runs on it unchanged. Only the transport here is new.

**Anything that cannot be inspected is refused.** Not allowed-by-default, not passed
through: a connection we cannot see into is a connection we cannot decide about, and this
whole product exists because "we could not tell, so we let it through" is how agents
exfiltrate data.
"""

from __future__ import annotations

import datetime as dt
import ipaddress
import logging
from dataclasses import dataclass, field

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

from agentic_auth.boundary.guarantee import Guarantee

logger = logging.getLogger(__name__)

# Weaker than `full` and `connector`, and the documentation says why: this mode depends
# on trust material installed in a runtime the integrator does not fully own.
GUARANTEE = Guarantee.NETWORK

# Why a call could not be inspected. Each one is a refusal, and each sends an operator
# somewhere different — which is the whole reason they are not one code.
UNINSPECTABLE_NO_CA = "EGRESS_NO_CA"
UNINSPECTABLE_NOT_TLS = "EGRESS_UNPARSEABLE"
UNINSPECTABLE_NO_LEAF = "EGRESS_NO_LEAF"

_CA_LIFETIME = dt.timedelta(days=825)
_LEAF_LIFETIME = dt.timedelta(days=90)


class Uninspectable(Exception):
    """This connection cannot be decided about, so it does not proceed."""

    def __init__(self, cause: str, detail: str) -> None:
        super().__init__(f"{cause}: {detail}")
        self.cause = cause
        self.detail = detail


@dataclass
class CertificateAuthority:
    """The CA whose certificate the operator installs in the agent's runtime.

    Generated rather than required at import so an operator can produce one with a
    single command, and so tests need no fixture files. A deployment that already has an
    internal CA should load that instead — ``from_pem`` exists for exactly that.
    """

    certificate: x509.Certificate
    private_key: rsa.RSAPrivateKey
    _leaves: dict[str, tuple[x509.Certificate, rsa.RSAPrivateKey]] = field(
        default_factory=dict, repr=False
    )

    @classmethod
    def generate(cls, *, common_name: str = "agentic-auth egress CA") -> CertificateAuthority:
        key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, common_name)])
        now = dt.datetime.now(dt.UTC)
        certificate = (
            x509.CertificateBuilder()
            .subject_name(subject)
            .issuer_name(subject)
            .public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now - dt.timedelta(minutes=5))
            .not_valid_after(now + _CA_LIFETIME)
            .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
            .sign(key, hashes.SHA256())
        )
        return cls(certificate=certificate, private_key=key)

    @classmethod
    def from_pem(cls, certificate_pem: bytes, key_pem: bytes) -> CertificateAuthority:
        return cls(
            certificate=x509.load_pem_x509_certificate(certificate_pem),
            private_key=serialization.load_pem_private_key(key_pem, password=None),  # type: ignore[arg-type]
        )

    def certificate_pem(self) -> bytes:
        """What the operator installs in the agent runtime's trust store."""
        return self.certificate.public_bytes(serialization.Encoding.PEM)

    def leaf_for(self, host: str) -> tuple[x509.Certificate, rsa.RSAPrivateKey]:
        """Mint (and cache) a certificate for one host, so the interception is invisible
        to an agent that trusts the CA.

        Raises :class:`Uninspectable` for a host no leaf can be minted for, which the
        caller turns into a refusal rather than a pass-through.
        """
        if not host:
            raise Uninspectable(UNINSPECTABLE_NO_LEAF, "no host to mint a certificate for")
        if host in self._leaves:
            return self._leaves[host]

        key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        now = dt.datetime.now(dt.UTC)
        try:
            san: x509.GeneralName = x509.IPAddress(ipaddress.ip_address(host))
        except ValueError:
            san = x509.DNSName(host)

        certificate = (
            x509.CertificateBuilder()
            .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, host)]))
            .issuer_name(self.certificate.subject)
            .public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now - dt.timedelta(minutes=5))
            .not_valid_after(now + _LEAF_LIFETIME)
            .add_extension(x509.SubjectAlternativeName([san]), critical=False)
            .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
            .sign(self.private_key, hashes.SHA256())
        )
        self._leaves[host] = (certificate, key)
        return self._leaves[host]


def parse_connect(line: str) -> tuple[str, int]:
    """``CONNECT host:port HTTP/1.1`` → ``(host, port)``.

    Anything else is uninspectable: this proxy speaks CONNECT, and a request it cannot
    parse is a request it cannot decide about.
    """
    parts = line.split()
    if len(parts) < 2 or parts[0].upper() != "CONNECT":
        raise Uninspectable(UNINSPECTABLE_NOT_TLS, f"not a CONNECT request: {line[:60]!r}")
    authority = parts[1]
    host, _, port = authority.rpartition(":")
    if not host or not port.isdigit():
        raise Uninspectable(UNINSPECTABLE_NOT_TLS, f"malformed authority {authority!r}")
    return host, int(port)


def inspect(ca: CertificateAuthority | None, connect_line: str) -> tuple[str, int]:
    """Decide whether this connection can be inspected at all, before anything proceeds.

    Returns the host and port when it can. Raises :class:`Uninspectable` when it cannot,
    naming the missing trust material so the operator-facing reason is actionable rather
    than "blocked" (FR-014).
    """
    if ca is None:
        raise Uninspectable(
            UNINSPECTABLE_NO_CA,
            "no CA is configured, so TLS cannot be inspected; install one in the agent "
            "runtime's trust store and configure it here (agentic-auth-boundary egress-ca)",
        )
    host, port = parse_connect(connect_line)
    ca.leaf_for(host)  # raises if no leaf can be minted
    return host, port


def refusal(error: Uninspectable) -> dict:
    """The operator-facing refusal. Names the missing trust material (FR-014)."""
    return {
        "error": {
            "code": "policy_denied",
            "message": error.detail,
            "details": {
                "reason": error.cause,
                "recoverable": False,
                "guarantee_level": GUARANTEE.value,
            },
        }
    }


def install_snippet(ca: CertificateAuthority) -> str:
    """What an operator has to do by hand. Documented, not automated (research.md R10):
    the step differs per runtime, and guessing wrong installs a CA in the wrong store."""
    return (
        "# Install the egress CA in the agent runtime's trust store.\n"
        "# This is the trust material FR-014 requires, and the reason this mode reports\n"
        "# guarantee_level=network rather than full.\n"
        "#\n"
        "# Debian/Ubuntu:\n"
        "#   cp egress-ca.pem /usr/local/share/ca-certificates/agentic-auth.crt\n"
        "#   update-ca-certificates\n"
        "# Alpine:\n"
        "#   cp egress-ca.pem /usr/local/share/ca-certificates/ && update-ca-certificates\n"
        "# Python (requests/httpx):\n"
        "#   export SSL_CERT_FILE=/path/to/egress-ca.pem\n"
        "# Node:\n"
        "#   export NODE_EXTRA_CA_CERTS=/path/to/egress-ca.pem\n"
    )


__all__ = [
    "GUARANTEE",
    "UNINSPECTABLE_NO_CA",
    "UNINSPECTABLE_NO_LEAF",
    "UNINSPECTABLE_NOT_TLS",
    "CertificateAuthority",
    "Uninspectable",
    "inspect",
    "install_snippet",
    "parse_connect",
    "refusal",
]
