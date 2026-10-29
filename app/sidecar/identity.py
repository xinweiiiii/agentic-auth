"""The sidecar's agent identity: an Ed25519 key that signs the two small tokens the identity
contract defines. Present only when the operator configured
``agent_name`` and ``identity_key_path`` together.

The key never leaves this process and never appears in a log or repr.
"""

from __future__ import annotations

from app.sdk.identity import AgentKey
from app.sidecar.config import SidecarConfig, SidecarConfigError


class SidecarIdentity:
    def __init__(self, agent_name: str, key: AgentKey, *, issuer: str = "agentic-auth") -> None:
        self._agent = agent_name
        self._key = key
        self._issuer = issuer

    def actor_token(self, subject_token: str) -> str:
        return self._key.actor_token(self._agent, subject_token, aud=self._issuer)

    def identity_assertion(self, grant: str, audience: str) -> str:
        return self._key.identity_assertion(self._agent, grant, audience)

    def __repr__(self) -> str:  # pragma: no cover - never print the key
        return f"SidecarIdentity(agent={self._agent!r})"


def load_identity(config: SidecarConfig) -> SidecarIdentity | None:
    if not config.agent_name or not config.identity_key_path:
        return None
    try:
        key = AgentKey.load(config.identity_key_path)
    except Exception as exc:  # a sidecar that cannot sign must not start permissive
        raise SidecarConfigError(f"cannot load identity key: {type(exc).__name__}") from exc
    return SidecarIdentity(config.agent_name, key)
