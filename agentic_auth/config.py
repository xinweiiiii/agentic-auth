"""Runtime configuration, loaded from the environment (prefix ``AGENTIC_AUTH_``)."""

from __future__ import annotations

from functools import lru_cache

from pydantic_settings import BaseSettings, SettingsConfigDict

from agentic_auth import runtime


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_prefix="AGENTIC_AUTH_",
        env_file=".env",
        extra="ignore",
    )

    database_url: str = "postgresql+asyncpg://app:app@localhost:5432/agentic_auth"
    redis_url: str = "redis://localhost:6379/0"
    admin_token: str = "dev-admin-token"
    discovery_timeout_seconds: float = 5.0

    # -- runtime plane -------------------------------------------
    issuer: str = "agentic-auth"
    # Ed25519 private key, PEM. Empty in dev -> an ephemeral key is generated at
    # startup and logged as ephemeral. Never leave this empty in production.
    issuer_private_key: str = ""
    issuer_kid: str = ""
    hop_token_ttl_seconds: int = 60
    session_ttl_seconds: int = 1800
    decision_cache_ttl_seconds: int = 30

    # -- audit plane ---------------------------------------------
    # A read-only bearer for the audit endpoints, so an auditor never needs the admin
    # token that can register manifests or record consent. Empty disables it; the admin
    # token is always accepted.
    audit_read_token: str = ""
    # Bound on the audit append + commit. An allow whose record cannot be committed in
    # this window is refused rather than dispatched without a record.
    audit_write_timeout_seconds: float = 1.0
    metrics_enabled: bool = True

    # -- Phase 4: three independent controls ---------------
    # Each is gated so an integrator adopts the sidecar + token-exchange core first and
    # layers the rest on. With all three off, Phase 1-3 behaviour is unchanged.
    #
    # transaction_tokens_enabled: privileged tool calls need a call-bound transaction token
    #   (POST /v1/token/transaction). Off -> the route answers 404, decisions report
    #   transaction_required=false, the sidecar and SDK never buffer or mint.
    # taint_enforcement_enabled: TAINTED_INTO_PRIVILEGED is returned. Off -> taint is still
    #   derived, propagated and RECORDED so operators can tune before enforcing.
    # identity_required: the exchange requires an actor_token signed by the holder's pinned
    #   key, and refuses agents without a live trust anchor (AGENT_NOT_ENROLLED). Off by
    #   default because it refuses every agent that has not enrolled.
    transaction_tokens_enabled: bool = True
    taint_enforcement_enabled: bool = True
    identity_required: bool = False

    # Transaction-token lifetime, seconds. One privileged call, minted right before it.
    transaction_token_ttl_seconds: int = 30
    # Largest request body the sidecar / mint will canonicalize for binding. Over the cap is
    # refused, never forwarded unbound.
    max_privileged_body_bytes: int = 1_048_576

    # -- Phase 4: identity ------------------------------------------------------
    # Bearer that may begin/complete enrollment. Empty disables it; admin always works.
    enroll_token: str = ""
    enroll_challenge_ttl_seconds: int = 120
    # The organization's human IdP, for principal binding. All
    # three empty -> every completion is quarantined with PRINCIPAL_IDP_NOT_CONFIGURED.
    principal_idp_issuer: str = ""
    principal_idp_jwks_url: str = ""
    principal_idp_audience: str = ""
    # The ID-token claim that must equal "agent://<name>".
    principal_binding_claim: str = "agent"
    # How long an offline verifier may go without refreshing revocation state before it
    # refuses every identity as stale.
    revocation_freshness_seconds: int = 30

    # -- Phase 5: four independent workstreams ---------------
    # Same discipline as Phase 4: each control is gated, every default reproduces Phase 4
    # behaviour, and an integrator adopts the gateway, a boundary mode, step-up and cold
    # start in any order. With all of these off, Phase 1-4 behaviour is unchanged.
    #
    # consent_granularity_enabled: a session may consent to a SUBSET of the data classes its
    #   pinned policy declares. Off -> the consented set is the declared set, which is
    #   exactly Phase 2-4 semantics, and ConsentCreate.data_classes is rejected.
    #   This is what makes SCOPE_NOT_CONSENTED mean what its name says: with it off, that
    #   reason fires only for a data class the pinned policy never declared, which step-up
    #   must never grant.
    # step_up_enabled: a recoverable deny returns a challenge instead of a hard failure, and
    #   /v1/consent/step-up* are routed. Off -> those routes answer 404 and no decision
    #   carries a challenge.
    # sandbox_enabled: /v1/agents/{id}/sandbox* are routed. Off -> 404.
    consent_granularity_enabled: bool = False
    step_up_enabled: bool = False
    sandbox_enabled: bool = False

    # How long a step-up challenge may go unanswered. Consumed with GETDEL, so a second
    # answer fails even inside the window.
    step_up_challenge_ttl_seconds: int = 300
    # A sandbox observation run ends here whether or not the agent stopped, and the
    # proposal covers what was observed up to that point.
    sandbox_run_deadline_seconds: int = 300
    # Bound on the gateway's decision. Past it the call is REFUSED, never retried: a slow
    # decision is no decision. Matches the sidecar's control_plane_timeout_seconds
    # so the gateway is not less available than a sidecar against the same control plane.
    gateway_decision_deadline_ms: int = 2000
    # What the control plane records when an enforcement point predates the guarantee
    # field. Every such caller was per-hop, so `full` is accurate rather than a guess.
    default_guarantee_level: str = "full"

    # -- Phase 6: observability ------------------------------------
    # Off by default, so a Phase 1-5 deployment sees no change at all. When off, nothing is
    # exported, `agentic_auth.observability` never imports the OpenTelemetry SDK, and the existing
    # `/metrics` surface behaves exactly as before.
    #
    # telemetry_key is REQUIRED when telemetry is enabled. It keys both the identity
    # pseudonyms and the session-derived trace ids. Missing -> the exporter refuses to start
    # and logs once; the component still serves traffic. There is deliberately no fallback to
    # plaintext and none to an unkeyed digest: agent names are a small, enumerable space, so an
    # unkeyed digest is recovered by brute force by anyone holding the telemetry.
    #
    # telemetry_identity_disclosure: export real agent names and the act chain instead of
    # pseudonyms. Off by default; its state is itself exported as a gauge so an organization can
    # alert on any deployment that has it on. Metrics are unaffected either way — "labels never
    # carry identities" is absolute and has no opt-in.
    #
    # telemetry_allow_sample_ratio: the fraction of ALLOW spans kept. Refusals ignore it
    # entirely -- a denied, fail-closed, taint-blocked or unrecorded decision is always kept.
    telemetry_enabled: bool = False
    telemetry_key: str = ""
    telemetry_identity_disclosure: bool = False
    telemetry_allow_sample_ratio: float = 1.0

    def model_post_init(self, _context: object) -> None:
        """Refuse a configuration that cannot do what it claims.

        Step-up without consent granularity is the one combination that is not merely
        unusual but incoherent: the only recoverable deny reason is SCOPE_NOT_CONSENTED,
        and without granularity that reason fires only for a data class the pinned policy
        never declared — which a consent prompt must never grant. The endpoints
        would answer every request correctly and grant nothing, forever. Refusing at
        startup is cheaper than discovering that in production.
        """
        if self.step_up_enabled and not self.consent_granularity_enabled:
            raise ValueError(
                "step_up_enabled requires consent_granularity_enabled: without it the only "
                "recoverable deny reason (SCOPE_NOT_CONSENTED) fires only for a data class "
                "the pinned policy never declared, which step-up may never grant. Set "
                "AGENTIC_AUTH_CONSENT_GRANULARITY_ENABLED=true, or turn step-up off."
            )

    # NOTE: there is deliberately no server-side observe-mode setting. The PDP is
    # mode-blind — it always decides honestly and always records — so it cannot be a
    # deployment-wide kill switch. Observe mode belongs to the enforcement point, which
    # is the only component that knows whether it will act on a deny:
    # AGENTIC_AUTH_SIDECAR_OBSERVE_MODE, per sidecar. A server-side flag here would read
    # as fleet-wide while changing nothing, and would make `false` look like "enforcement
    # is on" while a sidecar was still forwarding denied calls.
    #
    # The same reasoning rules out a server-side telemetry observe-mode flag. Each enforcement
    # point configures its own telemetry under AGENTIC_AUTH_SIDECAR_TELEMETRY_*; a setting here
    # that read as fleet-wide while changing nothing in a sidecar's process would be worse than
    # no setting at all.


@lru_cache
def _environment_settings() -> Settings:
    return Settings()


def get_settings() -> Settings:
    """This process's settings, from the environment — or, inside an embedded control
    plane's request, that instance's own (agentic_auth/runtime.py)."""
    current = runtime.override()
    return current.settings if current is not None else _environment_settings()


# Tests and the notebook reset the environment-derived settings between scenarios.
get_settings.cache_clear = _environment_settings.cache_clear  # type: ignore[attr-defined]
