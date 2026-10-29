"""Sustained multi-hop load, reporting p50/p95/p99 **per hop**.

Per hop, not per chain: a regression needs to be attributable to a specific hop, and a
chain-level average hides the one hop that got slow.

    locust -f tests/load/multi_hop.py --headless -u 50 -r 10 -t 2m \\
        --host http://localhost:8000

Target: p95 added latency per hop < 15 ms with a warm decision cache. The first
iteration of each user warms the cache; the reported numbers include it, so run long
enough for it to wash out.
"""

from __future__ import annotations

import os

from locust import HttpUser, between, task

ADMIN_TOKEN = os.environ.get("AGENTIC_AUTH_ADMIN_TOKEN", "dev-admin-token")
SCOPE = os.environ.get("LOAD_SCOPE", "orchestrator")
USER_SUB = "user:loadtest"

GRANT_TYPE = "urn:ietf:params:oauth:grant-type:token-exchange"
JWT_TOKEN_TYPE = "urn:ietf:params:oauth:token-type:jwt"

# (caller, target, data_class) for each hop of the standard 4-agent chain. The caller is
# whoever HOLDS the token at that point — the agent it was issued to.
CHAIN = [
    (USER_SUB, "agent://kb-search", "kb.internal"),
    ("agent://kb-search", "agent://summarizer", "account.read"),
    ("agent://summarizer", "agent://notifier", "account.write"),
]
# Phase 4: the privileged tool call at the end of the chain, with a transaction mint. Named
# separately so the common path and the privileged path get their own percentile rows.
PRIVILEGED = ("agent://notifier", "mcp://accounts.internal/close_account", "account.write")
PRIVILEGED_PARAMS = {"account_id": "acc-load", "reason": "load test"}


# Phase 5. The guarantee level this driver reports. Override with
# AGENTIC_AUTH_LOAD_GUARANTEE=connector to measure a boundary-mode deployment; the
# decision cost is the same, but the audit rows then say what was actually enforced.
GUARANTEE = os.environ.get("AGENTIC_AUTH_LOAD_GUARANTEE", "full")


class MultiHopUser(HttpUser):
    """One consent, then a full chain, repeatedly."""

    wait_time = between(0.1, 0.5)

    def on_start(self) -> None:
        self.admin = {"Authorization": f"Bearer {ADMIN_TOKEN}"}

    def _consent(self) -> tuple[str, str] | None:
        with self.client.post(
            "/v1/consent",
            headers=self.admin,
            json={"scope": SCOPE, "user_sub": USER_SUB},
            name="POST /v1/consent",
            catch_response=True,
        ) as r:
            if r.status_code != 201:
                r.failure(f"consent failed: {r.status_code} {r.text[:200]}")
                return None
            body = r.json()
            return body["session_id"], body["root_grant"]

    @task
    def run_chain(self) -> None:
        started = self._consent()
        if started is None:
            return
        session_id, token = started

        for index, (caller, target, data_class) in enumerate(CHAIN, start=1):
            # Each hop is named separately so the percentile tables are per hop.
            with self.client.post(
                "/v1/authorize",
                headers={"Authorization": f"Bearer {token}"},
                json={
                    "session_id": session_id,
                    "caller": caller,
                    "target": target,
                    "data_class": data_class,
                    # Phase 5: mandatory on the request. The SDK path is in the
                    # call path and decides every hop, so `full`.
                    "guarantee": GUARANTEE,
                },
                name=f"POST /v1/authorize [hop {index}]",
                catch_response=True,
            ) as r:
                if r.status_code != 200:
                    r.failure(f"authorize failed: {r.status_code}")
                    return
                if r.json()["outcome"] != "allow":
                    r.failure(f"unexpected deny at hop {index}: {r.json().get('reason')}")
                    return
                # The exchange spends exactly this recorded decision.
                action_id = r.json()["action_id"]

            with self.client.post(
                "/v1/token/exchange",
                data={
                    "grant_type": GRANT_TYPE,
                    "subject_token": token,
                    "subject_token_type": JWT_TOKEN_TYPE,
                    "resource": target,
                    "scope": data_class,
                    "action_id": action_id,
                },
                name=f"POST /v1/token/exchange [hop {index}]",
                catch_response=True,
            ) as r:
                if r.status_code != 200:
                    r.failure(f"exchange failed at hop {index}: {r.status_code}")
                    return
                token = r.json()["access_token"]

        # Phase 4: the privileged hop — authorize, exchange, then mint the transaction token.
        caller, target, data_class = PRIVILEGED
        with self.client.post(
            "/v1/authorize",
            headers={"Authorization": f"Bearer {token}"},
            json={
                "session_id": session_id,
                "caller": caller,
                "target": target,
                "data_class": data_class,
                "guarantee": GUARANTEE,
            },
            name="POST /v1/authorize [privileged]",
            catch_response=True,
        ) as r:
            if r.status_code != 200 or r.json()["outcome"] != "allow":
                r.failure(f"privileged authorize failed: {r.status_code} {r.text[:120]}")
                return
            priv_action_id = r.json()["action_id"]
            transaction_required = r.json().get("transaction_required", False)
        with self.client.post(
            "/v1/token/exchange",
            data={
                "grant_type": GRANT_TYPE,
                "subject_token": token,
                "subject_token_type": JWT_TOKEN_TYPE,
                "resource": target,
                "scope": data_class,
                "action_id": priv_action_id,
            },
            name="POST /v1/token/exchange [privileged]",
            catch_response=True,
        ) as r:
            if r.status_code != 200:
                r.failure(f"privileged exchange failed: {r.status_code}")
                return
            tool_token = r.json()["access_token"]
        if transaction_required:
            with self.client.post(
                "/v1/token/transaction",
                headers={"Authorization": f"Bearer {tool_token}"},
                json={"params": PRIVILEGED_PARAMS},
                name="POST /v1/token/transaction [privileged]",
                catch_response=True,
            ) as r:
                if r.status_code != 200:
                    r.failure(f"transaction mint failed: {r.status_code} {r.text[:120]}")
                    return

        # One query, full chain: the deepest action's delegation path, back to the
        # consenting human. Named on its own so locust reports it as its own percentile row.
        with self.client.get(
            f"/v1/audit/actions/{action_id}/chain",
            headers=self.admin,
            name="GET /v1/audit/actions/[id]/chain",
            catch_response=True,
        ) as r:
            if r.status_code != 200:
                r.failure(f"chain query failed: {r.status_code}")
            elif not r.json()["complete"]:
                r.failure(f"chain incomplete: {r.json()['break']}")
