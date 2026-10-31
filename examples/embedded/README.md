# Embedded quickstart

`quickstart.py` runs the whole control plane inside one Python process, with no Docker,
database, Redis or open ports. It registers the drift fixture's three agents, consents as
`user:alice`, makes three narrowing hops, is refused a tool nobody consented to, and reads
the delegation chain back to Alice.

```bash
pip install 'authzai[embedded]'
python examples/embedded/quickstart.py
```

```text
allow 4 user:alice → agent://bank-assistant → agent://balance-agent → agent://support-agent
deny OUT_OF_SCOPE
chain user:alice → bank-assistant → balance-agent → support-agent
```

This is the real control plane: the same app, policy decision point, token exchange and
audit log a deployment runs. The differences are where it runs:

- it is in-process instead of behind a socket
- it uses SQLite instead of PostgreSQL
- it uses an in-process Redis

`cp.client()` is the same `AgenticAuthClient` you would point at a deployed control plane.

**Embedded mode is for development and testing only.** The signing keys and the policy
decision point run in the same process as the agent they constrain. The instance logs a
warning saying so when it starts, and labels every decision it records `deployment: embedded`.
For anything real, deploy the control plane with the sidecar, gateway or boundary adapter in
front of your agents.

`tests/embedded/test_quickstart_script.py` runs this file as published, with networking
disabled, so it cannot quietly go stale.
