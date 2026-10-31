# Contributing

Thanks for considering a contribution.

## Setting up

Requires Docker and Python 3.12+.

```bash
git clone https://github.com/xinweiiiii/agentic-auth
cd agentic-auth
docker compose up -d                 # PostgreSQL 16 + Redis 7
python -m venv .venv && source .venv/bin/activate
pip install -e '.[dev]'
```

`[dev]` includes every install option, `otel` among them. Parts of the suite import the
OpenTelemetry SDK directly. The product itself does not need it: the observability layer is
optional at runtime and degrades to a no-op without it. The tests that prove that do need it
installed.

The distribution is `authzai` and the import root is `agentic_auth`. The install options
(`client`, `drift`, `embedded`, `server`, `otel`, `all`) are in `pyproject.toml`.
`tests/packaging/` checks that each one imports only what it should, against the built wheel:

```bash
pytest -m packaging tests/packaging   # builds the wheels, installs each extra into a fresh venv
```

## Running the checks

The same four things CI runs:

```bash
pytest                      # the full suite, needs the containers up
ruff check .
ruff format --check .
mypy
```

`pytest` needs PostgreSQL and Redis reachable at the `docker compose` defaults. Tests
truncate between cases, so run them against a throwaway database, never a real one.

Three pre-existing `mypy` errors are expected on a clean checkout. CI does not gate on
them. Please do not add a fourth.

### Slower checks

Not run on pull requests, because they cannot fit a useful feedback loop:

```bash
mutmut run                  # mutation testing over the pure decision modules
pytest tests/load           # throughput, needs a stable environment to mean anything
```

## Making a change

- Branch from `main`.
- Keep the change focused. One concern per pull request.
- Add tests for success, validation, permission, and not-found cases where they apply.
- The decision path is the product. A change to `agentic_auth/services/pdp.py`,
  `agentic_auth/services/edge_rules.py`, or anything under `agentic_auth/verify/` needs a test that would
  fail without it.
- Run the checks above before pushing.

## Things that are deliberate

Before changing one of these, please open an issue — they look like oversights and are not:

- **Metric names are frozen.** `tests/unit/test_metric_compatibility.py` holds them to the
  contracts in `docs/contracts/metrics/`. Operators' dashboards depend on them. New
  families are additive.
- **Labels never carry identities.** No agent name, user subject, session id, or target in
  any metric label. This is structural, not a setting.
- **An allowed call that cannot be recorded is refused.** Never dispatched unrecorded.
- **`agentic_auth/verify/` imports no control plane.** It must stay installable with `pyjwt[crypto]`
  alone; `tests/unit/test_verify_imports.py` enforces the import graph.
- **The FastAPI upper bound in `pyproject.toml`** is load-bearing. See the comment there.

## Wire formats

`docs/` holds the normative contracts a third party implements against —
[canonicalization and the binding hash](docs/canonicalization.md), the [verifier
library](docs/verifier-library.md), and the machine-readable schemas in `docs/contracts/`.
The test suite validates the running code against those same files, so a change to one is
a change to both.

## Security

Do not open an issue for a suspected vulnerability. See [SECURITY.md](SECURITY.md).

## Licence

Contributions are accepted under the [Apache License 2.0](LICENSE).
