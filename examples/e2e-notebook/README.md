# End-to-end walkthrough notebook

`customer_walkthrough.ipynb` is the product from the outside: a platform team at a fictional
bank takes three agents from "here is what they are allowed to do" through consent,
delegation, a privileged call, an attempted prompt injection, an audit review, a CI gate, a
revocation and an outage — using only the SDK (`app.sdk`), as a customer would.

Every cell asserts its own outcome, so the notebook is also a test: if it runs clean, the
behaviour it documents is the behaviour you get. The checked-in copy keeps its outputs, so
it reads without running anything.

It is also the source of the documentation site's **End-to-end walkthrough** page
(`website/docs/tutorials/end-to-end-walkthrough.md`), which is generated from this file by
`cd website && npm run gen-walkthrough`. After changing and re-running the notebook,
regenerate that page in the same commit — the Docs build workflow fails if the two have
drifted apart.

## Run it

```bash
docker compose up -d                 # PostgreSQL + Redis, from the repository root
pip install -e '.[notebook]'       # the product, plus Jupyter
cd examples/e2e-notebook
jupyter lab customer_walkthrough.ipynb
```

Then "Restart kernel and run all cells". Headless, as CI would:

```bash
pip install nbclient
python - <<'PY'
import nbformat
from nbclient import NotebookClient
nb = nbformat.read("customer_walkthrough.ipynb", as_version=4)
NotebookClient(nb, timeout=300, resources={"metadata": {"path": "."}}).execute()
PY
```

The notebook uses its own PostgreSQL database (`agentic_auth_notebook`) and Redis index
(`9`), created on first run and truncated on every run, so it never touches development
data. It opens no ports and reaches no network.

## What is real and what stands in

`local_stack.py` runs four services as ASGI apps behind one `httpx` transport that routes
by host. Real:

- **the control plane** — the actual FastAPI app, on real PostgreSQL and Redis, running as
  the least-privileged database role it runs as in production (which is what makes §14's
  append-only demonstration a demonstration rather than a claim)
- **the tool server** — a plain Starlette app guarded by `app.verify`, the same verifier
  library a customer puts in front of their own MCP tools
- **every decision, token, record, mint and revocation** — nothing is stubbed

Standing in for infrastructure a customer already owns:

- **`CapabilitySource`** — the `/.well-known/oauth-protected-resource` documents real MCP
  hosts publish (RFC 9728), which manifest reconciliation reads. Includes `down.internal`,
  which answers 503, so the notebook can show what an unreachable capability source does.
- **`FakeIdp`** — the company identity provider that enrollment binds an agent to.

The issuer key is ephemeral (generated at startup), which is fine for one process and is
exactly what the startup warning in the first cell is telling you.

## Files

| File | What it is |
|---|---|
| `customer_walkthrough.ipynb` | The walkthrough. Start here. |
| `local_stack.py` | The local deployment: control plane, capability source, tool server, IdP. |

## If a cell fails

- **`ConnectionRefusedError` / `InvalidCatalogName`** — `docker compose up -d` first.
- **`InsufficientPrivilege` on the first cell** — the notebook creates a role and grants;
  the `app` role must be able to. The bundled `docker-compose.yml` gives it that.
- **`permission denied for table audit_decisions` outside §14** — §14 expects it. Anywhere
  else it means the grants in `_prepare_schema` did not run; drop the
  `agentic_auth_notebook` database and re-run.
- **A hop fails with `GRANT_EXPIRED` at the tool server** — hop tokens live 60 seconds by
  design. Re-run the cell that minted the grant, or the whole notebook.
