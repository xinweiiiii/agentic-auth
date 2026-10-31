# End-to-end walkthrough notebook

`customer_walkthrough.ipynb` is the product from the outside. A platform team at a fictional
bank takes three agents through these steps, using only the SDK (`agentic_auth.sdk`), as a
customer would:

1. declaring what each agent is allowed to do
2. consent
3. delegation
4. a privileged call
5. an attempted prompt injection
6. an audit review
7. a CI gate
8. a revocation
9. an outage

Every cell asserts its own outcome, so the notebook is also a test: if it runs clean, the
behaviour it documents is the behaviour you get. The checked-in copy keeps its outputs, so
you can read it without running anything.

It is also the source of the documentation site's **End-to-end walkthrough** page, which the
docs repository generates from this file at a pinned release tag.

## Run it

```bash
pip install 'authzai[notebook]'      # the product, embedded mode, and Jupyter
cd examples/e2e-notebook
jupyter lab customer_walkthrough.ipynb
```

From a checkout, use `pip install -e '.[notebook]'` instead.

You need no Docker, database, Redis server or open ports. Choose "Restart kernel and run all
cells". To run it headless, as CI would:

```bash
pip install nbclient
python - <<'PY'
import nbformat
from nbclient import NotebookClient
nb = nbformat.read("customer_walkthrough.ipynb", as_version=4)
NotebookClient(nb, timeout=300, resources={"metadata": {"path": "."}}).execute()
PY
```

Every run starts from an empty control plane and leaves nothing behind.

## What is real and what stands in

`local_stack.py` runs everything on `agentic_auth.embedded`: the control plane inside the
notebook's process, reached through an in-process transport.

What is real:

- **The control plane.** It is the actual FastAPI app, decision point, token exchange and
  audit log a deployment runs. It runs on SQLite and an in-process Redis instead of
  PostgreSQL and a Redis server. `tests/conformance` holds embedded mode to the same
  decisions as a deployment.
- **Append-only audit storage.** It is enforced in the store by a trigger, so §14's
  demonstration is a demonstration rather than a claim. A deployment has the same trigger in
  PostgreSQL, and also runs as a role granted only `SELECT, INSERT`.
- **The tool server.** It is a plain Starlette app guarded by `agentic_auth.verify`, the same
  verifier library a customer puts in front of their own MCP tools.
- **Every decision, token, record, mint and revocation.** Nothing is stubbed.

What stands in for infrastructure a customer already owns:

- **`DOCUMENTS`.** These are the `/.well-known/oauth-protected-resource` documents real MCP
  hosts publish (RFC 9728), which manifest reconciliation reads. A host with no document,
  such as `down.internal`, is unreachable, so the notebook can show what that does.
- **`stack.idp`.** This is the company identity provider that enrollment binds an agent to.

**Embedded mode is for development and testing only.** The first cell's warning says so, and
every decision it records is labelled `deployment: embedded`.

## Files

| File | What it is |
|---|---|
| `customer_walkthrough.ipynb` | The walkthrough. Start here. |
| `local_stack.py` | The local deployment: embedded control plane, capability documents, tool server, IdP. |

## If a cell fails

- **`ImportError: ... needs the 'embedded' extra`.** Install `authzai[notebook]`, which
  includes it.
- **A hop fails with `GRANT_EXPIRED` at the tool server.** Hop tokens live 60 seconds by
  design. Re-run the cell that minted the grant, or the whole notebook.
