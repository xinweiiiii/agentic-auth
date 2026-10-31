# authzai-compat

Deprecated `app.*` import aliases for [`authzai`](https://pypi.org/project/authzai/). It is
published for the 0.2.x line only and **removed in 0.3.0**.

0.1.x installed its code as a top-level package named `app`. That collided with the
application package of nearly every FastAPI or Flask project that installed it. From 0.2.0
everything lives under `agentic_auth`:

```python
from agentic_auth.sdk import AgenticAuthClient  # was: from app.sdk import AgenticAuthClient
```

```bash
uvicorn agentic_auth.main:app                    # was: uvicorn app.main:app
```

This package keeps the old imports working while you migrate. Each `app.<x>` resolves to the
same module object as `agentic_auth.<x>` and warns once:

```text
DeprecationWarning: 'app.sdk' is deprecated; import 'agentic_auth.sdk' (removed in 0.3.0)
```

## Install

```bash
pip install 'authzai[client]' authzai-compat
```

## Migrate

```bash
grep -rlE '\b(from|import) app\.' . | xargs sed -i.bak -E 's/\b(from|import) app\./\1 agentic_auth./g'
```

Then remove `authzai-compat`.

## If your project has its own `app` package

This package installs a top-level `app`. That is why it is opt-in rather than part of `authzai`.

When you run your project from its own directory, that directory comes first on `sys.path`, so
**your** `app` wins and these aliases are not reachable. In that case, migrate the imports
rather than installing this package.
