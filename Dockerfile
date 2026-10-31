# The control plane, built from the released wheel — never from the source tree, so the image
# runs exactly the artifact PyPI and the GitHub release carry, under the same provenance.
#
#   python -m build && docker build -t agentic-auth .
#   docker run -p 8099:8099 -e AGENTIC_AUTH_DATABASE_URL=... -e AGENTIC_AUTH_REDIS_URL=... agentic-auth
#
# Migrations ship in the image; run them once per deployment, before the first start:
#   docker run --rm -e AGENTIC_AUTH_DATABASE_URL=... agentic-auth alembic upgrade head

FROM python:3.12-slim AS wheels
COPY dist/ /dist/
RUN pip wheel --no-cache-dir --wheel-dir /wheels "$(ls /dist/authzai-*.whl)[server]"

FROM python:3.12-slim
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1
RUN --mount=type=bind,from=wheels,source=/wheels,target=/wheels \
    pip install --no-cache-dir --no-index --find-links /wheels "authzai[server]"
WORKDIR /srv
COPY alembic.ini ./
COPY migrations/ ./migrations/
USER 10001
EXPOSE 8099
HEALTHCHECK --interval=10s --timeout=3s --retries=3 \
    CMD ["python", "-c", "import urllib.request,sys; sys.exit(urllib.request.urlopen('http://127.0.0.1:8099/healthz', timeout=2).status != 200)"]
CMD ["uvicorn", "agentic_auth.main:app", "--host", "0.0.0.0", "--port", "8099"]
