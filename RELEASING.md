# Releasing

A release is a tag. Pushing `vX.Y.Z` runs [`.github/workflows/release.yml`](.github/workflows/release.yml),
which builds, verifies, attests and publishes everything listed below. No manual uploads and
no repository secrets.

| Channel | What |
|---|---|
| PyPI | `authzai` and `authzai-compat`, wheel and sdist, with PEP 740 attestations |
| GitHub release | the same files, `SHA256SUMS`, and the CHANGELOG section as notes |
| GHCR | `ghcr.io/xinweiiiii/agentic-auth:X.Y.Z` (and `:latest`), built from the wheel, attested |

## One-time setup

- On PyPI and TestPyPI, add a **trusted publisher** for both `authzai` and `authzai-compat`:
  - owner `xinweiiiii`, repository `agentic-auth`
  - workflow `release.yml`, environment `release`
- In the repository settings, create the environment **`release`**, with the maintainers as
  required reviewers. The publish job waits for that approval.

## Cutting a release

1. Move the `## [Unreleased]` notes in `CHANGELOG.md` under `## [X.Y.Z] - YYYY-MM-DD`, and add
   its compare link at the bottom. The workflow refuses a version with no section.
2. Set `__version__ = "X.Y.Z"` in `agentic_auth/__init__.py`. Set the `version` and the
   `authzai==` pin in `compat/pyproject.toml` to the same number
   (`tests/unit/test_versions_agree.py` holds them equal).
3. Merge that to `main`, then tag the merge commit and push the tag:

   ```bash
   git tag -s vX.Y.Z -m "vX.Y.Z" && git push origin vX.Y.Z
   ```

4. Approve the `release` environment when the workflow asks.
5. `Confirm every channel` going green is the release being done. It checks PyPI, the
   release page and GHCR for the version, and names whatever is missing.

## A dry run

A pre-release tag (`vX.Y.ZrcN`) runs the whole workflow with three differences:

- it publishes to **TestPyPI** instead of PyPI
- it marks the GitHub release as a pre-release
- it does not move `:latest`

Use one to try a change to the pipeline itself.

## When a release stops part-way

**Re-run the failed jobs. Never delete and re-push the tag.** PyPI accepts a given version
exactly once, so a re-tag would leave PyPI and the release page permanently disagreeing.
Every publishing step is safe to re-run:

- PyPI uploads use `skip-existing`
- the GitHub release is updated in place
- the image tag is pushed again with identical content

## Checking a release you downloaded

```bash
gh release download vX.Y.Z --repo xinweiiiii/agentic-auth -D authzai-X.Y.Z && cd authzai-X.Y.Z
sha256sum -c SHA256SUMS

# Was this built by this repository's release workflow, from this tag?
gh attestation verify authzai-X.Y.Z-py3-none-any.whl --repo xinweiiiii/agentic-auth
gh attestation verify oci://ghcr.io/xinweiiiii/agentic-auth:X.Y.Z --repo xinweiiiii/agentic-auth
```

To install on a machine with no access to PyPI, download the dependencies on a machine that
has access, then install from the files:

```bash
pip download 'authzai[server]==X.Y.Z' -d wheels/      # on a connected machine
pip install --no-index --find-links wheels/ 'authzai[server]==X.Y.Z'
```
