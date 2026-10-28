# Security Policy

## Reporting a vulnerability

**Do not open a public issue.**

Report privately through [GitHub Security
Advisories](https://github.com/xinweiiiii/agentic-auth/security/advisories/new), which
opens a channel visible only to you and the maintainers.

If that is not available to you, email **help@authzai.dev** with `SECURITY` in the subject.

### What helps

- What you can do with it, not just what is wrong.
- The smallest reproduction you have — a request, a manifest, a token.
- Affected version or commit.
- Whether it is already public anywhere.

### What to expect

| | |
|---|---|
| Acknowledgement | within 3 working days |
| Initial assessment | within 10 working days |
| Fix or mitigation plan | agreed with you before any disclosure |

We will tell you what we find, credit you unless you prefer otherwise, and agree timing
with you before publishing.

## Supported versions

Pre-1.0. Fixes land on `main` and in the next release. There are no backported security
branches yet.

## Scope

In scope — anything that lets a caller do what the policy says it may not:

- A decision that allows something the pinned policy does not permit.
- Authority that widens across a hop instead of narrowing.
- A dispatched call with no audit record, or an audit record that can be altered.
- Forging, replaying, or reusing a token beyond its binding.
- Identity or taint that can be spoofed by the agent it describes.
- Identities, tokens, or request bodies appearing in metrics, traces, or logs.

Out of scope:

- Anything requiring the admin token. It is a full-trust credential by design.
- The documented development defaults — `dev-admin-token`, an empty issuer key generating
  an ephemeral one. These are loudly documented as development-only in `.env.example`.
- Denial of service through sheer volume against an unprotected deployment.
- Findings from a scanner with no demonstrated impact.

## Hardening

Before production, read [the deployment
guides](https://authzai.dev/how-to/deploy-the-sidecar-pep). The settings that matter most:

- Set `AGENTIC_AUTH_ISSUER_PRIVATE_KEY`. Empty generates an ephemeral key, every token
  stops verifying on restart, and two replicas will not agree.
- Replace `AGENTIC_AUTH_ADMIN_TOKEN`. Give auditors `AGENTIC_AUTH_AUDIT_READ_TOKEN`
  instead — it is read-only.
- Configure a principal IdP. Without one, every enrollment completes as `quarantined`
  rather than enrolling an agent nobody is accountable for.
- Keep `/metrics` on an internal network.
