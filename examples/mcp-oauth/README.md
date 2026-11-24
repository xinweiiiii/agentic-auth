# An MCP client through the connector proxy, with OAuth

```bash
pip install -e '.[server]'
python examples/mcp-oauth/run_local.py
```

A standard MCP client authenticates to the Agentic Auth connector proxy and calls a tool,
with no Agentic Auth code on the client side (`client_flow.py` imports nothing from it):

```text
1. call without a token          -> 401
2. protected resource metadata   -> authorization server https://idp.embedded.invalid
3. authorization server metadata -> issuer https://idp.embedded.invalid
4. user signed in                -> access token for https://mcp-proxy.example
5. call with the token           -> 200
   tool result: 3 articles found
6. audit chain root              -> https://idp.embedded.invalid#alice (embedded-test, client desktop-client)
```

Everything runs in one process: an embedded control plane with verified consent and client
mapping on, its built-in test IdP standing in for yours, the proxy as an OAuth protected
resource, and a small tool server. Step 4 is where a real client runs the authorization code
flow with PKCE at your IdP. The embedded IdP has no login page, so the example hands the
client the token that login would produce. Agentic Auth never runs the login itself.

The settings it uses are documented in `CONFIGURATION.md` under "MCP OAuth 2.1 (0.4.0)" and
"As an OAuth 2.1 protected resource".
