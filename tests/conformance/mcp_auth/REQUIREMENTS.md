# MCP authorization conformance: requirements index

Each requirement the suite covers, the MCP 2026-07-28 authorization text it comes from, and
the test that covers it. A requirement with no test is listed as `NOT COVERED: <why>`.
`test_requirements_index.py` fails if any ID below has neither a collected test carrying the
ID in its name nor that note, or if a `test_MCPA_*` test has no entry here.

Every test runs against both deployments, `server` and `embedded`. Proxy and gateway
requirements run against both enforcement points.

The quoted text is the requirement as this project reads the MCP authorization specification
(revision 2026-07-28, "Authorization"), which builds on OAuth 2.1, RFC 9728, RFC 8707 and
RFC 6750. If an official conformance suite is published, it replaces this one (spec
Assumptions).

| ID | Requirement | Source | Test |
|---|---|---|---|
| MCPA-RS-PRM | "MCP servers MUST implement the OAuth 2.0 Protected Resource Metadata (RFC 9728) specification to indicate the locations of authorization servers." | MCP Authorization, Authorization Server Discovery | `test_resource_server.py::test_MCPA_RS_PRM` |
| MCPA-RS-401 | "MCP servers MUST use the HTTP header `WWW-Authenticate` when returning a 401 Unauthorized to indicate the location of the resource server metadata URL." | MCP Authorization, Authorization Server Location; RFC 9728 §5.1 | `test_resource_server.py::test_MCPA_RS_401` |
| MCPA-RS-AUD | "MCP servers MUST validate that access tokens were issued specifically for them as the intended audience, according to RFC 8707." | MCP Authorization, Token Handling | `test_resource_server.py::test_MCPA_RS_AUD` |
| MCPA-RS-SIG | "MCP servers MUST validate access tokens", answering an invalid or expired one with "401 Unauthorized". | MCP Authorization, Token Handling and Error Handling; OAuth 2.1 §5.2 | `test_resource_server.py::test_MCPA_RS_SIG` |
| MCPA-RS-SCOPE | A token whose scopes are insufficient is answered "403 Forbidden" with `error="insufficient_scope"`. | MCP Authorization, Scope Challenge Handling; RFC 6750 §3.1 | `test_resource_server.py::test_MCPA_RS_SCOPE` |
| MCPA-RS-NOPASS | "The MCP server MUST NOT pass through the token it received from the MCP client" to an upstream API. | MCP Authorization, Access Token Privilege Restriction; Security Best Practices, Token Passthrough | `test_no_passthrough.py::test_MCPA_RS_NOPASS` |
| MCPA-RS-BEARER | "Access tokens MUST NOT be included in the URI query string." | MCP Authorization, Token Requirements; OAuth 2.1 §5.1 | `test_resource_server.py::test_MCPA_RS_BEARER` |
| MCPA-AS-META | Authorization server metadata follows RFC 8414; `issuer` matches. Agentic Auth never runs a login or client registration (spec FR-008, FR-015), so no authorization or registration endpoint appears. | RFC 8414 §2–3; spec FR-009 | `test_control_plane.py::test_MCPA_AS_META` |
| MCPA-CONSENT-VERIFY | The consenting human is the verified `iss#sub` of the user's token; absent or disagreeing evidence is refused. | spec FR-006, FR-007 | `test_control_plane.py::test_MCPA_CONSENT_VERIFY` |
| MCPA-CLIENT-MAP | A client is identified, not authorized: an unmapped client is refused with `CLIENT_NOT_AUTHORIZED`; a mapped one is governed by its agent's manifest. | spec FR-013, FR-014; PRD FR-15 | `test_control_plane.py::test_MCPA_CLIENT_MAP` |
| MCPA-FAILCLOSED | With the IdP's keys unreachable and none cached, every inbound token is refused, never allowed. | spec FR-021 | `test_control_plane.py::test_MCPA_FAILCLOSED` |
| MCPA-RS-TLS | "All authorization server endpoints MUST be served over HTTPS." Redirect URIs MUST be localhost or HTTPS. | MCP Authorization, Communication Security | NOT COVERED: TLS terminates in front of the proxy, outside this process. The proxy refuses to start with a non-https `RESOURCE_URL` (`tests/unit/test_gateway_config_oauth.py`). |
| MCPA-AS-PKCE | "MCP clients MUST implement PKCE." | MCP Authorization, Authorization Code Protection | NOT COVERED: a client and IdP requirement. Agentic Auth runs no authorization endpoint, so there is no code exchange here to test. |
| MCPA-AS-DCR | "MCP clients and authorization servers SHOULD support the OAuth 2.0 Dynamic Client Registration Protocol." | MCP Authorization, Dynamic Client Registration | NOT COVERED: registration stays at the customer's IdP (spec FR-015). MCPA-AS-META asserts we advertise no registration endpoint. |
