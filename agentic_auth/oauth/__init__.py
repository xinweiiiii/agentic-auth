"""OAuth 2.1 resource-server pieces shared by the enforcement points and the control plane.

Nothing in this package imports the database, the models or the control plane's settings:
the connector proxy and the gateway deploy next to an agent, and they validate inbound
tokens with exactly the same code consent does.
"""
