"""The sidecar PEP: enforcement for agent code the integrator did not write.

Checks that live inside an agent's own process can be skipped by the agent. Moving them
into a process the integrator controls is what makes the guarantee real. Runs as its own
uvicorn process (``agentic-auth-sidecar``) and shares this package's schemas, deny
vocabulary and token helpers rather than re-declaring them.
"""
