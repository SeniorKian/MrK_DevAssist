"""MRK Host Agent: a separate, optional process (``mrk-agent``) from the same image.

It is the only MRK component that may see the Docker socket and host ``/proc``.
Gate 16 is strictly read-only. The control plane talks to it over a private
network with HMAC-signed requests; RBAC and audit stay in the control plane.
"""

AGENT_VERSION = "0.1.0"
