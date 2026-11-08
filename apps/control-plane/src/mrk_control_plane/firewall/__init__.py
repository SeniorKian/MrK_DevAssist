"""MRK firewall helper: a separate, optional, privileged process (``mrk-firewall``).

It is the only MRK component with ``CAP_NET_ADMIN``. It owns exactly one nftables
table (``inet mrk``), tails read-only log files on request and turns matching lines
into compact signals. All decisions (rules, thresholds, allowlist, safety checks,
RBAC, audit) live in the control plane; the helper re-validates everything it is
given and never touches any other table (Docker, Dokploy, distro firewall).
"""

FIREWALL_VERSION = "0.1.0"
