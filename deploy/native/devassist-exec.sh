#!/usr/bin/env bash
# devassist-exec — run a command the way devassist.service sees the system (native install).
#
# The main service runs in its own mount namespace (/data, /usr/local/bin,
# /opt/verdaccio, /opt/pglite and a private /tmp with the supervisor socket).
# Maintenance commands from docs/18-operations-runbooks.md need that view:
#
#   sudo devassist-exec supervisorctl -c /opt/mrk/supervisord.conf status
#   sudo devassist-exec mrk-restore apply --plan ... (service stopped first)
#
# Service running: joins its mount namespace and environment as user devassist.
# Service stopped: starts a transient unit with the same mounts and env file.
set -Eeuo pipefail

UNIT="devassist.service"
RUN_USER="devassist"
INSTALL_CONF="/etc/devassist/install.conf"
INNER_PATH="/opt/mrk/venv/bin:/usr/local/bin:/usr/bin:/bin"

usage() {
    echo "usage: sudo devassist-exec <command> [args...]" >&2
    echo "  e.g. sudo devassist-exec supervisorctl -c /opt/mrk/supervisord.conf status" >&2
    exit 2
}

[ "$#" -gt 0 ] || usage
if [ "$(id -u)" -ne 0 ]; then
    echo "devassist-exec: run as root (sudo) / با sudo اجرا کنید" >&2
    exit 1
fi

data_dir="/var/lib/devassist"
if [ -r "$INSTALL_CONF" ]; then
    configured="$(sed -n 's/^DEVASSIST_DATA_DIR=//p' "$INSTALL_CONF" | head -n 1)"
    if [ -n "$configured" ]; then
        data_dir="$configured"
    fi
fi

pid="$(systemctl show --property=MainPID --value "$UNIT" 2>/dev/null || echo 0)"
if [ -n "$pid" ] && [ "$pid" != "0" ] && [ -r "/proc/$pid/environ" ]; then
    # Same environment as the running service (systemd's own parsing of the env file).
    mapfile -d '' service_env < "/proc/$pid/environ"
    cd /
    exec nsenter --target "$pid" --mount -- \
        setpriv --reuid="$RUN_USER" --regid="$RUN_USER" --clear-groups -- \
        env -i "${service_env[@]}" "$@"
fi

io_mode="--pipe"
if [ -t 0 ] && [ -t 1 ]; then
    io_mode="--pty"
fi
exec systemd-run --quiet --wait "$io_mode" --collect --service-type=exec \
    --uid="$RUN_USER" --gid="$RUN_USER" \
    --property=UMask=0027 \
    --property=EnvironmentFile=/etc/devassist/devassist.env \
    --setenv=PATH="$INNER_PATH" --setenv=HOME=/tmp \
    --property=BindPaths="$data_dir:/data" \
    --property=BindReadOnlyPaths="/opt/mrk/bin:/usr/local/bin /opt/mrk/verdaccio:/opt/verdaccio /opt/mrk/pglite:/opt/pglite" \
    --property=TemporaryFileSystem="/tmp:mode=1777,nosuid,nodev" \
    -- "$@"
