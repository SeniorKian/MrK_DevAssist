#!/bin/sh
set -eu

auth_dir="${MRK_PYPI_AUTH_DIR:-/data/pypi/auth}"
client_dir="${MRK_PYPI_CLIENT_DIR:-/data/pypi/client}"
root_password_file="$auth_dir/root-password"
bootstrap_pending_file="$auth_dir/bootstrap-pending"
bootstrap_state_file="$auth_dir/upstream-configured"
upstream_url="${MRK_PYPI_UPSTREAM_URL:-http://127.0.0.1:3142/simple/}"
local_server="http://127.0.0.1:${MRK_PYPI_PORT:-3141}"
password_source_file="${MRK_PYPI_ROOT_PASSWORD_FILE:-${MRK_DEVPI_ROOT_PASSWORD_FILE:-$root_password_file}}"
max_attempts="${MRK_PYPI_CONFIGURE_ATTEMPTS:-10}"

umask 077
mkdir -p "$client_dir"

wait_for_devpi() {
    attempt=0
    until python -c "import urllib.request; urllib.request.urlopen('${local_server}/+status', timeout=2).read(1)" >/dev/null 2>&1; do
        attempt=$((attempt + 1))
        # A first start on slow disks can take minutes; supervisord does not retry this program.
        if [ "$attempt" -ge "${MRK_PYPI_BOOTSTRAP_WAIT_SECONDS:-300}" ]; then
            echo "Timed out waiting for devpi to become ready for bootstrap." >&2
            return 1
        fi
        sleep 1
    done
}

# Create root/pypi, or (re)apply its mirror settings when an earlier run created
# the index but was interrupted before recording the state file.
# `set -e` is suspended inside a function used as an `until` condition, so every
# step returns explicitly on failure.
configure_index() {
    devpi use "$local_server" >/dev/null || return 1
    devpi login root --password "$(cat "$password_source_file")" >/dev/null || return 1
    if devpi getjson /root/pypi >/dev/null 2>&1; then
        index_flag=""
    else
        index_flag="-c"
    fi
    # shellcheck disable=SC2086 # index_flag is intentionally empty or "-c"
    devpi index $index_flag root/pypi \
        type=mirror \
        volatile=False \
        title=PyPI \
        "mirror_url=$upstream_url" || return 1
    devpi logoff >/dev/null 2>&1 || true
}

wait_for_devpi

if [ -s "$bootstrap_state_file" ]; then
    configured_url="$(cat "$bootstrap_state_file")"
    if [ "$configured_url" != "$upstream_url" ]; then
        echo "Configured PyPI upstream differs from MRK_PYPI_UPSTREAM_URL; refusing an automatic mirror switch." >&2
        echo "Configured: $configured_url" >&2
        echo "Requested:  $upstream_url" >&2
        exit 1
    fi
    exit 0
fi

if [ ! -f "$bootstrap_pending_file" ]; then
    echo "Existing devpi data has no bootstrap marker; refusing to mutate its mirror configuration." >&2
    echo "Use the authenticated admin workflow to import or change an existing mirror safely." >&2
    exit 1
fi

if [ ! -s "$password_source_file" ]; then
    echo "The devpi root password file is missing or empty: $password_source_file" >&2
    exit 1
fi

export DEVPI_CLIENTDIR="$client_dir"
attempt=1
until configure_index; do
    if [ "$attempt" -ge "$max_attempts" ]; then
        echo "Configuring the devpi mirror failed after $attempt attempts." >&2
        exit 1
    fi
    echo "Configuring the devpi mirror failed (attempt $attempt/$max_attempts); retrying." >&2
    sleep $((attempt * 3))
    attempt=$((attempt + 1))
    wait_for_devpi
done

printf '%s\n' "$upstream_url" > "$bootstrap_state_file"
chmod 600 "$bootstrap_state_file"
rm -f "$bootstrap_pending_file"
echo "Configured fresh devpi mirror upstream: $upstream_url"
