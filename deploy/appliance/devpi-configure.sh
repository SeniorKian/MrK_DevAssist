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

umask 077
mkdir -p "$client_dir"

attempt=0
until python -c "import urllib.request; urllib.request.urlopen('${local_server}/+status', timeout=2).read(1)" >/dev/null 2>&1; do
    attempt=$((attempt + 1))
    if [ "$attempt" -ge 30 ]; then
        echo "Timed out waiting for devpi to become ready for bootstrap." >&2
        exit 1
    fi
    sleep 1
done

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
devpi use "$local_server"
devpi login root --password "$(cat "$password_source_file")"
devpi index -c root/pypi \
    type=mirror \
    volatile=False \
    title=PyPI \
    "mirror_url=$upstream_url"

printf '%s\n' "$upstream_url" > "$bootstrap_state_file"
chmod 600 "$bootstrap_state_file"
rm -f "$bootstrap_pending_file"
echo "Configured fresh devpi mirror upstream: $upstream_url"
