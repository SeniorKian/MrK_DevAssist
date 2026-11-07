#!/bin/sh
set -eu

server_dir="${MRK_PYPI_SERVER_DIR:-/data/pypi/server}"
auth_dir="${MRK_PYPI_AUTH_DIR:-/data/pypi/auth}"
root_password_file="$auth_dir/root-password"
secret_file="$auth_dir/server-secret"
bootstrap_pending_file="$auth_dir/bootstrap-pending"
umask 077
mkdir -p "$server_dir"
mkdir -p "$auth_dir"

if [ ! -s "$secret_file" ]; then
    python -c "import secrets; print(secrets.token_urlsafe(64))" > "$secret_file"
fi
chmod 600 "$secret_file"

if [ ! -f "$server_dir/.nodeinfo" ]; then
    if [ -n "$(find "$server_dir" -mindepth 1 -maxdepth 1 -print -quit)" ]; then
        echo "Refusing to initialize non-empty devpi server directory: $server_dir" >&2
        exit 1
    fi
    password_source_file="${MRK_PYPI_ROOT_PASSWORD_FILE:-${MRK_DEVPI_ROOT_PASSWORD_FILE:-}}"
    if [ -n "$password_source_file" ]; then
        root_password="$(cat "$password_source_file")"
    elif [ -s "$root_password_file" ]; then
        root_password="$(cat "$root_password_file")"
    else
        python -c "import secrets; print(secrets.token_urlsafe(32))" > "$root_password_file"
        root_password="$(cat "$root_password_file")"
    fi
    chmod 600 "$root_password_file"
    devpi-init --serverdir "$server_dir" --no-root-pypi --root-passwd "$root_password"
    printf '%s\n' "fresh-install" > "$bootstrap_pending_file"
    chmod 600 "$bootstrap_pending_file"
    unset root_password
fi

set -- devpi-server \
    --serverdir "$server_dir" \
    --host 0.0.0.0 \
    --port "${MRK_PYPI_PORT:-3141}" \
    --threads "${MRK_PYPI_THREADS:-8}" \
    --request-timeout "${MRK_PYPI_REQUEST_TIMEOUT:-90}" \
    --mirror-cache-expiry "${MRK_PYPI_CACHE_EXPIRY:-300}" \
    --secretfile "$secret_file" \
    --restrict-modify root

if [ -n "${MRK_PYPI_OUTSIDE_URL:-}" ]; then
    set -- "$@" --outside-url "$MRK_PYPI_OUTSIDE_URL"
fi

exec "$@"
