#!/bin/sh
set -eu

server_dir="${MRK_PYPI_SERVER_DIR:-/data/pypi/server}"
server_dir="${server_dir%/}"
auth_dir="${MRK_PYPI_AUTH_DIR:-/data/pypi/auth}"
auth_dir="${auth_dir%/}"
root_password_file="$auth_dir/root-password"
secret_file="$auth_dir/server-secret"
bootstrap_pending_file="$auth_dir/bootstrap-pending"
# Lives inside the server directory itself, so an interrupted-init cleanup can
# only ever remove the directory that this script started initializing.
init_sentinel="$server_dir/.mrk-init-in-progress"
umask 077

case "$auth_dir/" in
    "$server_dir"/*)
        echo "Refusing: the devpi auth directory ($auth_dir) is inside the server directory ($server_dir)" >&2
        exit 1
        ;;
esac
if [ -L "$server_dir" ]; then
    echo "Refusing a symlinked devpi server directory: $server_dir" >&2
    exit 1
fi

mkdir -p "$server_dir"
mkdir -p "$auth_dir"

if [ ! -s "$secret_file" ]; then
    python -c "import secrets; print(secrets.token_urlsafe(64))" > "$secret_file"
fi
chmod 600 "$secret_file"

if [ -f "$init_sentinel" ]; then
    # Our own first init was interrupted (crash/kill). devpi-init writes .nodeinfo
    # before it creates the root user, so .nodeinfo alone does not prove a usable
    # server; the sentinel does. Nothing in here can be user data yet, because the
    # sentinel is removed before devpi-server ever serves the directory.
    echo "Removing an interrupted devpi initialization in $server_dir" >&2
    find "$server_dir" -mindepth 1 -maxdepth 1 -exec rm -rf {} +
    # A configured-upstream record cannot describe a server that never finished
    # initializing; drop it so devpi-configure bootstraps the new one.
    rm -f "$auth_dir/upstream-configured"
fi

if [ ! -f "$server_dir/.nodeinfo" ]; then
    if [ -n "$(find "$server_dir" -mindepth 1 -maxdepth 1 -print -quit)" ]; then
        echo "Refusing to initialize non-empty devpi server directory: $server_dir" >&2
        exit 1
    fi
    : > "$init_sentinel"
    printf '%s\n' "initializing" > "$bootstrap_pending_file"
    chmod 600 "$bootstrap_pending_file"
    password_source_file="${MRK_PYPI_ROOT_PASSWORD_FILE:-${MRK_DEVPI_ROOT_PASSWORD_FILE:-}}"
    if [ -z "$password_source_file" ]; then
        password_source_file="$root_password_file"
        if [ ! -s "$password_source_file" ]; then
            (umask 077 && python -c "import secrets; print(secrets.token_urlsafe(32))" > "$password_source_file")
        fi
        chmod 600 "$password_source_file"
    fi
    if [ ! -s "$password_source_file" ]; then
        echo "The devpi root password file is missing or empty: $password_source_file" >&2
        exit 1
    fi
    # Pass only an argon2 hash on the command line, never the password itself.
    root_password_hash="$(python -c 'import sys; from devpi_server.auth import hash_password; print(hash_password(sys.stdin.read().rstrip("\n")))' < "$password_source_file")"
    devpi-init --serverdir "$server_dir" --no-root-pypi --root-passwd-hash "$root_password_hash"
    unset root_password_hash
    printf '%s\n' "fresh-install" > "$bootstrap_pending_file"
    chmod 600 "$bootstrap_pending_file"
    rm -f "$init_sentinel"
fi

# mrk-devpi-server = devpi-server with the «My space» pre-upload quota check always
# loaded (mrk_control_plane.devpi_quota, docs/43 §0.1).
set -- mrk-devpi-server \
    --serverdir "$server_dir" \
    --host "${MRK_PYPI_LISTEN_HOST:-0.0.0.0}" \
    --port "${MRK_PYPI_PORT:-3141}" \
    --threads "${MRK_PYPI_THREADS:-16}" \
    --request-timeout "${MRK_PYPI_REQUEST_TIMEOUT:-900}" \
    --mirror-cache-expiry "${MRK_PYPI_CACHE_EXPIRY:-300}" \
    --secretfile "$secret_file" \
    --restrict-modify root

# Public URL for generated links: the environment wins; otherwise the file the
# panel writes from the primary PyPI domain (docs/35 §4). The file content is
# accepted only when it is a bare http(s)://host[:port] URL.
outside_url="${MRK_PYPI_OUTSIDE_URL:-}"
outside_url_file="${MRK_DATA_DIR:-/data}/pypi/outside-url"
if [ -z "$outside_url" ] && [ -f "$outside_url_file" ] && [ ! -L "$outside_url_file" ]; then
    candidate="$(head -c 300 "$outside_url_file" | tr -d '\r\n')"
    if printf '%s' "$candidate" | grep -Eq '^https?://[A-Za-z0-9.-]+(:[0-9]{1,5})?$'; then
        outside_url="$candidate"
    else
        echo "Ignoring an invalid PyPI outside URL file: $outside_url_file" >&2
    fi
fi
if [ -n "$outside_url" ]; then
    set -- "$@" --outside-url "$outside_url"
fi

exec "$@"
