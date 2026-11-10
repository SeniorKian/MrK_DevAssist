#!/usr/bin/env bash
# Start/stop a throwaway pglite-server for CI, mirroring the appliance's
# supervisord command line (deploy/images/panel/supervisord.conf).
#
#   scripts/ci_pglite_server.sh start <db-dir> [log-file]
#   scripts/ci_pglite_server.sh stop  <db-dir>
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
server="${PGLITE_SERVER:-$repo_root/deploy/pglite/node_modules/.bin/pglite-server}"
host=127.0.0.1
port=5433
action="${1:?usage: $0 start|stop <db-dir> [log-file]}"
db_dir="${2:?usage: $0 start|stop <db-dir> [log-file]}"
pid_file="$db_dir.pid"

port_open() {
  (exec 3<>"/dev/tcp/$host/$port") 2>/dev/null
}

case "$action" in
  start)
    log_file="${3:-$db_dir.log}"
    if port_open; then
      echo "port $host:$port is already in use" >&2
      exit 1
    fi
    mkdir -p "$(dirname "$db_dir")"
    nohup "$server" --db="$db_dir" --port="$port" --host="$host" --max-connections=1 \
      >"$log_file" 2>&1 &
    echo $! >"$pid_file"
    for _ in $(seq 1 120); do
      if port_open; then
        echo "pglite-server ready on $host:$port (pid $(cat "$pid_file"))"
        exit 0
      fi
      if ! kill -0 "$(cat "$pid_file")" 2>/dev/null; then
        echo "pglite-server exited before becoming ready" >&2
        cat "$log_file" >&2 || true
        exit 1
      fi
      sleep 0.5
    done
    echo "pglite-server did not open $host:$port within 60s" >&2
    cat "$log_file" >&2 || true
    exit 1
    ;;
  stop)
    if [[ -f "$pid_file" ]]; then
      pid="$(cat "$pid_file")"
      kill "$pid" 2>/dev/null || true
      for _ in $(seq 1 40); do
        kill -0 "$pid" 2>/dev/null || break
        sleep 0.25
      done
      kill -9 "$pid" 2>/dev/null || true
      rm -f "$pid_file"
    fi
    for _ in $(seq 1 40); do
      port_open || exit 0
      sleep 0.25
    done
    echo "port $host:$port still open after stop" >&2
    exit 1
    ;;
  *)
    echo "unknown action: $action" >&2
    exit 2
    ;;
esac
