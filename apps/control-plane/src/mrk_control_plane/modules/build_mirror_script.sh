#!/usr/bin/env bash
# DevAssist build mirrors (docs/48), layers A and B on one server.
#
#   install --registry HOST [--allow-restart] [--no-test]
#           [--no-daemon] [--no-buildkit] [--docker-config DIR] [--npm URL] [--pypi URL]
#           [--registry-ca FILE]   (only for a mirror with a private/self-signed certificate)
#
# HOST is DevAssist's image registry with its token service on (docs/48): Docker sends
# no password to a mirror, so the registry must point it at the panel for a token.
#   status [--registry HOST] [--docker-config DIR]
#   undo   [--registry HOST] [--docker-config DIR] [--allow-restart]
#
# Safe to run again. Every file it changes is backed up to /etc/devassist/backup first;
# daemon.json gets only its "registry-mirrors" entry, nothing else. Docker is reloaded,
# never restarted, unless --allow-restart is given.
set -euo pipefail

SCRIPT_VERSION="2"
STATE_DIR="/etc/devassist"
MARKER="$STATE_DIR/build-mirror.json"
BACKUP_DIR="$STATE_DIR/backup"
DAEMON_JSON="/etc/docker/daemon.json"
BUILDER="mrk-mirror"
HEADER="# Written by DevAssist (devassist-build-mirror.sh). 'undo' removes it."
# Small official images; the test pulls the first one the mirror does not hold yet.
TEST_IMAGES="busybox:1.37.0 alpine:3.22.2 hello-world:latest"
DOCKER_UA="docker/28.5.2 devassist-build-mirror"
# Mirrors with a path prefix in Zot; Docker Hub lives at the registry root.
PREFIXED="ghcr.io quay.io registry.k8s.io"

ACTION="${1:-}"
[ $# -gt 0 ] && shift
REGISTRY="" NPM_URL="" PYPI_URL="" DOCKER_CONFIG_DIR="auto" REGISTRY_CA=""
ALLOW_RESTART=0 RUN_TEST=1 DO_DAEMON=1 DO_BUILDKIT=1
while [ $# -gt 0 ]; do
  case "$1" in
    --registry) REGISTRY="${2:-}"; shift 2 ;;
    --npm) NPM_URL="${2:-}"; shift 2 ;;
    --pypi) PYPI_URL="${2:-}"; shift 2 ;;
    --docker-config) DOCKER_CONFIG_DIR="${2:-}"; shift 2 ;;
    --registry-ca) REGISTRY_CA="${2:-}"; shift 2 ;;
    --allow-restart) ALLOW_RESTART=1; shift ;;
    --no-test) RUN_TEST=0; shift ;;
    --no-daemon) DO_DAEMON=0; shift ;;
    --no-buildkit) DO_BUILDKIT=0; shift ;;
    *) echo "[!!] unknown option: $1" >&2; exit 2 ;;
  esac
done

ok() { printf '[ok] %s\n' "$*"; }
warn() { printf '[!!] %s\n' "$*"; }
info() { printf '[..] %s\n' "$*"; }
die() { printf '[!!] %s\n' "$*" >&2; exit 1; }

# "https://reg.example.com/" or "reg.example.com" -> "reg.example.com"
REGISTRY="${REGISTRY#https://}"
REGISTRY="${REGISTRY%%/*}"
case "$REGISTRY" in
  ""|*[!A-Za-z0-9.:-]*) [ -z "$REGISTRY" ] || die "registry must be a host name, e.g. registry.example.com" ;;
esac
MIRROR_URL="${REGISTRY:+https://$REGISTRY}"

need_root() { [ "$(id -u)" = "0" ] || die "run it as root: sudo bash ..."; }
need() { command -v "$1" >/dev/null 2>&1 || die "$1 is missing on this server ($2)"; }

docker_config_dir() {
  if [ "$DOCKER_CONFIG_DIR" != "auto" ]; then
    printf '%s' "$DOCKER_CONFIG_DIR"
    return
  fi
  # Dokploy's own container keeps /root/.docker in the volume "dokploy".
  local mount
  mount="$(docker volume inspect dokploy --format '{{.Mountpoint}}' 2>/dev/null || true)"
  if [ -n "$mount" ] && [ -d "$mount" ]; then
    printf '%s' "$mount"
  else
    printf '%s' "${HOME:-/root}/.docker"
  fi
}

backup() {
  [ -f "$1" ] || return 0
  mkdir -p "$BACKUP_DIR"
  cp -a "$1" "$BACKUP_DIR/$(basename "$1").$(date +%Y%m%d-%H%M%S)"
}

# daemon.json: add (or remove) our mirror in registry-mirrors and keep every other key.
edit_daemon() {
  local mode="$1" target="$DAEMON_JSON.devassist-new"
  python3 -I - "$DAEMON_JSON" "$target" "$mode" "$MIRROR_URL" <<'PY'
import json, os, sys
source, target, mode, mirror = sys.argv[1:5]
try:
    with open(source, encoding="utf-8") as handle:
        text = handle.read()
    data = json.loads(text) if text.strip() else {}
except FileNotFoundError:
    data = {}
except ValueError:
    sys.exit("daemon.json is not valid JSON; fix it first")
if not isinstance(data, dict):
    sys.exit("daemon.json is not a JSON object; fix it first")
mirrors = [m for m in data.get("registry-mirrors", []) if isinstance(m, str)]
mirrors = [m for m in mirrors if m.rstrip("/") != mirror.rstrip("/")]
if mode == "add":
    mirrors.insert(0, mirror)
if mirrors or "registry-mirrors" in data:
    # Kept as [] when our mirror was the last one: Docker only forgets mirrors on
    # reload when the key says so (a missing key keeps the old list in memory).
    data["registry-mirrors"] = mirrors
with open(target, "w", encoding="utf-8") as handle:
    json.dump(data, handle, indent=2)
    handle.write("\n")
if os.path.exists(source):
    os.chmod(target, os.stat(source).st_mode & 0o777)
PY
  if dockerd --help 2>/dev/null | grep -q -- '--validate'; then
    if ! dockerd --validate --config-file "$target" >/dev/null 2>&1; then
      rm -f "$target"
      die "Docker rejected the new daemon.json; nothing was changed"
    fi
  fi
  mkdir -p "$(dirname "$DAEMON_JSON")"
  mv "$target" "$DAEMON_JSON"
}

live_has_mirror() {
  docker info --format '{{json .RegistryConfig.Mirrors}}' 2>/dev/null | grep -q "$REGISTRY"
}

reload_docker() {
  if command -v systemctl >/dev/null 2>&1 && systemctl is-active --quiet docker; then
    systemctl reload docker
  else
    kill -HUP "$(pidof dockerd)"
  fi
  sleep 2
}

restart_docker() {
  warn "restarting Docker: containers stop for a moment"
  systemctl restart docker
  sleep 5
}

write_toml() {
  local file="$1"
  {
    printf '%s\n' "$HEADER"
    printf '[registry."docker.io"]\n  mirrors = ["%s"]\n' "$REGISTRY"
    for host in $PREFIXED; do
      printf '[registry."%s"]\n  mirrors = ["%s/%s"]\n' "$host" "$REGISTRY" "$host"
    done
    if [ -n "$REGISTRY_CA" ]; then
      printf '[registry."%s"]\n  ca = ["%s"]\n' "$REGISTRY" "$REGISTRY_CA"
    fi
  } >"$file"
  chmod 644 "$file"
}

write_marker() {
  mkdir -p "$STATE_DIR"
  python3 -I - "$MARKER" "$@" <<'PY'
import json, sys, time
path, *pairs = sys.argv[1:]
data = {"applied_at": int(time.time())}
for pair in pairs:
    key, _, value = pair.partition("=")
    data[key] = {"true": True, "false": False}.get(value, value)
with open(path, "w", encoding="utf-8") as handle:
    json.dump(data, handle, indent=2)
    handle.write("\n")
PY
  chmod 644 "$MARKER"
}

curl_mirror() {
  if [ -n "$REGISTRY_CA" ]; then
    curl --cacert "$REGISTRY_CA" -A "$DOCKER_UA" "$@"
  else
    curl -A "$DOCKER_UA" "$@"
  fi
}

mirror_check() {
  # As Docker sees it, with no password: "open", "token" (Docker follows that), "password"
  # (Docker skips the mirror) or "down".
  local headers code
  headers="$(curl_mirror -sS -o /dev/null -D - --max-time 10 "$MIRROR_URL/v2/" 2>/dev/null | tr -d '\r' || true)"
  code="$(printf '%s\n' "$headers" | awk 'toupper($1) ~ /^HTTP/ {c=$2} END {print c}')"
  case "$code" in
    200) echo "open" ;;
    401) if printf '%s\n' "$headers" | grep -qi '^www-authenticate: *bearer'; then echo "token"; else echo "password"; fi ;;
    *) echo "down" ;;
  esac
}

pull_token() {
  # The token Docker would get for these scopes, from the realm the registry names.
  local challenge
  challenge="$(curl_mirror -sS -o /dev/null -D - --max-time 10 "$MIRROR_URL/v2/" 2>/dev/null \
    | tr -d '\r' | grep -i '^www-authenticate: *bearer' || true)"
  [ -n "$challenge" ] || return 0
  python3 -I - "$challenge" "$REGISTRY_CA" "$@" <<'PY' 2>/dev/null || true
import json, re, ssl, sys, urllib.parse, urllib.request
challenge, ca, *scopes = sys.argv[1:]
fields = dict(re.findall(r'(\w+)="([^"]*)"', challenge))
query = [("service", fields.get("service", ""))] + [("scope", item) for item in scopes]
url = fields["realm"] + "?" + urllib.parse.urlencode(query)
context = ssl.create_default_context()
if ca:
    context.load_verify_locations(ca)
request = urllib.request.Request(url, headers={"User-Agent": "devassist-build-mirror"})
with urllib.request.urlopen(request, timeout=10, context=context) as answer:
    print(json.load(answer).get("token", ""))
PY
}

catalog() {
  # Repositories the mirror already stores (listing never makes it fetch anything),
  # as far as this server's token may see them.
  local token scopes=() image
  for image in $TEST_IMAGES; do scopes+=("repository:library/${image%%:*}:pull"); done
  local auth=()
  token="$(pull_token "${scopes[@]}" "repository::pull" "registry:catalog:*")"
  [ -z "$token" ] || auth=(-H "Authorization: Bearer $token")
  curl_mirror -sS --max-time 10 ${auth[@]+"${auth[@]}"} \
    "$MIRROR_URL/v2/_catalog?n=10000" 2>/dev/null \
    | python3 -I -c 'import json,sys; print("\n".join(json.load(sys.stdin).get("repositories") or []))' \
    2>/dev/null || true
}

self_test() {
  # Pull an image the mirror does not hold yet; it is a real pass only if the mirror
  # stores it afterwards. (Asking the mirror for the image would make it fetch it
  # itself, so that proves nothing.)
  local before image=""
  before="$(catalog)"
  for candidate in $TEST_IMAGES; do
    if ! printf '%s\n' "$before" | grep -qx "library/${candidate%%:*}"; then
      image="$candidate"
      break
    fi
  done
  if [ -z "$image" ]; then
    echo "cached"  # every test image is there already: an earlier run went through it
    return
  fi
  if ! docker pull --quiet "$image" >/dev/null 2>&1; then
    echo "pull_failed"
    return
  fi
  sleep 1
  if catalog | grep -qx "library/${image%%:*}"; then echo "ok"; else echo "not_via_mirror"; fi
}

do_install() {
  need_root
  need docker "install Docker first"
  need python3 "apt install python3"
  need curl "apt install curl"
  [ -n "$REGISTRY" ] || die "--registry is required"
  docker info >/dev/null 2>&1 || die "Docker is not running"
  if [ -n "$REGISTRY_CA" ]; then
    [ -f "$REGISTRY_CA" ] || die "--registry-ca: no such file: $REGISTRY_CA"
    mkdir -p "/etc/docker/certs.d/$REGISTRY"
    cp "$REGISTRY_CA" "/etc/docker/certs.d/$REGISTRY/ca.crt"
    ok "certificate for $REGISTRY added to /etc/docker/certs.d (docker pull)"
    # The built-in builder of 'docker build' trusts only the system store, read when
    # Docker starts.
    if [ -d /usr/local/share/ca-certificates ] && command -v update-ca-certificates >/dev/null 2>&1; then
      cp "$REGISTRY_CA" /usr/local/share/ca-certificates/devassist-mirror.crt
      update-ca-certificates >/dev/null 2>&1 || true
      ok "certificate added to the system store (builds trust it after a Docker restart)"
    elif [ -d /etc/pki/ca-trust/source/anchors ] && command -v update-ca-trust >/dev/null 2>&1; then
      cp "$REGISTRY_CA" /etc/pki/ca-trust/source/anchors/devassist-mirror.crt
      update-ca-trust extract >/dev/null 2>&1 || true
      ok "certificate added to the system store (builds trust it after a Docker restart)"
    else
      warn "could not add the certificate to the system store; builds may skip the mirror"
    fi
  fi

  local code
  code="$(mirror_check)"
  case "$code" in
    open) ok "image registry answers at $MIRROR_URL" ;;
    token)
      if [ -n "$(pull_token "repository:library/busybox:pull")" ]; then
        ok "image registry answers at $MIRROR_URL and the panel gives this server a pull token"
      else
        die "the registry points Docker at the panel for a token, but this server got none; check the token address and the trusted address ranges in DevAssist"
      fi ;;
    password) die "$MIRROR_URL asks Docker for a password, so Docker would skip it; turn on 'Docker access through the panel' in DevAssist (Builds from local mirrors, step 2)" ;;
    *) die "image registry does not answer at $MIRROR_URL; give it a domain with HTTPS first" ;;
  esac

  local daemon_mirror=false reloaded=false restart_needed=false
  if [ "$DO_DAEMON" = "1" ]; then
    backup "$DAEMON_JSON"
    edit_daemon add
    ok "daemon.json: $MIRROR_URL is the first registry mirror"
    daemon_mirror=true
    reload_docker
    if live_has_mirror; then
      reloaded=true
      ok "Docker reloaded the mirror without a restart"
    elif [ "$ALLOW_RESTART" = "1" ]; then
      restart_docker
      if live_has_mirror; then reloaded=true; ok "Docker uses the mirror after the restart"; fi
    else
      restart_needed=true
      warn "Docker did not pick up the mirror on reload; run again with --allow-restart"
    fi
  fi

  local config_dir toml=""
  config_dir="$(docker_config_dir)"
  if [ "$DO_BUILDKIT" = "1" ]; then
    mkdir -p "$config_dir/buildx"
    toml="$config_dir/buildx/buildkitd.default.toml"
    if [ -f "$toml" ] && ! head -n 1 "$toml" | grep -qF "$HEADER"; then
      backup "$toml"
    fi
    write_toml "$toml"
    # Read by every builder created afterwards (Railpack makes one per build). The
    # built-in builder of 'docker build' uses daemon.json's mirror instead.
    ok "builder mirrors written to $toml"
  fi

  local result="skipped"
  if [ "$RUN_TEST" = "1" ]; then
    result="$(self_test)"
    case "$result" in
      ok) ok "test: a test image came through the mirror" ;;
      cached) ok "test: the test images are in the mirror already (an earlier run passed)" ;;
      not_via_mirror) warn "test: the image did not come through the mirror (Docker pulled it directly)" ;;
      *) warn "test: docker pull failed" ;;
    esac
  fi

  write_marker "version=$SCRIPT_VERSION" "registry=$MIRROR_URL" "npm_url=$NPM_URL" \
    "pypi_url=$PYPI_URL" "buildkit_file=$toml" \
    "daemon_mirror=$daemon_mirror" "daemon_reloaded=$reloaded" \
    "restart_needed=$restart_needed" "test=$result" "registry_ca=$REGISTRY_CA" \
    "docker_version=$(docker version --format '{{.Server.Version}}' 2>/dev/null || echo unknown)"
  ok "done. Open DevAssist -> Build mirrors to see the result"
}

do_status() {
  local bad=0 config_dir toml
  if [ -f "$MARKER" ]; then ok "applied: $(tr -d '\n' <"$MARKER" | head -c 400)"; else warn "not applied on this server yet"; bad=1; fi
  [ -n "$REGISTRY" ] || REGISTRY="$(python3 -I -c 'import json,sys;print(json.load(open(sys.argv[1])).get("registry",""))' "$MARKER" 2>/dev/null | sed 's#https://##' || true)"
  [ -n "$REGISTRY_CA" ] || REGISTRY_CA="$(python3 -I -c 'import json,sys;print(json.load(open(sys.argv[1])).get("registry_ca",""))' "$MARKER" 2>/dev/null || true)"
  if [ -n "$REGISTRY" ]; then
    MIRROR_URL="https://$REGISTRY"
    grep -q "$REGISTRY" "$DAEMON_JSON" 2>/dev/null && ok "daemon.json has the mirror" || { warn "daemon.json has no mirror"; bad=1; }
    live_has_mirror && ok "Docker uses the mirror now" || { warn "Docker does not use the mirror yet"; bad=1; }
    case "$(mirror_check)" in
      open) ok "image registry answers" ;;
      token) if [ -n "$(pull_token "repository:library/busybox:pull")" ]; then ok "image registry answers; this server gets a pull token"; else warn "this server gets no pull token from the panel"; bad=1; fi ;;
      password) warn "image registry asks Docker for a password; Docker skips it"; bad=1 ;;
      *) warn "image registry does not answer at $MIRROR_URL"; bad=1 ;;
    esac
  fi
  config_dir="$(docker_config_dir)"
  toml="$config_dir/buildx/buildkitd.default.toml"
  [ -f "$toml" ] && ok "builder mirrors file: $toml" || { warn "no builder mirrors file at $toml"; bad=1; }
  return "$bad"
}

do_undo() {
  need_root
  need python3 "apt install python3"
  [ -n "$REGISTRY" ] || REGISTRY="$(python3 -I -c 'import json,sys;print(json.load(open(sys.argv[1])).get("registry",""))' "$MARKER" 2>/dev/null | sed 's#https://##' || true)"
  [ -n "$REGISTRY_CA" ] || REGISTRY_CA="$(python3 -I -c 'import json,sys;print(json.load(open(sys.argv[1])).get("registry_ca",""))' "$MARKER" 2>/dev/null || true)"
  if [ -n "$REGISTRY" ] && [ -f "$DAEMON_JSON" ]; then
    MIRROR_URL="https://$REGISTRY"
    backup "$DAEMON_JSON"
    edit_daemon remove
    reload_docker
    if live_has_mirror && [ "$ALLOW_RESTART" = "1" ]; then restart_docker; fi
    ok "mirror removed from daemon.json"
  fi
  local config_dir toml
  config_dir="$(docker_config_dir)"
  toml="$config_dir/buildx/buildkitd.default.toml"
  if [ -f "$toml" ] && head -n 1 "$toml" | grep -qF "$HEADER"; then
    rm -f "$toml"
    ok "builder mirrors file removed"
  fi
  # A builder made by version 1 of this script (--default-builder, since removed).
  if DOCKER_CONFIG="$config_dir" docker buildx inspect "$BUILDER" >/dev/null 2>&1; then
    DOCKER_CONFIG="$config_dir" docker buildx use --default default >/dev/null 2>&1 || true
    DOCKER_CONFIG="$config_dir" docker buildx rm "$BUILDER" >/dev/null 2>&1 || true
    ok "builder $BUILDER removed"
  fi
  # Certificates added by --registry-ca.
  if [ -n "$REGISTRY" ] && [ -n "$REGISTRY_CA" ]; then
    rm -rf "/etc/docker/certs.d/$REGISTRY"
    if [ -f /usr/local/share/ca-certificates/devassist-mirror.crt ]; then
      rm -f /usr/local/share/ca-certificates/devassist-mirror.crt
      update-ca-certificates >/dev/null 2>&1 || true
    fi
    if [ -f /etc/pki/ca-trust/source/anchors/devassist-mirror.crt ]; then
      rm -f /etc/pki/ca-trust/source/anchors/devassist-mirror.crt
      update-ca-trust extract >/dev/null 2>&1 || true
    fi
    ok "mirror certificate removed"
  fi
  rm -f "$MARKER"
  ok "undone. Backups stay in $BACKUP_DIR"
}

case "$ACTION" in
  install) do_install ;;
  status) do_status ;;
  undo) do_undo ;;
  *) echo "usage: $0 install|status|undo [options]" >&2; exit 2 ;;
esac
