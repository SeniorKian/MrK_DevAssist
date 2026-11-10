#!/usr/bin/env bash
# install-native.sh — install the MrK DevAssist PANEL without Docker (systemd),
# on Debian 12/13 or Ubuntu 22.04/24.04, amd64 or arm64.
#
# Only the panel is native: the same two programs as the `panel` image target of
# deploy/images/Dockerfile (PGlite + control plane, deploy/images/panel/supervisord.conf),
# built from this checkout with the versions of versions.lock.yaml:
#   * Python in a venv with apps/control-plane and deploy/appliance/requirements.txt
#     (pins checked like the Dockerfile);
#   * Node for PGlite (`npm ci`, lockfile hashes enforced) and the built admin UI.
# Every other service (agent, DNS, firewall, S3, npm, PyPI) runs in Docker and is
# added from the panel: My services -> Add a service (docs/44).
#
# Guide: docs/install-native.md (Persian: docs/install-native.fa.md).
#
#   sudo bash scripts/install-native.sh install
#   sudo bash scripts/install-native.sh upgrade     # after `git pull`
#   sudo bash scripts/install-native.sh status
#   sudo bash scripts/install-native.sh uninstall [--purge]
#   bash scripts/install-native.sh install --dry-run   # show the plan, change nothing

set -Eeuo pipefail

# ----------------------------------------------------------------------------- constants

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd -- "$SCRIPT_DIR/.." && pwd)"
LOCK_FILE="$REPO_ROOT/versions.lock.yaml"
readonly SCRIPT_DIR REPO_ROOT LOCK_FILE

readonly PREFIX="/opt/mrk"
readonly RELEASES="$PREFIX/releases"
readonly RUNTIMES="$PREFIX/runtimes"
readonly MARKER="$PREFIX/.devassist-native"
readonly CONF_DIR="/etc/devassist"
readonly INSTALL_CONF="$CONF_DIR/install.conf"
readonly ENV_FILE="$CONF_DIR/devassist.env"
readonly CACHE_DIR="/var/cache/devassist"
readonly UNIT_DIR="/etc/systemd/system"
readonly UNIT="devassist.service"
readonly TMPFILES="/etc/tmpfiles.d/devassist.conf"
readonly EXEC_HELPER="/usr/local/sbin/devassist-exec"
readonly RUN_USER="devassist"
# uid/gid of the service images: Docker services write their sockets as 10001.
readonly PREFERRED_ID=10001
# Data layout of the panel image (deploy/images/Dockerfile, deploy/appliance/entrypoint.py).
readonly DATA_SUBDIRS=(database control-plane modules)
# Host directories the DNS and firewall containers bind-mount for their sockets.
readonly SOCKET_DIRS=(/run/mrk-dns /run/mrk-firewall)
# Units of older native installs (before docs/44); only ever removed.
readonly LEGACY_UNITS=(devassist-agent devassist-firewall devassist-dns)

# ----------------------------------------------------------------------------- options

COMMAND="install"
DRY_RUN=0
ASSUME_YES=0
PURGE=0
DATA_DIR="/var/lib/devassist"
SKIP_PORT_CHECK=0
SKIP_OS_CHECK=0
MIN_FREE_GB=3
PYTHON_OVERRIDE=""
PIP_INDEX_URL=""
NPM_REGISTRY=""
NO_START=0
REBUILD=0
LANG_MODE="both"

NODE_DIST="${DEVASSIST_NODE_DIST:-https://nodejs.org/dist}"
UV_DIST="${DEVASSIST_UV_DIST:-https://github.com/astral-sh/uv/releases/download}"

usage() {
    cat <<'EOF'
Usage: sudo bash scripts/install-native.sh [COMMAND] [OPTIONS]

Installs only the panel. Add the other services from the panel (they run in Docker).

Commands:
  install     install or repair (default; safe to run again)
  upgrade     build the current checkout, then switch with a short restart
  status      show the unit, release and health
  uninstall   remove programs and units (data and /etc/devassist are kept)

Options:
  --data-dir DIR        data directory on the host (default /var/lib/devassist)
  --python PATH         use an existing Python 3.13 instead of the pinned build
  --pip-index-url URL   PyPI mirror for the build (trusted like PyPI: pip checks no hashes)
  --npm-registry URL    npm mirror for the build (lockfile hashes still enforced)
  --rebuild             rebuild even if this commit is already built
  --no-start            install but do not start or restart the service
  --skip-port-check     do not stop when a needed port is in use
  --skip-os-check       allow an untested distribution (unsupported)
  --min-free-gb N       free disk space required (default 3)
  --purge               with uninstall: also delete data, config and the user
  --yes                 do not ask for confirmation
  --dry-run             print what would be done, change nothing
  --lang fa|en|both     message language (default both)
  -h, --help            this help

Download mirrors (environment): DEVASSIST_NODE_DIST, DEVASSIST_UV_DIST, and
uv's own UV_PYTHON_INSTALL_MIRROR for Python builds.
EOF
}

parse_args() {
    if [[ $# -gt 0 && "$1" != -* ]]; then
        COMMAND="$1"
        shift
    fi
    while [[ $# -gt 0 ]]; do
        case "$1" in
            --data-dir) DATA_DIR="${2:?--data-dir needs a value}"; shift ;;
            --python) PYTHON_OVERRIDE="${2:?--python needs a value}"; shift ;;
            --pip-index-url) PIP_INDEX_URL="${2:?--pip-index-url needs a value}"; shift ;;
            --npm-registry) NPM_REGISTRY="${2:?--npm-registry needs a value}"; shift ;;
            --rebuild) REBUILD=1 ;;
            --no-start) NO_START=1 ;;
            --skip-port-check) SKIP_PORT_CHECK=1 ;;
            --skip-os-check) SKIP_OS_CHECK=1 ;;
            --min-free-gb) MIN_FREE_GB="${2:?--min-free-gb needs a value}"; shift ;;
            --purge) PURGE=1 ;;
            --yes|-y) ASSUME_YES=1 ;;
            --dry-run) DRY_RUN=1 ;;
            --lang) LANG_MODE="${2:?--lang needs a value}"; shift ;;
            -h|--help) usage; exit 0 ;;
            *) usage >&2; die "گزینه ناشناخته: $1" "unknown option: $1" ;;
        esac
        shift
    done
    case "$COMMAND" in
        install|upgrade|status|uninstall) ;;
        *) usage >&2; die "فرمان ناشناخته: $COMMAND" "unknown command: $COMMAND" ;;
    esac
    case "$LANG_MODE" in fa|en|both) ;; *) die "زبان باید fa، en یا both باشد" "--lang must be fa, en or both" ;; esac
    [[ "$MIN_FREE_GB" =~ ^[0-9]+$ ]] || die "--min-free-gb باید عدد باشد" "--min-free-gb must be a number"
}

# ----------------------------------------------------------------------------- output

if [[ -t 1 ]]; then
    C_INFO=$'\033[1;36m' C_WARN=$'\033[1;33m' C_ERR=$'\033[1;31m' C_OK=$'\033[1;32m' C_OFF=$'\033[0m'
else
    C_INFO="" C_WARN="" C_ERR="" C_OK="" C_OFF=""
fi

# say LEVEL "persian" "english"
say() {
    local level="$1" fa="$2" en="$3" color="$C_INFO" tag="devassist"
    case "$level" in
        warn) color="$C_WARN"; tag="devassist: warning" ;;
        error) color="$C_ERR"; tag="devassist: error" ;;
        ok) color="$C_OK" ;;
    esac
    case "$LANG_MODE" in
        en) printf '%s[%s]%s %s\n' "$color" "$tag" "$C_OFF" "$en" ;;
        fa) printf '%s[%s]%s %s\n' "$color" "$tag" "$C_OFF" "$fa" ;;
        *) printf '%s[%s]%s %s\n         %s\n' "$color" "$tag" "$C_OFF" "$en" "$fa" ;;
    esac
}
info() { say info "$1" "$2"; }
warn() { say warn "$1" "$2" >&2; }
ok() { say ok "$1" "$2"; }
die() { say error "$1" "$2" >&2; exit 1; }
step() { printf '\n%s==>%s %s\n' "$C_INFO" "$C_OFF" "$1"; }

on_error() {
    local code=$? line="$1"
    # Report once, from the main shell, not again from every command substitution.
    [[ $BASHPID -eq $$ ]] || exit "$code"
    say error "خطا در خط $line (کد $code). هیچ نسخه نیمه‌کاره‌ای فعال نمی‌شود." \
        "failed at line $line (exit $code). A half-built release is never activated." >&2
    exit "$code"
}
trap 'on_error $LINENO' ERR

# run CMD... : execute, or print in --dry-run mode.
run() {
    if [[ $DRY_RUN -eq 1 ]]; then
        printf '  + %s\n' "$(printf '%q ' "$@")"
        return 0
    fi
    "$@"
}

# put_file MODE OWNER GROUP DEST < content
put_file() {
    local mode="$1" owner="$2" group="$3" dest="$4" tmp
    if [[ $DRY_RUN -eq 1 ]]; then
        printf '  + write %s (%s %s:%s)\n' "$dest" "$mode" "$owner" "$group"
        cat >/dev/null
        return 0
    fi
    tmp="$(mktemp)"
    cat >"$tmp"
    install -m "$mode" -o "$owner" -g "$group" "$tmp" "$dest"
    rm -f "$tmp"
}

confirm() {
    local prompt_fa="$1" prompt_en="$2" expected="$3" answer
    [[ $ASSUME_YES -eq 1 || $DRY_RUN -eq 1 ]] && return 0
    [[ -t 0 ]] || die "برای ادامه بدون ترمینال --yes بدهید" "not a terminal; pass --yes to continue"
    info "$prompt_fa" "$prompt_en"
    read -r -p "> type/بنویسید $expected: " answer
    [[ "$answer" == "$expected" ]] || die "لغو شد" "cancelled"
}

have() { command -v "$1" >/dev/null 2>&1; }
unit_active() { systemctl is-active --quiet "$1" 2>/dev/null; }

# ----------------------------------------------------------------------------- versions.lock.yaml

# lock_version COMPONENT -> the `version:` of that component in versions.lock.yaml
lock_version() {
    awk -v name="$1" '
        $0 ~ "^  " name ":[[:space:]]*$" { found = 1; next }
        found && /^  [^ ]/ { exit }
        found && /^    version:/ {
            sub(/^    version:[[:space:]]*"?/, ""); sub(/"?[[:space:]]*$/, ""); print; exit
        }
    ' "$LOCK_FILE"
}

load_pins() {
    [[ -f "$LOCK_FILE" ]] || die "versions.lock.yaml پیدا نشد؛ اسکریپت را از داخل ریپو اجرا کنید" \
        "versions.lock.yaml not found; run the script from the repository checkout"
    PY_VERSION="$(lock_version python)"
    NODE_VERSION="$(lock_version node)"
    UV_VERSION="$(lock_version uv)"
    local name
    for name in PY_VERSION NODE_VERSION UV_VERSION; do
        [[ "${!name}" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]] || die "نسخه $name در versions.lock.yaml خوانده نشد" \
            "could not read $name from versions.lock.yaml"
    done
}

# ----------------------------------------------------------------------------- checks

require_root() {
    if [[ $EUID -ne 0 ]]; then
        if [[ $DRY_RUN -eq 1 ]]; then
            warn "بدون root فقط پیش‌نمایش است؛ بعضی بررسی‌ها کامل نیستند" \
                "not root: preview only, some checks are incomplete"
            return 0
        fi
        die "با sudo یا root اجرا کنید" "run as root (sudo)"
    fi
}

check_os() {
    [[ -r /etc/os-release ]] || die "/etc/os-release نیست؛ توزیع شناخته نشد" "cannot read /etc/os-release"
    local os_id os_version
    # shellcheck disable=SC1091
    os_id="$(. /etc/os-release && printf '%s' "${ID:-}")"
    # shellcheck disable=SC1091
    os_version="$(. /etc/os-release && printf '%s' "${VERSION_ID:-}")"
    case "$os_id:$os_version" in
        debian:12|debian:13|ubuntu:22.04|ubuntu:24.04)
            info "سیستم‌عامل: $os_id $os_version" "OS: $os_id $os_version" ;;
        *)
            if [[ $SKIP_OS_CHECK -eq 1 ]]; then
                warn "توزیع $os_id $os_version آزموده نشده است" "untested distribution $os_id $os_version"
            else
                die "فقط Debian 12/13 و Ubuntu 22.04/24.04 پشتیبانی می‌شوند ($os_id $os_version)" \
                    "only Debian 12/13 and Ubuntu 22.04/24.04 are supported (found $os_id $os_version)"
            fi ;;
    esac
    case "$(uname -m)" in
        x86_64) NODE_ARCH="x64"; UV_TRIPLE="x86_64-unknown-linux-gnu" ;;
        aarch64|arm64) NODE_ARCH="arm64"; UV_TRIPLE="aarch64-unknown-linux-gnu" ;;
        *) die "معماری $(uname -m) پشتیبانی نمی‌شود (فقط amd64 و arm64)" \
            "unsupported architecture $(uname -m) (amd64 and arm64 only)" ;;
    esac
    [[ -d /run/systemd/system ]] || die "systemd در حال اجرا نیست؛ نصب بومی systemd لازم دارد" \
        "systemd is not running; the native install needs systemd"
}

check_data_dir() {
    [[ "$DATA_DIR" =~ ^/[A-Za-z0-9._/-]+$ ]] || die "مسیر داده باید مطلق و بدون فاصله باشد: $DATA_DIR" \
        "the data directory must be an absolute path without spaces: $DATA_DIR"
    DATA_DIR="${DATA_DIR%/}"
    case "$DATA_DIR" in
        /|/opt/mrk|/opt/mrk/*|/etc|/etc/*|/usr|/usr/*|/proc*|/sys*|/dev*|/run*|/tmp*)
            die "این مسیر برای داده مناسب نیست: $DATA_DIR" "not a valid data directory: $DATA_DIR" ;;
    esac
    [[ ! -L "$DATA_DIR" ]] || die "مسیر داده نباید symlink باشد: $DATA_DIR" \
        "the data directory must not be a symlink: $DATA_DIR"
}

# free_kb PATH -> free KiB on the filesystem holding PATH (or its nearest parent)
free_kb() {
    local path="$1"
    while [[ ! -e "$path" ]]; do path="$(dirname -- "$path")"; done
    df -Pk -- "$path" | awk 'NR == 2 { print $4 }'
}

check_resources() {
    local need_kb=$((MIN_FREE_GB * 1024 * 1024)) path free mem_kb
    for path in "$PREFIX" "$CACHE_DIR" "$DATA_DIR"; do
        free="$(free_kb "$path")"
        if [[ -z "$free" || "$free" -lt "$need_kb" ]]; then
            die "فضای خالی کافی برای $path نیست (کمتر از ${MIN_FREE_GB} گیگابایت)" \
                "not enough free space for $path (less than ${MIN_FREE_GB} GiB)"
        fi
    done
    mem_kb="$(awk '/^MemTotal:/ { print $2 }' /proc/meminfo)"
    if [[ -n "$mem_kb" && "$mem_kb" -lt 1900000 ]]; then
        warn "حافظه کمتر از 2 گیگابایت است؛ پنل تا 1 گیگابایت و سرویس‌های Docker جدا مصرف می‌کنند" \
            "less than 2 GiB of RAM; the panel may use up to 1 GiB, plus the Docker services"
    fi
}

# port_users PORT -> listening sockets on that port (ss "Local Address:Port" column)
port_users() {
    ss -Hlntu 2>/dev/null | awk -v port="$1" '{ n = split($5, a, ":"); if (a[n] == port) print $1 " " $5 }'
}

check_ports() {
    [[ $SKIP_PORT_CHECK -eq 1 ]] && return 0
    unit_active "$UNIT" && return 0
    have ss || { warn "ss نیست؛ بررسی پورت‌ها انجام نشد" "ss not found; ports not checked"; return 0; }
    local port used failed=0
    # 8080: the panel. 5433: PGlite, loopback only.
    for port in 8080 5433; do
        used="$(port_users "$port")"
        if [[ -n "$used" ]]; then
            warn "پورت $port در حال استفاده است: $used" "port $port is already in use: $used"
            failed=1
        fi
    done
    [[ $failed -eq 0 ]] || die "پورت‌ها را آزاد کنید یا با --skip-port-check ادامه دهید" \
        "free the ports or continue with --skip-port-check"
}

check_docker_panel() {
    have docker || return 0
    if docker ps --format '{{.Names}} {{.Image}}' 2>/dev/null | grep -Eq 'mrk-panel|mrk-mirror|mrk/package-mirror'; then
        die "پنل DevAssist در Docker در حال اجراست؛ هر دو با هم روی یک سرور اجرا نشوند" \
            "the Docker panel of DevAssist is running; do not run both on one server"
    fi
}

check_existing_prefix() {
    if [[ -e "$PREFIX" && ! -e "$MARKER" ]]; then
        die "$PREFIX وجود دارد ولی مال این نصب نیست؛ دست نمی‌زنم" \
            "$PREFIX exists but was not created by this installer; refusing to touch it"
    fi
}

warn_legacy_units() {
    local unit
    for unit in "${LEGACY_UNITS[@]}"; do
        [[ -e "$UNIT_DIR/$unit.service" ]] || continue
        warn "$unit از نصب قدیمی مانده و دیگر مدیریت نمی‌شود؛ آن را از پنل با Docker جایگزین کنید و با «systemctl disable --now $unit» ببندید" \
            "$unit is left from an older install and no longer managed; replace it from the panel (Docker), then: systemctl disable --now $unit"
    done
}

# ----------------------------------------------------------------------------- packages and runtimes

install_packages() {
    step "System packages / بسته‌های سیستم"
    local missing=() pkg
    for pkg in ca-certificates curl xz-utils tar gzip coreutils util-linux iproute2 git; do
        dpkg-query -W -f='${Status}' "$pkg" 2>/dev/null | grep -q "install ok installed" || missing+=("$pkg")
    done
    [[ ${#missing[@]} -eq 0 ]] && return 0
    info "نصب بسته‌های سیستم: ${missing[*]}" "installing system packages: ${missing[*]}"
    run env DEBIAN_FRONTEND=noninteractive apt-get update -qq
    run env DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends "${missing[@]}"
}

download() {
    run curl --fail --silent --show-error --location --proto '=https' --tlsv1.2 \
        --retry 3 --retry-delay 2 --output "$2" "$1"
}

# verify_sha256 FILE EXPECTED_HEX
verify_sha256() {
    local file="$1" expected="$2"
    [[ $DRY_RUN -eq 1 ]] && { printf '  + verify sha256 %s\n' "$file"; return 0; }
    [[ "$expected" =~ ^[0-9a-f]{64}$ ]] || die "checksum نامعتبر برای $file" "invalid checksum for $file"
    printf '%s  %s\n' "$expected" "$file" | sha256sum --check --status \
        || die "checksum فایل $file درست نیست" "checksum mismatch for $file"
}

install_uv() {
    UV_BIN="$CACHE_DIR/tools/uv-$UV_VERSION/uv"
    [[ -x "$UV_BIN" ]] && return 0
    info "دانلود uv $UV_VERSION (فقط برای نصب Python)" "downloading uv $UV_VERSION (installs Python only)"
    local name="uv-$UV_TRIPLE.tar.gz" tmp="$CACHE_DIR/downloads"
    run install -d -m 0755 "$tmp" "$CACHE_DIR/tools/uv-$UV_VERSION"
    download "$UV_DIST/$UV_VERSION/$name" "$tmp/$name"
    download "$UV_DIST/$UV_VERSION/$name.sha256" "$tmp/$name.sha256"
    [[ $DRY_RUN -eq 1 ]] || verify_sha256 "$tmp/$name" "$(awk '{ print $1; exit }' "$tmp/$name.sha256")"
    run tar -xzf "$tmp/$name" -C "$CACHE_DIR/tools/uv-$UV_VERSION" --strip-components=1
}

install_python() {
    step "Python $PY_VERSION"
    if [[ -n "$PYTHON_OVERRIDE" ]]; then
        [[ -x "$PYTHON_OVERRIDE" ]] || die "Python پیدا نشد: $PYTHON_OVERRIDE" "Python not found: $PYTHON_OVERRIDE"
        PYTHON_BIN="$PYTHON_OVERRIDE"
        local actual
        actual="$("$PYTHON_BIN" -c 'import sys; print("%d.%d.%d" % sys.version_info[:3])')"
        [[ "$actual" == 3.13.* ]] || die "Python 3.13 لازم است (این $actual است)" "Python 3.13 is required (got $actual)"
        [[ "$actual" == "$PY_VERSION" ]] || warn "Python $actual با نسخه پین‌شده $PY_VERSION فرق دارد" \
            "Python $actual differs from the pinned $PY_VERSION"
        return 0
    fi
    install_uv
    run install -d -m 0755 "$RUNTIMES/python"
    run env UV_PYTHON_INSTALL_DIR="$RUNTIMES/python" UV_PYTHON_BIN_DIR="$CACHE_DIR/tools/uv-bin" \
        UV_CACHE_DIR="$CACHE_DIR/uv" "$UV_BIN" python install "$PY_VERSION"
    if [[ $DRY_RUN -eq 1 ]]; then
        PYTHON_BIN="$RUNTIMES/python/cpython-$PY_VERSION/bin/python3"
        return 0
    fi
    PYTHON_BIN="$(env UV_PYTHON_INSTALL_DIR="$RUNTIMES/python" UV_PYTHON_PREFERENCE=only-managed \
        "$UV_BIN" python find "$PY_VERSION")"
    [[ -x "$PYTHON_BIN" ]] || die "Python $PY_VERSION نصب نشد" "Python $PY_VERSION was not installed"
}

install_node() {
    step "Node.js $NODE_VERSION"
    local dir="node-v$NODE_VERSION-linux-$NODE_ARCH" tmp="$CACHE_DIR/downloads"
    NODE_HOME="$RUNTIMES/$dir"
    if [[ -x "$NODE_HOME/bin/node" ]]; then
        info "Node $NODE_VERSION از قبل نصب است" "Node $NODE_VERSION already installed"
        return 0
    fi
    run install -d -m 0755 "$tmp" "$RUNTIMES"
    download "$NODE_DIST/v$NODE_VERSION/$dir.tar.xz" "$tmp/$dir.tar.xz"
    download "$NODE_DIST/v$NODE_VERSION/SHASUMS256.txt" "$tmp/node-v$NODE_VERSION-SHASUMS256.txt"
    if [[ $DRY_RUN -eq 0 ]]; then
        verify_sha256 "$tmp/$dir.tar.xz" \
            "$(awk -v f="$dir.tar.xz" '$2 == f { print $1 }' "$tmp/node-v$NODE_VERSION-SHASUMS256.txt")"
    fi
    run tar -xJf "$tmp/$dir.tar.xz" -C "$RUNTIMES" --no-same-owner
}

# ----------------------------------------------------------------------------- build

source_commit() {
    local git_cmd=(git -c safe.directory="$REPO_ROOT" -C "$REPO_ROOT")
    if have git && "${git_cmd[@]}" rev-parse HEAD >/dev/null 2>&1; then
        COMMIT="$("${git_cmd[@]}" rev-parse HEAD)"
        RELEASE_ID="${COMMIT:0:12}"
        if [[ -n "$("${git_cmd[@]}" status --porcelain --untracked-files=no)" ]]; then
            RELEASE_ID="$RELEASE_ID-dirty-$(date -u +%Y%m%d%H%M%S)"
        fi
    else
        COMMIT="unknown"
        RELEASE_ID="build-$(date -u +%Y%m%d%H%M%S)"
    fi
    BUILD_DATE="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
    RELEASE_DIR="$RELEASES/$RELEASE_ID"
}

# npm_in DIR ARGS... : run npm in DIR with the pinned Node and optional mirror
npm_in() {
    local dir="$1"
    shift
    local -a env_vars=(PATH="$NODE_HOME/bin:/usr/bin:/bin" npm_config_cache="$CACHE_DIR/npm"
        npm_config_update_notifier=false npm_config_fund=false npm_config_audit=false
        VITE_BUILD_COMMIT="$COMMIT" VITE_BUILD_DATE="$BUILD_DATE")
    if [[ -n "$NPM_REGISTRY" ]]; then
        env_vars+=(npm_config_registry="$NPM_REGISTRY" npm_config_replace_registry_host=always)
    fi
    if [[ $DRY_RUN -eq 1 ]]; then
        printf '  + (cd %q && npm %s)\n' "$dir" "$*"
        return 0
    fi
    (cd "$dir" && env "${env_vars[@]}" "$NODE_HOME/bin/npm" "$@")
}

build_python_env() {
    step "Control plane venv"
    local venv="$RELEASE_DIR/venv" pip_args=()
    [[ -n "$PIP_INDEX_URL" ]] && pip_args+=(--index-url "$PIP_INDEX_URL")
    if [[ -n "$PYTHON_OVERRIDE" ]]; then
        run "$PYTHON_BIN" -m venv "$venv"
    else
        run env UV_CACHE_DIR="$CACHE_DIR/uv" "$UV_BIN" venv --seed --python "$PYTHON_BIN" "$venv"
    fi
    # Same install line and pin check as the python-base stage of deploy/images/Dockerfile.
    run env PIP_DISABLE_PIP_VERSION_CHECK=1 PIP_CACHE_DIR="$CACHE_DIR/pip" "$venv/bin/python" -m pip install \
        "${pip_args[@]}" "$REPO_ROOT/apps/control-plane" -r "$REPO_ROOT/deploy/appliance/requirements.txt"
    run "$venv/bin/python" -c "import importlib.metadata as md, sys; pins = [line.strip().split('==') for line in open(sys.argv[1]) if '==' in line and not line.startswith('#')]; bad = [(name, want, md.version(name)) for name, want in pins if md.version(name) != want]; sys.exit(f'runtime pin mismatch: {bad}' if bad else 0)" \
        "$REPO_ROOT/deploy/appliance/requirements.txt"
    run "$venv/bin/python" -m pip uninstall --yes pip wheel
}

build_node_parts() {
    step "PGlite, admin UI"
    run install -d -m 0755 "$RELEASE_DIR/pglite"
    run cp "$REPO_ROOT/deploy/pglite/package.json" "$REPO_ROOT/deploy/pglite/package-lock.json" "$RELEASE_DIR/pglite/"
    npm_in "$RELEASE_DIR/pglite" ci --omit=dev --ignore-scripts
    local build="$CACHE_DIR/build/admin-ui"
    run rm -rf "$build"
    run install -d -m 0755 "$build"
    run tar -C "$REPO_ROOT/apps/admin-ui" --exclude=./node_modules --exclude=./dist -cf "$CACHE_DIR/build/admin-ui.tar" .
    run tar -C "$build" -xf "$CACHE_DIR/build/admin-ui.tar"
    npm_in "$build" ci --ignore-scripts
    npm_in "$build" run build
    run cp -a "$build/dist" "$RELEASE_DIR/admin-ui"
    run rm -rf "$build" "$CACHE_DIR/build/admin-ui.tar"
}

# The command directory mounted at /usr/local/bin inside devassist.service: the
# absolute paths supervisord.conf and the control plane use.
build_bin_dir() {
    local bin="$RELEASE_DIR/bin" venv_bin="$RELEASE_DIR/venv/bin" entry name
    run install -d -m 0755 "$bin"
    if [[ $DRY_RUN -eq 1 ]]; then
        printf '  + link venv entry points, node and python wrappers into %s\n' "$bin"
        return 0
    fi
    for entry in "$venv_bin"/*; do
        name="$(basename -- "$entry")"
        case "$name" in activate*|python*|pip*|Activate*|deactivate*) continue ;; esac
        [[ -f "$entry" && -x "$entry" ]] && ln -sfn "$entry" "$bin/$name"
    done
    ln -sfn "$NODE_HOME/bin/node" "$bin/node"
    # A symlinked venv python would not find pyvenv.cfg; use small wrappers.
    for name in python python3; do
        # shellcheck disable=SC2016 # "$@" is written into the wrapper literally
        printf '#!/bin/sh\nexec %s "$@"\n' "$venv_bin/python" >"$bin/$name"
        chmod 0755 "$bin/$name"
    done
}

copy_release_files() {
    run install -m 0644 "$REPO_ROOT/deploy/images/panel/supervisord.conf" "$RELEASE_DIR/supervisord.conf"
    # Same CRLF guard as the Dockerfile.
    run sed -i 's/\r$//' "$RELEASE_DIR/supervisord.conf"
    run install -m 0644 "$REPO_ROOT/deploy/native/devassist_supervise.py" "$RELEASE_DIR/devassist_supervise.py"
    run install -m 0644 "$REPO_ROOT/LICENSE" "$RELEASE_DIR/LICENSE"
    printf 'commit=%s\nbuild_date=%s\npython=%s\nnode=%s\n' "$COMMIT" "$BUILD_DATE" "$PY_VERSION" "$NODE_VERSION" \
        | put_file 0644 root root "$RELEASE_DIR/RELEASE"
}

release_complete() { [[ -d "$1" && ! -e "$1/.incomplete" && -x "$1/venv/bin/python" && -d "$1/pglite" ]]; }

build_release() {
    source_commit
    if release_complete "$RELEASE_DIR" && [[ $REBUILD -eq 0 ]]; then
        ok "نسخه $RELEASE_ID از قبل ساخته شده است (برای ساخت دوباره --rebuild)" \
            "release $RELEASE_ID is already built (use --rebuild to build again)"
        return 0
    fi
    # Never delete or rebuild an existing release in place: it may be the active one.
    if [[ -e "$RELEASE_DIR" ]]; then
        RELEASE_ID="$RELEASE_ID-$(date -u +%Y%m%d%H%M%S)"
        RELEASE_DIR="$RELEASES/$RELEASE_ID"
    fi
    step "Build release $RELEASE_ID"
    run install -d -m 0755 "$RELEASE_DIR" "$CACHE_DIR"
    run touch "$RELEASE_DIR/.incomplete"
    install_python
    install_node
    build_python_env
    build_node_parts
    build_bin_dir
    copy_release_files
    # Application files stay root-owned and read-only for the runtime user (like the image).
    run chown -R root:root "$RELEASE_DIR"
    run chmod -R u=rwX,go=rX "$RELEASE_DIR"
    run rm -f "$RELEASE_DIR/.incomplete"
    ok "نسخه $RELEASE_ID ساخته شد" "release $RELEASE_ID built"
}

clean_incomplete_releases() {
    local dir
    [[ -d "$RELEASES" ]] || return 0
    for dir in "$RELEASES"/*; do
        [[ -d "$dir" && -e "$dir/.incomplete" ]] || continue
        warn "حذف نسخه نیمه‌کاره $(basename -- "$dir")" "removing the incomplete release $(basename -- "$dir")"
        run rm -rf "$dir"
    done
}

# Keep the active release and the one before it.
prune_releases() {
    local current keep=() dir
    [[ -d "$RELEASES" ]] || return 0
    current="$(readlink -f "$PREFIX/current" 2>/dev/null || true)"
    # shellcheck disable=SC2012 # release names are [A-Za-z0-9-] only
    mapfile -t keep < <(ls -1dt "$RELEASES"/*/ 2>/dev/null | head -n 2)
    for dir in "$RELEASES"/*/; do
        dir="${dir%/}"
        [[ -d "$dir" && "$dir" != "$current" ]] || continue
        [[ " ${keep[*]%/} " == *" $dir "* ]] && continue
        run rm -rf "$dir"
    done
}

# ----------------------------------------------------------------------------- system layout

ensure_user() {
    step "System user / کاربر سیستمی"
    if getent passwd "$RUN_USER" >/dev/null; then
        info "کاربر $RUN_USER وجود دارد" "user $RUN_USER exists"
    elif ! getent group "$PREFERRED_ID" >/dev/null && ! getent passwd "$PREFERRED_ID" >/dev/null; then
        # Same uid/gid as the images, so the panel reads the Docker services' sockets.
        run groupadd --system --gid "$PREFERRED_ID" "$RUN_USER"
        run useradd --system --uid "$PREFERRED_ID" --gid "$PREFERRED_ID" --no-create-home \
            --home-dir /nonexistent --shell /usr/sbin/nologin --comment "DevAssist" "$RUN_USER"
    else
        run groupadd --system "$RUN_USER"
        run useradd --system --gid "$RUN_USER" --no-create-home \
            --home-dir /nonexistent --shell /usr/sbin/nologin --comment "DevAssist" "$RUN_USER"
    fi
    if [[ $DRY_RUN -eq 0 && "$(id -u "$RUN_USER")" != "$PREFERRED_ID" ]]; then
        warn "uid کاربر $RUN_USER برابر 10001 نیست؛ سوکت‌های DNS و فایروال (uid 10001) شاید خوانا نباشند (docs/install-native.md)" \
            "$RUN_USER is not uid 10001; the DNS and firewall sockets (uid 10001) may be unreadable (docs/install-native.md)"
    fi
}

# mount_point PATH: an empty directory that systemd mounts over inside the unit.
mount_point() {
    local path="$1"
    if [[ -e "$path" || -L "$path" ]]; then
        [[ -d "$path" && ! -L "$path" ]] || die "$path باید پوشه باشد" "$path must be a directory"
        return 0
    fi
    run install -d -m 0755 -o root -g root "$path"
    CREATED_MOUNT_POINTS+=("$path")
}

ensure_layout() {
    step "Directories / پوشه‌ها"
    CREATED_MOUNT_POINTS=()
    if [[ -r "$INSTALL_CONF" ]]; then
        read -r -a CREATED_MOUNT_POINTS <<<"$(sed -n 's/^DEVASSIST_CREATED_MOUNT_POINTS=//p' "$INSTALL_CONF" | head -n 1)"
    fi
    run install -d -m 0755 -o root -g root "$PREFIX" "$RELEASES" "$RUNTIMES" "$CACHE_DIR"
    [[ -e "$MARKER" ]] || printf 'DevAssist native install; managed by scripts/install-native.sh\n' \
        | put_file 0644 root root "$MARKER"
    run install -d -m 0750 -o root -g "$RUN_USER" "$CONF_DIR"
    run install -d -m 0750 -o "$RUN_USER" -g "$RUN_USER" "$DATA_DIR"
    local sub
    for sub in "${DATA_SUBDIRS[@]}"; do
        run install -d -m 0750 -o "$RUN_USER" -g "$RUN_USER" "$DATA_DIR/$sub"
    done
    # Mount points for the container paths the code expects.
    mount_point /data
    mount_point /opt/pglite
    # Socket directories the DNS and firewall containers bind-mount (recreated at boot):
    # owned by the images' uid 10001, group devassist (setgid) so the panel can read them.
    {
        printf '# Written by scripts/install-native.sh: sockets of the Docker DNS and firewall services.\n'
        for sub in "${SOCKET_DIRS[@]}"; do
            printf 'd %s 2750 %s %s -\n' "$sub" "$PREFERRED_ID" "$RUN_USER"
        done
    } | put_file 0644 root root "$TMPFILES"
    run systemd-tmpfiles --create "$TMPFILES"
}

# set_env KEY VALUE: replace or append one line of the env file.
set_env() {
    if [[ $DRY_RUN -eq 1 ]]; then
        printf '  + set %s=%s in %s\n' "$1" "$2" "$ENV_FILE"
    elif grep -q "^$1=" "$ENV_FILE"; then
        sed -i "s|^$1=.*|$1=$2|" "$ENV_FILE"
    else
        printf '%s=%s\n' "$1" "$2" >>"$ENV_FILE"
    fi
}

install_config() {
    step "Configuration / تنظیمات"
    if [[ -e "$ENV_FILE" ]]; then
        info "$ENV_FILE از قبل هست و تغییرات شما می‌ماند" "$ENV_FILE exists; your changes are kept"
    else
        sed -e "s|@DEVASSIST_COMMIT@|$COMMIT|g" -e "s|@DEVASSIST_BUILD_DATE@|$BUILD_DATE|g" \
            "$REPO_ROOT/deploy/native/devassist.env.example" | put_file 0640 root "$RUN_USER" "$ENV_FILE"
    fi
    # Panel-only facts, also enforced on env files of older installs.
    set_env MRK_PANEL_RUNTIME native
    set_env MRK_NPM_ENABLED false
    set_env MRK_PYPI_ENABLED false
    set_env MRK_BUILD_COMMIT "$COMMIT"
    set_env MRK_BUILD_DATE "$BUILD_DATE"
    {
        printf '# Written by scripts/install-native.sh. Do not edit by hand.\n'
        printf 'DEVASSIST_DATA_DIR=%s\n' "$DATA_DIR"
        printf 'DEVASSIST_REPO=%s\n' "$REPO_ROOT"
        printf 'DEVASSIST_CREATED_MOUNT_POINTS=%s\n' "${CREATED_MOUNT_POINTS[*]}"
    } | put_file 0644 root root "$INSTALL_CONF"
    run install -m 0755 -o root -g root "$REPO_ROOT/deploy/native/devassist-exec.sh" "$EXEC_HELPER"
    sed -e "s|@DEVASSIST_DATA_DIR@|$DATA_DIR|g" "$REPO_ROOT/deploy/native/systemd/$UNIT" \
        | put_file 0644 root root "$UNIT_DIR/$UNIT"
    run systemctl daemon-reload
}

load_install_conf() {
    [[ -r "$INSTALL_CONF" ]] || return 0
    local value
    value="$(sed -n 's/^DEVASSIST_DATA_DIR=//p' "$INSTALL_CONF" | head -n 1)"
    [[ -n "$value" ]] && DATA_DIR="$value"
    return 0
}

# ----------------------------------------------------------------------------- activate

activate_release() {
    step "Activate / فعال‌سازی $RELEASE_ID"
    local link
    if unit_active "$UNIT" && [[ $NO_START -eq 0 ]]; then
        info "توقف سرویس (تا 3 دقیقه؛ PGlite آخر از همه بسته می‌شود)" \
            "stopping the service (up to 3 minutes; PGlite stops last)"
        run systemctl stop "$UNIT"
    fi
    run ln -sfn "releases/$RELEASE_ID" "$PREFIX/current"
    for link in venv admin-ui pglite bin supervisord.conf devassist_supervise.py LICENSE; do
        run ln -sfn "current/$link" "$PREFIX/$link"
    done
    # Leftovers of the pre-docs/44 layout (npm and PyPI ran inside the panel).
    run rm -f "$PREFIX/verdaccio" "$PREFIX/devpi-start.sh" "$PREFIX/devpi-configure.sh"
    [[ $NO_START -eq 1 ]] && return 0
    run systemctl enable "$UNIT"
    run systemctl start "$UNIT"
}

wait_ready() {
    [[ $NO_START -eq 1 || $DRY_RUN -eq 1 ]] && return 0
    info "منتظر آماده شدن پنل (اولین اجرا چند دقیقه طول می‌کشد)" \
        "waiting for the panel to be ready (the first start takes a few minutes)"
    local waited=0
    until "$EXEC_HELPER" python -m mrk_control_plane.healthcheck >/dev/null 2>&1; do
        unit_active "$UNIT" || die "سرویس devassist اجرا نمی‌شود؛ ببینید: journalctl -u devassist -n 100" \
            "devassist.service is not running; see: journalctl -u devassist -n 100"
        if [[ $waited -ge 600 ]]; then
            warn "پنل بعد از 10 دقیقه آماده نشد؛ لاگ را ببینید: journalctl -u devassist -f" \
                "the panel was not ready after 10 minutes; check: journalctl -u devassist -f"
            return 0
        fi
        sleep 5
        waited=$((waited + 5))
    done
    ok "پنل آماده است" "the panel is ready"
}

summary() {
    local port="" host=""
    if [[ -r "$ENV_FILE" ]]; then
        port="$(sed -n 's/^MRK_PORT=//p' "$ENV_FILE" | head -n 1)"
        host="$(sed -n 's/^MRK_HOST=//p' "$ENV_FILE" | head -n 1)"
    fi
    port="${port:-8080}"
    host="${host:-127.0.0.1}"
    printf '\n'
    ok "نصب تمام شد" "installation finished"
    cat <<EOF

  Panel / پنل:          http://$host:$port  (from your PC: ssh -L $port:127.0.0.1:$port <server>)
  First visit:          the panel shows "First Time Setup" to create the owner account
  Next / بعد:           My services -> Add a service (agent, DNS, firewall, S3 run in Docker)
                        سرویس‌های من ← افزودن سرویس (بقیه سرویس‌ها با Docker اجرا می‌شوند)
  Logs / لاگ:           journalctl -u devassist -f
  Config / تنظیمات:     $ENV_FILE  (then: systemctl restart devassist)
  Data / داده:          $DATA_DIR
  Upgrade / ارتقا:      git pull && sudo bash scripts/install-native.sh upgrade
  Uninstall / حذف:      sudo bash scripts/install-native.sh uninstall
EOF
}

# ----------------------------------------------------------------------------- commands

cmd_install() {
    if [[ "$COMMAND" == upgrade ]]; then
        [[ -e "$MARKER" && -r "$INSTALL_CONF" ]] || die "نصب بومی پیدا نشد؛ اول install را اجرا کنید" \
            "no native install found; run install first"
        load_install_conf
    elif [[ -r "$INSTALL_CONF" ]]; then
        local requested_dir="$DATA_DIR"
        load_install_conf
        if [[ "$requested_dir" != "/var/lib/devassist" && "$requested_dir" != "$DATA_DIR" ]]; then
            die "مسیر داده قبلاً $DATA_DIR بوده؛ جابه‌جایی داده دستی است" \
                "the data directory is already $DATA_DIR; moving data is a manual step"
        fi
    fi
    require_root
    check_os
    load_pins
    check_data_dir
    check_existing_prefix
    if [[ $EUID -eq 0 ]]; then
        check_resources
        check_docker_panel
        check_ports
    fi
    warn_legacy_units
    [[ $DRY_RUN -eq 1 ]] && info "حالت پیش‌نمایش: هیچ چیزی تغییر نمی‌کند" "dry run: nothing is changed"
    info "نسخه‌های پین‌شده: Python $PY_VERSION، Node $NODE_VERSION" \
        "pinned versions: Python $PY_VERSION, Node $NODE_VERSION"
    if [[ "$COMMAND" == upgrade ]]; then
        warn "پیش از ارتقا از پنل یک پشتیبان رمزنگاری‌شده بگیرید" "take an encrypted backup in the panel before upgrading"
        confirm "ارتقا پنل را چند دقیقه متوقف می‌کند." "The upgrade stops the panel for a few minutes." "UPGRADE"
    fi
    install_packages
    ensure_user
    ensure_layout
    clean_incomplete_releases
    build_release
    install_config
    activate_release
    prune_releases
    wait_ready
    summary
}

cmd_status() {
    local unit
    for unit in devassist "${LEGACY_UNITS[@]}"; do
        [[ -e "$UNIT_DIR/$unit.service" ]] || continue
        printf '%-18s %s\n' "$unit" "$(systemctl is-active "$unit" 2>/dev/null || true)"
    done
    if [[ ! -r "$PREFIX/current/RELEASE" ]]; then
        info "نصب بومی پیدا نشد" "no native install found"
        return 0
    fi
    printf '\nrelease: %s\n' "$(basename -- "$(readlink -f "$PREFIX/current")")"
    cat "$PREFIX/current/RELEASE"
    if [[ $EUID -eq 0 ]] && unit_active "$UNIT"; then
        if "$EXEC_HELPER" python -m mrk_control_plane.healthcheck >/dev/null 2>&1; then
            ok "پنل آماده است" "panel ready"
        else
            warn "پنل هنوز آماده نیست" "panel not ready"
        fi
    fi
}

cmd_uninstall() {
    require_root
    [[ -e "$MARKER" || -r "$INSTALL_CONF" ]] || die "نصب بومی پیدا نشد" "no native install found"
    load_install_conf
    # Data of the native agent/DNS/firewall of older installs.
    local -a legacy_data=(/var/lib/mrk-dns /var/lib/mrk-firewall /var/lib/mrk-agent)
    if [[ $PURGE -eq 1 ]]; then
        warn "--purge همه داده‌ها را برای همیشه پاک می‌کند: $DATA_DIR، $CONF_DIR و ${legacy_data[*]}" \
            "--purge permanently deletes all data: $DATA_DIR, $CONF_DIR and ${legacy_data[*]}"
        confirm "این کار برگشت‌پذیر نیست." "This cannot be undone." "DELETE"
    else
        confirm "برنامه‌ها و unitها حذف می‌شوند؛ داده و $CONF_DIR می‌مانند." \
            "Programs and units are removed; data and $CONF_DIR are kept." "UNINSTALL"
    fi
    local unit
    for unit in "${LEGACY_UNITS[@]}" devassist; do
        if [[ -e "$UNIT_DIR/$unit.service" ]]; then
            run systemctl disable --now "$unit.service" || true
            run rm -f "$UNIT_DIR/$unit.service"
        fi
    done
    run systemctl daemon-reload
    # A legacy native firewall helper's table must not outlive it (it would keep dropping traffic).
    if have nft && nft list table inet mrk >/dev/null 2>&1 && ! docker_firewall_running; then
        info "حذف جدول nftables «inet mrk» (فایروال بومی قدیمی)" "deleting the nftables table 'inet mrk' (old native firewall)"
        run nft delete table inet mrk
    fi
    run rm -f "$EXEC_HELPER" "$TMPFILES"
    [[ -e "$MARKER" ]] && run rm -rf "$PREFIX"
    run rm -rf "$CACHE_DIR"
    local path
    local -a created=()
    if [[ -r "$INSTALL_CONF" ]]; then
        read -r -a created <<<"$(sed -n 's/^DEVASSIST_CREATED_MOUNT_POINTS=//p' "$INSTALL_CONF" | head -n 1)"
    fi
    for path in "${created[@]}"; do
        [[ -d "$path" ]] && run rmdir --ignore-fail-on-non-empty "$path"
    done
    if [[ $PURGE -eq 1 ]]; then
        run rm -rf "$DATA_DIR" "${legacy_data[@]}" "$CONF_DIR"
        if getent passwd "$RUN_USER" >/dev/null; then run userdel "$RUN_USER"; fi
        if getent group "$RUN_USER" >/dev/null; then run groupdel "$RUN_USER"; fi
        ok "پنل DevAssist و همه داده‌هایش حذف شد" "the DevAssist panel and all its data were removed"
    else
        run rm -f "$INSTALL_CONF"
        ok "پنل DevAssist حذف شد؛ داده در $DATA_DIR و تنظیمات در $CONF_DIR ماند" \
            "the DevAssist panel was removed; data stays in $DATA_DIR and config in $CONF_DIR"
    fi
    info "سرویس‌های Docker (agent، DNS، فایروال، S3) دست نخوردند؛ آن‌ها را جدا حذف کنید" \
        "Docker services (agent, DNS, firewall, S3) are untouched; remove them separately"
}

# The Docker firewall helper owns the same table; never delete it from under it.
docker_firewall_running() {
    have docker && docker ps --format '{{.Names}}' 2>/dev/null | grep -q 'mrk-firewall'
}

main() {
    parse_args "$@"
    case "$COMMAND" in
        install|upgrade) cmd_install ;;
        status) cmd_status ;;
        uninstall) cmd_uninstall ;;
    esac
}

main "$@"
