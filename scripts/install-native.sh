#!/usr/bin/env bash
# install-native.sh — install DevAssist without Docker (systemd), on
# Debian 12/13 or Ubuntu 22.04/24.04, amd64 or arm64.
#
# It reproduces what deploy/appliance/Dockerfile builds and what the containers
# run, from this source checkout:
#   * Python (version from versions.lock.yaml) in a venv with the control plane
#     and deploy/appliance/requirements.txt, pins checked like the Dockerfile;
#   * Node (versions.lock.yaml) for Verdaccio and PGlite, `npm ci` from the
#     lockfiles (integrity hashes enforced), and the built admin UI;
#   * the Go DNS engine built from apps/dns-engine (go.sum enforced), or a
#     prebuilt binary (--dns-binary);
#   * the unchanged deploy/appliance/supervisord.conf and devpi scripts, run
#     by systemd units from deploy/native/systemd/.
#
# Guide: docs/install-native.md (Persian: docs/install-native.fa.md).
#
#   sudo bash scripts/install-native.sh install [--with-dns] [--with-firewall] [--with-agent]
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
readonly CACHE_DIR="/var/cache/devassist"
readonly UNIT_DIR="/etc/systemd/system"
readonly EXEC_HELPER="/usr/local/sbin/devassist-exec"
readonly RUN_USER="devassist"
readonly PREFERRED_ID=10001
# Fixed sub-directories of the data volume (deploy/appliance/entrypoint.py).
readonly DATA_SUBDIRS=(database npm npm/config npm/storage pypi pypi/server pypi/auth control-plane router)
readonly MAIN_PORTS=(8080 4873 3141 9000 9001 5433 3142)

# ----------------------------------------------------------------------------- options

COMMAND="install"
DRY_RUN=0
ASSUME_YES=0
PURGE=0
WITH_DNS=0
WITH_FIREWALL=0
WITH_AGENT=0
DATA_DIR="/var/lib/devassist"
SKIP_PORT_CHECK=0
SKIP_OS_CHECK=0
MIN_FREE_GB=5
DNS_BINARY=""
DNSBENCH_BINARY=""
PYTHON_OVERRIDE=""
PIP_INDEX_URL=""
NPM_REGISTRY=""
GOPROXY_URL=""
NO_START=0
REBUILD=0
LANG_MODE="both"

NODE_DIST="${DEVASSIST_NODE_DIST:-https://nodejs.org/dist}"
GO_DIST="${DEVASSIST_GO_DIST:-https://dl.google.com/go}"
UV_DIST="${DEVASSIST_UV_DIST:-https://github.com/astral-sh/uv/releases/download}"

usage() {
    cat <<'EOF'
Usage: sudo bash scripts/install-native.sh [COMMAND] [OPTIONS]

Commands:
  install     install or repair (default; safe to run again)
  upgrade     build the current checkout, then switch with a short restart
  status      show units, release and health
  uninstall   remove programs and units (data and /etc/devassist are kept)

Options:
  --with-dns            also install the DNS engine (devassist-dns, port 53)
  --with-firewall       also install the nftables firewall helper (devassist-firewall)
  --with-agent          also install the Host Agent (devassist-agent, needs Docker)
  --data-dir DIR        data directory on the host (default /var/lib/devassist)
  --dns-binary PATH     use this prebuilt mrk-dns instead of building it with Go
  --dnsbench-binary PATH  prebuilt mrk-dnsbench (optional, with --dns-binary)
  --python PATH         use an existing Python 3.13 instead of the pinned build
  --pip-index-url URL   PyPI mirror for the build (trusted like PyPI: pip checks no hashes)
  --npm-registry URL    npm mirror for the build (lockfile hashes still enforced)
  --goproxy URL         Go module proxy for the build (go.sum still enforced)
  --rebuild             rebuild even if this commit is already built
  --no-start            install but do not start or restart services
  --skip-port-check     do not stop when a needed port is in use
  --skip-os-check       allow an untested distribution (unsupported)
  --min-free-gb N       free disk space required (default 5)
  --purge               with uninstall: also delete data, config and the user
  --yes                 do not ask for confirmation
  --dry-run             print what would be done, change nothing
  --lang fa|en|both     message language (default both)
  -h, --help            this help

Download mirrors (environment): DEVASSIST_NODE_DIST, DEVASSIST_GO_DIST,
DEVASSIST_UV_DIST, and uv's own UV_PYTHON_INSTALL_MIRROR for Python builds.
EOF
}

parse_args() {
    if [[ $# -gt 0 && "$1" != -* ]]; then
        COMMAND="$1"
        shift
    fi
    while [[ $# -gt 0 ]]; do
        case "$1" in
            --with-dns) WITH_DNS=1 ;;
            --with-firewall) WITH_FIREWALL=1 ;;
            --with-agent) WITH_AGENT=1 ;;
            --data-dir) DATA_DIR="${2:?--data-dir needs a value}"; shift ;;
            --dns-binary) DNS_BINARY="${2:?--dns-binary needs a value}"; shift ;;
            --dnsbench-binary) DNSBENCH_BINARY="${2:?--dnsbench-binary needs a value}"; shift ;;
            --python) PYTHON_OVERRIDE="${2:?--python needs a value}"; shift ;;
            --pip-index-url) PIP_INDEX_URL="${2:?--pip-index-url needs a value}"; shift ;;
            --npm-registry) NPM_REGISTRY="${2:?--npm-registry needs a value}"; shift ;;
            --goproxy) GOPROXY_URL="${2:?--goproxy needs a value}"; shift ;;
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
    GO_VERSION="$(lock_version golang)"
    UV_VERSION="$(lock_version uv)"
    local name
    for name in PY_VERSION NODE_VERSION GO_VERSION UV_VERSION; do
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
    # shellcheck disable=SC1091
    OS_ID="$(. /etc/os-release && printf '%s' "${ID:-}")"
    # shellcheck disable=SC1091
    OS_VERSION="$(. /etc/os-release && printf '%s' "${VERSION_ID:-}")"
    case "$OS_ID:$OS_VERSION" in
        debian:12|debian:13|ubuntu:22.04|ubuntu:24.04)
            info "سیستم‌عامل: $OS_ID $OS_VERSION" "OS: $OS_ID $OS_VERSION" ;;
        *)
            if [[ $SKIP_OS_CHECK -eq 1 ]]; then
                warn "توزیع $OS_ID $OS_VERSION آزموده نشده است" "untested distribution $OS_ID $OS_VERSION"
            else
                die "فقط Debian 12/13 و Ubuntu 22.04/24.04 پشتیبانی می‌شوند ($OS_ID $OS_VERSION)" \
                    "only Debian 12/13 and Ubuntu 22.04/24.04 are supported (found $OS_ID $OS_VERSION)"
            fi ;;
    esac
    case "$(uname -m)" in
        x86_64) NODE_ARCH="x64"; GO_ARCH="amd64"; UV_TRIPLE="x86_64-unknown-linux-gnu" ;;
        aarch64|arm64) NODE_ARCH="arm64"; GO_ARCH="arm64"; UV_TRIPLE="aarch64-unknown-linux-gnu" ;;
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
    if [[ -L "$DATA_DIR" ]]; then
        die "مسیر داده نباید symlink باشد: $DATA_DIR" "the data directory must not be a symlink: $DATA_DIR"
    fi
}

# free_kb PATH -> free KiB on the filesystem holding PATH (or its nearest parent)
free_kb() {
    local path="$1"
    while [[ ! -e "$path" ]]; do path="$(dirname -- "$path")"; done
    df -Pk -- "$path" | awk 'NR == 2 { print $4 }'
}

check_resources() {
    local need_kb=$((MIN_FREE_GB * 1024 * 1024)) path free
    for path in "$PREFIX" "$CACHE_DIR" "$DATA_DIR"; do
        free="$(free_kb "$path")"
        if [[ -z "$free" || "$free" -lt "$need_kb" ]]; then
            die "فضای خالی کافی برای $path نیست (کمتر از ${MIN_FREE_GB} گیگابایت)" \
                "not enough free space for $path (less than ${MIN_FREE_GB} GiB)"
        fi
    done
    local mem_kb
    mem_kb="$(awk '/^MemTotal:/ { print $2 }' /proc/meminfo)"
    if [[ -n "$mem_kb" && "$mem_kb" -lt 1900000 ]]; then
        warn "حافظه کمتر از 2 گیگابایت است؛ سرویس اصلی تا 2 گیگابایت مصرف می‌کند" \
            "less than 2 GiB of RAM; the main service may use up to 2 GiB"
    fi
}

unit_active() { systemctl is-active --quiet "$1" 2>/dev/null; }

# port_users PORT -> listening sockets on that port (ss "Local Address:Port" column)
port_users() {
    ss -Hlntu 2>/dev/null | awk -v port="$1" '{ n = split($5, a, ":"); if (a[n] == port) print $1 " " $5 }'
}

check_ports() {
    [[ $SKIP_PORT_CHECK -eq 1 ]] && return 0
    have ss || { warn "ss نیست؛ بررسی پورت‌ها انجام نشد" "ss not found; ports not checked"; return 0; }
    local port used failed=0
    if ! unit_active devassist.service; then
        for port in "${MAIN_PORTS[@]}"; do
            used="$(port_users "$port")"
            if [[ -n "$used" ]]; then
                warn "پورت $port در حال استفاده است: $used" "port $port is already in use: $used"
                failed=1
            fi
        done
    fi
    if [[ $WITH_DNS -eq 1 ]] && ! unit_active devassist-dns.service; then
        # systemd-resolved's stub on 127.0.0.53/127.0.0.54 does not clash with 127.0.0.1:53.
        used="$(port_users 53 | awk '$2 !~ /^127\.0\.0\.5[34]:/')"
        if [[ -n "$used" ]]; then
            warn "پورت 53 گرفته شده است؛ با «sudo ss -lntup 'sport = :53'» ببینید کدام برنامه است" \
                "port 53 is in use; see which program with: sudo ss -lntup 'sport = :53'"
            printf '         %s\n' "$used" >&2
            failed=1
        fi
    fi
    if [[ $WITH_AGENT -eq 1 ]] && ! unit_active devassist-agent.service && [[ -n "$(port_users 7070)" ]]; then
        warn "پورت 7070 (Host Agent) گرفته شده است" "port 7070 (Host Agent) is in use"
        failed=1
    fi
    if [[ $failed -eq 1 ]]; then
        die "پورت‌ها را آزاد کنید یا با --skip-port-check ادامه دهید" \
            "free the ports or continue with --skip-port-check"
    fi
}

check_docker_install() {
    have docker || return 0
    local names
    names="$(docker ps --format '{{.Names}} {{.Image}}' 2>/dev/null || true)"
    if grep -Eq 'mrk-mirror|mrk-package-mirror|mrk/package-mirror' <<<"$names"; then
        die "نسخه Docker DevAssist در حال اجراست؛ هر دو با هم روی یک سرور اجرا نشوند (پورت‌ها و داده یکی است)" \
            "the Docker install of DevAssist is running; do not run both on one server (same ports)"
    fi
}

check_existing_prefix() {
    if [[ -e "$PREFIX" && ! -e "$MARKER" ]]; then
        die "$PREFIX وجود دارد ولی مال این نصب نیست؛ دست نمی‌زنم" \
            "$PREFIX exists but was not created by this installer; refusing to touch it"
    fi
}

# ----------------------------------------------------------------------------- packages

apt_install() {
    local missing=() pkg
    for pkg in "$@"; do
        dpkg-query -W -f='${Status}' "$pkg" 2>/dev/null | grep -q "install ok installed" || missing+=("$pkg")
    done
    [[ ${#missing[@]} -eq 0 ]] && return 0
    info "نصب بسته‌های سیستم: ${missing[*]}" "installing system packages: ${missing[*]}"
    run env DEBIAN_FRONTEND=noninteractive apt-get update -qq
    run env DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends "${missing[@]}"
}

install_packages() {
    step "System packages / بسته‌های سیستم"
    local packages=(ca-certificates curl xz-utils tar gzip coreutils util-linux iproute2 git)
    [[ $WITH_FIREWALL -eq 1 ]] && packages+=(nftables)
    apt_install "${packages[@]}"
}

# ----------------------------------------------------------------------------- downloads

download() {
    local url="$1" dest="$2"
    run curl --fail --silent --show-error --location --proto '=https' --tlsv1.2 \
        --retry 3 --retry-delay 2 --output "$dest" "$url"
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
    if [[ -x "$UV_BIN" ]]; then return 0; fi
    info "دانلود uv $UV_VERSION (فقط برای نصب Python)" "downloading uv $UV_VERSION (installs Python only)"
    local name="uv-$UV_TRIPLE.tar.gz" tmp="$CACHE_DIR/downloads" sum
    run install -d -m 0755 "$tmp" "$CACHE_DIR/tools/uv-$UV_VERSION"
    download "$UV_DIST/$UV_VERSION/$name" "$tmp/$name"
    download "$UV_DIST/$UV_VERSION/$name.sha256" "$tmp/$name.sha256"
    if [[ $DRY_RUN -eq 0 ]]; then
        sum="$(awk '{ print $1; exit }' "$tmp/$name.sha256")"
        verify_sha256 "$tmp/$name" "$sum"
    fi
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
    local dir="node-v$NODE_VERSION-linux-$NODE_ARCH"
    NODE_HOME="$RUNTIMES/$dir"
    if [[ -x "$NODE_HOME/bin/node" ]]; then
        info "Node $NODE_VERSION از قبل نصب است" "Node $NODE_VERSION already installed"
        return 0
    fi
    local tmp="$CACHE_DIR/downloads" sum
    run install -d -m 0755 "$tmp" "$RUNTIMES"
    download "$NODE_DIST/v$NODE_VERSION/$dir.tar.xz" "$tmp/$dir.tar.xz"
    download "$NODE_DIST/v$NODE_VERSION/SHASUMS256.txt" "$tmp/node-v$NODE_VERSION-SHASUMS256.txt"
    if [[ $DRY_RUN -eq 0 ]]; then
        sum="$(awk -v f="$dir.tar.xz" '$2 == f { print $1 }' "$tmp/node-v$NODE_VERSION-SHASUMS256.txt")"
        verify_sha256 "$tmp/$dir.tar.xz" "$sum"
    fi
    run tar -xJf "$tmp/$dir.tar.xz" -C "$RUNTIMES" --no-same-owner
}

install_go() {
    local name="go$GO_VERSION.linux-$GO_ARCH.tar.gz" tmp="$CACHE_DIR/downloads" sum
    GO_ROOT="$CACHE_DIR/tools/go-$GO_VERSION"
    if [[ -x "$GO_ROOT/bin/go" ]]; then return 0; fi
    info "دانلود Go $GO_VERSION (فقط برای ساخت موتور DNS)" "downloading Go $GO_VERSION (DNS engine build only)"
    run install -d -m 0755 "$tmp" "$GO_ROOT"
    download "$GO_DIST/$name" "$tmp/$name"
    download "$GO_DIST/$name.sha256" "$tmp/$name.sha256"
    if [[ $DRY_RUN -eq 0 ]]; then
        sum="$(awk '{ print $1; exit }' "$tmp/$name.sha256")"
        verify_sha256 "$tmp/$name" "$sum"
    fi
    run tar -xzf "$tmp/$name" -C "$GO_ROOT" --strip-components=1 --no-same-owner
}

# ----------------------------------------------------------------------------- build

source_commit() {
    if have git && git -c safe.directory="$REPO_ROOT" -C "$REPO_ROOT" rev-parse HEAD >/dev/null 2>&1; then
        COMMIT="$(git -c safe.directory="$REPO_ROOT" -C "$REPO_ROOT" rev-parse HEAD)"
        if [[ -n "$(git -c safe.directory="$REPO_ROOT" -C "$REPO_ROOT" status --porcelain --untracked-files=no)" ]]; then
            RELEASE_ID="${COMMIT:0:12}-dirty-$(date -u +%Y%m%d%H%M%S)"
        else
            RELEASE_ID="${COMMIT:0:12}"
        fi
    else
        COMMIT="unknown"
        RELEASE_ID="build-$(date -u +%Y%m%d%H%M%S)"
    fi
    BUILD_DATE="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
    RELEASE_DIR="$RELEASES/$RELEASE_ID"
}

npm_env() {
    local -a vars=(PATH="$NODE_HOME/bin:/usr/bin:/bin" npm_config_cache="$CACHE_DIR/npm"
        npm_config_update_notifier=false npm_config_fund=false npm_config_audit=false)
    if [[ -n "$NPM_REGISTRY" ]]; then
        vars+=(npm_config_registry="$NPM_REGISTRY" npm_config_replace_registry_host=always)
    fi
    printf '%s\n' "${vars[@]}"
}

# npm_in DIR ARGS... : run npm in DIR with the pinned Node and optional mirror
npm_in() {
    local dir="$1" env_vars
    shift
    mapfile -t env_vars < <(npm_env)
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
    # Same install line as the Dockerfile runtime stage.
    run env PIP_DISABLE_PIP_VERSION_CHECK=1 PIP_CACHE_DIR="$CACHE_DIR/pip" "$venv/bin/python" -m pip install \
        "${pip_args[@]}" "$REPO_ROOT/apps/control-plane" -r "$REPO_ROOT/deploy/appliance/requirements.txt"
    # Same pin check as the Dockerfile: the build fails on any runtime pin mismatch.
    run "$venv/bin/python" -c "import importlib.metadata as md, sys; pins = [line.strip().split('==') for line in open(sys.argv[1]) if '==' in line and not line.startswith('#')]; bad = [(name, want, md.version(name)) for name, want in pins if md.version(name) != want]; sys.exit(f'runtime pin mismatch: {bad}' if bad else 0)" \
        "$REPO_ROOT/deploy/appliance/requirements.txt"
    run "$venv/bin/python" -m pip uninstall --yes pip wheel
}

build_node_parts() {
    step "Verdaccio, PGlite, admin UI"
    local part
    for part in verdaccio pglite; do
        run install -d -m 0755 "$RELEASE_DIR/$part"
        run cp "$REPO_ROOT/deploy/$part/package.json" "$REPO_ROOT/deploy/$part/package-lock.json" "$RELEASE_DIR/$part/"
        npm_in "$RELEASE_DIR/$part" ci --omit=dev --ignore-scripts
    done
    # docs/43 §0.1: Verdaccio's pre-publish quota plugin (no dependencies).
    run cp -R "$REPO_ROOT/deploy/verdaccio/plugins" "$RELEASE_DIR/verdaccio/plugins"
    local build="$CACHE_DIR/build/admin-ui"
    run rm -rf "$build"
    run install -d -m 0755 "$build"
    run tar -C "$REPO_ROOT/apps/admin-ui" --exclude=./node_modules --exclude=./dist -cf "$CACHE_DIR/build/admin-ui.tar" .
    run tar -C "$build" -xf "$CACHE_DIR/build/admin-ui.tar"
    npm_in "$build" ci --ignore-scripts
    if [[ $DRY_RUN -eq 1 ]]; then
        printf '  + (cd %q && VITE_BUILD_COMMIT=... npm run build)\n' "$build"
    else
        local env_vars
        mapfile -t env_vars < <(npm_env)
        (cd "$build" && env "${env_vars[@]}" VITE_BUILD_COMMIT="$COMMIT" VITE_BUILD_DATE="$BUILD_DATE" \
            "$NODE_HOME/bin/npm" run build)
    fi
    run cp -a "$build/dist" "$RELEASE_DIR/admin-ui"
    run rm -rf "$build" "$CACHE_DIR/build/admin-ui.tar"
}

build_dns() {
    step "DNS engine (mrk-dns)"
    if [[ -n "$DNS_BINARY" ]]; then
        [[ -f "$DNS_BINARY" ]] || die "فایل mrk-dns پیدا نشد: $DNS_BINARY" "mrk-dns binary not found: $DNS_BINARY"
        run install -m 0755 "$DNS_BINARY" "$RELEASE_DIR/bin/mrk-dns"
        if [[ -n "$DNSBENCH_BINARY" ]]; then
            run install -m 0755 "$DNSBENCH_BINARY" "$RELEASE_DIR/bin/mrk-dnsbench"
        fi
        run "$RELEASE_DIR/bin/mrk-dns" version
        return 0
    fi
    install_go
    local build="$CACHE_DIR/build/dns-engine"
    local -a go_env=(PATH="$GO_ROOT/bin:/usr/bin:/bin" GOROOT="$GO_ROOT" GOPATH="$CACHE_DIR/go"
        GOMODCACHE="$CACHE_DIR/go/pkg/mod" GOCACHE="$CACHE_DIR/go/cache"
        CGO_ENABLED=0 GOFLAGS=-trimpath GOTOOLCHAIN=local)
    [[ -n "$GOPROXY_URL" ]] && go_env+=(GOPROXY="$GOPROXY_URL")
    run rm -rf "$build"
    run install -d -m 0755 "$build"
    run cp -a "$REPO_ROOT/apps/dns-engine/." "$build/"
    # Same steps and flags as the dns-builder stage of the Dockerfile.
    local go="$GO_ROOT/bin/go"
    run env -C "$build" "${go_env[@]}" "$go" mod download
    run env -C "$build" "${go_env[@]}" "$go" mod verify
    run env -C "$build" "${go_env[@]}" "$go" build -buildvcs=false \
        -ldflags "-s -w -X mrk/dns-engine/internal/version.Commit=$COMMIT" \
        -o "$RELEASE_DIR/bin/mrk-dns" ./cmd/mrk-dns
    run env -C "$build" "${go_env[@]}" "$go" build -buildvcs=false -ldflags "-s -w" \
        -o "$RELEASE_DIR/bin/mrk-dnsbench" ./cmd/mrk-dnsbench
    run "$RELEASE_DIR/bin/mrk-dns" version
    run rm -rf "$build"
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
        case "$name" in
            activate*|python*|pip*|Activate*|deactivate*) continue ;;
        esac
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

copy_appliance_files() {
    local file
    for file in supervisord.conf devpi-start.sh devpi-configure.sh; do
        run install -m 0644 "$REPO_ROOT/deploy/appliance/$file" "$RELEASE_DIR/$file"
    done
    # Same CRLF guard as the Dockerfile.
    run sed -i 's/\r$//' "$RELEASE_DIR/devpi-start.sh" "$RELEASE_DIR/devpi-configure.sh" "$RELEASE_DIR/supervisord.conf"
    run install -m 0644 "$REPO_ROOT/deploy/native/devassist_supervise.py" "$RELEASE_DIR/devassist_supervise.py"
    run install -m 0644 "$REPO_ROOT/LICENSE" "$RELEASE_DIR/LICENSE"
    printf 'commit=%s\nbuild_date=%s\npython=%s\nnode=%s\ngo=%s\n' \
        "$COMMIT" "$BUILD_DATE" "$PY_VERSION" "$NODE_VERSION" "$GO_VERSION" \
        | put_file 0644 root root "$RELEASE_DIR/RELEASE"
}

release_complete() { [[ -d "$1" && ! -e "$1/.incomplete" && -x "$1/venv/bin/python" ]]; }

build_release() {
    source_commit
    if release_complete "$RELEASE_DIR" && [[ $REBUILD -eq 0 ]]; then
        ok "نسخه $RELEASE_ID از قبل ساخته شده است (برای ساخت دوباره --rebuild)" \
            "release $RELEASE_ID is already built (use --rebuild to build again)"
        if [[ $WITH_DNS -eq 1 && ! -x "$RELEASE_DIR/bin/mrk-dns" ]]; then
            # Adding DNS to an existing release: build only the engine into it.
            build_dns
            run chown -R root:root "$RELEASE_DIR/bin"
            run chmod -R u=rwX,go=rX "$RELEASE_DIR/bin"
        fi
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
    [[ $WITH_DNS -eq 1 ]] && build_dns
    copy_appliance_files
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
    current="$(readlink -f "$PREFIX/current" 2>/dev/null || true)"
    [[ -d "$RELEASES" ]] || return 0
    mapfile -t keep < <(ls -1dt "$RELEASES"/*/ 2>/dev/null | head -n 2)
    for dir in "$RELEASES"/*/; do
        dir="${dir%/}"
        [[ -d "$dir" ]] || continue
        [[ "$dir" == "$current" ]] && continue
        [[ " ${keep[*]%/} " == *" $dir "* ]] && continue
        run rm -rf "$dir"
    done
}

# ----------------------------------------------------------------------------- system layout

ensure_user() {
    step "System user / کاربر سیستمی"
    if getent passwd "$RUN_USER" >/dev/null; then
        info "کاربر $RUN_USER وجود دارد" "user $RUN_USER exists"
        return 0
    fi
    local -a id_args=()
    # Same uid/gid as the image (10001) when free, so data moves between Docker and native installs.
    if ! getent group "$PREFERRED_ID" >/dev/null && ! getent passwd "$PREFERRED_ID" >/dev/null; then
        run groupadd --system --gid "$PREFERRED_ID" "$RUN_USER"
        id_args=(--uid "$PREFERRED_ID" --gid "$PREFERRED_ID")
    else
        warn "uid/gid 10001 آزاد نیست؛ شناسه سیستمی دیگری انتخاب می‌شود" \
            "uid/gid 10001 is taken; a different system id is used"
        run groupadd --system "$RUN_USER"
        id_args=(--gid "$RUN_USER")
    fi
    run useradd --system "${id_args[@]}" --no-create-home --home-dir /nonexistent \
        --shell /usr/sbin/nologin --comment "DevAssist" "$RUN_USER"
}

# mount_point PATH: an empty directory that systemd mounts over inside a unit.
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
        local previous
        previous="$(sed -n 's/^DEVASSIST_CREATED_MOUNT_POINTS=//p' "$INSTALL_CONF" | head -n 1)"
        read -r -a CREATED_MOUNT_POINTS <<<"$previous"
    fi
    run install -d -m 0755 -o root -g root "$PREFIX" "$RELEASES" "$RUNTIMES" "$CACHE_DIR"
    [[ -e "$MARKER" ]] || printf 'DevAssist native install; managed by scripts/install-native.sh\n' \
        | put_file 0644 root root "$MARKER"
    run install -d -m 0750 -o root -g "$RUN_USER" "$CONF_DIR"
    # Data directory with the fixed layout of deploy/appliance/entrypoint.py (0750, devassist).
    run install -d -m 0750 -o "$RUN_USER" -g "$RUN_USER" "$DATA_DIR"
    local sub
    for sub in "${DATA_SUBDIRS[@]}"; do
        run install -d -m 0750 -o "$RUN_USER" -g "$RUN_USER" "$DATA_DIR/$sub"
    done
    # Mount points for the container paths the code expects.
    mount_point /data
    mount_point /opt/verdaccio
    mount_point /opt/pglite
    run install -d -m 0755 -o root -g root "$PREFIX/firewall-logroot/system" \
        "$PREFIX/agent-host/proc" "$PREFIX/agent-host/cgroup" "$PREFIX/agent-host/volumes" "$PREFIX/agent-host/root"
}

# install_env_file TEMPLATE DEST : write once, never overwrite operator changes.
install_env_file() {
    local template="$1" dest="$2"
    if [[ -e "$dest" ]]; then
        info "$dest از قبل هست و دست‌نخورده می‌ماند" "$dest exists and is kept unchanged"
        return 0
    fi
    sed -e "s|@DEVASSIST_COMMIT@|$COMMIT|g" -e "s|@DEVASSIST_BUILD_DATE@|$BUILD_DATE|g" "$template" \
        | put_file 0640 root "$RUN_USER" "$dest"
}

install_config() {
    step "Configuration / تنظیمات"
    install_env_file "$REPO_ROOT/deploy/native/devassist.env.example" "$CONF_DIR/devassist.env"
    # Build metadata always follows the active release.
    run sed -i -e "s|^MRK_BUILD_COMMIT=.*|MRK_BUILD_COMMIT=$COMMIT|" \
        -e "s|^MRK_BUILD_DATE=.*|MRK_BUILD_DATE=$BUILD_DATE|" "$CONF_DIR/devassist.env"
    [[ $WITH_DNS -eq 1 ]] && install_env_file "$REPO_ROOT/deploy/native/dns.env.example" "$CONF_DIR/dns.env"
    [[ $WITH_FIREWALL -eq 1 ]] && install_env_file "$REPO_ROOT/deploy/native/firewall.env.example" "$CONF_DIR/firewall.env"
    [[ $WITH_AGENT -eq 1 ]] && install_env_file "$REPO_ROOT/deploy/native/agent.env.example" "$CONF_DIR/agent.env"
    {
        printf '# Written by scripts/install-native.sh. Do not edit by hand.\n'
        printf 'DEVASSIST_DATA_DIR=%s\n' "$DATA_DIR"
        printf 'DEVASSIST_REPO=%s\n' "$REPO_ROOT"
        printf 'DEVASSIST_WITH_DNS=%s\n' "$WITH_DNS"
        printf 'DEVASSIST_WITH_FIREWALL=%s\n' "$WITH_FIREWALL"
        printf 'DEVASSIST_WITH_AGENT=%s\n' "$WITH_AGENT"
        printf 'DEVASSIST_CREATED_MOUNT_POINTS=%s\n' "${CREATED_MOUNT_POINTS[*]}"
    } | put_file 0644 root root "$INSTALL_CONF"
    run install -m 0755 -o root -g root "$REPO_ROOT/deploy/native/devassist-exec.sh" "$EXEC_HELPER"
}

selected_units() {
    printf '%s\n' devassist.service
    [[ $WITH_DNS -eq 1 ]] && printf '%s\n' devassist-dns.service
    [[ $WITH_FIREWALL -eq 1 ]] && printf '%s\n' devassist-firewall.service
    [[ $WITH_AGENT -eq 1 ]] && printf '%s\n' devassist-agent.service
    return 0
}

install_units() {
    step "systemd units"
    local unit
    while read -r unit; do
        sed -e "s|@DEVASSIST_DATA_DIR@|$DATA_DIR|g" "$REPO_ROOT/deploy/native/systemd/$unit" \
            | put_file 0644 root root "$UNIT_DIR/$unit"
    done < <(selected_units)
    run systemctl daemon-reload
}

# Read previously chosen components so `upgrade` keeps them.
load_install_conf() {
    [[ -r "$INSTALL_CONF" ]] || return 0
    local value
    value="$(sed -n 's/^DEVASSIST_DATA_DIR=//p' "$INSTALL_CONF" | head -n 1)"
    [[ -n "$value" ]] && DATA_DIR="$value"
    [[ "$(sed -n 's/^DEVASSIST_WITH_DNS=//p' "$INSTALL_CONF")" == 1 ]] && WITH_DNS=1
    [[ "$(sed -n 's/^DEVASSIST_WITH_FIREWALL=//p' "$INSTALL_CONF")" == 1 ]] && WITH_FIREWALL=1
    [[ "$(sed -n 's/^DEVASSIST_WITH_AGENT=//p' "$INSTALL_CONF")" == 1 ]] && WITH_AGENT=1
    return 0
}

# ----------------------------------------------------------------------------- activate

activate_release() {
    step "Activate / فعال‌سازی $RELEASE_ID"
    local was_active=0 unit link
    unit_active devassist.service && was_active=1
    if [[ $was_active -eq 1 && $NO_START -eq 0 ]]; then
        info "توقف سرویس (تا 3 دقیقه؛ PGlite آخر از همه بسته می‌شود)" \
            "stopping the service (up to 3 minutes; PGlite stops last)"
        run systemctl stop devassist.service
    fi
    run ln -sfn "releases/$RELEASE_ID" "$PREFIX/current"
    for link in venv admin-ui verdaccio pglite bin supervisord.conf devpi-start.sh devpi-configure.sh \
        devassist_supervise.py LICENSE; do
        run ln -sfn "current/$link" "$PREFIX/$link"
    done
    [[ $NO_START -eq 1 ]] && return 0
    while read -r unit; do
        run systemctl enable "$unit"
        if [[ "$unit" == devassist.service ]]; then
            run systemctl start "$unit"
        else
            run systemctl restart "$unit"
        fi
    done < <(selected_units)
}

wait_ready() {
    [[ $NO_START -eq 1 || $DRY_RUN -eq 1 ]] && return 0
    info "منتظر آماده شدن پنل (اولین اجرا چند دقیقه طول می‌کشد)" \
        "waiting for the panel to be ready (the first start takes a few minutes)"
    local waited=0
    until "$EXEC_HELPER" python -m mrk_control_plane.healthcheck >/dev/null 2>&1; do
        if ! unit_active devassist.service; then
            die "سرویس devassist اجرا نمی‌شود؛ ببینید: journalctl -u devassist -n 100" \
                "devassist.service is not running; see: journalctl -u devassist -n 100"
        fi
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
    if [[ -r "$CONF_DIR/devassist.env" ]]; then
        port="$(sed -n 's/^MRK_PORT=//p' "$CONF_DIR/devassist.env" | head -n 1)"
        host="$(sed -n 's/^MRK_HOST=//p' "$CONF_DIR/devassist.env" | head -n 1)"
    fi
    port="${port:-8080}"
    host="${host:-127.0.0.1}"
    printf '\n'
    ok "نصب تمام شد" "installation finished"
    cat <<EOF

  Panel / پنل:          http://$host:$port  (from your PC: ssh -L $port:127.0.0.1:$port <server>)
  First visit:          the panel shows "First Time Setup" to create the owner account
  Logs / لاگ:           journalctl -u devassist -f
  Config / تنظیمات:     $CONF_DIR/devassist.env  (then: systemctl restart devassist)
  Data / داده:          $DATA_DIR
  Maintenance:          sudo devassist-exec supervisorctl -c /opt/mrk/supervisord.conf status
  Upgrade / ارتقا:      git pull && sudo bash scripts/install-native.sh upgrade
  Uninstall / حذف:      sudo bash scripts/install-native.sh uninstall

  Network: every service listens on 127.0.0.1 only (see /etc/devassist/devassist.env).
  If you open one on a public address, firewall it, e.g.:  ufw deny 4873/tcp
  شبکه: همه سرویس‌ها فقط روی 127.0.0.1 هستند؛ اگر یکی را عمومی کردید با فایروال ببندید.
EOF
    if [[ $WITH_DNS -eq 1 ]]; then
        cat <<'EOF'

  DNS: listening on 127.0.0.1:53 and 172.17.0.1:53 (first start). Test: dig @127.0.0.1 localhost
  Then follow Panel -> DNS -> Setup (resolver and Docker steps). The engine is
  managed with `systemctl ... devassist-dns`, not `docker compose`.
EOF
    fi
    if [[ $WITH_FIREWALL -eq 1 || $WITH_AGENT -eq 1 ]]; then
        cat <<'EOF'

  Pairing keys are logged once / کلید جفت‌سازی یک بار در لاگ می‌آید:
    journalctl -u devassist-agent | grep "pairing key"      (URL: http://127.0.0.1:7070)
    journalctl -u devassist-firewall | grep "pairing key"   (URL: unix:/run/mrk-firewall/firewall.sock)
EOF
    fi
}

# ----------------------------------------------------------------------------- commands

preflight() {
    require_root
    check_os
    load_pins
    check_data_dir
    check_existing_prefix
    if [[ $EUID -eq 0 ]]; then
        check_resources
        check_docker_install
        check_ports
    fi
}

cmd_install() {
    if [[ "$COMMAND" == upgrade ]]; then
        [[ -e "$MARKER" && -r "$INSTALL_CONF" ]] || die "نصب بومی پیدا نشد؛ اول install را اجرا کنید" \
            "no native install found; run install first"
        load_install_conf
    elif [[ -r "$INSTALL_CONF" ]]; then
        # Re-running install keeps components chosen before and adds new ones.
        local requested_dir="$DATA_DIR"
        load_install_conf
        if [[ "$requested_dir" != "/var/lib/devassist" && "$requested_dir" != "$DATA_DIR" ]]; then
            die "مسیر داده قبلاً $DATA_DIR بوده؛ جابه‌جایی داده دستی است" \
                "the data directory is already $DATA_DIR; moving data is a manual step"
        fi
    fi
    preflight
    [[ $DRY_RUN -eq 1 ]] && info "حالت پیش‌نمایش: هیچ چیزی تغییر نمی‌کند" "dry run: nothing is changed"
    info "نسخه‌های پین‌شده: Python $PY_VERSION، Node $NODE_VERSION، Go $GO_VERSION" \
        "pinned versions: Python $PY_VERSION, Node $NODE_VERSION, Go $GO_VERSION"
    if [[ "$COMMAND" == upgrade ]]; then
        warn "پیش از ارتقا از پنل یک پشتیبان رمزنگاری‌شده بگیرید (چرخه داده → پشتیبان)" \
            "take an encrypted backup in the panel before upgrading (data lifecycle -> backup)"
        confirm "ارتقا سرویس را چند دقیقه متوقف می‌کند." "The upgrade stops the service for a few minutes." "UPGRADE"
    fi
    install_packages
    ensure_user
    ensure_layout
    clean_incomplete_releases
    build_release
    install_config
    install_units
    activate_release
    prune_releases
    wait_ready
    summary
}

cmd_status() {
    local unit
    for unit in devassist devassist-dns devassist-firewall devassist-agent; do
        [[ -e "$UNIT_DIR/$unit.service" ]] || continue
        printf '%-18s %s\n' "$unit" "$(systemctl is-active "$unit" 2>/dev/null || true)"
    done
    if [[ -r "$PREFIX/current/RELEASE" ]]; then
        printf '\nrelease: %s\n' "$(basename -- "$(readlink -f "$PREFIX/current")")"
        cat "$PREFIX/current/RELEASE"
    else
        info "نصب بومی پیدا نشد" "no native install found"
        return 0
    fi
    if [[ $EUID -eq 0 ]] && unit_active devassist.service; then
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
    if [[ $PURGE -eq 1 ]]; then
        warn "--purge همه داده‌ها را برای همیشه پاک می‌کند: $DATA_DIR، /var/lib/mrk-dns، /var/lib/mrk-firewall، /var/lib/mrk-agent و $CONF_DIR" \
            "--purge permanently deletes all data: $DATA_DIR, /var/lib/mrk-dns, /var/lib/mrk-firewall, /var/lib/mrk-agent and $CONF_DIR"
        confirm "این کار برگشت‌پذیر نیست." "This cannot be undone." "DELETE"
    else
        confirm "برنامه‌ها و unitها حذف می‌شوند؛ داده و $CONF_DIR می‌مانند." \
            "Programs and units are removed; data and $CONF_DIR are kept." "UNINSTALL"
    fi
    local unit
    for unit in devassist-agent devassist-firewall devassist-dns devassist; do
        if [[ -e "$UNIT_DIR/$unit.service" ]]; then
            run systemctl disable --now "$unit.service" || true
            run rm -f "$UNIT_DIR/$unit.service"
        fi
    done
    run systemctl daemon-reload
    # The firewall helper's table must not outlive it (it would keep dropping traffic).
    if have nft && nft list table inet mrk >/dev/null 2>&1; then
        info "حذف جدول nftables «inet mrk»" "deleting the nftables table 'inet mrk'"
        run nft delete table inet mrk
    fi
    run rm -f "$EXEC_HELPER"
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
        run rm -rf "$DATA_DIR" /var/lib/mrk-dns /var/lib/mrk-firewall /var/lib/mrk-agent "$CONF_DIR"
        if getent passwd "$RUN_USER" >/dev/null; then run userdel "$RUN_USER"; fi
        if getent group "$RUN_USER" >/dev/null; then run groupdel "$RUN_USER"; fi
        ok "DevAssist و همه داده‌هایش حذف شد" "DevAssist and all its data were removed"
    else
        run rm -f "$INSTALL_CONF"
        ok "DevAssist حذف شد؛ داده در $DATA_DIR و تنظیمات در $CONF_DIR ماند" \
            "DevAssist was removed; data stays in $DATA_DIR and config in $CONF_DIR"
    fi
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
