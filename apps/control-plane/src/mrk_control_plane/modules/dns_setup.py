"""DNS setup guide (docs/37 §4): six steps detected from engine + Host Agent facts.

Pure functions: ``build_steps(inputs)`` turns what the panel could observe into
``[{id, state, detail_code, params, title_fa, title_en, commands, revert}]``.
Commands are for Debian/Ubuntu hosts, copy-paste safe (every change makes a
backup first) and every changing step has a revert. Nothing here runs a command.

States: ``done`` | ``todo`` | ``warning`` | ``unknown`` (could not be checked;
the full commands are still shown).
"""

from __future__ import annotations

import ipaddress
from dataclasses import dataclass, field
from typing import Any

Commands = tuple[list[dict[str, Any]], list[dict[str, Any]]]

STEP_IDS = (
    "engine_running",
    "port_53_free",
    "host_resolver",
    "docker_daemon",
    "verify_from_host",
    "verify_from_container",
)
DEFAULT_GATEWAY = "172.17.0.1"
DEFAULT_LISTEN = ("127.0.0.1:53", "172.17.0.1:53")
DEFAULT_FALLBACKS = ("1.1.1.1", "9.9.9.9")
TEST_NAME = "example.com"
RESOLVED_STUBS = frozenset({"127.0.0.53", "127.0.0.54"})
DROPIN = "/etc/systemd/resolved.conf.d/mrk.conf"
# Known DNS daemons: process name (comm) -> systemd unit on Debian/Ubuntu.
KNOWN_UNITS = {
    "dnsmasq": "dnsmasq",
    "named": "bind9",
    "unbound": "unbound",
    "pdns_server": "pdns",
    "pdns_recursor": "pdns-recursor",
    "systemd-resolve": "systemd-resolved",
    "coredns": "coredns",
    "knotd": "knot",
    "kresd": "kresd@1",
}
TITLES: dict[str, tuple[str, str]] = {
    "engine_running": ("روشن کردن موتور DNS", "Start the DNS engine"),
    "port_53_free": ("آزاد بودن پورت 53", "Port 53 is free"),
    "host_resolver": ("استفاده خود سرور از MRK DNS", "Make the server use MRK DNS"),
    "docker_daemon": ("استفاده کانتینرها از MRK DNS", "Make containers use MRK DNS"),
    "verify_from_host": ("بررسی از روی سرور", "Check from the server"),
    "verify_from_container": ("بررسی از داخل کانتینر", "Check from a container"),
}


@dataclass(slots=True)
class SetupInputs:
    installed: bool
    reachable: bool
    engine_error: str | None = None
    status: dict[str, Any] | None = None
    settings: dict[str, Any] | None = None
    agent_state: str = "not_configured"  # ok | not_configured | unreachable | unsupported
    facts: dict[str, Any] | None = None
    resolve: dict[str, Any] | None = None
    resolve_error: str | None = None
    gateway: str | None = None
    fallbacks: list[str] = field(default_factory=lambda: list(DEFAULT_FALLBACKS))
    default_listen: list[str] = field(default_factory=lambda: list(DEFAULT_LISTEN))


def _cmd(
    cid: str, fa: str, en: str, code: str, *, danger: bool = False,
    note: tuple[str, str] | None = None,
) -> dict[str, Any]:
    item: dict[str, Any] = {"id": cid, "title_fa": fa, "title_en": en, "code": code.strip("\n")}
    if danger:
        item["danger"] = True
    if note:
        item["note_fa"], item["note_en"] = note
    return item


def _step(
    sid: str, state: str, detail: str, params: dict[str, Any] | None = None,
    commands: list[dict[str, Any]] | None = None, revert: list[dict[str, Any]] | None = None,
) -> dict[str, Any]:
    return {
        "id": sid,
        "title_fa": TITLES[sid][0],
        "title_en": TITLES[sid][1],
        "state": state,
        "detail_code": detail,
        "params": params or {},
        "commands": commands or [],
        "revert": revert or [],
    }


def _host_of(address: str) -> str | None:
    text = address.strip()
    if text.startswith("["):
        text = text[1:].split("]", 1)[0]
    elif text.count(":") == 1:
        text = text.split(":", 1)[0]
    try:
        return str(ipaddress.ip_address(text))
    except ValueError:
        return None


def listen_hosts(inputs: SetupInputs) -> list[str]:
    raw: list[str] = []
    listen = (inputs.settings or {}).get("listen")
    if isinstance(listen, list) and listen:
        raw = [str(item.get("address", "")) for item in listen if isinstance(item, dict)]
    if not raw:
        raw = list(inputs.default_listen)
    hosts: list[str] = []
    for item in raw:
        host = _host_of(item)
        if host and host not in hosts:
            hosts.append(host)
    return hosts


def docker_gateway(inputs: SetupInputs) -> str:
    if inputs.gateway:
        return inputs.gateway
    facts_gateway = (inputs.facts or {}).get("docker_bridge_gateway")
    if isinstance(facts_gateway, str) and facts_gateway:
        return facts_gateway
    for host in listen_hosts(inputs):
        address = ipaddress.ip_address(host)
        if address.version == 4 and not address.is_loopback and not address.is_unspecified:
            return host
    return DEFAULT_GATEWAY


def fallbacks(inputs: SetupInputs) -> list[str]:
    values = [item for item in inputs.fallbacks if _host_of(item)]
    return values or list(DEFAULT_FALLBACKS)


# ----------------------------------------------------------------------------- commands


def engine_commands() -> Commands:
    commands = [
        _cmd("compose_up", "روشن کردن سرویس mrk-dns (در پوشه فایل Compose)",
             "Start the mrk-dns service (in the folder of the compose file)",
             "docker compose --profile dns up -d mrk-dns"),
        _cmd("compose_check", "دیدن وضعیت و لاگ موتور", "See the engine state and log",
             "docker compose --profile dns ps mrk-dns\n"
             "docker compose --profile dns logs --tail=50 mrk-dns"),
    ]
    revert = [
        _cmd("compose_stop", "خاموش کردن و حذف کانتینر mrk-dns (داده‌ها می‌مانند)",
             "Stop and remove the mrk-dns container (data is kept)",
             "docker compose --profile dns stop mrk-dns\n"
             "docker compose --profile dns rm -f mrk-dns"),
    ]
    return commands, revert


def port_commands(unit: str | None) -> Commands:
    commands = [
        _cmd("show_port_53", "دیدن برنامه‌ای که پورت 53 را گرفته",
             "See which program holds port 53",
             "sudo ss -lntup 'sport = :53'"),
    ]
    revert: list[dict[str, Any]] = []
    if unit and unit != "systemd-resolved":
        commands.append(_cmd(
            "disable_unit", f"خاموش کردن {unit} (فقط اگر دیگر لازمش ندارید)",
            f"Turn off {unit} (only if you no longer need it)",
            f"sudo systemctl disable --now {unit}",
            danger=True,
            note=("هر سرویسی که به این DNS تکیه دارد از کار می‌افتد.",
                  "Anything that relies on this DNS server stops resolving."),
        ))
        revert.append(_cmd("enable_unit", f"روشن کردن دوباره {unit}", f"Turn {unit} back on",
                           f"sudo systemctl enable --now {unit}"))
    return commands, revert


def resolved_commands(fallback: list[str]) -> Commands:
    primary = fallback[0]
    others = " ".join(fallback)
    dropin = (
        "sudo mkdir -p /etc/systemd/resolved.conf.d\n"
        f"sudo tee {DROPIN} >/dev/null <<'EOF'\n"
        "[Resolve]\n"
        "# MRK DNS first, a public DNS as backup if MRK DNS is down\n"
        f"DNS=127.0.0.1 {primary}\n"
        f"FallbackDNS={others}\n"
        "DNSStubListener=no\n"
        "EOF"
    )
    link = (
        "sudo cp -P /etc/resolv.conf /etc/resolv.conf.mrk-backup\n"
        "sudo ln -sf /run/systemd/resolve/resolv.conf /etc/resolv.conf\n"
        "sudo systemctl restart systemd-resolved"
    )
    commands = [
        _cmd("resolved_dropin", f"تنظیم systemd-resolved با فایل جدا {DROPIN}",
             f"Configure systemd-resolved with a separate file {DROPIN}", dropin),
        _cmd("resolv_conf_link", "وصل کردن /etc/resolv.conf به فهرست DNSهای systemd-resolved",
             "Point /etc/resolv.conf at systemd-resolved's server list", link,
             note=("قبل از این گام موتور DNS باید روشن باشد؛ DNS پشتیبان هم در فهرست هست.",
                   "Start the DNS engine first; the backup DNS is in the list too.")),
        _cmd("resolver_check", "دیدن نتیجه", "Check the result",
             "cat /etc/resolv.conf\nresolvectl status | head -n 20"),
    ]
    revert = [
        _cmd("resolved_revert", "برگرداندن تنظیم قبلی systemd-resolved",
             "Restore the previous systemd-resolved setup",
             f"sudo rm -f {DROPIN}\n"
             "if [ -e /etc/resolv.conf.mrk-backup ] || [ -L /etc/resolv.conf.mrk-backup ]; then\n"
             "  sudo mv -f /etc/resolv.conf.mrk-backup /etc/resolv.conf\n"
             "else\n"
             "  sudo ln -sf ../run/systemd/resolve/stub-resolv.conf /etc/resolv.conf\n"
             "fi\n"
             "sudo systemctl restart systemd-resolved"),
    ]
    return commands, revert


def static_resolv_commands(fallback: list[str]) -> Commands:
    lines = "\n".join(f"nameserver {item}" for item in ["127.0.0.1", *fallback[:2]])
    commands = [
        _cmd("resolv_conf_static", "نوشتن /etc/resolv.conf با MRK DNS و DNS پشتیبان",
             "Write /etc/resolv.conf with MRK DNS and a backup DNS",
             "sudo cp -P /etc/resolv.conf /etc/resolv.conf.mrk-backup\n"
             "sudo rm -f /etc/resolv.conf\n"
             "sudo tee /etc/resolv.conf >/dev/null <<'EOF'\n"
             f"{lines}\n"
             "options timeout:2 attempts:2\n"
             "EOF",
             note=("اگر NetworkManager، resolvconf یا DHCP این فایل را بازنویسی کند، DNS را در "
                   "تنظیمات همان ابزار هم به 127.0.0.1 تغییر دهید.",
                   "If NetworkManager, resolvconf or DHCP rewrites this file, set the DNS "
                   "to 127.0.0.1 in that tool as well.")),
    ]
    revert = [
        _cmd("resolv_conf_restore", "برگرداندن /etc/resolv.conf قبلی",
             "Restore the previous /etc/resolv.conf",
             "sudo mv -f /etc/resolv.conf.mrk-backup /etc/resolv.conf"),
    ]
    return commands, revert


def docker_commands(gateway: str, fallback: str) -> Commands:
    dns_json = f'["{gateway}", "{fallback}"]'
    merge = (
        "sudo apt-get install -y jq\n"
        "sudo mkdir -p /etc/docker\n"
        "if sudo test -f /etc/docker/daemon.json; then\n"
        "  sudo cp -a /etc/docker/daemon.json /etc/docker/daemon.json.mrk-backup\n"
        "else\n"
        "  echo '{}' | sudo tee /etc/docker/daemon.json >/dev/null\n"
        "fi\n"
        f"sudo jq '.dns = {dns_json}' /etc/docker/daemon.json \\\n"
        "  | sudo tee /etc/docker/daemon.json.new >/dev/null \\\n"
        "  && sudo mv /etc/docker/daemon.json.new /etc/docker/daemon.json\n"
        "sudo jq . /etc/docker/daemon.json"
    )
    manual = (
        "# /etc/docker/daemon.json — keep every key that is already there, add only \"dns\":\n"
        "{\n"
        f'  "dns": {dns_json}\n'
        "}"
    )
    restart_note = (
        "همه کانتینرهای سرور، از جمله Dokploy و برنامه‌هایش و خود MRK، چند ثانیه تا چند دقیقه "
        "قطع و دوباره روشن می‌شوند. در زمان کم‌کار انجام دهید.",
        "Every container on the server, including Dokploy, its apps and MRK itself, stops "
        "and starts again (seconds to minutes). Do this at a quiet time.",
    )
    commands = [
        _cmd("daemon_json_merge", "افزودن dns به daemon.json بدون حذف تنظیمات دیگر (با jq)",
             "Add dns to daemon.json keeping the other settings (with jq)", merge),
        _cmd("daemon_json_manual", "یا دستی: فقط کلید dns را اضافه کنید",
             "Or by hand: add only the dns key", manual),
        _cmd("docker_restart", "راه‌اندازی دوباره Docker (همه کانتینرها را ری‌استارت می‌کند)",
             "Restart Docker (restarts all containers)", "sudo systemctl restart docker",
             danger=True, note=restart_note),
    ]
    revert = [
        _cmd("daemon_json_revert", "برگرداندن daemon.json قبلی", "Restore the previous daemon.json",
             "if sudo test -f /etc/docker/daemon.json.mrk-backup; then\n"
             "  sudo mv -f /etc/docker/daemon.json.mrk-backup /etc/docker/daemon.json\n"
             "else\n"
             "  sudo jq 'del(.dns)' /etc/docker/daemon.json \\\n"
             "    | sudo tee /etc/docker/daemon.json.new >/dev/null \\\n"
             "    && sudo mv /etc/docker/daemon.json.new /etc/docker/daemon.json\n"
             "fi\n"
             "sudo systemctl restart docker",
             danger=True, note=restart_note),
    ]
    return commands, revert


def verify_host_commands() -> list[dict[str, Any]]:
    return [
        _cmd("dig_local", "پرسش مستقیم از MRK DNS", "Ask MRK DNS directly",
             "sudo apt-get install -y dnsutils\n"
             f"dig @127.0.0.1 {TEST_NAME} +short"),
        _cmd("dig_system", "پرسش با DNS خود سرور (خط SERVER باید 127.0.0.1 باشد)",
             "Ask through the server's own resolver (SERVER should be 127.0.0.1)",
             f"dig {TEST_NAME} | grep -E 'SERVER|status'\ngetent hosts {TEST_NAME}"),
    ]


def verify_container_commands(gateway: str) -> list[dict[str, Any]]:
    return [
        _cmd("container_nslookup", "پرسش از داخل یک کانتینر موقت (Server باید gateway باشد)",
             f"Ask from a throw-away container (Server should be {gateway})",
             f"docker run --rm busybox:1.36 nslookup {TEST_NAME}"),
        _cmd("container_resolv", "دیدن DNS کانتینرها", "See the DNS a container gets",
             "docker run --rm busybox:1.36 cat /etc/resolv.conf"),
    ]


# ----------------------------------------------------------------------------- detection


def _agent_detail(inputs: SetupInputs) -> str:
    return {
        "not_configured": "agent_not_configured",
        "unreachable": "agent_unreachable",
        "unsupported": "agent_unsupported",
    }.get(inputs.agent_state, "agent_unavailable")


def step_engine(inputs: SetupInputs) -> dict[str, Any]:
    commands, revert = engine_commands()
    if not inputs.installed:
        return _step("engine_running", "todo", "not_installed", {}, commands, revert)
    if not inputs.reachable:
        return _step("engine_running", "warning", "engine_unreachable",
                     {"reason": inputs.engine_error}, commands, revert)
    status = inputs.status or {}
    failed = [
        item for item in status.get("listeners") or []
        if isinstance(item, dict) and item.get("ok") is False
    ]
    params = {"version": status.get("version"), "uptime_s": status.get("uptime_s")}
    if failed:
        first = failed[0]
        params.update({"address": first.get("address"), "proto": first.get("proto"),
                       "error": first.get("error"), "failed": len(failed)})
        return _step("engine_running", "warning", "listener_failed", params, commands, revert)
    return _step("engine_running", "done", "running", params, commands, revert)


def _conflicts(inputs: SetupInputs) -> list[dict[str, Any]]:
    facts = inputs.facts or {}
    wanted = set(listen_hosts(inputs))
    ok_mrk = {
        _host_of(str(item.get("address", "")))
        for item in (inputs.status or {}).get("listeners") or []
        if isinstance(item, dict) and item.get("ok")
    }
    result = []
    for item in (facts.get("port_53") or {}).get("items") or []:
        address = item.get("address")
        process = item.get("process") or {}
        comm = process.get("comm") if isinstance(process, dict) else None
        if comm == "mrk-dns":
            continue
        if comm is None and inputs.reachable and address in ok_mrk:
            continue  # the engine's own socket (owner not readable)
        try:
            unspecified = ipaddress.ip_address(address).is_unspecified
        except ValueError:
            continue
        if address in wanted or unspecified or any(
            ipaddress.ip_address(host).is_unspecified for host in wanted
        ):
            result.append(item)
    return result


def step_port(inputs: SetupInputs) -> dict[str, Any]:
    if inputs.agent_state != "ok" or not (inputs.facts or {}).get("host_proc"):
        commands, revert = port_commands(None)
        detail = _agent_detail(inputs) if inputs.agent_state != "ok" else "host_proc_unavailable"
        return _step("port_53_free", "unknown", detail,
                     {"listen": listen_hosts(inputs)}, commands, revert)
    if not (inputs.facts.get("port_53") or {}).get("readable"):
        commands, revert = port_commands(None)
        return _step("port_53_free", "unknown", "host_proc_unavailable",
                     {"listen": listen_hosts(inputs)}, commands, revert)
    conflicts = _conflicts(inputs)
    if not conflicts:
        detail = "held_by_mrk" if inputs.reachable else "free"
        commands, revert = port_commands(None)
        return _step("port_53_free", "done", detail, {"listen": listen_hosts(inputs)},
                     commands, revert)
    first = conflicts[0]
    process = first.get("process") or {}
    comm = process.get("comm") or first.get("process_hint")
    unit = KNOWN_UNITS.get(comm or "")
    commands, revert = port_commands(unit)
    params = {
        "address": first.get("address"), "proto": first.get("proto"), "process": comm,
        "pid": process.get("pid"), "unit": unit, "listen": listen_hosts(inputs),
        "conflicts": len(conflicts),
    }
    if comm in {"systemd-resolve", "systemd-resolved"}:
        commands, revert = resolved_commands(fallbacks(inputs))
        return _step("port_53_free", "todo", "systemd_resolved_stub", params, commands, revert)
    return _step("port_53_free", "warning", "port_in_use", params, commands, revert)


def step_host_resolver(inputs: SetupInputs) -> dict[str, Any]:
    fallback = fallbacks(inputs)
    facts = inputs.facts or {}
    resolv = facts.get("resolv_conf") if inputs.agent_state == "ok" else None
    resolved = facts.get("resolved") or {}
    running = facts.get("systemd_resolved_running")
    uses_resolved = bool(
        (resolv or {}).get("managed_by") == "systemd-resolved" or running
    )
    if resolv is None or not resolv.get("present"):
        commands, revert = resolved_commands(fallback)
        static_commands, static_revert = static_resolv_commands(fallback)
        detail = _agent_detail(inputs) if inputs.agent_state != "ok" else "host_root_unavailable"
        return _step("host_resolver", "unknown", detail, {"fallback": fallback},
                     commands + static_commands, revert + static_revert)
    if uses_resolved:
        commands, revert = resolved_commands(fallback)
    else:
        commands, revert = static_resolv_commands(fallback)
    nameservers = list(resolv.get("nameservers") or [])
    ours = set(listen_hosts(inputs)) | {"127.0.0.1"}
    params = {
        "nameservers": nameservers,
        "managed_by": resolv.get("managed_by"),
        "symlink": resolv.get("symlink"),
        "resolved_mode": resolv.get("resolved_mode"),
        "mrk_dropin": bool(resolved.get("mrk_dropin")),
        "stub_disabled": bool(resolved.get("stub_disabled")),
        "fallback": fallback,
    }
    if nameservers and nameservers[0] in ours:
        if len(nameservers) == 1:
            return _step("host_resolver", "warning", "no_fallback", params, commands, revert)
        return _step("host_resolver", "done", "uses_mrk", params, commands, revert)
    if nameservers and nameservers[0] in RESOLVED_STUBS:
        if resolved.get("mrk_dropin") and "127.0.0.1" in (resolved.get("dns") or []):
            # resolved forwards to MRK, but the stub stays in front of it.
            return _step("host_resolver", "warning", "resolved_stub_forwarding", params,
                         commands, revert)
        return _step("host_resolver", "todo", "systemd_resolved_stub", params, commands, revert)
    if any(item in ours for item in nameservers):
        return _step("host_resolver", "warning", "mrk_not_first", params, commands, revert)
    detail = "uses_other_dns" if uses_resolved else "static_resolv_conf"
    return _step("host_resolver", "todo", detail, params, commands, revert)


def step_docker(inputs: SetupInputs) -> dict[str, Any]:
    gateway = docker_gateway(inputs)
    fallback = fallbacks(inputs)
    commands, revert = docker_commands(gateway, fallback[0])
    facts = inputs.facts or {}
    daemon = facts.get("docker_daemon") if inputs.agent_state == "ok" else None
    params: dict[str, Any] = {"gateway": gateway, "fallback": fallback[0]}
    if daemon is None:
        detail = _agent_detail(inputs) if inputs.agent_state != "ok" else "host_root_unavailable"
        return _step("docker_daemon", "unknown", detail, params, commands, revert)
    params.update({"present": daemon.get("present"), "dns": daemon.get("dns"),
                   "keys": daemon.get("keys") or []})
    if not daemon.get("present"):
        return _step("docker_daemon", "todo", "daemon_json_missing", params, commands, revert)
    if daemon.get("valid") is False:
        return _step("docker_daemon", "warning", "daemon_json_invalid", params, commands, revert)
    dns = daemon.get("dns") or []
    ours = set(listen_hosts(inputs)) | {gateway}
    if not dns:
        return _step("docker_daemon", "todo", "dns_not_set", params, commands, revert)
    if dns[0] not in ours:
        detail = "mrk_not_first" if any(item in ours for item in dns) else "uses_other_dns"
        return _step("docker_daemon", "todo", detail, params, commands, revert)
    if len(dns) == 1:
        return _step("docker_daemon", "warning", "no_fallback", params, commands, revert)
    return _step("docker_daemon", "done", "uses_mrk", params, commands, revert)


def step_verify_host(inputs: SetupInputs, host_step: dict[str, Any]) -> dict[str, Any]:
    commands = verify_host_commands()
    params: dict[str, Any] = {"name": TEST_NAME}
    if not inputs.reachable:
        return _step("verify_from_host", "todo" if not inputs.installed else "warning",
                     "engine_not_running", params, commands)
    answer = inputs.resolve or {}
    params.update({"rcode": answer.get("rcode"), "source": answer.get("source"),
                   "rtt_ms": answer.get("rtt_ms"),
                   "answers": len(answer.get("answers") or [])})
    if inputs.resolve is None:
        params["error"] = inputs.resolve_error
        return _step("verify_from_host", "warning", "resolve_failed", params, commands)
    if answer.get("rcode") not in {"NOERROR", 0}:
        return _step("verify_from_host", "warning", "resolve_failed", params, commands)
    if host_step["state"] == "done":
        return _step("verify_from_host", "done", "ok", params, commands)
    if host_step["state"] == "unknown":
        return _step("verify_from_host", "unknown", "engine_ok_host_unknown", params, commands)
    return _step("verify_from_host", "todo", "engine_ok_host_not_using", params, commands)


def step_verify_container(inputs: SetupInputs, docker_step: dict[str, Any]) -> dict[str, Any]:
    gateway = docker_gateway(inputs)
    commands = verify_container_commands(gateway)
    params = {"gateway": gateway, "name": TEST_NAME}
    if docker_step["state"] in {"todo", "warning"} and docker_step["detail_code"] != "no_fallback":
        return _step("verify_from_container", "todo", "docker_dns_not_set", params, commands)
    if not inputs.reachable:
        return _step("verify_from_container", "todo", "engine_not_running", params, commands)
    gateway_listener = any(
        _host_of(str(item.get("address", ""))) == gateway and item.get("ok")
        for item in (inputs.status or {}).get("listeners") or []
        if isinstance(item, dict)
    )
    params["gateway_listener"] = gateway_listener
    if inputs.status is not None and not gateway_listener:
        return _step("verify_from_container", "warning", "gateway_not_listening", params,
                     commands)
    # The panel never starts containers itself: this check is always manual.
    return _step("verify_from_container", "unknown", "manual_check", params, commands)


def build_steps(inputs: SetupInputs) -> list[dict[str, Any]]:
    engine = step_engine(inputs)
    port = step_port(inputs)
    host = step_host_resolver(inputs)
    docker = step_docker(inputs)
    return [
        engine,
        port,
        host,
        docker,
        step_verify_host(inputs, host),
        step_verify_container(inputs, docker),
    ]


def setup_complete(steps: list[dict[str, Any]]) -> bool:
    """Every checkable step done; the container check may stay manual (unknown)."""
    by_id = {step["id"]: step for step in steps}
    required = STEP_IDS[:5]
    if any(by_id[sid]["state"] != "done" for sid in required):
        return False
    return by_id["verify_from_container"]["state"] in {"done", "unknown"}
