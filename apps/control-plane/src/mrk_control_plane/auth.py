from __future__ import annotations

import hashlib
import os
import re
import secrets
import threading
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Final

from argon2 import PasswordHasher
from argon2.exceptions import InvalidHashError, VerifyMismatchError
from sqlalchemy import delete, func, or_, select, update
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session as OrmSession

from .database import Database
from .models import (
    ApiToken,
    AuditEvent,
    CustomRole,
    SystemSetting,
    User,
    UserInvite,
    UserPasswordState,
)
from .models import Session as LoginSession


def password_policy() -> dict[str, object]:
    """Operator-configurable password rule; default: 6+ chars with letters and digits."""
    try:
        min_length = int(os.getenv("MRK_PASSWORD_MIN_LENGTH", "6"))
    except ValueError:
        min_length = 6
    min_length = max(4, min(min_length, 128))

    def flag(name: str) -> bool:
        return os.getenv(name, "true").strip().lower() not in {"0", "false", "no", "off"}

    return {
        "min_length": min_length,
        "require_letters": flag("MRK_PASSWORD_REQUIRE_LETTERS"),
        "require_digits": flag("MRK_PASSWORD_REQUIRE_DIGITS"),
    }


ROLE_PERMISSIONS: Final[dict[str, frozenset[str]]] = {
    "owner": frozenset({"*"}),
    "admin": frozenset(
        {
            "system:read", "upstream:read", "upstream:write", "upstream:operate",
            "cache:read", "cache:write", "task:read", "task:write", "audit:read",
            "user:read", "user:write", "token:read", "token:write", "backup:read",
            "backup:write", "notification:read", "notification:write", "agent:read",
            "agent:write",
            # Gate 17 (docs/29 §1)
            "metrics:read", "logs:read", "docker:operate", "docker:prune", "dokploy:read",
            "dokploy:deploy", "dokploy:write",
            # Gate 18 (docs/31 §1)
            "s3:read", "s3:write", "s3:admin", "backup:server:read", "backup:server:write",
            "updates:read", "updates:write",
            # Gate 19 (docs/32 §1)
            "firewall:read", "firewall:write", "vuln:read", "vuln:write", "db:read",
            "db:write",
        }
    ),
    "operator": frozenset(
        {
            "system:read", "upstream:read", "upstream:operate", "cache:read",
            "cache:write", "task:read", "task:write", "audit:read", "backup:read",
            "notification:read", "agent:read",
            # Gate 17 (docs/29 §1)
            "metrics:read", "logs:read", "docker:operate", "dokploy:read", "dokploy:deploy",
            # Gate 18 (docs/31 §1)
            "s3:read", "s3:write", "backup:server:read", "updates:read", "updates:write",
            # Gate 19 (docs/32 §1)
            "firewall:read", "vuln:read", "vuln:write",
        }
    ),
    "developer": frozenset(
        {
            "system:read", "upstream:read", "cache:read", "task:read", "token:read",
            "token:write", "metrics:read", "dokploy:read",
            # Gate 18 (docs/31 §1)
            "s3:read", "updates:read",
            # Gate 19 (docs/32 §1)
            "vuln:read",
        }
    ),
    "viewer": frozenset(
        {
            "system:read", "upstream:read", "cache:read", "task:read", "metrics:read",
            # Gate 18 (docs/31 §1)
            "updates:read",
            # Gate 19 (docs/32 §1)
            "vuln:read",
        }
    ),
}

BUILTIN_ROLES: Final[tuple[str, ...]] = tuple(ROLE_PERMISSIONS)
CUSTOM_ROLE_PREFIX: Final = "custom:"
DANGER_LEVELS: Final[tuple[str, ...]] = ("none", "low", "medium", "high", "critical")
INVITE_TTL_SECONDS: Final = 7 * 86400


@dataclass(frozen=True, slots=True)
class PermissionSpec:
    id: str
    group: str
    name_fa: str
    name_en: str
    description_fa: str
    description_en: str
    danger: str = "none"
    requires: tuple[str, ...] = ()


# The 7 navigation sections of docs/33 §1.1; the catalogue groups by them (§5.3).
PERMISSION_GROUPS: Final[tuple[tuple[str, str, str], ...]] = (
    ("home", "خانه", "Home"),
    ("packages", "بسته‌ها", "Packages"),
    ("server", "سرور و برنامه‌ها", "Server & apps"),
    ("files", "فایل‌ها و پشتیبان", "Files & backups"),
    ("security", "امنیت و اینترنت", "Security & internet"),
    ("people", "کاربران و دسترسی", "People & access"),
    ("alerts", "اعلان‌ها و تاریخچه", "Alerts & history"),
)

_P = PermissionSpec
PERMISSION_CATALOG: Final[tuple[PermissionSpec, ...]] = (
    _P("system:read", "home", "دیدن وضعیت کلی سامانه", "See system status",
       "صفحه خانه، سلامت سرویس‌ها و فضای دیسک را نشان می‌دهد.",
       "Shows Home, service health and disk space."),
    _P("cache:read", "packages", "دیدن بسته‌های ذخیره‌شده", "See cached packages",
       "فهرست بسته‌های npm و PyPI ذخیره‌شده و جست‌وجو در آن‌ها.",
       "List and search the cached npm and PyPI packages."),
    _P("cache:write", "packages", "نگه‌داشتن، قرنطینه، پاک کردن و پیش‌دریافت بسته‌ها",
       "Pin, quarantine, remove and prefetch packages",
       "بسته‌ها را نگه می‌دارد، قرنطینه یا پاک می‌کند و از قبل دریافت می‌کند.",
       "Pins, quarantines, removes and prefetches packages.", "medium", ("cache:read",)),
    _P("upstream:read", "packages", "دیدن منابع دریافت (و پروکسی/DNS)",
       "See package sources (and proxy/DNS)",
       "منابع دریافت بسته، پروکسی‌ها و تنظیم DNS را نشان می‌دهد.",
       "Shows package sources, proxies and DNS settings."),
    _P("upstream:operate", "packages", "امتحان، مسدود کردن و حالت بدون اینترنت منابع",
       "Test, block and switch sources offline",
       "منبع را امتحان یا موقتاً مسدود می‌کند و حالت بدون اینترنت را روشن می‌کند.",
       "Tests or temporarily blocks a source and toggles offline mode.", "medium",
       ("upstream:read",)),
    _P("upstream:write", "packages", "افزودن/تغییر منابع، پروکسی، DNS و منابع داخلی",
       "Add/change sources, proxies, DNS, internal sources",
       "منبع، پروکسی و DNS را اضافه یا عوض می‌کند؛ روی همه ارتباط‌های اینترنتی اثر دارد.",
       "Adds or changes sources, proxies and DNS; affects all outbound traffic.", "high",
       ("upstream:read",)),
    _P("agent:read", "server", "دیدن سرور و کانتینرها", "See server and containers",
       "وضعیت سرور، کانتینرها و دستیار سرور را نشان می‌دهد.",
       "Shows the server, its containers and the server helper."),
    _P("agent:write", "server", "وصل کردن دستیار سرور و تنظیم هشدارهای مصرف",
       "Pair the server helper; set resource alerts",
       "دستیار سرور را وصل یا قطع می‌کند و حد هشدار مصرف منابع را تعیین می‌کند.",
       "Pairs or unpairs the server helper and sets resource alert limits.", "high",
       ("agent:read",)),
    _P("metrics:read", "server", "دیدن نمودار مصرف منابع", "See resource charts",
       "نمودار پردازنده، حافظه و دیسک سرور و کانتینرها.",
       "CPU, memory and disk charts for the server and containers."),
    _P("logs:read", "server", "دیدن لاگ کانتینرها", "Read container logs",
       "خروجی کانتینرها را نشان می‌دهد؛ ممکن است اطلاعات حساس داشته باشد.",
       "Shows container output, which may contain sensitive data.", "medium",
       ("agent:read",)),
    _P("docker:operate", "server", "روشن/خاموش/راه‌اندازی دوباره کانتینر و دریافت نسخه",
       "Start/stop/restart containers, pull images",
       "کانتینرها را روشن، خاموش یا دوباره راه‌اندازی می‌کند و نسخه تازه می‌گیرد.",
       "Starts, stops or restarts containers and pulls images.", "medium", ("agent:read",)),
    _P("docker:prune", "server", "پاک کردن موارد بی‌استفاده Docker", "Clean up unused Docker items",
       "ایمیج‌ها، کانتینرها و فضای بی‌استفاده Docker را برای همیشه پاک می‌کند.",
       "Permanently removes unused Docker images, containers and space.", "high",
       ("docker:operate",)),
    _P("dokploy:read", "server", "دیدن برنامه‌های Dokploy", "See Dokploy apps",
       "پروژه‌ها و برنامه‌های Dokploy و وضعیت انتشارشان.",
       "Dokploy projects, apps and their deployments."),
    _P("dokploy:deploy", "server", "انتشار، توقف و شروع برنامه‌های Dokploy",
       "Deploy, stop and start Dokploy apps",
       "برنامه‌های Dokploy را منتشر، متوقف یا شروع می‌کند.",
       "Deploys, stops and starts Dokploy apps.", "medium", ("dokploy:read",)),
    _P("dokploy:write", "server", "وصل/قطع کردن Dokploy و تنظیم آن",
       "Connect/disconnect and tune Dokploy",
       "اتصال به Dokploy و کلید دسترسی آن را تنظیم می‌کند.",
       "Sets up the Dokploy connection and its access key.", "high", ("dokploy:read",)),
    _P("updates:read", "server", "دیدن نسخه‌های تازه برنامه‌ها", "See available image updates",
       "نشان می‌دهد برای کدام برنامه‌ها نسخه جدید آمده است.",
       "Shows which apps have a newer image version."),
    _P("updates:write", "server", "بررسی دستی و تنظیم بررسی نسخه‌ها",
       "Check now; change update-check settings",
       "بررسی نسخه‌ها را همین حالا اجرا می‌کند و زمان‌بندی آن را تغییر می‌دهد.",
       "Runs an update check now and changes its schedule.", "low", ("updates:read",)),
    _P("db:read", "server", "دیدن دیتابیس‌ها و داده‌هایشان", "Browse databases and data",
       "محتوای دیتابیس‌ها را نشان می‌دهد؛ داده‌های واقعی کاربران دیده می‌شود.",
       "Shows database contents, including real user data.", "high"),
    _P("db:write", "server", "نوشتن در دیتابیس و مدیریت اتصال‌ها",
       "Write to databases; manage connections",
       "داده‌ها را در دیتابیس تغییر می‌دهد یا پاک می‌کند و اتصال‌ها را مدیریت می‌کند.",
       "Changes or deletes database data and manages connections.", "critical", ("db:read",)),
    _P("s3:read", "files", "دیدن و دانلود فایل‌ها", "See and download files",
       "فایل‌های فضای فایل را نشان می‌دهد و دانلود می‌کند.",
       "Lists and downloads files in the file space.", "medium"),
    _P("s3:write", "files", "آپلود، پاک کردن و لینک اشتراک فایل", "Upload, delete and share files",
       "فایل آپلود یا پاک می‌کند و برای آن لینک اشتراک می‌سازد.",
       "Uploads or deletes files and creates share links.", "medium", ("s3:read",)),
    _P("s3:admin", "files", "ساخت پوشه اصلی، کاربر و کلید فضای فایل",
       "Manage buckets, file-space users and keys",
       "پوشه‌های اصلی، کاربران و کلیدهای فضای فایل را می‌سازد و حذف می‌کند.",
       "Creates and removes buckets, file-space users and keys.", "high", ("s3:read",)),
    _P("backup:read", "files", "دیدن پشتیبان‌های پنل", "See panel backups",
       "فهرست پشتیبان‌های خود پنل MRK.", "Lists backups of the MRK panel itself."),
    _P("backup:write", "files", "ساخت پشتیبان پنل و آماده‌سازی بازگردانی",
       "Create panel backups; prepare restore",
       "از پنل پشتیبان می‌گیرد و برنامه بازگردانی آماده می‌کند.",
       "Creates panel backups and prepares a restore plan.", "high", ("backup:read",)),
    _P("backup:server:read", "files", "دیدن پشتیبان برنامه‌ها", "See app backups",
       "کارها و اجراهای پشتیبان‌گیری از برنامه‌های سرور.",
       "Backup jobs and runs for the server's apps."),
    _P("backup:server:write", "files", "ساخت، اجرا و دانلود پشتیبان برنامه‌ها و گرفتن کلید",
       "Create, run, download app backups; export keys",
       "پشتیبان برنامه‌ها را می‌سازد، اجرا و دانلود می‌کند و کلید رمزگشایی را می‌گیرد.",
       "Creates, runs and downloads app backups and exports their keys.", "high",
       ("backup:server:read",)),
    _P("firewall:read", "security", "دیدن وضعیت دیوار آتش و IPهای مسدود",
       "See firewall and blocked IPs",
       "حالت دیوار آتش، قواعد و نشانی‌های مسدودشده را نشان می‌دهد.",
       "Shows the firewall mode, rules and blocked addresses."),
    _P("firewall:write", "security", "تغییر حالت دیوار آتش، قواعد و مسدود کردن",
       "Change firewall mode, rules and blocks",
       "اشتباه در آن می‌تواند دسترسی همه، حتی خودتان، را به سرور ببندد.",
       "A mistake can lock everyone, including you, out of the server.", "critical",
       ("firewall:read",)),
    _P("vuln:read", "security", "دیدن مشکلات امنیتی برنامه‌ها", "See vulnerability findings",
       "مشکلات امنیتی پیداشده در ایمیج برنامه‌ها.", "Security findings in app images."),
    _P("vuln:write", "security", "اسکن دستی، نادیده گرفتن و تنظیم بررسی امنیتی",
       "Scan, ignore findings, change scan settings",
       "اسکن را اجرا می‌کند، یافته‌ها را نادیده می‌گیرد و زمان‌بندی را تغییر می‌دهد.",
       "Runs scans, ignores findings and changes the schedule.", "low", ("vuln:read",)),
    _P("user:read", "people", "دیدن افراد و نقش‌ها", "See people and roles",
       "فهرست افراد، نقش‌ها و تنظیم ثبت‌نام عمومی.",
       "Lists people, roles and the public sign-up setting."),
    _P("user:write", "people", "دعوت، غیرفعال کردن و تغییر نقش افراد",
       "Invite, disable and change roles",
       "افراد را دعوت یا غیرفعال می‌کند و نقششان را عوض می‌کند.",
       "Invites or disables people and changes their roles.", "critical", ("user:read",)),
    _P("token:read", "people", "دیدن کلیدهای برنامه خود", "See own app keys",
       "کلیدهای برنامه‌ای که خودتان ساخته‌اید.", "The app keys you created yourself."),
    _P("token:write", "people", "ساخت و لغو کلید برنامه", "Create and revoke app keys",
       "برای برنامه‌ها و CI کلید دسترسی می‌سازد یا لغو می‌کند.",
       "Creates or revokes access keys for apps and CI.", "medium", ("token:read",)),
    _P("notification:read", "alerts", "دیدن کانال‌ها و قواعد اعلان", "See alert channels and rules",
       "کانال‌های تلگرام/بله/ایمیل/وب‌هوک و قواعد اعلان.",
       "Telegram/Bale/email/webhook channels and alert rules."),
    _P("notification:write", "alerts", "افزودن/تغییر کانال و قواعد اعلان",
       "Add/change alert channels and rules",
       "کانال اعلان می‌سازد یا عوض می‌کند و قواعد ارسال را تعیین می‌کند.",
       "Adds or changes alert channels and delivery rules.", "medium",
       ("notification:read",)),
    _P("task:read", "alerts", "دیدن کارهای در حال انجام", "See background jobs",
       "کارهای پس‌زمینه و نتیجه آن‌ها.", "Background jobs and their results."),
    _P("task:write", "alerts", "لغو یا تکرار کارها", "Cancel or retry jobs",
       "کار در حال انجام را لغو یا کار ناموفق را تکرار می‌کند.",
       "Cancels a running job or retries a failed one.", "low", ("task:read",)),
    _P("audit:read", "alerts", "دیدن تاریخچه فعالیت", "See activity history",
       "چه کسی، چه زمانی، چه کاری کرده است.", "Who did what, and when.", "medium"),
)
del _P

WILDCARD_PERMISSION: Final = PermissionSpec(
    "*", "people", "همه اجازه‌ها (فقط مالک)", "All permissions (owner)",
    "هر کاری را مجاز می‌کند؛ فقط نقش مالک آن را دارد.",
    "Allows everything; only the owner role holds it.", "critical",
)
KNOWN_PERMISSIONS: Final[frozenset[str]] = frozenset(item.id for item in PERMISSION_CATALOG)
PERMISSION_REQUIRES: Final[dict[str, frozenset[str]]] = {
    item.id: frozenset(item.requires) for item in PERMISSION_CATALOG
}
_PERMISSION_INDEX: Final[dict[str, PermissionSpec]] = {
    item.id: item for item in PERMISSION_CATALOG
}

# Plain role cards (docs/33 §5.1). Role dropdowns render these names, never keys.
BUILTIN_ROLE_INFO: Final[dict[str, dict[str, object]]] = {
    "owner": {
        "name_fa": "مالک", "name_en": "Owner",
        "description_fa": "همه کارها، از جمله کارهای خیلی حساس",
        "description_en": "Everything, including the most sensitive actions",
        "can_fa": ["همه کارها", "اتصال پوشه‌های سرور به فضای فایل", "ساختن مالک دیگر",
                   "ساختن و تغییر نقش‌های سفارشی"],
        "can_en": ["Everything", "Link server folders to the file space",
                   "Create other owners", "Create and edit custom roles"],
        "cannot_fa": [], "cannot_en": [],
        "note_fa": "بهتر است فقط یک نفر این نقش را داشته باشد.",
        "note_en": "Only one person should have this role.",
    },
    "admin": {
        "name_fa": "مدیر", "name_en": "Admin",
        "description_fa": "همه چیز را تنظیم می‌کند",
        "description_en": "Sets everything up",
        "can_fa": ["تغییر همه تنظیمات", "افزودن و حذف افراد", "وصل کردن Dokploy و دستیار سرور",
                   "دیوار آتش، دیتابیس‌ها و فضای فایل", "تنظیم پشتیبان‌گیری"],
        "can_en": ["Change every setting", "Add and remove people",
                   "Connect Dokploy and the server helper",
                   "Firewall, databases and file space", "Set up backups"],
        "cannot_fa": ["اتصال پوشه‌های سرور به فضای فایل", "ساختن مالک"],
        "cannot_en": ["Link server folders to the file space", "Create an owner"],
        "note_fa": "می‌تواند افراد دیگر را هم اضافه کند.",
        "note_en": "Can add other people too.",
    },
    "operator": {
        "name_fa": "مسئول روزانه", "name_en": "Operator",
        "description_fa": "کارهای هر روز را انجام می‌دهد، تنظیمات اصلی را نه",
        "description_en": "Does the daily work, not the core setup",
        "can_fa": ["روشن و خاموش کردن کانتینرها و انتشار برنامه‌ها", "اجرای پشتیبان‌گیری",
                   "امتحان و مسدود کردن منابع و مدیریت بسته‌ها", "آپلود فایل",
                   "بررسی نسخه‌ها و آسیب‌پذیری‌ها، دیدن لاگ و تاریخچه"],
        "can_en": ["Start/stop containers and deploy apps", "Run backups",
                   "Test/block sources and manage cached packages", "Upload files",
                   "Check updates and vulnerabilities; see logs and history"],
        "cannot_fa": ["افزودن افراد", "تغییر پروکسی و DNS", "تنظیم پشتیبان‌گیری یا Dokploy",
                      "دیوار آتش و دیتابیس‌ها"],
        "cannot_en": ["Add people", "Change proxies or DNS", "Set up backups or Dokploy",
                      "Firewall and databases"],
    },
    "developer": {
        "name_fa": "برنامه‌نویس", "name_en": "Developer",
        "description_fa": "بسته‌ها را استفاده می‌کند و وضعیت را می‌بیند",
        "description_en": "Uses packages and sees the status",
        "can_fa": ["دیدن بسته‌ها و منابع", "دیدن نمودار سرور و برنامه‌ها", "دیدن فایل‌ها",
                   "ساختن کلید برنامه برای خودش"],
        "can_en": ["See packages and sources", "See server charts and apps", "See files",
                   "Create own app keys"],
        "cannot_fa": ["تغییر هر چیزی روی سرور", "دیدن لاگ‌ها", "دیدن تاریخچه"],
        "cannot_en": ["Change anything on the server", "See logs", "See history"],
    },
    "viewer": {
        "name_fa": "بیننده", "name_en": "Viewer",
        "description_fa": "فقط می‌بیند",
        "description_en": "Can only look",
        "can_fa": ["دیدن وضعیت", "دیدن بسته‌ها و منابع", "دیدن نمودارها",
                   "دیدن نسخه‌های تازه و مشکلات امنیتی"],
        "can_en": ["See status", "See packages and sources", "See charts",
                   "See updates and security findings"],
        "cannot_fa": ["تغییر هر چیزی"],
        "cannot_en": ["Change anything"],
    },
}


def permission_catalog() -> dict[str, object]:
    """GET /api/v1/permissions payload: the catalogue grouped by nav section."""
    groups: list[dict[str, object]] = []
    for group_id, name_fa, name_en in PERMISSION_GROUPS:
        items = [item for item in PERMISSION_CATALOG if item.group == group_id]
        if group_id == "people":
            items.append(WILDCARD_PERMISSION)
        groups.append(
            {
                "id": group_id,
                "name_fa": name_fa,
                "name_en": name_en,
                "permissions": [
                    {
                        "id": item.id,
                        "name_fa": item.name_fa,
                        "name_en": item.name_en,
                        "description_fa": item.description_fa,
                        "description_en": item.description_en,
                        "danger": item.danger,
                        "requires": list(item.requires),
                        "assignable": item.id != "*",
                    }
                    for item in items
                ],
            }
        )
    return {"groups": groups, "danger_levels": list(DANGER_LEVELS)}


def missing_dependencies(permissions: frozenset[str] | set[str]) -> dict[str, list[str]]:
    """Return {permission: [required permissions it lacks]} (write ⇒ read, ...)."""
    missing: dict[str, list[str]] = {}
    for permission in sorted(permissions):
        lacking = sorted(PERMISSION_REQUIRES.get(permission, frozenset()) - set(permissions))
        if lacking:
            missing[permission] = lacking
    return missing


def dependency_closure(permissions: frozenset[str] | set[str]) -> frozenset[str]:
    result = set(permissions)
    pending = list(result)
    while pending:
        for required in PERMISSION_REQUIRES.get(pending.pop(), frozenset()):
            if required not in result:
                result.add(required)
                pending.append(required)
    return frozenset(result)


def covers(granted: frozenset[str], wanted: frozenset[str] | set[str]) -> bool:
    """True when a holder of ``granted`` holds every permission in ``wanted``."""
    return "*" in granted or set(wanted) <= granted


class FieldError(ValueError):
    """A validation failure tied to request fields (docs/33 §2.3, BE4).

    Still a ValueError with the historical message, so older ``except
    ValueError`` paths and message checks keep working.
    """

    def __init__(
        self,
        code: str,
        message: str,
        field: str | None = None,
        reason: str | None = None,
        *,
        status_code: int = 422,
        params: dict[str, object] | None = None,
        fields: list[dict[str, object]] | None = None,
    ) -> None:
        super().__init__(message)
        self.code = code
        self.message = message
        self.status_code = status_code
        if fields is not None:
            self.fields = fields
        elif field is not None:
            entry: dict[str, object] = {"field": field, "reason_code": reason or "invalid"}
            if params:
                entry["params"] = params
            self.fields = [entry]
        else:
            self.fields = []

    @property
    def reason(self) -> str | None:
        return str(self.fields[0]["reason_code"]) if self.fields else None


class PermissionEscalationError(PermissionError):
    """The actor tried to grant or touch permissions they do not hold."""

    def __init__(self, message: str, permissions: list[str] | None = None) -> None:
        super().__init__(message)
        self.message = message
        self.permissions = permissions or []


class RoleInUseError(Exception):
    def __init__(self, role: str, users: list[dict[str, object]]) -> None:
        super().__init__(f"role {role} is assigned to {len(users)} user(s)")
        self.role = role
        self.users = users


def _role_card(role: str, permissions: frozenset[str]) -> dict[str, object]:
    info = BUILTIN_ROLE_INFO.get(role, {})
    return {
        "id": role,
        "name": role,
        "builtin": True,
        "editable": False,
        "name_fa": info.get("name_fa", role),
        "name_en": info.get("name_en", role),
        "description_fa": info.get("description_fa", ""),
        "description_en": info.get("description_en", ""),
        "note_fa": info.get("note_fa"),
        "note_en": info.get("note_en"),
        "can_fa": list(info.get("can_fa", [])),  # type: ignore[call-overload]
        "can_en": list(info.get("can_en", [])),  # type: ignore[call-overload]
        "cannot_fa": list(info.get("cannot_fa", [])),  # type: ignore[call-overload]
        "cannot_en": list(info.get("cannot_en", [])),  # type: ignore[call-overload]
        "permissions": sorted(permissions),
    }


def _custom_role_card(row: CustomRole) -> dict[str, object]:
    held = set(row.permissions)
    granted = [spec for spec in PERMISSION_CATALOG if spec.id in held]
    withheld = [
        spec
        for spec in PERMISSION_CATALOG
        if spec.id not in held and spec.danger in {"high", "critical"}
    ]
    return {
        "id": f"{CUSTOM_ROLE_PREFIX}{row.id}",
        "name": f"{CUSTOM_ROLE_PREFIX}{row.id}",
        "builtin": False,
        "editable": True,
        "name_fa": row.name,
        "name_en": row.name,
        "display_name": row.name,
        "description_fa": row.description,
        "description_en": row.description,
        "description": row.description,
        "note_fa": None,
        "note_en": None,
        "can_fa": [spec.name_fa for spec in granted],
        "can_en": [spec.name_en for spec in granted],
        "cannot_fa": [spec.name_fa for spec in withheld],
        "cannot_en": [spec.name_en for spec in withheld],
        "permissions": sorted(item for item in row.permissions if item in KNOWN_PERMISSIONS),
        "created_at": row.created_at,
        "updated_at": row.updated_at,
    }


def generate_one_time_password(min_length: int = 16) -> str:
    """A strong temporary password that always satisfies password_policy()."""
    alphabet = "abcdefghjkmnpqrstuvwxyzABCDEFGHJKMNPQRSTUVWXYZ23456789"
    length = max(16, min_length)
    while True:
        value = "".join(secrets.choice(alphabet) for _ in range(length))
        if any(char.isalpha() for char in value) and any(char.isdigit() for char in value):
            # Groups of four are easier to read aloud or retype.
            return "-".join(value[index:index + 4] for index in range(0, length, 4))


@dataclass(frozen=True, slots=True)
class Principal:
    user_id: int
    username: str
    role: str
    permissions: frozenset[str]
    session_id: int | None
    csrf_hash: str
    token_id: int | None = None
    display_name: str | None = None
    email: str | None = None
    must_change_password: bool = False

    def allows(self, permission: str) -> bool:
        return "*" in self.permissions or permission in self.permissions


class AuthStore:
    def __init__(
        self,
        data_dir: Path,
        session_ttl_seconds: int = 28800,
        database: Database | None = None,
        rate_limit_attempts: int = 5,
        rate_limit_window_seconds: int = 300,
        session_prune_age_seconds: int = 7 * 86400,
    ) -> None:
        self.root = data_dir / "control-plane"
        self.root.mkdir(parents=True, exist_ok=True, mode=0o700)
        self.session_ttl_seconds = session_ttl_seconds
        self.rate_limit_attempts = rate_limit_attempts
        self.rate_limit_window_seconds = rate_limit_window_seconds
        self.session_prune_age_seconds = session_prune_age_seconds
        self.hasher = PasswordHasher(time_cost=3, memory_cost=65536, parallelism=2)
        self._dummy_password_hash = self.hasher.hash(secrets.token_urlsafe(32))
        self._lock = threading.RLock()
        self._attempts: dict[str, list[float]] = {}
        # Each Argon2 check uses 64 MiB; cap concurrency so a burst of bad
        # logins cannot exhaust memory or every worker thread.
        self._hash_slots = threading.BoundedSemaphore(
            int(os.getenv("MRK_PASSWORD_HASH_CONCURRENCY", "4"))
        )
        self.db = database or Database(data_dir)
        self.db.initialize()

    @staticmethod
    def _digest(value: str) -> str:
        return hashlib.sha256(value.encode("utf-8")).hexdigest()

    @staticmethod
    def csrf_for_session(session_token: str) -> str:
        """Derive the CSRF token from the secret session token.

        It stays the same for the life of a session, so reloading or opening a
        second tab no longer invalidates the first tab's token. The session
        token is HttpOnly, so another site cannot compute this value.
        """
        return hashlib.sha256(f"mrk-csrf:{session_token}".encode()).hexdigest()

    def _verify_password(self, password_hash: str, password: str) -> bool:
        with self._hash_slots:
            return self.hasher.verify(password_hash, password)

    def _hash_password(self, password: str) -> str:
        with self._hash_slots:
            return self.hasher.hash(password)

    @staticmethod
    def validate_username(username: str, field: str = "username") -> str:
        normalized = username.strip().lower()
        if not 3 <= len(normalized) <= 64 or not all(
            item.isalnum() or item in "._-" for item in normalized
        ):
            reason = (
                "too_short" if len(normalized) < 3
                else "too_long" if len(normalized) > 64
                else "invalid_characters"
            )
            raise FieldError(
                "invalid_username", "username must be 3-64 safe characters", field, reason,
                params={"min_length": 3, "max_length": 64, "allowed": "a-z 0-9 . _ -"},
            )
        return normalized

    @staticmethod
    def validate_password(password: str, field: str = "password") -> None:
        policy = password_policy()
        min_length = int(policy["min_length"])  # type: ignore[call-overload]
        if len(password) < min_length or len(password) > 256:
            raise FieldError(
                "weak_password",
                f"password must be between {min_length} and 256 characters",
                field,
                "too_short" if len(password) < min_length else "too_long",
                params={"min_length": min_length, "max_length": 256},
            )
        if policy["require_letters"] and not any(char.isalpha() for char in password):
            raise FieldError(
                "weak_password", "password must contain at least one letter", field,
                "missing_letter",
            )
        if policy["require_digits"] and not any(char.isdigit() for char in password):
            raise FieldError(
                "weak_password", "password must contain at least one digit", field,
                "missing_digit",
            )

    @staticmethod
    def validate_display_name(display_name: str, field: str = "display_name") -> str:
        normalized = " ".join(display_name.strip().split())
        if not 2 <= len(normalized) <= 100:
            raise FieldError(
                "invalid_name", "display name must be between 2 and 100 characters", field,
                "too_short" if len(normalized) < 2 else "too_long",
                params={"min_length": 2, "max_length": 100},
            )
        return normalized

    @staticmethod
    def validate_email(email: str, field: str = "email") -> str:
        normalized = email.strip().lower()
        if len(normalized) > 254 or re.fullmatch(
            r"[^@\s]{1,64}@[^@\s]{1,189}", normalized
        ) is None:
            raise FieldError("invalid_email", "invalid email", field, "invalid_format")
        return normalized

    # ----- roles -------------------------------------------------------------
    @staticmethod
    def _custom_role_row(db: OrmSession, role: str) -> CustomRole | None:
        if not role.startswith(CUSTOM_ROLE_PREFIX):
            return None
        return db.get(CustomRole, role[len(CUSTOM_ROLE_PREFIX):])

    def _role_permissions_db(self, db: OrmSession, role: str) -> frozenset[str] | None:
        """Permissions of a built-in or custom role; None when the role is unknown."""
        builtin = ROLE_PERMISSIONS.get(role)
        if builtin is not None:
            return builtin
        row = self._custom_role_row(db, role)
        if row is None:
            return None
        # Filter on read too: a permission removed from the code must not linger.
        return frozenset(item for item in row.permissions if item in KNOWN_PERMISSIONS)

    def role_permissions(self, role: str) -> frozenset[str] | None:
        if role in ROLE_PERMISSIONS:
            return ROLE_PERMISSIONS[role]
        with self.db.session() as db:
            return self._role_permissions_db(db, role)

    def _check_assignable(
        self, db: OrmSession, role: str, actor_permissions: frozenset[str] | None
    ) -> frozenset[str]:
        permissions = self._role_permissions_db(db, role)
        if permissions is None:
            raise FieldError("unknown_role", "unknown role", "role", "unknown_role")
        if actor_permissions is not None and not covers(actor_permissions, permissions):
            raise PermissionEscalationError(
                "the role grants permissions you do not have",
                sorted(set(permissions) - set(actor_permissions)),
            )
        return permissions

    @staticmethod
    def _validate_role_fields(
        name: str | None, description: str | None
    ) -> tuple[str | None, str | None]:
        normalized_name = None
        if name is not None:
            normalized_name = " ".join(name.strip().split())
            if not 2 <= len(normalized_name) <= 80:
                raise FieldError(
                    "invalid_role", "role name must be between 2 and 80 characters", "name",
                    "too_short" if len(normalized_name) < 2 else "too_long",
                    params={"min_length": 2, "max_length": 80},
                )
            if normalized_name.lower() in BUILTIN_ROLES or normalized_name.lower().startswith(
                CUSTOM_ROLE_PREFIX
            ):
                raise FieldError(
                    "invalid_role", "role name is reserved", "name", "reserved",
                )
        normalized_description = None
        if description is not None:
            normalized_description = description.strip()
            if len(normalized_description) > 500:
                raise FieldError(
                    "invalid_role", "role description must be at most 500 characters",
                    "description", "too_long", params={"max_length": 500},
                )
        return normalized_name, normalized_description

    @staticmethod
    def validate_role_permissions(
        permissions: list[str] | set[str] | frozenset[str],
        actor_permissions: frozenset[str],
    ) -> list[str]:
        """Validate a custom role's permission set; returns it sorted.

        Never ``*``; only catalogue keys; every dependency present (write ⇒
        read, ...); and nothing the editor does not hold themselves.
        """
        requested = set(permissions)
        if not requested:
            raise FieldError(
                "invalid_role", "a role needs at least one permission", "permissions",
                "required",
            )
        if "*" in requested:
            raise FieldError(
                "invalid_role", "a custom role cannot hold every permission (*)",
                "permissions", "wildcard_forbidden",
            )
        unknown = sorted(requested - KNOWN_PERMISSIONS)
        if unknown:
            raise FieldError(
                "invalid_role", "unknown permission", status_code=422,
                fields=[
                    {"field": "permissions", "reason_code": "unknown_permission",
                     "params": {"permission": item}}
                    for item in unknown
                ],
            )
        missing = missing_dependencies(requested)
        if missing:
            raise FieldError(
                "permission_dependency_missing",
                "some permissions need others to work",
                fields=[
                    {"field": "permissions", "reason_code": "missing_dependency",
                     "params": {"permission": item, "requires": needs}}
                    for item, needs in missing.items()
                ],
            )
        if not covers(actor_permissions, requested):
            raise PermissionEscalationError(
                "you cannot grant permissions you do not have",
                sorted(requested - set(actor_permissions)),
            )
        return sorted(requested)

    def list_roles(self) -> list[dict[str, object]]:
        with self.db.session() as db:
            counts = dict(
                db.execute(select(User.role, func.count()).group_by(User.role)).all()
            )
            rows = db.scalars(select(CustomRole).order_by(CustomRole.name)).all()
            items = [
                {**_role_card(name, permissions), "user_count": int(counts.get(name, 0))}
                for name, permissions in ROLE_PERMISSIONS.items()
            ]
            for row in rows:
                card = _custom_role_card(row)
                card["user_count"] = int(counts.get(str(card["id"]), 0))
                items.append(card)
            return items

    def get_role(self, role: str) -> dict[str, object] | None:
        role = self._normalize_role_id(role)
        if role in ROLE_PERMISSIONS:
            return _role_card(role, ROLE_PERMISSIONS[role])
        with self.db.session() as db:
            row = self._custom_role_row(db, role)
            return _custom_role_card(row) if row is not None else None

    @staticmethod
    def _normalize_role_id(role: str) -> str:
        role = role.strip()
        if role in ROLE_PERMISSIONS or role.startswith(CUSTOM_ROLE_PREFIX):
            return role
        return f"{CUSTOM_ROLE_PREFIX}{role}"

    def create_custom_role(
        self,
        name: str,
        description: str | None,
        permissions: list[str],
        actor: Principal,
    ) -> dict[str, object]:
        normalized_name, normalized_description = self._validate_role_fields(
            name, description or ""
        )
        granted = self.validate_role_permissions(permissions, actor.permissions)
        now = int(time.time())
        try:
            with self.db.session() as db, db.begin():
                if db.scalar(
                    select(CustomRole.id).where(
                        func.lower(CustomRole.name) == str(normalized_name).lower()
                    )
                ) is not None:
                    raise FieldError(
                        "role_name_exists", "a role with this name already exists", "name",
                        "duplicate", status_code=409,
                    )
                row = CustomRole(
                    id=secrets.token_hex(6),
                    name=str(normalized_name),
                    description=normalized_description or "",
                    permissions=granted,
                    created_by_user_id=actor.user_id,
                    updated_by_user_id=actor.user_id,
                    created_at=now,
                    updated_at=now,
                )
                db.add(row)
                db.flush()
                self._audit_db(
                    db, actor.user_id, "role.create", "role",
                    f"{CUSTOM_ROLE_PREFIX}{row.id}", "success",
                )
                return _custom_role_card(row)
        except IntegrityError as exc:
            raise FieldError(
                "role_name_exists", "a role with this name already exists", "name",
                "duplicate", status_code=409,
            ) from exc

    def update_custom_role(
        self,
        role: str,
        actor: Principal,
        name: str | None = None,
        description: str | None = None,
        permissions: list[str] | None = None,
    ) -> dict[str, object] | None:
        role = self._normalize_role_id(role)
        if role in ROLE_PERMISSIONS:
            raise FieldError(
                "builtin_role_immutable", "built-in roles cannot be changed", "role",
                "builtin", status_code=409,
            )
        normalized_name, normalized_description = self._validate_role_fields(
            name, description
        )
        granted = (
            self.validate_role_permissions(permissions, actor.permissions)
            if permissions is not None
            else None
        )
        try:
            with self.db.session() as db, db.begin():
                row = self._custom_role_row(db, role)
                if row is None:
                    return None
                if not covers(actor.permissions, frozenset(row.permissions)):
                    # Editing a role you could not have created would let you
                    # keep (or rename) grants above your own level.
                    raise PermissionEscalationError(
                        "the role holds permissions you do not have",
                        sorted(set(row.permissions) - set(actor.permissions)),
                    )
                if normalized_name is not None and normalized_name != row.name:
                    clash = db.scalar(
                        select(CustomRole.id).where(
                            func.lower(CustomRole.name) == normalized_name.lower(),
                            CustomRole.id != row.id,
                        )
                    )
                    if clash is not None:
                        raise FieldError(
                            "role_name_exists", "a role with this name already exists",
                            "name", "duplicate", status_code=409,
                        )
                    row.name = normalized_name
                if normalized_description is not None:
                    row.description = normalized_description
                if granted is not None:
                    row.permissions = granted
                row.updated_at = int(time.time())
                row.updated_by_user_id = actor.user_id
                self._audit_db(db, actor.user_id, "role.update", "role", role, "success")
                db.flush()
                return _custom_role_card(row)
        except IntegrityError as exc:
            raise FieldError(
                "role_name_exists", "a role with this name already exists", "name",
                "duplicate", status_code=409,
            ) from exc

    def delete_custom_role(self, role: str, actor: Principal) -> bool:
        role = self._normalize_role_id(role)
        if role in ROLE_PERMISSIONS:
            raise FieldError(
                "builtin_role_immutable", "built-in roles cannot be deleted", "role",
                "builtin", status_code=409,
            )
        with self.db.session() as db, db.begin():
            row = self._custom_role_row(db, role)
            if row is None:
                return False
            users = db.scalars(select(User).where(User.role == role).order_by(User.username))
            assigned = [
                {"id": item.id, "username": item.username,
                 "display_name": item.display_name, "enabled": item.enabled}
                for item in users
            ]
            if assigned:
                raise RoleInUseError(role, assigned)
            db.delete(row)
            self._audit_db(db, actor.user_id, "role.delete", "role", role, "success")
            return True

    # ----- password state ------------------------------------------------------
    @staticmethod
    def _must_change(db: OrmSession, user_id: int) -> bool:
        state = db.get(UserPasswordState, user_id)
        return bool(state is not None and state.must_change_password)

    @staticmethod
    def _set_must_change(
        db: OrmSession, user_id: int, value: bool, reason: str | None = None
    ) -> None:
        now = int(time.time())
        state = db.get(UserPasswordState, user_id)
        if state is None:
            state = UserPasswordState(user_id=user_id)
            db.add(state)
        state.must_change_password = value
        if value:
            state.reason = reason
            state.set_at = now
        else:
            state.changed_at = now

    def has_users(self) -> bool:
        with self.db.session() as db:
            return db.scalar(select(User.id).limit(1)) is not None

    def setup_owner(
        self,
        display_name: str,
        email: str,
        password: str,
        source_ip: str | None,
        request_id: str | None,
    ) -> str:
        key = f"setup:{source_ip or '-'}"
        with self._lock:
            if self.has_users():
                raise ValueError("instance is already initialized")
            if self._rate_limited(key):
                raise ValueError("setup is rate limited")
            try:
                normalized_name = self.validate_display_name(display_name)
                normalized_email = self.validate_email(email)
                self.validate_password(password)
            except ValueError:
                # Count rejected attempts; previously nothing was ever recorded,
                # so the setup limiter could never trigger.
                self._record_attempt(key)
                raise
            local_part = re.sub(r"[^a-z0-9._-]+", "-", normalized_email.split("@", 1)[0])
            username = local_part.strip("-._")[:48]
            if len(username) < 3:
                username = "owner"
            now = int(time.time())
            # Hash before opening the transaction: PGlite has one connection.
            password_hash = self._hash_password(password)
            try:
                with self.db.session() as db, db.begin():
                    if db.scalar(select(User.id).limit(1)) is not None:
                        raise ValueError("instance is already initialized")
                    db.add(
                        SystemSetting(
                            key="instance_initialized",
                            value={"initialized": True},
                            updated_at=now,
                            updated_by_user_id=None,
                        )
                    )
                    owner = User(
                        username=username,
                        password_hash=password_hash,
                        role="owner",
                        enabled=True,
                        display_name=normalized_name,
                        email=normalized_email,
                        identity_provider="local",
                        mfa_enabled=False,
                        created_at=now,
                        updated_at=now,
                    )
                    db.add(owner)
                    db.flush()
                    self._audit_db(
                        db,
                        owner.id,
                        "auth.setup",
                        "instance",
                        "owner",
                        "success",
                        source_ip,
                        request_id,
                    )
            except IntegrityError as exc:
                raise ValueError("instance is already initialized") from exc
            self._attempts.pop(key, None)
            return normalized_email

    def public_registration_enabled(self) -> bool:
        with self.db.session() as db:
            setting = db.get(SystemSetting, "public_registration")
            return bool(setting and setting.value.get("enabled") is True)

    def set_public_registration(self, enabled: bool, actor_user_id: int) -> bool:
        now = int(time.time())
        with self.db.session() as db, db.begin():
            setting = db.get(SystemSetting, "public_registration")
            if setting is None:
                setting = SystemSetting(
                    key="public_registration",
                    value={"enabled": enabled, "default_role": "viewer"},
                    updated_at=now,
                    updated_by_user_id=actor_user_id,
                )
                db.add(setting)
            else:
                setting.value = {"enabled": enabled, "default_role": "viewer"}
                setting.updated_at = now
                setting.updated_by_user_id = actor_user_id
            self._audit_db(
                db,
                actor_user_id,
                "registration.policy.update",
                "system_setting",
                "public_registration",
                "success",
            )
        return enabled

    def register_public_user(
        self,
        display_name: str,
        email: str,
        password: str,
        source_ip: str | None,
        request_id: str | None,
    ) -> str:
        key = f"register:{source_ip or '-'}"
        with self._lock:
            if not self.public_registration_enabled():
                raise ValueError("public registration is disabled")
            if self._rate_limited(key):
                raise ValueError("registration is rate limited")
            normalized_name = self.validate_display_name(display_name)
            normalized_email = self.validate_email(email)
            local_part = re.sub(
                r"[^a-z0-9._-]+", "-", normalized_email.split("@", 1)[0]
            )
            username = local_part.strip("-._")[:42]
            if len(username) < 3:
                username = "user"
            username = f"{username}-{secrets.token_hex(3)}"
            try:
                user_id = self.create_user(
                    username,
                    password,
                    "viewer",
                    actor_user_id=None,
                    display_name=normalized_name,
                    email=normalized_email,
                )
            except ValueError:
                self._record_attempt(key)
                raise
            # Successful sign-ups count too, so one address cannot create
            # accounts without limit.
            self._record_attempt(key)
            self.record_audit(
                user_id,
                "auth.register",
                "user",
                str(user_id),
                "success",
                source_ip,
                request_id,
            )
            return normalized_email

    def create_user(
        self,
        username: str,
        password: str,
        role: str,
        actor_user_id: int | None,
        display_name: str | None = None,
        email: str | None = None,
        actor_permissions: frozenset[str] | None = None,
        must_change_password: bool = False,
    ) -> int:
        normalized = self.validate_username(username)
        self.validate_password(password)
        normalized_name = self.validate_display_name(display_name) if display_name else None
        normalized_email = self.validate_email(email) if email else None
        if role not in ROLE_PERMISSIONS and not role.startswith(CUSTOM_ROLE_PREFIX):
            raise FieldError("unknown_role", "unknown role", "role", "unknown_role")
        now = int(time.time())
        # Hash outside the transaction so Argon2 never holds the only PGlite connection.
        password_hash = self._hash_password(password)
        try:
            with self.db.session() as db, db.begin():
                self._check_assignable(db, role, actor_permissions)
                self._check_unique(db, normalized, normalized_email)
                user = User(
                    username=normalized,
                    password_hash=password_hash,
                    role=role,
                    enabled=True,
                    display_name=normalized_name,
                    email=normalized_email,
                    identity_provider="local",
                    mfa_enabled=False,
                    created_at=now,
                    updated_at=now,
                )
                db.add(user)
                db.flush()
                if must_change_password:
                    self._set_must_change(db, int(user.id), True, "created")
                self._audit_db(
                    db, actor_user_id, "user.create", "user", str(user.id), "success"
                )
                return int(user.id)
        except IntegrityError as exc:
            raise FieldError(
                "account_exists", "username or email already exists", "username", "duplicate",
                status_code=409,
            ) from exc

    @staticmethod
    def _check_unique(db: OrmSession, username: str, email: str | None) -> None:
        if db.scalar(select(User.id).where(User.username == username)) is not None:
            raise FieldError(
                "account_exists", "username or email already exists", "username", "duplicate",
                status_code=409,
            )
        if email is not None and db.scalar(
            select(User.id).where(User.email == email)
        ) is not None:
            raise FieldError(
                "account_exists", "username or email already exists", "email", "duplicate",
                status_code=409,
            )

    def _unique_username(self, db: OrmSession, display_name: str, email: str | None) -> str:
        """Suggest a username from the email (or an ASCII name), unique in the table."""
        source = email.split("@", 1)[0] if email else display_name
        base = re.sub(r"[^a-z0-9._-]+", "-", source.strip().lower()).strip("-._")[:40]
        if len(base) < 3:
            base = "user"
        candidate = base
        while db.scalar(select(User.id).where(User.username == candidate)) is not None:
            candidate = f"{base}-{secrets.token_hex(2)}"
        return candidate

    # ----- invites -------------------------------------------------------------
    def invite_user(
        self,
        display_name: str,
        email: str | None,
        role: str,
        actor: Principal,
        username: str | None = None,
        create_link: bool = True,
        source_ip: str | None = None,
        request_id: str | None = None,
    ) -> dict[str, object]:
        """Create an account with a one-time password and an optional invite link.

        The password and link token are returned exactly once; only hashes are
        stored. The user must choose a new password at first sign-in.
        """
        normalized_name = self.validate_display_name(display_name)
        normalized_email = self.validate_email(email) if email else None
        normalized_username = self.validate_username(username) if username else None
        if role not in ROLE_PERMISSIONS and not role.startswith(CUSTOM_ROLE_PREFIX):
            raise FieldError("unknown_role", "unknown role", "role", "unknown_role")
        one_time_password = generate_one_time_password(
            int(password_policy()["min_length"])  # type: ignore[call-overload]
        )
        password_hash = self._hash_password(one_time_password)
        token = secrets.token_urlsafe(32) if create_link else None
        now = int(time.time())
        try:
            with self.db.session() as db, db.begin():
                self._check_assignable(db, role, actor.permissions)
                final_username = normalized_username or self._unique_username(
                    db, normalized_name, normalized_email
                )
                self._check_unique(db, final_username, normalized_email)
                user = User(
                    username=final_username,
                    password_hash=password_hash,
                    role=role,
                    enabled=True,
                    display_name=normalized_name,
                    email=normalized_email,
                    identity_provider="local",
                    mfa_enabled=False,
                    created_at=now,
                    updated_at=now,
                )
                db.add(user)
                db.flush()
                self._set_must_change(db, int(user.id), True, "invite")
                invite_payload: dict[str, object] | None = None
                if token is not None:
                    invite = UserInvite(
                        user_id=user.id,
                        token_hash=self._digest(token),
                        created_by_user_id=actor.user_id,
                        created_at=now,
                        expires_at=now + INVITE_TTL_SECONDS,
                    )
                    db.add(invite)
                    db.flush()
                    invite_payload = {
                        "id": invite.id,
                        "token": token,
                        "path": f"/#/invite/{token}",
                        "expires_at": invite.expires_at,
                    }
                self._audit_db(
                    db, actor.user_id, "user.invite", "user", str(user.id), "success",
                    source_ip, request_id,
                )
                return {
                    "user": {
                        "id": int(user.id),
                        "username": user.username,
                        "display_name": user.display_name,
                        "email": user.email,
                        "role": user.role,
                        "must_change_password": True,
                    },
                    "one_time_password": one_time_password,
                    "must_change_password": True,
                    "invite": invite_payload,
                }
        except IntegrityError as exc:
            raise FieldError(
                "account_exists", "username or email already exists", "username", "duplicate",
                status_code=409,
            ) from exc

    def _invite_row(
        self, db: OrmSession, token: str, now: int
    ) -> tuple[UserInvite, User]:
        if not token or len(token) > 128:
            raise FieldError("invite_invalid", "invite link is not valid", "token",
                             "not_found", status_code=404)
        row = db.execute(
            select(UserInvite, User)
            .join(User, User.id == UserInvite.user_id)
            .where(UserInvite.token_hash == self._digest(token))
        ).first()
        if row is None:
            raise FieldError("invite_invalid", "invite link is not valid", "token",
                             "not_found", status_code=404)
        invite, user = row
        if invite.used_at is not None or invite.revoked_at is not None:
            raise FieldError("invite_used", "invite link was already used", "token",
                             "already_used", status_code=410)
        if invite.expires_at <= now:
            raise FieldError("invite_expired", "invite link has expired", "token",
                             "expired", status_code=410, params={"expired_at": invite.expires_at})
        if not user.enabled:
            raise FieldError("invite_invalid", "invite link is not valid", "token",
                             "account_disabled", status_code=404)
        return invite, user

    def get_invite(self, token: str, source_ip: str | None = None) -> dict[str, object]:
        key = f"invite:{source_ip or '-'}"
        if self._rate_limited(key):
            raise FieldError("rate_limited", "Too many attempts; try again later",
                             status_code=429)
        try:
            with self.db.session() as db:
                invite, user = self._invite_row(db, token, int(time.time()))
                return {
                    "display_name": user.display_name,
                    "email": user.email,
                    "username": user.username,
                    "expires_at": invite.expires_at,
                    "password_policy": password_policy(),
                }
        except FieldError as exc:
            if exc.status_code == 404:
                self._record_attempt(key)
            raise

    def accept_invite(
        self,
        token: str,
        password: str,
        source_ip: str | None,
        request_id: str | None,
    ) -> tuple[str, str, Principal]:
        key = f"invite:{source_ip or '-'}"
        if self._rate_limited(key):
            raise FieldError("rate_limited", "Too many attempts; try again later",
                             status_code=429)
        self.validate_password(password)
        password_hash = self._hash_password(password)
        now = int(time.time())
        try:
            with self.db.session() as db, db.begin():
                invite, user = self._invite_row(db, token, now)
                user.password_hash = password_hash
                user.updated_at = now
                invite.used_at = now
                self._set_must_change(db, int(user.id), False)
                self._revoke_invites(db, int(user.id), now)
                # Any session opened with the one-time password ends here.
                self._revoke_sessions(db, int(user.id), now)
                self._audit_db(
                    db, user.id, "auth.invite.accept", "user", str(user.id), "success",
                    source_ip, request_id,
                )
                return self._open_session(db, user, source_ip, request_id)
        except FieldError as exc:
            if exc.status_code == 404:
                self._record_attempt(key)
                self.record_audit(None, "auth.invite.accept", "invite", None, "failure",
                                  source_ip, request_id)
            raise

    @staticmethod
    def _revoke_invites(db: OrmSession, user_id: int, now: int) -> None:
        db.execute(
            update(UserInvite)
            .where(
                UserInvite.user_id == user_id,
                UserInvite.used_at.is_(None),
                UserInvite.revoked_at.is_(None),
            )
            .values(revoked_at=now)
        )

    @staticmethod
    def _revoke_sessions(
        db: OrmSession, user_id: int, now: int, keep_session_id: int | None = None
    ) -> None:
        query = update(LoginSession).where(
            LoginSession.user_id == user_id, LoginSession.revoked_at.is_(None)
        )
        if keep_session_id is not None:
            query = query.where(LoginSession.id != keep_session_id)
        db.execute(query.values(revoked_at=now))

    def change_password(
        self,
        principal: Principal,
        current_password: str,
        new_password: str,
        source_ip: str | None = None,
        request_id: str | None = None,
    ) -> Principal:
        key = f"password:{principal.user_id}"
        if self._rate_limited(key):
            raise FieldError("rate_limited", "Too many attempts; try again later",
                             status_code=429)
        with self.db.session() as db:
            user = db.get(User, principal.user_id)
            stored_hash = user.password_hash if user is not None and user.enabled else None
        valid = False
        if stored_hash is not None:
            try:
                valid = self._verify_password(stored_hash, current_password)
            except (VerifyMismatchError, InvalidHashError):
                valid = False
        if not valid:
            self._record_attempt(key)
            self.record_audit(principal.user_id, "auth.password.change", "user",
                              str(principal.user_id), "failure", source_ip, request_id)
            raise FieldError("invalid_current_password", "current password is not correct",
                             "current_password", "incorrect", status_code=422)
        self.validate_password(new_password, "new_password")
        if new_password == current_password:
            raise FieldError("weak_password", "the new password must differ from the current one",
                             "new_password", "same_as_current")
        password_hash = self._hash_password(new_password)
        now = int(time.time())
        with self.db.session() as db, db.begin():
            user = db.get(User, principal.user_id)
            if user is None or user.password_hash != stored_hash:
                raise FieldError("invalid_current_password", "the password changed meanwhile",
                                 "current_password", "incorrect", status_code=409)
            user.password_hash = password_hash
            user.updated_at = now
            self._set_must_change(db, int(user.id), False)
            self._revoke_invites(db, int(user.id), now)
            # Other browsers signed in with the old password are signed out.
            self._revoke_sessions(db, int(user.id), now, keep_session_id=principal.session_id)
            self._audit_db(db, user.id, "auth.password.change", "user", str(user.id),
                           "success", source_ip, request_id)
            permissions = self._role_permissions_db(db, user.role) or frozenset()
            self._clear_attempts(key)
            return self._principal(
                user, principal.session_id, principal.csrf_hash, principal.token_id,
                role_permissions=permissions, must_change=False,
            )

    def _record_attempt(self, key: str) -> None:
        # Always under the lock: _rate_limited iterates the dict while pruning.
        with self._lock:
            self._attempts.setdefault(key, []).append(time.monotonic())

    def _clear_attempts(self, key: str) -> None:
        with self._lock:
            self._attempts.pop(key, None)

    def _rate_limited(self, key: str) -> bool:
        with self._lock:
            now = time.monotonic()
            window = self.rate_limit_window_seconds
            if len(self._attempts) > 10000:
                # Bound memory: rotating usernames used to grow this forever.
                for stale in [
                    name
                    for name, items in self._attempts.items()
                    if not items or items[-1] <= now - window
                ]:
                    del self._attempts[stale]
            recent = [item for item in self._attempts.get(key, []) if item > now - window]
            if recent:
                self._attempts[key] = recent
            else:
                self._attempts.pop(key, None)
            return len(recent) >= self.rate_limit_attempts

    @staticmethod
    def _principal(
        user: User,
        session_id: int | None,
        csrf_hash: str,
        token_id: int | None = None,
        permissions: frozenset[str] | None = None,
        *,
        role_permissions: frozenset[str] | None = None,
        must_change: bool = False,
    ) -> Principal:
        if role_permissions is None:
            role_permissions = ROLE_PERMISSIONS.get(user.role, frozenset())
        return Principal(
            int(user.id),
            user.username,
            user.role,
            # "is not None": an empty token scope set must stay empty, never
            # widen to the whole role.
            permissions if permissions is not None else role_permissions,
            session_id, csrf_hash, token_id, user.display_name, user.email,
            must_change,
        )

    def _open_session(
        self,
        db: OrmSession,
        user: User,
        source_ip: str | None,
        request_id: str | None,
    ) -> tuple[str, str, Principal]:
        now = int(time.time())
        user.last_login_at = now
        user.updated_at = now
        token = secrets.token_urlsafe(32)
        csrf = self.csrf_for_session(token)
        login_session = LoginSession(
            user_id=user.id,
            token_hash=self._digest(token),
            csrf_hash=self._digest(csrf),
            created_at=now,
            expires_at=now + self.session_ttl_seconds,
        )
        db.add(login_session)
        db.flush()
        self._audit_db(
            db, user.id, "auth.login", "session", str(login_session.id), "success",
            source_ip, request_id,
        )
        return token, csrf, self._principal(
            user, int(login_session.id), login_session.csrf_hash,
            role_permissions=self._role_permissions_db(db, user.role) or frozenset(),
            must_change=self._must_change(db, int(user.id)),
        )

    def authenticate(
        self, username: str, password: str, source_ip: str | None, request_id: str | None
    ) -> tuple[str, str, Principal] | None:
        normalized = username.strip().lower()
        key = f"{source_ip or '-'}:{normalized}"
        if self._rate_limited(key):
            self.record_audit(
                None, "auth.login", "session", None, "rate_limited", source_ip, request_id
            )
            return None
        with self.db.session() as db:
            found = db.scalar(
                select(User).where(or_(User.username == normalized, User.email == normalized))
            )
            candidate = (
                (int(found.id), found.password_hash)
                if found is not None and found.enabled
                else None
            )
        # Argon2 runs with no database connection held: PGlite has exactly one,
        # and a login burst used to queue every other request behind hashing.
        valid = False
        if candidate is not None:
            try:
                valid = self._verify_password(candidate[1], password)
            except (VerifyMismatchError, InvalidHashError):
                valid = False
        else:
            try:
                self._verify_password(self._dummy_password_hash, password)
            except (VerifyMismatchError, InvalidHashError):
                pass
        if not valid or candidate is None:
            self._record_attempt(key)
            self.record_audit(None, "auth.login", "session", None, "failure", source_ip, request_id)
            return None
        with self.db.session() as db, db.begin():
            user = db.get(User, candidate[0])
            if (
                user is None
                or not user.enabled
                or user.password_hash != candidate[1]
                or self._role_permissions_db(db, user.role) is None
            ):
                # Disabled or changed while the password was being checked (or
                # the account's role no longer exists).
                self._record_attempt(key)
                self._audit_db(
                    db, None, "auth.login", "session", None, "failure", source_ip, request_id
                )
                return None
            self._clear_attempts(key)
            return self._open_session(db, user, source_ip, request_id)

    def principal_for_token(self, token: str | None) -> Principal | None:
        if not token:
            return None
        now = int(time.time())
        with self.db.session() as db:
            row = db.execute(
                select(LoginSession, User)
                .join(User, User.id == LoginSession.user_id)
                .where(
                    LoginSession.token_hash == self._digest(token),
                    LoginSession.revoked_at.is_(None), LoginSession.expires_at > now,
                )
            ).first()
            if row is None:
                return None
            login_session, user = row
            if not user.enabled:
                return None
            # Resolved per request, so a custom-role edit applies immediately.
            role_permissions = self._role_permissions_db(db, user.role)
            if role_permissions is None:
                return None
            return self._principal(
                user, int(login_session.id), login_session.csrf_hash,
                role_permissions=role_permissions,
                must_change=self._must_change(db, int(user.id)),
            )

    def verify_csrf(self, principal: Principal, token: str | None) -> bool:
        return bool(token) and secrets.compare_digest(principal.csrf_hash, self._digest(token))

    def prune(self, audit_retention_days: int) -> dict[str, int]:
        """Delete long-dead sessions and audit events past retention.

        Neither table was ever pruned, so the single PGlite database kept growing.
        """
        now = int(time.time())
        session_cutoff = now - self.session_prune_age_seconds
        with self.db.session() as db, db.begin():
            sessions = db.execute(
                delete(LoginSession).where(
                    or_(
                        LoginSession.expires_at < session_cutoff,
                        LoginSession.revoked_at < session_cutoff,
                    )
                )
            ).rowcount
            audits = 0
            if audit_retention_days > 0:
                audits = db.execute(
                    delete(AuditEvent).where(
                        AuditEvent.occurred_at < now - audit_retention_days * 86400
                    )
                ).rowcount
        return {"sessions": int(sessions or 0), "audit_events": int(audits or 0)}

    def issue_csrf(self, principal: Principal, session_token: str) -> str:
        if principal.session_id is None:
            raise ValueError("CSRF tokens are only available for browser sessions")
        csrf = self.csrf_for_session(session_token)
        if secrets.compare_digest(principal.csrf_hash, self._digest(csrf)):
            return csrf
        # Sessions created before the token was derived get it stored once.
        with self.db.session() as db, db.begin():
            db.execute(
                update(LoginSession)
                .where(LoginSession.id == principal.session_id, LoginSession.revoked_at.is_(None))
                .values(csrf_hash=self._digest(csrf))
            )
        return csrf

    def principal_for_api_token(self, token: str | None) -> Principal | None:
        if not token or not token.startswith("mrk_"):
            return None
        now = int(time.time())
        with self.db.session() as db, db.begin():
            row = db.execute(
                select(ApiToken, User)
                .join(User, User.id == ApiToken.user_id)
                .where(
                    ApiToken.token_hash == self._digest(token), ApiToken.revoked_at.is_(None),
                    ApiToken.expires_at > now,
                )
            ).first()
            if row is None:
                return None
            api_token, user = row
            if not user.enabled:
                return None
            role_permissions = self._role_permissions_db(db, user.role)
            if role_permissions is None:
                return None
            api_token.last_used_at = now
            requested = frozenset(api_token.scopes)
            # Intersect with the role as it is *now* (built-in or custom), so a
            # narrowed custom role narrows every token at once.
            permissions = requested if "*" in role_permissions else requested & role_permissions
            if not permissions:
                # Every scope was removed from the role since issue: the token
                # can do nothing, so it does not authenticate at all.
                return None
            return self._principal(
                user, None, "", int(api_token.id), permissions,
                role_permissions=role_permissions,
                must_change=self._must_change(db, int(user.id)),
            )

    def update_user(
        self,
        user_id: int,
        role: str | None,
        enabled: bool | None,
        actor_user_id: int,
        actor_permissions: frozenset[str] | None = None,
    ) -> None:
        if role is not None and role not in ROLE_PERMISSIONS and not role.startswith(
            CUSTOM_ROLE_PREFIX
        ):
            raise FieldError("unknown_role", "unknown role", "role", "unknown_role")
        now = int(time.time())
        with self.db.session() as db, db.begin():
            user = db.get(User, user_id)
            if user is None:
                raise FieldError("user_not_found", "user not found", "user_id", "not_found",
                                 status_code=404)
            if actor_permissions is not None:
                current = self._role_permissions_db(db, user.role) or frozenset()
                if not covers(actor_permissions, current):
                    # Nobody may change (or disable) a person who holds more than they do.
                    raise PermissionEscalationError(
                        "the user holds permissions you do not have",
                        sorted(set(current) - set(actor_permissions)),
                    )
            if role is not None:
                self._check_assignable(db, role, actor_permissions)
            next_role = role if role is not None else user.role
            next_enabled = enabled if enabled is not None else user.enabled
            if user.role == "owner" and (next_role != "owner" or not next_enabled):
                owners = db.scalar(
                    select(func.count()).select_from(User).where(
                        User.role == "owner", User.enabled.is_(True)
                    )
                )
                if int(owners or 0) <= 1:
                    raise FieldError(
                        "last_owner", "the last enabled owner cannot be changed",
                        "role" if next_role != "owner" else "enabled", "last_owner",
                        status_code=409,
                    )
            user.role = next_role
            user.enabled = next_enabled
            user.updated_at = now
            self._revoke_sessions(db, user_id, now)
            db.execute(
                update(ApiToken)
                .where(ApiToken.user_id == user_id, ApiToken.revoked_at.is_(None))
                .values(revoked_at=now)
            )
            if not next_enabled:
                self._revoke_invites(db, user_id, now)
            self._audit_db(db, actor_user_id, "user.update", "user", str(user_id), "success")

    def create_api_token(
        self, user_id: int, name: str, scopes: list[str], expires_in_seconds: int
    ) -> tuple[int, str]:
        normalized_name = name.strip()
        if not 3 <= len(normalized_name) <= 80:
            raise FieldError(
                "invalid_token", "token name must be between 3 and 80 characters", "name",
                "too_short" if len(normalized_name) < 3 else "too_long",
                params={"min_length": 3, "max_length": 80},
            )
        if not 900 <= expires_in_seconds <= 31536000:
            raise FieldError(
                "invalid_token", "token expiry must be between 15 minutes and 365 days",
                "expires_in_seconds", "out_of_range", params={"min": 900, "max": 31536000},
            )
        if not scopes:
            raise FieldError(
                "invalid_token", "at least one scope is required", "scopes", "required"
            )
        with self.db.session() as db, db.begin():
            user = db.get(User, user_id)
            role_permissions = (
                self._role_permissions_db(db, user.role) if user is not None else None
            )
            if user is None or role_permissions is None:
                raise FieldError("invalid_token", "user not found", "user_id", "not_found")
            unknown = sorted(set(scopes) - KNOWN_PERMISSIONS - {"*"})
            if unknown:
                raise FieldError(
                    "invalid_token", "unknown scope",
                    fields=[
                        {"field": "scopes", "reason_code": "unknown_permission",
                         "params": {"permission": item}}
                        for item in unknown
                    ],
                )
            if not covers(role_permissions, set(scopes)):
                raise FieldError(
                    "invalid_token", "token scope exceeds role permissions", "scopes",
                    "exceeds_role",
                    params={"permissions": sorted(set(scopes) - set(role_permissions))},
                )
            token = f"mrk_{secrets.token_urlsafe(32)}"
            now = int(time.time())
            api_token = ApiToken(
                user_id=user_id, name=normalized_name, token_hash=self._digest(token),
                scopes=sorted(set(scopes)), created_at=now,
                expires_at=now + expires_in_seconds,
            )
            db.add(api_token)
            db.flush()
            self._audit_db(
                db, user_id, "token.create", "api_token", str(api_token.id), "success"
            )
            return int(api_token.id), token

    def list_api_tokens(self, user_id: int) -> list[dict[str, object]]:
        with self.db.session() as db:
            rows = db.scalars(
                select(ApiToken).where(ApiToken.user_id == user_id).order_by(ApiToken.id.desc())
            ).all()
            return [
                {
                    "id": row.id, "name": row.name, "scopes": list(row.scopes),
                    "created_at": row.created_at, "expires_at": row.expires_at,
                    "last_used_at": row.last_used_at, "revoked_at": row.revoked_at,
                }
                for row in rows
            ]

    def revoke_api_token(self, token_id: int, user_id: int) -> bool:
        now = int(time.time())
        with self.db.session() as db, db.begin():
            result = db.execute(
                update(ApiToken)
                .where(
                    ApiToken.id == token_id, ApiToken.user_id == user_id,
                    ApiToken.revoked_at.is_(None),
                )
                .values(revoked_at=now)
            )
            changed = bool(result.rowcount)
            if changed:
                self._audit_db(
                    db, user_id, "token.revoke", "api_token", str(token_id), "success"
                )
            return changed

    def revoke_session(self, session_id: int, actor_user_id: int, request_id: str | None) -> None:
        now = int(time.time())
        with self.db.session() as db, db.begin():
            db.execute(
                update(LoginSession)
                .where(LoginSession.id == session_id)
                .values(revoked_at=now)
            )
            self._audit_db(
                db, actor_user_id, "auth.logout", "session", str(session_id), "success",
                request_id=request_id,
            )

    def rotate_session(self, principal: Principal) -> tuple[str, str]:
        token = secrets.token_urlsafe(32)
        csrf = self.csrf_for_session(token)
        now = int(time.time())
        with self.db.session() as db, db.begin():
            db.execute(
                update(LoginSession)
                .where(LoginSession.id == principal.session_id, LoginSession.revoked_at.is_(None))
                .values(
                    token_hash=self._digest(token), csrf_hash=self._digest(csrf),
                    expires_at=now + self.session_ttl_seconds,
                )
            )
            self._audit_db(
                db, principal.user_id, "auth.refresh", "session",
                str(principal.session_id), "success",
            )
        return token, csrf

    def list_users(self) -> list[dict[str, object]]:
        with self.db.session() as db:
            rows = db.scalars(select(User).order_by(User.username)).all()
            must_change = set(
                db.scalars(
                    select(UserPasswordState.user_id).where(
                        UserPasswordState.must_change_password.is_(True)
                    )
                )
            )
            now = int(time.time())
            pending = set(
                db.scalars(
                    select(UserInvite.user_id).where(
                        UserInvite.used_at.is_(None),
                        UserInvite.revoked_at.is_(None),
                        UserInvite.expires_at > now,
                    )
                )
            )
            return [
                {
                    "id": row.id, "username": row.username, "display_name": row.display_name,
                    "email": row.email, "role": row.role, "enabled": row.enabled,
                    "identity_provider": row.identity_provider, "mfa_enabled": row.mfa_enabled,
                    "created_at": row.created_at, "last_login_at": row.last_login_at,
                    "must_change_password": row.id in must_change,
                    "invite_pending": row.id in pending,
                }
                for row in rows
            ]

    def list_audit(self, limit: int = 100) -> list[dict[str, object]]:
        with self.db.session() as db:
            rows = db.scalars(
                select(AuditEvent).order_by(AuditEvent.id.desc()).limit(min(max(limit, 1), 500))
            ).all()
            return [
                {
                    "id": row.id, "actor_user_id": row.actor_user_id, "action": row.action,
                    "object_type": row.object_type, "object_id": row.object_id,
                    "result": row.result, "source_ip": row.source_ip,
                    "request_id": row.request_id, "occurred_at": row.occurred_at,
                }
                for row in rows
            ]

    def record_audit(
        self,
        actor_user_id: int | None,
        action: str,
        object_type: str,
        object_id: str | None,
        result: str = "success",
        source_ip: str | None = None,
        request_id: str | None = None,
    ) -> None:
        with self.db.session() as db, db.begin():
            self._audit_db(
                db, actor_user_id, action, object_type, object_id, result, source_ip, request_id
            )

    @staticmethod
    def _audit_db(
        db: OrmSession,
        actor_user_id: int | None,
        action: str,
        object_type: str,
        object_id: str | None,
        result: str,
        source_ip: str | None = None,
        request_id: str | None = None,
    ) -> None:
        # Clip to the column sizes: PostgreSQL rejects over-long values (SQLite
        # does not), which turned a long package name or backup filename into a
        # 500 *after* the audited change had already been made.
        db.add(
            AuditEvent(
                actor_user_id=actor_user_id,
                action=action[:120],
                object_type=object_type[:80],
                object_id=object_id[:255] if object_id is not None else None,
                result=result[:32],
                source_ip=source_ip[:64] if source_ip is not None else None,
                request_id=request_id[:128] if request_id is not None else None,
                occurred_at=int(time.time()),
            )
        )
