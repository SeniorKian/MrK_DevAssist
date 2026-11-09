# ruff: noqa: E501 - data table: one-line bilingual names/descriptions read better unwrapped
"""Built-in DNS domain templates (docs/41 §5). Read-only; users copy and edit a copy.

Placeholders: ``{domain}``, ``{domain_dashed}`` (``example-com``), ``{server_ipv4}``,
``{server_ipv6}``, ``{mail_host}``, ``{dkim_value}`` and each template's own variables.
A record whose placeholder resolves to an empty value is skipped (an AAAA record on
a server without IPv6, an optional DKIM key, ...), unless the variable is required.

Provider records follow the providers' current documentation (2026):

* Google Workspace: one MX ``smtp.google.com`` (priority 1), SPF ``include:_spf.google.com``,
  DKIM TXT at ``google._domainkey`` (value from the Admin console), site verification TXT.
* Microsoft 365: MX ``<domain-with-dashes>.mail.protection.outlook.com`` (priority 0; the
  admin centre shows the exact host, and new DNSSEC tenants get ``*.mx.microsoft``),
  SPF ``include:spf.protection.outlook.com``, CNAME ``autodiscover`` →
  ``autodiscover.outlook.com``, ``MS=ms…`` verification TXT, DKIM CNAMEs ``selector1``/
  ``selector2`` (targets from the Defender portal).
"""

from __future__ import annotations

from typing import Any

ZONE_DEFAULT: dict[str, Any] = {"ttl": 3600, "soa": None, "ns": []}
CAA_LE = {"flags": 0, "tag": "issue", "value": "letsencrypt.org"}


def _var(key: str, fa: str, en: str, default: str | None = None,
         required: bool = False) -> dict[str, Any]:
    return {"key": key, "label_fa": fa, "label_en": en, "default": default,
            "required": required}


def _web(names: tuple[str, ...]) -> list[dict[str, Any]]:
    records: list[dict[str, Any]] = []
    for name in names:
        records.append({"name": name, "type": "A", "data": {"address": "{server_ipv4}"}})
        records.append({"name": name, "type": "AAAA", "data": {"address": "{server_ipv6}"}})
    return records


def _dmarc(policy: str) -> dict[str, Any]:
    return {"name": "_dmarc", "type": "TXT", "data": {"text": f"v=DMARC1; p={policy}"}}


DMARC_POLICY = _var("dmarc_policy", "سیاست DMARC (none، quarantine یا reject)",
                    "DMARC policy (none, quarantine or reject)", "none", True)

BUILTIN_TEMPLATES: tuple[dict[str, Any], ...] = (
    {
        "id": "website",
        "name_fa": "وب‌سایت ساده",
        "name_en": "Simple website",
        "description_fa": "دامنه و www به همین سرور (A و در صورت داشتن IPv6، AAAA).",
        "description_en": "The domain and www point at this server (A, and AAAA when the server has IPv6).",
        "zone": ZONE_DEFAULT,
        "records": _web(("@", "www")),
        "variables": [],
    },
    {
        "id": "website_email",
        "name_fa": "وب‌سایت + ایمیل",
        "name_en": "Website + email",
        "description_fa": "وب‌سایت روی همین سرور، ایمیل روی سرور ایمیل شما (MX، SPF، DMARC، CAA و DKIM اختیاری).",
        "description_en": "Website on this server, mail on your mail server (MX, SPF, DMARC, CAA and optional DKIM).",
        "zone": ZONE_DEFAULT,
        "records": [
            *_web(("@", "www")),
            {"name": "@", "type": "MX", "data": {"preference": 10, "exchange": "{mail_host}"}},
            {"name": "@", "type": "TXT", "data": {"text": "v=spf1 mx ~all"}},
            _dmarc("{dmarc_policy}"),
            {"name": "@", "type": "CAA", "data": CAA_LE},
            {"name": "{dkim_selector}._domainkey", "type": "TXT", "data": {"text": "{dkim_value}"},
             "comment": "DKIM"},
        ],
        "variables": [
            _var("mail_host", "نام سرور ایمیل", "Mail server host name", "mail.{domain}", True),
            {**DMARC_POLICY, "default": "quarantine"},
            _var("dkim_selector", "انتخابگر DKIM", "DKIM selector", "default", True),
            _var("dkim_value", "مقدار DKIM (اختیاری، از سرور ایمیل)", "DKIM value (optional, from your mail server)"),
        ],
    },
    {
        "id": "google_workspace",
        "name_fa": "Google Workspace",
        "name_en": "Google Workspace",
        "description_fa": "ایمیل Gmail سازمانی: MX، SPF، DMARC و (اختیاری) DKIM و تأیید دامنه از کنسول مدیریت Google.",
        "description_en": "Gmail for your domain: MX, SPF, DMARC and (optional) DKIM and domain verification from the Google Admin console.",
        "zone": ZONE_DEFAULT,
        "records": [
            {"name": "@", "type": "MX", "data": {"preference": 1, "exchange": "smtp.google.com"}},
            {"name": "@", "type": "TXT", "data": {"text": "v=spf1 include:_spf.google.com ~all"}},
            _dmarc("{dmarc_policy}"),
            {"name": "google._domainkey", "type": "TXT", "data": {"text": "{dkim_value}"},
             "comment": "Google DKIM"},
            {"name": "@", "type": "TXT", "data": {"text": "{google_verification}"},
             "comment": "Google site verification"},
        ],
        "variables": [
            DMARC_POLICY,
            _var("dkim_value", "مقدار DKIM از کنسول Google (اختیاری)", "DKIM value from the Google Admin console (optional)"),
            _var("google_verification", "رکورد تأیید Google (google-site-verification=…، اختیاری)",
                 "Google verification record (google-site-verification=…, optional)"),
        ],
    },
    {
        "id": "microsoft_365",
        "name_fa": "Microsoft 365",
        "name_en": "Microsoft 365",
        "description_fa": "ایمیل Exchange Online: MX، SPF، autodiscover، DMARC و (اختیاری) تأیید دامنه و DKIM. نام MX را با مقدار مرکز مدیریت مقایسه کنید.",
        "description_en": "Exchange Online mail: MX, SPF, autodiscover, DMARC and (optional) verification and DKIM. Compare the MX host with the admin centre.",
        "zone": ZONE_DEFAULT,
        "records": [
            {"name": "@", "type": "MX", "data": {"preference": 0, "exchange": "{m365_mx}"}},
            {"name": "@", "type": "TXT", "data": {"text": "v=spf1 include:spf.protection.outlook.com -all"}},
            {"name": "autodiscover", "type": "CNAME", "data": {"target": "autodiscover.outlook.com"}},
            _dmarc("{dmarc_policy}"),
            {"name": "@", "type": "TXT", "data": {"text": "{ms_verification}"},
             "comment": "Microsoft 365 verification"},
            {"name": "selector1._domainkey", "type": "CNAME", "data": {"target": "{m365_dkim1}"},
             "comment": "Microsoft 365 DKIM"},
            {"name": "selector2._domainkey", "type": "CNAME", "data": {"target": "{m365_dkim2}"},
             "comment": "Microsoft 365 DKIM"},
        ],
        "variables": [
            _var("m365_mx", "نام سرور MX از مرکز مدیریت", "MX host from the admin centre",
                 "{domain_dashed}.mail.protection.outlook.com", True),
            DMARC_POLICY,
            _var("ms_verification", "رکورد تأیید (MS=ms…، اختیاری)", "Verification record (MS=ms…, optional)"),
            _var("m365_dkim1", "مقصد CNAME برای selector1 (اختیاری)", "CNAME target for selector1 (optional)"),
            _var("m365_dkim2", "مقصد CNAME برای selector2 (اختیاری)", "CNAME target for selector2 (optional)"),
        ],
    },
    {
        "id": "dokploy_apps",
        "name_fa": "برنامه‌های Dokploy",
        "name_en": "Dokploy apps",
        "description_fa": "دامنه و همه زیردامنه‌ها (wildcard *) به همین سرور تا هر برنامه Dokploy زیردامنه خودش را بگیرد.",
        "description_en": "The domain and every subdomain (wildcard *) point at this server so each Dokploy app gets its own subdomain.",
        "zone": ZONE_DEFAULT,
        "records": [*_web(("@", "*")), {"name": "@", "type": "CAA", "data": CAA_LE}],
        "variables": [],
    },
    {
        "id": "security_only",
        "name_fa": "فقط امنیت (بدون ایمیل)",
        "name_en": "Security only (no email)",
        "description_fa": "برای دامنه‌ای که ایمیل ندارد: کسی نتواند به نام آن ایمیل جعلی بفرستد و فقط Let's Encrypt گواهی بدهد.",
        "description_en": "For a domain without email: nobody can send forged mail in its name and only Let's Encrypt may issue certificates.",
        "zone": ZONE_DEFAULT,
        "records": [
            {"name": "@", "type": "TXT", "data": {"text": "v=spf1 -all"}},
            {"name": "_dmarc", "type": "TXT", "data": {"text": "v=DMARC1; p=reject; sp=reject; adkim=s; aspf=s"}},
            {"name": "@", "type": "MX", "data": {"preference": 0, "exchange": "."},
             "comment": "null MX (RFC 7505): no mail"},
            {"name": "@", "type": "CAA", "data": CAA_LE},
        ],
        "variables": [],
    },
)

BUILTIN_IDS = tuple(item["id"] for item in BUILTIN_TEMPLATES)
DEFAULT_TEMPLATE_ID = "website"
