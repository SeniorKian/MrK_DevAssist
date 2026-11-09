/**
 * Activity history in plain words (docs/33 §3.1, F6).
 *
 * Each backend audit `action` maps to a sentence template:
 *   {actor}  the person (display name or username; «سامانه» / "The system" when empty)
 *   {target} the object id or name
 * A part inside [square brackets] is dropped when a placeholder inside it is empty, so
 * «{actor} منبع دریافت[ «{target}»] را پاک کرد» reads well with or without a target.
 *
 * Use: humanizeAudit(language, event, { actorName }) → { sentence, result }
 */
import type { Language } from "../i18n";
import type { Bi } from "./text";

export const AUDIT_ACTIONS: Record<string, Bi> = {
  // Sign-in and people
  "auth.login": { fa: "{actor} وارد پنل شد", en: "{actor} signed in" },
  "auth.logout": { fa: "{actor} از پنل خارج شد", en: "{actor} signed out" },
  "auth.refresh": { fa: "ورود {actor} تمدید شد", en: "{actor}'s sign-in was extended" },
  "auth.register": { fa: "{actor} با ثبت‌نام عمومی حساب ساخت", en: "{actor} signed up" },
  "auth.setup": { fa: "{actor} حساب مالک را ساخت و پنل را راه انداخت", en: "{actor} created the owner account" },
  "auth.password.change": { fa: "{actor} رمز خود را عوض کرد", en: "{actor} changed their password" },
  "user.create": { fa: "{actor} حساب تازه‌ای[ برای «{target}»] ساخت", en: "{actor} created an account[ for “{target}”]" },
  "user.update": { fa: "{actor} حساب[ «{target}»] را تغییر داد", en: "{actor} changed the account[ “{target}”]" },
  "role.create": { fa: "{actor} نقش تازه[ «{target}»] را ساخت", en: "{actor} created the role[ “{target}”]" },
  "role.update": { fa: "{actor} نقش[ «{target}»] را تغییر داد", en: "{actor} changed the role[ “{target}”]" },
  "role.delete": { fa: "{actor} نقش[ «{target}»] را پاک کرد", en: "{actor} deleted the role[ “{target}”]" },
  "token.create": { fa: "{actor} یک کلید برنامه تازه ساخت", en: "{actor} created an app key" },
  "token.revoke": { fa: "{actor} یک کلید برنامه را باطل کرد", en: "{actor} revoked an app key" },
  "registration.policy.update": { fa: "{actor} تنظیم ثبت‌نام عمومی را تغییر داد", en: "{actor} changed public sign-up" },
  "audit.export": { fa: "{actor} فایل تاریخچه فعالیت را دانلود کرد", en: "{actor} downloaded the activity history" },
  "support.bundle.export": { fa: "{actor} بسته گزارش برای پشتیبانی را دانلود کرد", en: "{actor} downloaded a support report" },

  // Packages and sources
  "upstream.create": { fa: "{actor} منبع دریافت[ «{target}»] را اضافه کرد", en: "{actor} added the package source[ “{target}”]" },
  "upstream.update": { fa: "{actor} منبع دریافت[ «{target}»] را تغییر داد", en: "{actor} changed the package source[ “{target}”]" },
  "upstream.delete": { fa: "{actor} منبع دریافت[ «{target}»] را پاک کرد", en: "{actor} removed the package source[ “{target}”]" },
  "upstream.test": { fa: "{actor} اتصال منبع دریافت[ «{target}»] را امتحان کرد", en: "{actor} tested the package source[ “{target}”]" },
  "upstream.block": { fa: "{actor} منبع دریافت[ «{target}»] را موقتاً مسدود کرد", en: "{actor} temporarily blocked the package source[ “{target}”]" },
  "upstream.unblock": { fa: "{actor} منبع دریافت[ «{target}»] را از مسدودی درآورد", en: "{actor} unblocked the package source[ “{target}”]" },
  "upstream.credential.replace": { fa: "{actor} رمز منبع دریافت[ «{target}»] را عوض کرد", en: "{actor} replaced the password of[ “{target}”]" },
  "upstream.credential.remove": { fa: "{actor} رمز منبع دریافت[ «{target}»] را برداشت", en: "{actor} removed the password of[ “{target}”]" },
  "ecosystem.offline": { fa: "{actor}[ {target} را] به حالت بدون اینترنت برد", en: "{actor} switched[ {target}] to offline mode" },
  "ecosystem.online": { fa: "{actor} اینترنت[ {target}] را دوباره روشن کرد", en: "{actor} switched[ {target}] back online" },
  "package.policy": { fa: "{actor} وضعیت بسته[ «{target}»] را تغییر داد (نگه‌داشتن یا قرنطینه)", en: "{actor} changed keep/quarantine for[ “{target}”]" },
  "package.prefetch": { fa: "پیش‌دریافت بسته‌ها انجام شد", en: "Packages were downloaded ahead" },
  "package.prefetch.enqueue": { fa: "{actor} پیش‌دریافت بسته‌ها را شروع کرد", en: "{actor} started downloading packages ahead" },
  "package.purge": { fa: "بسته[ «{target}»] از ذخیره محلی پاک شد", en: "[“{target}” ]was removed from local copies" },
  "package.purge.enqueue": { fa: "{actor} پاک کردن بسته[ «{target}»] را شروع کرد", en: "{actor} started removing[ “{target}”]" },
  "package.quarantine.purge.enqueue": { fa: "{actor} پاک کردن نسخه‌های قرنطینه‌شده[ «{target}»] را شروع کرد", en: "{actor} started removing quarantined versions[ of “{target}”]" },
  "package.revalidate": { fa: "بسته[ «{target}»] دوباره از منبع دریافت شد", en: "[“{target}” ]was fetched again from its source" },
  "package.revalidate.enqueue": { fa: "{actor} دریافت دوباره بسته[ «{target}»] را شروع کرد", en: "{actor} started fetching[ “{target}”] again" },
  "package.trash.delete": { fa: "{actor} بسته[ «{target}»] را از سطل بازیافت برای همیشه پاک کرد", en: "{actor} deleted[ “{target}”] from the recycle bin forever" },
  "package.trash.restore": { fa: "{actor} بسته[ «{target}»] را از سطل بازیافت برگرداند", en: "{actor} restored[ “{target}”] from the recycle bin" },
  "package.trash.expire": { fa: "مهلت سطل بازیافت[ «{target}»] تمام شد و پاک شد", en: "[“{target}” ]expired from the recycle bin" },

  // Panel backups and storage health
  "backup.create": { fa: "پشتیبان پنل ساخته شد", en: "A panel backup was created" },
  "backup.create.enqueue": { fa: "{actor} ساخت پشتیبان پنل را شروع کرد", en: "{actor} started a panel backup" },
  "backup.download": { fa: "{actor} یک فایل پشتیبان پنل را دانلود کرد", en: "{actor} downloaded a panel backup file" },
  "lifecycle.cleanup": { fa: "فضای دیسک آزاد شد", en: "Disk space was freed" },
  "lifecycle.cleanup.enqueue": { fa: "{actor} آزاد کردن فضای دیسک را شروع کرد", en: "{actor} started freeing disk space" },
  "backup.prune": { fa: "پشتیبان‌های قدیمی پنل پاک شدند", en: "Old panel backups were removed" },
  "backup.validate": { fa: "{actor} سالم بودن یک فایل پشتیبان پنل را بررسی کرد", en: "{actor} checked a panel backup file" },
  "backup.restore.plan": { fa: "{actor} بازگردانی از پشتیبان را آماده کرد", en: "{actor} prepared a restore" },
  "backup.restore.apply": { fa: "پنل از پشتیبان بازگردانی شد", en: "The panel was restored from a backup" },
  "integrity.scan": { fa: "سالم بودن فایل‌های ذخیره‌شده بررسی شد", en: "Stored files were checked for damage" },
  "integrity.scan.enqueue": { fa: "{actor} بررسی سالم بودن فایل‌ها را شروع کرد", en: "{actor} started a file health check" },

  // Background jobs
  "task.cancel": { fa: "{actor} یک کار را لغو کرد", en: "{actor} cancelled a job" },
  "task.retry": { fa: "{actor} یک کار را دوباره شروع کرد", en: "{actor} retried a job" },

  // Server helper, Docker, logs, resource use
  "agent.config.update": { fa: "{actor} اتصال دستیار سرور را تنظیم کرد", en: "{actor} set up the server helper connection" },
  "agent.test": { fa: "{actor} اتصال دستیار سرور را امتحان کرد", en: "{actor} tested the server helper" },
  "agent.unpair": { fa: "{actor} دستیار سرور را جدا کرد", en: "{actor} disconnected the server helper" },
  "docker.container.start": { fa: "{actor} کانتینر[ «{target}»] را روشن کرد", en: "{actor} started the container[ “{target}”]" },
  "docker.container.stop": { fa: "{actor} کانتینر[ «{target}»] را خاموش کرد", en: "{actor} stopped the container[ “{target}”]" },
  "docker.container.restart": { fa: "{actor} کانتینر[ «{target}»] را دوباره راه‌اندازی کرد", en: "{actor} restarted the container[ “{target}”]" },
  "docker.image.pull": { fa: "{actor} نسخه برنامه[ «{target}»] را روی سرور دانلود کرد", en: "{actor} downloaded the image[ “{target}”]" },
  "docker.prune": { fa: "{actor} موارد بی‌استفاده Docker را پاک کرد", en: "{actor} cleaned up unused Docker items" },
  "logs.view": { fa: "{actor} لاگ کانتینر[ «{target}»] را دید", en: "{actor} viewed the logs of[ “{target}”]" },
  "monitoring.settings.update": { fa: "{actor} تنظیم هشدارهای مصرف منابع را تغییر داد", en: "{actor} changed resource alert settings" },

  // Dokploy
  "dokploy.config.update": { fa: "{actor} اتصال Dokploy را تنظیم کرد", en: "{actor} set up the Dokploy connection" },
  "dokploy.test": { fa: "{actor} اتصال Dokploy را امتحان کرد", en: "{actor} tested the Dokploy connection" },
  "dokploy.disconnect": { fa: "{actor} اتصال Dokploy را قطع کرد", en: "{actor} disconnected Dokploy" },
  "dokploy.deployment.log.view": { fa: "{actor} گزارش یک انتشار را در Dokploy دید", en: "{actor} viewed a deployment log" },
  "dokploy.service.deploy": { fa: "{actor} برنامه[ «{target}»] را منتشر کرد", en: "{actor} deployed[ “{target}”]" },
  "dokploy.service.redeploy": { fa: "{actor} برنامه[ «{target}»] را دوباره منتشر کرد", en: "{actor} redeployed[ “{target}”]" },
  "dokploy.service.start": { fa: "{actor} برنامه[ «{target}»] را روشن کرد", en: "{actor} started[ “{target}”]" },
  "dokploy.service.stop": { fa: "{actor} برنامه[ «{target}»] را متوقف کرد", en: "{actor} stopped[ “{target}”]" },

  // Image updates
  "updates.check": { fa: "{actor} بررسی نسخه‌های تازه را اجرا کرد", en: "{actor} checked for new versions" },
  "updates.settings.update": { fa: "{actor} تنظیم بررسی نسخه‌ها را تغییر داد", en: "{actor} changed update-check settings" },

  // Services and domains (docs/35)
  "services.action": { fa: "{actor} سرویس[ «{target}»] را روشن، خاموش یا دوباره راه‌اندازی کرد", en: "{actor} started, stopped or restarted the service[ “{target}”]" },
  "services.start": { fa: "{actor} سرویس[ «{target}»] را روشن کرد", en: "{actor} started the service[ “{target}”]" },
  "services.stop": { fa: "{actor} سرویس[ «{target}»] را خاموش کرد", en: "{actor} stopped the service[ “{target}”]" },
  "services.restart": { fa: "{actor} سرویس[ «{target}»] را دوباره راه‌اندازی کرد", en: "{actor} restarted the service[ “{target}”]" },
  "service.action": { fa: "{actor} سرویس[ «{target}»] را روشن، خاموش یا دوباره راه‌اندازی کرد", en: "{actor} started, stopped or restarted the service[ “{target}”]" },
  "domain.create": { fa: "{actor} دامنه[ «{target}»] را اضافه کرد", en: "{actor} added the domain[ “{target}”]" },
  "domain.update": { fa: "{actor} دامنه[ «{target}»] را تغییر داد", en: "{actor} changed the domain[ “{target}”]" },
  "domain.delete": { fa: "{actor} دامنه[ «{target}»] را برداشت", en: "{actor} removed the domain[ “{target}”]" },
  "domain.verify": { fa: "{actor} سلامت دامنه[ «{target}»] را بررسی کرد", en: "{actor} checked the domain[ “{target}”]" },
  "domain.check": { fa: "سلامت دامنه[ «{target}»] خودکار بررسی شد", en: "The domain[ “{target}”] was checked automatically" },
  "service.crashed": { fa: "سرویس[ «{target}»] از کار افتاد", en: "The service[ “{target}”] crashed" },
  "service.recovered": { fa: "سرویس[ «{target}»] دوباره کار می‌کند", en: "The service[ “{target}”] works again" },
  "domain.unhealthy": { fa: "دامنه[ «{target}»] مشکل پیدا کرد", en: "The domain[ “{target}”] developed a problem" },
  "domain.cert_expiring": { fa: "گواهی HTTPS دامنه[ «{target}»] به‌زودی تمام می‌شود", en: "The HTTPS certificate of[ “{target}”] expires soon" },
  "domains.routing.update": { fa: "{actor} روش اتصال دامنه‌ها را تغییر داد", en: "{actor} changed how domains are routed" },

  // Pishkar DNS (docs/37 §4)
  "dns.settings.update": { fa: "{actor} تنظیمات DNS را تغییر داد", en: "{actor} changed the DNS settings" },
  "dns.zone.create": { fa: "{actor} دامنه[ «{target}»] را به DNS اضافه کرد", en: "{actor} added the domain[ “{target}”] to DNS" },
  "dns.zone.update": { fa: "{actor} دامنه[ «{target}»] را در DNS تغییر داد", en: "{actor} changed the domain[ “{target}”] in DNS" },
  "dns.zone.delete": { fa: "{actor} دامنه[ «{target}»] را از DNS پاک کرد", en: "{actor} removed the domain[ “{target}”] from DNS" },
  "dns.zone.import": { fa: "{actor} رکوردهای دامنه[ «{target}»] را از فایل وارد کرد", en: "{actor} imported records into[ “{target}”]" },
  "dns.zone.rollback": { fa: "{actor} دامنه[ «{target}»] را به نسخه قبلی برگرداند", en: "{actor} rolled back the domain[ “{target}”]" },
  "dns.record.create": { fa: "{actor} رکورد[ «{target}»] را اضافه کرد", en: "{actor} added the DNS record[ “{target}”]" },
  "dns.record.update": { fa: "{actor} رکورد[ «{target}»] را تغییر داد", en: "{actor} changed the DNS record[ “{target}”]" },
  "dns.record.delete": { fa: "{actor} رکورد[ «{target}»] را پاک کرد", en: "{actor} removed the DNS record[ “{target}”]" },
  "dns.override.create": { fa: "{actor} نام[ «{target}»] را در DNS اضافه کرد", en: "{actor} added the DNS name[ “{target}”]" },
  "dns.override.update": { fa: "{actor} نام[ «{target}»] را در DNS تغییر داد", en: "{actor} changed the DNS name[ “{target}”]" },
  "dns.override.delete": { fa: "{actor} نام[ «{target}»] را از DNS برداشت", en: "{actor} removed the DNS name[ “{target}”]" },
  "dns.override.sync": { fa: "نام‌های «سرویس‌های من» در DNS به‌روز شد", en: "The My services names were synced into DNS" },
  "dns.integration.update": { fa: "{actor} اتصال DNS به «سرویس‌های من» را تغییر داد", en: "{actor} changed how DNS works with My services" },
  "dns.cache.flush": { fa: "{actor} جواب‌های ذخیره‌شده DNS[ برای «{target}»] را پاک کرد", en: "{actor} cleared stored DNS answers[ for “{target}”]" },
  "dns.logs.export": { fa: "{actor} لاگ پرسش‌های DNS را دانلود کرد", en: "{actor} downloaded the DNS question log" },
  "dns.logs.delete": { fa: "{actor} لاگ پرسش‌های DNS[ «{target}»] را پاک کرد", en: "{actor} deleted the DNS question log[ for “{target}”]" },
  "dns.mitigation.create": { fa: "{actor} در DNS برای[ «{target}»] محدودیت گذاشت", en: "{actor} set a DNS limit[ on “{target}”]" },
  "dns.dnssec.refresh": { fa: "{actor} کلید اعتماد ریشه DNS را به‌روز کرد", en: "{actor} updated DNS's root trust key" },
  "dns.tls.upload": { fa: "{actor} گواهی اتصال رمزدار DNS را بارگذاری کرد", en: "{actor} uploaded DNS's encrypted connection certificate" },
  "dns.tls.self_signed": { fa: "{actor} برای اتصال رمزدار DNS گواهی خودامضا ساخت", en: "{actor} made a self-signed certificate for encrypted DNS" },
  "dns.tls.delete": { fa: "{actor} گواهی اتصال رمزدار DNS را حذف کرد", en: "{actor} removed DNS's encrypted connection certificate" },
  "dns.doh_token.create": { fa: "{actor} کلید دسترسی DNS رمزدار[ «{target}»] را ساخت", en: "{actor} made the encrypted DNS token[ “{target}”]" },
  "dns.doh_token.update": { fa: "{actor} کلید دسترسی DNS رمزدار[ «{target}»] را تغییر داد", en: "{actor} changed the encrypted DNS token[ “{target}”]" },
  "dns.doh_token.delete": { fa: "{actor} کلید دسترسی DNS رمزدار[ «{target}»] را باطل کرد", en: "{actor} cancelled the encrypted DNS token[ “{target}”]" },
  "dns.mitigation.delete": { fa: "{actor} محدودیت DNS[ «{target}»] را برداشت", en: "{actor} removed the DNS limit[ on “{target}”]" },
  // docs/41: templates, transfers, signing, blocking, backup
  "dns.template.create": { fa: "{actor} قالب دامنه[ «{target}»] را ساخت", en: "{actor} made the domain template[ “{target}”]" },
  "dns.template.update": { fa: "{actor} قالب دامنه[ «{target}»] را تغییر داد", en: "{actor} changed the domain template[ “{target}”]" },
  "dns.template.delete": { fa: "{actor} قالب دامنه[ «{target}»] را پاک کرد", en: "{actor} deleted the domain template[ “{target}”]" },
  "dns.template.default": { fa: "{actor} قالب پیش‌فرض دامنه‌ها را[ «{target}»] کرد", en: "{actor} set the default domain template[ to “{target}”]" },
  "dns.zone.apply_template": { fa: "{actor} رکوردهای یک قالب را به دامنه[ «{target}»] اضافه کرد", en: "{actor} added a template's records to[ “{target}”]" },
  "dns.zone.refresh": { fa: "{actor} نسخه تازه دامنه[ «{target}»] را از سرور اصلی خواست", en: "{actor} asked for a fresh copy of[ “{target}”]" },
  "dns.zone.dnssec_rollover": { fa: "{actor} کلید امضای دامنه[ «{target}»] را عوض کرد", en: "{actor} changed the signing key of[ “{target}”]" },
  "dns.tsig.create": { fa: "{actor} کلید امضای انتقال[ «{target}»] را ساخت", en: "{actor} made the transfer signing key[ “{target}”]" },
  "dns.tsig.delete": { fa: "{actor} کلید امضای انتقال[ «{target}»] را پاک کرد", en: "{actor} deleted the transfer signing key[ “{target}”]" },
  "dns.filtering.refresh": { fa: "{actor} فهرست‌های مسدودسازی DNS را به‌روز کرد", en: "{actor} updated the DNS block lists" },
  "dns.backup.download": { fa: "{actor} از DNS پشتیبان دانلود کرد", en: "{actor} downloaded a DNS backup" },
  "dns.restore": { fa: "{actor} DNS را از فایل پشتیبان بازگردانی کرد", en: "{actor} restored DNS from a backup file" },

  // File space
  "s3.settings.update": { fa: "{actor} تنظیم فضای فایل را تغییر داد", en: "{actor} changed file space settings" },
  "s3.bucket.create": { fa: "{actor} پوشه اصلی[ «{target}»] را ساخت", en: "{actor} created the bucket[ “{target}”]" },
  "s3.bucket.update": { fa: "{actor} پوشه اصلی[ «{target}»] را تغییر داد", en: "{actor} changed the bucket[ “{target}”]" },
  "s3.bucket.delete": { fa: "{actor} پوشه اصلی[ «{target}»] را پاک کرد", en: "{actor} deleted the bucket[ “{target}”]" },
  "s3.folder.create": { fa: "{actor} پوشه[ «{target}»] را ساخت", en: "{actor} created the folder[ “{target}”]" },
  "s3.identity.create": { fa: "{actor} کاربر فضای فایل[ «{target}»] را ساخت", en: "{actor} created the file-space user[ “{target}”]" },
  "s3.identity.update": { fa: "{actor} کاربر فضای فایل[ «{target}»] را تغییر داد", en: "{actor} changed the file-space user[ “{target}”]" },
  "s3.identity.delete": { fa: "{actor} کاربر فضای فایل[ «{target}»] را پاک کرد", en: "{actor} deleted the file-space user[ “{target}”]" },
  "s3.key.create": { fa: "{actor} یک کلید دسترسی تازه ساخت", en: "{actor} created an access key" },
  "s3.key.update": { fa: "{actor} یک کلید دسترسی را تغییر داد", en: "{actor} changed an access key" },
  "s3.key.delete": { fa: "{actor} یک کلید دسترسی را پاک کرد", en: "{actor} deleted an access key" },
  "s3.object.upload": { fa: "{actor} فایل[ «{target}»] را آپلود کرد", en: "{actor} uploaded[ “{target}”]" },
  "s3.object.delete": { fa: "{actor} فایل[ «{target}»] را پاک کرد", en: "{actor} deleted[ “{target}”]" },
  "s3.object.move": { fa: "{actor} فایل[ «{target}»] را جابه‌جا کرد", en: "{actor} moved[ “{target}”]" },
  "s3.object.share": { fa: "{actor} برای فایل[ «{target}»] لینک اشتراک ساخت", en: "{actor} created a share link for[ “{target}”]" },

  // App backups
  "server_backup.settings.update": { fa: "{actor} تنظیم پشتیبان برنامه‌ها را تغییر داد", en: "{actor} changed app backup settings" },
  "server_backup.job.create": { fa: "{actor} برنامه پشتیبان[ «{target}»] را ساخت", en: "{actor} created the backup schedule[ “{target}”]" },
  "server_backup.job.update": { fa: "{actor} برنامه پشتیبان[ «{target}»] را تغییر داد", en: "{actor} changed the backup schedule[ “{target}”]" },
  "server_backup.job.delete": { fa: "{actor} برنامه پشتیبان[ «{target}»] را پاک کرد", en: "{actor} deleted the backup schedule[ “{target}”]" },
  "server_backup.job.run": { fa: "{actor} پشتیبان‌گیری[ «{target}»] را همین حالا اجرا کرد", en: "{actor} ran the backup[ “{target}”] now" },
  "server_backup.run.download": { fa: "{actor} یک فایل پشتیبان را دانلود کرد", en: "{actor} downloaded a backup file" },
  "server_backup.key.export": { fa: "{actor} کلید رمزگشایی پشتیبان‌ها را گرفت", en: "{actor} exported the backup key" },
  "server_backup.destination.create": { fa: "{actor} مقصد پشتیبان[ «{target}»] را اضافه کرد", en: "{actor} added the backup destination[ “{target}”]" },
  "server_backup.destination.update": { fa: "{actor} مقصد پشتیبان[ «{target}»] را تغییر داد", en: "{actor} changed the backup destination[ “{target}”]" },
  "server_backup.destination.delete": { fa: "{actor} مقصد پشتیبان[ «{target}»] را پاک کرد", en: "{actor} removed the backup destination[ “{target}”]" },
  "server_backup.destination.test": { fa: "{actor} مقصد پشتیبان[ «{target}»] را امتحان کرد", en: "{actor} tested the backup destination[ “{target}”]" },

  // Internet: proxies and DNS
  "settings.proxy.create": { fa: "{actor} پروکسی[ «{target}»] را اضافه کرد", en: "{actor} added the proxy[ “{target}”]" },
  "settings.proxy.update": { fa: "{actor} پروکسی[ «{target}»] را تغییر داد", en: "{actor} changed the proxy[ “{target}”]" },
  "settings.proxy.delete": { fa: "{actor} پروکسی[ «{target}»] را پاک کرد", en: "{actor} removed the proxy[ “{target}”]" },
  "settings.proxy.default": { fa: "{actor} پروکسی پیش‌فرض را عوض کرد", en: "{actor} changed the default proxy" },
  "settings.proxy.test": { fa: "{actor} پروکسی[ «{target}»] را امتحان کرد", en: "{actor} tested the proxy[ “{target}”]" },
  "settings.outbound_service.update": { fa: "{actor} پروکسی یک سرویس را تغییر داد", en: "{actor} changed which proxy a service uses" },
  "settings.network.dns": { fa: "{actor} تنظیم DNS را تغییر داد", en: "{actor} changed the DNS setting" },
  "settings.network.upstream_policy": { fa: "{actor} اجازه منابع داخل شبکه را تغییر داد", en: "{actor} changed the internal-source policy" },

  // Alerts
  "notification.settings.update": { fa: "{actor} تنظیم اعلان‌ها را تغییر داد", en: "{actor} changed alert settings" },
  "notification.channel.create": { fa: "{actor} کانال اعلان[ «{target}»] را اضافه کرد", en: "{actor} added the alert channel[ “{target}”]" },
  "notification.channel.update": { fa: "{actor} کانال اعلان[ «{target}»] را تغییر داد", en: "{actor} changed the alert channel[ “{target}”]" },
  "notification.channel.delete": { fa: "{actor} کانال اعلان[ «{target}»] را پاک کرد", en: "{actor} removed the alert channel[ “{target}”]" },
  "notification.channel.test": { fa: "{actor} به کانال[ «{target}»] پیام آزمایشی فرستاد", en: "{actor} sent a test message to[ “{target}”]" },
  "notification.test": { fa: "{actor} پیام آزمایشی فرستاد", en: "{actor} sent a test message" },
  "notification.test_event": { fa: "{actor} یک رویداد آزمایشی ساخت", en: "{actor} raised a test event" },
  "notification.rule.create": { fa: "{actor} قاعده اعلان تازه‌ای ساخت", en: "{actor} created an alert rule" },
  "notification.rule.update": { fa: "{actor} یک قاعده اعلان را تغییر داد", en: "{actor} changed an alert rule" },
  "notification.rule.delete": { fa: "{actor} یک قاعده اعلان را پاک کرد", en: "{actor} removed an alert rule" },

  // Firewall
  "firewall.mode.change": { fa: "{actor} حالت دیوار آتش را عوض کرد", en: "{actor} changed the firewall mode" },
  "firewall.settings.update": { fa: "{actor} تنظیم دیوار آتش را تغییر داد", en: "{actor} changed firewall settings" },
  "firewall.config.update": { fa: "{actor} اتصال نگهبان دیوار آتش را تنظیم کرد", en: "{actor} set up the firewall helper" },
  "firewall.test": { fa: "{actor} اتصال نگهبان دیوار آتش را امتحان کرد", en: "{actor} tested the firewall helper" },
  "firewall.unpair": { fa: "{actor} نگهبان دیوار آتش را جدا کرد", en: "{actor} disconnected the firewall helper" },
  "firewall.block.create": { fa: "{actor} نشانی[ {target}] را مسدود کرد", en: "{actor} blocked[ {target}]" },
  "firewall.block.delete": { fa: "{actor} نشانی[ {target}] را از مسدودی درآورد", en: "{actor} unblocked[ {target}]" },
  "firewall.blocks.clear": { fa: "{actor} همه مسدودی‌ها را برداشت", en: "{actor} cleared all blocks" },
  "firewall.rule.create": { fa: "{actor} قاعده دیوار آتش[ «{target}»] را ساخت", en: "{actor} created the firewall rule[ “{target}”]" },
  "firewall.rule.update": { fa: "{actor} قاعده دیوار آتش[ «{target}»] را تغییر داد", en: "{actor} changed the firewall rule[ “{target}”]" },
  "firewall.rule.delete": { fa: "{actor} قاعده دیوار آتش[ «{target}»] را پاک کرد", en: "{actor} deleted the firewall rule[ “{target}”]" },

  // Security scan
  "vuln.scan": { fa: "{actor} بررسی امنیتی برنامه‌ها را اجرا کرد", en: "{actor} ran a security check" },
  "vuln.settings.update": { fa: "{actor} تنظیم بررسی امنیتی را تغییر داد", en: "{actor} changed security check settings" },
  "vuln.ignore.create": { fa: "{actor} یک مشکل امنیتی را نادیده گرفت", en: "{actor} ignored a security issue" },
  "vuln.ignore.delete": { fa: "{actor} نادیده‌گرفتن یک مشکل امنیتی را برداشت", en: "{actor} stopped ignoring a security issue" },

  // Databases
  "dbadmin.settings.update": { fa: "{actor} تنظیم بخش پایگاه‌های داده را تغییر داد", en: "{actor} changed database settings" },
  "dbadmin.connection.create": { fa: "{actor} اتصال پایگاه داده[ «{target}»] را اضافه کرد", en: "{actor} added the database connection[ “{target}”]" },
  "dbadmin.connection.update": { fa: "{actor} اتصال پایگاه داده[ «{target}»] را تغییر داد", en: "{actor} changed the database connection[ “{target}”]" },
  "dbadmin.connection.delete": { fa: "{actor} اتصال پایگاه داده[ «{target}»] را پاک کرد", en: "{actor} removed the database connection[ “{target}”]" },
  "dbadmin.connection.test": { fa: "{actor} اتصال پایگاه داده[ «{target}»] را امتحان کرد", en: "{actor} tested the database connection[ “{target}”]" },
  "dbadmin.schema.read": { fa: "{actor} ساختار پایگاه داده[ «{target}»] را دید", en: "{actor} viewed the structure of[ “{target}”]" },
  "dbadmin.table.read": { fa: "{actor} داده‌های یک جدول را دید", en: "{actor} viewed a table's data" },
  "dbadmin.query.read": { fa: "{actor} یک درخواست خواندنی روی پایگاه داده اجرا کرد", en: "{actor} ran a read query" },
  "dbadmin.query.dry_run": { fa: "{actor} یک درخواست تغییر را بدون اجرا امتحان کرد", en: "{actor} dry-ran a write query" },
  "dbadmin.query.write": { fa: "{actor} داده‌های پایگاه داده را تغییر داد", en: "{actor} changed database data" },
  "dbadmin.export": { fa: "{actor} از پایگاه داده فایل خروجی گرفت", en: "{actor} exported database data" }
};

/** Task kinds: used for `task.<kind>` audit rows and job lists. */
export const TASK_KIND_WORDS: Record<string, Bi> = {
  "package.prefetch": { fa: "پیش‌دریافت بسته‌ها", en: "Download packages ahead" },
  "package.purge": { fa: "پاک کردن بسته از ذخیره محلی", en: "Remove a package from local copies" },
  "package.quarantine.purge": { fa: "پاک کردن نسخه‌های قرنطینه‌شده", en: "Remove quarantined versions" },
  "package.revalidate": { fa: "دریافت دوباره بسته از منبع", en: "Fetch a package again" },
  "integrity.scan": { fa: "بررسی سالم بودن فایل‌ها", en: "File health check" },
  "backup.create": { fa: "ساخت پشتیبان پنل", en: "Panel backup" },
  "lifecycle.cleanup": { fa: "آزاد کردن فضای دیسک", en: "Free up disk space" }
};

/** Audit result → pill. */
export const AUDIT_RESULTS: Record<string, { tone: "ok" | "error" | "warn" | "info"; label: Bi }> = {
  success: { tone: "ok", label: { fa: "انجام شد", en: "Done" } },
  succeeded: { tone: "ok", label: { fa: "انجام شد", en: "Done" } },
  failure: { tone: "error", label: { fa: "انجام نشد", en: "Didn't work" } },
  failed: { tone: "error", label: { fa: "انجام نشد", en: "Didn't work" } },
  error: { tone: "error", label: { fa: "انجام نشد", en: "Didn't work" } },
  denied: { tone: "warn", label: { fa: "اجازه داده نشد", en: "Not allowed" } },
  rejected: { tone: "warn", label: { fa: "پذیرفته نشد", en: "Refused" } },
  started: { tone: "info", label: { fa: "شروع شد", en: "Started" } },
  queued: { tone: "info", label: { fa: "در نوبت", en: "Queued" } },
  cancelled: { tone: "info", label: { fa: "لغو شد", en: "Cancelled" } }
};

const SYSTEM_ACTOR: Bi = { fa: "سامانه", en: "The system" };

export type AuditEventLike = {
  action: string;
  result?: string | null;
  object_type?: string | null;
  object_id?: string | number | null;
};

/** Fill a template, dropping `[…]` parts whose placeholders are empty. */
function render(template: string, params: Record<string, string>): string {
  const withOptional = template.replace(/\[([^\]]*)\]/g, (_m, part: string) => {
    const keys = [...part.matchAll(/\{(\w+)\}/g)].map((match) => match[1]);
    return keys.every((key) => params[key]) ? part : "";
  });
  return withOptional.replace(/\{(\w+)\}/g, (_m, key: string) => params[key] ?? "").replace(/\s{2,}/g, " ").trim();
}

function capitalize(text: string) {
  return text ? text.charAt(0).toUpperCase() + text.slice(1) : text;
}

/** A plain sentence for one audit row, plus its result pill. Unknown actions get a gentle generic sentence. */
export function humanizeAudit(
  language: Language,
  event: AuditEventLike,
  options: { actorName?: string | null; targetName?: string | null } = {}
) {
  const actor = options.actorName?.trim() || SYSTEM_ACTOR[language];
  const target = options.targetName?.trim() || (event.object_id !== null && event.object_id !== undefined ? String(event.object_id) : "");
  let template = AUDIT_ACTIONS[event.action]?.[language];
  if (!template && event.action.startsWith("task.")) {
    const kind = TASK_KIND_WORDS[event.action.slice(5)];
    if (kind) template = language === "fa" ? `کار «${kind.fa}» اجرا شد` : `Job “${kind.en}” ran`;
  }
  if (!template) template = language === "fa" ? "{actor} یک تغییر انجام داد" : "{actor} made a change";
  const sentence = render(template, { actor, target });
  const result = AUDIT_RESULTS[event.result ?? "success"] ?? AUDIT_RESULTS.success;
  return {
    sentence: language === "en" ? capitalize(sentence) : sentence,
    result: { tone: result.tone, label: result.label[language] },
    known: Boolean(AUDIT_ACTIONS[event.action])
  };
}
