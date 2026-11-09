/**
 * «DNS › تنظیمات › پشتیبان DNS» (contract docs/41 §4, §7; dns:admin).
 * Download one file with everything DNS keeps (settings, domains, names, keys, certificate), and
 * bring it back later. The server checks the whole file before changing anything.
 */
import { useRef, useState } from "react";
import { Box, Button, CircularProgress, Stack, Typography } from "@mui/material";
import DownloadRoundedIcon from "@mui/icons-material/DownloadRounded";
import UploadFileRoundedIcon from "@mui/icons-material/UploadFileRounded";
import { hasPermission } from "./api";
import { CONFIRM_WORDS, errorSentence, pick, say, type Bi } from "./copy";
import { FriendlyError, NoAccess, Notice, SectionCard, formatSize, useConfirmAction, useKit, useUndoSnackbar } from "./kit";
import { downloadDnsBackup, restoreDnsBackup } from "./dnsFinal";
import { isMissingEndpoint } from "./dnsUi";

const COPY = {
  title: { fa: "پشتیبان DNS", en: "DNS backup" },
  hint: { fa: "یک فایل با همه چیزهای DNS: تنظیمات، دامنه‌ها، نام‌ها، کلیدها و گواهی. برای انتقال به سرور دیگر یا برگرداندن بعد از اشتباه.", en: "One file with everything in DNS: settings, domains, names, keys and the certificate. To move to another server or undo a mistake." },
  secretNote: { fa: "این فایل کلیدهای امضا را دارد؛ آن را جای امنی نگه دارید و برای کسی نفرستید.", en: "This file holds signing keys; keep it somewhere safe and don't send it to anyone." },
  download: { fa: "دانلود پشتیبان", en: "Download backup" },
  downloaded: { fa: "فایل «{name}» دانلود شد.", en: "The file “{name}” was downloaded." },
  restore: { fa: "بازگردانی از فایل", en: "Restore from a file" },
  restoreTitle: { fa: "همه تنظیمات DNS با فایل «{name}» جایگزین شود؟", en: "Replace every DNS setting with “{name}”?" },
  restoreBody: { fa: "تنظیمات، دامنه‌ها و نام‌های فعلی DNS همان می‌شوند که در فایل است. پیشکار اول کل فایل را بررسی می‌کند و اگر مشکلی داشت، چیزی تغییر نمی‌کند.", en: "DNS settings, domains and names become what's in the file. Pishkar checks the whole file first; if anything is wrong, nothing changes." },
  restoreConsequence1: { fa: "تغییرهایی که بعد از ساخت این فایل داده‌اید از بین می‌رود.", en: "Changes made after this file was created are lost." },
  restoreConsequence2: { fa: "پیشنهاد: اول یک پشتیبان تازه دانلود کنید.", en: "Tip: download a fresh backup first." },
  restoreYes: { fa: "بله، بازگردانی کن", en: "Yes, restore" },
  restoring: { fa: "در حال بازگردانی…", en: "Restoring…" },
  restored: { fa: "پشتیبان DNS بازگردانی شد و همین حالا اعمال شد.", en: "The DNS backup was restored and applied right away." },
  restartRequired: { fa: "پشتیبان بازگردانی شد. برای اعمال کلیدهای امضا، DNS را یک بار دوباره راه‌اندازی کنید.", en: "The backup was restored. Restart DNS once so the signing keys take effect." },
  restoredZones: { fa: "پشتیبان بازگردانی شد؛ {count} دامنه.", en: "The backup was restored; {count} domains." },
  badFile: { fa: "این فایل پشتیبان DNS نیست؛ فایلی با پسوند ‎.tar.gz بدهید.", en: "This isn't a DNS backup; pick a .tar.gz file." },
  restoreFailed: { fa: "بازگردانی انجام نشد و چیزی تغییر نکرد.", en: "The restore didn't happen and nothing changed." },
  notSupported: { fa: "برنامه DNS روی سرور هنوز پشتیبان ندارد. آن را به‌روز کنید.", en: "The DNS program on the server can't make backups yet. Update it." }
} satisfies Record<string, Bi>;

export function DnsBackupCard({ permissions }: { permissions: readonly string[] }) {
  const { language } = useKit();
  const canAdmin = hasPermission(permissions, "dns:admin");
  const [busy, setBusy] = useState<"download" | "restore" | null>(null);
  const [error, setError] = useState<unknown>(null);
  const fileInput = useRef<HTMLInputElement | null>(null);
  const { ask, dialog } = useConfirmAction();
  const { notify, snackbar } = useUndoSnackbar();

  const download = async () => {
    setBusy("download");
    setError(null);
    try {
      const name = await downloadDnsBackup();
      notify({ message: say(language, COPY.downloaded, { name }), tone: "success" });
    } catch (caught) {
      setError(caught);
    } finally {
      setBusy(null);
    }
  };

  const restore = async (file: File) => {
    if (!/\.(tar\.gz|tgz)$/i.test(file.name)) {
      notify({ message: pick(language, COPY.badFile), tone: "error" });
      return;
    }
    const ok = await ask({
      title: say(language, COPY.restoreTitle, { name: file.name }),
      body: `${pick(language, COPY.restoreBody)} (${formatSize(file.size, language)})`,
      consequences: [pick(language, COPY.restoreConsequence1), pick(language, COPY.restoreConsequence2)],
      severity: "destructive",
      typed: CONFIRM_WORDS.restoreDns,
      confirmLabel: pick(language, COPY.restoreYes)
    });
    if (!ok) return;
    setBusy("restore");
    setError(null);
    try {
      const result = await restoreDnsBackup(file);
      notify({ message: result.restart_required ? pick(language, COPY.restartRequired) : typeof result.zones === "number" ? say(language, COPY.restoredZones, { count: result.zones }) : pick(language, COPY.restored), tone: result.restart_required ? "info" : "success" });
    } catch (caught) {
      setError(caught);
      notify({ message: errorSentence(language, caught, "dns"), tone: "error" });
    } finally {
      setBusy(null);
    }
  };

  return (
    <SectionCard title={pick(language, COPY.title)} hint={pick(language, COPY.hint)}>
      {canAdmin ? (
        <Stack spacing={2}>
          <Typography variant="body2" color="text.secondary">{pick(language, COPY.secretNote)}</Typography>
          <Stack direction="row" gap={1} flexWrap="wrap">
            <Button variant="contained" startIcon={busy === "download" ? <CircularProgress size={16} color="inherit" /> : <DownloadRoundedIcon />} disabled={busy !== null} onClick={() => void download()} sx={{ minHeight: 44 }}>
              {pick(language, COPY.download)}
            </Button>
            <Button variant="outlined" color="warning" startIcon={busy === "restore" ? <CircularProgress size={16} color="inherit" /> : <UploadFileRoundedIcon />} disabled={busy !== null} onClick={() => fileInput.current?.click()} sx={{ minHeight: 44 }}>
              {pick(language, busy === "restore" ? COPY.restoring : COPY.restore)}
            </Button>
            <Box component="input" ref={fileInput} type="file" accept=".tar.gz,.tgz,application/gzip" hidden onChange={(event: React.ChangeEvent<HTMLInputElement>) => {
              const file = event.target.files?.[0];
              event.target.value = "";
              if (file) void restore(file);
            }} />
          </Stack>
          {error ? (
            isMissingEndpoint(error)
              ? <Notice tone="info">{pick(language, COPY.notSupported)}</Notice>
              : <FriendlyError error={error} title={busy === null ? undefined : pick(language, COPY.restoreFailed)} scope="dns" onClose={() => setError(null)} />
          ) : null}
        </Stack>
      ) : (
        <NoAccess needs="dns:admin" />
      )}
      {dialog}
      {snackbar}
    </SectionCard>
  );
}
