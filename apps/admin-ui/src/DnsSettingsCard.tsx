import { useEffect, useState } from "react";
import { Box, Button, Chip, CircularProgress, FormControlLabel, Stack, Switch, TextField, ToggleButton, ToggleButtonGroup, Typography } from "@mui/material";
import { ApiError, getJson, isAbortError, mutateJson } from "./api";
import { pick, say, type Bi } from "./copy";
import { FriendlyError, HelpTip, ListInput, NoAccess, Notice, NumberInput, SectionCard, TestResult, useKit, useUndoSnackbar, type TestOutcome } from "./kit";
import type { Language } from "./i18n";

/** Security › DNS & internal network: which DNS DevAssist uses to find package sources (applies at once). */

type DnsSettings = { mode: "system" | "custom"; servers: string[]; timeout_seconds: number; prefer_ipv4: boolean };
type DnsTest = { ok: boolean; mode: string; addresses: string[]; latency_ms: number };

const MAX_SERVERS = 6;
const HOSTNAME = /^[A-Za-z0-9.-]{1,253}$/;
const SERVER = /^(\d{1,3}(\.\d{1,3}){3}(:\d{1,5})?|\[[0-9A-Fa-f:]+\](:\d{1,5})?|[0-9A-Fa-f:]+)$/;

const COPY = {
  title: { fa: "DNS برای منابع دریافت", en: "DNS for package sources" },
  hint: {
    fa: "DevAssist آدرس منابع را با کدام DNS (دفترچه تلفن اینترنت) پیدا کند. تغییر فوراً اعمال می‌شود.",
    en: "Which DNS (the internet's phone book) DevAssist uses to find package sources. Changes apply at once."
  },
  mode: { fa: "از کجا آدرس‌ها را پیدا کند؟", en: "Where should it look up addresses?" },
  system: { fa: "همان DNS سرور", en: "The server's own DNS" },
  custom: { fa: "سرورهای DNS دلخواه", en: "Custom DNS servers" },
  servers: { fa: "سرورهای DNS", en: "DNS servers" },
  serversHelp: { fa: "هر کدام را بنویسید و Enter بزنید؛ مثل 1.1.1.1 یا 9.9.9.9:53. حداکثر ۶ تا.", en: "Type each one and press Enter, like 1.1.1.1 or 9.9.9.9:53. Up to 6." },
  badServer: { fa: "باید یک IP باشد، مثل 1.1.1.1 یا 1.1.1.1:53.", en: "This must be an IP, like 1.1.1.1 or 1.1.1.1:53." },
  needServer: { fa: "دست‌کم یک سرور DNS بنویسید.", en: "Add at least one DNS server." },
  timeout: { fa: "حداکثر زمان انتظار برای هر پرسش", en: "Longest wait for each lookup" },
  seconds: { fa: "ثانیه", en: "seconds" },
  preferIpv4: { fa: "اول آدرس‌های IPv4 امتحان شوند", en: "Try IPv4 addresses first" },
  save: { fa: "ذخیره", en: "Save" },
  saved: { fa: "تنظیم DNS ذخیره شد.", en: "The DNS setting was saved." },
  testTitle: { fa: "امتحان پیدا کردن یک آدرس", en: "Try looking up an address" },
  testName: { fa: "نام سایت", en: "Site name" },
  testNameHint: { fa: "فقط نام، مثل pypi.org (بدون https://)", en: "Just the name, like pypi.org (no https://)" },
  test: { fa: "امتحان کن", en: "Try it" },
  testFailed: { fa: "آدرسی برای این نام پیدا نشد.", en: "No address was found for this name." },
  testOk: { fa: "پیدا شد ({count} آدرس).", en: "Found ({count} addresses)." },
  testNote: { fa: "امتحان با همین مقدارهای روی صفحه انجام می‌شود، حتی اگر هنوز ذخیره نکرده باشید.", en: "The test uses the values on screen, even before you save." },
  npmNote: {
    fa: "این تنظیم روی npm اثر ندارد؛ برای npm باید DNS را در فایل Compose عوض کنید.",
    en: "This doesn't affect npm; for npm, change DNS in the Compose file."
  },
  helpDns: {
    fa: "اگر DNS سرور شما بعضی سایت‌ها را پیدا نمی‌کند یا فیلتر است، این‌جا یک DNS دیگر بدهید.",
    en: "If your server's DNS can't find some sites or is filtered, give another DNS here."
  }
} satisfies Record<string, Bi>;

export function DnsSettingsCard({ canWrite }: { language?: Language; canWrite: boolean }) {
  const { language } = useKit();
  const { notify, snackbar } = useUndoSnackbar();
  const [settings, setSettings] = useState<DnsSettings | null>(null);
  // Last server-validated list: sent in system mode so hidden, unsaved values never break a save.
  const [savedServers, setSavedServers] = useState<string[]>([]);
  const [servers, setServers] = useState<string[]>([]);
  const [timeout, setTimeoutValue] = useState<number | null>(2);
  const [loadError, setLoadError] = useState<unknown>(null);
  const [saveError, setSaveError] = useState<unknown>(null);
  const [saving, setSaving] = useState(false);
  const [testName, setTestName] = useState("pypi.org");
  const [outcome, setOutcome] = useState<TestOutcome>({ state: "idle" });
  const [addresses, setAddresses] = useState<string[]>([]);

  useEffect(() => {
    const controller = new AbortController();
    void (async () => {
      try {
        const payload = await getJson<{ dns: DnsSettings }>("/api/v1/settings/network", controller.signal);
        setSettings(payload.dns);
        setSavedServers(payload.dns.servers);
        setServers(payload.dns.servers);
        setTimeoutValue(payload.dns.timeout_seconds);
      } catch (caught) {
        if (isAbortError(caught) || (caught instanceof ApiError && caught.status === 401)) return;
        setLoadError(caught);
      }
    })();
    return () => controller.abort();
  }, []);

  const custom = settings?.mode === "custom";
  const timeoutOk = timeout !== null && timeout >= 0.2 && timeout <= 10;
  const serversError = custom && servers.length === 0 ? pick(language, COPY.needServer) : null;
  const testHost = testName.trim();
  const testHostOk = HOSTNAME.test(testHost);

  const save = async () => {
    if (!settings || !timeoutOk || serversError) return;
    setSaving(true);
    setSaveError(null);
    try {
      const payload = await mutateJson<{ dns: DnsSettings }>("/api/v1/settings/network/dns", {
        method: "PUT",
        body: { mode: settings.mode, servers: custom ? servers : savedServers, timeout_seconds: timeout, prefer_ipv4: settings.prefer_ipv4 }
      });
      setSettings(payload.dns);
      setSavedServers(payload.dns.servers);
      setServers(payload.dns.servers);
      setTimeoutValue(payload.dns.timeout_seconds);
      notify({ message: pick(language, COPY.saved) });
    } catch (caught) {
      if (!(caught instanceof ApiError && caught.status === 401)) setSaveError(caught);
    } finally {
      setSaving(false);
    }
  };

  const test = async () => {
    if (!settings || !testHostOk || serversError) return;
    setOutcome({ state: "running" });
    setAddresses([]);
    try {
      const body = custom ? { hostname: testHost, mode: "custom", servers } : { hostname: testHost, mode: "system" };
      const result = await mutateJson<DnsTest>("/api/v1/settings/network/dns-test", { body });
      if (result.ok && result.addresses.length) {
        setAddresses(result.addresses);
        setOutcome({ state: "ok", latencyMs: result.latency_ms });
      } else {
        setOutcome({ state: "fail", message: pick(language, COPY.testFailed) });
      }
    } catch (caught) {
      setOutcome({ state: "fail", error: caught });
    }
  };

  return (
    <SectionCard title={pick(language, COPY.title)} hint={pick(language, COPY.hint)} action={<HelpTip>{pick(language, COPY.helpDns)}</HelpTip>}>
      {loadError !== null && <FriendlyError error={loadError} onRetry={() => window.location.reload()} />}
      {settings && (
        <Stack spacing={2}>
          <Box>
            <Typography variant="body2" sx={{ mb: 1, fontWeight: 650 }}>{pick(language, COPY.mode)}</Typography>
            <ToggleButtonGroup
              exclusive
              value={settings.mode}
              disabled={!canWrite}
              onChange={(_event, value: DnsSettings["mode"] | null) => value && setSettings({ ...settings, mode: value })}
              sx={{ flexWrap: "wrap", "& .MuiToggleButton-root": { minHeight: 44, px: 2 } }}
            >
              <ToggleButton value="system">{pick(language, COPY.system)}</ToggleButton>
              <ToggleButton value="custom">{pick(language, COPY.custom)}</ToggleButton>
            </ToggleButtonGroup>
          </Box>
          {custom && (
            <Box>
              <ListInput
                label={pick(language, COPY.servers)}
                value={servers}
                onChange={setServers}
                max={MAX_SERVERS}
                validate={(item) => (SERVER.test(item) ? null : pick(language, COPY.badServer))}
                helperText={serversError ?? pick(language, COPY.serversHelp)}
                suggestions={["1.1.1.1", "8.8.8.8", "9.9.9.9"]}
                disabled={!canWrite}
              />
            </Box>
          )}
          <Stack direction={{ xs: "column", sm: "row" }} spacing={2} alignItems={{ sm: "center" }}>
            <Box sx={{ maxWidth: 320, width: "100%" }}>
              <NumberInput label={pick(language, COPY.timeout)} value={timeout} onChange={setTimeoutValue} min={0.2} max={10} unit={pick(language, COPY.seconds)} disabled={!canWrite} />
            </Box>
            <FormControlLabel
              control={<Switch checked={settings.prefer_ipv4} disabled={!canWrite} onChange={(_event, value) => setSettings({ ...settings, prefer_ipv4: value })} />}
              label={pick(language, COPY.preferIpv4)}
            />
          </Stack>
          {saveError !== null && <FriendlyError error={saveError} onClose={() => setSaveError(null)} />}
          {!canWrite && <NoAccess needs="upstream:write" />}
          <Box>
            <Button variant="contained" disabled={!canWrite || saving || !timeoutOk || Boolean(serversError)} onClick={() => void save()} startIcon={saving ? <CircularProgress size={16} color="inherit" /> : undefined} sx={{ minHeight: 44 }}>
              {pick(language, COPY.save)}
            </Button>
          </Box>

          <Box sx={{ borderTop: 1, borderColor: "divider", pt: 2 }}>
            <Typography variant="subtitle2" component="h3" sx={{ fontWeight: 720, mb: 1 }}>{pick(language, COPY.testTitle)}</Typography>
            <Stack direction={{ xs: "column", sm: "row" }} spacing={1.5} alignItems={{ sm: "flex-start" }}>
              <TextField
                size="small"
                label={pick(language, COPY.testName)}
                value={testName}
                error={testName.length > 0 && !testHostOk}
                helperText={pick(language, COPY.testNameHint)}
                slotProps={{ htmlInput: { dir: "ltr", maxLength: 253, spellCheck: false } }}
                onChange={(event) => setTestName(event.target.value)}
              />
              <Button variant="outlined" disabled={!canWrite || outcome.state === "running" || !testHostOk || Boolean(serversError)} onClick={() => void test()} sx={{ minHeight: 40 }}>
                {pick(language, COPY.test)}
              </Button>
            </Stack>
            <Box sx={{ mt: 1.5 }}>
              <TestResult outcome={outcome} />
              {addresses.length > 0 && (
                <Stack direction="row" flexWrap="wrap" gap={1} sx={{ mt: 1 }} aria-label={say(language, COPY.testOk, { count: addresses.length })}>
                  {addresses.map((address) => <Chip key={address} size="small" variant="outlined" dir="ltr" label={address} />)}
                </Stack>
              )}
            </Box>
            <Typography variant="caption" color="text.secondary" display="block" sx={{ mt: 1 }}>{pick(language, COPY.testNote)}</Typography>
          </Box>
          <Notice>{pick(language, COPY.npmNote)}</Notice>
        </Stack>
      )}
      {snackbar}
    </SectionCard>
  );
}
