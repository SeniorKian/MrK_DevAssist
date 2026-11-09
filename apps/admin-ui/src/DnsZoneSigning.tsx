/**
 * «امضای امنیتی» of one domain (contract docs/41 §2.5, §7).
 *
 * Simple: one switch, and once it's on the DS record ready to copy with a step-by-step guide for
 * the domain registrar. Turning it off warns to remove the DS from the registrar first.
 * Advanced: algorithm, NSEC/NSEC3, signature lifetimes, the keys and a key change (rollover).
 */
import { useCallback, useEffect, useState } from "react";
import { Box, Button, CircularProgress, FormControlLabel, MenuItem, Stack, Switch, TextField, Typography } from "@mui/material";
import VerifiedUserRoundedIcon from "@mui/icons-material/VerifiedUserRounded";
import AutorenewRoundedIcon from "@mui/icons-material/AutorenewRounded";
import { hasPermission } from "./api";
import { CONFIRM_WORDS, errorSentence, pick, say, type Bi } from "./copy";
import {
  CopyField, FriendlyError, KeyValueList, Ltr, NoAccess, Notice, NumberInput, RelativeTime, SectionCard, StatusPill, useConfirmAction, useKit,
  useUndoSnackbar
} from "./kit";
import { patchZone, type DnsZone } from "./dns";
import {
  DEFAULT_ZONE_DNSSEC, DIGEST_WORDS, KEY_STATE_WORDS, fetchZoneDetail, fetchZoneDnssec, rolloverZoneKey, toTime, type DsRecord, type ZoneDnssecSettings,
  type ZoneDnssecStatus
} from "./dnsFinal";
import { Loading, isMissingEndpoint, useLoader } from "./dnsUi";

const COPY = {
  title: { fa: "امضای امنیتی دامنه", en: "Domain security signing" },
  hint: {
    fa: "با امضای امنیتی (DNSSEC) هیچ‌کس نمی‌تواند به نام دامنه شما جواب جعلی بدهد؛ دستگاه‌ها امضا را بررسی می‌کنند. پیشکار کلیدها و تمدید امضاها را خودش انجام می‌دهد.",
    en: "With security signing (DNSSEC) nobody can give fake answers in your domain's name; devices check the signature. Pishkar handles the keys and renews the signatures itself."
  },
  on: { fa: "امضا روشن است", en: "Signing is on" },
  off: { fa: "امضا خاموش است", en: "Signing is off" },
  turnOn: { fa: "امضا کن", en: "Sign this domain" },
  switchLabel: { fa: "این دامنه امضا شود", en: "Sign this domain" },
  onTitle: { fa: "دامنه «{zone}» امضا شود؟", en: "Sign the domain “{zone}”?" },
  onBody: { fa: "پیشکار کلیدها را می‌سازد و همه رکوردها را امضا می‌کند. بعد یک قدم کوچک می‌ماند: گذاشتن «رکورد DS» در پنل جایی که دامنه را خریده‌اید.", en: "Pishkar makes the keys and signs every record. One small step is left after that: putting the DS record in the panel where you bought the domain." },
  onYes: { fa: "بله، امضا کن", en: "Yes, sign it" },
  turnedOn: { fa: "امضای «{zone}» روشن شد. حالا رکورد DS را در ثبت‌کننده دامنه بگذارید.", en: "Signing for “{zone}” is on. Now put the DS record at your domain registrar." },
  offTitle: { fa: "امضای «{zone}» خاموش شود؟", en: "Turn off signing for “{zone}”?" },
  offBody: { fa: "اول رکورد DS را از پنل ثبت‌کننده دامنه پاک کنید و یکی دو روز صبر کنید. اگر DS بماند و امضا خاموش شود، دامنه برای خیلی از کاربران باز نمی‌شود.", en: "First remove the DS record from your domain registrar's panel and wait a day or two. If the DS stays while signing is off, the domain stops opening for many people." },
  offConsequence1: { fa: "DS را از ثبت‌کننده دامنه پاک کرده‌ام.", en: "I removed the DS from the domain registrar." },
  offConsequence2: { fa: "دست‌کم یک روز از پاک کردن آن گذشته است.", en: "At least a day has passed since then." },
  offYes: { fa: "بله، خاموش کن", en: "Yes, turn off" },
  turnedOff: { fa: "امضای «{zone}» خاموش شد.", en: "Signing for “{zone}” is off." },
  dsTitle: { fa: "رکورد DS برای ثبت‌کننده دامنه", en: "DS record for your domain registrar" },
  dsHint: { fa: "این را در پنل جایی که دامنه را خریده‌اید بگذارید تا امضا در همه اینترنت معتبر شود.", en: "Put this in the panel where you bought the domain so the signature counts across the internet." },
  dsWaiting: { fa: "کلیدها در حال ساخته شدن است؛ چند لحظه بعد رکورد DS اینجا می‌آید.", en: "The keys are being made; the DS record shows up here in a moment." },
  dsFull: { fa: "رکورد کامل", en: "Full record" },
  keyTag: { fa: "شماره کلید «Key Tag»", en: "Key Tag" },
  algorithmNumber: { fa: "الگوریتم «Algorithm»", en: "Algorithm" },
  digestType: { fa: "نوع چکیده «Digest Type»", en: "Digest Type" },
  digest: { fa: "چکیده «Digest»", en: "Digest" },
  guideTitle: { fa: "چطور در ثبت‌کننده دامنه بگذارم؟", en: "How do I add it at my registrar?" },
  guide1: { fa: "وارد پنل جایی شوید که دامنه را خریده‌اید (مثلاً «ایرنیک» برای دامنه‌های ‎.ir یا شرکتی که از آن خریده‌اید).", en: "Sign in to the panel where you bought the domain (for example IRNIC for .ir domains, or the company you bought it from)." },
  guide2: { fa: "بخشی به نام «DNSSEC» یا «رکورد DS» پیدا کنید؛ معمولاً در تنظیمات دامنه یا سرورهای نام است.", en: "Find a part called DNSSEC or DS records; it's usually in the domain's settings or name servers." },
  guide3: { fa: "یک رکورد تازه بسازید و چهار خانه بالا را دقیقاً همان‌طور کپی کنید. اگر فقط یک خانه می‌خواهد، «رکورد کامل» را بگذارید.", en: "Add a new record and copy the four fields above exactly. If it asks for one field only, use the full record." },
  guide4: { fa: "ذخیره کنید. تا ۴۸ ساعت طول می‌کشد؛ بعد در «تست» یک نام از این دامنه بپرسید تا «امضا درست» ببینید.", en: "Save. It can take up to 48 hours; then ask a name from this domain under Test and look for “Signed”." },
  advancedTitle: { fa: "جزئیات امضا", en: "Signing details" },
  algorithm: { fa: "الگوریتم کلید", en: "Key algorithm" },
  denial: { fa: "اثبات «نیست»", en: "Proof of “not found”" },
  nsec: { fa: "«NSEC» (ساده)", en: "NSEC (simple)" },
  nsec3: { fa: "«NSEC3» (نام‌ها را پنهان می‌کند)", en: "NSEC3 (hides names)" },
  iterations: { fa: "تکرار NSEC3", en: "NSEC3 iterations" },
  iterationsHint: { fa: "پیشنهاد: ۰", en: "Recommended: 0" },
  salt: { fa: "نمک NSEC3 (خالی پیشنهادی)", en: "NSEC3 salt (empty recommended)" },
  optOut: { fa: "رد شدن از زیردامنه‌های بدون امضا «opt-out»", en: "Skip unsigned delegations (opt-out)" },
  validity: { fa: "اعتبار هر امضا (روز)", en: "Each signature lasts (days)" },
  refreshDays: { fa: "تمدید امضا چند روز پیش از پایان", en: "Renew this many days before the end" },
  refreshTooBig: { fa: "زمان تمدید باید کمتر از اعتبار امضا باشد.", en: "Renewal must be shorter than the signature's life." },
  algorithmLocked: { fa: "تا امضا روشن است الگوریتم عوض نمی‌شود؛ برای عوض کردن، امضا را خاموش و با الگوریتم تازه روشن کنید (و DS تازه بگذارید).", en: "The algorithm can't change while signing is on; turn signing off and on again with the new one (and put the new DS)." },
  algorithmChange: { fa: "عوض کردن الگوریتم یعنی کلیدهای تازه و رکورد DS تازه؛ DS قبلی را در ثبت‌کننده عوض کنید.", en: "Changing the algorithm means new keys and a new DS record; replace the DS at the registrar." },
  save: { fa: "ذخیره", en: "Save" },
  discard: { fa: "دور انداختن تغییرات", en: "Discard changes" },
  saved: { fa: "ذخیره شد و همین حالا اعمال شد.", en: "Saved and applied right away." },
  keysTitle: { fa: "کلیدها", en: "Keys" },
  keyRole: { fa: "{role} · شماره {tag}", en: "{role} · tag {tag}" },
  ksk: { fa: "کلید اصلی (KSK)", en: "Key-signing key (KSK)" },
  zsk: { fa: "کلید امضای رکوردها (ZSK)", en: "Zone-signing key (ZSK)" },
  csk: { fa: "کلید ترکیبی (CSK)", en: "Combined key (CSK)" },
  nextResign: { fa: "تمدید بعدی امضاها", en: "Next signature renewal" },
  rolloverZsk: { fa: "عوض کردن کلید امضای رکوردها", en: "Change the zone-signing key" },
  rolloverKsk: { fa: "عوض کردن کلید اصلی", en: "Change the key-signing key" },
  rolloverZskTitle: { fa: "کلید امضای رکوردهای «{zone}» عوض شود؟", en: "Change the zone-signing key of “{zone}”?" },
  rolloverZskBody: { fa: "کلید تازه اول منتشر می‌شود و بعد جای قبلی را می‌گیرد؛ کاری با ثبت‌کننده لازم نیست.", en: "The new key is published first and then takes over; nothing is needed at the registrar." },
  rolloverKskTitle: { fa: "کلید اصلی «{zone}» عوض شود؟", en: "Change the key-signing key of “{zone}”?" },
  rolloverKskBody: { fa: "یک رکورد DS تازه ساخته می‌شود. باید DS تازه را در ثبت‌کننده دامنه بگذارید و DS قبلی را فقط پس از یکی دو روز بردارید.", en: "A new DS record is made. Put the new DS at the registrar, and remove the old DS only after a day or two." },
  rolloverYes: { fa: "بله، عوض کن", en: "Yes, change it" },
  rolledOver: { fa: "عوض کردن کلید شروع شد.", en: "The key change has started." },
  loadFailed: { fa: "وضعیت امضای این دامنه خوانده نشد.", en: "This domain's signing state didn't load." },
  notSupported: { fa: "برنامه DNS روی سرور هنوز امضای دامنه را ندارد. آن را به‌روز کنید.", en: "The DNS program on the server can't sign domains yet. Update it." },
  signingError: { fa: "امضا با مشکل روبه‌رو شده", en: "Signing has a problem" }
} satisfies Record<string, Bi>;

const ALGORITHMS: { value: string; label: Bi }[] = [
  { value: "ECDSAP256SHA256", label: { fa: "«ECDSA P-256» (پیشنهادی، همه جا کار می‌کند)", en: "ECDSA P-256 (recommended, works everywhere)" } },
  { value: "ED25519", label: { fa: "Ed25519 (تازه‌تر و کوتاه‌تر)", en: "Ed25519 (newer and shorter)" } }
];

/** `example.com. 3600 IN DS 12345 13 2 ABCD…` → its four parts. */
export function dsParts(ds: DsRecord): { keyTag: string; algorithm: string; digestType: string; digest: string } {
  const tokens = (ds.text ?? "").trim().split(/\s+/);
  const at = tokens.findIndex((token) => token.toUpperCase() === "DS");
  const rest = at >= 0 ? tokens.slice(at + 1) : [];
  return {
    keyTag: String(ds.key_tag ?? rest[0] ?? ""),
    algorithm: String(ds.algorithm ?? rest[1] ?? ""),
    digestType: String(ds.digest_type ?? rest[2] ?? ""),
    digest: String(ds.digest ?? rest.slice(3).join("") ?? "")
  };
}

function DsCard({ zone, ds }: { zone: string; ds: DsRecord[] }) {
  const { language } = useKit();
  // Prefer SHA-256 (type 2); show the others in Advanced only.
  const sorted = [...ds].sort((a, b) => (String(a.digest_type) === "2" ? -1 : String(b.digest_type) === "2" ? 1 : 0));
  const { isAdvanced } = useKit();
  const shown = isAdvanced ? sorted : sorted.slice(0, 1);
  return (
    <SectionCard title={pick(language, COPY.dsTitle)} hint={pick(language, COPY.dsHint)}>
      <Stack spacing={2.5}>
        {!shown.length ? <Notice tone="info">{pick(language, COPY.dsWaiting)}</Notice> : null}
        {shown.map((record, index) => {
          const parts = dsParts(record);
          const typeWord = DIGEST_WORDS[parts.digestType];
          return (
            <Stack key={`${parts.keyTag}-${parts.digestType}-${index}`} spacing={1.25}>
              {shown.length > 1 && typeWord ? <Typography variant="subtitle2" sx={{ fontWeight: 720 }}>{pick(language, typeWord)}</Typography> : null}
              <Box sx={{ display: "grid", gap: 1.25, gridTemplateColumns: { xs: "1fr", sm: "repeat(3, minmax(0, 1fr))" } }}>
                <CopyField label={pick(language, COPY.keyTag)} value={parts.keyTag} />
                <CopyField label={pick(language, COPY.algorithmNumber)} value={parts.algorithm} />
                <CopyField label={pick(language, COPY.digestType)} value={parts.digestType} />
              </Box>
              <CopyField label={pick(language, COPY.digest)} value={parts.digest} />
              {record.text ? <CopyField label={pick(language, COPY.dsFull)} value={record.text} /> : null}
            </Stack>
          );
        })}
        <Box component="details" sx={{ "& summary": { cursor: "pointer", fontWeight: 700, minHeight: 32 } }} open={!isAdvanced}>
          <summary>{pick(language, COPY.guideTitle)}</summary>
          <Box component="ol" sx={{ m: 0, mt: 1, ps: 3, "& li": { lineHeight: 1.9, mb: 0.5 } }}>
            {[COPY.guide1, COPY.guide2, COPY.guide3, COPY.guide4].map((step, index) => <li key={index}><Typography variant="body2" component="span">{pick(language, step)}</Typography></li>)}
          </Box>
        </Box>
        <Typography variant="caption" color="text.secondary"><Ltr mono>{zone}</Ltr></Typography>
      </Stack>
    </SectionCard>
  );
}

function roleWord(language: "fa" | "en", role: string | undefined): string {
  if (role === "ksk") return pick(language, COPY.ksk);
  if (role === "zsk") return pick(language, COPY.zsk);
  if (role === "csk") return pick(language, COPY.csk);
  return role ?? "—";
}

export function ZoneSigningTab({ zone, permissions }: { zone: DnsZone; permissions: readonly string[] }) {
  const { language, isAdvanced } = useKit();
  const canWrite = hasPermission(permissions, "dns:write");
  const detailLoader = useCallback((signal: AbortSignal) => fetchZoneDetail(zone.name, signal), [zone.name]);
  const detail = useLoader<DnsZone>(detailLoader);
  const statusLoader = useCallback((signal: AbortSignal) => fetchZoneDnssec(zone.name, signal), [zone.name]);
  const status = useLoader<ZoneDnssecStatus>(statusLoader);
  const settings: ZoneDnssecSettings = { ...DEFAULT_ZONE_DNSSEC, ...(detail.data?.dnssec ?? zone.dnssec ?? {}), nsec3: { ...DEFAULT_ZONE_DNSSEC.nsec3, ...((detail.data?.dnssec ?? zone.dnssec)?.nsec3 ?? {}) } };
  const enabled = Boolean(status.data?.enabled ?? settings.enabled);
  const [draft, setDraft] = useState<ZoneDnssecSettings>(settings);
  const [busy, setBusy] = useState<string | null>(null);
  const [error, setError] = useState<unknown>(null);
  const { ask, dialog } = useConfirmAction();
  const { notify, snackbar } = useUndoSnackbar();
  const settingsKey = JSON.stringify(settings);
  useEffect(() => setDraft(JSON.parse(settingsKey) as ZoneDnssecSettings), [settingsKey]);

  // Keys are made a moment after turning on; look again until the DS shows up.
  useEffect(() => {
    if (!enabled || (status.data?.ds?.length ?? 0) > 0) return;
    const timer = window.setTimeout(() => void status.reload(), 4_000);
    return () => window.clearTimeout(timer);
  }, [enabled, status.data, status.reload]);

  const reloadAll = () => {
    void detail.reload();
    void status.reload();
  };

  const save = async (next: ZoneDnssecSettings, message: string) => {
    setError(null);
    await patchZone(zone.name, { dnssec: next });
    notify({ message, tone: "success" });
    reloadAll();
  };

  const toggle = async (on: boolean) => {
    const ok = on
      ? await ask({ title: say(language, COPY.onTitle, { zone: zone.name }), body: pick(language, COPY.onBody), confirmLabel: pick(language, COPY.onYes) })
      : await ask({
          title: say(language, COPY.offTitle, { zone: zone.name }),
          body: pick(language, COPY.offBody),
          consequences: [pick(language, COPY.offConsequence1), pick(language, COPY.offConsequence2)],
          severity: "destructive",
          typed: CONFIRM_WORDS.confirm,
          confirmLabel: pick(language, COPY.offYes)
        });
    if (!ok) return;
    setBusy("toggle");
    try {
      await save({ ...settings, enabled: on }, say(language, on ? COPY.turnedOn : COPY.turnedOff, { zone: zone.name }));
    } catch (caught) {
      setError(caught);
    } finally {
      setBusy(null);
    }
  };

  const saveDetails = async () => {
    setBusy("details");
    try {
      await save(draft, pick(language, COPY.saved));
    } catch (caught) {
      setError(caught);
    } finally {
      setBusy(null);
    }
  };

  const rollover = async (role: "zsk" | "ksk") => {
    const ok = await ask({
      title: say(language, role === "ksk" ? COPY.rolloverKskTitle : COPY.rolloverZskTitle, { zone: zone.name }),
      body: pick(language, role === "ksk" ? COPY.rolloverKskBody : COPY.rolloverZskBody),
      severity: role === "ksk" ? "disruptive" : undefined,
      confirmLabel: pick(language, COPY.rolloverYes)
    });
    if (!ok) return;
    setBusy(role);
    try {
      await rolloverZoneKey(zone.name, role);
      notify({ message: pick(language, COPY.rolledOver), tone: "success" });
      void status.reload();
    } catch (caught) {
      notify({ message: errorSentence(language, caught, "dns"), tone: "error" });
    } finally {
      setBusy(null);
    }
  };

  if (!detail.data && !status.data && (detail.loading || status.loading || (!detail.error && !status.error))) return <Loading />;
  const missing = isMissingEndpoint(status.error) && !detail.data?.dnssec;
  const dirty = JSON.stringify(draft) !== JSON.stringify(settings);
  const refreshProblem = draft.refresh_days >= draft.signature_validity_days ? pick(language, COPY.refreshTooBig) : null;
  const keys = status.data?.keys ?? [];

  return (
    <Stack spacing={2.5}>
      <SectionCard
        title={pick(language, COPY.title)}
        hint={pick(language, COPY.hint)}
        status={<StatusPill tone={status.data?.error ? "warn" : enabled ? "ok" : "off"} label={pick(language, status.data?.error ? COPY.signingError : enabled ? COPY.on : COPY.off)} />}
      >
        <Stack spacing={2}>
          {missing ? <Notice tone="info">{pick(language, COPY.notSupported)}</Notice> : null}
          {status.error && !missing && !status.data ? <FriendlyError error={status.error} title={pick(language, COPY.loadFailed)} onRetry={reloadAll} severity="warning" /> : null}
          {status.data?.error ? <Notice tone="warning"><Ltr mono>{status.data.error}</Ltr></Notice> : null}
          {canWrite ? (
            <Stack direction="row" alignItems="center" gap={1.5} flexWrap="wrap">
              {enabled ? (
                <FormControlLabel control={<Switch checked onChange={() => void toggle(false)} disabled={busy !== null} />} label={pick(language, COPY.switchLabel)} />
              ) : (
                <Button variant="contained" startIcon={busy === "toggle" ? <CircularProgress size={16} color="inherit" /> : <VerifiedUserRoundedIcon />} disabled={busy !== null || missing} onClick={() => void toggle(true)} sx={{ minHeight: 44 }}>
                  {pick(language, COPY.turnOn)}
                </Button>
              )}
            </Stack>
          ) : (
            <NoAccess needs="dns:write" />
          )}
          {error ? <FriendlyError error={error} scope="dns" onClose={() => setError(null)} /> : null}
          {enabled && status.data?.next_resign ? (
            <KeyValueList dense items={[{ label: pick(language, COPY.nextResign), value: <RelativeTime value={toTime(status.data.next_resign)} /> }]} />
          ) : null}
        </Stack>
      </SectionCard>

      {enabled ? <DsCard zone={zone.name} ds={status.data?.ds ?? []} /> : null}

      {isAdvanced && !missing ? (
        <SectionCard title={pick(language, COPY.advancedTitle)} collapsible defaultCollapsed={!enabled}>
          <Stack spacing={2}>
            <Box component="fieldset" disabled={!canWrite || busy !== null} sx={{ border: 0, p: 0, m: 0, minWidth: 0 }}>
              <Stack spacing={2}>
                <TextField select label={pick(language, COPY.algorithm)} value={draft.algorithm} onChange={(event) => setDraft({ ...draft, algorithm: event.target.value })} disabled={enabled} helperText={enabled ? pick(language, COPY.algorithmLocked) : " "} fullWidth>
                  {ALGORITHMS.map((item) => <MenuItem key={item.value} value={item.value}>{pick(language, item.label)}</MenuItem>)}
                </TextField>
                <TextField select label={pick(language, COPY.denial)} value={draft.denial} onChange={(event) => setDraft({ ...draft, denial: event.target.value })} fullWidth>
                  <MenuItem value="nsec">{pick(language, COPY.nsec)}</MenuItem>
                  <MenuItem value="nsec3">{pick(language, COPY.nsec3)}</MenuItem>
                </TextField>
                {draft.denial === "nsec3" ? (
                  <Stack direction={{ xs: "column", sm: "row" }} gap={1.5}>
                    <NumberInput label={pick(language, COPY.iterations)} value={draft.nsec3.iterations} onChange={(value) => setDraft({ ...draft, nsec3: { ...draft.nsec3, iterations: value ?? 0 } })} min={0} max={150} integer helperText={pick(language, COPY.iterationsHint)} />
                    <TextField label={pick(language, COPY.salt)} value={draft.nsec3.salt} onChange={(event) => setDraft({ ...draft, nsec3: { ...draft.nsec3, salt: event.target.value.trim() } })} fullWidth slotProps={{ htmlInput: { dir: "ltr", spellCheck: false } }} />
                  </Stack>
                ) : null}
                {draft.denial === "nsec3" ? (
                  <FormControlLabel control={<Switch checked={draft.nsec3.opt_out} onChange={(event) => setDraft({ ...draft, nsec3: { ...draft.nsec3, opt_out: event.target.checked } })} />} label={pick(language, COPY.optOut)} />
                ) : null}
                <Stack direction={{ xs: "column", sm: "row" }} gap={1.5}>
                  <NumberInput label={pick(language, COPY.validity)} value={draft.signature_validity_days} onChange={(value) => setDraft({ ...draft, signature_validity_days: value ?? 14 })} min={2} max={90} integer />
                  <NumberInput label={pick(language, COPY.refreshDays)} value={draft.refresh_days} onChange={(value) => setDraft({ ...draft, refresh_days: value ?? 3 })} min={1} max={60} integer error={refreshProblem} />
                </Stack>
              </Stack>
            </Box>
            {canWrite && dirty ? (
              <Stack direction="row" gap={1} justifyContent="flex-end">
                <Button onClick={() => setDraft(settings)} disabled={busy !== null} sx={{ minHeight: 44 }}>{pick(language, COPY.discard)}</Button>
                <Button variant="contained" onClick={() => void saveDetails()} disabled={busy !== null || Boolean(refreshProblem)} startIcon={busy === "details" ? <CircularProgress size={16} color="inherit" /> : undefined} sx={{ minHeight: 44 }}>{pick(language, COPY.save)}</Button>
              </Stack>
            ) : null}
            {enabled && keys.length ? (
              <>
                <Typography variant="subtitle2" sx={{ fontWeight: 720 }}>{pick(language, COPY.keysTitle)}</Typography>
                <Stack spacing={1}>
                  {keys.map((key, index) => {
                    const state = KEY_STATE_WORDS[key.state ?? ""];
                    return (
                      <Stack key={`${key.tag}-${index}`} direction="row" gap={1} alignItems="center" flexWrap="wrap" sx={{ py: 0.75, borderBottom: "1px solid", borderColor: "divider" }}>
                        <Typography variant="body2" sx={{ fontWeight: 700, flex: 1, minWidth: 180 }}>{say(language, COPY.keyRole, { role: roleWord(language, key.role), tag: String(key.tag ?? "—") })}</Typography>
                        <Typography variant="caption" color="text.secondary"><Ltr mono>{key.algorithm ?? ""}</Ltr></Typography>
                        {key.created ? <Typography variant="caption" color="text.secondary"><RelativeTime value={toTime(key.created)} /></Typography> : null}
                        {state ? <StatusPill tone={state.tone} label={pick(language, state.label)} /> : key.state ? <StatusPill tone="info" label={key.state} /> : null}
                      </Stack>
                    );
                  })}
                </Stack>
                {canWrite ? (
                  <Stack direction="row" gap={1} flexWrap="wrap">
                    <Button variant="outlined" startIcon={busy === "zsk" ? <CircularProgress size={14} /> : <AutorenewRoundedIcon />} disabled={busy !== null} onClick={() => void rollover("zsk")} sx={{ minHeight: 44 }}>{pick(language, COPY.rolloverZsk)}</Button>
                    <Button variant="outlined" color="warning" startIcon={busy === "ksk" ? <CircularProgress size={14} /> : <AutorenewRoundedIcon />} disabled={busy !== null} onClick={() => void rollover("ksk")} sx={{ minHeight: 44 }}>{pick(language, COPY.rolloverKsk)}</Button>
                  </Stack>
                ) : null}
              </>
            ) : null}
          </Stack>
        </SectionCard>
      ) : null}
      {dialog}
      {snackbar}
    </Stack>
  );
}
