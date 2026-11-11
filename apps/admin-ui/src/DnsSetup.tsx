/**
 * «DNS › راه‌اندازی» (docs/36 §7, contract docs/37 §4 `GET /api/v1/dns/setup`).
 * Step-by-step checklist: each step has its state, a plain explanation of `detail_code`, the exact
 * commands to copy (DevAssist never changes system files itself) and, folded away, the commands that undo it.
 * «دوباره بررسی کن» runs the checks again.
 */
import { useCallback, useEffect, useRef, useState } from "react";
import { Box, Button, CircularProgress, Collapse, LinearProgress, Stack, Typography } from "@mui/material";
import RefreshRoundedIcon from "@mui/icons-material/RefreshRounded";
import UndoRoundedIcon from "@mui/icons-material/UndoRounded";
import CheckCircleRoundedIcon from "@mui/icons-material/CheckCircleRounded";
import { ApiError, isAbortError } from "./api";
import { pick, say, type Bi } from "./copy";
import { CopyField, FriendlyError, KeyValueList, Ltr, Notice, SectionCard, StatusPill, helperProblem, useKit } from "./kit";
import { commandTitle, fetchDnsSetup, setupDetail, setupStateWord, SETUP_STEP_WORDS, setupStepTitle, type DnsSetup, type DnsSetupStep } from "./dns";

const COPY = {
  intro: {
    fa: "این قدم‌ها را به ترتیب روی سرور انجام دهید. DevAssist خودش به فایل‌های سیستم دست نمی‌زند؛ فقط دستور دقیق می‌دهد و بعد بررسی می‌کند.",
    en: "Do these steps on the server, in order. DevAssist never edits system files itself; it gives you the exact commands, then checks."
  },
  progress: { fa: "{done} از {total} قدم اصلی انجام شده", en: "{done} of {total} main steps done" },
  allDone: { fa: "همه قدم‌های اصلی انجام شده. بررسی دستی داخل کانتینر اختیاری است.", en: "Every main step is done. The manual check inside a container is optional." },
  optional: { fa: "اختیاری", en: "Optional" },
  recheck: { fa: "دوباره بررسی کن", en: "Check again" },
  checking: { fa: "در حال بررسی…", en: "Checking…" },
  noAgent: {
    fa: "دستیار سرور وصل نیست، پس DevAssist بعضی قدم‌ها را خودش نمی‌تواند بررسی کند. دستورها کامل‌اند؛ اجرا کنید و ادامه دهید.",
    en: "The server helper isn't connected, so DevAssist can't check some steps itself. The commands are complete; run them and carry on."
  },
  step: { fa: "قدم {n}", en: "Step {n}" },
  commands: { fa: "دستورها", en: "Commands" },
  commandsHint: { fa: "روی سرور، در ترمینال، به ترتیب اجرا کنید.", en: "Run these on the server, in a terminal, in order." },
  noCommands: { fa: "برای این قدم دستوری لازم نیست.", en: "This step needs no command." },
  showRevert: { fa: "برگرداندن این قدم", en: "Undo this step" },
  hideRevert: { fa: "بستن دستورهای برگرداندن", en: "Hide the undo commands" },
  revertHint: { fa: "اگر خواستید این قدم را برگردانید، این دستورها را اجرا کنید.", en: "If you want to undo this step, run these commands." },
  dockerWarning: {
    fa: "دقت کنید: راه‌اندازی دوباره Docker همه برنامه‌های Dokploy را هم چند ثانیه تا چند دقیقه قطع و دوباره روشن می‌کند. این کار را در ساعت خلوت انجام دهید.",
    en: "Careful: restarting Docker also stops and restarts every Dokploy app, for a few seconds to a few minutes. Do it at a quiet time."
  },
  backupNote: {
    fa: "دستورها همیشه یک DNS پشتیبان هم کنار DevAssist می‌گذارند تا اگر DevAssist افتاد، اینترنت سرور قطع نشود.",
    en: "The commands always add a backup DNS next to DevAssist, so the server keeps its internet if DevAssist goes down."
  },
  loadFailed: { fa: "قدم‌های راه‌اندازی خوانده نشد.", en: "The setup steps didn't load." },
  moduleMissing: { fa: "بخش DNS روی نسخه فعلی سرور نیست. DevAssist را به‌روز کنید.", en: "DNS isn't on your server's current version. Update DevAssist." },
  empty: { fa: "سرور هنوز قدمی برای راه‌اندازی نفرستاده است.", en: "The server hasn't sent any setup steps yet." },
  technicalCode: { fa: "کد بررسی", en: "Check code" },
  technicalParams: { fa: "جزئیات", en: "Details" }
} satisfies Record<string, Bi>;

function isManualOptionalStep(step: DnsSetupStep): boolean {
  return step.id === "verify_from_container" && step.state === "unknown" && step.detail_code === "manual_check";
}

function StepCard({ step, index }: { step: DnsSetupStep; index: number }) {
  const { language, isAdvanced } = useKit();
  const [showRevert, setShowRevert] = useState(false);
  const optional = isManualOptionalStep(step);
  const state = optional
    ? { tone: "off" as const, label: pick(language, COPY.optional) }
    : setupStateWord(language, step.state);
  const why = SETUP_STEP_WORDS[step.id]?.why;
  const commands = step.commands ?? [];
  const revert = step.revert ?? [];
  const done = step.state === "done";
  const n = language === "fa" ? new Intl.NumberFormat("fa-IR").format(index + 1) : String(index + 1);
  const params = Object.entries(step.params ?? {});

  return (
    <SectionCard
      title={`${say(language, COPY.step, { n })}: ${setupStepTitle(language, step.id, step)}`}
      hint={why ? pick(language, why) : undefined}
      status={<StatusPill tone={state.tone} label={state.label} />}
      collapsible={done}
      defaultCollapsed={done}
      tone={step.state === "warning" ? "warning" : "default"}
    >
      <Stack spacing={2} id={`mrk-dns-step-${step.id}`}>
        <Typography variant="body2" sx={{ lineHeight: 1.9 }} color={done ? "text.secondary" : "text.primary"}>
          {setupDetail(language, step)}
        </Typography>

        {step.id === "docker_daemon" && !done ? <Notice tone="warning">{pick(language, COPY.dockerWarning)}</Notice> : null}
        {(step.id === "host_resolver" || step.id === "docker_daemon") && !done ? (
          <Typography variant="caption" color="text.secondary">{pick(language, COPY.backupNote)}</Typography>
        ) : null}

        {commands.length ? (
          <Stack spacing={1.5}>
            <Box>
              <Typography variant="subtitle2" sx={{ fontWeight: 720 }}>{pick(language, COPY.commands)}</Typography>
              <Typography variant="caption" color="text.secondary">{pick(language, COPY.commandsHint)}</Typography>
            </Box>
            {commands.map((command, commandIndex) => (
              <CopyField key={command.id ?? commandIndex} label={commandTitle(language, command, commandIndex)} value={command.code} multiline />
            ))}
          </Stack>
        ) : !done ? (
          <Typography variant="body2" color="text.secondary">{pick(language, COPY.noCommands)}</Typography>
        ) : null}

        {revert.length ? (
          <Box>
            <Button size="small" startIcon={<UndoRoundedIcon />} onClick={() => setShowRevert((value) => !value)} aria-expanded={showRevert} sx={{ minHeight: 40 }}>
              {pick(language, showRevert ? COPY.hideRevert : COPY.showRevert)}
            </Button>
            <Collapse in={showRevert} unmountOnExit>
              <Stack spacing={1.5} sx={{ mt: 1.5 }}>
                <Typography variant="caption" color="text.secondary">{pick(language, COPY.revertHint)}</Typography>
                {revert.map((command, commandIndex) => (
                  <CopyField key={command.id ?? commandIndex} label={commandTitle(language, command, commandIndex)} value={command.code} multiline />
                ))}
              </Stack>
            </Collapse>
          </Box>
        ) : null}

        {isAdvanced ? (
          <KeyValueList
            dense
            items={[
              { label: pick(language, COPY.technicalCode), value: `${step.id} · ${step.detail_code ?? "—"}`, ltr: true },
              ...(params.length
                ? [{ label: pick(language, COPY.technicalParams), value: <Ltr mono>{params.map(([key, value]) => `${key}=${Array.isArray(value) ? value.join(",") : String(value)}`).join("  ")}</Ltr> }]
                : [])
            ]}
          />
        ) : null}
      </Stack>
    </SectionCard>
  );
}

export default function DnsSetupTab(_props: { permissions: readonly string[] }) {
  const { language } = useKit();
  const [setup, setSetup] = useState<DnsSetup | null>(null);
  const [error, setError] = useState<unknown>(null);
  const [loading, setLoading] = useState(false);
  const controller = useRef<AbortController | null>(null);

  const load = useCallback(async (refresh = false) => {
    controller.current?.abort();
    const current = new AbortController();
    controller.current = current;
    setLoading(true);
    try {
      setSetup(await fetchDnsSetup(current.signal, refresh));
      setError(null);
    } catch (caught) {
      if (isAbortError(caught) || (caught instanceof ApiError && caught.status === 401)) return;
      setError(caught);
    } finally {
      if (controller.current === current) setLoading(false);
    }
  }, []);

  useEffect(() => {
    void load();
    return () => controller.current?.abort();
  }, [load]);

  const steps = setup?.steps ?? [];
  const requiredSteps = steps.filter((step) => !isManualOptionalStep(step));
  const doneCount = requiredSteps.filter((step) => step.state === "done").length;
  const unknownCount = requiredSteps.filter((step) => step.state === "unknown").length;
  const allDone = steps.length > 0 && (setup?.complete ?? (requiredSteps.length > 0 && doneCount === requiredSteps.length));
  const number = (value: number) => (language === "fa" ? new Intl.NumberFormat("fa-IR").format(value) : String(value));

  const recheck = (
    <Button variant="contained" onClick={() => void load(true)} disabled={loading} startIcon={loading ? <CircularProgress size={16} color="inherit" /> : <RefreshRoundedIcon />} sx={{ minHeight: 44 }}>
      {pick(language, loading ? COPY.checking : COPY.recheck)}
    </Button>
  );

  if (error && !setup) {
    if (helperProblem(error) === "module_missing") return <Notice tone="info">{pick(language, COPY.moduleMissing)}</Notice>;
    return <FriendlyError error={error} title={pick(language, COPY.loadFailed)} onRetry={() => void load()} />;
  }

  return (
    <Stack spacing={2.5}>
      <SectionCard
        title={pick(language, { fa: "راه‌اندازی DNS روی سرور", en: "Set up DNS on the server" })}
        hint={pick(language, COPY.intro)}
        status={setup ? <StatusPill tone={allDone ? "ok" : "info"} label={say(language, COPY.progress, { done: number(doneCount), total: number(requiredSteps.length) })} /> : undefined}
      >
        <Stack spacing={1.5}>
          {setup ? <LinearProgress variant="determinate" value={requiredSteps.length ? (doneCount / requiredSteps.length) * 100 : 0} sx={{ height: 8, borderRadius: 99 }} aria-hidden /> : <LinearProgress aria-hidden />}
          {allDone ? (
            <Stack direction="row" alignItems="center" gap={1}>
              <CheckCircleRoundedIcon color="success" aria-hidden />
              <Typography variant="body2">{pick(language, COPY.allDone)}</Typography>
            </Stack>
          ) : null}
          {unknownCount > 0 ? <Notice tone="info">{pick(language, COPY.noAgent)}</Notice> : null}
          <Box>{recheck}</Box>
        </Stack>
      </SectionCard>
      {error && setup ? <FriendlyError error={error} title={pick(language, COPY.loadFailed)} onRetry={() => void load()} severity="warning" /> : null}
      {setup && !steps.length ? <Notice tone="info">{pick(language, COPY.empty)}</Notice> : null}
      {steps.map((step, index) => (
        <StepCard key={step.id} step={step} index={index} />
      ))}
      {steps.length > 2 ? <Box>{recheck}</Box> : null}
    </Stack>
  );
}
