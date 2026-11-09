/**
 * Small pieces shared by the «فضای من» pages: plain-Persian errors for quotas and plan features,
 * usage bars, the read-only notice and the domain-ownership steps (TXT / NS).
 */
import { Box, LinearProgress, Paper, Stack, Typography } from "@mui/material";
import LockClockRoundedIcon from "@mui/icons-material/LockClockRounded";
import type { Language } from "../i18n";
import { ApiError } from "../api";
import { errorSentence, FEATURE_WORDS, formatQuota, MY, MY_DNS, pick, quotaLabel, say, type FeatureKey } from "../copy";
import { CopyField, EmptyState, FriendlyError, Notice, useKit } from "../kit";
import type { UsageRow, VerificationMethod } from "./myApi";
import { useMySpace } from "./MySpaceContext";

/** One plain sentence for any My space failure; quota and plan errors name the limit and the numbers. */
export function myErrorSentence(language: Language, error: unknown): string {
  return errorSentence(language, error, "my");
}

const isPlanError = (error: unknown) =>
  error instanceof ApiError && (error.code === "quota_exceeded" || error.code === "QuotaExceeded" || error.code === "feature_disabled");

/** FriendlyError with the My space wording; plan limits are a calm warning, not a failure. */
export function MyError({ error, onRetry, onClose, title }: { error: unknown; onRetry?: () => void; onClose?: () => void; title?: string }) {
  const { language } = useKit();
  if (isPlanError(error)) return <Notice tone="warning">{myErrorSentence(language, error)}</Notice>;
  return <FriendlyError error={error} onRetry={onRetry} onClose={onClose} title={title} scope="my" />;
}

export function UsageBar({ row }: { row: UsageRow }) {
  const { language } = useKit();
  const used = formatQuota(language, row.key, row.used);
  const text = row.limit === null ? say(language, MY.usedUnlimited, { used }) : say(language, MY.usageOf, { used, limit: formatQuota(language, row.key, row.limit) });
  const color = row.level === "full" ? "error" : row.level === "near" ? "warning" : "primary";
  return (
    <Box>
      <Stack direction="row" justifyContent="space-between" alignItems="baseline" gap={1} sx={{ mb: 0.5 }}>
        <Typography variant="body2" fontWeight={650}>{quotaLabel(language, row.key)}</Typography>
        <Typography variant="caption" color={row.level === "ok" ? "text.secondary" : `${color}.main`} sx={{ whiteSpace: "nowrap" }}>{text}</Typography>
      </Stack>
      <LinearProgress
        variant="determinate"
        value={row.percent ?? 0}
        color={color}
        aria-label={`${quotaLabel(language, row.key)}: ${text}`}
        sx={{ height: 8, borderRadius: 4, opacity: row.limit === null ? 0.35 : 1 }}
      />
    </Box>
  );
}

/** Why this person can only look here (paused space, viewer role, read-only "view as"). */
export function ReadOnlyNotice() {
  const { language } = useKit();
  const { readOnlyReason } = useMySpace();
  if (!readOnlyReason || readOnlyReason === "viewAs") return null;
  return <Notice tone={readOnlyReason === "suspended" ? "warning" : "info"}>{pick(language, readOnlyReason === "suspended" ? MY.suspended : MY.readOnlyRole)}</Notice>;
}

/** The plan doesn't include this part. */
export function FeatureOff({ feature }: { feature: FeatureKey }) {
  const { language } = useKit();
  return (
    <EmptyState
      icon={LockClockRoundedIcon}
      title={pick(language, MY.featureOffTitle)}
      body={say(language, MY.featureOffBody, { feature: pick(language, FEATURE_WORDS[feature].label) })}
    />
  );
}

/** «ثابت کنید این دامنه مال شماست»: the TXT record and/or the name servers, each copyable. */
export function VerificationSteps({ methods }: { methods: VerificationMethod[] }) {
  const { language } = useKit();
  const txt = methods.find((item) => item.kind === "txt");
  const ns = methods.find((item) => item.kind === "ns");
  return (
    <Stack spacing={2}>
      {txt && (
        <Paper variant="outlined" sx={{ p: 2, borderRadius: 2 }}>
          <Typography fontWeight={720} sx={{ mb: 0.5 }}>{pick(language, MY_DNS.verifyTxt)}</Typography>
          <Typography variant="body2" color="text.secondary" sx={{ mb: 1.5 }}>{pick(language, MY_DNS.verifyTxtSteps)}</Typography>
          <Stack spacing={1.25}>
            <CopyField label={pick(language, MY_DNS.recordType)} value="TXT" />
            <CopyField label={pick(language, MY_DNS.recordHost)} value={txt.name ?? ""} />
            <CopyField label={pick(language, MY_DNS.recordValue)} value={txt.value ?? ""} />
          </Stack>
        </Paper>
      )}
      {ns && (ns.targets?.length ?? 0) > 0 && (
        <Paper variant="outlined" sx={{ p: 2, borderRadius: 2 }}>
          <Typography fontWeight={720} sx={{ mb: 0.5 }}>{pick(language, MY_DNS.verifyNs)}</Typography>
          <Typography variant="body2" color="text.secondary" sx={{ mb: 1.5 }}>{pick(language, MY_DNS.verifyNsSteps)}</Typography>
          <Stack spacing={1.25}>
            {(ns.targets ?? []).map((target, index) => (
              <CopyField key={target} label={say(language, MY_DNS.nameServer, { n: index + 1 })} value={target} />
            ))}
          </Stack>
        </Paper>
      )}
      <Typography variant="caption" color="text.secondary">{pick(language, MY_DNS.verifyWait)}</Typography>
    </Stack>
  );
}

