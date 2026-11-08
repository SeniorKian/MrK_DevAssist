/**
 * Docker tools (Server › Docker tools, Advanced only; container actions are also used on Server › overview):
 * start/stop/restart with confirmations, «دریافت نسخه برنامه» (image pull) and «پاک‌سازی موارد بی‌استفاده» (prune with preview).
 */
import { useCallback, useEffect, useState, type FormEvent } from "react";
import {
  Box,
  Button,
  Checkbox,
  CircularProgress,
  Divider,
  FormControlLabel,
  FormGroup,
  LinearProgress,
  MenuItem,
  Stack,
  TextField,
  Typography
} from "@mui/material";
import CloudDownloadRoundedIcon from "@mui/icons-material/CloudDownloadRounded";
import CleaningServicesRoundedIcon from "@mui/icons-material/CleaningServicesRounded";
import { ApiError, getJson, isAbortError, mutateJson } from "./api";
import type { Language } from "./i18n";
import {
  Bytes, ConfirmAction, FriendlyError, Ltr, Notice, Num, RelativeTime, SectionCard, useConfirmAction, useKit, formatSize,
  helperProblemText
} from "./kit";
import { CONFIRM_WORDS, errorSentence, nameConfirmation, pick, reasonFor, say, type Bi } from "./copy";

const BASE = "/api/v1/agent";

type Action = "start" | "stop" | "restart";

const COPY = {
  start: { fa: "روشن کن", en: "Start" },
  stop: { fa: "خاموش کن", en: "Stop" },
  restart: { fa: "راه‌اندازی دوباره", en: "Restart" },
  startTitle: { fa: "کانتینر «{name}» روشن شود؟", en: "Start container “{name}”?" },
  stopTitle: { fa: "کانتینر «{name}» خاموش شود؟", en: "Stop container “{name}”?" },
  restartTitle: { fa: "کانتینر «{name}» دوباره راه‌اندازی شود؟", en: "Restart container “{name}”?" },
  stopBody: { fa: "برنامه‌هایی که به این کانتینر وابسته‌اند تا روشن شدن دوباره کار نمی‌کنند.", en: "Anything that depends on this container stops working until it's started again." },
  restartBody: { fa: "کانتینر چند ثانیه از دسترس خارج می‌شود و دوباره بالا می‌آید.", en: "The container is unavailable for a few seconds, then comes back." },
  protectedBody: {
    fa: "این کانتینر مال Dokploy است. اگر خاموشش کنید یا دوباره راه‌اندازی‌اش کنید، ممکن است برنامه‌ها یا سایت‌ها از دسترس خارج شوند. فقط اگر مطمئنید ادامه دهید.",
    en: "This container belongs to Dokploy. Stopping or restarting it can take your apps or sites offline. Only continue if you're sure."
  },
  protectedNote: { fa: "این کار در تاریخچه فعالیت ثبت می‌شود.", en: "This is recorded in the activity history." },
  doneStart: { fa: "کانتینر «{name}» روشن شد.", en: "Container “{name}” started." },
  doneStop: { fa: "کانتینر «{name}» خاموش شد.", en: "Container “{name}” stopped." },
  doneRestart: { fa: "کانتینر «{name}» دوباره راه‌اندازی شد.", en: "Container “{name}” restarted." },

  pullTitle: { fa: "دریافت نسخه برنامه", en: "Download an app image" },
  pullHint: { fa: "یک نسخه برنامه را روی سرور دانلود می‌کند؛ چیزی را اجرا یا عوض نمی‌کند.", en: "Downloads an app image onto the server; nothing is started or replaced." },
  imageRef: { fa: "نام نسخه", en: "Image name" },
  imageRefHint: { fa: "نام و برچسب نسخه را بنویسید؛ مثل نمونه:", en: "Write the image name and tag, for example:" },
  imageRefRule: { fa: "نام نسخه فقط حروف انگلیسی، عدد و نشانه‌های . _ - / : @ دارد.", en: "An image name only has letters, digits and . _ - / : @" },
  pull: { fa: "دانلود کن", en: "Download" },
  pulling: { fa: "در حال دانلود…", en: "Downloading…" },
  pullOk: { fa: "نسخه «{image}» روی سرور دانلود شد.", en: "Image “{image}” was downloaded to the server." },
  pullFailed: { fa: "نسخه دانلود نشد.", en: "The image wasn't downloaded." },
  digest: { fa: "شناسه نسخه", en: "Digest" },
  started: { fa: "شروع شد", en: "Started" },

  pruneTitle: { fa: "پاک‌سازی موارد بی‌استفاده", en: "Clean up unused items" },
  pruneHint: { fa: "اول فهرست پاک‌شدنی‌ها را می‌بینید و بعد تصمیم می‌گیرید.", en: "You see the list of what would go first, then decide." },
  pruneSafety: {
    fa: "فضای داده کانتینرها (Volume) هیچ‌وقت پاک نمی‌شود. کانتینرها، شبکه‌ها و نسخه‌های Dokploy، و هر نسخه‌ای که کانتینری از آن استفاده می‌کند (حتی خاموش)، هم پاک نمی‌شوند.",
    en: "Container data (volumes) is never removed. Dokploy's containers, networks and images, and any image a container uses (even a stopped one), are never removed either."
  },
  targets: { fa: "چه چیزهایی پاک شود", en: "What to clean" },
  t_containers: { fa: "کانتینرهای خاموش (کانتینرهایی که عمداً خاموش کرده‌اید هم پاک می‌شوند؛ داده‌هایشان می‌ماند)", en: "Stopped containers (including ones you stopped on purpose; their data is kept)" },
  t_images: { fa: "نسخه‌های برنامه", en: "App images" },
  t_build_cache: { fa: "حافظه موقت ساخت", en: "Build cache" },
  t_networks: { fa: "شبکه‌های بی‌استفاده", en: "Unused networks" },
  imagesMode: { fa: "کدام نسخه‌ها", en: "Which images" },
  mode_dangling: { fa: "فقط نسخه‌های بی‌نام", en: "Only unnamed images" },
  mode_unused: { fa: "همه نسخه‌هایی که استفاده نمی‌شوند", en: "Every image that isn't used" },
  preview: { fa: "دیدن فهرست", en: "Show the list" },
  previewing: { fa: "در حال حساب کردن…", en: "Working it out…" },
  planTitle: { fa: "این موارد پاک شوند؟", en: "Remove these items?" },
  reclaimable: { fa: "فضایی که آزاد می‌شود", en: "Space freed" },
  containers: { fa: "کانتینرها", en: "Containers" },
  images: { fa: "نسخه‌های برنامه", en: "App images" },
  networks: { fa: "شبکه‌ها", en: "Networks" },
  buildCache: { fa: "حافظه موقت ساخت", en: "Build cache" },
  more: { fa: "و {n} مورد دیگر", en: "and {n} more" },
  nothing: { fa: "چیزی برای پاک کردن نیست؛ سرور تمیز است.", en: "Nothing to remove; the server is tidy." },
  execute: { fa: "پاک کن", en: "Clean up" },
  planChanged: { fa: "از وقتی فهرست را دیدید چیزهایی عوض شده. فهرست تازه را یک بار دیگر ببینید.", en: "Things changed since you looked. Review the fresh list once more." },
  pruneDone: { fa: "پاک‌سازی تمام شد و {bytes} آزاد شد.", en: "Clean-up finished; {bytes} freed." },
  removedLine: { fa: "پاک‌شده: {c} کانتینر، {i} نسخه و {n} شبکه.", en: "Removed: {c} containers, {i} images and {n} networks." },
  someFailed: { fa: "{n} مورد پاک نشد. فهرست را تازه کنید و دوباره امتحان کنید.", en: "{n} items weren't removed. Refresh and try again." },
  untagged: { fa: "بی‌نام", en: "unnamed" },
} satisfies Record<string, Bi>;

/** Module missing / not paired / helper down get the shared sentences; specific backend codes use copy/errors.ts. */
export function dockerErrorText(language: Language, error: unknown) {
  return helperProblemText(language, error) ?? errorSentence(language, error);
}

export type ActionContainer = { id: string; name: string; state: string; protected: boolean };

export function cleanName(name: string) {
  return name.replace(/^\//, "");
}

export function isRunning(state: string) {
  return state === "running" || state === "restarting";
}

const TITLE: Record<Action, Bi> = { start: COPY.startTitle, stop: COPY.stopTitle, restart: COPY.restartTitle };
const DONE: Record<Action, Bi> = { start: COPY.doneStart, stop: COPY.doneStop, restart: COPY.doneRestart };

export function actionLabel(language: Language, action: Action) {
  return pick(language, COPY[action]);
}

/**
 * Start/stop/restart with the right confirmation: none for start, a simple confirm for stop/restart,
 * and a typed container name for protected (Dokploy) containers. Render `dialog` once.
 */
export function useContainerActions({ onDone, onError }: { onDone: (message: string) => void; onError: (error: unknown) => void }) {
  const { language } = useKit();
  const { ask, dialog } = useConfirmAction();
  const [busy, setBusy] = useState<string | null>(null);

  const run = useCallback(
    async (container: ActionContainer, action: Action) => {
      const name = cleanName(container.name);
      const label = pick(language, COPY[action]);
      if (container.protected) {
        const ok = await ask({
          title: say(language, TITLE[action], { name }),
          body: pick(language, COPY.protectedBody),
          consequences: [pick(language, COPY.protectedNote)],
          severity: "destructive",
          typed: nameConfirmation(name, name),
          confirmLabel: label
        });
        if (!ok) return;
      } else if (action !== "start") {
        const ok = await ask({
          title: say(language, TITLE[action], { name }),
          body: pick(language, action === "stop" ? COPY.stopBody : COPY.restartBody),
          severity: "disruptive",
          undoable: true,
          confirmLabel: label
        });
        if (!ok) return;
      }
      setBusy(container.id);
      try {
        const body: { action: Action; allow_protected?: boolean; confirmation?: string } = { action };
        if (container.protected) {
          body.allow_protected = true;
          body.confirmation = name;
        }
        await mutateJson(`${BASE}/containers/${encodeURIComponent(container.id)}/action`, { method: "POST", body });
        onDone(say(language, DONE[action], { name }));
      } catch (caught) {
        if (!(caught instanceof ApiError && caught.status === 401)) onError(caught);
      } finally {
        setBusy(null);
      }
    },
    [ask, language, onDone, onError]
  );

  return { run, busy, dialog };
}

// ── Pull ─────────────────────────────────────────────────────────────────────

type Job = { id: string; kind: string; state: "running" | "succeeded" | "failed"; result?: { digest?: string } | null; error_code?: string | null; started_at?: number | string | null };

const IMAGE_PATTERN = /^[A-Za-z0-9][A-Za-z0-9._\-/:@]{0,254}$/;

export function PullImageCard() {
  const { language, isAdvanced } = useKit();
  const [image, setImage] = useState("");
  const [submitting, setSubmitting] = useState(false);
  const [jobId, setJobId] = useState<string | null>(null);
  const [job, setJob] = useState<Job | null>(null);
  const [result, setResult] = useState<{ ok: boolean; image: string; digest?: string; code?: string } | null>(null);
  const [error, setError] = useState<unknown>(null);
  const trimmed = image.trim();
  const valid = IMAGE_PATTERN.test(trimmed) && !trimmed.includes("..");

  useEffect(() => {
    if (!jobId) return;
    const controller = new AbortController();
    let timer: number | undefined;
    const tick = async () => {
      try {
        const next = await getJson<Job>(`${BASE}/jobs/${encodeURIComponent(jobId)}`, controller.signal);
        setJob(next);
        if (next.state === "running") timer = window.setTimeout(() => void tick(), 2000);
        else {
          setResult((previous) => ({ ok: next.state === "succeeded", image: previous?.image ?? "", digest: next.result?.digest, code: next.error_code ?? undefined }));
          setJobId(null);
        }
      } catch (caught) {
        if (isAbortError(caught) || (caught instanceof ApiError && caught.status === 401)) return;
        setError(caught);
        setJobId(null);
      }
    };
    void tick();
    return () => {
      controller.abort();
      window.clearTimeout(timer);
    };
  }, [jobId]);

  const submit = async (event: FormEvent) => {
    event.preventDefault();
    if (!valid || submitting || jobId) return;
    setSubmitting(true);
    setError(null);
    setResult(null);
    setJob(null);
    try {
      const response = await mutateJson<{ job_id?: string; ok?: boolean; digest?: string }>(`${BASE}/images/pull`, { method: "POST", body: { image: trimmed } });
      if (response?.job_id) {
        setResult({ ok: false, image: trimmed });
        setJobId(response.job_id);
      } else setResult({ ok: Boolean(response?.ok ?? true), image: trimmed, digest: response?.digest });
    } catch (caught) {
      if (!(caught instanceof ApiError && caught.status === 401)) setError(caught);
    } finally {
      setSubmitting(false);
    }
  };

  const running = submitting || jobId !== null;
  return (
    <SectionCard title={pick(language, COPY.pullTitle)} hint={pick(language, COPY.pullHint)}>
      <Box component="form" onSubmit={submit} noValidate>
        <Stack direction={{ xs: "column", sm: "row" }} spacing={1.5} alignItems={{ sm: "flex-start" }}>
          <TextField
            fullWidth
            size="small"
            label={pick(language, COPY.imageRef)}
            value={image}
            disabled={running}
            error={image.length > 0 && !valid}
            helperText={image.length > 0 && !valid ? pick(language, COPY.imageRefRule) : <>{pick(language, COPY.imageRefHint)} <Ltr mono>nginx:1.27</Ltr></>}
            onChange={(event) => setImage(event.target.value)}
            slotProps={{ htmlInput: { dir: "ltr", autoComplete: "off", spellCheck: false } }}
          />
          <Button type="submit" variant="contained" disabled={!valid || running} startIcon={running ? <CircularProgress size={16} color="inherit" /> : <CloudDownloadRoundedIcon />} sx={{ flexShrink: 0, minHeight: 40 }}>
            {running ? pick(language, COPY.pulling) : pick(language, COPY.pull)}
          </Button>
        </Stack>
      </Box>
      {running && (
        <Box sx={{ mt: 2 }} role="status">
          <LinearProgress aria-label={pick(language, COPY.pulling)} />
          {job?.started_at && <Typography variant="caption" color="text.secondary">{pick(language, COPY.started)}: <RelativeTime value={job.started_at} /></Typography>}
        </Box>
      )}
      {result && !running && (
        <Box sx={{ mt: 2 }}>
          {result.ok ? (
            <Notice tone="success">
              {say(language, COPY.pullOk, { image: result.image })}
              {isAdvanced && result.digest && <Box sx={{ mt: 0.5, fontSize: 12 }}>{pick(language, COPY.digest)}: <Ltr mono>{result.digest}</Ltr></Box>}
            </Notice>
          ) : (
            <Notice tone="error">{pick(language, COPY.pullFailed)} {reasonFor(language, result.code)}</Notice>
          )}
        </Box>
      )}
      {error !== null && <Box sx={{ mt: 2 }}><FriendlyError error={error} onClose={() => setError(null)} /></Box>}
    </SectionCard>
  );
}

// ── Prune ────────────────────────────────────────────────────────────────────

type Target = "containers" | "images" | "build_cache" | "networks";
const TARGETS: Target[] = ["containers", "images", "build_cache", "networks"];
type PrunePlan = {
  token: string;
  containers?: Array<{ id: string; name: string; size_bytes?: number }>;
  images?: Array<{ id: string; tags?: string[]; size_bytes?: number }>;
  networks?: Array<{ id: string; name: string }>;
  build_cache_bytes?: number;
  reclaimable_bytes?: number;
};
type PruneResult = { removed?: { containers?: number; images?: number; networks?: number }; reclaimed_bytes?: number; errors?: unknown[] };

const LIST_LIMIT = 40;

function PlanList({ title, items }: { title: string; items: Array<{ key: string; label: string; size?: number }> }) {
  const { language } = useKit();
  if (items.length === 0) return null;
  return (
    <Box>
      <Typography variant="subtitle2">{title} (<Num value={items.length} />)</Typography>
      <Stack divider={<Divider flexItem />} sx={{ mt: 0.5 }}>
        {items.slice(0, LIST_LIMIT).map((item) => (
          <Stack key={item.key} direction="row" justifyContent="space-between" spacing={1} sx={{ py: 0.5, minWidth: 0 }}>
            <Typography variant="body2" noWrap title={item.label} sx={{ minWidth: 0 }}><Ltr>{item.label}</Ltr></Typography>
            {item.size !== undefined && <Typography variant="body2" color="text.secondary" sx={{ flexShrink: 0 }}><Bytes value={item.size} /></Typography>}
          </Stack>
        ))}
      </Stack>
      {items.length > LIST_LIMIT && <Typography variant="caption" color="text.secondary">{say(language, COPY.more, { n: items.length - LIST_LIMIT })}</Typography>}
    </Box>
  );
}

export function PruneCard() {
  const { language } = useKit();
  const [targets, setTargets] = useState<Record<Target, boolean>>({ containers: false, images: true, build_cache: true, networks: false });
  const [imagesMode, setImagesMode] = useState<"dangling" | "unused">("dangling");
  const [previewing, setPreviewing] = useState(false);
  const [plan, setPlan] = useState<PrunePlan | null>(null);
  const [planRevision, setPlanRevision] = useState(0);
  const [planChanged, setPlanChanged] = useState(false);
  const [executing, setExecuting] = useState(false);
  const [dialogError, setDialogError] = useState<unknown>(null);
  const [error, setError] = useState<unknown>(null);
  const [result, setResult] = useState<PruneResult | null>(null);
  const selected = TARGETS.filter((target) => targets[target]);
  const body = () => ({ targets: selected, images_mode: imagesMode });

  const preview = async (afterChange = false) => {
    setPreviewing(true);
    setError(null);
    if (!afterChange) setResult(null);
    try {
      const next = await mutateJson<PrunePlan>(`${BASE}/prune/preview`, { method: "POST", body: body() });
      setPlan(next);
      setPlanRevision((value) => value + 1);
      setPlanChanged(afterChange);
      setDialogError(null);
    } catch (caught) {
      if (!(caught instanceof ApiError && caught.status === 401)) {
        if (afterChange) setDialogError(caught);
        else setError(caught);
      }
    } finally {
      setPreviewing(false);
    }
  };

  const execute = async () => {
    if (!plan) return;
    setExecuting(true);
    setDialogError(null);
    try {
      const outcome = await mutateJson<PruneResult>(`${BASE}/prune`, { method: "POST", body: { token: plan.token, ...body(), confirmation: CONFIRM_WORDS.prune.token } });
      setResult(outcome ?? {});
      setPlan(null);
    } catch (caught) {
      if (caught instanceof ApiError && caught.status === 401) return;
      if (caught instanceof ApiError && caught.code === "plan_changed") await preview(true);
      else setDialogError(caught);
    } finally {
      setExecuting(false);
    }
  };

  const containers = (plan?.containers ?? []).map((item) => ({ key: item.id, label: cleanName(item.name), size: item.size_bytes }));
  const images = (plan?.images ?? []).map((item) => ({
    key: item.id,
    label: item.tags?.length ? item.tags.join(", ") : `${pick(language, COPY.untagged)} · ${item.id.replace(/^sha256:/, "").slice(0, 12)}`,
    size: item.size_bytes
  }));
  const networks = (plan?.networks ?? []).map((item) => ({ key: item.id, label: item.name }));
  const buildCache = plan?.build_cache_bytes ?? 0;
  const empty = containers.length + images.length + networks.length === 0 && buildCache <= 0;
  const failed = result?.errors?.length ?? 0;

  return (
    <SectionCard title={pick(language, COPY.pruneTitle)} hint={pick(language, COPY.pruneHint)}>
      <Stack spacing={1.5}>
        <Notice>{pick(language, COPY.pruneSafety)}</Notice>
        <Box>
          <Typography variant="subtitle2" id="mrk-prune-targets">{pick(language, COPY.targets)}</Typography>
          <FormGroup aria-labelledby="mrk-prune-targets">
            {TARGETS.map((target) => (
              <FormControlLabel
                key={target}
                sx={{ minHeight: 44 }}
                control={<Checkbox checked={targets[target]} onChange={(event) => setTargets((value) => ({ ...value, [target]: event.target.checked }))} />}
                label={pick(language, COPY[`t_${target}`])}
              />
            ))}
          </FormGroup>
        </Box>
        <Stack direction={{ xs: "column", sm: "row" }} spacing={1.5} alignItems={{ sm: "center" }}>
          <TextField select size="small" label={pick(language, COPY.imagesMode)} value={imagesMode} disabled={!targets.images} onChange={(event) => setImagesMode(event.target.value as "dangling" | "unused")} sx={{ minWidth: 260 }}>
            <MenuItem value="dangling">{pick(language, COPY.mode_dangling)}</MenuItem>
            <MenuItem value="unused">{pick(language, COPY.mode_unused)}</MenuItem>
          </TextField>
          <Button variant="contained" color="warning" disabled={selected.length === 0 || previewing} startIcon={previewing ? <CircularProgress size={16} color="inherit" /> : <CleaningServicesRoundedIcon />} onClick={() => void preview()} sx={{ minHeight: 40 }}>
            {previewing ? pick(language, COPY.previewing) : pick(language, COPY.preview)}
          </Button>
        </Stack>
        {error !== null && <FriendlyError error={error} onRetry={() => void preview()} onClose={() => setError(null)} />}
        {result && (
          <Notice tone={failed > 0 ? "warning" : "success"}>
            <Typography variant="body2" fontWeight={700}>{say(language, COPY.pruneDone, { bytes: formatSize(result.reclaimed_bytes ?? 0, language) })}</Typography>
            <Typography variant="body2">
              {say(language, COPY.removedLine, { c: result.removed?.containers ?? 0, i: result.removed?.images ?? 0, n: result.removed?.networks ?? 0 })}
            </Typography>
            {failed > 0 && <Typography variant="body2">{say(language, COPY.someFailed, { n: failed })}</Typography>}
          </Notice>
        )}
      </Stack>
      {plan && (
        <ConfirmAction
          key={planRevision}
          open
          title={pick(language, COPY.planTitle)}
          severity="destructive"
          undoable={false}
          typed={empty ? undefined : CONFIRM_WORDS.prune}
          confirmLabel={pick(language, COPY.execute)}
          confirmDisabled={empty || previewing}
          busy={executing}
          error={dialogError}
          onConfirm={() => void execute()}
          onClose={() => { setPlan(null); setPlanChanged(false); setDialogError(null); }}
        >
          <Stack spacing={2}>
            {planChanged && <Notice tone="warning">{pick(language, COPY.planChanged)}</Notice>}
            <Stack direction="row" justifyContent="space-between" alignItems="baseline">
              <Typography variant="body2" color="text.secondary">{pick(language, COPY.reclaimable)}</Typography>
              <Typography variant="h6" fontWeight={780}><Bytes value={plan.reclaimable_bytes ?? 0} /></Typography>
            </Stack>
            {empty ? <Typography variant="body2" color="text.secondary">{pick(language, COPY.nothing)}</Typography> : (
              <Stack spacing={1.5} sx={{ maxHeight: 320, overflow: "auto" }}>
                <PlanList title={pick(language, COPY.containers)} items={containers} />
                <PlanList title={pick(language, COPY.images)} items={images} />
                <PlanList title={pick(language, COPY.networks)} items={networks} />
                {buildCache > 0 && (
                  <Stack direction="row" justifyContent="space-between">
                    <Typography variant="subtitle2">{pick(language, COPY.buildCache)}</Typography>
                    <Typography variant="body2" color="text.secondary"><Bytes value={buildCache} /></Typography>
                  </Stack>
                )}
              </Stack>
            )}
            <Typography variant="caption" color="text.secondary">{pick(language, COPY.pruneSafety)}</Typography>
          </Stack>
        </ConfirmAction>
      )}
    </SectionCard>
  );
}

/** Server › Docker tools tab body (Advanced only): pull and prune, each gated by its own permission. */
export function DockerToolsSection({ canOperate, canPrune }: { canOperate: boolean; canPrune: boolean }) {
  return (
    <Stack spacing={2.5}>
      {canOperate && <PullImageCard />}
      {canPrune && <PruneCard />}
    </Stack>
  );
}
