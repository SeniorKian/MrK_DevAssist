/**
 * Where a service keeps its data, asked in the add-service wizard.
 *
 * `GET /api/v1/install/{id}/storage` lists the slots. Own slots: a Docker volume (default)
 * or a folder on the server. Shared slots (the panel writes or reads the same data) follow
 * the panel's own mount and are shown read-only. `POST /api/v1/install/{id}/storage/check`
 * checks chosen folders through the server agent and gives the commands to fix them.
 */
import { useEffect, useState } from "react";
import { Box, Button, FormControlLabel, Radio, RadioGroup, Skeleton, Stack, TextField, Typography } from "@mui/material";
import FactCheckRoundedIcon from "@mui/icons-material/FactCheckRounded";
import { getJson, isAbortError, mutateJson } from "./api";
import { pick, type Bi } from "./copy";
import { CopyField, FriendlyError, Ltr, Notice, StatusPill, useKit } from "./kit";

export type StorageChoice = { kind: "volume" | "path"; value: string };
export type StorageChoices = Record<string, StorageChoice>;

type PanelSource = { kind: "path" | "volume" | "missing" | "unknown" | "native"; value: string | null; inside_volume?: string | null };
type Slot = {
  key: string;
  target: string;
  volume: string;
  label_fa: string;
  label_en: string;
  owner: string | null;
  shared: boolean;
  panel_path: string | null;
  shared_with: { service: string; container: string; path: string } | null;
  suggested_path: string;
  choice: StorageChoice;
  panel?: PanelSource;
};
type StorageView = { id: string; slots: Slot[]; panel_mounts_source: "agent" | "dokploy" | "none"; checks_available: boolean };
type CheckItem = { key: string; kind: "volume" | "path"; path?: string; status: "ok" | "warn" | "error" | "unknown"; code: string | null; fix?: string | null; owner?: string; free_bytes?: number };
type CheckResult = { items: CheckItem[]; ok: boolean; checked: boolean };

const COPY = {
  title: { fa: "جای نگهداری داده‌ها", en: "Where the data is kept" },
  hint: {
    fa: "پیش‌فرض یک والیوم داکر است. اگر می‌خواهید داده‌ها در پوشه مشخصی روی سرور باشند (مثلاً دیسک جدا)، «پوشه روی سرور» را انتخاب کنید.",
    en: "The default is a Docker volume. To keep the data in a specific folder on the server (for example a separate disk), pick “Folder on the server”."
  },
  volume: { fa: "والیوم داکر", en: "Docker volume" },
  folder: { fa: "پوشه روی سرور", en: "Folder on the server" },
  folderLabel: { fa: "مسیر کامل پوشه", en: "Full folder path" },
  owner: { fa: "مالک پوشه باید {owner} باشد؛ سرویس با همین کاربر اجرا می‌شود.", en: "The folder must belong to {owner}; the service runs as that user." },
  shared: {
    fa: "مشترک با سرویس «پنل»: این پوشه در سرویس جدید ({target}) باید به همان جایی وصل شود که پنل در مسیر {panelPath} دارد. پنل این را خودش پیدا کرد و در فایل‌ها گذاشت:",
    en: "Shared with the “panel” service: in the new service ({target}) this must connect to the same place the panel has at {panelPath}. The panel found it and put it in the files:"
  },
  sharedKeep: {
    fa: "اگر بعداً جای این داده را در پنل عوض کردید، همین خط را در این سرویس هم عوض کنید؛ این دو همیشه باید یکی باشند.",
    en: "If you later move this data in the panel, change this line in this service too; the two must always match."
  },
  sharedSummary: {
    fa: "این سرویس با سرویس‌های قبلی پوشه مشترک دارد. اتصال‌ها:",
    en: "This service shares folders with earlier services. Connections:"
  },
  sharedMissing: {
    fa: "پنل این پوشه را جدا وصل نکرده، پس دو سرویس نمی‌توانند آن را با هم ببینند. اول این خط را به والیوم‌های سرویس «پنل» اضافه کنید، پوشه را با دستور زیر بسازید، پنل را دوباره منتشر کنید و بعد این صفحه را دوباره باز کنید. سرویس جدید هم همین پوشه را می‌گیرد:",
    en: "The panel doesn't mount this folder on its own, so the two services can't share it. First add this line to the “panel” service's volumes, create the folder with the command below, redeploy the panel, then open this page again. The new service gets the same folder:"
  },
  panelLine: { fa: "خط سرویس پنل", en: "Line for the panel service" },
  serviceLine: { fa: "خط سرویس جدید", en: "Line for the new service" },
  createFolder: { fa: "ساخت پوشه روی سرور", en: "Create the folder on the server" },
  sharedUnknown: {
    fa: "پنل نتوانست ببیند خودش این داده را کجا نگه می‌دارد (دستیار سرور یا Dokploy وصل نیست). پیش‌فرض والیومی با نام زیر است:",
    en: "The panel couldn't see where it keeps this data itself (the server agent or Dokploy isn't connected). The default is the volume:"
  },
  fromAgent: { fa: "از کانتینر خود پنل خوانده شد.", en: "Read from the panel's own container." },
  fromDokploy: { fa: "از فایل compose پنل در Dokploy خوانده شد.", en: "Read from the panel's compose file in Dokploy." },
  check: { fa: "بررسی پوشه‌ها", en: "Check the folders" },
  checking: { fa: "در حال بررسی…", en: "Checking…" },
  noChecks: {
    fa: "دستیار سرور وصل نیست، پس پوشه‌ها بررسی نمی‌شوند. قبل از نصب مطمئن شوید پوشه وجود دارد و مالکش درست است.",
    en: "The server agent isn't connected, so folders can't be checked. Before installing, make sure the folder exists and has the right owner."
  },
  allGood: { fa: "همه پوشه‌ها آماده‌اند.", en: "Every folder is ready." },
  fixFirst: { fa: "قبل از نصب این دستورها را روی سرور اجرا کنید:", en: "Run these commands on the server before installing:" }
} satisfies Record<string, Bi>;

const CODES: Record<string, Bi> = {
  path_missing: { fa: "این پوشه هنوز وجود ندارد.", en: "This folder doesn't exist yet." },
  path_wrong_owner: { fa: "مالک این پوشه درست نیست.", en: "This folder has the wrong owner." },
  path_not_folder: { fa: "این مسیر پوشه نیست.", en: "This path isn't a folder." },
  path_refused: { fa: "این مسیر برای داده مناسب نیست.", en: "This path can't hold data." },
  low_space: { fa: "کمتر از ۱ گیگابایت جای خالی مانده است.", en: "Less than 1 GB of free space is left." },
  not_checked: { fa: "بررسی نشد.", en: "Not checked." }
};

export function useStorage(serviceId: string) {
  const [view, setView] = useState<StorageView | null>(null);
  const [error, setError] = useState<unknown>(null);
  const [choices, setChoices] = useState<StorageChoices>({});
  useEffect(() => {
    const controller = new AbortController();
    getJson<StorageView>(`/api/v1/install/${serviceId}/storage`, controller.signal)
      .then((payload) => {
        setView(payload);
        setChoices(Object.fromEntries(payload.slots.map((slot) => [slot.key, slot.choice])));
      })
      .catch((caught) => {
        if (!isAbortError(caught)) setError(caught);
      });
    return () => controller.abort();
  }, [serviceId]);
  // Only own slots are sent; shared ones always follow the panel on the server side.
  const request = view ? Object.fromEntries(view.slots.filter((slot) => !slot.shared).map((slot) => [slot.key, choices[slot.key] ?? slot.choice])) : {};
  return { view, error, choices, setChoices, request };
}

export function InstallStorage({ serviceId, storage }: { serviceId: string; storage: ReturnType<typeof useStorage> }) {
  const { language } = useKit();
  const { view, error, choices, setChoices, request } = storage;
  const [result, setResult] = useState<CheckResult | null>(null);
  const [checking, setChecking] = useState(false);
  const [checkError, setCheckError] = useState<unknown>(null);

  if (error) return <FriendlyError error={error} inline />;
  if (!view) return <Skeleton variant="rounded" height={88} />;
  if (view.slots.length === 0) return null;

  const set = (key: string, choice: StorageChoice) => {
    setChoices((current) => ({ ...current, [key]: choice }));
    setResult(null);
  };
  const check = async () => {
    setChecking(true);
    setCheckError(null);
    try {
      setResult(await mutateJson<CheckResult>(`/api/v1/install/${serviceId}/storage/check`, { method: "POST", body: { storage: request } }));
    } catch (caught) {
      setCheckError(caught);
    } finally {
      setChecking(false);
    }
  };
  const byKey = Object.fromEntries((result?.items ?? []).map((item) => [item.key, item]));
  const fixes = (result?.items ?? []).map((item) => item.fix).filter((fix): fix is string => Boolean(fix));
  const anyFolder = view.slots.some((slot) => slot.shared ? slot.choice.kind === "path" : choices[slot.key]?.kind === "path");

  return (
    <Stack spacing={1.5}>
      <Box>
        <Typography variant="subtitle2">{pick(language, COPY.title)}</Typography>
        <Typography variant="body2" color="text.secondary">{pick(language, COPY.hint)}</Typography>
      </Box>
      {view.slots.some((slot) => slot.shared) ? (
        <Notice tone="info">
          {pick(language, COPY.sharedSummary)}
          <Box component="ul" sx={{ m: 0, mt: 0.5, ps: 2.5 }}>
            {view.slots.filter((slot) => slot.shared).map((slot) => (
              <li key={slot.key}>
                <Ltr mono>{`${slot.shared_with?.container ?? "mrk-panel"}:${slot.panel_path}`}</Ltr>{" ⟷ "}<Ltr mono>{`${serviceId}:${slot.target}`}</Ltr>
              </li>
            ))}
          </Box>
        </Notice>
      ) : null}
      {view.slots.map((slot) => {
        const label = language === "fa" ? slot.label_fa : slot.label_en;
        const checked = byKey[slot.key];
        const pill = checked && checked.kind === "path" ? (
          <StatusPill tone={checked.status === "ok" ? "ok" : checked.status === "error" ? "warn" : "off"}
            label={checked.status === "ok" ? pick(language, COPY.allGood) : pick(language, CODES[checked.code ?? "not_checked"] ?? CODES.not_checked)} />
        ) : null;
        if (slot.shared) {
          const panel = slot.panel ?? { kind: "unknown", value: null };
          return (
            <Box key={slot.key} sx={{ p: 1.5, border: 1, borderColor: "divider", borderRadius: 2 }}>
              <Stack direction="row" spacing={1} alignItems="center" flexWrap="wrap" useFlexGap>
                <Typography fontWeight={600}>{label}</Typography>
                {pill}
              </Stack>
              {panel.kind === "path" || panel.kind === "volume" ? (
                <Stack spacing={0.5} sx={{ mt: 0.5 }}>
                  <Typography variant="body2" color="text.secondary">
                    {pick(language, COPY.shared).replace("{target}", slot.target).replace("{panelPath}", slot.panel_path ?? "")}
                  </Typography>
                  <Ltr mono>{`${panel.value}:${slot.target}`}</Ltr>
                  <Typography variant="caption" color="text.secondary">
                    {pick(language, view.panel_mounts_source === "dokploy" ? COPY.fromDokploy : COPY.fromAgent)} {pick(language, COPY.sharedKeep)}
                  </Typography>
                </Stack>
              ) : panel.kind === "missing" ? (
                <Stack spacing={1} sx={{ mt: 1 }}>
                  <Notice tone="warning">{pick(language, COPY.sharedMissing)}</Notice>
                  <CopyField label={pick(language, COPY.panelLine)} value={`- ${slot.suggested_path}:${slot.panel_path}`} />
                  <CopyField label={pick(language, COPY.createFolder)} value={`sudo mkdir -p ${slot.suggested_path}${slot.owner ? ` && sudo chown -R ${slot.owner} ${slot.suggested_path}` : ""}`} />
                  <CopyField label={pick(language, COPY.serviceLine)} value={`- ${slot.suggested_path}:${slot.target}`} />
                </Stack>
              ) : panel.kind === "unknown" ? (
                <Typography variant="body2" color="text.secondary" sx={{ mt: 0.5 }}>
                  {pick(language, COPY.sharedUnknown)} <Ltr mono>{slot.volume}</Ltr>
                </Typography>
              ) : null}
            </Box>
          );
        }
        const choice = choices[slot.key] ?? slot.choice;
        return (
          <Box key={slot.key} sx={{ p: 1.5, border: 1, borderColor: "divider", borderRadius: 2 }}>
            <Stack direction="row" spacing={1} alignItems="center" flexWrap="wrap" useFlexGap>
              <Typography fontWeight={600}>{label}</Typography>
              {pill}
            </Stack>
            <RadioGroup row value={choice.kind}
              onChange={(event) => set(slot.key, event.target.value === "path"
                ? { kind: "path", value: choice.kind === "path" ? choice.value : slot.suggested_path }
                : { kind: "volume", value: slot.volume })}>
              <FormControlLabel value="volume" control={<Radio size="small" />} label={pick(language, COPY.volume)} />
              <FormControlLabel value="path" control={<Radio size="small" />} label={pick(language, COPY.folder)} />
            </RadioGroup>
            {choice.kind === "path" ? (
              <TextField
                label={pick(language, COPY.folderLabel)}
                value={choice.value}
                onChange={(event) => set(slot.key, { kind: "path", value: event.target.value })}
                helperText={slot.owner ? pick(language, COPY.owner).replace("{owner}", slot.owner) : undefined}
                slotProps={{ htmlInput: { dir: "ltr", spellCheck: false } }}
                size="small"
                fullWidth
              />
            ) : (
              <Typography variant="caption" color="text.secondary"><Ltr mono>{`${slot.volume}:${slot.target}`}</Ltr></Typography>
            )}
          </Box>
        );
      })}
      {anyFolder ? (
        view.checks_available ? (
          <Stack spacing={1}>
            <Box>
              <Button variant="outlined" onClick={() => void check()} disabled={checking} startIcon={<FactCheckRoundedIcon />}>
                {pick(language, checking ? COPY.checking : COPY.check)}
              </Button>
            </Box>
            {checkError ? <FriendlyError error={checkError} inline /> : null}
            {result && result.ok && fixes.length === 0 ? <Notice tone="success">{pick(language, COPY.allGood)}</Notice> : null}
            {fixes.length > 0 ? (
              <Stack spacing={1}>
                <Notice tone={result?.ok ? "info" : "warning"}>{pick(language, COPY.fixFirst)}</Notice>
                <CopyField label="bash" value={fixes.join("\n")} />
              </Stack>
            ) : null}
          </Stack>
        ) : (
          <Notice tone="info">{pick(language, COPY.noChecks)}</Notice>
        )
      ) : null}
    </Stack>
  );
}
