/**
 * «کاربران و دسترسی» › My space admin (docs/43 §2, §4; permission `tenancy:admin`):
 * - plans: features on/off + limits («بی‌سقف» = no limit), default plan;
 * - workspaces: usage, change plan / per-space exceptions, pause, delete or hand resources to the system
 *   (typed slug), ownership transfer of one resource, «دیدن به‌جای صاحب فضا» (read-only by default);
 * - pending sign-ups: approve (with a plan) / reject;
 * - settings: My space on/off, sign-up mode (off / approval / open), default plan, domain proof, admin area local only.
 */
import { useCallback, useEffect, useMemo, useState } from "react";
import {
  Box, Button, Checkbox, Chip, Dialog, DialogActions, DialogContent, DialogTitle, Divider, FormControlLabel, InputAdornment, MenuItem, Radio,
  RadioGroup, Stack, Switch, TextField, ToggleButton, ToggleButtonGroup, Typography, useMediaQuery, useTheme
} from "@mui/material";
import AddRoundedIcon from "@mui/icons-material/AddRounded";
import EditRoundedIcon from "@mui/icons-material/EditRounded";
import DeleteOutlineRoundedIcon from "@mui/icons-material/DeleteOutlineRounded";
import SearchRoundedIcon from "@mui/icons-material/SearchRounded";
import InfoRoundedIcon from "@mui/icons-material/InfoRounded";
import TuneRoundedIcon from "@mui/icons-material/TuneRounded";
import PauseCircleRoundedIcon from "@mui/icons-material/PauseCircleRounded";
import PlayCircleRoundedIcon from "@mui/icons-material/PlayCircleRounded";
import VisibilityRoundedIcon from "@mui/icons-material/VisibilityRounded";
import SwapHorizRoundedIcon from "@mui/icons-material/SwapHorizRounded";
import WorkspacesRoundedIcon from "@mui/icons-material/WorkspacesRounded";
import HowToRegRoundedIcon from "@mui/icons-material/HowToRegRounded";
import PersonOffRoundedIcon from "@mui/icons-material/PersonOffRounded";
import Inventory2RoundedIcon from "@mui/icons-material/Inventory2Rounded";
import LockRoundedIcon from "@mui/icons-material/LockRounded";
import HourglassTopRoundedIcon from "@mui/icons-material/HourglassTopRounded";
import PublicRoundedIcon from "@mui/icons-material/PublicRounded";
import { hasPermission } from "../api";
import type { AuthUser } from "../App";
import {
  errorSentence, FEATURE_KEYS, FEATURE_WORDS, formatQuota, MY, nameConfirmation, pick, QUOTA_KEYS, QUOTA_WORDS, say, TENANCY, workspaceRoleName, type FeatureKey,
  type QuotaKey
} from "../copy";
import {
  BytesInput, ChoiceCards, ConfirmAction, EmptyState, FriendlyError, KeyValueList, Ltr, Notice, NumberInput, RelativeTime, ResponsiveList, SectionCard,
  StatusPill, useConfirmAction, useKit, useUndoSnackbar, type ListColumn, type RowAction
} from "../kit";
import { RECORD_TYPES } from "../dns";
import { FormDialog, isMissingEndpoint, Loading, useList, useLoader } from "../dnsUi";
import { planName, usageRows, type LimitValue, type Plan } from "../my/myApi";
import { useMySpace } from "../my/MySpaceContext";
import { UsageBar } from "../my/MyKit";
import {
  approveSignup, deletePlan, fetchPlans, fetchSignups, fetchWorkspaceDetail, fetchWorkspaces, patchWorkspace, rejectSignup, removeWorkspace, savePlan,
  fetchTenancySettings, saveTenancySettings, startViewAs, transferOwnership, type AdminWorkspace, type ResourceRow, type Signup, type TenancySettings,
  type WorkspaceDetail
} from "./tenancyApi";

const featureOf = (key: string) => QUOTA_WORDS[key as QuotaKey]?.feature;
const QUOTA_FIELDS = QUOTA_KEYS;

function Missing() {
  const { language } = useKit();
  return <Notice tone="info">{pick(language, TENANCY.missing)}</Notice>;
}

function limitText(language: "fa" | "en", key: string, value: LimitValue | undefined): string {
  if (Array.isArray(value)) return value.length ? value.join("، ") : pick(language, TENANCY.unlimited);
  if (value === null || value === undefined) return pick(language, TENANCY.unlimited);
  return formatQuota(language, key, value);
}

// ── limit inputs ─────────────────────────────────────────────────────────────

function LimitField({ quota, value, onChange, hint, allowUnlimited = true }: { quota: QuotaKey; value: LimitValue | undefined; onChange: (value: number | null) => void; hint?: string; allowUnlimited?: boolean }) {
  const { language } = useKit();
  const info = QUOTA_WORDS[quota];
  const unlimited = allowUnlimited && (value === null || value === undefined || Array.isArray(value));
  const number = typeof value === "number" ? value : null;
  const label = pick(language, info.label);
  return (
    <Stack direction={{ xs: "column", sm: "row" }} gap={1} alignItems={{ sm: "center" }} sx={{ py: 0.5 }}>
      <Box sx={{ flex: 1, minWidth: 0 }}>
        {unlimited ? (
          <TextField label={label} value={pick(language, TENANCY.unlimited)} disabled fullWidth size="small" helperText={hint} />
        ) : info.unit === "bytes" ? (
          <BytesInput label={label} value={number} onChange={(bytes) => onChange(bytes ?? 0)} min={0} helperText={hint} />
        ) : (
          <NumberInput label={label} value={number} onChange={(next) => onChange(next ?? 0)} min={0} integer helperText={hint} fullWidth />
        )}
      </Box>
      {allowUnlimited && (
        <FormControlLabel
          control={<Checkbox checked={unlimited} onChange={(event) => onChange(event.target.checked ? null : info.unit === "bytes" ? 1024 ** 3 : 1)} />}
          label={pick(language, TENANCY.unlimited)}
          sx={{ flexShrink: 0, minHeight: 44 }}
        />
      )}
    </Stack>
  );
}

function RecordTypesField({ value, onChange }: { value: string[]; onChange: (value: string[]) => void }) {
  const { language } = useKit();
  return (
    <Box>
      <Typography variant="body2" fontWeight={650}>{pick(language, TENANCY.recordTypes)}</Typography>
      <Typography variant="caption" color="text.secondary">{pick(language, TENANCY.recordTypesHint)}</Typography>
      <Stack direction="row" gap={0.75} flexWrap="wrap" sx={{ mt: 1 }}>
        {RECORD_TYPES.map((type) => {
          const on = value.includes(type);
          return (
            <Chip
              key={type}
              label={<Ltr>{type}</Ltr>}
              color={on ? "primary" : "default"}
              variant={on ? "filled" : "outlined"}
              onClick={() => onChange(on ? value.filter((item) => item !== type) : [...value, type])}
              aria-pressed={on}
              sx={{ minHeight: 36 }}
            />
          );
        })}
      </Stack>
    </Box>
  );
}

// ── plans ────────────────────────────────────────────────────────────────────

const EMPTY_PLAN: Plan = { id: "", name_fa: "", name_en: "", description: "", default: false, features: { dns: true, s3: true, api_tokens: true }, quotas: {} };

function PlanDialog({ initial, onClose, onSaved }: { initial: Plan | null; onClose: () => void; onSaved: (name: string) => void }) {
  const { language } = useKit();
  const [plan, setPlan] = useState<Plan>(() => initial ?? EMPTY_PLAN);
  const [touched, setTouched] = useState(false);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<unknown>(null);
  const problem = (plan.name_fa ?? "").trim() || (plan.name_en ?? "").trim() ? null : pick(language, TENANCY.nameRequired);
  const recordTypes = Array.isArray(plan.quotas.dns_record_types) ? plan.quotas.dns_record_types : [];

  const setQuota = (key: string, value: LimitValue | undefined) =>
    setPlan((current) => {
      const quotas = { ...current.quotas };
      if (value === undefined || (Array.isArray(value) && value.length === 0)) delete quotas[key];
      else quotas[key] = value;
      return { ...current, quotas };
    });

  const submit = async () => {
    setTouched(true);
    if (problem) return;
    setBusy(true);
    setError(null);
    try {
      // Every limit is sent: «بی‌سقف» as null.
      const quotas: Record<string, LimitValue> = {};
      for (const key of QUOTA_FIELDS) quotas[key] = typeof plan.quotas[key] === "number" ? plan.quotas[key] : null;
      if (recordTypes.length) quotas.dns_record_types = recordTypes;
      const features: Partial<Record<FeatureKey, boolean>> = {};
      for (const key of FEATURE_KEYS) features[key] = plan.features[key] === true;
      await savePlan({ ...plan, id: initial?.id, features, quotas });
      onSaved(planName(language, plan));
    } catch (caught) {
      setError(caught);
    } finally {
      setBusy(false);
    }
  };

  return (
    <FormDialog
      title={initial ? say(language, TENANCY.editPlan, { name: planName(language, initial) }) : pick(language, TENANCY.newPlan)}
      submitLabel={pick(language, initial ? MY.save : TENANCY.createPlan)}
      busy={busy}
      error={error}
      onSubmit={() => void submit()}
      onClose={onClose}
      wide
    >
      <Stack direction={{ xs: "column", sm: "row" }} gap={2}>
        <TextField label={pick(language, TENANCY.nameFa)} value={plan.name_fa ?? ""} onChange={(event) => setPlan({ ...plan, name_fa: event.target.value })} error={touched && Boolean(problem)} helperText={touched && problem ? problem : " "} fullWidth />
        <TextField label={pick(language, TENANCY.nameEn)} value={plan.name_en ?? ""} onChange={(event) => setPlan({ ...plan, name_en: event.target.value })} helperText=" " fullWidth slotProps={{ htmlInput: { dir: "ltr" } }} />
      </Stack>
      <TextField label={pick(language, TENANCY.description)} value={plan.description ?? ""} onChange={(event) => setPlan({ ...plan, description: event.target.value })} fullWidth multiline minRows={2} />
      <FormControlLabel control={<Switch checked={Boolean(plan.default)} onChange={(event) => setPlan({ ...plan, default: event.target.checked })} />} label={pick(language, TENANCY.isDefault)} />
      <Divider />
      <Typography variant="subtitle1" fontWeight={720}>{pick(language, TENANCY.features)}</Typography>
      <Stack>
        {FEATURE_KEYS.map((key) => (
          <FormControlLabel
            key={key}
            control={<Switch checked={plan.features[key] === true} onChange={(event) => setPlan({ ...plan, features: { ...plan.features, [key]: event.target.checked } })} />}
            label={
              <Box sx={{ py: 0.5 }}>
                <Typography variant="body2" fontWeight={650}>{pick(language, FEATURE_WORDS[key].label)}</Typography>
                <Typography variant="caption" color="text.secondary">{pick(language, FEATURE_WORDS[key].hint)}</Typography>
              </Box>
            }
            sx={{ alignItems: "center", minHeight: 48 }}
          />
        ))}
      </Stack>
      <Divider />
      <Typography variant="subtitle1" fontWeight={720}>{pick(language, TENANCY.quotas)}</Typography>
      <Stack spacing={0.5}>
        {QUOTA_FIELDS.map((key) => <LimitField key={key} quota={key} value={plan.quotas[key]} onChange={(value) => setQuota(key, value)} />)}
      </Stack>
      <RecordTypesField value={recordTypes} onChange={(value) => setQuota("dns_record_types", value)} />
    </FormDialog>
  );
}

function PlansTab({ createRequest }: { createRequest: number }) {
  const { language } = useKit();
  const loader = useCallback((signal: AbortSignal) => fetchPlans(signal), []);
  const { items, error, loading, reload } = useList<Plan>(loader);
  const [editing, setEditing] = useState<{ plan: Plan | null } | null>(null);
  const { ask, dialog } = useConfirmAction();
  const { notify, snackbar } = useUndoSnackbar();

  useEffect(() => {
    if (createRequest > 0) setEditing({ plan: null });
  }, [createRequest]);

  if (error && isMissingEndpoint(error)) return <Missing />;

  const remove = async (plan: Plan) => {
    const ok = await ask({ title: say(language, TENANCY.planDeleteTitle, { name: planName(language, plan) }), body: pick(language, TENANCY.planDeleteBody), severity: "destructive", undoable: false });
    if (!ok) return;
    try {
      await deletePlan(plan.id);
      notify({ message: say(language, MY.removed, { name: planName(language, plan) }) });
      reload();
    } catch (caught) {
      notify({ message: errorSentence(language, caught), tone: "error" });
    }
  };

  const featuresOn = (plan: Plan) => FEATURE_KEYS.filter((key) => plan.features[key]).length;
  const columns: ListColumn<Plan>[] = [
    {
      key: "name",
      header: pick(language, MY.name),
      render: (plan) => (
        <Stack direction="row" gap={1} alignItems="center" flexWrap="wrap">
          <Typography fontWeight={650} component="span">{planName(language, plan)}</Typography>
          {plan.default && <Chip size="small" color="primary" variant="outlined" label={pick(language, TENANCY.defaultBadge)} />}
        </Stack>
      )
    },
    { key: "features", header: pick(language, TENANCY.features), render: (plan) => say(language, TENANCY.featuresOn, { n: featuresOn(plan) }) },
    { key: "storage", header: pick(language, QUOTA_WORDS.s3_bytes.label), render: (plan) => limitText(language, "s3_bytes", plan.quotas.s3_bytes) },
    { key: "zones", header: pick(language, QUOTA_WORDS.dns_zones.label), render: (plan) => limitText(language, "dns_zones", plan.quotas.dns_zones) },
    { key: "used", header: pick(language, TENANCY.colInUse), render: (plan) => (plan.workspaces === null || plan.workspaces === undefined ? "—" : say(language, TENANCY.inUse, { n: plan.workspaces })) }
  ];
  const actions: RowAction<Plan>[] = [
    { key: "edit", label: pick(language, TENANCY.edit), icon: EditRoundedIcon, onClick: (plan) => setEditing({ plan }) },
    { key: "delete", label: pick(language, MY.remove), icon: DeleteOutlineRoundedIcon, danger: true, hidden: (plan) => Boolean(plan.builtin), onClick: (plan) => void remove(plan) }
  ];

  return (
    <SectionCard title={pick(language, TENANCY.plans)} hint={pick(language, TENANCY.plansHint)} flush>
      {error ? <Box sx={{ p: 2 }}><FriendlyError error={error} onRetry={reload} /></Box> : null}
      {loading && !items ? <Loading /> : null}
      {items && (
        <ResponsiveList
          label={pick(language, TENANCY.plans)}
          rows={items}
          rowKey={(plan) => plan.id}
          columns={columns}
          card={{ title: (plan) => planName(language, plan), meta: (plan) => `${say(language, TENANCY.featuresOn, { n: featuresOn(plan) })} · ${limitText(language, "s3_bytes", plan.quotas.s3_bytes)}`, status: (plan) => (plan.default ? <StatusPill tone="info" label={pick(language, TENANCY.defaultBadge)} /> : null) }}
          actions={actions}
          onRowClick={(plan) => setEditing({ plan })}
          empty={<EmptyState icon={Inventory2RoundedIcon} title={pick(language, TENANCY.plansEmptyTitle)} body={pick(language, TENANCY.plansEmptyBody)} action={<Button variant="contained" startIcon={<AddRoundedIcon />} onClick={() => setEditing({ plan: null })}>{pick(language, TENANCY.newPlan)}</Button>} />}
        />
      )}
      {editing && (
        <PlanDialog
          initial={editing.plan}
          onClose={() => setEditing(null)}
          onSaved={(name) => {
            setEditing(null);
            notify({ message: say(language, TENANCY.planSaved, { name }), tone: "success" });
            reload();
          }}
        />
      )}
      {dialog}
      {snackbar}
    </SectionCard>
  );
}


// ── workspaces ───────────────────────────────────────────────────────────────

function PlanOverridesDialog({ workspace, plans, onClose, onSaved }: { workspace: AdminWorkspace; plans: Plan[]; onClose: () => void; onSaved: () => void }) {
  const { language } = useKit();
  const [planId, setPlanId] = useState<string>(workspace.plan_id ?? "");
  const [overrides, setOverrides] = useState<Record<string, LimitValue>>(workspace.quota_overrides);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<unknown>(null);
  const plan = plans.find((item) => item.id === planId) ?? null;

  const submit = async () => {
    setBusy(true);
    setError(null);
    try {
      // An exception that was turned off is sent as null (= remove it).
      const body: Record<string, LimitValue> = {};
      for (const key of Object.keys(workspace.quota_overrides)) if (!(key in overrides)) body[key] = null;
      for (const [key, value] of Object.entries(overrides)) if (typeof value === "number") body[key] = value;
      await patchWorkspace(workspace.id, { ...(planId && planId !== workspace.plan_id ? { plan_id: planId } : {}), quota_overrides: body });
      onSaved();
    } catch (caught) {
      setError(caught);
    } finally {
      setBusy(false);
    }
  };

  return (
    <FormDialog title={say(language, TENANCY.changePlanTitle, { name: workspace.name })} hint={pick(language, TENANCY.changePlanHint)} submitLabel={pick(language, MY.save)} busy={busy} error={error} onSubmit={() => void submit()} onClose={onClose} wide>
      <TextField select label={pick(language, TENANCY.plan)} value={planId} onChange={(event) => setPlanId(event.target.value)} fullWidth>
        {plans.map((item) => <MenuItem key={item.id} value={item.id}>{planName(language, item)}</MenuItem>)}
      </TextField>
      <Typography variant="subtitle1" fontWeight={720}>{pick(language, TENANCY.overrides)}</Typography>
      <Stack spacing={1}>
        {QUOTA_FIELDS.map((key) => {
          const on = Object.prototype.hasOwnProperty.call(overrides, key);
          const fromPlan = say(language, TENANCY.fromPlan, { value: limitText(language, key, plan?.quotas[key]) });
          return (
            <Box key={key} sx={{ border: 1, borderColor: on ? "primary.main" : "divider", borderRadius: 2, px: 1.5, py: 1 }}>
              <Stack direction="row" alignItems="center" gap={1}>
                <Typography variant="body2" fontWeight={650} sx={{ flex: 1 }}>{pick(language, QUOTA_WORDS[key].label)}</Typography>
                <FormControlLabel
                  control={
                    <Switch
                      checked={on}
                      onChange={(event) =>
                        setOverrides((current) => {
                          const next = { ...current };
                          if (event.target.checked) next[key] = typeof plan?.quotas[key] === "number" ? plan.quotas[key] : QUOTA_WORDS[key].unit === "bytes" ? 1024 ** 3 : 1;
                          else delete next[key];
                          return next;
                        })
                      }
                    />
                  }
                  label={pick(language, TENANCY.override)}
                />
              </Stack>
              {on ? (
                <LimitField quota={key} value={overrides[key]} allowUnlimited={false} onChange={(value) => setOverrides((current) => ({ ...current, [key]: value ?? 0 }))} hint={fromPlan} />
              ) : (
                <Typography variant="caption" color="text.secondary">{fromPlan}</Typography>
              )}
            </Box>
          );
        })}
      </Stack>
    </FormDialog>
  );
}

function TransferDialog({ resource, workspaces, onClose, onDone }: { resource: ResourceRow; workspaces: AdminWorkspace[]; onClose: () => void; onDone: () => void }) {
  const { language } = useKit();
  const [target, setTarget] = useState<string>("__system");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<unknown>(null);
  const submit = async () => {
    setBusy(true);
    setError(null);
    try {
      await transferOwnership(resource.kind, resource.resource_id, target === "__system" ? null : target);
      onDone();
    } catch (caught) {
      setError(caught);
    } finally {
      setBusy(false);
    }
  };
  return (
    <FormDialog title={say(language, TENANCY.transferTitle, { name: resource.name })} hint={pick(language, TENANCY.transferHint)} submitLabel={pick(language, TENANCY.transferYes)} busy={busy} error={error} onSubmit={() => void submit()} onClose={onClose}>
      <TextField select label={pick(language, TENANCY.colSpace)} value={target} onChange={(event) => setTarget(event.target.value)} fullWidth>
        <MenuItem value="__system">{pick(language, TENANCY.toSystem)}</MenuItem>
        {workspaces.map((item) => <MenuItem key={item.id} value={item.id}>{item.name} <Typography component="span" variant="caption" color="text.secondary" sx={{ mx: 1 }}><Ltr>{item.slug}</Ltr></Typography></MenuItem>)}
      </TextField>
    </FormDialog>
  );
}

function kindWord(language: "fa" | "en", kind: string) {
  const key = `kind_${kind}` as keyof typeof TENANCY;
  return pick(language, (TENANCY[key] as { fa: string; en: string } | undefined) ?? TENANCY.kind_other);
}

function DetailDialog({ id, workspaces, onClose, onChanged }: { id: string; workspaces: AdminWorkspace[]; onClose: () => void; onChanged: () => void }) {
  const { language } = useKit();
  const theme = useTheme();
  const fullScreen = useMediaQuery(theme.breakpoints.down("sm"));
  const loader = useCallback((signal: AbortSignal) => fetchWorkspaceDetail(id, signal), [id]);
  const { data, error, loading, reload } = useLoader<WorkspaceDetail>(loader);
  const [moving, setMoving] = useState<ResourceRow | null>(null);
  const { notify, snackbar } = useUndoSnackbar();
  const workspace = data?.workspace;
  const rows = workspace ? usageRows(workspace, workspace.features, featureOf) : [];
  return (
    <Dialog open onClose={onClose} fullScreen={fullScreen} fullWidth maxWidth="md" aria-labelledby="mrk-ws-detail">
      <DialogTitle id="mrk-ws-detail">{say(language, TENANCY.detailTitle, { name: workspace?.name ?? "" })}</DialogTitle>
      <DialogContent>
        {loading && !data ? <Loading /> : null}
        {error ? <FriendlyError error={error} onRetry={reload} /> : null}
        {workspace && (
          <Stack spacing={2.5}>
            <KeyValueList
              items={[
                { label: pick(language, TENANCY.colSpace), value: <>{workspace.name} <Ltr>{`(${workspace.slug})`}</Ltr></> },
                { label: pick(language, TENANCY.colOwner), value: workspace.owner ? workspace.owner.display_name || workspace.owner.username : "—" },
                { label: pick(language, TENANCY.colPlan), value: planName(language, workspace.plan) || "—" },
                { label: pick(language, TENANCY.colStatus), value: <StatusPill tone={workspace.status === "suspended" ? "warn" : "ok"} label={pick(language, workspace.status === "suspended" ? TENANCY.suspendedPill : TENANCY.active)} /> },
                { label: "ID", value: <Ltr mono>{workspace.id}</Ltr>, advancedOnly: true, copy: workspace.id }
              ]}
            />
            <Box>
              <Typography variant="subtitle1" fontWeight={720} sx={{ mb: 1 }}>{pick(language, TENANCY.usage)}</Typography>
              <Stack spacing={1.5}>{rows.map((row) => <UsageBar key={row.key} row={row} />)}</Stack>
            </Box>
            <Box>
              <Typography variant="subtitle1" fontWeight={720} sx={{ mb: 1 }}>{pick(language, TENANCY.members)}</Typography>
              <Stack spacing={0.5}>
                {data.members.map((member) => (
                  <Stack key={member.user_id} direction="row" gap={1} alignItems="center">
                    <Typography variant="body2" sx={{ flex: 1 }}>{member.display_name || member.username}</Typography>
                    <Typography variant="caption" color="text.secondary">{workspaceRoleName(language, member.role)}</Typography>
                  </Stack>
                ))}
              </Stack>
            </Box>
            <Box>
              <Typography variant="subtitle1" fontWeight={720} sx={{ mb: 1 }}>{pick(language, TENANCY.resources)}</Typography>
              {data.resources.length === 0 ? (
                <Typography variant="body2" color="text.secondary">{pick(language, TENANCY.resourcesEmpty)}</Typography>
              ) : (
                <Stack spacing={0.75}>
                  {data.resources.map((resource) => (
                    <Stack key={`${resource.kind}:${resource.resource_id}`} direction="row" gap={1} alignItems="center" sx={{ border: 1, borderColor: "divider", borderRadius: 1.5, px: 1.5, py: 0.75 }}>
                      <Typography variant="caption" color="text.secondary" sx={{ minWidth: 90 }}>{kindWord(language, resource.kind)}</Typography>
                      <Typography variant="body2" sx={{ flex: 1, minWidth: 0 }} noWrap><Ltr>{resource.name}</Ltr></Typography>
                      <Button size="small" startIcon={<SwapHorizRoundedIcon />} onClick={() => setMoving(resource)} sx={{ minHeight: 40 }}>{pick(language, TENANCY.transfer)}</Button>
                    </Stack>
                  ))}
                </Stack>
              )}
            </Box>
          </Stack>
        )}
      </DialogContent>
      <DialogActions sx={{ px: 3, pb: 2 }}>
        <Button onClick={onClose} sx={{ minHeight: 44 }}>{pick(language, MY.close)}</Button>
      </DialogActions>
      {moving && (
        <TransferDialog
          resource={moving}
          workspaces={workspaces.filter((item) => item.id !== id)}
          onClose={() => setMoving(null)}
          onDone={() => {
            notify({ message: say(language, TENANCY.transferred, { name: moving.name }), tone: "success" });
            setMoving(null);
            reload();
            onChanged();
          }}
        />
      )}
      {snackbar}
    </Dialog>
  );
}

function WorkspacesTab({ user }: { user: AuthUser }) {
  const { language } = useKit();
  const space = useMySpace();
  const [query, setQuery] = useState("");
  const [debounced, setDebounced] = useState("");
  const [status, setStatus] = useState<"" | "active" | "suspended">("");
  useEffect(() => {
    const timer = window.setTimeout(() => setDebounced(query), 300);
    return () => window.clearTimeout(timer);
  }, [query]);
  const loader = useCallback((signal: AbortSignal) => fetchWorkspaces(debounced, status, signal), [debounced, status]);
  const { items, error, loading, reload } = useList<AdminWorkspace>(loader);
  const plansLoader = useCallback((signal: AbortSignal) => fetchPlans(signal).catch(() => [] as Plan[]), []);
  const plans = useList<Plan>(plansLoader);
  const [detail, setDetail] = useState<string | null>(null);
  const [changing, setChanging] = useState<AdminWorkspace | null>(null);
  const [removing, setRemoving] = useState<AdminWorkspace | null>(null);
  const [removeMode, setRemoveMode] = useState<"delete" | "transfer">("transfer");
  const [viewing, setViewing] = useState<AdminWorkspace | null>(null);
  const [viewWrite, setViewWrite] = useState(false);
  const [busy, setBusy] = useState(false);
  const [dialogError, setDialogError] = useState<unknown>(null);
  const { ask, dialog } = useConfirmAction();
  const { notify, snackbar } = useUndoSnackbar();
  const canWriteAs = hasPermission(user.permissions, "tenancy:impersonate_write");
  const planList = plans.items ?? [];
  const planOf = (workspace: AdminWorkspace) => workspace.plan ?? planList.find((item) => item.id === workspace.plan_id) ?? null;

  if (error && isMissingEndpoint(error)) return <Missing />;

  const toggleSuspend = async (workspace: AdminWorkspace) => {
    const suspending = workspace.status !== "suspended";
    if (suspending) {
      const ok = await ask({ title: say(language, TENANCY.suspendTitle, { name: workspace.name }), body: pick(language, TENANCY.suspendBody), severity: "disruptive", confirmLabel: pick(language, TENANCY.suspendYes) });
      if (!ok) return;
    }
    try {
      await patchWorkspace(workspace.id, { status: suspending ? "suspended" : "active" });
      notify({ message: say(language, suspending ? TENANCY.suspended : TENANCY.resumed, { name: workspace.name }), tone: "success" });
      reload();
    } catch (caught) {
      notify({ message: errorSentence(language, caught), tone: "error" });
    }
  };

  const confirmRemove = async () => {
    if (!removing) return;
    setBusy(true);
    setDialogError(null);
    try {
      await removeWorkspace(removing.id, removing.slug, removeMode);
      notify({ message: say(language, TENANCY.removed, { name: removing.name }) });
      setRemoving(null);
      reload();
    } catch (caught) {
      setDialogError(caught);
    } finally {
      setBusy(false);
    }
  };

  const confirmViewAs = async () => {
    if (!viewing) return;
    setBusy(true);
    setDialogError(null);
    try {
      const session = await startViewAs(viewing.id, viewWrite && canWriteAs);
      space.startViewAs({ token: session.token, workspaceId: viewing.id, workspaceName: viewing.name, expiresAt: session.expiresAt, write: viewWrite && canWriteAs });
      setViewing(null);
    } catch (caught) {
      setDialogError(caught);
    } finally {
      setBusy(false);
    }
  };

  const usageCell = (workspace: AdminWorkspace) => {
    const rows = usageRows(workspace, workspace.features, featureOf).filter((row) => row.limit !== null).sort((a, b) => (b.percent ?? 0) - (a.percent ?? 0)).slice(0, 2);
    if (!rows.length) return <Typography variant="caption" color="text.secondary">—</Typography>;
    return <Stack spacing={0.75} sx={{ minWidth: 160 }}>{rows.map((row) => <UsageBar key={row.key} row={row} />)}</Stack>;
  };

  const columns: ListColumn<AdminWorkspace>[] = [
    {
      key: "space",
      header: pick(language, TENANCY.colSpace),
      render: (workspace) => (
        <Box sx={{ minWidth: 0 }}>
          <Typography fontWeight={650} component="span">{workspace.name}</Typography>
          <Typography variant="caption" color="text.secondary" display="block"><Ltr>{workspace.slug}</Ltr> · {pick(language, workspace.kind === "team" ? MY.team : MY.personal)}</Typography>
        </Box>
      )
    },
    { key: "owner", header: pick(language, TENANCY.colOwner), render: (workspace) => (workspace.owner ? workspace.owner.display_name || workspace.owner.username : "—") },
    { key: "plan", header: pick(language, TENANCY.colPlan), render: (workspace) => planName(language, planOf(workspace)) || "—" },
    { key: "usage", header: pick(language, TENANCY.colUsage), render: usageCell, hideOnCard: true },
    { key: "members", header: pick(language, TENANCY.colMembers), render: (workspace) => (workspace.members === null ? "—" : String(workspace.members)), advancedOnly: true },
    { key: "status", header: pick(language, TENANCY.colStatus), render: (workspace) => <StatusPill tone={workspace.status === "suspended" ? "warn" : "ok"} label={pick(language, workspace.status === "suspended" ? TENANCY.suspendedPill : TENANCY.active)} /> }
  ];
  const actions: RowAction<AdminWorkspace>[] = [
    { key: "detail", label: pick(language, TENANCY.details), icon: InfoRoundedIcon, onClick: (workspace) => setDetail(workspace.id) },
    { key: "plan", label: pick(language, TENANCY.changePlan), icon: TuneRoundedIcon, onClick: (workspace) => setChanging(workspace) },
    { key: "view", label: pick(language, TENANCY.viewAs), icon: VisibilityRoundedIcon, onClick: (workspace) => { setViewWrite(false); setDialogError(null); setViewing(workspace); } },
    { key: "suspend", label: pick(language, TENANCY.suspend), icon: PauseCircleRoundedIcon, hidden: (workspace) => workspace.status === "suspended", onClick: (workspace) => void toggleSuspend(workspace) },
    { key: "resume", label: pick(language, TENANCY.resume), icon: PlayCircleRoundedIcon, hidden: (workspace) => workspace.status !== "suspended", onClick: (workspace) => void toggleSuspend(workspace) },
    { key: "remove", label: pick(language, TENANCY.remove), icon: DeleteOutlineRoundedIcon, danger: true, onClick: (workspace) => { setRemoveMode("transfer"); setDialogError(null); setRemoving(workspace); } }
  ];

  return (
    <SectionCard title={pick(language, TENANCY.workspaces)} hint={pick(language, TENANCY.workspacesHint)} flush>
      <Stack direction={{ xs: "column", sm: "row" }} gap={1.5} sx={{ p: 2, pb: 1 }} alignItems={{ sm: "center" }}>
        <TextField
          size="small"
          value={query}
          onChange={(event) => setQuery(event.target.value)}
          placeholder={pick(language, TENANCY.search)}
          slotProps={{ htmlInput: { "aria-label": pick(language, TENANCY.search), dir: "auto" }, input: { startAdornment: <InputAdornment position="start"><SearchRoundedIcon fontSize="small" /></InputAdornment> } }}
          sx={{ minWidth: { sm: 280 } }}
        />
        <ToggleButtonGroup exclusive size="small" value={status} onChange={(_event, value: "" | "active" | "suspended" | null) => value !== null && setStatus(value)} aria-label={pick(language, TENANCY.colStatus)}>
          <ToggleButton value="" sx={{ minHeight: 40, px: 1.5 }}>{pick(language, TENANCY.filterAll)}</ToggleButton>
          <ToggleButton value="active" sx={{ minHeight: 40, px: 1.5 }}>{pick(language, TENANCY.filterActive)}</ToggleButton>
          <ToggleButton value="suspended" sx={{ minHeight: 40, px: 1.5 }}>{pick(language, TENANCY.filterSuspended)}</ToggleButton>
        </ToggleButtonGroup>
      </Stack>
      {error ? <Box sx={{ p: 2 }}><FriendlyError error={error} onRetry={reload} /></Box> : null}
      {loading && !items ? <Loading /> : null}
      {items && (
        <ResponsiveList
          label={pick(language, TENANCY.workspaces)}
          rows={items}
          rowKey={(workspace) => workspace.id}
          columns={columns}
          card={{
            title: (workspace) => workspace.name,
            meta: (workspace) => [workspace.owner?.display_name || workspace.owner?.username, planName(language, planOf(workspace))].filter(Boolean).join(" · "),
            status: (workspace) => <StatusPill tone={workspace.status === "suspended" ? "warn" : "ok"} label={pick(language, workspace.status === "suspended" ? TENANCY.suspendedPill : TENANCY.active)} />
          }}
          actions={actions}
          onRowClick={(workspace) => setDetail(workspace.id)}
          empty={debounced || status
            ? <EmptyState compact icon={SearchRoundedIcon} title={pick(language, TENANCY.wsNoMatch)} />
            : <EmptyState icon={WorkspacesRoundedIcon} title={pick(language, TENANCY.wsEmptyTitle)} body={pick(language, TENANCY.wsEmptyBody)} />}
        />
      )}
      {detail && <DetailDialog id={detail} workspaces={items ?? []} onClose={() => setDetail(null)} onChanged={reload} />}
      {changing && (
        <PlanOverridesDialog
          workspace={changing}
          plans={planList}
          onClose={() => setChanging(null)}
          onSaved={() => {
            notify({ message: say(language, TENANCY.planChanged, { name: changing.name }), tone: "success" });
            setChanging(null);
            reload();
          }}
        />
      )}
      <ConfirmAction
        open={removing !== null}
        title={say(language, TENANCY.removeTitle, { name: removing?.name ?? "" })}
        body={pick(language, TENANCY.removeBody)}
        severity="destructive"
        undoable={false}
        typed={removing ? nameConfirmation(removing.slug, removing.slug) : undefined}
        busy={busy}
        error={dialogError}
        onConfirm={() => void confirmRemove()}
        onClose={() => setRemoving(null)}
      >
        <RadioGroup value={removeMode} onChange={(event) => setRemoveMode(event.target.value as "delete" | "transfer")}>
          <FormControlLabel value="transfer" control={<Radio />} label={<Box sx={{ py: 0.5 }}><Typography variant="body2" fontWeight={650}>{pick(language, TENANCY.modeTransfer)}</Typography><Typography variant="caption" color="text.secondary">{pick(language, TENANCY.modeTransferBody)}</Typography></Box>} />
          <FormControlLabel value="delete" control={<Radio color="error" />} label={<Box sx={{ py: 0.5 }}><Typography variant="body2" fontWeight={650}>{pick(language, TENANCY.modeDelete)}</Typography><Typography variant="caption" color="text.secondary">{pick(language, TENANCY.modeDeleteBody)}</Typography></Box>} />
        </RadioGroup>
      </ConfirmAction>
      <ConfirmAction
        open={viewing !== null}
        title={say(language, TENANCY.viewAsTitle, { name: viewing?.name ?? "" })}
        body={pick(language, TENANCY.viewAsBody)}
        confirmLabel={pick(language, TENANCY.viewAsYes)}
        severity={viewWrite ? "disruptive" : undefined}
        busy={busy}
        error={dialogError}
        onConfirm={() => void confirmViewAs()}
        onClose={() => setViewing(null)}
      >
        {canWriteAs && (
          <FormControlLabel control={<Checkbox checked={viewWrite} onChange={(event) => setViewWrite(event.target.checked)} color="warning" />} label={pick(language, TENANCY.viewAsWrite)} />
        )}
      </ConfirmAction>
      {dialog}
      {snackbar}
    </SectionCard>
  );
}

// ── sign-ups ─────────────────────────────────────────────────────────────────

function SignupsTab() {
  const { language } = useKit();
  const loader = useCallback((signal: AbortSignal) => fetchSignups(signal), []);
  const { items, error, loading, reload } = useList<Signup>(loader);
  const plansLoader = useCallback((signal: AbortSignal) => fetchPlans(signal).catch(() => [] as Plan[]), []);
  const plans = useList<Plan>(plansLoader);
  const settingsLoader = useCallback((signal: AbortSignal) => fetchTenancySettings(signal).catch(() => null), []);
  const settings = useLoader<TenancySettings | null>(settingsLoader);
  const [approving, setApproving] = useState<Signup | null>(null);
  const [planId, setPlanId] = useState("");
  const [busy, setBusy] = useState(false);
  const [dialogError, setDialogError] = useState<unknown>(null);
  const { ask, dialog } = useConfirmAction();
  const { notify, snackbar } = useUndoSnackbar();
  const signupMode = settings.data?.signup;
  const nameOf = (signup: Signup) => signup.display_name || signup.username || signup.email || signup.id;

  if (error && isMissingEndpoint(error)) return <Missing />;

  const approve = async () => {
    if (!approving) return;
    setBusy(true);
    setDialogError(null);
    try {
      await approveSignup(approving.id, planId || null);
      notify({ message: say(language, TENANCY.approved, { name: nameOf(approving) }), tone: "success" });
      setApproving(null);
      reload();
    } catch (caught) {
      setDialogError(caught);
    } finally {
      setBusy(false);
    }
  };

  const reject = async (signup: Signup) => {
    const ok = await ask({ title: say(language, TENANCY.rejectTitle, { name: nameOf(signup) }), body: pick(language, TENANCY.rejectBody), severity: "disruptive", confirmLabel: pick(language, TENANCY.rejectYes) });
    if (!ok) return;
    try {
      await rejectSignup(signup.id);
      notify({ message: say(language, TENANCY.rejected, { name: nameOf(signup) }) });
      reload();
    } catch (caught) {
      notify({ message: errorSentence(language, caught), tone: "error" });
    }
  };

  const defaultPlan = (plans.items ?? []).find((plan) => plan.default)?.id ?? "";
  return (
    <Stack spacing={2}>
      {signupMode !== undefined && signupMode !== "approval" && <Notice>{pick(language, TENANCY.signupsOff)}</Notice>}
      <SectionCard title={pick(language, TENANCY.signupsTitle)} hint={pick(language, TENANCY.signupsHint)} flush>
        {error ? <Box sx={{ p: 2 }}><FriendlyError error={error} onRetry={reload} /></Box> : null}
        {loading && !items ? <Loading /> : null}
        {items && (
          <ResponsiveList
            label={pick(language, TENANCY.signupsTitle)}
            rows={items}
            rowKey={(signup) => signup.id}
            columns={[
              { key: "who", header: pick(language, TENANCY.colPerson), render: (signup) => <Box><Typography fontWeight={650} component="span">{nameOf(signup)}</Typography>{signup.email && <Typography variant="caption" color="text.secondary" display="block"><Ltr>{signup.email}</Ltr></Typography>}</Box> },
              { key: "when", header: pick(language, TENANCY.colWhen), render: (signup) => <RelativeTime value={signup.created_at} /> }
            ]}
            card={{ title: nameOf, meta: (signup) => (signup.email ? <Ltr>{signup.email}</Ltr> : null) }}
            actions={[
              { key: "approve", label: pick(language, TENANCY.approve), icon: HowToRegRoundedIcon, onClick: (signup) => { setPlanId(defaultPlan); setDialogError(null); setApproving(signup); } },
              { key: "reject", label: pick(language, TENANCY.reject), icon: PersonOffRoundedIcon, danger: true, onClick: (signup) => void reject(signup) }
            ]}
            empty={<EmptyState icon={HourglassTopRoundedIcon} title={pick(language, TENANCY.signupsEmptyTitle)} body={pick(language, TENANCY.signupsEmptyBody)} />}
          />
        )}
      </SectionCard>
      <ConfirmAction
        open={approving !== null}
        title={say(language, TENANCY.approveTitle, { name: approving ? nameOf(approving) : "" })}
        body={pick(language, TENANCY.approveBody)}
        confirmLabel={pick(language, TENANCY.approveYes)}
        busy={busy}
        error={dialogError}
        onConfirm={() => void approve()}
        onClose={() => setApproving(null)}
      >
        {(plans.items?.length ?? 0) > 0 && (
          <TextField select label={pick(language, TENANCY.plan)} value={planId} onChange={(event) => setPlanId(event.target.value)} fullWidth sx={{ mt: 1 }}>
            {(plans.items ?? []).map((plan) => <MenuItem key={plan.id} value={plan.id}>{planName(language, plan)}</MenuItem>)}
          </TextField>
        )}
      </ConfirmAction>
      {dialog}
      {snackbar}
    </Stack>
  );
}

// ── settings ─────────────────────────────────────────────────────────────────

type SignupMode = "off" | "approval" | "open";

function SettingsTab() {
  const { language } = useKit();
  const loader = useCallback((signal: AbortSignal) => fetchTenancySettings(signal), []);
  const { data, error, loading, reload } = useLoader<TenancySettings>(loader);
  const plansLoader = useCallback((signal: AbortSignal) => fetchPlans(signal).catch(() => [] as Plan[]), []);
  const plans = useList<Plan>(plansLoader);
  const [settings, setSettings] = useState<TenancySettings | null>(null);
  const [saving, setSaving] = useState(false);
  const [saveError, setSaveError] = useState<unknown>(null);
  const { ask, dialog } = useConfirmAction();
  const { notify, snackbar } = useUndoSnackbar();
  const space = useMySpace();

  useEffect(() => {
    if (data) setSettings(data);
  }, [data]);

  const save = async (changes: Partial<TenancySettings>) => {
    setSaving(true);
    setSaveError(null);
    try {
      setSettings(await saveTenancySettings(changes));
      notify({ message: pick(language, TENANCY.settingsSaved), tone: "success" });
      // Turning My space on or off changes what the area switch can show.
      if ("enabled" in changes) void space.reload();
    } catch (caught) {
      setSaveError(caught);
    } finally {
      setSaving(false);
    }
  };

  if (error && isMissingEndpoint(error)) return <Notice tone="info">{pick(language, TENANCY.settingsMissing)}</Notice>;
  if (error) return <FriendlyError error={error} onRetry={reload} />;
  if (loading || !settings) return <Loading />;

  const busy = saving;
  return (
    <Stack spacing={2.5}>
      {saveError ? <FriendlyError error={saveError} onClose={() => setSaveError(null)} /> : null}
      <SectionCard title={pick(language, TENANCY.settingsTitle)} hint={pick(language, TENANCY.settingsHint)}>
        <Stack spacing={2.5}>
          <FormControlLabel
            control={<Switch checked={settings.enabled} disabled={busy} onChange={(event) => void save({ enabled: event.target.checked })} />}
            label={<Box sx={{ py: 0.5 }}><Typography fontWeight={650}>{pick(language, TENANCY.enabled)}</Typography><Typography variant="caption" color="text.secondary">{pick(language, TENANCY.enabledHint)}</Typography></Box>}
          />
          <Box>
            <Typography fontWeight={650} sx={{ mb: 1 }}>{pick(language, TENANCY.signup)}</Typography>
            <ChoiceCards<SignupMode>
              label={pick(language, TENANCY.signup)}
              value={settings.signup}
              onChange={(next) => { if (!busy && next !== settings.signup) void save({ signup: next }); }}
              options={[
                { key: "off", icon: LockRoundedIcon, title: pick(language, TENANCY.signup_off), body: pick(language, TENANCY.signup_off_body) },
                { key: "approval", icon: HowToRegRoundedIcon, title: pick(language, TENANCY.signup_approval), body: pick(language, TENANCY.signup_approval_body) },
                { key: "open", icon: PublicRoundedIcon, title: pick(language, TENANCY.signup_open), body: pick(language, TENANCY.signup_open_body), tone: "warning" }
              ]}
            />
          </Box>
          <TextField select label={pick(language, TENANCY.defaultPlan)} value={settings.default_plan_id ?? ""} disabled={busy} onChange={(event) => void save({ default_plan_id: event.target.value || null })} fullWidth>
            <MenuItem value="">{pick(language, TENANCY.noDefault)}</MenuItem>
            {(plans.items ?? []).map((plan) => <MenuItem key={plan.id} value={plan.id}>{planName(language, plan)}</MenuItem>)}
            {settings.default_plan_id && !(plans.items ?? []).some((plan) => plan.id === settings.default_plan_id) ? <MenuItem value={settings.default_plan_id}><Ltr mono>{settings.default_plan_id}</Ltr></MenuItem> : null}
          </TextField>
          <FormControlLabel
            control={
              <Switch
                checked={settings.verify_domains}
                disabled={busy}
                onChange={async (event) => {
                  const next = event.target.checked;
                  if (!next) {
                    const ok = await ask({ title: pick(language, TENANCY.verifyOffTitle), body: pick(language, TENANCY.verifyOffBody), severity: "disruptive" });
                    if (!ok) return;
                  }
                  void save({ verify_domains: next });
                }}
              />
            }
            label={<Box sx={{ py: 0.5 }}><Typography fontWeight={650}>{pick(language, TENANCY.verifyDomains)}</Typography><Typography variant="caption" color="text.secondary">{pick(language, TENANCY.verifyDomainsHint)}</Typography></Box>}
          />
          <FormControlLabel
            control={<Switch checked={settings.admin_area_local_only} disabled={busy} onChange={(event) => void save({ admin_area_local_only: event.target.checked })} />}
            label={<Box sx={{ py: 0.5 }}><Typography fontWeight={650}>{pick(language, TENANCY.adminLocal)}</Typography><Typography variant="caption" color="text.secondary">{pick(language, TENANCY.adminLocalHint)}</Typography></Box>}
          />
        </Stack>
      </SectionCard>
      {dialog}
      {snackbar}
    </Stack>
  );
}

export type TenancyTab = "workspaces" | "plans" | "signups" | "my-space";

export function TenancyPanel({ user, tab, createRequest }: { user: AuthUser; tab: TenancyTab; createRequest: number }) {
  if (tab === "plans") return <PlansTab createRequest={createRequest} />;
  if (tab === "signups") return <SignupsTab />;
  if (tab === "my-space") return <SettingsTab />;
  return <WorkspacesTab user={user} />;
}
