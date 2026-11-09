/**
 * «فضای من › فضای فایل» (docs/43 §3, §4): folders (buckets) of this workspace, the file browser
 * (drag-and-drop upload, folders, download, temporary links — the shared `S3FileManager` against
 * `/api/v1/my/s3/buckets`), public folders when the plan allows, folder domains with proof of
 * ownership, and access keys whose policy DevAssist builds from a template (shown once).
 */
import { useCallback, useEffect, useState } from "react";
import { Box, Button, Checkbox, CircularProgress, FormControlLabel, FormGroup, Stack, Tab, Tabs, TextField, Typography } from "@mui/material";
import ArrowBackRoundedIcon from "@mui/icons-material/ArrowBackRounded";
import CreateNewFolderRoundedIcon from "@mui/icons-material/CreateNewFolderRounded";
import DeleteOutlineRoundedIcon from "@mui/icons-material/DeleteOutlineRounded";
import FolderOpenRoundedIcon from "@mui/icons-material/FolderOpenRounded";
import FolderRoundedIcon from "@mui/icons-material/FolderRounded";
import PublicRoundedIcon from "@mui/icons-material/PublicRounded";
import LockRoundedIcon from "@mui/icons-material/LockRounded";
import KeyRoundedIcon from "@mui/icons-material/KeyRounded";
import LinkRoundedIcon from "@mui/icons-material/LinkRounded";
import LinkOffRoundedIcon from "@mui/icons-material/LinkOffRounded";
import FactCheckRoundedIcon from "@mui/icons-material/FactCheckRounded";
import RefreshRoundedIcon from "@mui/icons-material/RefreshRounded";
import VisibilityRoundedIcon from "@mui/icons-material/VisibilityRounded";
import EditNoteRoundedIcon from "@mui/icons-material/EditNoteRounded";
import AdminPanelSettingsRoundedIcon from "@mui/icons-material/AdminPanelSettingsRounded";
import { MY, MY_DNS, MY_FILES, nameConfirmation, pick, say } from "../copy";
import {
  ChoiceCards, CopyField, EmptyState, Ltr, NameDialog, RelativeTime, ResponsiveList, SectionCard, StatusPill, useConfirmAction, useKit,
  useUndoSnackbar, type ListColumn, type RowAction
} from "../kit";
import { FormDialog, Loading, useList, useLoader } from "../dnsUi";
import { S3FileManager } from "../S3FileManager";
import { KeySecretDialog } from "../S3Access";
import { formatBytes, formatNumber } from "../format";
import {
  addBucketDomain, createMyBucket, createMyKey, deleteMyBucket, deleteMyIdentity, fetchBucketDomains, fetchMyBuckets, fetchMyIdentities,
  MY_BUCKETS_BASE, numericLimit, removeBucketDomain, retryBucketRoute, setBucketPublic, verifyBucketDomain, type BucketDomain, type BucketRoute,
  type KeyTemplate, type MyBucket,
  type MyIdentity, type NewS3Key
} from "./myApi";
import { useMySpace } from "./MySpaceContext";
import { MyError, myErrorSentence, VerificationSteps } from "./MyKit";

const BUCKET_NAME = /^[a-z0-9][a-z0-9-]{1,61}[a-z0-9]$/;
const LEVEL_ICON = { read_only: VisibilityRoundedIcon, read_write: EditNoteRoundedIcon, admin: AdminPanelSettingsRoundedIcon } as const;

function levelTitle(language: "fa" | "en", level: KeyTemplate) {
  return pick(language, MY_FILES[`level_${level}` as const]);
}

// ── folder domains ───────────────────────────────────────────────────────────

const ROUTE_TONE = { ok: "ok", pending: "busy", manual: "info", failed: "error", conflict: "error", off: "off" } as const;

/** Whether a proven domain is reachable from the internet yet (docs/43 §0.1). */
function RouteState({ route, busy, disabled, canRetry, onRetry }: { route: BucketRoute; busy: boolean; disabled: boolean; canRetry: boolean; onRetry: () => void }) {
  const { language } = useKit();
  if (route.state === "unverified") return null;
  const state = route.state;
  return (
    <Stack direction="row" alignItems="center" gap={1} flexWrap="wrap" sx={{ mt: 1 }}>
      <StatusPill tone={ROUTE_TONE[state]} label={pick(language, MY_FILES[`route_${state}` as const])} />
      <Typography variant="body2" color="text.secondary" sx={{ flex: 1, minWidth: 200 }}>{pick(language, MY_FILES[`routeHint_${state}` as const])}</Typography>
      {canRetry && state === "failed" && (
        <Button size="small" disabled={disabled} onClick={onRetry} startIcon={busy ? <CircularProgress size={14} color="inherit" /> : <RefreshRoundedIcon />} sx={{ minHeight: 40 }}>
          {pick(language, MY_FILES.routeRetry)}
        </Button>
      )}
    </Stack>
  );
}

function BucketDomains({ bucket }: { bucket: string }) {
  const { language } = useKit();
  const space = useMySpace();
  const loader = useCallback((signal: AbortSignal) => fetchBucketDomains(bucket, signal), [bucket]);
  const { items, error, loading, reload } = useList<BucketDomain>(loader);
  const [adding, setAdding] = useState(false);
  const [checking, setChecking] = useState<string | null>(null);
  const [checkError, setCheckError] = useState<unknown>(null);
  const { ask, dialog } = useConfirmAction();
  const { notify, snackbar } = useUndoSnackbar();

  const retry = async (domain: string) => {
    setChecking(domain);
    setCheckError(null);
    try {
      await retryBucketRoute(bucket, domain);
      reload();
    } catch (caught) {
      setCheckError(caught);
    } finally {
      setChecking(null);
    }
  };

  const verify = async (domain: string) => {
    setChecking(domain);
    setCheckError(null);
    try {
      await verifyBucketDomain(bucket, domain);
      reload();
    } catch (caught) {
      setCheckError(caught);
    } finally {
      setChecking(null);
    }
  };

  const remove = async (domain: string) => {
    const ok = await ask({ title: say(language, MY_FILES.domainRemoveTitle, { name: domain }), body: pick(language, MY_FILES.domainRemoveBody), severity: "disruptive", confirmLabel: pick(language, MY_FILES.domainRemoveYes) });
    if (!ok) return;
    try {
      await removeBucketDomain(bucket, domain);
      notify({ message: say(language, MY.removed, { name: domain }) });
      reload();
      void space.reload();
    } catch (caught) {
      notify({ message: myErrorSentence(language, caught), tone: "error" });
    }
  };

  return (
    <SectionCard
      title={pick(language, MY_FILES.domains)}
      hint={pick(language, MY_FILES.domainsHint)}
      action={space.canWrite ? <Button variant="outlined" startIcon={<LinkRoundedIcon />} onClick={() => setAdding(true)} sx={{ minHeight: 40 }}>{pick(language, MY_FILES.addDomain)}</Button> : undefined}
    >
      <Stack spacing={1.5}>
        {error ? <MyError error={error} onRetry={reload} /> : null}
        {loading && !items ? <Loading /> : null}
        {items && items.length === 0 && <Typography variant="body2" color="text.secondary">{pick(language, MY_FILES.domainsEmpty)}</Typography>}
        {(items ?? []).map((item) => (
          <Box key={item.domain} sx={{ border: 1, borderColor: "divider", borderRadius: 2, p: 1.5 }}>
            <Stack direction="row" alignItems="center" gap={1} flexWrap="wrap">
              <Typography fontWeight={650} sx={{ flex: 1, minWidth: 0 }} noWrap><Ltr>{item.domain}</Ltr></Typography>
              <StatusPill tone={item.verified ? "ok" : "warn"} label={pick(language, item.verified ? MY_DNS.active : MY_DNS.waiting)} />
              {space.canWrite && (
                <Button size="small" color="error" startIcon={<LinkOffRoundedIcon />} onClick={() => void remove(item.domain)} sx={{ minHeight: 40 }}>{pick(language, MY.remove)}</Button>
              )}
            </Stack>
            {item.verified && item.route && (
              <RouteState route={item.route} busy={checking === item.domain} disabled={checking !== null} canRetry={space.canWrite} onRetry={() => void retry(item.domain)} />
            )}
            {!item.verified && item.verification && (
              <Stack spacing={1.5} sx={{ mt: 1.5 }}>
                <VerificationSteps methods={item.verification.methods} />
                {space.canWrite && (
                  <Box>
                    <Button variant="contained" size="small" disabled={checking !== null} onClick={() => void verify(item.domain)} startIcon={checking === item.domain ? <CircularProgress size={14} color="inherit" /> : <FactCheckRoundedIcon />} sx={{ minHeight: 40 }}>
                      {pick(language, checking === item.domain ? MY_DNS.checking : MY_DNS.checkNow)}
                    </Button>
                  </Box>
                )}
              </Stack>
            )}
          </Box>
        ))}
        {checkError ? <MyError error={checkError} onClose={() => setCheckError(null)} /> : null}
      </Stack>
      {adding && (
        <NameDialog
          title={say(language, MY_FILES.addDomainTitle, { name: bucket })}
          hint={pick(language, MY_FILES.addDomainHint)}
          label={pick(language, MY_FILES.domainLabel)}
          saveLabel={pick(language, MY_FILES.addDomain)}
          validate={(value) => (/^(?!-)[a-z0-9-]+(\.[a-z0-9-]+)+$/i.test(value.trim()) ? null : pick(language, MY_DNS.domainBad))}
          onClose={() => setAdding(false)}
          onSubmit={async (value) => {
            await addBucketDomain(bucket, value.trim().toLowerCase());
            setAdding(false);
            notify({ message: say(language, MY_FILES.domainAdded, { name: value.trim() }), tone: "success" });
            reload();
            void space.reload();
          }}
        />
      )}
      {dialog}
      {snackbar}
    </SectionCard>
  );
}

// ── folders ──────────────────────────────────────────────────────────────────

function BucketsTab({ createRequest }: { createRequest: number }) {
  const { language } = useKit();
  const space = useMySpace();
  const loader = useCallback((signal: AbortSignal) => fetchMyBuckets(signal), []);
  const { data, error, loading, reload } = useLoader(loader);
  const [creating, setCreating] = useState(false);
  const [open, setOpen] = useState<string | null>(null);
  const { ask, dialog } = useConfirmAction();
  const { notify, snackbar } = useUndoSnackbar();
  const prefix = data?.suggestedPrefix ?? (space.workspace?.slug ? `${space.workspace.slug}-` : "");
  const limit = numericLimit(space.workspace, "s3_buckets");

  useEffect(() => {
    if (createRequest > 0 && space.canWrite) setCreating(true);
  }, [createRequest, space.canWrite]);

  const buckets = data?.items ?? [];
  const current = buckets.find((bucket) => bucket.name === open) ?? null;

  const togglePublic = async (bucket: MyBucket) => {
    if (!bucket.public_read) {
      const ok = await ask({ title: say(language, MY_FILES.publicTitle, { name: bucket.name }), body: pick(language, MY_FILES.publicBody), severity: "disruptive", confirmLabel: pick(language, MY_FILES.publicYes) });
      if (!ok) return;
    }
    try {
      await setBucketPublic(bucket.name, !bucket.public_read);
      notify({ message: say(language, bucket.public_read ? MY_FILES.nowPrivate : MY_FILES.nowPublic, { name: bucket.name }), tone: "success" });
      reload();
    } catch (caught) {
      notify({ message: myErrorSentence(language, caught), tone: "error" });
    }
  };

  const remove = async (bucket: MyBucket) => {
    const ok = await ask({ title: say(language, MY_FILES.deleteTitle, { name: bucket.name }), body: pick(language, MY_FILES.deleteBody), severity: "destructive", undoable: false, typed: nameConfirmation(bucket.name, bucket.name) });
    if (!ok) return;
    try {
      await deleteMyBucket(bucket.name);
      notify({ message: say(language, MY.removed, { name: bucket.name }) });
      if (open === bucket.name) setOpen(null);
      reload();
      void space.reload();
    } catch (caught) {
      notify({ message: myErrorSentence(language, caught), tone: "error" });
    }
  };

  if (current) {
    return (
      <Stack spacing={2}>
        <Stack direction="row" alignItems="center" gap={1} flexWrap="wrap">
          <Button startIcon={<ArrowBackRoundedIcon sx={{ transform: language === "fa" ? "scaleX(-1)" : undefined }} />} onClick={() => setOpen(null)} sx={{ minHeight: 44 }}>{pick(language, MY_FILES.back)}</Button>
          <Typography variant="h6" component="h2" sx={{ flex: 1, minWidth: 0 }} noWrap><Ltr>{current.name}</Ltr></Typography>
          <StatusPill tone={current.public_read ? "warn" : "ok"} label={pick(language, current.public_read ? MY_FILES.public : MY_FILES.private)} />
        </Stack>
        <SectionCard flush>
          <Box sx={{ p: { xs: 1.5, sm: 2 } }}>
            <S3FileManager
              bucket={current.name}
              language={language}
              canWrite={space.canWrite}
              base={MY_BUCKETS_BASE}
              hideNoAccess
              onChanged={() => {
                reload();
                void space.reload();
              }}
            />
          </Box>
        </SectionCard>
        {current.public_read && <Typography variant="caption" color="text.secondary">{pick(language, MY_FILES.publicNote)}</Typography>}
        {space.has("s3_bucket_domains") && <BucketDomains bucket={current.name} />}
        {snackbar}
      </Stack>
    );
  }

  const columns: ListColumn<MyBucket>[] = [
    { key: "name", header: pick(language, MY_FILES.nameLabel), render: (bucket) => <Stack direction="row" gap={1} alignItems="center"><FolderRoundedIcon sx={{ color: "#f59e0b" }} aria-hidden /><Typography fontWeight={650} component="span"><Ltr>{bucket.name}</Ltr></Typography></Stack> },
    { key: "files", header: pick(language, MY_FILES.filesCol), render: (bucket) => (bucket.objects === null ? "—" : formatNumber(bucket.objects, language)) },
    { key: "size", header: pick(language, MY_FILES.size), align: "end", render: (bucket) => (bucket.bytes === null ? "—" : formatBytes(bucket.bytes, language)) },
    { key: "access", header: pick(language, MY.status), render: (bucket) => <StatusPill tone={bucket.public_read ? "warn" : "ok"} label={pick(language, bucket.public_read ? MY_FILES.public : MY_FILES.private)} /> }
  ];
  const actions: RowAction<MyBucket>[] = [
    { key: "open", label: pick(language, MY.open), icon: FolderOpenRoundedIcon, onClick: (bucket) => setOpen(bucket.name) },
    {
      key: "public",
      label: pick(language, MY_FILES.makePublic),
      icon: PublicRoundedIcon,
      hidden: (bucket) => bucket.public_read || !space.canWrite || !space.has("s3_public_links"),
      onClick: (bucket) => void togglePublic(bucket)
    },
    { key: "private", label: pick(language, MY_FILES.makePrivate), icon: LockRoundedIcon, hidden: (bucket) => !bucket.public_read || !space.canWrite, onClick: (bucket) => void togglePublic(bucket) },
    { key: "delete", label: pick(language, MY.remove), icon: DeleteOutlineRoundedIcon, danger: true, hidden: () => !space.canWrite, onClick: (bucket) => void remove(bucket) }
  ];

  return (
    <Stack spacing={2.5}>
      <SectionCard
        title={pick(language, MY_FILES.buckets)}
        hint={pick(language, MY_FILES.bucketsHint)}
        status={limit !== null ? <Typography variant="caption" color="text.secondary">{say(language, MY.usageOf, { used: formatNumber(buckets.length, language), limit: formatNumber(limit, language) })}</Typography> : undefined}
        flush
      >
        {error ? <Box sx={{ p: 2 }}><MyError error={error} onRetry={reload} /></Box> : null}
        {loading && !data ? <Loading /> : null}
        {data && (
          <ResponsiveList
            label={pick(language, MY_FILES.listLabel)}
            rows={buckets}
            rowKey={(bucket) => bucket.name}
            columns={columns}
            card={{
              title: (bucket) => <Ltr>{bucket.name}</Ltr>,
              meta: (bucket) => [bucket.objects === null ? null : say(language, MY_FILES.files, { n: bucket.objects }), bucket.bytes === null ? null : formatBytes(bucket.bytes, language)].filter(Boolean).join(" · "),
              status: (bucket) => <StatusPill tone={bucket.public_read ? "warn" : "ok"} label={pick(language, bucket.public_read ? MY_FILES.public : MY_FILES.private)} />
            }}
            actions={actions}
            onRowClick={(bucket) => setOpen(bucket.name)}
            empty={
              <EmptyState
                icon={CreateNewFolderRoundedIcon}
                title={pick(language, MY_FILES.emptyTitle)}
                body={pick(language, MY_FILES.emptyBody)}
                action={space.canWrite ? <Button variant="contained" startIcon={<CreateNewFolderRoundedIcon />} onClick={() => setCreating(true)}>{pick(language, MY_FILES.create)}</Button> : undefined}
              />
            }
          />
        )}
      </SectionCard>
      {data?.endpoint && <SectionCard><CopyField label={pick(language, MY_FILES.endpoint)} value={data.endpoint} /></SectionCard>}
      {creating && (
        <NameDialog
          title={pick(language, MY_FILES.createTitle)}
          hint={`${pick(language, MY_FILES.createHint)}${prefix ? ` ${say(language, MY_FILES.nameSuggest, { name: `${prefix}files` })}` : ""}`}
          label={pick(language, MY_FILES.nameLabel)}
          initial={prefix}
          saveLabel={pick(language, MY_FILES.create)}
          validate={(value) => (BUCKET_NAME.test(value.trim()) && !value.includes("--") ? null : pick(language, MY_FILES.nameRule))}
          onClose={() => setCreating(false)}
          onSubmit={async (value) => {
            const name = value.trim();
            await createMyBucket(name);
            setCreating(false);
            notify({ message: say(language, MY_FILES.created, { name }), tone: "success" });
            reload();
            void space.reload();
            setOpen(name);
          }}
        />
      )}
      {dialog}
      {snackbar}
    </Stack>
  );
}

// ── access keys ──────────────────────────────────────────────────────────────

function NewKeyDialog({ buckets, onClose, onCreated }: { buckets: string[]; onClose: () => void; onCreated: (secret: NewS3Key | null, name: string) => void }) {
  const { language } = useKit();
  const [name, setName] = useState("");
  const [level, setLevel] = useState<KeyTemplate>("read_write");
  const [chosen, setChosen] = useState<string[]>([]);
  const [touched, setTouched] = useState(false);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<unknown>(null);
  const problem = name.trim() ? null : pick(language, MY_FILES.keyNameRequired);

  const submit = async () => {
    setTouched(true);
    if (problem) return;
    setBusy(true);
    setError(null);
    try {
      onCreated(await createMyKey(name.trim(), level, chosen), name.trim());
    } catch (caught) {
      setError(caught);
    } finally {
      setBusy(false);
    }
  };

  return (
    <FormDialog title={pick(language, MY_FILES.newKeyTitle)} submitLabel={pick(language, MY_FILES.keyCreate)} busy={busy} error={error} onSubmit={() => void submit()} onClose={onClose} wide>
      <TextField
        autoFocus
        label={pick(language, MY_FILES.keyName)}
        placeholder={pick(language, MY_FILES.keyNamePlaceholder)}
        value={name}
        onChange={(event) => setName(event.target.value)}
        error={touched && Boolean(problem)}
        helperText={touched && problem ? problem : " "}
        fullWidth
      />
      <Typography variant="subtitle2">{pick(language, MY_FILES.keyLevel)}</Typography>
      <ChoiceCards<KeyTemplate>
        label={pick(language, MY_FILES.keyLevel)}
        value={level}
        onChange={setLevel}
        options={(["read_only", "read_write", "admin"] as KeyTemplate[]).map((key) => ({
          key,
          icon: LEVEL_ICON[key],
          title: levelTitle(language, key),
          body: pick(language, MY_FILES[`level_${key}_body` as const]),
          tone: key === "admin" ? "warning" : undefined
        }))}
      />
      {level !== "admin" && buckets.length > 0 && (
        <Box>
          <Typography variant="subtitle2">{pick(language, MY_FILES.keyBuckets)}</Typography>
          <Typography variant="caption" color="text.secondary">{pick(language, MY_FILES.keyBucketsHint)}</Typography>
          <FormGroup>
            {buckets.map((bucket) => (
              <FormControlLabel
                key={bucket}
                control={<Checkbox checked={chosen.includes(bucket)} onChange={(event) => setChosen((list) => (event.target.checked ? [...list, bucket] : list.filter((item) => item !== bucket)))} />}
                label={<Ltr>{bucket}</Ltr>}
              />
            ))}
          </FormGroup>
        </Box>
      )}
    </FormDialog>
  );
}

function KeysTab() {
  const { language } = useKit();
  const space = useMySpace();
  const loader = useCallback((signal: AbortSignal) => fetchMyIdentities(signal), []);
  const { items, error, loading, reload } = useList<MyIdentity>(loader);
  const bucketsLoader = useCallback((signal: AbortSignal) => fetchMyBuckets(signal), []);
  const buckets = useLoader(bucketsLoader);
  const [creating, setCreating] = useState(false);
  const [secret, setSecret] = useState<NewS3Key | null>(null);
  const { ask, dialog } = useConfirmAction();
  const { notify, snackbar } = useUndoSnackbar();
  const limit = numericLimit(space.workspace, "s3_keys");

  const remove = async (identity: MyIdentity) => {
    const ok = await ask({ title: say(language, MY_FILES.keyDeleteTitle, { name: identity.name }), body: pick(language, MY_FILES.keyDeleteBody), severity: "destructive", undoable: false });
    if (!ok) return;
    try {
      await deleteMyIdentity(identity.id);
      notify({ message: say(language, MY.removed, { name: identity.name }) });
      reload();
      void space.reload();
    } catch (caught) {
      notify({ message: myErrorSentence(language, caught), tone: "error" });
    }
  };

  const bucketText = (identity: MyIdentity) => (identity.template === "admin" || identity.buckets.length === 0 ? pick(language, MY_FILES.allBuckets) : identity.buckets.join("، "));
  const columns: ListColumn<MyIdentity>[] = [
    { key: "name", header: pick(language, MY.name), render: (identity) => <Typography fontWeight={650} component="span">{identity.name}</Typography> },
    { key: "level", header: pick(language, MY_FILES.keyLevelCol), render: (identity) => levelTitle(language, identity.template) },
    { key: "buckets", header: pick(language, MY_FILES.keyBucketsCol), render: (identity) => bucketText(identity) },
    { key: "keys", header: "ID", advancedOnly: true, ltr: true, render: (identity) => <Ltr mono>{identity.access_key_id}</Ltr> },
    { key: "created", header: pick(language, MY.created), render: (identity) => <RelativeTime value={identity.created_at ?? null} /> }
  ];

  return (
    <SectionCard
      title={pick(language, MY_FILES.keys)}
      hint={pick(language, MY_FILES.keysHint)}
      status={limit !== null ? <Typography variant="caption" color="text.secondary">{say(language, MY.usageOf, { used: formatNumber((items ?? []).length, language), limit: formatNumber(limit, language) })}</Typography> : undefined}
      action={space.canWrite ? <Button variant="outlined" startIcon={<KeyRoundedIcon />} onClick={() => setCreating(true)} sx={{ minHeight: 40 }}>{pick(language, MY_FILES.newKey)}</Button> : undefined}
      flush
    >
      {error ? <Box sx={{ p: 2 }}><MyError error={error} onRetry={reload} /></Box> : null}
      {loading && !items ? <Loading /> : null}
      {items && (
        <ResponsiveList
          label={pick(language, MY_FILES.keys)}
          rows={items}
          rowKey={(identity) => identity.id}
          columns={columns}
          card={{ title: (identity) => identity.name, meta: (identity) => `${levelTitle(language, identity.template)} · ${bucketText(identity)}` }}
          actions={space.canWrite ? [{ key: "delete", label: pick(language, MY.remove), icon: DeleteOutlineRoundedIcon, danger: true, onClick: (identity) => void remove(identity) }] : undefined}
          empty={
            <EmptyState
              icon={KeyRoundedIcon}
              title={pick(language, MY_FILES.keysEmptyTitle)}
              body={pick(language, MY_FILES.keysEmptyBody)}
              action={space.canWrite ? <Button variant="contained" startIcon={<KeyRoundedIcon />} onClick={() => setCreating(true)}>{pick(language, MY_FILES.newKey)}</Button> : undefined}
            />
          }
        />
      )}
      {creating && (
        <NewKeyDialog
          buckets={(buckets.data?.items ?? []).map((bucket) => bucket.name)}
          onClose={() => setCreating(false)}
          onCreated={(created, name) => {
            setCreating(false);
            setSecret(created);
            if (!created) notify({ message: say(language, MY_FILES.created, { name }), tone: "success" });
            reload();
            void space.reload();
          }}
        />
      )}
      <KeySecretDialog secret={secret} onClose={() => setSecret(null)} />
      {dialog}
      {snackbar}
    </SectionCard>
  );
}

export default function MyFiles({ createRequest }: { createRequest: number }) {
  const { language } = useKit();
  const [tab, setTab] = useState<"folders" | "keys">("folders");
  return (
    <Stack spacing={2}>
      <Tabs value={tab} onChange={(_event, value: "folders" | "keys") => setTab(value)} variant="scrollable" allowScrollButtonsMobile aria-label={pick(language, MY.tabFiles)}>
        <Tab value="folders" label={pick(language, MY_FILES.tabFolders)} sx={{ minHeight: 44 }} />
        <Tab value="keys" label={pick(language, MY_FILES.tabKeys)} sx={{ minHeight: 44 }} />
      </Tabs>
      {tab === "folders" ? <BucketsTab createRequest={createRequest} /> : <KeysTab />}
    </Stack>
  );
}
