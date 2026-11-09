/**
 * «فضای من › دامنه‌ها» (docs/43 §3 DNS, §4): add a domain with the default template, prove it's yours
 * (TXT or NS, «بررسی کن»), records, and signing when the plan allows it.
 *
 * Reuses the admin DNS pieces against `/api/v1/my/dns` (`<DnsApiScope>`): `RecordDialog` (limited to
 * the plan's record types), `TemplateChooser`, `ApplyTemplateDialog` and `ZoneSigningTab`.
 */
import { useCallback, useEffect, useState } from "react";
import { Box, Button, CircularProgress, FormControlLabel, Stack, Switch, Tab, Tabs, TextField, Typography } from "@mui/material";
import AddRoundedIcon from "@mui/icons-material/AddRounded";
import ArrowBackRoundedIcon from "@mui/icons-material/ArrowBackRounded";
import EditRoundedIcon from "@mui/icons-material/EditRounded";
import DeleteOutlineRoundedIcon from "@mui/icons-material/DeleteOutlineRounded";
import FolderOpenRoundedIcon from "@mui/icons-material/FolderOpenRounded";
import TravelExploreRoundedIcon from "@mui/icons-material/TravelExploreRounded";
import DashboardCustomizeRoundedIcon from "@mui/icons-material/DashboardCustomizeRounded";
import FactCheckRoundedIcon from "@mui/icons-material/FactCheckRounded";
import { MY, MY_DNS, nameConfirmation, pick, say } from "../copy";
import { CopyField, EmptyState, Ltr, Notice, ResponsiveList, SectionCard, StatusPill, useConfirmAction, useKit, useUndoSnackbar, type ListColumn, type RowAction } from "../kit";
import { deleteRecord, fetchRecords, isDnsName, recordTypeLabel, recordValue, type DnsRecord } from "../dns";
import { DnsApiScope, FormDialog, Loading, ltrInput, useList, useLoader } from "../dnsUi";
import { formatTtl, RecordDialog, recordNameLabel } from "../DnsNames";
import { ApplyTemplateDialog, TemplateChooser, type TemplateChoice } from "../DnsTemplates";
import { fetchZoneDnssec, type ZoneDnssecStatus } from "../dnsFinal";
import { mutateJson } from "../api";
import { formatNumber } from "../format";
import { createMyZone, deleteMyZone, fetchMyZones, fetchVerification, listLimit, MY_DNS_BASE, numericLimit, verifyZone, type MyZone, type Verification } from "./myApi";
import { useMySpace } from "./MySpaceContext";
import { MyError, myErrorSentence, VerificationSteps } from "./MyKit";

function AddZoneDialog({ onClose, onCreated }: { onClose: () => void; onCreated: (zone: MyZone) => void }) {
  const { language } = useKit();
  const space = useMySpace();
  const [name, setName] = useState("");
  const [touched, setTouched] = useState(false);
  const [choice, setChoice] = useState<TemplateChoice>({ templateId: null, variables: {}, ready: true, known: false });
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<unknown>(null);
  const clean = name.trim().toLowerCase().replace(/^https?:\/\//, "").replace(/\/.*$/, "").replace(/\.$/, "");
  const valid = isDnsName(clean) && clean.includes(".");
  const templates = space.has("dns_templates");

  const submit = async () => {
    setTouched(true);
    if (!valid || (templates && !choice.ready)) return;
    setBusy(true);
    setError(null);
    try {
      const body: { name: string; template_id?: string | null; variables?: Record<string, string> } = { name: clean };
      if (templates && (choice.known || choice.templateId)) {
        body.template_id = choice.templateId;
        if (choice.templateId) body.variables = choice.variables;
      }
      const created = await createMyZone(body);
      onCreated({ ...created, name: created.name || clean });
    } catch (caught) {
      setError(caught);
    } finally {
      setBusy(false);
    }
  };

  return (
    <FormDialog title={pick(language, MY_DNS.addTitle)} hint={pick(language, MY_DNS.addHint)} submitLabel={pick(language, MY_DNS.add)} busy={busy} error={error} onSubmit={() => void submit()} onClose={onClose} wide={templates}>
      <TextField
        autoFocus
        label={pick(language, MY_DNS.domain)}
        value={name}
        onChange={(event) => setName(event.target.value)}
        placeholder="example.com"
        error={(touched || name.length > 3) && !valid}
        helperText={(touched || name.length > 3) && !valid ? pick(language, MY_DNS.domainBad) : pick(language, MY_DNS.domainHint)}
        fullWidth
        slotProps={ltrInput}
      />
      {templates && <TemplateChooser zone={valid ? clean : "example.com"} zoneValid={valid} touched={touched} onChange={setChoice} />}
    </FormDialog>
  );
}

function VerificationCard({ zone, onVerified }: { zone: string; onVerified: () => void }) {
  const { language } = useKit();
  const loader = useCallback((signal: AbortSignal) => fetchVerification(zone, signal), [zone]);
  const { data, error, loading, reload } = useLoader<Verification>(loader);
  const [checking, setChecking] = useState(false);
  const [result, setResult] = useState<"no" | null>(null);
  const [checkError, setCheckError] = useState<unknown>(null);
  const { notify, snackbar } = useUndoSnackbar();

  const check = async () => {
    setChecking(true);
    setResult(null);
    setCheckError(null);
    try {
      if (await verifyZone(zone)) {
        notify({ message: say(language, MY_DNS.verified, { name: zone }), tone: "success" });
        onVerified();
      } else {
        setResult("no");
      }
    } catch (caught) {
      setCheckError(caught);
    } finally {
      setChecking(false);
    }
  };

  return (
    <SectionCard title={pick(language, MY_DNS.verifyTitle)} hint={pick(language, MY_DNS.verifyBody)} tone="warning">
      <Stack spacing={2}>
        {loading && !data ? <Loading /> : null}
        {error ? <MyError error={error} title={pick(language, MY_DNS.verifyLoadFailed)} onRetry={reload} /> : null}
        {data ? <VerificationSteps methods={data.methods} /> : null}
        {result === "no" && <Notice tone="info">{pick(language, MY_DNS.notYet)}</Notice>}
        {checkError ? <MyError error={checkError} onRetry={() => void check()} onClose={() => setCheckError(null)} /> : null}
        <Box>
          <Button variant="contained" onClick={() => void check()} disabled={checking} startIcon={checking ? <CircularProgress size={16} color="inherit" /> : <FactCheckRoundedIcon />} sx={{ minHeight: 44 }}>
            {pick(language, checking ? MY_DNS.checking : MY_DNS.checkNow)}
          </Button>
        </Box>
      </Stack>
      {snackbar}
    </SectionCard>
  );
}

function RecordsCard({ zone }: { zone: MyZone }) {
  const { language } = useKit();
  const space = useMySpace();
  const loader = useCallback((signal: AbortSignal) => fetchRecords(zone.name, signal), [zone.name]);
  const { items, error, loading, reload } = useList<DnsRecord>(loader);
  const [editing, setEditing] = useState<{ item: DnsRecord | null; key: number } | null>(null);
  const [applying, setApplying] = useState(false);
  const { ask, dialog } = useConfirmAction();
  const { notify, snackbar } = useUndoSnackbar();
  const types = listLimit(space.workspace, "dns_record_types");
  const limit = numericLimit(space.workspace, "dns_records_per_zone");
  const records = (items ?? []).filter((record) => record.type !== "SOA");
  const fqdn = (name: string) => (name === "@" || !name ? zone.name : `${name}.${zone.name}`);
  const editable = (record: DnsRecord) => space.canWrite && (!types || types.includes(record.type)) && record.type !== "SOA";

  const remove = async (record: DnsRecord) => {
    const ok = await ask({ title: say(language, MY_DNS.recordDeleteTitle, { name: fqdn(record.name) }), body: pick(language, MY_DNS.recordDeleteBody), severity: "destructive", undoable: false });
    if (!ok) return;
    try {
      await deleteRecord(zone.name, record.id);
      notify({ message: say(language, MY.removed, { name: fqdn(record.name) }) });
      reload();
    } catch (caught) {
      notify({ message: myErrorSentence(language, caught), tone: "error" });
    }
  };

  const columns: ListColumn<DnsRecord>[] = [
    { key: "name", header: pick(language, MY_DNS.colName), render: (record) => recordNameLabel(language, record.name) },
    { key: "type", header: pick(language, MY_DNS.colType), render: (record) => recordTypeLabel(language, record.type) },
    { key: "value", header: pick(language, MY_DNS.colValue), ltr: true, render: (record) => <Ltr mono>{recordValue(record)}</Ltr> },
    { key: "ttl", header: pick(language, MY_DNS.colTtl), advancedOnly: true, render: (record) => (typeof record.ttl === "number" ? formatTtl(language, record.ttl) : "—") }
  ];
  const actions: RowAction<DnsRecord>[] = [
    { key: "edit", label: pick(language, MY_DNS.editRecord), icon: EditRoundedIcon, hidden: (record) => !editable(record), onClick: (record) => setEditing({ item: record, key: Date.now() }) },
    { key: "delete", label: pick(language, MY.remove), icon: DeleteOutlineRoundedIcon, danger: true, hidden: (record) => !editable(record), onClick: (record) => void remove(record) }
  ];

  return (
    <SectionCard
      title={pick(language, MY_DNS.recordsTitle)}
      hint={pick(language, MY_DNS.recordsHint)}
      status={<Typography variant="caption" color="text.secondary">{limit !== null ? say(language, MY_DNS.recordsOf, { n: records.length, limit }) : say(language, MY_DNS.records, { n: records.length })}</Typography>}
      action={space.canWrite ? (
        <Stack direction="row" gap={1} flexWrap="wrap">
          {space.has("dns_templates") && <Button startIcon={<DashboardCustomizeRoundedIcon />} onClick={() => setApplying(true)} sx={{ minHeight: 40 }}>{pick(language, MY_DNS.applyTemplate)}</Button>}
          <Button variant="outlined" startIcon={<AddRoundedIcon />} onClick={() => setEditing({ item: null, key: Date.now() })} sx={{ minHeight: 40 }}>{pick(language, MY_DNS.addRecord)}</Button>
        </Stack>
      ) : undefined}
      flush
    >
      {error ? <Box sx={{ p: 2 }}><MyError error={error} onRetry={reload} /></Box> : null}
      {loading && !items ? <Loading /> : null}
      {types && space.canWrite ? <Box sx={{ px: 2, pt: 1 }}><Typography variant="caption" color="text.secondary">{say(language, MY_DNS.limitNote, { types: types.join("، ") })}</Typography></Box> : null}
      {items && (
        <ResponsiveList
          label={pick(language, MY_DNS.recordsTitle)}
          rows={records}
          rowKey={(record) => record.id}
          columns={columns}
          card={{
            title: (record) => <>{recordNameLabel(language, record.name)} · {recordTypeLabel(language, record.type)}</>,
            meta: (record) => <Ltr mono>{recordValue(record)}</Ltr>,
            status: (record) => (record.disabled ? <StatusPill tone="off" label={pick(language, MY_DNS.off)} /> : null)
          }}
          actions={space.canWrite ? actions : undefined}
          empty={
            <EmptyState
              compact
              title={pick(language, MY_DNS.recordsEmpty)}
              body={pick(language, MY_DNS.recordsEmptyBody)}
              action={space.canWrite ? <Button variant="contained" startIcon={<AddRoundedIcon />} onClick={() => setEditing({ item: null, key: Date.now() })}>{pick(language, MY_DNS.addRecord)}</Button> : undefined}
            />
          }
        />
      )}
      {editing && (
        <RecordDialog
          key={editing.key}
          zone={zone.name}
          initial={editing.item}
          groups={null}
          types={types}
          onClose={() => setEditing(null)}
          onSaved={(name) => {
            setEditing(null);
            notify({ message: say(language, MY_DNS.recordSaved, { name }), tone: "success" });
            reload();
            void space.reload();
          }}
        />
      )}
      {applying && (
        <ApplyTemplateDialog
          zone={zone.name}
          onClose={() => setApplying(false)}
          onApplied={() => {
            setApplying(false);
            notify({ message: pick(language, MY_DNS.templateApplied), tone: "success" });
            reload();
          }}
        />
      )}
      {dialog}
      {snackbar}
    </SectionCard>
  );
}

/** «امضای امنیتی» (docs/43 §0.1: `GET …/{z}/dnssec`, `PUT …/{z}/dnssec {enabled}`), with the DS record for the registrar. */
function SigningCard({ zone, onChanged }: { zone: string; onChanged: () => void }) {
  const { language } = useKit();
  const space = useMySpace();
  const loader = useCallback((signal: AbortSignal) => fetchZoneDnssec(zone, signal), [zone]);
  const { data, error, loading, reload } = useLoader<ZoneDnssecStatus>(loader);
  const [busy, setBusy] = useState(false);
  const [saveError, setSaveError] = useState<unknown>(null);
  const { ask, dialog } = useConfirmAction();
  const { notify, snackbar } = useUndoSnackbar();
  const enabled = data?.enabled === true;
  const ds = (data?.ds ?? []).map((item) => item.text || [item.key_tag, item.algorithm, item.digest_type, item.digest].filter((part) => part !== undefined && part !== null).join(" ")).filter(Boolean);

  const toggle = async (next: boolean) => {
    if (!next) {
      const ok = await ask({ title: say(language, MY_DNS.signOffTitle, { zone }), body: pick(language, MY_DNS.signOffBody), severity: "disruptive", confirmLabel: pick(language, MY_DNS.signOffYes) });
      if (!ok) return;
    }
    setBusy(true);
    setSaveError(null);
    try {
      await mutateJson(`${MY_DNS_BASE}/zones/${encodeURIComponent(zone)}/dnssec`, { method: "PUT", body: { enabled: next } });
      notify({ message: say(language, next ? MY_DNS.signedOn : MY_DNS.signedOff, { zone }), tone: "success" });
      reload();
      onChanged();
    } catch (caught) {
      setSaveError(caught);
    } finally {
      setBusy(false);
    }
  };

  return (
    <SectionCard title={pick(language, MY_DNS.signingTitle)} hint={pick(language, MY_DNS.signingHint)}>
      <Stack spacing={2}>
        {error ? <MyError error={error} onRetry={reload} /> : null}
        {saveError ? <MyError error={saveError} onClose={() => setSaveError(null)} /> : null}
        {loading && !data ? <Loading /> : null}
        {data && (
          <FormControlLabel
            control={<Switch checked={enabled} disabled={busy || !space.canWrite} onChange={(event) => void toggle(event.target.checked)} />}
            label={pick(language, MY_DNS.signOn)}
          />
        )}
        {enabled && ds.length > 0 && (
          <Box>
            <Typography fontWeight={720}>{pick(language, MY_DNS.dsTitle)}</Typography>
            <Typography variant="body2" color="text.secondary" sx={{ mb: 1.5 }}>{pick(language, MY_DNS.dsHint)}</Typography>
            <Stack spacing={1.25}>
              {ds.map((text, index) => <CopyField key={text} label={say(language, MY_DNS.dsRecord, { n: index + 1 })} value={text} />)}
            </Stack>
          </Box>
        )}
        {enabled && data && ds.length === 0 && <Notice>{pick(language, MY_DNS.signingPreparing)}</Notice>}
      </Stack>
      {dialog}
      {snackbar}
    </SectionCard>
  );
}

type DetailTab = "records" | "verify" | "signing";

function ZoneDetail({ zone, onBack, onChanged }: { zone: MyZone; onBack: () => void; onChanged: () => void }) {
  const { language } = useKit();
  const space = useMySpace();
  const pending = !zone.verified;
  const tabs: DetailTab[] = pending ? ["verify", "records"] : ["records", ...(space.has("dns_dnssec") && space.canWrite ? (["signing"] as DetailTab[]) : [])];
  const [tab, setTab] = useState<DetailTab>(tabs[0]);
  const current = tabs.includes(tab) ? tab : tabs[0];
  const label: Record<DetailTab, string> = { records: pick(language, MY_DNS.tabRecords), verify: pick(language, MY_DNS.tabVerify), signing: pick(language, MY_DNS.tabSigning) };
  return (
    <Stack spacing={2}>
      <Stack direction="row" alignItems="center" gap={1} flexWrap="wrap">
        <Button startIcon={<ArrowBackRoundedIcon sx={{ transform: language === "fa" ? "scaleX(-1)" : undefined }} />} onClick={onBack} sx={{ minHeight: 44 }}>{pick(language, MY_DNS.backToList)}</Button>
        <Typography variant="h6" component="h2" sx={{ flex: 1, minWidth: 0 }} noWrap><Ltr>{zone.name}</Ltr></Typography>
        <StatusPill tone={pending ? "warn" : "ok"} label={pick(language, pending ? MY_DNS.waiting : MY_DNS.active)} />
      </Stack>
      {tabs.length > 1 && (
        <Tabs value={current} onChange={(_event, value: DetailTab) => setTab(value)} variant="scrollable" allowScrollButtonsMobile aria-label={zone.name}>
          {tabs.map((key) => <Tab key={key} value={key} label={label[key]} sx={{ minHeight: 44 }} />)}
        </Tabs>
      )}
      {current === "verify" && <VerificationCard zone={zone.name} onVerified={onChanged} />}
      {current === "records" && <RecordsCard zone={zone} />}
      {current === "signing" && <SigningCard zone={zone.name} onChanged={onChanged} />}
    </Stack>
  );
}

export default function MyDomains({ createRequest }: { createRequest: number }) {
  const { language } = useKit();
  const space = useMySpace();
  const loader = useCallback((signal: AbortSignal) => fetchMyZones(signal), []);
  const { items, error, loading, reload } = useList<MyZone>(loader);
  const [adding, setAdding] = useState(false);
  const [open, setOpen] = useState<string | null>(null);
  const { ask, dialog } = useConfirmAction();
  const { notify, snackbar } = useUndoSnackbar();
  const limit = numericLimit(space.workspace, "dns_zones");

  useEffect(() => {
    if (createRequest > 0 && space.canWrite) setAdding(true);
  }, [createRequest, space.canWrite]);

  const remove = async (zone: MyZone) => {
    const ok = await ask({
      title: say(language, MY_DNS.deleteTitle, { name: zone.name }),
      body: pick(language, MY_DNS.deleteBody),
      severity: "destructive",
      undoable: false,
      typed: nameConfirmation(zone.name, zone.name)
    });
    if (!ok) return;
    try {
      await deleteMyZone(zone.name);
      notify({ message: say(language, MY.removed, { name: zone.name }) });
      if (open === zone.name) setOpen(null);
      reload();
      void space.reload();
    } catch (caught) {
      notify({ message: myErrorSentence(language, caught), tone: "error" });
    }
  };

  const zones = items ?? [];
  const openZone = zones.find((zone) => zone.name === open) ?? null;

  const columns: ListColumn<MyZone>[] = [
    { key: "name", header: pick(language, MY_DNS.domain), render: (zone) => <Typography fontWeight={650} component="span"><Ltr>{zone.name}</Ltr></Typography> },
    { key: "status", header: pick(language, MY.status), render: (zone) => <StatusPill tone={zone.verified ? "ok" : "warn"} label={pick(language, zone.verified ? MY_DNS.active : MY_DNS.waiting)} /> },
    { key: "records", header: pick(language, MY_DNS.recordsTitle), render: (zone) => (zone.records === null ? "—" : say(language, MY_DNS.records, { n: zone.records })) },
    { key: "signed", header: pick(language, MY_DNS.tabSigning), render: (zone) => (zone.dnssec ? pick(language, MY_DNS.signed) : "—"), advancedOnly: true }
  ];
  const actions: RowAction<MyZone>[] = [
    { key: "open", label: pick(language, MY.open), icon: FolderOpenRoundedIcon, onClick: (zone) => setOpen(zone.name) },
    { key: "delete", label: pick(language, MY.remove), icon: DeleteOutlineRoundedIcon, danger: true, hidden: () => !space.canWrite, onClick: (zone) => void remove(zone) }
  ];

  return (
    <DnsApiScope base={MY_DNS_BASE}>
      {openZone ? (
        <ZoneDetail
          zone={openZone}
          onBack={() => setOpen(null)}
          onChanged={() => {
            reload();
            void space.reload();
          }}
        />
      ) : (
        <SectionCard
          title={pick(language, MY_DNS.title)}
          hint={pick(language, MY_DNS.hint)}
          status={limit !== null ? <Typography variant="caption" color="text.secondary">{say(language, MY.usageOf, { used: formatNumber(zones.length, language), limit: formatNumber(limit, language) })}</Typography> : undefined}
          flush
        >
          {error ? <Box sx={{ p: 2 }}><MyError error={error} onRetry={reload} /></Box> : null}
          {loading && !items ? <Loading /> : null}
          {items && (
            <ResponsiveList
              label={pick(language, MY_DNS.listLabel)}
              rows={zones}
              rowKey={(zone) => zone.name}
              columns={columns}
              card={{
                title: (zone) => <Ltr>{zone.name}</Ltr>,
                meta: (zone) => (zone.records === null ? null : say(language, MY_DNS.records, { n: zone.records })),
                status: (zone) => <StatusPill tone={zone.verified ? "ok" : "warn"} label={pick(language, zone.verified ? MY_DNS.active : MY_DNS.waiting)} />
              }}
              actions={actions}
              onRowClick={(zone) => setOpen(zone.name)}
              empty={
                <EmptyState
                  icon={TravelExploreRoundedIcon}
                  title={pick(language, MY_DNS.emptyTitle)}
                  body={pick(language, MY_DNS.emptyBody)}
                  action={space.canWrite ? <Button variant="contained" startIcon={<AddRoundedIcon />} onClick={() => setAdding(true)}>{pick(language, MY_DNS.add)}</Button> : undefined}
                />
              }
            />
          )}
        </SectionCard>
      )}
      {adding && (
        <AddZoneDialog
          onClose={() => setAdding(false)}
          onCreated={(zone) => {
            setAdding(false);
            notify({ message: say(language, zone.verified ? MY_DNS.added : MY_DNS.addedVerify, { name: zone.name }), tone: "success" });
            reload();
            void space.reload();
            setOpen(zone.name);
          }}
        />
      )}
      {dialog}
      {snackbar}
    </DnsApiScope>
  );
}
