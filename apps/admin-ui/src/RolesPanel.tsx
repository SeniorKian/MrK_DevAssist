import { useCallback, useEffect, useMemo, useState } from "react";
import {
  Box, Button, Dialog, DialogActions, DialogContent, DialogTitle, Grid, MenuItem, Skeleton, Stack, TextField, Typography,
  useMediaQuery, useTheme
} from "@mui/material";
import AddRoundedIcon from "@mui/icons-material/AddRounded";
import VisibilityRoundedIcon from "@mui/icons-material/VisibilityRounded";
import EditRoundedIcon from "@mui/icons-material/EditRounded";
import DeleteOutlineRoundedIcon from "@mui/icons-material/DeleteOutlineRounded";
import TuneRoundedIcon from "@mui/icons-material/TuneRounded";
import { hasPermission, mutateJson, ApiError } from "./api";
import type { AuthUser } from "./App";
import { EmptyState, FriendlyError, NoAccess, Notice, SectionCard, useConfirmAction, useKit, useUndoSnackbar } from "./kit";
import { PermissionMatrix, RoleCard, closeOver, fieldMessages, indexCatalog, missingDependencies, permissionLabel, roleView, sortRoles, usePermissionCatalog, useRoles, type RoleRecord } from "./kit/people";
import { errorSentence, pick, say, type Bi } from "./copy";

const T = {
  builtinTitle: { fa: "نقش‌های آماده", en: "Built-in roles" },
  builtinHint: { fa: "هر نقش می‌گوید آن شخص چه کارهایی می‌تواند و چه کارهایی نمی‌تواند بکند.", en: "Each role says what a person can and can't do." },
  customTitle: { fa: "نقش‌های سفارشی", en: "Custom roles" },
  customHint: { fa: "اگر هیچ نقش آماده‌ای مناسب نیست، نقش خودتان را بسازید و دقیقاً بگویید چه اجازه‌هایی داشته باشد.", en: "If no built-in role fits, make your own and choose exactly what it may do." },
  customSimpleHint: { fa: "برای ساختن نقش دلخواه، «حالت پیشرفته» را روشن کنید.", en: "Turn on Advanced mode to make your own role." },
  seeAll: { fa: "دیدن همه اجازه‌ها", en: "See all permissions" },
  edit: { fa: "ویرایش", en: "Edit" },
  remove: { fa: "پاک کردن", en: "Delete" },
  newRole: { fa: "ساخت نقش تازه", en: "New role" },
  noCustomTitle: { fa: "هنوز نقش سفارشی ندارید", en: "No custom roles yet" },
  noCustomBody: { fa: "نقش‌های آماده برای بیشتر تیم‌ها کافی است. اگر لازم شد، این‌جا نقش خودتان را بسازید.", en: "The built-in roles fit most teams. If you need something else, make your own here." },
  permissionsOf: { fa: "اجازه‌های «{role}»", en: "Permissions of “{role}”" },
  // editor
  editorNew: { fa: "ساخت نقش تازه", en: "New role" },
  editorEdit: { fa: "ویرایش نقش «{role}»", en: "Edit “{role}”" },
  name: { fa: "نام نقش", en: "Role name" },
  nameRule: { fa: "نام نقش باید بین ۲ تا ۸۰ نویسه باشد.", en: "The role name must be 2 to 80 characters." },
  description: { fa: "توضیح کوتاه (اختیاری)", en: "Short description (optional)" },
  descriptionHint: { fa: "مثلاً «برای همکاران پشتیبانی که فقط پشتیبان می‌گیرند».", en: "For example “For support staff who only run backups”." },
  startFrom: { fa: "شروع از روی", en: "Start from" },
  startBlank: { fa: "خالی (هیچ اجازه‌ای)", en: "Blank (no permissions)" },
  startHint: { fa: "اجازه‌های یک نقش دیگر کپی می‌شود؛ بعد کم و زیادش کنید.", en: "Copies another role's permissions; then adjust them." },
  summary: { fa: "این نقش {count} اجازه دارد{danger}.", en: "This role has {count} permissions{danger}." },
  summaryDanger: { fa: "؛ {count} مورد از آن‌ها خطرناک است", en: "; {count} of them are dangerous" },
  diff: { fa: "نسبت به «{base}»: {added} اضافه، {removed} کم.", en: "Compared with “{base}”: {added} added, {removed} removed." },
  added: { fa: "اضافه شده: {list}", en: "Added: {list}" },
  removed: { fa: "برداشته شده: {list}", en: "Removed: {list}" },
  needOne: { fa: "دست‌کم یک اجازه را تیک بزنید.", en: "Tick at least one permission." },
  save: { fa: "ذخیره نقش", en: "Save role" },
  create: { fa: "ساخت نقش", en: "Create role" },
  missingDep: { fa: "«{name}» بدون «{needs}» کار نمی‌کند؛ آن را هم تیک بزنید.", en: "“{name}” doesn't work without “{needs}”; tick it too." },
  missingSummary: { fa: "چند اجازه به اجازه دیگری نیاز دارند که تیک نخورده. ردیف‌های قرمز را ببینید.", en: "Some permissions need others that aren't ticked. See the red rows." },
  fixDeps: { fa: "تیک زدن خودکار نیازها", en: "Tick what they need" },
  escalationRow: { fa: "شما خودتان این اجازه را ندارید، پس نمی‌توانید آن را به نقشی بدهید.", en: "You don't hold this permission, so you can't give it to a role." },
  escalationSummary: { fa: "این نقش اجازه‌هایی دارد که خودتان ندارید. تیک ردیف‌های قرمز را بردارید.", en: "This role has permissions you don't hold. Untick the red rows." },
  createdToast: { fa: "نقش «{role}» ساخته شد.", en: "“{role}” was created." },
  savedToast: { fa: "نقش «{role}» ذخیره شد. کسانی که این نقش را دارند همین حالا اجازه‌های تازه را می‌گیرند.", en: "“{role}” was saved. People with this role get the new permissions right away." },
  // delete
  deleteTitle: { fa: "نقش «{role}» پاک شود؟", en: "Delete “{role}”?" },
  deleteBody: { fa: "این نقش برای همیشه پاک می‌شود. کسی که این نقش را دارد باید اول نقش دیگری بگیرد.", en: "This role is deleted for good. Anyone who has it must get another role first." },
  deletedToast: { fa: "نقش «{role}» پاک شد.", en: "“{role}” was deleted." },
  inUse: { fa: "نقش «{role}» هنوز برای این افراد است: {people}. اول در بخش «افراد» نقششان را عوض کنید، بعد دوباره پاکش کنید.", en: "“{role}” still belongs to: {people}. Change their role under People first, then delete it again." },
  goPeople: { fa: "رفتن به افراد", en: "Go to People" },
  ownerOnly: { fa: "ساختن و تغییر نقش سفارشی فقط از دست «مالک» برمی‌آید.", en: "Only the owner can make or change custom roles." }
} satisfies Record<string, Bi>;

type EditorState = { mode: "new" } | { mode: "edit"; role: RoleRecord };

export type RolesPanelProps = {
  user: AuthUser;
  /** Increment to open the "new role" editor (the page's primary button, Advanced + owner). */
  createRequest?: number;
};

export function RolesPanel({ user, createRequest = 0 }: RolesPanelProps) {
  const { language, isAdvanced, c } = useKit();
  const theme = useTheme();
  const fullScreen = useMediaQuery(theme.breakpoints.down("sm"));
  const { ask, dialog: confirmDialog } = useConfirmAction();
  const { notify, snackbar } = useUndoSnackbar();
  const canRead = hasPermission(user.permissions, "user:read");
  const isOwner = user.permissions.includes("*");
  const { roles, error, reload } = useRoles(canRead);
  const { catalog } = usePermissionCatalog();
  const index = useMemo(() => indexCatalog(catalog), [catalog]);
  const [viewing, setViewing] = useState<RoleRecord | null>(null);
  const [editor, setEditor] = useState<EditorState | null>(null);
  const [inUse, setInUse] = useState<{ role: string; people: string[] } | null>(null);

  // editor form
  const [name, setName] = useState("");
  const [description, setDescription] = useState("");
  const [base, setBase] = useState("");
  const [selected, setSelected] = useState<string[]>([]);
  const [problems, setProblems] = useState<Record<string, string>>({});
  const [formError, setFormError] = useState<unknown>(null);
  const [summaryProblem, setSummaryProblem] = useState<string | null>(null);
  const [nameError, setNameError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  const sorted = useMemo(() => sortRoles(roles ?? []), [roles]);
  const builtins = sorted.filter((item) => item.builtin);
  const customs = sorted.filter((item) => !item.builtin);

  const openEditor = useCallback((state: EditorState) => {
    setEditor(state);
    setProblems({});
    setFormError(null);
    setSummaryProblem(null);
    setNameError(null);
    if (state.mode === "edit") {
      setName(state.role.name_fa);
      setDescription(state.role.description_fa ?? "");
      setBase(state.role.id);
      setSelected([...state.role.permissions]);
    } else {
      setName("");
      setDescription("");
      setBase("");
      setSelected([]);
    }
  }, []);

  useEffect(() => {
    if (createRequest > 0 && isOwner && isAdvanced) openEditor({ mode: "new" });
  }, [createRequest, isOwner, isAdvanced, openEditor]);

  const basePermissions = (roleId: string): string[] => {
    const record = sorted.find((item) => item.id === roleId);
    if (!record) return [];
    if (record.permissions.includes("*")) return [...index.keys()].filter((id) => id !== "*");
    return [...record.permissions];
  };

  const roleName = (record: RoleRecord) => roleView(language, record).name;
  const nameOf = (id: string) => permissionLabel(language, id, index);
  const quoteList = (ids: string[]) => ids.map((id) => `«${nameOf(id)}»`).join(language === "fa" ? "، " : ", ");

  const baseRecord = sorted.find((item) => item.id === base);
  const baseSet = new Set(base ? basePermissions(base) : []);
  const selectedSet = new Set(selected);
  const addedIds = selected.filter((id) => !baseSet.has(id));
  const removedIds = [...baseSet].filter((id) => !selectedSet.has(id));
  const dangerCount = selected.filter((id) => ["high", "critical"].includes(index.get(id)?.danger ?? "none")).length;

  const save = async () => {
    setFormError(null);
    setSummaryProblem(null);
    setProblems({});
    setNameError(null);
    const trimmed = name.trim();
    if (trimmed.length < 2 || trimmed.length > 80) {
      setNameError(pick(language, T.nameRule));
      return;
    }
    if (selected.length === 0) {
      setSummaryProblem(pick(language, T.needOne));
      return;
    }
    const missing = missingDependencies(selected, index);
    if (Object.keys(missing).length) {
      setProblems(Object.fromEntries(Object.entries(missing).map(([id, needs]) => [id, say(language, T.missingDep, { name: nameOf(id), needs: needs.map(nameOf).join(language === "fa" ? "»، «" : "”, “") })])));
      setSummaryProblem(pick(language, T.missingSummary));
      return;
    }
    if (!editor) return;
    setBusy(true);
    try {
      const body = { name: trimmed, description: description.trim() || null, permissions: selected };
      if (editor.mode === "new") {
        await mutateJson("/api/v1/roles", { method: "POST", body });
        notify({ message: say(language, T.createdToast, { role: trimmed }) });
      } else {
        await mutateJson(`/api/v1/roles/${encodeURIComponent(editor.role.id)}`, { method: "PATCH", body });
        notify({ message: say(language, T.savedToast, { role: trimmed }) });
      }
      setEditor(null);
      await reload();
    } catch (caught) {
      explain(caught);
    } finally {
      setBusy(false);
    }
  };

  const explain = (caught: unknown) => {
    if (!(caught instanceof ApiError)) {
      setFormError(caught);
      return;
    }
    if (caught.code === "permission_dependency_missing") {
      const next: Record<string, string> = {};
      for (const issue of caught.fields) {
        const permission = String(issue.params?.permission ?? "");
        const requires = Array.isArray(issue.params?.requires) ? (issue.params?.requires as string[]) : [];
        if (permission) next[permission] = say(language, T.missingDep, { name: nameOf(permission), needs: requires.map(nameOf).join(language === "fa" ? "»، «" : "”, “") });
      }
      setProblems(next);
      setSummaryProblem(pick(language, T.missingSummary));
      return;
    }
    if (caught.code === "permission_escalation") {
      const list = caught.permissions ?? [];
      setProblems(Object.fromEntries(list.map((id) => [id, pick(language, T.escalationRow)])));
      setSummaryProblem(pick(language, T.escalationSummary));
      return;
    }
    const fields = fieldMessages(language, caught);
    if (fields.name) {
      setNameError(fields.name);
      return;
    }
    setFormError(caught);
  };

  const fixDependencies = () => {
    setSelected([...closeOver(selected, index)].filter((id) => id !== "*").sort());
    setProblems({});
    setSummaryProblem(null);
  };

  const remove = async (record: RoleRecord) => {
    const label = roleName(record);
    const ok = await ask({ title: say(language, T.deleteTitle, { role: label }), body: pick(language, T.deleteBody), severity: "destructive", undoable: false });
    if (!ok) return;
    try {
      await mutateJson(`/api/v1/roles/${encodeURIComponent(record.id)}`, { method: "DELETE" });
      notify({ message: say(language, T.deletedToast, { role: label }) });
      setInUse(null);
      await reload();
    } catch (caught) {
      if (caught instanceof ApiError && caught.code === "role_in_use") {
        const users = Array.isArray(caught.users) ? (caught.users as { username?: string; display_name?: string | null }[]) : [];
        setInUse({ role: label, people: users.map((item) => item.display_name?.trim() || item.username || "?") });
        return;
      }
      notify({ message: describeSentence(language, caught), tone: "error" });
    }
  };

  if (!canRead) return <NoAccess needs="user:read" variant="card" />;

  return (
    <Stack spacing={2.5}>
      {error !== null && <FriendlyError error={error} onRetry={() => void reload()} />}
      {inUse && (
        <Notice tone="warning" action={<Button color="inherit" href="#/people/people" sx={{ minHeight: 44 }}>{pick(language, T.goPeople)}</Button>}>
          {say(language, T.inUse, { role: inUse.role, people: inUse.people.join(language === "fa" ? "، " : ", ") })}
        </Notice>
      )}

      <SectionCard title={pick(language, T.builtinTitle)} hint={pick(language, T.builtinHint)}>
        {roles === null && error === null ? (
          <Grid container spacing={2}>{[0, 1, 2].map((key) => <Grid key={key} size={{ xs: 12, md: 6, lg: 4 }}><Skeleton variant="rounded" height={220} /></Grid>)}</Grid>
        ) : (
          <Grid container spacing={2}>
            {(builtins.length ? builtins.map((record) => ({ record, view: roleView(language, record) })) : (["viewer", "developer", "operator", "admin", "owner"] as const).map((id) => ({ record: null, view: roleView(language, null, id) }))).map(({ record, view }) => (
              <Grid key={view.id} size={{ xs: 12, md: 6, lg: 4 }}>
                <RoleCard
                  role={view}
                  showCount
                  footer={
                    <Button size="small" startIcon={<VisibilityRoundedIcon />} onClick={() => setViewing(record ?? { id: view.id, name: view.id, builtin: true, editable: false, name_fa: view.name, name_en: view.name, permissions: view.permissions })} sx={{ minHeight: 40 }}>
                      {pick(language, T.seeAll)}
                    </Button>
                  }
                />
              </Grid>
            ))}
          </Grid>
        )}
      </SectionCard>

      <SectionCard
        title={pick(language, T.customTitle)}
        hint={pick(language, T.customHint)}
        action={isAdvanced && isOwner ? <Button variant="outlined" startIcon={<AddRoundedIcon />} onClick={() => openEditor({ mode: "new" })} sx={{ minHeight: 44 }}>{pick(language, T.newRole)}</Button> : undefined}
      >
        <Stack spacing={2}>
          {!isOwner && <NoAccess needs="*" />}
          {isOwner && !isAdvanced && (
            <Typography variant="body2" color="text.secondary" sx={{ display: "flex", alignItems: "center", gap: 0.75 }}>
              <TuneRoundedIcon fontSize="small" aria-hidden />{pick(language, T.customSimpleHint)}
            </Typography>
          )}
          {customs.length === 0 && roles !== null ? (
            <EmptyState
              compact
              title={pick(language, T.noCustomTitle)}
              body={pick(language, T.noCustomBody)}
              action={isAdvanced && isOwner ? <Button variant="contained" startIcon={<AddRoundedIcon />} onClick={() => openEditor({ mode: "new" })} sx={{ minHeight: 44 }}>{pick(language, T.newRole)}</Button> : undefined}
            />
          ) : (
            <Grid container spacing={2}>
              {customs.map((record) => (
                <Grid key={record.id} size={{ xs: 12, md: 6, lg: 4 }}>
                  <RoleCard
                    role={roleView(language, record)}
                    showCount
                    footer={
                      <>
                        <Button size="small" startIcon={<VisibilityRoundedIcon />} onClick={() => setViewing(record)} sx={{ minHeight: 40 }}>{pick(language, T.seeAll)}</Button>
                        {isAdvanced && isOwner && record.editable && (
                          <>
                            <Button size="small" startIcon={<EditRoundedIcon />} onClick={() => openEditor({ mode: "edit", role: record })} sx={{ minHeight: 40 }}>{pick(language, T.edit)}</Button>
                            <Button size="small" color="error" startIcon={<DeleteOutlineRoundedIcon />} onClick={() => void remove(record)} sx={{ minHeight: 40 }}>{pick(language, T.remove)}</Button>
                          </>
                        )}
                      </>
                    }
                  />
                </Grid>
              ))}
            </Grid>
          )}
        </Stack>
      </SectionCard>

      <Dialog open={viewing !== null} onClose={() => setViewing(null)} fullScreen={fullScreen} fullWidth maxWidth="md" aria-labelledby="mrk-role-perms-title">
        {viewing && (
          <>
            <DialogTitle id="mrk-role-perms-title" sx={{ fontWeight: 760 }}>{say(language, T.permissionsOf, { role: roleName(viewing) })}</DialogTitle>
            <DialogContent>
              <PermissionMatrix catalog={catalog} value={viewing.permissions} readOnly />
            </DialogContent>
            <DialogActions sx={{ px: 3, pb: 2 }}>
              <Button variant="contained" onClick={() => setViewing(null)} sx={{ minHeight: 44 }}>{c.close}</Button>
            </DialogActions>
          </>
        )}
      </Dialog>

      <Dialog open={editor !== null} onClose={busy ? undefined : () => setEditor(null)} fullScreen={fullScreen} fullWidth maxWidth="md" aria-labelledby="mrk-role-editor-title">
        {editor && (
          <>
            <DialogTitle id="mrk-role-editor-title" sx={{ fontWeight: 760 }}>
              {editor.mode === "new" ? pick(language, T.editorNew) : say(language, T.editorEdit, { role: roleName(editor.role) })}
            </DialogTitle>
            <DialogContent>
              <Stack spacing={2} sx={{ pt: 0.5 }}>
                {!isOwner && <Notice tone="info">{pick(language, T.ownerOnly)}</Notice>}
                <TextField
                  autoFocus
                  fullWidth
                  label={pick(language, T.name)}
                  value={name}
                  onChange={(event) => { setName(event.target.value); setNameError(null); }}
                  error={Boolean(nameError)}
                  helperText={nameError ?? " "}
                  slotProps={{ htmlInput: { maxLength: 80 } }}
                />
                <TextField
                  fullWidth
                  multiline
                  minRows={2}
                  label={pick(language, T.description)}
                  value={description}
                  onChange={(event) => setDescription(event.target.value)}
                  helperText={pick(language, T.descriptionHint)}
                  slotProps={{ htmlInput: { maxLength: 500 } }}
                />
                <TextField
                  select
                  fullWidth
                  label={pick(language, T.startFrom)}
                  value={base}
                  helperText={pick(language, T.startHint)}
                  slotProps={{ select: { displayEmpty: true }, inputLabel: { shrink: true } }}
                  onChange={(event) => {
                    const next = event.target.value;
                    setBase(next);
                    setSelected(next ? basePermissions(next) : []);
                    setProblems({});
                    setSummaryProblem(null);
                  }}
                >
                  <MenuItem value="">{pick(language, T.startBlank)}</MenuItem>
                  {sorted.filter((item) => item.id !== "owner").map((item) => <MenuItem key={item.id} value={item.id}>{roleName(item)}</MenuItem>)}
                </TextField>

                <Box sx={{ p: 1.5, borderRadius: 1.25, bgcolor: "action.hover" }} role="status" aria-live="polite">
                  <Typography variant="body2" sx={{ fontWeight: 700 }}>
                    {say(language, T.summary, { count: selected.length, danger: dangerCount ? say(language, T.summaryDanger, { count: dangerCount }) : "" })}
                  </Typography>
                  {baseRecord && (
                    <>
                      <Typography variant="caption" color="text.secondary" display="block">
                        {say(language, T.diff, { base: roleName(baseRecord), added: addedIds.length, removed: removedIds.length })}
                      </Typography>
                      {addedIds.length > 0 && <Typography variant="caption" color="success.main" display="block">{say(language, T.added, { list: quoteList(addedIds.slice(0, 6)) })}</Typography>}
                      {removedIds.length > 0 && <Typography variant="caption" color="text.secondary" display="block">{say(language, T.removed, { list: quoteList(removedIds.slice(0, 6)) })}</Typography>}
                    </>
                  )}
                </Box>

                {summaryProblem && (
                  <Notice tone="error" action={Object.keys(problems).length && summaryProblem === pick(language, T.missingSummary) ? <Button color="inherit" onClick={fixDependencies} sx={{ minHeight: 40 }}>{pick(language, T.fixDeps)}</Button> : undefined}>
                    {summaryProblem}
                  </Notice>
                )}

                <PermissionMatrix
                  catalog={catalog}
                  value={selected}
                  onChange={(next) => { setSelected(next); setProblems({}); setSummaryProblem(null); }}
                  grantable={user.permissions}
                  problems={problems}
                />
                {formError !== null && <FriendlyError error={formError} noAction />}
              </Stack>
            </DialogContent>
            <DialogActions sx={{ px: 3, pb: 2, gap: 1 }}>
              <Button onClick={() => setEditor(null)} disabled={busy} sx={{ minHeight: 44 }}>{c.cancel}</Button>
              <Button variant="contained" onClick={() => void save()} disabled={busy || !isOwner} sx={{ minHeight: 44 }}>
                {busy ? c.saving : editor.mode === "new" ? pick(language, T.create) : pick(language, T.save)}
              </Button>
            </DialogActions>
          </>
        )}
      </Dialog>

      {confirmDialog}
      {snackbar}
    </Stack>
  );
}

function describeSentence(language: "fa" | "en", error: unknown) {
  const fields = Object.values(fieldMessages(language, error));
  return fields[0] ?? errorSentence(language, error);
}

export default RolesPanel;
