/**
 * «فضای من» (docs/43 §4): one page for `#/my/<tab>` — home, domains, file space, packages, members,
 * API keys and activity of the current workspace. Tabs the plan doesn't include are hidden in the menu
 * and show a calm "not in your plan" card if opened by link.
 */
import { useEffect, useRef, useState, type ReactNode } from "react";
import { Box, Button, LinearProgress, ListSubheader, MenuItem, Stack, TextField, Typography, useMediaQuery, useTheme } from "@mui/material";
import AddRoundedIcon from "@mui/icons-material/AddRounded";
import PersonAddAlt1RoundedIcon from "@mui/icons-material/PersonAddAlt1Rounded";
import KeyRoundedIcon from "@mui/icons-material/KeyRounded";
import CreateNewFolderRoundedIcon from "@mui/icons-material/CreateNewFolderRounded";
import HourglassEmptyRoundedIcon from "@mui/icons-material/HourglassEmptyRounded";
import WorkspacesRoundedIcon from "@mui/icons-material/WorkspacesRounded";
import { MY, pick, say, type FeatureKey } from "../copy";
import { EmptyState, FriendlyError, NameDialog, PageHeader, useKit, useUndoSnackbar } from "../kit";
import { MY_TABS, hashQuery, isMyTab, myHref, type MyTabKey } from "../nav";
import { acceptInvite, createWorkspace } from "./myApi";
import { myErrorSentence } from "./MyKit";
import { MY_TEAM } from "../copy";
import { useMySpace } from "./MySpaceContext";
import { FeatureOff, ReadOnlyNotice } from "./MyKit";
import MyHome from "./MyHome";
import MyDomains from "./MyDomains";
import MyFiles from "./MyFiles";
import MyPackages from "./MyPackages";
import MyTeam from "./MyTeam";
import MyTokens from "./MyTokens";
import MyActivity from "./MyActivity";

/** The workspace switcher (side nav, phone page top). Offers «ساخت فضای تیمی» when the plan allows teams. */
export function WorkspacePicker({ dense = false }: { dense?: boolean }) {
  const { language } = useKit();
  const space = useMySpace();
  const { notify, snackbar } = useUndoSnackbar();
  const [creating, setCreating] = useState(false);
  if (space.status !== "ready" || !space.workspace) return null;
  const personal = space.workspaces.filter((item) => item.kind === "personal");
  const teams = space.workspaces.filter((item) => item.kind === "team");
  const canCreate = !space.viewAs && space.has("teams");
  return (
    <>
      <TextField
        select
        size="small"
        fullWidth
        label={pick(language, MY.workspace)}
        value={space.workspace.id}
        onChange={(event) => {
          if (event.target.value === "__new") setCreating(true);
          else space.setWorkspace(event.target.value);
        }}
        disabled={Boolean(space.viewAs)}
        sx={{ "& .MuiInputBase-root": { minHeight: dense ? 40 : 44 } }}
      >
        {personal.length > 0 && <ListSubheader>{pick(language, MY.personal)}</ListSubheader>}
        {personal.map((item) => <MenuItem key={item.id} value={item.id}>{item.name}</MenuItem>)}
        {teams.length > 0 && <ListSubheader>{pick(language, MY.team)}</ListSubheader>}
        {teams.map((item) => <MenuItem key={item.id} value={item.id}>{item.name}</MenuItem>)}
        {canCreate && <MenuItem value="__new"><AddRoundedIcon fontSize="small" sx={{ mx: 0.5 }} />{pick(language, MY.newTeam)}</MenuItem>}
      </TextField>
      {creating && (
        <NameDialog
          title={pick(language, MY.newTeamTitle)}
          hint={pick(language, MY.newTeamHint)}
          label={pick(language, MY.teamName)}
          saveLabel={pick(language, MY.newTeam)}
          ltr={false}
          validate={(value) => (value.trim() ? null : pick(language, MY.teamName))}
          onClose={() => setCreating(false)}
          onSubmit={async (value) => {
            const created = await createWorkspace(value.trim());
            setCreating(false);
            await space.reload();
            if (created.id) space.setWorkspace(created.id);
            notify({ message: say(language, MY.teamCreated, { name: value.trim() }), tone: "success" });
          }}
        />
      )}
      {snackbar}
    </>
  );
}

type Requests = { domain: number; bucket: number; invite: number; token: number };

export default function MySpacePage({ tab: tabProp }: { tab?: string }) {
  const { language } = useKit();
  const theme = useTheme();
  const isPhone = useMediaQuery(theme.breakpoints.down("md"));
  const space = useMySpace();
  const [requests, setRequests] = useState<Requests>({ domain: 0, bucket: 0, invite: 0, token: 0 });
  const bump = (key: keyof Requests) => setRequests((value) => ({ ...value, [key]: value[key] + 1 }));
  const tabKey: MyTabKey = isMyTab(tabProp) ? tabProp : "home";
  const tab = MY_TABS.find((item) => item.key === tabKey) ?? MY_TABS[0];
  const { notify, snackbar } = useUndoSnackbar();

  // An invite link (`#/my/team?accept=<token>`) joins the space once the person is signed in.
  const accepted = useRef(false);
  const ready = space.status === "ready";
  useEffect(() => {
    const token = hashQuery().get("accept");
    if (!token || !ready || accepted.current) return;
    accepted.current = true;
    window.history.replaceState(null, "", myHref("team"));
    acceptInvite(token)
      .then(async (result) => {
        await space.reload();
        if (result?.workspace_id) space.setWorkspace(result.workspace_id);
        notify({ message: pick(language, MY_TEAM.accepted), tone: "success" });
      })
      .catch((caught: unknown) => notify({ message: myErrorSentence(language, caught), tone: "error" }));
  }, [ready, space, language, notify]);

  if (space.status === "loading" && !space.workspace) {
    return (
      <Stack spacing={1.5} sx={{ py: 4 }} alignItems="center">
        <Typography color="text.secondary">{pick(language, MY.loading)}</Typography>
        <LinearProgress sx={{ width: "100%", maxWidth: 360 }} aria-label={pick(language, MY.loading)} />
      </Stack>
    );
  }
  if (space.status === "unavailable") {
    return <EmptyState icon={HourglassEmptyRoundedIcon} title={pick(language, MY.notReadyTitle)} body={pick(language, MY.notReadyBody)} />;
  }
  if (space.status === "error" && !space.workspace) {
    return <FriendlyError error={space.error} title={pick(language, MY.failedTitle)} onRetry={() => void space.reload()} />;
  }
  if (!space.workspace) {
    return <EmptyState icon={WorkspacesRoundedIcon} title={pick(language, MY.noWorkspaceTitle)} body={pick(language, MY.noWorkspaceBody)} />;
  }

  const featureMissing = tab.features.length > 0 && !tab.features.some(space.has) ? (tab.features[0] as FeatureKey) : null;
  let primary: ReactNode = null;
  if (!featureMissing && space.canWrite) {
    if (tabKey === "domains") primary = <Button variant="contained" startIcon={<AddRoundedIcon />} onClick={() => bump("domain")} sx={{ minHeight: 44 }}>{pick(language, MY.quickDomain)}</Button>;
    if (tabKey === "files") primary = <Button variant="contained" startIcon={<CreateNewFolderRoundedIcon />} onClick={() => bump("bucket")} sx={{ minHeight: 44 }}>{pick(language, MY.quickBucket)}</Button>;
  }
  if (!featureMissing && tabKey === "keys" && (space.readOnlyReason === null || space.readOnlyReason === "viewer")) {
    primary = <Button variant="contained" startIcon={<KeyRoundedIcon />} onClick={() => bump("token")} sx={{ minHeight: 44 }}>{pick(language, MY.quickKey)}</Button>;
  }
  if (!featureMissing && tabKey === "team" && space.canManage && space.workspace.kind === "team") {
    primary = <Button variant="contained" startIcon={<PersonAddAlt1RoundedIcon />} onClick={() => bump("invite")} sx={{ minHeight: 44 }}>{pick(language, MY.quickInvite)}</Button>;
  }

  return (
    <>
      {isPhone && <Box sx={{ mb: 2 }}><WorkspacePicker /></Box>}
      <PageHeader title={pick(language, tab.label)} subtitle={pick(language, tab.hint)} icon={tab.icon} primaryAction={primary ?? undefined} />
      <Box role="region" aria-label={pick(language, tab.label)} sx={{ pb: { xs: 10, sm: 2 } }}>
        <Stack spacing={2.5}>
          <ReadOnlyNotice />
          {featureMissing ? <FeatureOff feature={featureMissing} /> : (
            <Box key={space.workspace.id}>
              {tabKey === "home" && <MyHome onGo={(next) => { window.location.hash = myHref(next); }} />}
              {tabKey === "domains" && <MyDomains createRequest={requests.domain} />}
              {tabKey === "files" && <MyFiles createRequest={requests.bucket} />}
              {tabKey === "packages" && <MyPackages />}
              {tabKey === "team" && <MyTeam inviteRequest={requests.invite} />}
              {tabKey === "keys" && <MyTokens createRequest={requests.token} />}
              {tabKey === "activity" && <MyActivity />}
            </Box>
          )}
        </Stack>
      </Box>
      {snackbar}
    </>
  );
}
