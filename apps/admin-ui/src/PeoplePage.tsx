import { useState } from "react";
import { Box, Button, Stack } from "@mui/material";
import GroupRoundedIcon from "@mui/icons-material/GroupRounded";
import PersonAddAlt1RoundedIcon from "@mui/icons-material/PersonAddAlt1Rounded";
import KeyRoundedIcon from "@mui/icons-material/KeyRounded";
import AddRoundedIcon from "@mui/icons-material/AddRounded";
import { hasPermission } from "./api";
import type { AuthUser } from "./App";
import { GroupTabs, NoAccess, PageHeader, useGroupTab, useKit } from "./kit";
import { findGroup, visibleTabs } from "./nav";
import { pick, type Bi } from "./copy";
import { PeoplePanel } from "./PeoplePanel";
import { RolesPanel } from "./RolesPanel";
import { AppKeysPanel } from "./AppKeysPanel";
import { RegistrationCard, SignInSecuritySettings } from "./RegistrationCard";

const T = {
  title: { fa: "کاربران و دسترسی", en: "People & access" },
  invite: { fa: "دعوت همکار", en: "Invite a teammate" },
  newKey: { fa: "ساخت کلید برنامه", en: "Create an app key" },
  newRole: { fa: "ساخت نقش تازه", en: "New role" }
} satisfies Record<string, Bi>;

/** Same shape the shell passes to every group page (AppShell ShellPageProps); extra props are ignored. */
export type PeoplePageProps = { user: AuthUser; tab?: string };

/** People & access (docs/33 §1.1 group 6): people · roles · app keys · public sign-up. */
export default function PeoplePage({ user, tab: tabProp }: PeoplePageProps) {
  const { language, mode, isAdvanced } = useKit();
  const group = findGroup("people");
  const tabs = group ? visibleTabs(group, user.permissions, mode) : [];
  const hashTab = useGroupTab("people", tabs[0]?.key ?? "people");
  const wanted = tabProp || hashTab;
  const current = tabs.find((item) => item.key === wanted) ?? tabs[0] ?? null;
  const [inviteRequest, setInviteRequest] = useState(0);
  const [keyRequest, setKeyRequest] = useState(0);
  const [roleRequest, setRoleRequest] = useState(0);
  const isOwner = user.permissions.includes("*");
  const title = group ? pick(language, group.label) : pick(language, T.title);

  if (!current) {
    return (
      <>
        <PageHeader title={title} icon={GroupRoundedIcon} />
        <NoAccess needs={["user:read", "token:read"]} variant="card" />
      </>
    );
  }
  const tab = current.key;

  let primary = null;
  if (tab === "people" && hasPermission(user.permissions, "user:write")) {
    primary = <Button variant="contained" startIcon={<PersonAddAlt1RoundedIcon />} onClick={() => setInviteRequest((value) => value + 1)} sx={{ minHeight: 44 }}>{pick(language, T.invite)}</Button>;
  } else if (tab === "app-keys" && hasPermission(user.permissions, "token:write")) {
    primary = <Button variant="contained" startIcon={<KeyRoundedIcon />} onClick={() => setKeyRequest((value) => value + 1)} sx={{ minHeight: 44 }}>{pick(language, T.newKey)}</Button>;
  } else if (tab === "roles" && isOwner && isAdvanced) {
    primary = <Button variant="contained" startIcon={<AddRoundedIcon />} onClick={() => setRoleRequest((value) => value + 1)} sx={{ minHeight: 44 }}>{pick(language, T.newRole)}</Button>;
  }

  return (
    <>
      <PageHeader
        title={title}
        subtitle={pick(language, current.hint)}
        icon={GroupRoundedIcon}
        primaryAction={primary ?? undefined}
        tabs={<GroupTabs group="people" permissions={user.permissions} value={tab} />}
      />
      <Box role="tabpanel" id={`tabpanel-people-${tab}`} aria-labelledby={`tab-people-${tab}`} sx={{ pb: { xs: 10, sm: 2 } }}>
        {tab === "people" && <PeoplePanel user={user} inviteRequest={inviteRequest} />}
        {tab === "roles" && <RolesPanel user={user} createRequest={roleRequest} />}
        {tab === "app-keys" && <AppKeysPanel user={user} createRequest={keyRequest} />}
        {tab === "signup" && (
          <Stack spacing={2.5}>
            <RegistrationCard user={user} />
            <SignInSecuritySettings user={user} />
          </Stack>
        )}
      </Box>
    </>
  );
}
