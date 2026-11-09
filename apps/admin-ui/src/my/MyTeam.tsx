/**
 * «فضای من › اعضا» (docs/43 §1 membership, §3): members and invites of a team space, with the roles
 * صاحب فضا / گرداننده / عضو / فقط دیدن. Nobody is offered a role above their own (an admin gives
 * member/viewer; only an owner makes another owner), and an admin can't change or remove an owner
 * or another admin. Also rename/delete the space (owner, typed slug).
 */
import { useCallback, useEffect, useState } from "react";
import { Box, Button, MenuItem, Stack, TextField, Typography } from "@mui/material";
import ManageAccountsRoundedIcon from "@mui/icons-material/ManageAccountsRounded";
import PersonRemoveRoundedIcon from "@mui/icons-material/PersonRemoveRounded";
import LogoutRoundedIcon from "@mui/icons-material/LogoutRounded";
import CancelScheduleSendRoundedIcon from "@mui/icons-material/CancelScheduleSendRounded";
import GroupsRoundedIcon from "@mui/icons-material/GroupsRounded";
import { ApiError } from "../api";
import { MY, MY_TEAM, nameConfirmation, pick, say, WORKSPACE_ROLE_ORDER, WORKSPACE_ROLES, workspaceRoleName, type WorkspaceRole } from "../copy";
import {
  CopyField, DangerZone, EmptyState, Ltr, NameDialog, Notice, RelativeTime, ResponsiveList, SectionCard, StatusPill, useConfirmAction, useKit,
  useUndoSnackbar, type ListColumn, type RowAction
} from "../kit";
import { FormDialog, Loading, ltrInput, useList } from "../dnsUi";
import {
  addMember, cancelInvite, createInvite, changeMemberRole, deleteWorkspace, fetchInvites, fetchMembers, removeMember, renameWorkspace, type Invite, type Member
} from "./myApi";
import { useMySpace } from "./MySpaceContext";
import { MyError, myErrorSentence } from "./MyKit";

const rank = (role: WorkspaceRole) => WORKSPACE_ROLE_ORDER.indexOf(role);

function InviteDialog({ onClose, onDone }: { onClose: () => void; onDone: (who: string, link: string | null) => void }) {
  const { language } = useKit();
  const space = useMySpace();
  const roles = space.assignableRoles;
  const [who, setWho] = useState("");
  const [role, setRole] = useState<WorkspaceRole>(roles.includes("member") ? "member" : roles[roles.length - 1] ?? "viewer");
  const [touched, setTouched] = useState(false);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<unknown>(null);
  const problem = who.trim() ? null : pick(language, MY_TEAM.whoRequired);

  const submit = async () => {
    setTouched(true);
    if (problem || !space.workspace) return;
    setBusy(true);
    setError(null);
    try {
      const target = who.trim();
      try {
        await addMember(space.workspace.id, target, role);
        onDone(target, null);
      } catch (caught) {
        // No account with that email yet: send an invite instead and show its one-time link.
        if (!(caught instanceof ApiError && caught.code === "user_not_found" && target.includes("@"))) throw caught;
        const invite = await createInvite(space.workspace.id, target, role);
        const link = invite.token ? `${window.location.origin}${window.location.pathname}#/my/team?accept=${encodeURIComponent(invite.token)}` : null;
        onDone(target, link);
      }
    } catch (caught) {
      setError(caught);
    } finally {
      setBusy(false);
    }
  };

  return (
    <FormDialog
      title={say(language, MY_TEAM.inviteTitle, { name: space.workspace?.name ?? "" })}
      hint={pick(language, MY_TEAM.inviteHint)}
      submitLabel={pick(language, MY_TEAM.send)}
      busy={busy}
      error={error}
      onSubmit={() => void submit()}
      onClose={onClose}
    >
      <TextField
        autoFocus
        label={pick(language, MY_TEAM.who)}
        value={who}
        onChange={(event) => setWho(event.target.value)}
        error={touched && Boolean(problem)}
        helperText={touched && problem ? problem : " "}
        fullWidth
        slotProps={ltrInput}
      />
      <TextField select label={pick(language, MY_TEAM.role)} value={role} onChange={(event) => setRole(event.target.value as WorkspaceRole)} helperText={pick(language, MY_TEAM.roleHint)} fullWidth>
        {roles.map((item) => (
          <MenuItem key={item} value={item}>
            <Stack>
              <span>{pick(language, WORKSPACE_ROLES[item].name)}</span>
              <Typography variant="caption" color="text.secondary">{pick(language, WORKSPACE_ROLES[item].oneLiner)}</Typography>
            </Stack>
          </MenuItem>
        ))}
      </TextField>
    </FormDialog>
  );
}

function RoleDialog({ member, onClose, onDone }: { member: Member; onClose: () => void; onDone: (role: WorkspaceRole) => void }) {
  const { language } = useKit();
  const space = useMySpace();
  const [role, setRole] = useState<WorkspaceRole>(member.role);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<unknown>(null);
  const submit = async () => {
    if (!space.workspace) return;
    setBusy(true);
    setError(null);
    try {
      await changeMemberRole(space.workspace.id, member.user_id, role);
      onDone(role);
    } catch (caught) {
      setError(caught);
    } finally {
      setBusy(false);
    }
  };
  return (
    <FormDialog title={pick(language, MY_TEAM.changeRole)} hint={member.display_name || member.username} submitLabel={pick(language, MY.save)} busy={busy} error={error} disabled={role === member.role} onSubmit={() => void submit()} onClose={onClose}>
      <TextField select label={pick(language, MY_TEAM.role)} value={role} onChange={(event) => setRole(event.target.value as WorkspaceRole)} helperText={pick(language, MY_TEAM.roleHint)} fullWidth>
        {[...new Set([member.role, ...space.assignableRoles])].map((item) => (
          <MenuItem key={item} value={item} disabled={!space.assignableRoles.includes(item)}>{pick(language, WORKSPACE_ROLES[item].name)}</MenuItem>
        ))}
      </TextField>
    </FormDialog>
  );
}

export default function MyTeam({ inviteRequest }: { inviteRequest: number }) {
  const { language } = useKit();
  const space = useMySpace();
  const workspace = space.workspace!;
  const isTeam = workspace.kind === "team";
  const myId = String(space.me?.user?.id ?? "");
  const myRole = workspace.role;
  const membersLoader = useCallback((signal: AbortSignal) => fetchMembers(workspace.id, signal), [workspace.id]);
  const members = useList<Member>(membersLoader, isTeam);
  const invitesLoader = useCallback((signal: AbortSignal) => fetchInvites(workspace.id, signal).catch((caught: unknown) => {
    if (caught instanceof ApiError && (caught.status === 404 || caught.status === 405)) return [] as Invite[];
    throw caught;
  }), [workspace.id]);
  const invites = useList<Invite>(invitesLoader, isTeam && space.canManage);
  const [inviting, setInviting] = useState(false);
  const [link, setLink] = useState<string | null>(null);
  const [roleFor, setRoleFor] = useState<Member | null>(null);
  const [renaming, setRenaming] = useState(false);
  const { ask, dialog } = useConfirmAction();
  const { notify, snackbar } = useUndoSnackbar();

  useEffect(() => {
    if (inviteRequest > 0 && space.canManage && isTeam) setInviting(true);
  }, [inviteRequest, space.canManage, isTeam]);

  /** I may act on a member whose role is below mine; an owner may act on anyone but can't drop the last owner. */
  const canActOn = (member: Member) => space.canManage && member.user_id !== myId && (myRole === "owner" || rank(member.role) < rank(myRole));
  const nameOf = (member: Member) => member.display_name || member.username || member.email || member.user_id;

  const remove = async (member: Member) => {
    const self = member.user_id === myId;
    const ok = await ask({
      title: self ? say(language, MY_TEAM.leaveTitle, { name: workspace.name }) : say(language, MY_TEAM.removeTitle, { name: nameOf(member) }),
      body: pick(language, self ? MY_TEAM.leaveBody : MY_TEAM.removeBody),
      severity: "disruptive",
      confirmLabel: pick(language, self ? MY_TEAM.leaveYes : MY_TEAM.removeYes)
    });
    if (!ok) return;
    try {
      await removeMember(workspace.id, member.user_id);
      if (self) {
        await space.reload();
        return;
      }
      notify({ message: say(language, MY_TEAM.memberRemoved, { name: nameOf(member) }) });
      members.reload();
      void space.reload();
    } catch (caught) {
      notify({ message: myErrorSentence(language, caught), tone: "error" });
    }
  };

  const cancel = async (invite: Invite) => {
    try {
      await cancelInvite(workspace.id, invite.id);
      notify({ message: pick(language, MY_TEAM.inviteCancelled) });
      invites.reload();
    } catch (caught) {
      notify({ message: myErrorSentence(language, caught), tone: "error" });
    }
  };

  const removeSpace = async () => {
    const ok = await ask({
      title: say(language, MY_TEAM.deleteSpaceTitle, { name: workspace.name }),
      body: pick(language, MY_TEAM.deleteSpaceDesc),
      severity: "destructive",
      undoable: false,
      typed: nameConfirmation(workspace.slug, workspace.slug)
    });
    if (!ok) return;
    try {
      await deleteWorkspace(workspace.id, workspace.slug);
      notify({ message: say(language, MY_TEAM.spaceDeleted, { name: workspace.name }) });
      const personal = space.workspaces.find((item) => item.kind === "personal");
      if (personal) space.setWorkspace(personal.id);
      await space.reload();
    } catch (caught) {
      notify({ message: myErrorSentence(language, caught), tone: "error" });
    }
  };

  if (!isTeam) {
    return <Notice>{pick(language, MY_TEAM.personalNote)}</Notice>;
  }

  const columns: ListColumn<Member>[] = [
    {
      key: "who",
      header: pick(language, MY_TEAM.colMember),
      render: (member) => (
        <Box sx={{ minWidth: 0 }}>
          <Typography fontWeight={650} component="span">{nameOf(member)}</Typography>
          {member.user_id === myId && <Typography component="span" variant="caption" color="primary.main" sx={{ mx: 0.75 }}>{pick(language, MY_TEAM.you)}</Typography>}
          {member.email && <Typography variant="caption" color="text.secondary" display="block"><Ltr>{member.email}</Ltr></Typography>}
        </Box>
      )
    },
    { key: "role", header: pick(language, MY_TEAM.colRole), render: (member) => <StatusPill tone={member.role === "owner" ? "warn" : "info"} label={workspaceRoleName(language, member.role)} /> },
    { key: "joined", header: pick(language, MY_TEAM.colJoined), render: (member) => <RelativeTime value={member.joined_at ?? null} /> }
  ];
  const actions: RowAction<Member>[] = [
    { key: "role", label: pick(language, MY_TEAM.changeRole), icon: ManageAccountsRoundedIcon, hidden: (member) => !canActOn(member), onClick: (member) => setRoleFor(member) },
    { key: "remove", label: pick(language, MY_TEAM.removeMember), icon: PersonRemoveRoundedIcon, danger: true, hidden: (member) => !canActOn(member), onClick: (member) => void remove(member) },
    { key: "leave", label: pick(language, MY_TEAM.leave), icon: LogoutRoundedIcon, hidden: (member) => member.user_id !== myId || Boolean(space.viewAs), onClick: (member) => void remove(member) }
  ];

  return (
    <Stack spacing={2.5}>
      {link && (
        <SectionCard title={pick(language, MY_TEAM.inviteLink)} hint={pick(language, MY_TEAM.inviteLinkHint)} action={<Button onClick={() => setLink(null)}>{pick(language, MY.close)}</Button>}>
          <CopyField label={pick(language, MY_TEAM.inviteLink)} value={link} />
        </SectionCard>
      )}
      <SectionCard
        title={pick(language, MY_TEAM.membersTitle)}
        hint={pick(language, MY_TEAM.membersHint)}
        flush
      >
        {members.error ? <Box sx={{ p: 2 }}><MyError error={members.error} onRetry={members.reload} /></Box> : null}
        {members.loading && !members.items ? <Loading /> : null}
        {members.items && (
          <ResponsiveList
            label={pick(language, MY_TEAM.listLabel)}
            rows={members.items}
            rowKey={(member) => member.user_id}
            columns={columns}
            card={{ title: (member) => nameOf(member), meta: (member) => (member.email ? <Ltr>{member.email}</Ltr> : null), status: (member) => <StatusPill tone={member.role === "owner" ? "warn" : "info"} label={workspaceRoleName(language, member.role)} /> }}
            actions={actions}
            empty={<EmptyState icon={GroupsRoundedIcon} title={pick(language, MY_TEAM.membersEmpty)} body={pick(language, MY_TEAM.membersEmptyBody)} />}
          />
        )}
      </SectionCard>

      {space.canManage && (invites.items?.length ?? 0) > 0 && (
        <SectionCard title={pick(language, MY_TEAM.invitesTitle)} hint={pick(language, MY_TEAM.invitesHint)} flush>
          <ResponsiveList
            label={pick(language, MY_TEAM.invitesTitle)}
            rows={invites.items ?? []}
            rowKey={(invite) => invite.id}
            columns={[
              { key: "who", header: pick(language, MY_TEAM.colMember), render: (invite) => <Ltr>{invite.who}</Ltr> },
              { key: "role", header: pick(language, MY_TEAM.colRole), render: (invite) => workspaceRoleName(language, invite.role) },
              { key: "expires", header: pick(language, MY_TEAM.expires), render: (invite) => <RelativeTime value={invite.expires_at ?? null} /> }
            ]}
            card={{ title: (invite) => <Ltr>{invite.who}</Ltr>, meta: (invite) => workspaceRoleName(language, invite.role) }}
            actions={[{ key: "cancel", label: pick(language, MY_TEAM.cancelInvite), icon: CancelScheduleSendRoundedIcon, danger: true, onClick: (invite) => void cancel(invite) }]}
          />
        </SectionCard>
      )}

      {space.canManage && (
        <SectionCard title={pick(language, MY_TEAM.spaceTitle)}>
          <Stack direction="row" gap={1} flexWrap="wrap" alignItems="center">
            <Typography sx={{ flex: 1, minWidth: 0 }} fontWeight={650}>{workspace.name} <Typography component="span" variant="caption" color="text.secondary"><Ltr>{workspace.slug}</Ltr></Typography></Typography>
            <Button variant="outlined" onClick={() => setRenaming(true)} sx={{ minHeight: 40 }}>{pick(language, MY_TEAM.rename)}</Button>
          </Stack>
        </SectionCard>
      )}
      {space.isOwner && (
        <DangerZone
          simpleToo
          items={[{
            title: pick(language, MY_TEAM.deleteSpace),
            description: pick(language, MY_TEAM.deleteSpaceDesc),
            action: <Button color="error" variant="outlined" onClick={() => void removeSpace()} sx={{ minHeight: 40 }}>{pick(language, MY.remove)}</Button>
          }]}
        />
      )}

      {inviting && (
        <InviteDialog
          onClose={() => setInviting(false)}
          onDone={(who, inviteLink) => {
            setInviting(false);
            notify({ message: say(language, MY_TEAM.invited, { who }), tone: "success" });
            setLink(inviteLink);
            members.reload();
            invites.reload();
          }}
        />
      )}
      {roleFor && (
        <RoleDialog
          member={roleFor}
          onClose={() => setRoleFor(null)}
          onDone={(role) => {
            notify({ message: say(language, MY_TEAM.roleChanged, { name: nameOf(roleFor), role: workspaceRoleName(language, role) }), tone: "success" });
            setRoleFor(null);
            members.reload();
          }}
        />
      )}
      {renaming && (
        <NameDialog
          title={pick(language, MY_TEAM.rename)}
          label={pick(language, MY.teamName)}
          initial={workspace.name}
          saveLabel={pick(language, MY.save)}
          ltr={false}
          validate={(value) => (value.trim() ? null : pick(language, MY.teamName))}
          onClose={() => setRenaming(false)}
          onSubmit={async (value) => {
            await renameWorkspace(workspace.id, value.trim());
            setRenaming(false);
            notify({ message: pick(language, MY_TEAM.renamed), tone: "success" });
            await space.reload();
          }}
        />
      )}
      {dialog}
      {snackbar}
    </Stack>
  );
}
