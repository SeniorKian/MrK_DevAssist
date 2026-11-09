import { useCallback, useEffect, useMemo, useRef, useState, type ReactNode } from "react";
import {
  Avatar, Box, Button, Card, CardContent, Checkbox, Chip, Dialog, DialogActions, DialogContent, DialogTitle, FormControlLabel, Grid,
  IconButton, InputAdornment, ListItemIcon, ListItemText, Menu, MenuItem, Skeleton, Stack, Switch, TextField, Typography,
  useMediaQuery, useTheme
} from "@mui/material";
import PersonAddAlt1RoundedIcon from "@mui/icons-material/PersonAddAlt1Rounded";
import SwapHorizRoundedIcon from "@mui/icons-material/SwapHorizRounded";
import BlockRoundedIcon from "@mui/icons-material/BlockRounded";
import CheckCircleOutlineRoundedIcon from "@mui/icons-material/CheckCircleOutlineRounded";
import SearchRoundedIcon from "@mui/icons-material/SearchRounded";
import GroupRoundedIcon from "@mui/icons-material/GroupRounded";
import LockResetRoundedIcon from "@mui/icons-material/LockResetRounded";
import LogoutRoundedIcon from "@mui/icons-material/LogoutRounded";
import DeleteForeverRoundedIcon from "@mui/icons-material/DeleteForeverRounded";
import { ApiError, getJson, hasPermission, isAbortError, mutateJson } from "./api";
import type { AuthUser } from "./App";
import {
  ActionWizard, EmptyState, FriendlyError, KeyValueList, Ltr, NoAccess, Notice, OneTimeSecret, RelativeTime, DateTime, StatusPill,
  useConfirmAction, useKit, useUndoSnackbar, CardMenu, type WizardStep
} from "./kit";
import { RolePicker, covers, fieldMessages, initials, roleTitle, roleView, sortRoles, useRoles, type RoleRecord, type RoleView, type UserRecord } from "./kit/people";
import { errorSentence, normalizeTyped, pick, say, type Bi } from "./copy";
import { nameConfirmation } from "./copy/confirm";

const T = {
  listTitle: { fa: "افراد", en: "People" },
  search: { fa: "جست‌وجوی نام یا نام کاربری", en: "Search by name or username" },
  you: { fa: "شما", en: "You" },
  ownRow: { fa: "حساب خودتان این‌جا عوض نمی‌شود؛ از منوی «حساب من» استفاده کنید.", en: "You can't change your own account here; use “My account”." },
  ownerOnly: { fa: "فقط «مالک» می‌تواند حساب مالک را عوض کند.", en: "Only the owner can change an owner's account." },
  active: { fa: "فعال", en: "Active" },
  inactive: { fa: "غیرفعال", en: "Inactive" },
  invited: { fa: "دعوت شده؛ هنوز وارد نشده", en: "Invited; hasn't signed in yet" },
  mustChange: { fa: "باید رمزش را عوض کند", en: "Must change password" },
  lastSeen: { fa: "آخرین ورود: ", en: "Last sign-in: " },
  never: { fa: "هنوز وارد نشده", en: "Hasn't signed in yet" },
  menu: { fa: "کارهای مربوط به {name}", en: "Actions for {name}" },
  changeRole: { fa: "تغییر نقش", en: "Change role" },
  disable: { fa: "غیرفعال کردن", en: "Deactivate" },
  enable: { fa: "فعال کردن", en: "Activate" },
  emptyTitle: { fa: "هنوز همکاری اضافه نکرده‌اید", en: "You haven't added anyone yet" },
  emptyBody: { fa: "همکارانتان را دعوت کنید تا هر کس با نقش مناسب خودش وارد شود.", en: "Invite your teammates so each person signs in with the right role." },
  noMatch: { fa: "کسی با «{query}» پیدا نشد.", en: "Nobody matches “{query}”." },
  invite: { fa: "دعوت همکار", en: "Invite a teammate" },
  readOnly: { fa: "نقش شما فقط اجازه دیدن افراد را دارد.", en: "Your role can only see people." },
  // invite wizard
  stepWho: { fa: "کیست؟", en: "Who?" },
  stepWhoHint: { fa: "نام همکارتان را بنویسید. ایمیل اختیاری است.", en: "Write your teammate's name. Email is optional." },
  stepRole: { fa: "چه کاری بکند؟", en: "What can they do?" },
  stepRoleHint: { fa: "یک نقش انتخاب کنید. بعداً هم می‌شود عوضش کرد.", en: "Pick a role. You can change it later." },
  stepSend: { fa: "بفرستید", en: "Send" },
  stepSendHint: { fa: "حساب ساخته می‌شود و یک رمز موقت و لینک دعوت می‌گیرید.", en: "The account is created and you get a temporary password and an invite link." },
  name: { fa: "نام و نام خانوادگی", en: "Full name" },
  nameRule: { fa: "نام را بنویسید (دست‌کم ۲ نویسه).", en: "Write a name (at least 2 characters)." },
  username: { fa: "نام کاربری برای ورود", en: "Username for signing in" },
  usernameHint: { fa: "خالی بگذارید تا MRK خودش یکی بسازد.", en: "Leave empty and MRK will make one." },
  usernameRule: { fa: "نام کاربری فقط حروف کوچک انگلیسی، عدد، نقطه، خط تیره و زیرخط دارد (۳ تا ۶۴ نویسه).", en: "A username uses lowercase letters, digits, dots, dashes and underscores (3–64 characters)." },
  email: { fa: "ایمیل (اختیاری)", en: "Email (optional)" },
  emailRule: { fa: "ایمیل را مثل name@example.com بنویسید.", en: "Write the email like name@example.com." },
  rolesLabel: { fa: "نقش‌ها", en: "Roles" },
  pickRole: { fa: "یک نقش انتخاب کنید.", en: "Pick a role." },
  notYours: { fa: "شما خودتان همه کارهای این نقش را نمی‌توانید، پس نمی‌توانید آن را بدهید.", en: "You can't do everything this role does, so you can't give it." },
  ownerRoleOnly: { fa: "فقط «مالک» می‌تواند مالک تازه بسازد.", en: "Only the owner can make another owner." },
  strongRole: { fa: "این نقش اجازه‌های زیادی دارد. فقط به کسی بدهید که کاملاً به او اعتماد دارید.", en: "This role is powerful. Give it only to someone you fully trust." },
  makeLink: { fa: "یک لینک دعوت یک‌بار مصرف هم بساز", en: "Also make a one-time invite link" },
  makeLinkHint: { fa: "با لینک، همکارتان خودش رمز دلخواهش را می‌گذارد.", en: "With the link, your teammate sets their own password." },
  finish: { fa: "ساخت حساب و دعوت", en: "Create account and invite" },
  summaryName: { fa: "نام", en: "Name" },
  summaryUsername: { fa: "نام کاربری", en: "Username" },
  summaryEmail: { fa: "ایمیل", en: "Email" },
  summaryRole: { fa: "نقش", en: "Role" },
  auto: { fa: "خودکار ساخته می‌شود", en: "Made automatically" },
  none: { fa: "ندارد", en: "None" },
  // one-time secret
  issuedTitle: { fa: "حساب «{name}» ساخته شد", en: "“{name}”'s account is ready" },
  issuedBody: { fa: "این اطلاعات را برای همکارتان بفرستید. در اولین ورود باید رمز را عوض کند.", en: "Send these to your teammate. They'll change the password on first sign-in." },
  issuedUsername: { fa: "نام کاربری", en: "Username" },
  issuedPassword: { fa: "رمز موقت", en: "Temporary password" },
  issuedLink: { fa: "لینک دعوت", en: "Invite link" },
  issuedMessage: { fa: "پیام دعوت آماده (کپی و بفرستید)", en: "Ready invite message (copy and send)" },
  messageText: {
    fa: "سلام {name}! برایتان در پنل MRK حساب ساخته شد.\nنشانی پنل: {url}\nنام کاربری: {username}\nرمز موقت: {password}\nدر اولین ورود رمز را عوض کنید.",
    en: "Hi {name}! You now have an account on the MRK panel.\nPanel address: {url}\nUsername: {username}\nTemporary password: {password}\nPlease change the password when you first sign in."
  },
  messageLink: {
    fa: "\nیا با این لینک وارد شوید و رمز دلخواهتان را بگذارید:\n{link}",
    en: "\nOr open this link and choose your own password:\n{link}"
  },
  invitedToast: { fa: "«{name}» دعوت شد.", en: "“{name}” was invited." },
  // change role
  roleDialogTitle: { fa: "نقش «{name}» را عوض کنید", en: "Change “{name}”'s role" },
  roleWarning: { fa: "با تغییر نقش، «{name}» از همه دستگاه‌ها خارج می‌شود و کلیدهای برنامه‌اش از کار می‌افتند. باید دوباره وارد شود.", en: "Changing the role signs “{name}” out everywhere and stops their app keys. They'll need to sign in again." },
  saveRole: { fa: "ذخیره نقش تازه", en: "Save new role" },
  roleSaved: { fa: "نقش «{name}» به «{role}» تغییر کرد.", en: "“{name}” is now “{role}”." },
  // enable / disable
  disableTitle: { fa: "حساب «{name}» غیرفعال شود؟", en: "Deactivate “{name}”?" },
  disableBody: { fa: "«{name}» دیگر نمی‌تواند وارد شود.", en: "“{name}” won't be able to sign in." },
  disableEffects1: { fa: "از همه دستگاه‌ها خارج می‌شود.", en: "They're signed out everywhere." },
  disableEffects2: { fa: "کلیدهای برنامه‌اش از کار می‌افتند.", en: "Their app keys stop working." },
  enableTitle: { fa: "حساب «{name}» دوباره فعال شود؟", en: "Activate “{name}” again?" },
  enableBody: { fa: "«{name}» دوباره می‌تواند وارد شود. کلیدهای برنامه قبلی‌اش باطل می‌مانند.", en: "“{name}” can sign in again. Their old app keys stay revoked." },
  disabledToast: { fa: "حساب «{name}» غیرفعال شد.", en: "“{name}” was deactivated." },
  enabledToast: { fa: "حساب «{name}» فعال شد.", en: "“{name}” was activated." },
  // reset password
  resetPassword: { fa: "رمز تازه بده", en: "Reset password" },
  resetTitle: { fa: "برای «{name}» رمز موقت تازه ساخته شود؟", en: "Give “{name}” a new temporary password?" },
  resetBody: { fa: "رمز فعلی «{name}» دیگر کار نمی‌کند. یک رمز موقت و لینک یک‌بار مصرف می‌گیرید تا برایش بفرستید.", en: "“{name}”'s current password stops working. You get a temporary password and a one-time link to send them." },
  resetEffects1: { fa: "از همه دستگاه‌ها خارج می‌شود.", en: "They're signed out everywhere." },
  resetEffects2: { fa: "در ورود بعدی باید رمز خودش را بگذارد.", en: "They'll choose their own password at next sign-in." },
  resetConfirm: { fa: "بله، رمز تازه بساز", en: "Yes, make a new password" },
  resetIssuedTitle: { fa: "رمز موقت تازه «{name}»", en: "“{name}”'s new temporary password" },
  resetIssuedBody: { fa: "این اطلاعات را برای «{name}» بفرستید. در ورود بعدی باید رمز را عوض کند.", en: "Send these to “{name}”. They'll change the password at next sign-in." },
  resetIssuedLink: { fa: "لینک گذاشتن رمز", en: "Set-password link" },
  resetMessageText: {
    fa: "سلام {name}! رمز شما در پنل MRK عوض شد.\nنشانی پنل: {url}\nنام کاربری: {username}\nرمز موقت: {password}\nدر ورود بعدی رمز را عوض کنید.",
    en: "Hi {name}! Your MRK panel password was reset.\nPanel address: {url}\nUsername: {username}\nTemporary password: {password}\nPlease change the password when you next sign in."
  },
  resetToast: { fa: "برای «{name}» رمز موقت تازه ساخته شد.", en: "“{name}” has a new temporary password." },
  // sign out everywhere
  signOutAll: { fa: "خروج از همه دستگاه‌ها", en: "Sign out everywhere" },
  signOutTitle: { fa: "«{name}» از همه دستگاه‌ها خارج شود؟", en: "Sign “{name}” out everywhere?" },
  signOutBody: { fa: "«{name}» در همه مرورگرها خارج می‌شود و باید دوباره وارد شود. رمزش عوض نمی‌شود.", en: "“{name}” is signed out in every browser and must sign in again. Their password stays the same." },
  signOutTokens: { fa: "کلیدهای برنامه‌اش را هم باطل کن", en: "Also revoke their app keys" },
  signOutConfirm: { fa: "بله، خارج کن", en: "Yes, sign out" },
  signOutToast: { fa: "«{name}» از همه دستگاه‌ها خارج شد.", en: "“{name}” was signed out everywhere." },
  // delete
  deleteUser: { fa: "حذف حساب", en: "Delete account" },
  deleteTitle: { fa: "حساب «{name}» برای همیشه حذف شود؟", en: "Delete “{name}”'s account for good?" },
  deleteBody: { fa: "«{name}» دیگر نمی‌تواند وارد شود و حسابش برنمی‌گردد. تاریخچه کارهایش می‌ماند.", en: "“{name}” can't sign in again and the account can't be brought back. Their history stays." },
  deleteEffects1: { fa: "از همه دستگاه‌ها خارج می‌شود و کلیدهای برنامه‌اش پاک می‌شوند.", en: "They're signed out and their app keys are removed." },
  deleteEffects2: { fa: "اگر فقط موقتاً نباید وارد شود، «غیرفعال کردن» بهتر است.", en: "If they only need a break, “Deactivate” is better." },
  deletedToast: { fa: "حساب «{name}» حذف شد.", en: "“{name}”'s account was deleted." },
  // advanced
  advId: { fa: "شناسه", en: "ID" },
  advEmail: { fa: "ایمیل", en: "Email" },
  advCreated: { fa: "ساخته شده", en: "Created" },
  advProvider: { fa: "روش ورود", en: "Sign-in method" },
  advTwoStep: { fa: "ورود دومرحله‌ای", en: "Two-step sign-in" },
  advRole: { fa: "کلید نقش", en: "Role key" },
  localSignIn: { fa: "نام کاربری و رمز", en: "Username and password" },
  yes: { fa: "روشن", en: "On" },
  no: { fa: "خاموش", en: "Off" }
} satisfies Record<string, Bi>;

const USERNAME = /^[a-z0-9._-]{3,64}$/;
const EMAIL = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;

function displayName(user: Pick<UserRecord, "display_name" | "username">) {
  return user.display_name?.trim() || user.username;
}

/** «Maryam Rezaei» → "maryam.rezaei"; Persian names give no suggestion (the server makes one). */
function suggestUsername(name: string, email: string) {
  const fromName = name.trim().toLowerCase().replace(/\s+/g, ".").replace(/[^a-z0-9._-]/g, "");
  if (fromName.length >= 3 && /^[a-z0-9._-]+$/.test(name.trim().toLowerCase().replace(/\s+/g, "."))) return fromName.slice(0, 64);
  const local = email.split("@")[0]?.toLowerCase().replace(/[^a-z0-9._-]/g, "") ?? "";
  return local.length >= 3 ? local.slice(0, 64) : "";
}

type InviteResult = {
  user?: { id: number; username: string; display_name?: string | null };
  one_time_password: string;
  must_change_password?: boolean;
  invite?: { id: number; token?: string; path?: string; expires_at?: number } | null;
};

type Issued = { name: string; username: string; password: string; link: string | null; kind?: "invite" | "reset" };

function userStatus(user: UserRecord): { tone: "ok" | "off" | "info" | "warn"; label: Bi } {
  if (!user.enabled) return { tone: "off", label: T.inactive };
  if (user.invite_pending) return { tone: "info", label: T.invited };
  if (user.must_change_password) return { tone: "warn", label: T.mustChange };
  return { tone: "ok", label: T.active };
}

export type PeoplePanelProps = {
  user: AuthUser;
  /** Increment to open the invite wizard (the page's primary button). */
  inviteRequest?: number;
};

export function PeoplePanel({ user, inviteRequest = 0 }: PeoplePanelProps) {
  const { language, isAdvanced, c } = useKit();
  const theme = useTheme();
  const fullScreen = useMediaQuery(theme.breakpoints.down("sm"));
  const { ask, dialog: confirmDialog } = useConfirmAction();
  const { notify, snackbar } = useUndoSnackbar();
  const canRead = hasPermission(user.permissions, "user:read");
  const canWrite = hasPermission(user.permissions, "user:write");
  const isOwner = user.permissions.includes("*") || user.role === "owner";
  const { roles, reload: reloadRoles } = useRoles(canRead);
  const [users, setUsers] = useState<UserRecord[] | null>(null);
  const [loadError, setLoadError] = useState<unknown>(null);
  const [query, setQuery] = useState("");
  const controller = useRef<AbortController | null>(null);

  // invite wizard
  const [inviteOpen, setInviteOpen] = useState(false);
  const [form, setForm] = useState({ name: "", username: "", email: "", role: "viewer", link: true });
  const [fieldErrors, setFieldErrors] = useState<Record<string, string>>({});
  const [issued, setIssued] = useState<Issued | null>(null);

  // change role
  const [roleTarget, setRoleTarget] = useState<UserRecord | null>(null);
  const [nextRole, setNextRole] = useState("viewer");
  const [roleBusy, setRoleBusy] = useState(false);
  const [roleError, setRoleError] = useState<unknown>(null);

  const load = useCallback(async () => {
    if (!canRead) return;
    controller.current?.abort();
    const current = new AbortController();
    controller.current = current;
    try {
      const payload = await getJson<{ items: UserRecord[] }>("/api/v1/users", current.signal);
      setUsers(payload.items ?? []);
      setLoadError(null);
    } catch (caught) {
      if (isAbortError(caught) || (caught instanceof ApiError && caught.status === 401)) return;
      setLoadError(caught);
    }
  }, [canRead]);

  useEffect(() => {
    void load();
    return () => controller.current?.abort();
  }, [load]);

  const openInvite = useCallback(() => {
    setForm({ name: "", username: "", email: "", role: "viewer", link: true });
    setFieldErrors({});
    setInviteOpen(true);
  }, []);

  useEffect(() => {
    if (inviteRequest > 0 && canWrite) openInvite();
  }, [inviteRequest, canWrite, openInvite]);

  // Home's quick action / checklist link: #/people/people?invite=1
  useEffect(() => {
    if (canWrite && /[?&]invite=1/.test(window.location.hash)) openInvite();
  }, [canWrite, openInvite]);

  const roleList = useMemo(() => sortRoles(roles ?? []), [roles]);
  const views = useMemo(() => roleList.map((record) => roleView(language, record)), [roleList, language]);
  const pickerRoles = useMemo(() => {
    if (roleList.length > 0) return views;
    // Roles unavailable: offer the built-in cards from the copy catalogue.
    return (["viewer", "developer", "operator", "admin", "owner"] as const).map((id) => roleView(language, null, id));
  }, [roleList.length, views, language]);

  const roleReason = (role: RoleView): string | null => {
    if (role.id === "owner" && !isOwner) return pick(language, T.ownerRoleOnly);
    if (!isOwner && !covers(user.permissions, role.permissions)) return pick(language, T.notYours);
    return null;
  };

  const userRows = users ?? [];
  const filtered = useMemo(() => {
    const needle = normalizeTyped(query);
    if (!needle) return userRows;
    return userRows.filter((item) => [item.username, item.display_name ?? "", item.email ?? ""].some((field) => normalizeTyped(field).includes(needle)));
  }, [userRows, query]);

  const editableReason = (target: UserRecord): string | null => {
    if (target.id === user.id) return pick(language, T.ownRow);
    if (target.role === "owner" && !isOwner) return pick(language, T.ownerOnly);
    return null;
  };

  const toggleEnabled = async (target: UserRecord) => {
    const name = displayName(target);
    const enabling = !target.enabled;
    const ok = await ask(
      enabling
        ? { title: say(language, T.enableTitle, { name }), body: say(language, T.enableBody, { name }), confirmLabel: pick(language, T.enable) }
        : {
            title: say(language, T.disableTitle, { name }),
            body: say(language, T.disableBody, { name }),
            consequences: [pick(language, T.disableEffects1), pick(language, T.disableEffects2)],
            undoable: true,
            severity: "destructive",
            confirmLabel: pick(language, T.disable)
          }
    );
    if (!ok) return;
    try {
      await mutateJson(`/api/v1/users/${target.id}`, { method: "PATCH", body: { enabled: enabling } });
      notify({ message: say(language, enabling ? T.enabledToast : T.disabledToast, { name }) });
      await load();
    } catch (caught) {
      notify({ message: describeForToast(language, caught), tone: "error" });
    }
  };

  const openRoleDialog = (target: UserRecord) => {
    setRoleTarget(target);
    setNextRole(target.role);
    setRoleError(null);
  };

  const saveRole = async () => {
    if (!roleTarget || nextRole === roleTarget.role) return;
    setRoleBusy(true);
    setRoleError(null);
    try {
      await mutateJson(`/api/v1/users/${roleTarget.id}`, { method: "PATCH", body: { role: nextRole } });
      notify({ message: say(language, T.roleSaved, { name: displayName(roleTarget), role: roleTitle(language, nextRole, roles) }) });
      setRoleTarget(null);
      await Promise.all([load(), reloadRoles()]);
    } catch (caught) {
      setRoleError(caught);
    } finally {
      setRoleBusy(false);
    }
  };

  const resetPassword = async (target: UserRecord) => {
    const name = displayName(target);
    const ok = await ask({
      title: say(language, T.resetTitle, { name }),
      body: say(language, T.resetBody, { name }),
      consequences: [pick(language, T.resetEffects1), pick(language, T.resetEffects2)],
      confirmLabel: pick(language, T.resetConfirm)
    });
    if (!ok) return;
    try {
      const result = await mutateJson<InviteResult>(`/api/v1/users/${target.id}/password-reset`, { method: "POST", body: { create_link: true } });
      const invite = result.invite ?? null;
      const link = invite ? (invite.token ? `${window.location.origin}/#/invite/${invite.token}` : `${window.location.origin}${invite.path ?? ""}`) : null;
      setIssued({ name, username: result.user?.username ?? target.username, password: result.one_time_password, link, kind: "reset" });
      notify({ message: say(language, T.resetToast, { name }) });
      await load();
    } catch (caught) {
      notify({ message: describeForToast(language, caught), tone: "error" });
    }
  };

  const tokensRef = useRef<HTMLInputElement | null>(null);
  const signOutEverywhere = async (target: UserRecord) => {
    const name = displayName(target);
    const ok = await ask({
      title: say(language, T.signOutTitle, { name }),
      body: say(language, T.signOutBody, { name }),
      confirmLabel: pick(language, T.signOutConfirm),
      children: (
        <FormControlLabel
          control={<Checkbox inputRef={tokensRef} defaultChecked={false} />}
          label={pick(language, T.signOutTokens)}
        />
      )
    });
    if (!ok) return;
    const includeTokens = Boolean(tokensRef.current?.checked);
    try {
      await mutateJson(`/api/v1/users/${target.id}/sessions/revoke`, { method: "POST", body: { include_tokens: includeTokens } });
      notify({ message: say(language, T.signOutToast, { name }) });
    } catch (caught) {
      notify({ message: describeForToast(language, caught), tone: "error" });
    }
  };

  const deleteUser = async (target: UserRecord) => {
    const name = displayName(target);
    const ok = await ask({
      title: say(language, T.deleteTitle, { name }),
      body: say(language, T.deleteBody, { name }),
      consequences: [pick(language, T.deleteEffects1), pick(language, T.deleteEffects2)],
      severity: "destructive",
      typed: nameConfirmation(target.username, target.username),
      confirmLabel: pick(language, T.deleteUser)
    });
    if (!ok) return;
    try {
      await mutateJson(`/api/v1/users/${target.id}`, { method: "DELETE" });
      notify({ message: say(language, T.deletedToast, { name }) });
      await Promise.all([load(), reloadRoles()]);
    } catch (caught) {
      notify({ message: describeForToast(language, caught), tone: "error" });
    }
  };

  const panelUrl = `${window.location.origin}/`;

  const steps: WizardStep[] = [
    {
      key: "who",
      title: pick(language, T.stepWho),
      hint: pick(language, T.stepWhoHint),
      validate: () => {
        if (form.name.trim().length < 2) return pick(language, T.nameRule);
        if (form.username.trim() && !USERNAME.test(form.username.trim())) return pick(language, T.usernameRule);
        if (form.email.trim() && !EMAIL.test(form.email.trim())) return pick(language, T.emailRule);
        return null;
      },
      render: () => {
        const suggestion = suggestUsername(form.name, form.email);
        return (
          <Stack spacing={1.5}>
            <TextField
              autoFocus
              fullWidth
              label={pick(language, T.name)}
              value={form.name}
              onChange={(event) => { setForm({ ...form, name: event.target.value }); setFieldErrors(({ display_name: _drop, ...rest }) => rest); }}
              error={Boolean(fieldErrors.display_name)}
              helperText={fieldErrors.display_name ?? " "}
              slotProps={{ htmlInput: { maxLength: 100 } }}
            />
            <TextField
              fullWidth
              label={pick(language, T.username)}
              value={form.username}
              placeholder={suggestion || undefined}
              onChange={(event) => { setForm({ ...form, username: event.target.value.toLowerCase() }); setFieldErrors(({ username: _drop, ...rest }) => rest); }}
              error={Boolean(fieldErrors.username)}
              helperText={fieldErrors.username ?? pick(language, T.usernameHint)}
              autoComplete="off"
              slotProps={{ htmlInput: { dir: "ltr", maxLength: 64, spellCheck: false }, inputLabel: suggestion ? { shrink: true } : undefined }}
            />
            <TextField
              fullWidth
              type="email"
              label={pick(language, T.email)}
              value={form.email}
              onChange={(event) => { setForm({ ...form, email: event.target.value }); setFieldErrors(({ email: _drop, ...rest }) => rest); }}
              error={Boolean(fieldErrors.email)}
              helperText={fieldErrors.email ?? " "}
              autoComplete="off"
              slotProps={{ htmlInput: { dir: "ltr", maxLength: 254 } }}
            />
          </Stack>
        );
      }
    },
    {
      key: "role",
      title: pick(language, T.stepRole),
      hint: pick(language, T.stepRoleHint),
      validate: () => {
        const role = pickerRoles.find((item) => item.id === form.role);
        if (!role || roleReason(role)) return pick(language, T.pickRole);
        return null;
      },
      render: () => (
        <Stack spacing={1.5}>
          <RolePicker
            label={pick(language, T.rolesLabel)}
            roles={pickerRoles}
            value={form.role}
            onChange={(role) => { setForm({ ...form, role }); setFieldErrors(({ role: _drop, ...rest }) => rest); }}
            disabledReason={roleReason}
          />
          {(form.role === "admin" || form.role === "owner") && <Notice tone="warning">{pick(language, T.strongRole)}</Notice>}
          {fieldErrors.role && <Typography role="alert" variant="body2" color="error.main">{fieldErrors.role}</Typography>}
        </Stack>
      )
    },
    {
      key: "send",
      title: pick(language, T.stepSend),
      hint: pick(language, T.stepSendHint),
      render: () => (
        <Stack spacing={2}>
          <KeyValueList
            items={[
              { label: pick(language, T.summaryName), value: form.name.trim() },
              { label: pick(language, T.summaryUsername), value: form.username.trim() ? <Ltr>{form.username.trim()}</Ltr> : pick(language, T.auto) },
              { label: pick(language, T.summaryEmail), value: form.email.trim() ? <Ltr>{form.email.trim()}</Ltr> : pick(language, T.none) },
              { label: pick(language, T.summaryRole), value: roleTitle(language, form.role, roles) }
            ]}
          />
          <FormControlLabel
            control={<Switch checked={form.link} onChange={(_event, value) => setForm({ ...form, link: value })} />}
            label={
              <Box>
                <Typography variant="body2" sx={{ fontWeight: 650 }}>{pick(language, T.makeLink)}</Typography>
                <Typography variant="caption" color="text.secondary">{pick(language, T.makeLinkHint)}</Typography>
              </Box>
            }
          />
        </Stack>
      )
    }
  ];

  const finishInvite = async () => {
    setFieldErrors({});
    const body: Record<string, unknown> = { display_name: form.name.trim(), role: form.role, create_link: form.link };
    if (form.username.trim()) body.username = form.username.trim();
    if (form.email.trim()) body.email = form.email.trim();
    try {
      const result = await mutateJson<InviteResult>("/api/v1/users/invite", { method: "POST", body });
      const invite = result.invite ?? null;
      const link = invite ? (invite.token ? `${window.location.origin}/#/invite/${invite.token}` : `${window.location.origin}${invite.path ?? ""}`) : null;
      setIssued({
        name: form.name.trim(),
        username: result.user?.username ?? form.username.trim(),
        password: result.one_time_password,
        link
      });
      notify({ message: say(language, T.invitedToast, { name: form.name.trim() }) });
      void load();
      void reloadRoles();
    } catch (caught) {
      setFieldErrors(fieldMessages(language, caught));
      throw caught;
    }
  };

  if (!canRead) return <NoAccess needs="user:read" variant="card" />;

  const header = (
    <Stack direction={{ xs: "column", sm: "row" }} spacing={1.5} alignItems={{ sm: "center" }} justifyContent="space-between">
      {userRows.length > 6 ? (
        <TextField
          size="small"
          value={query}
          onChange={(event) => setQuery(event.target.value)}
          placeholder={pick(language, T.search)}
          slotProps={{
            htmlInput: { "aria-label": pick(language, T.search) },
            input: { startAdornment: <InputAdornment position="start"><SearchRoundedIcon fontSize="small" /></InputAdornment> }
          }}
          sx={{ minWidth: { sm: 320 } }}
        />
      ) : <Box />}
      {!canWrite && <NoAccess needs="user:write" />}
    </Stack>
  );

  return (
    <Stack spacing={2}>
      {loadError !== null && <FriendlyError error={loadError} onRetry={() => void load()} />}
      {header}
      {users === null && loadError === null && (
        <Grid container spacing={2}>
          {[0, 1, 2].map((key) => <Grid key={key} size={{ xs: 12, sm: 6, lg: 4 }}><Skeleton variant="rounded" height={150} /></Grid>)}
        </Grid>
      )}
      {users !== null && userRows.length <= 1 && (
        <Card>
          <EmptyState
            icon={GroupRoundedIcon}
            title={pick(language, T.emptyTitle)}
            body={pick(language, T.emptyBody)}
            action={canWrite ? <Button variant="contained" startIcon={<PersonAddAlt1RoundedIcon />} onClick={openInvite} sx={{ minHeight: 44 }}>{pick(language, T.invite)}</Button> : undefined}
            compact
          />
        </Card>
      )}
      {users !== null && query && filtered.length === 0 && (
        <Typography color="text.secondary">{say(language, T.noMatch, { query })}</Typography>
      )}
      <Grid container spacing={2}>
        {filtered.map((item) => {
          const name = displayName(item);
          const view = roleView(language, roleList.find((record) => record.id === item.role) ?? null, item.role);
          const status = userStatus(item);
          const reason = editableReason(item);
          const self = item.id === user.id;
          const menuItems = canWrite && !reason
            ? [
                { key: "role", label: pick(language, T.changeRole), icon: <SwapHorizRoundedIcon fontSize="small" />, onClick: () => openRoleDialog(item) },
                item.enabled
                  ? { key: "disable", label: pick(language, T.disable), icon: <BlockRoundedIcon fontSize="small" />, danger: true, onClick: () => void toggleEnabled(item) }
                  : { key: "enable", label: pick(language, T.enable), icon: <CheckCircleOutlineRoundedIcon fontSize="small" />, onClick: () => void toggleEnabled(item) },
                ...(item.enabled
                  ? [
                      { key: "reset", label: pick(language, T.resetPassword), icon: <LockResetRoundedIcon fontSize="small" />, onClick: () => void resetPassword(item) },
                      { key: "signout", label: pick(language, T.signOutAll), icon: <LogoutRoundedIcon fontSize="small" />, onClick: () => void signOutEverywhere(item) }
                    ]
                  : []),
                { key: "delete", label: pick(language, T.deleteUser), icon: <DeleteForeverRoundedIcon fontSize="small" />, danger: true, onClick: () => void deleteUser(item) }
              ]
            : [];
          return (
            <Grid key={item.id} size={{ xs: 12, sm: 6, lg: 4 }}>
              <Card sx={{ height: "100%", opacity: item.enabled ? 1 : 0.72 }}>
                <CardContent sx={{ p: 2, "&:last-child": { pb: 2 } }}>
                  <Stack direction="row" spacing={1.5} alignItems="flex-start">
                    <Avatar sx={{ bgcolor: `${view.color}.main`, color: `${view.color}.contrastText`, width: 44, height: 44, fontWeight: 760 }} aria-hidden>
                      {initials(name)}
                    </Avatar>
                    <Box sx={{ minWidth: 0, flex: 1 }}>
                      <Stack direction="row" spacing={0.75} alignItems="center" flexWrap="wrap" useFlexGap>
                        <Typography component="h3" sx={{ fontWeight: 760 }} noWrap title={name}>{name}</Typography>
                        {self && <Chip size="small" color="primary" variant="outlined" label={pick(language, T.you)} />}
                      </Stack>
                      {item.display_name && <Typography variant="caption" color="text.secondary" display="block" noWrap><Ltr>{item.username}</Ltr></Typography>}
                      <Typography variant="body2" sx={{ mt: 0.5, fontWeight: 650 }}>{view.name}</Typography>
                      <Typography variant="caption" color="text.secondary" display="block">{view.oneLiner}</Typography>
                    </Box>
                    <CardMenu label={say(language, T.menu, { name })} items={menuItems} />
                  </Stack>
                  <Stack direction="row" spacing={1} alignItems="center" flexWrap="wrap" useFlexGap sx={{ mt: 1.5 }}>
                    <StatusPill tone={status.tone} label={pick(language, status.label)} />
                    <Typography variant="caption" color="text.secondary">
                      {item.last_login_at ? <>{pick(language, T.lastSeen)}<RelativeTime value={item.last_login_at} /></> : pick(language, T.never)}
                    </Typography>
                  </Stack>
                  {reason && canWrite && <Typography variant="caption" color="text.secondary" display="block" sx={{ mt: 1 }}>{reason}</Typography>}
                  {isAdvanced && (
                    <Box sx={{ mt: 1.5 }}>
                      <KeyValueList
                        dense
                        items={[
                          { label: pick(language, T.advId), value: String(item.id), ltr: true },
                          { label: pick(language, T.advRole), value: item.role, ltr: true },
                          { label: pick(language, T.advEmail), value: item.email || c.emptyDash, ltr: Boolean(item.email) },
                          { label: pick(language, T.advCreated), value: <DateTime value={item.created_at} /> },
                          { label: pick(language, T.advProvider), value: item.identity_provider && item.identity_provider !== "local" ? item.identity_provider : pick(language, T.localSignIn) },
                          { label: pick(language, T.advTwoStep), value: pick(language, item.mfa_enabled ? T.yes : T.no) }
                        ]}
                      />
                    </Box>
                  )}
                </CardContent>
              </Card>
            </Grid>
          );
        })}
      </Grid>

      <ActionWizard
        open={inviteOpen}
        title={pick(language, T.invite)}
        steps={steps}
        finishLabel={pick(language, T.finish)}
        onFinish={finishInvite}
        onClose={() => setInviteOpen(false)}
      />

      {issued && (
        <OneTimeSecret
          open
          title={say(language, issued.kind === "reset" ? T.resetIssuedTitle : T.issuedTitle, { name: issued.name })}
          body={issued.kind === "reset" ? say(language, T.resetIssuedBody, { name: issued.name }) : pick(language, T.issuedBody)}
          items={[
            { label: pick(language, T.issuedUsername), value: issued.username, ltr: true },
            { label: pick(language, T.issuedPassword), value: issued.password, ltr: true },
            ...(issued.link ? [{ label: pick(language, issued.kind === "reset" ? T.resetIssuedLink : T.issuedLink), value: issued.link, ltr: true }] : [])
          ]}
          message={{
            label: pick(language, T.issuedMessage),
            value:
              say(language, issued.kind === "reset" ? T.resetMessageText : T.messageText, { name: issued.name, url: panelUrl, username: issued.username, password: issued.password }) +
              (issued.link ? say(language, T.messageLink, { link: issued.link }) : "")
          }}
          onClose={() => setIssued(null)}
        />
      )}

      <Dialog open={roleTarget !== null} onClose={roleBusy ? undefined : () => setRoleTarget(null)} fullScreen={fullScreen} fullWidth maxWidth="md" aria-labelledby="mrk-role-dialog-title">
        {roleTarget && (
          <>
            <DialogTitle id="mrk-role-dialog-title" sx={{ fontWeight: 760 }}>{say(language, T.roleDialogTitle, { name: displayName(roleTarget) })}</DialogTitle>
            <DialogContent>
              <Stack spacing={2} sx={{ pt: 0.5 }}>
                <Notice tone="warning">{say(language, T.roleWarning, { name: displayName(roleTarget) })}</Notice>
                <RolePicker
                  label={pick(language, T.rolesLabel)}
                  roles={pickerRoles}
                  value={nextRole}
                  onChange={setNextRole}
                  disabledReason={roleReason}
                />
                {roleError !== null && <FriendlyError error={roleError} noAction />}
              </Stack>
            </DialogContent>
            <DialogActions sx={{ px: 3, pb: 2, gap: 1 }}>
              <Button onClick={() => setRoleTarget(null)} disabled={roleBusy} sx={{ minHeight: 44 }}>{c.cancel}</Button>
              <Button variant="contained" onClick={() => void saveRole()} disabled={roleBusy || nextRole === roleTarget.role} sx={{ minHeight: 44 }}>
                {roleBusy ? c.saving : pick(language, T.saveRole)}
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

function describeForToast(language: "fa" | "en", error: unknown) {
  const fields = Object.values(fieldMessages(language, error));
  return fields[0] ?? errorSentence(language, error);
}

export default PeoplePanel;
