import { useCallback, useEffect, useMemo, useState, type FormEvent } from "react";
import {
  Alert,
  Box,
  Button,
  Card,
  CardContent,
  Chip,
  CircularProgress,
  Divider,
  FormControlLabel,
  Grid,
  MenuItem,
  Paper,
  Stack,
  Switch,
  Table,
  TableBody,
  TableCell,
  TableContainer,
  TableHead,
  TableRow,
  TextField,
  Typography
} from "@mui/material";
import AddRoundedIcon from "@mui/icons-material/AddRounded";
import RefreshRoundedIcon from "@mui/icons-material/RefreshRounded";
import type { Language } from "./i18n";

type UserRecord = {
  id: number;
  username: string;
  role: string;
  enabled: number;
  created_at: number;
  last_login_at: number | null;
};

type RoleRecord = { name: string; permissions: string[] };
type AuditRecord = {
  id: number;
  actor_user_id: number | null;
  action: string;
  object_type: string;
  object_id: string | null;
  result: string;
  source_ip: string | null;
  occurred_at: number;
};
type TokenRecord = {
  id: number;
  name: string;
  scopes: string[];
  created_at: number;
  expires_at: number;
  last_used_at: number | null;
  revoked_at: number | null;
};

type AccessPanelProps = {
  language: Language;
  csrf: string;
  permissions: string[];
  canWrite: boolean;
  onUnauthorized: () => void;
};

const text = {
  fa: {
    title: "کنترل دسترسی",
    hint: "کاربران، نقش‌های ثابت و رویدادهای امنیتی را از یک نقطه مدیریت کنید.",
    users: "کاربران",
    roles: "نقش‌ها",
    audit: "لاگ ممیزی",
    username: "نام کاربری",
    password: "رمز عبور (حداقل ۱۴ نویسه)",
    role: "نقش",
    state: "وضعیت",
    lastLogin: "آخرین ورود",
    active: "فعال",
    create: "ساخت کاربر",
    creating: "در حال ساخت…",
    refresh: "بروزرسانی",
    permissions: "مجوزها",
    action: "عملیات",
    result: "نتیجه",
    actor: "عامل",
    time: "زمان",
    none: "—",
    loadError: "دریافت اطلاعات دسترسی ناموفق بود.",
    createError: "ساخت کاربر ناموفق بود؛ نام کاربری یا ورودی‌ها را بررسی کنید.",
    created: "کاربر با موفقیت ساخته شد.",
    readOnly: "نقش شما فقط اجازه مشاهده این بخش را دارد."
    ,tokens: "توکن‌های API",
    tokenName: "نام توکن",
    tokenExpiry: "اعتبار",
    oneDay: "۱ روز",
    thirtyDays: "۳۰ روز",
    oneYear: "۱ سال",
    createToken: "ساخت توکن خواندنی",
    tokenOnce: "این مقدار فقط همین یک‌بار نمایش داده می‌شود؛ اکنون آن را کپی کنید.",
    revoke: "لغو",
    disable: "غیرفعال‌سازی",
    enable: "فعال‌سازی",
    saveRole: "ذخیره نقش",
    tokenError: "عملیات توکن ناموفق بود."
    ,registration: "ثبت‌نام عمومی"
    ,registrationHint: "پس از راه‌اندازی اولیه، ثبت‌نام عمومی پیش‌فرض بسته است. در صورت فعال‌سازی، حساب‌های جدید با نقش viewer ساخته می‌شوند."
    ,registrationEnabled: "اجازه ثبت‌نام کاربر جدید"
    ,registrationError: "تغییر وضعیت ثبت‌نام انجام نشد."
  },
  en: {
    title: "Access control",
    hint: "Manage users, immutable roles, and security events from one place.",
    users: "Users",
    roles: "Roles",
    audit: "Audit log",
    username: "Username",
    password: "Password (14+ characters)",
    role: "Role",
    state: "State",
    lastLogin: "Last sign-in",
    active: "Active",
    create: "Create user",
    creating: "Creating…",
    refresh: "Refresh",
    permissions: "Permissions",
    action: "Action",
    result: "Result",
    actor: "Actor",
    time: "Time",
    none: "—",
    loadError: "Could not load access-control data.",
    createError: "Could not create the user. Check the username and inputs.",
    created: "User created successfully.",
    readOnly: "Your role has read-only access to this section."
    ,tokens: "API tokens",
    tokenName: "Token name",
    tokenExpiry: "Expiry",
    oneDay: "1 day",
    thirtyDays: "30 days",
    oneYear: "1 year",
    createToken: "Create read-only token",
    tokenOnce: "This value is shown only once. Copy it now.",
    revoke: "Revoke",
    disable: "Disable",
    enable: "Enable",
    saveRole: "Save role",
    tokenError: "The token operation failed."
    ,registration: "Public registration"
    ,registrationHint: "Public registration is closed after first-run setup. When enabled, new accounts receive the viewer role."
    ,registrationEnabled: "Allow new user registration"
    ,registrationError: "Could not update registration policy."
  }
} as const;

function formatTime(timestamp: number | null, language: Language) {
  if (!timestamp) return text[language].none;
  return new Intl.DateTimeFormat(language === "fa" ? "fa-IR" : "en-US", {
    dateStyle: "medium",
    timeStyle: "short"
  }).format(new Date(timestamp * 1000));
}

export function AccessPanel({
  language,
  csrf,
  permissions,
  canWrite,
  onUnauthorized
}: AccessPanelProps) {
  const copy = text[language];
  const [users, setUsers] = useState<UserRecord[]>([]);
  const [roles, setRoles] = useState<RoleRecord[]>([]);
  const [audit, setAudit] = useState<AuditRecord[]>([]);
  const [tokens, setTokens] = useState<TokenRecord[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(false);
  const [notice, setNotice] = useState<"created" | "createError" | null>(null);
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [role, setRole] = useState("viewer");
  const [creating, setCreating] = useState(false);
  const [tokenName, setTokenName] = useState("");
  const [tokenExpiry, setTokenExpiry] = useState(2592000);
  const [issuedToken, setIssuedToken] = useState("");
  const [registrationEnabled, setRegistrationEnabled] = useState(false);
  const [registrationSaving, setRegistrationSaving] = useState(false);
  const canReadTokens = permissions.includes("*") || permissions.includes("token:read");
  const canWriteTokens = permissions.includes("*") || permissions.includes("token:write");

  const load = useCallback(async () => {
    setLoading(true);
    setError(false);
    try {
      const responses = await Promise.all([
        fetch("/api/v1/users", { cache: "no-store" }),
        fetch("/api/v1/roles", { cache: "no-store" }),
        fetch("/api/v1/audit-events?limit=50", { cache: "no-store" }),
        canReadTokens
          ? fetch("/api/v1/tokens", { cache: "no-store" })
          : Promise.resolve(new Response(JSON.stringify({ items: [] }), { status: 200 })),
        fetch("/api/v1/settings/registration", { cache: "no-store" })
      ]);
      if (responses.some((response) => response.status === 401)) {
        onUnauthorized();
        return;
      }
      if (responses.some((response) => !response.ok)) throw new Error("access request failed");
      const [userPayload, rolePayload, auditPayload, tokenPayload, registrationPayload] = await Promise.all(
        responses.map((response) => response.json())
      );
      setUsers(userPayload.items as UserRecord[]);
      setRoles(rolePayload.items as RoleRecord[]);
      setAudit(auditPayload.items as AuditRecord[]);
      setTokens(tokenPayload.items as TokenRecord[]);
      setRegistrationEnabled(Boolean(registrationPayload.enabled));
    } catch {
      setError(true);
    } finally {
      setLoading(false);
    }
  }, [canReadTokens, onUnauthorized]);

  useEffect(() => void load(), [load]);

  const userNames = useMemo(
    () => new Map(users.map((item) => [item.id, item.username])),
    [users]
  );

  const createUser = async (event: FormEvent<HTMLFormElement>) => {
    event.preventDefault();
    setCreating(true);
    setNotice(null);
    try {
      const response = await fetch("/api/v1/users", {
        method: "POST",
        headers: {
          Accept: "application/json",
          "Content-Type": "application/json",
          "X-CSRF-Token": csrf
        },
        body: JSON.stringify({ username, password, role })
      });
      if (response.status === 401) {
        onUnauthorized();
        return;
      }
      if (!response.ok) throw new Error("create failed");
      setUsername("");
      setPassword("");
      setNotice("created");
      await load();
    } catch {
      setNotice("createError");
    } finally {
      setCreating(false);
    }
  };

  const updateUser = async (userId: number, values: { role?: string; enabled?: boolean }) => {
    setNotice(null);
    const response = await fetch(`/api/v1/users/${userId}`, {
      method: "PATCH",
      headers: {
        Accept: "application/json",
        "Content-Type": "application/json",
        "X-CSRF-Token": csrf
      },
      body: JSON.stringify(values)
    });
    if (response.status === 401) return onUnauthorized();
    if (!response.ok) {
      setNotice("createError");
      return;
    }
    await load();
  };

  const createToken = async (event: FormEvent<HTMLFormElement>) => {
    event.preventDefault();
    setIssuedToken("");
    const response = await fetch("/api/v1/tokens", {
      method: "POST",
      headers: {
        Accept: "application/json",
        "Content-Type": "application/json",
        "X-CSRF-Token": csrf
      },
      body: JSON.stringify({
        name: tokenName,
        scopes: ["system:read", "upstream:read", "cache:read", "task:read"],
        expires_in_seconds: tokenExpiry
      })
    });
    if (response.status === 401) return onUnauthorized();
    if (!response.ok) {
      setNotice("createError");
      return;
    }
    const payload = (await response.json()) as { token: string };
    setIssuedToken(payload.token);
    setTokenName("");
    await load();
  };

  const revokeToken = async (tokenId: number) => {
    const response = await fetch(`/api/v1/tokens/${tokenId}`, {
      method: "DELETE",
      headers: { Accept: "application/json", "X-CSRF-Token": csrf }
    });
    if (response.status === 401) return onUnauthorized();
    if (!response.ok) {
      setNotice("createError");
      return;
    }
    await load();
  };

  const updateRegistration = async (enabled: boolean) => {
    setRegistrationSaving(true);
    const response = await fetch("/api/v1/settings/registration", {
      method: "PATCH",
      headers: {
        Accept: "application/json",
        "Content-Type": "application/json",
        "X-CSRF-Token": csrf
      },
      body: JSON.stringify({ enabled })
    });
    setRegistrationSaving(false);
    if (response.status === 401) return onUnauthorized();
    if (!response.ok) {
      setNotice("createError");
      return;
    }
    setRegistrationEnabled(enabled);
  };

  return (
    <Stack spacing={3}>
      <Stack
        direction={{ xs: "column", sm: "row" }}
        justifyContent="space-between"
        alignItems={{ sm: "flex-end" }}
        spacing={2}
      >
        <Box>
          <Typography variant="h4" component="h1">{copy.title}</Typography>
          <Typography color="text.secondary" sx={{ mt: 0.8 }}>{copy.hint}</Typography>
        </Box>
        <Button
          variant="outlined"
          startIcon={loading ? <CircularProgress size={16} /> : <RefreshRoundedIcon />}
          onClick={() => void load()}
          disabled={loading}
        >
          {copy.refresh}
        </Button>
      </Stack>

      {error && <Alert severity="error">{copy.loadError}</Alert>}
      {notice && <Alert severity={notice === "created" ? "success" : "error"}>{copy[notice]}</Alert>}
      {!canWrite && <Alert severity="info">{copy.readOnly}</Alert>}

      <Card>
        <CardContent sx={{ p: 3, "&:last-child": { pb: 3 } }}>
          <Stack direction={{ xs: "column", sm: "row" }} justifyContent="space-between" alignItems={{ sm: "center" }} spacing={2}>
            <Box>
              <Typography variant="h6">{copy.registration}</Typography>
              <Typography variant="body2" color="text.secondary" sx={{ mt: 0.6, maxWidth: 760 }}>{copy.registrationHint}</Typography>
            </Box>
            <FormControlLabel
              control={
                <Switch
                  checked={registrationEnabled}
                  disabled={!canWrite || registrationSaving}
                  onChange={(event) => void updateRegistration(event.target.checked)}
                />
              }
              label={copy.registrationEnabled}
              sx={{ m: 0, flexShrink: 0 }}
            />
          </Stack>
        </CardContent>
      </Card>

      {canWrite && (
        <Card>
          <CardContent sx={{ p: 3, "&:last-child": { pb: 3 } }}>
            <Typography variant="h6">{copy.create}</Typography>
            <Box component="form" onSubmit={(event) => void createUser(event)} sx={{ mt: 2 }}>
              <Grid container spacing={2}>
                <Grid size={{ xs: 12, md: 3 }}>
                  <TextField fullWidth required label={copy.username} value={username} onChange={(event) => setUsername(event.target.value)} />
                </Grid>
                <Grid size={{ xs: 12, md: 4 }}>
                  <TextField fullWidth required type="password" inputProps={{ minLength: 14 }} label={copy.password} value={password} onChange={(event) => setPassword(event.target.value)} />
                </Grid>
                <Grid size={{ xs: 12, md: 3 }}>
                  <TextField select fullWidth label={copy.role} value={role} onChange={(event) => setRole(event.target.value)}>
                    {roles.map((item) => <MenuItem key={item.name} value={item.name}>{item.name}</MenuItem>)}
                  </TextField>
                </Grid>
                <Grid size={{ xs: 12, md: 2 }}>
                  <Button fullWidth type="submit" variant="contained" startIcon={<AddRoundedIcon />} disabled={creating} sx={{ height: "100%", minHeight: 56 }}>
                    {creating ? copy.creating : copy.create}
                  </Button>
                </Grid>
              </Grid>
            </Box>
          </CardContent>
        </Card>
      )}

      {canReadTokens && (
        <Card>
          <CardContent sx={{ p: 3, "&:last-child": { pb: 3 } }}>
            <Typography variant="h6">{copy.tokens}</Typography>
            {issuedToken && (
              <Alert severity="warning" sx={{ mt: 2 }}>
                <Typography variant="body2" fontWeight={700}>{copy.tokenOnce}</Typography>
                <Typography component="code" dir="ltr" sx={{ mt: 1, display: "block", overflowWrap: "anywhere" }}>{issuedToken}</Typography>
              </Alert>
            )}
            {canWriteTokens && (
              <Box component="form" onSubmit={(event) => void createToken(event)} sx={{ mt: 2 }}>
                <Grid container spacing={2}>
                  <Grid size={{ xs: 12, md: 5 }}><TextField fullWidth required label={copy.tokenName} value={tokenName} onChange={(event) => setTokenName(event.target.value)} /></Grid>
                  <Grid size={{ xs: 12, md: 3 }}><TextField select fullWidth label={copy.tokenExpiry} value={tokenExpiry} onChange={(event) => setTokenExpiry(Number(event.target.value))}><MenuItem value={86400}>{copy.oneDay}</MenuItem><MenuItem value={2592000}>{copy.thirtyDays}</MenuItem><MenuItem value={31536000}>{copy.oneYear}</MenuItem></TextField></Grid>
                  <Grid size={{ xs: 12, md: 4 }}><Button fullWidth type="submit" variant="outlined" sx={{ height: "100%", minHeight: 56 }}>{copy.createToken}</Button></Grid>
                </Grid>
              </Box>
            )}
            <Stack divider={<Divider flexItem />} sx={{ mt: 2 }}>
              {tokens.map((item) => <Stack key={item.id} direction={{ xs: "column", sm: "row" }} alignItems={{ sm: "center" }} spacing={1.5} sx={{ py: 1.5 }}><Box sx={{ flex: 1, minWidth: 0 }}><Typography fontWeight={700}>{item.name}</Typography><Typography variant="caption" color="text.secondary" dir="ltr" display="block" noWrap>{item.scopes.join(" · ")}</Typography></Box><Typography variant="caption" color="text.secondary" noWrap>{formatTime(item.expires_at, language)}</Typography>{canWriteTokens && !item.revoked_at && <Button size="small" color="error" onClick={() => void revokeToken(item.id)}>{copy.revoke}</Button>}</Stack>)}
            </Stack>
          </CardContent>
        </Card>
      )}

      <Grid container spacing={3}>
        <Grid size={{ xs: 12, xl: 7 }}>
          <Card sx={{ height: "100%" }}>
            <CardContent sx={{ p: 0, "&:last-child": { pb: 0 } }}>
              <Typography variant="h6" sx={{ px: 3, pt: 3 }}>{copy.users}</Typography>
              <TableContainer sx={{ mt: 1.5 }}>
                <Table size="small">
                  <TableHead><TableRow><TableCell>{copy.username}</TableCell><TableCell>{copy.role}</TableCell><TableCell>{copy.state}</TableCell><TableCell>{copy.lastLogin}</TableCell><TableCell /></TableRow></TableHead>
                  <TableBody>{users.map((item) => <TableRow key={item.id} hover><TableCell><Typography fontWeight={680}>{item.username}</Typography></TableCell><TableCell>{canWrite ? <TextField select size="small" value={item.role} onChange={(event) => void updateUser(item.id, { role: event.target.value })} sx={{ minWidth: 120 }}>{roles.map((roleItem) => <MenuItem key={roleItem.name} value={roleItem.name}>{roleItem.name}</MenuItem>)}</TextField> : <Chip size="small" variant="outlined" label={item.role} />}</TableCell><TableCell><Chip size="small" color={item.enabled ? "success" : "default"} label={item.enabled ? copy.active : copy.none} /></TableCell><TableCell sx={{ whiteSpace: "nowrap" }}>{formatTime(item.last_login_at, language)}</TableCell><TableCell align="right">{canWrite && <Button size="small" color={item.enabled ? "warning" : "success"} onClick={() => void updateUser(item.id, { enabled: !item.enabled })}>{item.enabled ? copy.disable : copy.enable}</Button>}</TableCell></TableRow>)}</TableBody>
                </Table>
              </TableContainer>
            </CardContent>
          </Card>
        </Grid>

        <Grid size={{ xs: 12, xl: 5 }}>
          <Card sx={{ height: "100%" }}>
            <CardContent sx={{ p: 3, "&:last-child": { pb: 3 } }}>
              <Typography variant="h6">{copy.roles}</Typography>
              <Stack divider={<Divider flexItem />} sx={{ mt: 1.5 }}>
                {roles.map((item) => <Box key={item.name} sx={{ py: 1.5 }}><Stack direction="row" justifyContent="space-between" spacing={1}><Typography fontWeight={720}>{item.name}</Typography><Chip size="small" label={`${item.permissions.length} ${copy.permissions}`} /></Stack><Typography variant="caption" color="text.secondary" dir="ltr" sx={{ mt: 0.6, display: "block", overflowWrap: "anywhere" }}>{item.permissions.join(" · ")}</Typography></Box>)}
              </Stack>
            </CardContent>
          </Card>
        </Grid>

        <Grid size={12}>
          <Card>
            <CardContent sx={{ p: 0, "&:last-child": { pb: 0 } }}>
              <Typography variant="h6" sx={{ px: 3, pt: 3 }}>{copy.audit}</Typography>
              <TableContainer sx={{ mt: 1.5 }}>
                <Table size="small">
                  <TableHead><TableRow><TableCell>{copy.time}</TableCell><TableCell>{copy.actor}</TableCell><TableCell>{copy.action}</TableCell><TableCell>{copy.result}</TableCell><TableCell>IP</TableCell></TableRow></TableHead>
                  <TableBody>{audit.map((item) => <TableRow key={item.id} hover><TableCell sx={{ whiteSpace: "nowrap" }}>{formatTime(item.occurred_at, language)}</TableCell><TableCell>{item.actor_user_id ? userNames.get(item.actor_user_id) ?? `#${item.actor_user_id}` : copy.none}</TableCell><TableCell dir="ltr">{item.action}</TableCell><TableCell><Chip size="small" color={item.result === "success" ? "success" : "warning"} variant="outlined" label={item.result} /></TableCell><TableCell dir="ltr">{item.source_ip ?? copy.none}</TableCell></TableRow>)}</TableBody>
                </Table>
              </TableContainer>
            </CardContent>
          </Card>
        </Grid>
      </Grid>
    </Stack>
  );
}
