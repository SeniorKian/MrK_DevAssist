import { useEffect, useState } from "react";
import { Box, FormControlLabel, ListSubheader, MenuItem, Switch, TextField, Tooltip, Typography } from "@mui/material";
import { getJson, isAbortError } from "./api";
import type { Language } from "./i18n";

/** Shared outbound-proxy types, data hook and the per-connection proxy picker. */

export type ProxyType = "http" | "https" | "socks5" | "socks5h";
export const PROXY_TYPES: ProxyType[] = ["http", "https", "socks5", "socks5h"];

export type ProxyUsage = { kind: "upstream" | "notification_channel" | string; id: string; name: string; via_default: boolean };
export type ProxyRecord = {
  id: string;
  name: string;
  type: ProxyType;
  host: string;
  port: number;
  username: string | null;
  secret_configured: boolean;
  enabled: boolean;
  no_proxy: string[];
  is_default: boolean;
  created_at: number;
  updated_at: number;
  used_by: ProxyUsage[];
};
export type ProxyList = { items: ProxyRecord[]; default_proxy_id: string | null };

/** "" = direct (no proxy), "default" = the default proxy, otherwise a proxy id. */
export type ProxyChoice = string;

export function choiceFromApi(value: string | null | undefined): ProxyChoice {
  return value ?? "";
}

export function choiceToApi(value: ProxyChoice): string | null {
  return value === "" ? null : value;
}

/** Proxy types a connection kind supports: npm only HTTP/HTTPS, email only SOCKS. */
export function supportedTypesFor(group: string): ProxyType[] {
  if (group === "npm") return ["http", "https"];
  if (group === "email") return ["socks5", "socks5h"];
  return PROXY_TYPES;
}

const labels = {
  fa: {
    direct: "مستقیم (بدون پروکسی)",
    useDefault: "پروکسی پیش‌فرض",
    specific: "یک پروکسی مشخص",
    proxy: "پروکسی",
    sendThrough: "از پروکسی رد شود",
    noDefault: "هنوز پروکسی پیش‌فرض ندارید. در «امنیت و اینترنت › اینترنت و پروکسی» یکی را پیش‌فرض کنید.",
    unsupported: "پروکسی پیش‌فرض برای این سرویس مناسب نیست؛ یک پروکسی دیگر انتخاب کنید.",
    disabledProxy: "خاموش",
    notSupportedShort: "مناسب این سرویس نیست",
    specificInSimple: "از پروکسی «{name}» استفاده می‌شود."
  },
  en: {
    direct: "Direct (no proxy)",
    useDefault: "Default proxy",
    specific: "A specific proxy",
    proxy: "Proxy",
    sendThrough: "Go through the proxy",
    noDefault: "You don't have a default proxy yet. Make one the default in Security & internet › Internet & proxy.",
    unsupported: "The default proxy doesn't suit this service; pick another proxy.",
    disabledProxy: "off",
    notSupportedShort: "doesn't suit this service",
    specificInSimple: "Uses the proxy “{name}”."
  }
} as const;

/** Short Latin name of a proxy type (shown next to a proxy's name). */
export const PROXY_TYPE_SHORT: Record<ProxyType, string> = { http: "HTTP", https: "HTTPS", socks5: "SOCKS5", socks5h: "SOCKS5h" };

/** Load the proxy list once (null while loading; `failed` when the user may not read proxies). */
export function useProxyList(refreshKey = 0) {
  const [list, setList] = useState<ProxyList | null>(null);
  const [failed, setFailed] = useState(false);
  useEffect(() => {
    const controller = new AbortController();
    void (async () => {
      try {
        setList(await getJson<ProxyList>("/api/v1/settings/proxies", controller.signal));
        setFailed(false);
      } catch (caught) {
        if (isAbortError(caught)) return;
        setFailed(true);
      }
    })();
    return () => controller.abort();
  }, [refreshKey]);
  return { list, failed };
}

export function defaultProxyOf(list: ProxyList | null) {
  if (!list?.default_proxy_id) return null;
  return list.items.find((item) => item.id === list.default_proxy_id) ?? null;
}

/** Why "use the default proxy" is unavailable for a connection, or null when it is available. */
export function defaultUnavailableReason(language: Language, list: ProxyList | null, supported: ProxyType[]): string | null {
  const copy = labels[language];
  const fallback = defaultProxyOf(list);
  if (!fallback) return copy.noDefault;
  if (!supported.includes(fallback.type)) return copy.unsupported;
  return null;
}

type PickerProps = {
  language: Language;
  list: ProxyList | null;
  value: ProxyChoice;
  onChange: (value: ProxyChoice) => void;
  supported: ProxyType[];
  /** Advanced = full select; Simple = one "send through proxy" switch bound to the default proxy. */
  advanced: boolean;
  disabled?: boolean;
  /** Accessible name of the connection, for the switch label. */
  label?: string;
  size?: "small" | "medium";
  hideLabel?: boolean;
};

export function ProxyPicker({ language, list, value, onChange, supported, advanced, disabled, label, size = "small", hideLabel }: PickerProps) {
  const copy = labels[language];
  const reason = defaultUnavailableReason(language, list, supported);
  const fallback = defaultProxyOf(list);

  if (!advanced) {
    const specific = value !== "" && value !== "default" ? list?.items.find((item) => item.id === value) : null;
    const checked = value !== "";
    // Turning the switch on needs a usable default; turning it off is always allowed.
    const blocked = !checked && reason !== null;
    const control = (
      <Switch
        checked={checked}
        disabled={disabled || blocked}
        onChange={(_event, on) => onChange(on ? "default" : "")}
        slotProps={{ input: { "aria-label": label ? `${copy.sendThrough} · ${label}` : copy.sendThrough } }}
      />
    );
    const body = hideLabel ? control : <FormControlLabel control={control} label={copy.sendThrough} />;
    return (
      <Box>
        <Tooltip title={blocked ? reason : specific ? copy.specificInSimple.replace("{name}", specific.name) : value === "default" && fallback ? `${copy.useDefault}: ${fallback.name}` : ""}>
          <span>{body}</span>
        </Tooltip>
        {!hideLabel && blocked && <Typography variant="caption" color="text.secondary" display="block">{reason}</Typography>}
      </Box>
    );
  }

  const items = list?.items ?? [];
  const known = value === "" || value === "default" || items.some((item) => item.id === value);
  return (
    <TextField
      select
      fullWidth
      size={size}
      label={hideLabel ? undefined : copy.proxy}
      value={known ? value : ""}
      disabled={disabled}
      onChange={(event) => onChange(event.target.value)}
      slotProps={{ htmlInput: { "aria-label": label ? `${copy.proxy} · ${label}` : copy.proxy } }}
    >
      <MenuItem value="">{copy.direct}</MenuItem>
      <MenuItem value="default" disabled={reason !== null && value !== "default"}>
        {copy.useDefault}{fallback ? ` (${fallback.name})` : ""}
      </MenuItem>
      {items.length > 0 && <ListSubheader>{copy.specific}</ListSubheader>}
      {items.map((item) => {
        const ok = supported.includes(item.type);
        return (
          <MenuItem key={item.id} value={item.id} disabled={!ok && value !== item.id}>
            <Box component="span" dir="auto">{item.name}</Box>
            <Box component="span" sx={{ color: "text.secondary", marginInlineStart: 1, fontSize: 12 }}>
              {PROXY_TYPE_SHORT[item.type] ?? item.type}{!item.enabled ? ` · ${copy.disabledProxy}` : ""}{!ok ? ` · ${copy.notSupportedShort}` : ""}
            </Box>
          </MenuItem>
        );
      })}
    </TextField>
  );
}
