import { useCallback, useEffect, useState } from "react";
import {
  Alert,
  Box,
  Button,
  Card,
  CardContent,
  Chip,
  CircularProgress,
  Grid,
  IconButton,
  Paper,
  Stack,
  Tooltip,
  Typography
} from "@mui/material";
import ContentCopyRoundedIcon from "@mui/icons-material/ContentCopyRounded";
import DnsRoundedIcon from "@mui/icons-material/DnsRounded";
import RefreshRoundedIcon from "@mui/icons-material/RefreshRounded";
import type { Language } from "./i18n";

type ComponentState = "ready" | "unavailable" | "not_configured";
type RegistryStatus = {
  components: Record<string, ComponentState>;
  database?: { dialect: string; mode: string };
};

type RegistriesPanelProps = {
  language: Language;
  onUnauthorized: () => void;
};

export function RegistriesPanel({ language, onUnauthorized }: RegistriesPanelProps) {
  const fa = language === "fa";
  const [status, setStatus] = useState<RegistryStatus | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(false);
  const [copied, setCopied] = useState("");

  const load = useCallback(async () => {
    setLoading(true);
    setError(false);
    try {
      const response = await fetch("/api/v1/system/status", { cache: "no-store" });
      if (response.status === 401) return onUnauthorized();
      if (!response.ok) throw new Error("status failed");
      setStatus((await response.json()) as RegistryStatus);
    } catch {
      setError(true);
    } finally {
      setLoading(false);
    }
  }, [onUnauthorized]);

  useEffect(() => void load(), [load]);

  const registries = [
    {
      key: "npm_registry",
      name: "npm",
      port: "4873",
      endpoint: "https://npm.example.com/",
      command: "npm config set registry https://npm.example.com/"
    },
    {
      key: "pypi_registry",
      name: "PyPI",
      port: "3141",
      endpoint: "https://pypi.example.com/root/pypi/+simple/",
      command: "pip config set global.index-url https://pypi.example.com/root/pypi/+simple/"
    }
  ];

  const copy = async (value: string, key: string) => {
    await navigator.clipboard.writeText(value);
    setCopied(key);
    window.setTimeout(() => setCopied(""), 1400);
  };

  return (
    <Stack spacing={3}>
      <Stack direction={{ xs: "column", sm: "row" }} justifyContent="space-between" alignItems={{ sm: "flex-end" }} spacing={2}>
        <Box>
          <Typography variant="h4" component="h1">{fa ? "رجیستری‌ها" : "Registries"}</Typography>
          <Typography color="text.secondary" sx={{ mt: 0.8 }}>
            {fa ? "وضعیت سرویس‌دهی، endpointها و تنظیم سریع کلاینت‌ها" : "Serving health, endpoints, and client configuration"}
          </Typography>
        </Box>
        <Button variant="outlined" onClick={() => void load()} disabled={loading} startIcon={loading ? <CircularProgress size={16} /> : <RefreshRoundedIcon />}>
          {fa ? "بروزرسانی" : "Refresh"}
        </Button>
      </Stack>

      {error && <Alert severity="error">{fa ? "دریافت وضعیت رجیستری‌ها ناموفق بود." : "Could not load registry status."}</Alert>}

      <Grid container spacing={3}>
        {registries.map((registry) => {
          const state = status?.components[registry.key] ?? "not_configured";
          const color = state === "ready" ? "success" : state === "unavailable" ? "error" : "warning";
          return (
            <Grid key={registry.key} size={{ xs: 12, lg: 6 }}>
              <Card sx={{ height: "100%" }}>
                <CardContent sx={{ p: 3, "&:last-child": { pb: 3 } }}>
                  <Stack direction="row" justifyContent="space-between" alignItems="flex-start" spacing={2}>
                    <Stack direction="row" spacing={1.5} alignItems="center">
                      <Box sx={{ width: 42, height: 42, borderRadius: 1, bgcolor: "action.hover", color: "primary.main", display: "grid", placeItems: "center" }}><DnsRoundedIcon /></Box>
                      <Box><Typography variant="h6">{registry.name}</Typography><Typography variant="caption" color="text.secondary">{fa ? `پورت ${registry.port}` : `Port ${registry.port}`}</Typography></Box>
                    </Stack>
                    <Chip size="small" color={color} variant="outlined" label={state === "ready" ? (fa ? "آماده" : "Ready") : state === "unavailable" ? (fa ? "خارج از دسترس" : "Unavailable") : (fa ? "پیکربندی نشده" : "Not configured")} />
                  </Stack>
                  <Paper variant="outlined" sx={{ mt: 2.5, p: 1.5, bgcolor: "transparent", borderRadius: 1 }}>
                    <Stack direction="row" spacing={1} alignItems="center" sx={{ minWidth: 0 }}>
                      <Typography dir="ltr" variant="body2" sx={{ flex: 1, minWidth: 0, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>{registry.endpoint}</Typography>
                      <Tooltip title={copied === `${registry.key}-url` ? (fa ? "کپی شد" : "Copied") : (fa ? "کپی" : "Copy")}><IconButton size="small" onClick={() => void copy(registry.endpoint, `${registry.key}-url`)}><ContentCopyRoundedIcon fontSize="small" /></IconButton></Tooltip>
                    </Stack>
                  </Paper>
                  <Typography variant="caption" color="text.secondary" sx={{ mt: 2, display: "block" }}>{fa ? "دستور تنظیم کلاینت" : "Client setup command"}</Typography>
                  <Paper variant="outlined" sx={{ mt: 0.8, p: 1.5, bgcolor: "background.default", borderRadius: 1 }}>
                    <Stack direction="row" spacing={1} alignItems="center" sx={{ minWidth: 0 }}>
                      <Typography component="code" dir="ltr" variant="body2" sx={{ flex: 1, minWidth: 0, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>{registry.command}</Typography>
                      <IconButton size="small" onClick={() => void copy(registry.command, `${registry.key}-command`)}><ContentCopyRoundedIcon fontSize="small" /></IconButton>
                    </Stack>
                  </Paper>
                </CardContent>
              </Card>
            </Grid>
          );
        })}
      </Grid>

      <Alert severity="info" variant="outlined">
        {fa
          ? "در reverse proxy فقط دامنه‌های عمومی را به پورت‌های 8080، 4873 و 3141 متصل کنید؛ پورت داخلی دیتابیس هرگز publish نمی‌شود."
          : "Expose only ports 8080, 4873, and 3141 through your reverse proxy. The internal database port is never published."}
      </Alert>
    </Stack>
  );
}
