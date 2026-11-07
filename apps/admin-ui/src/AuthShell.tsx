import type { ReactNode } from "react";
import { Box, Button, Chip, Stack, Typography } from "@mui/material";
import HubRoundedIcon from "@mui/icons-material/HubRounded";
import SecurityRoundedIcon from "@mui/icons-material/SecurityRounded";
import StorageRoundedIcon from "@mui/icons-material/StorageRounded";
import type { Language } from "./i18n";
import { translate } from "./i18n";

type AuthShellProps = {
  language: Language;
  onLanguageChange: () => void;
  children: ReactNode;
};

export function AuthShell({ language, onLanguageChange, children }: AuthShellProps) {
  const items = [
    { icon: SecurityRoundedIcon, label: translate(language, "securedSetup") },
    { icon: StorageRoundedIcon, label: translate(language, "localData") },
    { icon: HubRoundedIcon, label: translate(language, "modularPlatform") }
  ];

  return (
    <Box
      component="main"
      dir={language === "fa" ? "rtl" : "ltr"}
      sx={{
        minHeight: "100vh",
        display: "grid",
        gridTemplateColumns: { xs: "1fr", md: "minmax(340px, 0.85fr) minmax(520px, 1.15fr)" },
        bgcolor: "background.default"
      }}
    >
      <Box
        sx={{
          display: { xs: "none", md: "flex" },
          flexDirection: "column",
          justifyContent: "space-between",
          p: { md: 5, lg: 7 },
          borderInlineEnd: 1,
          borderColor: "divider",
          background:
            "radial-gradient(circle at 30% 20%, rgba(45,212,191,.16), transparent 34%), linear-gradient(160deg, rgba(56,189,248,.06), transparent 52%)"
        }}
      >
        <Stack direction="row" alignItems="center" spacing={1.5}>
          <Box
            aria-hidden
            sx={{
              width: 42,
              height: 42,
              borderRadius: 1.25,
              display: "grid",
              placeItems: "center",
              fontWeight: 850,
              color: "#042f2e",
              background: "linear-gradient(145deg, #99f6e4, #38bdf8)"
            }}
          >
            MRK
          </Box>
          <Box>
            <Typography fontWeight={800}>MRK Package Mirror</Typography>
            <Typography variant="caption" color="text.secondary">
              {translate(language, "subtitle")}
            </Typography>
          </Box>
        </Stack>

        <Box sx={{ maxWidth: 500 }}>
          <Chip label="Operations Console" color="primary" variant="outlined" size="small" />
          <Typography variant="h3" component="p" sx={{ mt: 2.5, fontWeight: 820, lineHeight: 1.25 }}>
            {language === "fa" ? "زیرساخت پکیج، تحت کنترل شما" : "Package infrastructure, under your control"}
          </Typography>
          <Typography color="text.secondary" sx={{ mt: 2, lineHeight: 1.9 }}>
            {language === "fa"
              ? "مدیریت رجیستری‌ها، سلامت سرویس و دسترسی‌ها در یک کنترل‌پلین امن و قابل توسعه."
              : "Manage registries, service health, and access from one secure, extensible control plane."}
          </Typography>
          <Stack spacing={1.4} sx={{ mt: 4 }}>
            {items.map(({ icon: Icon, label }) => (
              <Stack key={label} direction="row" alignItems="center" spacing={1.25}>
                <Box
                  sx={{
                    width: 34,
                    height: 34,
                    display: "grid",
                    placeItems: "center",
                    border: 1,
                    borderColor: "divider",
                    borderRadius: 1
                  }}
                >
                  <Icon color="primary" sx={{ fontSize: 19 }} />
                </Box>
                <Typography variant="body2" fontWeight={620}>
                  {label}
                </Typography>
              </Stack>
            ))}
          </Stack>
        </Box>
        <Typography variant="caption" color="text.secondary">
          MRK · Single-node appliance
        </Typography>
      </Box>

      <Box sx={{ minWidth: 0, display: "flex", flexDirection: "column", p: { xs: 2, sm: 4, lg: 7 } }}>
        <Stack direction="row" justifyContent="space-between" alignItems="center">
          <Stack direction="row" alignItems="center" spacing={1.2} sx={{ display: { md: "none" } }}>
            <Box sx={{ width: 34, height: 34, display: "grid", placeItems: "center", bgcolor: "primary.main", color: "#042f2e", borderRadius: 1, fontWeight: 850, fontSize: 12 }}>MRK</Box>
            <Typography fontWeight={780}>Package Mirror</Typography>
          </Stack>
          <Box sx={{ display: { xs: "none", md: "block" } }} />
          <Button size="small" variant="outlined" onClick={onLanguageChange}>
            {translate(language, "language")}
          </Button>
        </Stack>
        <Box sx={{ width: "100%", maxWidth: 560, m: "auto", py: { xs: 5, md: 3 } }}>{children}</Box>
      </Box>
    </Box>
  );
}
