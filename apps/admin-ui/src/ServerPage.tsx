/**
 * «سرور و برنامه‌ها» / Server & apps (docs/33 §1.1 group 3). Tabs come from nav.ts:
 * overview (host + containers + Agent pairing) · resources (usage charts) · apps (Dokploy) ·
 * updates (image updates) · databases (Gate 19 dbadmin) · docker (Advanced only: pull / prune).
 * Each tab is a separate panel, loaded on demand.
 */
import { lazy, Suspense, useEffect, useMemo, useState, type ReactNode } from "react";
import { Box, CircularProgress } from "@mui/material";
import DnsRoundedIcon from "@mui/icons-material/DnsRounded";
import type { AuthUser } from "./App";
import type { Language } from "./i18n";
import { PageHeader, GroupTabs, useKit } from "./kit";
import { pick } from "./copy";
import { findGroup, parseHash, visibleTabs } from "./nav";

const ServerPanel = lazy(() => import("./ServerPanel").then((module) => ({ default: module.ServerPanel })));
const MonitoringPanel = lazy(() => import("./MonitoringPanel").then((module) => ({ default: module.MonitoringPanel })));
const DokployPanel = lazy(() => import("./DokployPanel").then((module) => ({ default: module.DokployPanel })));
const UpdatesPanel = lazy(() => import("./UpdatesPanel").then((module) => ({ default: module.UpdatesPanel })));
const DbAdminPanel = lazy(() => import("./DbAdminPanel").then((module) => ({ default: module.DbAdminPanel })));

export type GroupPageProps = {
  user?: Pick<AuthUser, "permissions"> | null;
  permissions?: string[];
  language?: Language;
  onUnauthorized?: () => void;
};

const COPY = {
  title: { fa: "سرور و برنامه‌ها", en: "Server & apps" },
  subtitle: {
    fa: "وضعیت سرور، مصرف منابع و برنامه‌هایی که روی آن اجرا می‌شوند.",
    en: "Your server's health, its resource use and the apps running on it."
  }
};

/** Older links and Home routes use a few other tab names; map them to nav.ts keys. */
const TAB_ALIASES: Record<string, string> = { monitoring: "resources", dokploy: "apps", dbadmin: "databases", db: "databases" };

/** Current tab of a group from the hash, accepting `?query` suffixes and aliases. */
export function useHashTab(group: "server" | "files" | "services", aliases: Record<string, string>, valid: string[], fallback: string) {
  const read = () => {
    const raw = window.location.hash.replace(/^#\/?/, "").split("?")[0];
    const [first, second] = raw.split("/");
    if (first === group && second) {
      const key = aliases[second] ?? second;
      if (valid.includes(key)) return key;
    }
    const route = parseHash(window.location.hash.split("?")[0]);
    if (route?.kind === "tab" && route.group === group && valid.includes(route.tab)) return route.tab;
    return fallback;
  };
  const [tab, setTab] = useState(read);
  useEffect(() => {
    const onChange = () => setTab(read());
    window.addEventListener("hashchange", onChange);
    return () => window.removeEventListener("hashchange", onChange);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [group, valid.join(","), fallback]);
  return tab;
}

export function TabFallback() {
  return (
    <Box sx={{ display: "grid", placeItems: "center", py: 6 }}>
      <CircularProgress size={28} aria-hidden />
    </Box>
  );
}

export function TabBody({ children }: { children: ReactNode }) {
  return <Suspense fallback={<TabFallback />}>{children}</Suspense>;
}

export default function ServerPage({ user, permissions: permissionsProp, onUnauthorized }: GroupPageProps) {
  const { language, mode } = useKit();
  const permissions = useMemo(() => user?.permissions ?? permissionsProp ?? [], [user, permissionsProp]);
  const group = findGroup("server");
  const tabs = group ? visibleTabs(group, permissions, mode).map((item) => item.key) : [];
  const tab = useHashTab("server", TAB_ALIASES, tabs, tabs[0] ?? "overview");
  const unauthorized = onUnauthorized ?? (() => undefined);
  const panelProps = { language, permissions, onUnauthorized: unauthorized };

  return (
    <>
      <PageHeader
        title={pick(language, COPY.title)}
        subtitle={pick(language, COPY.subtitle)}
        icon={DnsRoundedIcon}
        tabs={<GroupTabs group="server" permissions={permissions} value={tab} />}
      />
      <TabBody>
        {tab === "overview" && <ServerPanel {...panelProps} section="overview" />}
        {tab === "resources" && <MonitoringPanel {...panelProps} />}
        {tab === "apps" && <DokployPanel {...panelProps} />}
        {tab === "updates" && <UpdatesPanel {...panelProps} />}
        {tab === "databases" && <DbAdminPanel {...panelProps} />}
        {tab === "docker" && <ServerPanel {...panelProps} section="docker" />}
      </TabBody>
    </>
  );
}
