/**
 * «کد و ایمیج‌ها» / Code & images. Tabs come from nav.ts:
 * git (Gitea: repositories, GitHub/GitLab mirrors, users, organizations) ·
 * registry (Zot: private Docker images + a Docker Hub / ghcr / quay mirror with fallbacks).
 */
import { lazy, useMemo } from "react";
import CodeRoundedIcon from "@mui/icons-material/CodeRounded";
import { PageHeader, GroupTabs, useKit } from "./kit";
import { pick } from "./copy";
import { findGroup, visibleTabs } from "./nav";
import { TabBody, useHashTab, type GroupPageProps } from "./ServerPage";

const GitPanel = lazy(() => import("./GitPanel").then((module) => ({ default: module.GitPanel })));
const RegistryPanel = lazy(() => import("./RegistryPanel").then((module) => ({ default: module.RegistryPanel })));

const COPY = {
  title: { fa: "کد و ایمیج‌ها", en: "Code & images" },
  subtitle: {
    fa: "کد پروژه‌ها و ایمیج‌های Docker روی سرور خودتان؛ حتی وقتی GitHub یا Docker Hub کند یا بسته است.",
    en: "Your projects' code and Docker images on your own server, even when GitHub or Docker Hub is slow or blocked."
  }
};

/** Other names for the tabs (older links, search) → nav.ts tab keys. */
const TAB_ALIASES: Record<string, string> = {
  gitea: "git",
  repos: "git",
  mirrors: "git",
  docker: "registry",
  images: "registry",
  zot: "registry"
};

export default function CodePage({ user, permissions: permissionsProp, onUnauthorized }: GroupPageProps) {
  const { language, mode } = useKit();
  const permissions = useMemo(() => user?.permissions ?? permissionsProp ?? [], [user, permissionsProp]);
  const group = findGroup("code");
  const tabs = group ? visibleTabs(group, permissions, mode).map((item) => item.key) : [];
  const tab = useHashTab("code", TAB_ALIASES, tabs, tabs[0] ?? "git");
  const panelProps = { language, permissions, onUnauthorized: onUnauthorized ?? (() => undefined) };

  return (
    <>
      <PageHeader
        title={pick(language, COPY.title)}
        subtitle={pick(language, COPY.subtitle)}
        icon={CodeRoundedIcon}
        tabs={<GroupTabs group="code" permissions={permissions} value={tab} />}
      />
      <TabBody>
        {tab === "git" && <GitPanel {...panelProps} />}
        {tab === "registry" && <RegistryPanel {...panelProps} />}
      </TabBody>
    </>
  );
}
