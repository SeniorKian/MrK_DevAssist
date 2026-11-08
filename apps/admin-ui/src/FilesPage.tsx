/**
 * «فایل‌ها و پشتیبان» / Files & backups (docs/33 §1.1 group 4). Tabs come from nav.ts:
 * space (S3 buckets, file manager, access keys) · app-backups (server backups) ·
 * panel-backup (the panel's own backup / restore) · health (free disk space, integrity check).
 */
import { lazy, useMemo } from "react";
import FolderRoundedIcon from "@mui/icons-material/FolderRounded";
import { PageHeader, GroupTabs, useKit } from "./kit";
import { pick } from "./copy";
import { findGroup, visibleTabs } from "./nav";
import { TabBody, useHashTab, type GroupPageProps } from "./ServerPage";

const S3Panel = lazy(() => import("./S3Panel").then((module) => ({ default: module.S3Panel })));
const ServerBackupsPanel = lazy(() => import("./ServerBackupsPanel").then((module) => ({ default: module.ServerBackupsPanel })));
const LifecyclePanel = lazy(() => import("./LifecyclePanel").then((module) => ({ default: module.LifecyclePanel })));

const COPY = {
  title: { fa: "فایل‌ها و پشتیبان", en: "Files & backups" },
  subtitle: {
    fa: "فایل‌هایتان را نگه دارید و از برنامه‌ها و خود پنل پشتیبان بگیرید.",
    en: "Keep your files, and back up your apps and the panel itself."
  }
};

/** Names used by Home routes and older links (docs/34 §1) → nav.ts tab keys. */
const TAB_ALIASES: Record<string, string> = {
  storage: "space",
  s3: "space",
  backups: "app-backups",
  "server-backups": "app-backups",
  lifecycle: "panel-backup",
  maintenance: "health"
};

export default function FilesPage({ user, permissions: permissionsProp, onUnauthorized }: GroupPageProps) {
  const { language, mode } = useKit();
  const permissions = useMemo(() => user?.permissions ?? permissionsProp ?? [], [user, permissionsProp]);
  const group = findGroup("files");
  const tabs = group ? visibleTabs(group, permissions, mode).map((item) => item.key) : [];
  const tab = useHashTab("files", TAB_ALIASES, tabs, tabs[0] ?? "space");
  const panelProps = { language, permissions, onUnauthorized: onUnauthorized ?? (() => undefined) };

  return (
    <>
      <PageHeader
        title={pick(language, COPY.title)}
        subtitle={pick(language, COPY.subtitle)}
        icon={FolderRoundedIcon}
        tabs={<GroupTabs group="files" permissions={permissions} value={tab} />}
      />
      <TabBody>
        {tab === "space" && <S3Panel {...panelProps} />}
        {tab === "app-backups" && <ServerBackupsPanel {...panelProps} />}
        {tab === "panel-backup" && <LifecyclePanel {...panelProps} section="backup" />}
        {tab === "health" && <LifecyclePanel {...panelProps} section="health" />}
      </TabBody>
    </>
  );
}
