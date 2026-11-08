import type { ReactNode } from "react";
import { Box } from "@mui/material";
import { findGroup, visibleTabs, type GroupKey } from "./nav";
import { pick } from "./copy";
import { GroupTabs, NoAccess, PageHeader, useGroupTab, useKit } from "./kit";
import { SearchTab, PrefetchTab } from "./PackagesPanel";
import { SourcesTab } from "./UpstreamsPanel";
import { ConnectTab } from "./RegistriesPanel";

/**
 * «بسته‌ها» (docs/33 §1.1 group 2): search & manage · download ahead · package sources · connect your projects.
 * The shell mounts this page for `#/packages/<tab>`; the tabs come from nav.ts.
 */

export type GroupPageProps = {
  permissions: readonly string[];
  /** Current tab from the shell; falls back to the hash. */
  tab?: string;
  user?: { permissions: string[] };
  language?: string;
  onUnauthorized?: () => void;
};

/** Shared by PackagesPage and SecurityPage: the visible tab of a group, honouring permissions and mode. */
export function useVisibleTab(group: GroupKey, permissions: readonly string[], tab?: string) {
  const { mode } = useKit();
  const definition = findGroup(group);
  const tabs = definition ? visibleTabs(definition, permissions, mode) : [];
  const hashTab = useGroupTab(group, tabs[0]?.key ?? "");
  const wanted = tab || hashTab;
  const current = tabs.find((item) => item.key === wanted) ?? tabs[0] ?? null;
  return { definition, tabs, current };
}

export function TabPanel({ group, tab, children }: { group: string; tab: string; children: ReactNode }) {
  return (
    <Box role="tabpanel" id={`tabpanel-${group}-${tab}`} aria-labelledby={`tab-${group}-${tab}`} sx={{ pb: { xs: 10, sm: 2 } }}>
      {children}
    </Box>
  );
}

export default function PackagesPage(props: GroupPageProps) {
  const permissions = props.permissions ?? props.user?.permissions ?? [];
  const { language } = useKit();
  const { definition, current } = useVisibleTab("packages", permissions, props.tab);
  const title = definition ? pick(language, definition.label) : "";

  if (!current) {
    return (
      <>
        <PageHeader title={title} icon={definition?.icon} />
        <NoAccess needs={["cache:read", "upstream:read", "system:read"]} variant="card" />
      </>
    );
  }

  return (
    <>
      <PageHeader
        title={title}
        subtitle={pick(language, current.hint)}
        icon={definition?.icon}
        tabs={<GroupTabs group="packages" permissions={permissions} value={current.key} />}
      />
      <TabPanel group="packages" tab={current.key}>
        {current.key === "search" && <SearchTab permissions={permissions} />}
        {current.key === "prefetch" && <PrefetchTab permissions={permissions} />}
        {current.key === "sources" && <SourcesTab permissions={permissions} />}
        {current.key === "connect" && <ConnectTab />}
      </TabPanel>
    </>
  );
}
