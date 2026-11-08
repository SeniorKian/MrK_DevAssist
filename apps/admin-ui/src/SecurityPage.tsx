import { lazy, Suspense } from "react";
import { LinearProgress } from "@mui/material";
import { pick } from "./copy";
import { GroupTabs, NoAccess, PageHeader, useKit } from "./kit";
import { InternetTab, DnsTab } from "./NetworkPanel";
import { TabPanel, useVisibleTab, type GroupPageProps } from "./PackagesPage";

/**
 * «امنیت و اینترنت» (docs/33 §1.1 group 5): firewall · security check · internet & proxy ·
 * DNS & internal network (Advanced, includes the private-sources policy).
 */

const FirewallPanel = lazy(() => import("./FirewallPanel"));
const VulnPanel = lazy(() => import("./VulnPanel"));

export default function SecurityPage(props: GroupPageProps) {
  const permissions = props.permissions ?? props.user?.permissions ?? [];
  const { language } = useKit();
  const { definition, current } = useVisibleTab("security", permissions, props.tab);
  const title = definition ? pick(language, definition.label) : "";

  if (!current) {
    return (
      <>
        <PageHeader title={title} icon={definition?.icon} />
        <NoAccess needs={["firewall:read", "vuln:read", "upstream:read"]} variant="card" />
      </>
    );
  }

  return (
    <>
      <PageHeader
        title={title}
        subtitle={pick(language, current.hint)}
        icon={definition?.icon}
        tabs={<GroupTabs group="security" permissions={permissions} value={current.key} />}
      />
      <TabPanel group="security" tab={current.key}>
        <Suspense fallback={<LinearProgress />}>
          {current.key === "firewall" && <FirewallPanel permissions={permissions} />}
          {current.key === "vuln" && <VulnPanel permissions={permissions} />}
          {current.key === "internet" && <InternetTab permissions={permissions} />}
          {current.key === "dns" && <DnsTab permissions={permissions} />}
        </Suspense>
      </TabPanel>
    </>
  );
}
