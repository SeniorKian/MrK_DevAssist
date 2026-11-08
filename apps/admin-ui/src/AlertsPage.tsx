import { useState } from "react";
import { Box, Button, Stack } from "@mui/material";
import NotificationsRoundedIcon from "@mui/icons-material/NotificationsRounded";
import AddRoundedIcon from "@mui/icons-material/AddRounded";
import { hasPermission } from "./api";
import type { AuthUser } from "./App";
import { GroupTabs, NoAccess, PageHeader, useGroupTab, useKit } from "./kit";
import { findGroup, visibleTabs } from "./nav";
import { pick, type Bi } from "./copy";
import { ChannelsPanel } from "./ChannelsPanel";
import { DeliveriesPanel } from "./DeliveriesPanel";
import { RulesPanel } from "./RulesPanel";
import { JobsPanel } from "./JobsPanel";
import { HistoryPanel, SupportPanel } from "./HistoryPanel";

const T = {
  title: { fa: "اعلان‌ها و تاریخچه", en: "Alerts & history" },
  addChannel: { fa: "افزودن کانال", en: "Add a channel" },
  addRule: { fa: "قاعده تازه", en: "New rule" }
} satisfies Record<string, Bi>;

/** Same shape the shell passes to every group page (AppShell ShellPageProps); extra props are ignored. */
export type AlertsPageProps = { user: AuthUser; tab?: string };

/** Alerts & history (docs/33 §1.1 group 7): channels · rules · jobs · activity history · support (Advanced). */
export default function AlertsPage({ user, tab: tabProp }: AlertsPageProps) {
  const { language, mode } = useKit();
  const permissions = user.permissions;
  const group = findGroup("alerts");
  const tabs = group ? visibleTabs(group, permissions, mode) : [];
  const hashTab = useGroupTab("alerts", tabs[0]?.key ?? "channels");
  const wanted = tabProp || hashTab;
  const current = tabs.find((item) => item.key === wanted) ?? tabs[0] ?? null;
  const [channelRequest, setChannelRequest] = useState(0);
  const [ruleRequest, setRuleRequest] = useState(0);
  const [deliveriesKey, setDeliveriesKey] = useState(0);
  const title = group ? pick(language, group.label) : pick(language, T.title);

  if (!current) {
    return (
      <>
        <PageHeader title={title} icon={NotificationsRoundedIcon} />
        <NoAccess needs={["notification:read", "task:read", "audit:read"]} variant="card" />
      </>
    );
  }
  const tab = current.key;
  const canWrite = hasPermission(permissions, "notification:write");

  let primary = null;
  if (tab === "channels" && canWrite) {
    primary = <Button variant="contained" startIcon={<AddRoundedIcon />} onClick={() => setChannelRequest((value) => value + 1)} sx={{ minHeight: 44 }}>{pick(language, T.addChannel)}</Button>;
  } else if (tab === "rules" && canWrite) {
    primary = <Button variant="contained" startIcon={<AddRoundedIcon />} onClick={() => setRuleRequest((value) => value + 1)} sx={{ minHeight: 44 }}>{pick(language, T.addRule)}</Button>;
  }

  return (
    <>
      <PageHeader
        title={title}
        subtitle={pick(language, current.hint)}
        icon={NotificationsRoundedIcon}
        primaryAction={primary ?? undefined}
        tabs={<GroupTabs group="alerts" permissions={permissions} value={tab} />}
      />
      <Box role="tabpanel" id={`tabpanel-alerts-${tab}`} aria-labelledby={`tab-alerts-${tab}`} sx={{ pb: { xs: 10, sm: 2 } }}>
        {tab === "channels" && (
          <Stack spacing={2.5}>
            <ChannelsPanel user={user} addRequest={channelRequest} onChanged={() => setDeliveriesKey((value) => value + 1)} />
            <DeliveriesPanel refreshKey={deliveriesKey} />
          </Stack>
        )}
        {tab === "rules" && <RulesPanel user={user} addRequest={ruleRequest} />}
        {tab === "jobs" && <JobsPanel permissions={permissions} />}
        {tab === "history" && <HistoryPanel permissions={permissions} />}
        {tab === "support" && <SupportPanel permissions={permissions} />}
      </Box>
    </>
  );
}
