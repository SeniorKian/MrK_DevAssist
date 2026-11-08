import { useEffect, useState } from "react";
import { Tab, Tabs } from "@mui/material";
import { findGroup, parseHash, routeHref, visibleTabs, type GroupKey } from "../nav";
import { useKit } from "./useKit";

/** Current tab of a group from the hash (`#/packages/sources` → "sources"); follows hash changes. */
export function useGroupTab(group: GroupKey, fallback: string) {
  const read = () => {
    const route = parseHash(window.location.hash);
    return route?.kind === "tab" && route.group === group ? route.tab : fallback;
  };
  const [tab, setTab] = useState(read);
  useEffect(() => {
    const onChange = () => setTab(read());
    window.addEventListener("hashchange", onChange);
    return () => window.removeEventListener("hashchange", onChange);
  }, [group, fallback]);
  return tab;
}

export type GroupTabsProps = {
  group: GroupKey;
  /** The signed-in user's permissions; tabs they can't use are hidden. */
  permissions: readonly string[];
  /** Controlled value; defaults to the hash. */
  value?: string;
  onChange?: (tab: string) => void;
};

/**
 * Tabs for one nav group, synced with `#/<group>/<tab>`. Filters by permission and Simple/Advanced,
 * scrollable on phones. Renders nothing when the group has a single visible tab.
 */
export function GroupTabs({ group, permissions, value, onChange }: GroupTabsProps) {
  const { language, mode } = useKit();
  const definition = findGroup(group);
  const tabs = definition ? visibleTabs(definition, permissions, mode) : [];
  const hashTab = useGroupTab(group, tabs[0]?.key ?? "");
  const current = value ?? hashTab;
  if (tabs.length < 2) return null;
  const selected = tabs.some((tab) => tab.key === current) ? current : tabs[0].key;
  return (
    <Tabs
      value={selected}
      onChange={(_event, next: string) => {
        if (onChange) onChange(next);
        else window.location.hash = routeHref(group, next);
      }}
      variant="scrollable"
      scrollButtons="auto"
      allowScrollButtonsMobile
      aria-label={definition?.label[language]}
      sx={{ minHeight: 44, borderBottom: 1, borderColor: "divider", "& .MuiTab-root": { minHeight: 44, fontWeight: 650 } }}
    >
      {tabs.map((tab) => (
        <Tab key={tab.key} value={tab.key} label={tab.label[language]} id={`tab-${group}-${tab.key}`} aria-controls={`tabpanel-${group}-${tab.key}`} />
      ))}
    </Tabs>
  );
}
