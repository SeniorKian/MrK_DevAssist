/** «فضای من › خانه»: greeting, plan, usage bars against the plan's limits, near-limit warnings, quick actions. */
import { Stack, Typography } from "@mui/material";
import TravelExploreRoundedIcon from "@mui/icons-material/TravelExploreRounded";
import CreateNewFolderRoundedIcon from "@mui/icons-material/CreateNewFolderRounded";
import Inventory2RoundedIcon from "@mui/icons-material/Inventory2Rounded";
import PersonAddAlt1RoundedIcon from "@mui/icons-material/PersonAddAlt1Rounded";
import KeyRoundedIcon from "@mui/icons-material/KeyRounded";
import { formatQuota, MY, pick, quotaLabel, QUOTA_WORDS, say, type QuotaKey } from "../copy";
import { AttentionList, QuickActionGrid, QuickActionTile, SectionCard, Verdict, useKit, type AttentionItem } from "../kit";
import type { MyTabKey } from "../nav";
import { planName, usageRows } from "./myApi";
import { useMySpace } from "./MySpaceContext";
import { UsageBar } from "./MyKit";

export default function MyHome({ onGo }: { onGo: (tab: MyTabKey) => void }) {
  const { language } = useKit();
  const space = useMySpace();
  const workspace = space.workspace!;
  const features = workspace.features;
  const rows = usageRows(workspace, features, (key) => QUOTA_WORDS[key as QuotaKey]?.feature);
  const full = rows.filter((row) => row.level === "full");
  const near = rows.filter((row) => row.level === "near");
  const user = space.me?.user;
  const who = user?.display_name || user?.username;

  const attention: AttentionItem[] = [...full, ...near].map((row) => {
    const label = quotaLabel(language, row.key);
    const params = { label, used: formatQuota(language, row.key, row.used), limit: formatQuota(language, row.key, row.limit ?? 0) };
    const target: MyTabKey | null = row.key.startsWith("dns") ? "domains" : row.key.startsWith("s3") ? "files" : row.key.endsWith("_bytes") ? "packages" : row.key === "members" ? "team" : row.key === "api_tokens" ? "keys" : null;
    return {
      id: row.key,
      severity: row.level === "full" ? "critical" : "warning",
      title: say(language, row.level === "full" ? MY.fullTitle : MY.nearTitle, params),
      why: row.level === "full" ? pick(language, MY.fullWhy) : say(language, MY.nearWhy, params),
      action: target ? { label: pick(language, MY.open), onClick: () => onGo(target) } : undefined
    };
  });

  const can = space.canWrite;
  const quick = [
    space.has("dns") && can ? <QuickActionTile key="dns" icon={TravelExploreRoundedIcon} label={pick(language, MY.quickDomain)} onClick={() => onGo("domains")} /> : null,
    space.has("s3") && can ? <QuickActionTile key="s3" icon={CreateNewFolderRoundedIcon} label={pick(language, MY.quickBucket)} onClick={() => onGo("files")} /> : null,
    (space.has("npm") || space.has("pypi")) ? <QuickActionTile key="pkg" icon={Inventory2RoundedIcon} label={pick(language, MY.quickPackages)} onClick={() => onGo("packages")} /> : null,
    workspace.kind === "team" && space.canManage ? <QuickActionTile key="team" icon={PersonAddAlt1RoundedIcon} label={pick(language, MY.quickInvite)} onClick={() => onGo("team")} /> : null,
    space.has("api_tokens") && can ? <QuickActionTile key="key" icon={KeyRoundedIcon} label={pick(language, MY.quickKey)} onClick={() => onGo("keys")} /> : null
  ].filter(Boolean);

  return (
    <Stack spacing={2.5}>
      <Verdict
        greeting={who ? say(language, MY.hello, { name: who }) : pick(language, MY.helloPlain)}
        verdict={pick(language, full.length ? MY.homeFull : near.length ? MY.homeNear : MY.homeAllGood)}
        tone={full.length ? "error" : near.length ? "warn" : "ok"}
      />
      <AttentionList items={attention} />
      <SectionCard
        title={pick(language, MY.usageTitle)}
        hint={pick(language, MY.usageHint)}
        status={<Typography variant="body2" color="text.secondary">{say(language, MY.planIs, { plan: planName(language, workspace.plan) || pick(language, MY.noPlan) })}</Typography>}
      >
        {rows.length === 0 ? (
          <Typography variant="body2" color="text.secondary">{pick(language, MY.noUsage)}</Typography>
        ) : (
          <Stack spacing={2}>
            {rows.map((row) => <UsageBar key={row.key} row={row} />)}
          </Stack>
        )}
      </SectionCard>
      {quick.length > 0 && (
        <SectionCard title={pick(language, MY.quickTitle)}>
          <QuickActionGrid>{quick}</QuickActionGrid>
        </SectionCard>
      )}
    </Stack>
  );
}
