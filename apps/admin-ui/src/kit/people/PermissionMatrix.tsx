import { useMemo, useState } from "react";
import {
  Accordion, AccordionDetails, AccordionSummary, Box, Checkbox, Chip, Stack, ToggleButton, ToggleButtonGroup, Typography
} from "@mui/material";
import ExpandMoreRoundedIcon from "@mui/icons-material/ExpandMoreRounded";
import { DANGER_WORDS, type Danger } from "../../copy/roles";
import { pick, say } from "../../copy/text";
import { Ltr } from "../Formatted";
import { useKit } from "../useKit";
import { closeOver, dependentsOf, indexCatalog, permissionLabel, type PermissionCatalog, type PermissionGroupSpec, type PermissionSpec } from "./types";

const COPY = {
  count: { fa: "{on} از {total}", en: "{on} of {total}" },
  none: { fa: "هیچ", en: "None" },
  view: { fa: "فقط دیدن", en: "View" },
  full: { fa: "همه", en: "Full" },
  groupLevel: { fa: "سطح دسترسی بخش «{group}»", en: "Access level for “{group}”" },
  needs: { fa: "به این هم نیاز دارد: {list}", en: "Also needs: {list}" },
  notYours: { fa: "شما خودتان این اجازه را ندارید، پس نمی‌توانید آن را بدهید.", en: "You don't hold this, so you can't grant it." },
  addedDeps: { fa: "«{list}» هم روشن شد، چون «{name}» بدون آن کار نمی‌کند.", en: "“{list}” was turned on too, because “{name}” needs it." },
  removedDeps: { fa: "«{list}» هم خاموش شد، چون به «{name}» نیاز دارد.", en: "“{list}” was turned off too, because it needs “{name}”." },
  everything: { fa: "این نقش همه اجازه‌ها را دارد.", en: "This role holds every permission." },
  listJoin: { fa: "»، «", en: "”, “" }
};

const DANGER_TONE: Record<Danger, "default" | "info" | "warning" | "error"> = {
  none: "default",
  low: "info",
  medium: "warning",
  high: "error",
  critical: "error"
};

export type PermissionMatrixProps = {
  catalog: PermissionCatalog;
  /** Ticked permission ids. `*` ticks everything (read-only display of the owner role). */
  value: readonly string[];
  /** Omit (or pass `readOnly`) for a read-only view. Dependencies are added/removed automatically. */
  onChange?: (next: string[]) => void;
  readOnly?: boolean;
  /** Permissions the editor may grant (their own). Others are shown but can't be ticked. Omit = all. */
  grantable?: readonly string[];
  /** id → a plain problem sentence (from a server error), highlighted on the row. */
  problems?: Record<string, string>;
  /** Groups open at first render (default: groups with something ticked). */
  expandAll?: boolean;
};

function isView(id: string) {
  return /:read$/.test(id);
}

/**
 * Permissions grouped by the 7 nav sections (docs/33 §5.3). Each group has a «هیچ / فقط دیدن / همه»
 * switch; each row has the plain name, a danger badge, what it needs, and (Advanced) the technical key.
 * Ticking a permission adds what it needs; unticking removes what depends on it, with a plain note.
 */
export function PermissionMatrix({ catalog, value, onChange, readOnly, grantable, problems, expandAll }: PermissionMatrixProps) {
  const { language, isAdvanced } = useKit();
  const index = useMemo(() => indexCatalog(catalog), [catalog]);
  const everything = value.includes("*");
  const selected = useMemo(() => new Set(value), [value]);
  const editable = Boolean(onChange) && !readOnly;
  const [note, setNote] = useState<string | null>(null);
  const canGrant = (id: string) => !grantable || grantable.includes("*") || grantable.includes(id);
  const name = (id: string) => permissionLabel(language, id, index);
  const joinNames = (ids: string[]) => ids.map(name).join(COPY.listJoin[language]);

  const groups = useMemo(
    () => catalog.groups.map((group) => ({ ...group, permissions: group.permissions.filter((item) => item.assignable !== false) })).filter((group) => group.permissions.length > 0),
    [catalog]
  );

  const apply = (next: Set<string>, message: string | null) => {
    setNote(message);
    onChange?.([...next].filter((id) => id !== "*").sort());
  };

  const toggle = (spec: PermissionSpec, on: boolean) => {
    if (!editable) return;
    const next = new Set(selected);
    if (on) {
      const closed = closeOver([spec.id], index);
      const added = [...closed].filter((id) => id !== spec.id && !next.has(id));
      closed.forEach((id) => next.add(id));
      apply(next, added.length ? say(language, COPY.addedDeps, { list: joinNames(added), name: name(spec.id) }) : null);
    } else {
      next.delete(spec.id);
      const removed = dependentsOf(spec.id, next, index);
      removed.forEach((id) => next.delete(id));
      apply(next, removed.length ? say(language, COPY.removedDeps, { list: joinNames(removed), name: name(spec.id) }) : null);
    }
  };

  const level = (group: PermissionGroupSpec): "none" | "view" | "full" | null => {
    const ids = group.permissions.map((item) => item.id);
    const on = ids.filter((id) => everything || selected.has(id));
    if (on.length === 0) return "none";
    if (on.length === ids.length) return "full";
    const views = ids.filter(isView);
    if (views.length > 0 && on.length === views.length && views.every((id) => on.includes(id))) return "view";
    return null;
  };

  const setLevel = (group: PermissionGroupSpec, target: "none" | "view" | "full") => {
    if (!editable) return;
    const next = new Set(selected);
    const ids = group.permissions.map((item) => item.id);
    ids.forEach((id) => next.delete(id));
    const wanted = target === "none" ? [] : target === "view" ? ids.filter(isView) : ids;
    const closed = closeOver(wanted.filter(canGrant), index);
    closed.forEach((id) => next.add(id));
    // Removing a group may break permissions elsewhere that need it.
    const broken = [...next].filter((id) => [...closeOver([id], index)].some((need) => !next.has(need)));
    broken.forEach((id) => next.delete(id));
    apply(next, broken.length ? say(language, COPY.removedDeps, { list: joinNames(broken), name: pick(language, { fa: group.name_fa, en: group.name_en }) }) : null);
  };

  return (
    <Stack spacing={1}>
      {everything && <Typography variant="body2" sx={{ fontWeight: 700 }}>{COPY.everything[language]}</Typography>}
      {note && (
        <Typography role="status" variant="body2" color="info.main" sx={{ lineHeight: 1.8 }}>{note}</Typography>
      )}
      {groups.map((group) => {
        const groupName = language === "fa" ? group.name_fa : group.name_en;
        const onCount = group.permissions.filter((item) => everything || selected.has(item.id)).length;
        const current = level(group);
        const open = expandAll || onCount > 0 || group.permissions.some((item) => problems?.[item.id]);
        return (
          <Accordion key={group.id} defaultExpanded={open} disableGutters variant="outlined" sx={{ borderRadius: 1.25, "&::before": { display: "none" } }}>
            <AccordionSummary expandIcon={<ExpandMoreRoundedIcon />} sx={{ px: 2, "& .MuiAccordionSummary-content": { alignItems: "center", gap: 1, flexWrap: "wrap" } }}>
              <Typography component="h4" sx={{ fontWeight: 760 }}>{groupName}</Typography>
              <Chip size="small" variant="outlined" label={say(language, COPY.count, { on: onCount, total: group.permissions.length })} />
            </AccordionSummary>
            <AccordionDetails sx={{ px: 2, pt: 0 }}>
              {editable && (
                <ToggleButtonGroup
                  exclusive
                  size="small"
                  value={current}
                  onChange={(_event, next: "none" | "view" | "full" | null) => next && setLevel(group, next)}
                  aria-label={say(language, COPY.groupLevel, { group: groupName })}
                  sx={{ mb: 1.5, "& .MuiToggleButton-root": { minHeight: 36, px: 1.75 } }}
                >
                  <ToggleButton value="none">{COPY.none[language]}</ToggleButton>
                  {group.permissions.some((item) => isView(item.id)) && <ToggleButton value="view">{COPY.view[language]}</ToggleButton>}
                  <ToggleButton value="full">{COPY.full[language]}</ToggleButton>
                </ToggleButtonGroup>
              )}
              <Stack spacing={0.5}>
                {group.permissions.map((spec) => {
                  const checked = everything || selected.has(spec.id);
                  const grantableHere = canGrant(spec.id);
                  const problem = problems?.[spec.id];
                  const description = language === "fa" ? spec.description_fa : spec.description_en;
                  const needs = spec.requires.filter((id) => !checked || !selected.has(id));
                  const rowId = `perm-${spec.id.replace(/[^a-z0-9]/gi, "-")}`;
                  return (
                    <Box
                      key={spec.id}
                      sx={{
                        display: "flex",
                        gap: 1,
                        alignItems: "flex-start",
                        p: 0.75,
                        borderRadius: 1,
                        border: 1,
                        borderColor: problem ? "error.main" : "transparent"
                      }}
                    >
                      <Checkbox
                        checked={checked}
                        disabled={!editable || (!grantableHere && !checked)}
                        onChange={(_event, on) => toggle(spec, on)}
                        slotProps={{ input: { "aria-labelledby": rowId } }}
                        sx={{ p: 1, mt: -0.5 }}
                      />
                      <Box sx={{ minWidth: 0, flex: 1 }}>
                        <Stack direction="row" spacing={0.75} alignItems="center" flexWrap="wrap" useFlexGap>
                          <Typography id={rowId} variant="body2" sx={{ fontWeight: 650, lineHeight: 1.8 }}>
                            {language === "fa" ? spec.name_fa : spec.name_en}
                          </Typography>
                          {spec.danger !== "none" && spec.danger !== "low" && (
                            <Chip size="small" color={DANGER_TONE[spec.danger]} variant="outlined" label={pick(language, DANGER_WORDS[spec.danger])} sx={{ height: 22 }} />
                          )}
                        </Stack>
                        {description && <Typography variant="caption" color="text.secondary" display="block" sx={{ lineHeight: 1.8 }}>{description}</Typography>}
                        {editable && needs.length > 0 && (
                          <Typography variant="caption" color="text.secondary" display="block">
                            {say(language, COPY.needs, { list: needs.map((id) => `«${name(id)}»`).join(language === "fa" ? "، " : ", ") })}
                          </Typography>
                        )}
                        {editable && !grantableHere && <Typography variant="caption" color="text.secondary" display="block">{COPY.notYours[language]}</Typography>}
                        {problem && <Typography variant="caption" color="error.main" display="block" sx={{ fontWeight: 650 }}>{problem}</Typography>}
                        {isAdvanced && (
                          <Typography variant="caption" color="text.disabled" display="block">
                            <Ltr mono>{spec.id}</Ltr>
                          </Typography>
                        )}
                      </Box>
                    </Box>
                  );
                })}
              </Stack>
            </AccordionDetails>
          </Accordion>
        );
      })}
    </Stack>
  );
}
