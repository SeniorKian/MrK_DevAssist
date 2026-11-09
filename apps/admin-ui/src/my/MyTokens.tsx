/**
 * «فضای من › کلیدهای برنامه» (docs/43 §3): keys for scripts, limited to this workspace, with scopes
 * that are a subset of my role here (a viewer only gets «دیدن» scopes, never admin permissions),
 * an end date and optional IP allow-list. The key is shown once.
 */
import { useCallback, useEffect, useState } from "react";
import { Box, Button, Checkbox, FormControlLabel, FormGroup, Stack, TextField, ToggleButton, ToggleButtonGroup, Typography } from "@mui/material";
import KeyRoundedIcon from "@mui/icons-material/KeyRounded";
import BlockRoundedIcon from "@mui/icons-material/BlockRounded";
import { MY, MY_SCOPES, MY_TOKENS, pick, say, scopeLabel } from "../copy";
import { ActionWizard, EmptyState, ListInput, Notice, OneTimeSecret, RelativeTime, ResponsiveList, SectionCard, StatusPill, useConfirmAction, useKit, useUndoSnackbar, type ListColumn } from "../kit";
import { isCidr, isIPv4, isIPv6 } from "../dns";
import { Loading, useList } from "../dnsUi";
import { formatNumber } from "../format";
import { createToken, fetchTokens, numericLimit, revokeToken, type MyToken } from "./myApi";
import { useMySpace } from "./MySpaceContext";
import { MyError, myErrorSentence } from "./MyKit";

type Expiry = "30" | "90" | "365" | "never";

function expirySeconds(choice: Expiry): number | null {
  return choice === "never" ? null : Number(choice) * 86_400;
}

function isPast(value: number | string | null): boolean {
  if (value === null || value === undefined || value === "") return false;
  const time = typeof value === "number" ? (value < 1e12 ? value * 1000 : value) : Date.parse(value);
  return Number.isFinite(time) && time < Date.now();
}

function CreateWizard({ onClose, onCreated }: { onClose: () => void; onCreated: () => void }) {
  const { language } = useKit();
  const space = useMySpace();
  const [name, setName] = useState("");
  const [scopes, setScopes] = useState<string[]>([]);
  const [expiry, setExpiry] = useState<Expiry>("90");
  const [ips, setIps] = useState<string[]>([]);
  const [secret, setSecret] = useState<string | null>(null);
  const viewer = space.workspace?.role === "viewer";
  const areaOn = (area: "dns" | "s3" | "packages") => (area === "packages" ? space.has("npm") || space.has("pypi") : space.has(area));
  const offered = MY_SCOPES.filter((scope) => areaOn(scope.area) && (!scope.write || !viewer));

  const finish = async () => {
    if (!space.workspace) return;
    const seconds = expirySeconds(expiry);
    const token = await createToken({ name: name.trim(), scopes, ...(seconds ? { expires_in_seconds: seconds } : {}), ...(ips.length ? { ip_allow: ips } : {}) });
    setSecret(token);
    onCreated();
  };

  return (
    <ActionWizard
      open
      title={pick(language, MY_TOKENS.createTitle)}
      finishLabel={pick(language, MY_TOKENS.create)}
      onClose={onClose}
      onFinish={finish}
      done={secret !== null ? (
        <OneTimeSecret open title={pick(language, MY_TOKENS.secretTitle)} body={pick(language, MY_TOKENS.secretBody)} items={[{ label: pick(language, MY_TOKENS.secret), value: secret }]} onClose={onClose} />
      ) : undefined}
      steps={[
        {
          key: "name",
          title: pick(language, MY_TOKENS.stepName),
          hint: pick(language, MY_TOKENS.stepNameHint),
          validate: () => (name.trim() ? null : pick(language, MY_TOKENS.nameRequired)),
          render: () => (
            <TextField autoFocus fullWidth label={pick(language, MY.name)} placeholder={pick(language, MY_TOKENS.namePlaceholder)} value={name} onChange={(event) => setName(event.target.value)} />
          )
        },
        {
          key: "scopes",
          title: pick(language, MY_TOKENS.stepScopes),
          hint: pick(language, MY_TOKENS.stepScopesHint),
          validate: () => (scopes.length ? null : pick(language, MY_TOKENS.scopesRequired)),
          render: () => (
            <Stack spacing={1.5}>
              {viewer && <Notice>{pick(language, MY_TOKENS.viewerOnly)}</Notice>}
              <FormGroup>
                {offered.map((scope) => (
                  <FormControlLabel
                    key={scope.key}
                    control={
                      <Checkbox
                        checked={scopes.includes(scope.key)}
                        onChange={(event) =>
                          setScopes((list) => {
                            if (!event.target.checked) {
                              // Without reading, writing makes no sense either.
                              const drop = new Set([scope.key, ...(scope.write ? [] : [scope.key.replace(":read", ":write")])]);
                              return list.filter((item) => !drop.has(item));
                            }
                            // Writing needs reading too.
                            const next = new Set([...list, scope.key]);
                            if (scope.write) next.add(scope.key.replace(":write", ":read"));
                            return [...next];
                          })
                        }
                      />
                    }
                    label={pick(language, scope.label)}
                    sx={{ minHeight: 44 }}
                  />
                ))}
              </FormGroup>
            </Stack>
          )
        },
        {
          key: "limits",
          title: pick(language, MY_TOKENS.stepLimits),
          optional: true,
          render: () => (
            <Stack spacing={2.5}>
              <Box>
                <Typography variant="body2" sx={{ mb: 0.75 }} id="mrk-token-expiry">{pick(language, MY_TOKENS.expiry)}</Typography>
                <ToggleButtonGroup exclusive size="small" value={expiry} onChange={(_event, value: Expiry | null) => value && setExpiry(value)} aria-labelledby="mrk-token-expiry" sx={{ flexWrap: "wrap" }}>
                  {(["30", "90", "365", "never"] as Expiry[]).map((value) => (
                    <ToggleButton key={value} value={value} sx={{ minHeight: 44, px: 2 }}>{pick(language, MY_TOKENS[`e_${value}` as const])}</ToggleButton>
                  ))}
                </ToggleButtonGroup>
              </Box>
              <ListInput
                label={pick(language, MY_TOKENS.ipAllow)}
                helperText={pick(language, MY_TOKENS.ipAllowHint)}
                value={ips}
                onChange={setIps}
                validate={(item) => (isIPv4(item) || isIPv6(item) || isCidr(item) ? null : pick(language, MY_TOKENS.ipBad))}
              />
            </Stack>
          )
        }
      ]}
    />
  );
}

export default function MyTokens({ createRequest }: { createRequest: number }) {
  const { language } = useKit();
  const space = useMySpace();
  const loader = useCallback((signal: AbortSignal) => fetchTokens(signal), []);
  const { items, error, loading, reload } = useList<MyToken>(loader);
  const [creating, setCreating] = useState(false);
  const { ask, dialog } = useConfirmAction();
  const { notify, snackbar } = useUndoSnackbar();
  const limit = numericLimit(space.workspace, "api_tokens");
  // A viewer may still make a key for themselves (its scopes are read-only); a paused space or "view as" can't.
  const allowed = space.readOnlyReason === null || space.readOnlyReason === "viewer";

  useEffect(() => {
    if (createRequest > 0 && allowed) setCreating(true);
  }, [createRequest, allowed]);

  const revoke = async (token: MyToken) => {
    const ok = await ask({ title: say(language, MY_TOKENS.revokeTitle, { name: token.name }), body: pick(language, MY_TOKENS.revokeBody), severity: "destructive", undoable: false, confirmLabel: pick(language, MY_TOKENS.revokeYes) });
    if (!ok) return;
    try {
      await revokeToken(token.id);
      notify({ message: say(language, MY_TOKENS.revoked, { name: token.name }) });
      reload();
      void space.reload();
    } catch (caught) {
      notify({ message: myErrorSentence(language, caught), tone: "error" });
    }
  };

  const scopesText = (token: MyToken) => token.scopes.map((scope) => scopeLabel(language, scope)).join("، ");
  const columns: ListColumn<MyToken>[] = [
    { key: "name", header: pick(language, MY_TOKENS.colName), render: (token) => <Typography fontWeight={650} component="span">{token.name}</Typography> },
    { key: "scopes", header: pick(language, MY_TOKENS.colScopes), render: scopesText },
    { key: "expires", header: pick(language, MY_TOKENS.colExpires), render: (token) => (token.expires_at === null ? pick(language, MY_TOKENS.noEnd) : isPast(token.expires_at) ? <StatusPill tone="off" label={pick(language, MY_TOKENS.expired)} /> : <RelativeTime value={token.expires_at} />) },
    { key: "used", header: pick(language, MY_TOKENS.colUsed), render: (token) => (token.last_used_at === null ? pick(language, MY_TOKENS.neverUsed) : <RelativeTime value={token.last_used_at} />) }
  ];

  return (
    <SectionCard
      title={pick(language, MY_TOKENS.title)}
      hint={pick(language, MY_TOKENS.hint)}
      status={limit !== null ? <Typography variant="caption" color="text.secondary">{say(language, MY.usageOf, { used: formatNumber((items ?? []).length, language), limit: formatNumber(limit, language) })}</Typography> : undefined}
      flush
    >
      {error ? <Box sx={{ p: 2 }}><MyError error={error} onRetry={reload} /></Box> : null}
      {loading && !items ? <Loading /> : null}
      {items && (
        <ResponsiveList
          label={pick(language, MY_TOKENS.listLabel)}
          rows={items}
          rowKey={(token) => token.id}
          columns={columns}
          card={{ title: (token) => token.name, meta: scopesText, status: (token) => (isPast(token.expires_at) ? <StatusPill tone="off" label={pick(language, MY_TOKENS.expired)} /> : null) }}
          actions={allowed ? [{ key: "revoke", label: pick(language, MY_TOKENS.revoke), icon: BlockRoundedIcon, danger: true, onClick: (token) => void revoke(token) }] : undefined}
          empty={
            <EmptyState
              icon={KeyRoundedIcon}
              title={pick(language, MY_TOKENS.emptyTitle)}
              body={pick(language, MY_TOKENS.emptyBody)}
              action={allowed ? <Button variant="contained" startIcon={<KeyRoundedIcon />} onClick={() => setCreating(true)}>{pick(language, MY_TOKENS.create)}</Button> : undefined}
            />
          }
        />
      )}
      {creating && <CreateWizard onClose={() => setCreating(false)} onCreated={() => { reload(); void space.reload(); }} />}
      {dialog}
      {snackbar}
    </SectionCard>
  );
}
