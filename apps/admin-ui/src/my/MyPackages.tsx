/**
 * «فضای من › بسته‌ها» (docs/43 §3, §0.1): the workspace's own npm scope (`@<slug>`) and Python index
 * (`<slug>/dev`), ready-to-paste `npm config` / `pip` / `twine` lines with a publish key (shown once,
 * with the server's ready `.npmrc` / `.pypirc` when it sends one), the publish keys, the published
 * packages and «پاک کردن این نسخه».
 */
import { useCallback, useState } from "react";
import { Box, Button, CircularProgress, Dialog, DialogActions, DialogContent, DialogTitle, Stack, Typography, useMediaQuery, useTheme } from "@mui/material";
import KeyRoundedIcon from "@mui/icons-material/KeyRounded";
import Inventory2RoundedIcon from "@mui/icons-material/Inventory2Rounded";
import DeleteOutlineRoundedIcon from "@mui/icons-material/DeleteOutlineRounded";
import BlockRoundedIcon from "@mui/icons-material/BlockRounded";
import { ApiError, registryEndpoints } from "../api";
import { MY, MY_PACKAGES, pick, say } from "../copy";
import { CopyField, EmptyState, Ltr, OneTimeSecret, type SecretItem, RelativeTime, ResponsiveList, SectionCard, StatusPill, useConfirmAction, useKit, useUndoSnackbar, type ListColumn } from "../kit";
import { Loading, useList, useLoader } from "../dnsUi";
import { formatBytes } from "../format";
import {
  createPackageToken, deletePackageToken, deletePackageVersion, fetchMyPackages, fetchPackageTokens, type MyPackage, type MyPackages as Packages, type PackageToken
} from "./myApi";
import { useMySpace } from "./MySpaceContext";
import { MyError, myErrorSentence } from "./MyKit";

const TOKEN_PLACEHOLDER = "<TOKEN>";

function withSlash(url: string) {
  return url.endsWith("/") ? url : `${url}/`;
}

/** `https://npm.example.org/` → `//npm.example.org/` (the npm auth key). */
function npmAuthKey(registry: string) {
  return withSlash(registry.replace(/^https?:/, ""));
}

function npmLines(scope: string, registry: string, token: string) {
  return {
    config: `npm config set ${scope}:registry ${withSlash(registry)}\nnpm config set ${npmAuthKey(registry)}:_authToken ${token}`,
    publish: "npm publish"
  };
}

function pipLines(indexUrl: string, uploadUrl: string, username: string, token: string) {
  const withAuth = indexUrl.replace(/^(https?:\/\/)/, `$1${username}:${token}@`);
  return {
    config: `pip config set global.index-url ${withSlash(withAuth)}`,
    upload: `twine upload --repository-url ${withSlash(uploadUrl)} -u ${username} -p ${token} dist/*`
  };
}

function addresses(data: Packages | null, slug: string) {
  const derived = registryEndpoints();
  const pypiOrigin = derived.pypi.replace(/\/root\/pypi\/\+simple\/?$/, "");
  const index = data?.pypi.index ?? (slug ? `${slug}/dev` : "");
  const indexUrl = data?.pypi.indexUrl ?? `${pypiOrigin}/${index}/+simple/`;
  const scope = data?.npm.scope ?? (slug ? `@${slug}` : "");
  return {
    npmRegistry: data?.npm.registry ?? derived.npm,
    indexUrl,
    uploadUrl: data?.pypi.uploadUrl ?? indexUrl.replace(/\+simple\/?$/, ""),
    scope: !scope || scope.startsWith("@") ? scope : `@${scope}`,
    index
  };
}

function VersionsDialog({ item, onClose, onChanged }: { item: MyPackage; onClose: () => void; onChanged: () => void }) {
  const { language } = useKit();
  const space = useMySpace();
  const theme = useTheme();
  const fullScreen = useMediaQuery(theme.breakpoints.down("sm"));
  const { ask, dialog } = useConfirmAction();
  const { notify, snackbar } = useUndoSnackbar();
  const [busy, setBusy] = useState<string | null>(null);
  const [gone, setGone] = useState<string[]>([]);
  const versions = item.versions.filter((version) => !gone.includes(version.version));

  const remove = async (version: string) => {
    const ok = await ask({ title: say(language, MY_PACKAGES.deleteVersionTitle, { version, name: item.name }), body: pick(language, MY_PACKAGES.deleteVersionBody), severity: "destructive", undoable: false });
    if (!ok) return;
    setBusy(version);
    try {
      await deletePackageVersion(item.ecosystem, item.name, version);
      setGone((list) => [...list, version]);
      notify({ message: say(language, MY_PACKAGES.versionDeleted, { version }) });
      onChanged();
    } catch (caught) {
      notify({ message: myErrorSentence(language, caught), tone: "error" });
    } finally {
      setBusy(null);
    }
  };

  return (
    <Dialog open onClose={onClose} fullScreen={fullScreen} fullWidth maxWidth="sm" aria-labelledby="mrk-my-versions">
      <DialogTitle id="mrk-my-versions">{say(language, MY_PACKAGES.versionsTitle, { name: item.name })}</DialogTitle>
      <DialogContent>
        <Stack spacing={1}>
          {versions.length === 0 && <Typography color="text.secondary">{pick(language, MY_PACKAGES.noVersions)}</Typography>}
          {versions.map((version) => (
            <Stack key={version.version} direction="row" alignItems="center" gap={1} sx={{ border: 1, borderColor: "divider", borderRadius: 1.5, px: 1.5, py: 1 }}>
              <Typography fontWeight={650} sx={{ flex: 1, minWidth: 0 }}><Ltr mono>{version.version}</Ltr></Typography>
              {version.size !== null && <Typography variant="caption" color="text.secondary">{formatBytes(version.size, language)}</Typography>}
              {version.created_at ? <Typography variant="caption" color="text.secondary"><RelativeTime value={version.created_at} /></Typography> : null}
              {space.canWrite && (
                <Button size="small" color="error" disabled={busy !== null} onClick={() => void remove(version.version)} startIcon={busy === version.version ? <CircularProgress size={14} /> : <DeleteOutlineRoundedIcon />} aria-label={`${pick(language, MY_PACKAGES.deleteVersion)} ${version.version}`} sx={{ minHeight: 40 }}>
                  {pick(language, MY.remove)}
                </Button>
              )}
            </Stack>
          ))}
        </Stack>
      </DialogContent>
      <DialogActions sx={{ px: 3, pb: 2 }}>
        <Button onClick={onClose} sx={{ minHeight: 44 }}>{pick(language, MY.close)}</Button>
      </DialogActions>
      {dialog}
      {snackbar}
    </Dialog>
  );
}

type Secret = { ecosystem: "npm" | "pypi"; token: string; username: string | null; setup: string | null };

export default function MyPackages() {
  const { language } = useKit();
  const space = useMySpace();
  const loader = useCallback((signal: AbortSignal) => fetchMyPackages(signal), []);
  const { data, error, loading, reload } = useLoader(loader);
  const tokensLoader = useCallback((signal: AbortSignal) => fetchPackageTokens(signal).catch((caught: unknown) => {
    if (caught instanceof ApiError && (caught.status === 404 || caught.status === 405)) return [] as PackageToken[];
    throw caught;
  }), []);
  const tokens = useList<PackageToken>(tokensLoader);
  const [making, setMaking] = useState<"npm" | "pypi" | null>(null);
  const [secret, setSecret] = useState<Secret | null>(null);
  const [tokenError, setTokenError] = useState<unknown>(null);
  const [open, setOpen] = useState<MyPackage | null>(null);
  const { ask, dialog } = useConfirmAction();
  const { notify, snackbar } = useUndoSnackbar();
  const where = addresses(data, space.workspace?.slug ?? "");
  const npmOn = space.has("npm") && data?.npm.enabled !== false;
  const pypiOn = space.has("pypi") && data?.pypi.enabled !== false;

  const makeToken = async (ecosystem: "npm" | "pypi") => {
    setMaking(ecosystem);
    setTokenError(null);
    try {
      const name = `${ecosystem}-${new Date().toISOString().slice(0, 10)}`;
      const result = await createPackageToken(ecosystem, name);
      setSecret({ ecosystem, ...result });
      tokens.reload();
    } catch (caught) {
      setTokenError(caught);
    } finally {
      setMaking(null);
    }
  };

  const revoke = async (token: PackageToken) => {
    const ok = await ask({ title: say(language, MY_PACKAGES.revokeTitle, { name: token.name }), body: pick(language, MY_PACKAGES.revokeBody), severity: "destructive", undoable: false });
    if (!ok) return;
    try {
      await deletePackageToken(token.id);
      notify({ message: say(language, MY.removed, { name: token.name }) });
      tokens.reload();
    } catch (caught) {
      notify({ message: myErrorSentence(language, caught), tone: "error" });
    }
  };

  const npm = npmLines(where.scope, where.npmRegistry, TOKEN_PLACEHOLDER);
  const pip = pipLines(where.indexUrl, where.uploadUrl, "<USERNAME>", TOKEN_PLACEHOLDER);
  let secretItems: SecretItem[] = [];
  if (secret) {
    if (secret.ecosystem === "npm") {
      secretItems = [{ label: pick(language, MY_PACKAGES.configNpm), value: npmLines(where.scope, where.npmRegistry, secret.token).config, multiline: true }];
    } else {
      const lines = pipLines(where.indexUrl, where.uploadUrl, secret.username ?? "__token__", secret.token);
      secretItems = [
        { label: pick(language, MY_PACKAGES.configPip), value: lines.config, multiline: true },
        { label: pick(language, MY_PACKAGES.uploadPip), value: lines.upload, multiline: true }
      ];
    }
    if (secret.setup) secretItems.push({ label: pick(language, secret.ecosystem === "npm" ? MY_PACKAGES.fileNpmrc : MY_PACKAGES.filePypirc), value: secret.setup, multiline: true });
    secretItems.push({ label: pick(language, MY_PACKAGES.token), value: secret.token });
  }

  const tokenButton = (ecosystem: "npm" | "pypi") => {
    const allowed = space.canWrite && (ecosystem === "npm" ? data?.npm.publish : data?.pypi.publish) !== false;
    return allowed ? (
      <Button variant="contained" onClick={() => void makeToken(ecosystem)} disabled={making !== null} startIcon={making === ecosystem ? <CircularProgress size={16} color="inherit" /> : <KeyRoundedIcon />} sx={{ minHeight: 44 }}>
        {pick(language, making === ecosystem ? MY_PACKAGES.making : MY_PACKAGES.makeToken)}
      </Button>
    ) : undefined;
  };

  const columns: ListColumn<MyPackage>[] = [
    { key: "name", header: pick(language, MY_PACKAGES.colPackage), render: (item) => <Typography fontWeight={650} component="span"><Ltr mono>{item.name}</Ltr></Typography> },
    { key: "kind", header: pick(language, MY_PACKAGES.colKind), render: (item) => (item.ecosystem === "npm" ? "npm" : "PyPI") },
    { key: "versions", header: pick(language, MY_PACKAGES.colVersions), render: (item) => say(language, MY_PACKAGES.versions, { n: item.versions.length }) },
    { key: "size", header: pick(language, MY_PACKAGES.colSize), align: "end", render: (item) => (item.size === null ? "—" : formatBytes(item.size, language)) }
  ];

  return (
    <Stack spacing={2.5}>
      {error ? <MyError error={error} onRetry={reload} /> : null}
      {loading && !data ? <Loading /> : null}
      {tokenError ? <MyError error={tokenError} onClose={() => setTokenError(null)} /> : null}
      {npmOn && (
        <SectionCard title={pick(language, MY_PACKAGES.npmTitle)} hint={say(language, MY_PACKAGES.npmHint, { scope: where.scope })} action={tokenButton("npm")}>
          <Stack spacing={1.5}>
            <Typography variant="body2" fontWeight={650}>{pick(language, MY_PACKAGES.setupTitle)}</Typography>
            <CopyField label={pick(language, MY_PACKAGES.configNpm)} value={npm.config} multiline helperText={pick(language, MY_PACKAGES.tokenPlaceholder)} />
            <CopyField label={pick(language, MY_PACKAGES.publishNpm)} value={npm.publish} />
            {data?.npm.usage !== null && data?.npm.usage !== undefined && <Typography variant="caption" color="text.secondary">{say(language, MY_PACKAGES.usage, { size: formatBytes(data.npm.usage, language) })}</Typography>}
          </Stack>
        </SectionCard>
      )}
      {pypiOn && (
        <SectionCard title={pick(language, MY_PACKAGES.pypiTitle)} hint={say(language, MY_PACKAGES.pypiHint, { index: where.index })} action={tokenButton("pypi")}>
          <Stack spacing={1.5}>
            <Typography variant="body2" fontWeight={650}>{pick(language, MY_PACKAGES.setupTitle)}</Typography>
            <CopyField label={pick(language, MY_PACKAGES.configPip)} value={pip.config} multiline helperText={pick(language, MY_PACKAGES.tokenPlaceholder)} />
            <CopyField label={pick(language, MY_PACKAGES.uploadPip)} value={pip.upload} multiline />
            {data?.pypi.usage !== null && data?.pypi.usage !== undefined && <Typography variant="caption" color="text.secondary">{say(language, MY_PACKAGES.usage, { size: formatBytes(data.pypi.usage, language) })}</Typography>}
          </Stack>
        </SectionCard>
      )}
      {(tokens.items?.length ?? 0) > 0 && (
        <SectionCard title={pick(language, MY_PACKAGES.tokensTitle)} hint={pick(language, MY_PACKAGES.tokensHint)} flush>
          <ResponsiveList
            label={pick(language, MY_PACKAGES.tokensTitle)}
            rows={tokens.items ?? []}
            rowKey={(token) => token.id}
            columns={[
              { key: "name", header: pick(language, MY.name), render: (token) => <Ltr>{token.name}</Ltr> },
              { key: "kind", header: pick(language, MY_PACKAGES.colKind), render: (token) => (token.ecosystem === "npm" ? "npm" : "PyPI") },
              { key: "created", header: pick(language, MY.created), render: (token) => <RelativeTime value={token.created_at ?? null} /> }
            ]}
            card={{ title: (token) => <Ltr>{token.name}</Ltr>, meta: (token) => (token.ecosystem === "npm" ? "npm" : "PyPI") }}
            actions={space.canWrite ? [{ key: "revoke", label: pick(language, MY_PACKAGES.revoke), icon: BlockRoundedIcon, danger: true, onClick: (token) => void revoke(token) }] : undefined}
          />
        </SectionCard>
      )}
      {data && (
        <SectionCard title={pick(language, MY_PACKAGES.listTitle)} flush>
          <ResponsiveList
            label={pick(language, MY_PACKAGES.listTitle)}
            rows={data.items}
            rowKey={(item) => `${item.ecosystem}:${item.name}`}
            columns={columns}
            card={{
              title: (item) => <Ltr mono>{item.name}</Ltr>,
              meta: (item) => [say(language, MY_PACKAGES.versions, { n: item.versions.length }), item.size === null ? null : formatBytes(item.size, language)].filter(Boolean).join(" · "),
              status: (item) => <StatusPill tone="info" label={item.ecosystem === "npm" ? "npm" : "PyPI"} />
            }}
            onRowClick={(item) => setOpen(item)}
            actions={[{ key: "open", label: pick(language, MY.open), icon: Inventory2RoundedIcon, onClick: (item) => setOpen(item) }]}
            empty={<EmptyState icon={Inventory2RoundedIcon} title={pick(language, MY_PACKAGES.listEmptyTitle)} body={pick(language, MY_PACKAGES.listEmptyBody)} />}
          />
        </SectionCard>
      )}
      {!npmOn && !pypiOn && data && <Box><Typography color="text.secondary">{pick(language, MY_PACKAGES.off)}</Typography></Box>}
      <OneTimeSecret open={secret !== null} title={pick(language, MY_PACKAGES.tokenTitle)} body={pick(language, MY_PACKAGES.tokenBody)} items={secretItems} onClose={() => setSecret(null)} />
      {open && <VersionsDialog item={open} onClose={() => setOpen(null)} onChanged={reload} />}
      {dialog}
      {snackbar}
    </Stack>
  );
}
