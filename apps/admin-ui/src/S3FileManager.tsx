/**
 * Files inside one bucket (Files › file space). Simple: upload, download, share link, new folder, delete.
 * Advanced adds selection + bulk delete, rename/move, full paths, content types and exact times.
 */
import { useCallback, useEffect, useMemo, useRef, useState, type ChangeEvent, type DragEvent, type FormEvent } from "react";
import {
  Box,
  Breadcrumbs,
  Button,
  Checkbox,
  Chip,
  CircularProgress,
  Dialog,
  DialogActions,
  DialogContent,
  DialogTitle,
  IconButton,
  InputAdornment,
  LinearProgress,
  Link,
  Paper,
  Stack,
  TextField,
  ToggleButton,
  ToggleButtonGroup,
  Typography,
  useMediaQuery,
  useTheme
} from "@mui/material";
import type { SvgIconComponent } from "@mui/icons-material";
import FolderRoundedIcon from "@mui/icons-material/FolderRounded";
import InsertDriveFileRoundedIcon from "@mui/icons-material/InsertDriveFileRounded";
import ImageRoundedIcon from "@mui/icons-material/ImageRounded";
import MovieRoundedIcon from "@mui/icons-material/MovieRounded";
import AudiotrackRoundedIcon from "@mui/icons-material/AudiotrackRounded";
import PictureAsPdfRoundedIcon from "@mui/icons-material/PictureAsPdfRounded";
import FolderZipRoundedIcon from "@mui/icons-material/FolderZipRounded";
import DescriptionRoundedIcon from "@mui/icons-material/DescriptionRounded";
import UploadRoundedIcon from "@mui/icons-material/UploadRounded";
import CreateNewFolderRoundedIcon from "@mui/icons-material/CreateNewFolderRounded";
import RefreshRoundedIcon from "@mui/icons-material/RefreshRounded";
import DownloadRoundedIcon from "@mui/icons-material/DownloadRounded";
import ShareRoundedIcon from "@mui/icons-material/ShareRounded";
import DriveFileRenameOutlineRoundedIcon from "@mui/icons-material/DriveFileRenameOutlineRounded";
import DeleteOutlineRoundedIcon from "@mui/icons-material/DeleteOutlineRounded";
import FolderOpenRoundedIcon from "@mui/icons-material/FolderOpenRounded";
import CloseRoundedIcon from "@mui/icons-material/CloseRounded";
import SearchRoundedIcon from "@mui/icons-material/SearchRounded";
import { ApiError, getCsrfToken, getJson, isAbortError, mutateJson, refreshCsrf } from "./api";
import type { Language } from "./i18n";
import {
  CopyField, EmptyState, FriendlyError, Ltr, NoAccess, Notice, RelativeTime, ResponsiveList, useConfirmAction, useKit, useUndoSnackbar,
  NameDialog, type ListColumn, type RowAction
} from "./kit";
import { deleteConfirmation, errorSentence, nameConfirmation, pick, say, type Bi } from "./copy";
import { formatBytes, formatNumber } from "./format";

type S3Object = { key: string; size: number; etag?: string; last_modified?: string | number | null; content_type?: string | null };
type Listing = { prefixes: string[]; objects: S3Object[]; next_continuation: string | null };
type Upload = { id: number; name: string; key: string; size: number; loaded: number; state: "queued" | "uploading" | "done" | "failed" | "cancelled"; error?: string };
type Share = { url: string; expires_at: number | string | null; endpoint?: string; warning?: string | null };
type Entry = { kind: "folder"; key: string } | { kind: "file"; key: string; object: S3Object };

const BASE = "/api/v1/s3/buckets";
const PAGE = 200;

const T = {
  root: { fa: "پوشه اصلی", en: "Bucket" },
  upload: { fa: "آپلود فایل", en: "Upload files" },
  newFolder: { fa: "پوشه تازه", en: "New folder" },
  folderName: { fa: "نام پوشه", en: "Folder name" },
  folderTitle: { fa: "ساخت پوشه تازه", en: "Create a folder" },
  folderHint: { fa: "این پوشه داخل «{place}» ساخته می‌شود.", en: "The folder is created inside “{place}”." },
  folderRule: { fa: "نام پوشه نمی‌تواند «/» داشته باشد.", en: "A folder name can't contain “/”." },
  create: { fa: "ساخت پوشه", en: "Create folder" },
  dropHere: { fa: "فایل‌ها را این‌جا رها کنید تا آپلود شوند", en: "Drop files here to upload them" },
  emptyTitle: { fa: "این پوشه هنوز خالی است", en: "This folder is empty" },
  emptyBody: { fa: "فایل‌ها را بکشید و این‌جا رها کنید، یا دکمه آپلود را بزنید.", en: "Drag files here, or use the upload button." },
  emptyReadOnly: { fa: "هنوز فایلی در این پوشه نیست.", en: "There are no files in this folder yet." },
  noMatchTitle: { fa: "چیزی با «{q}» پیدا نشد", en: "Nothing matches “{q}”" },
  noMatchBody: { fa: "املای نام را بررسی کنید یا جست‌وجو را پاک کنید.", en: "Check the spelling or clear the search." },
  loadMore: { fa: "نمایش موارد بیشتر", en: "Show more" },
  filter: { fa: "جست‌وجو در همین پوشه", en: "Search this folder" },
  selected: { fa: "{n} مورد انتخاب شده", en: "{n} selected" },
  selectAll: { fa: "انتخاب همه", en: "Select all" },
  deleteSelected: { fa: "پاک کردن انتخاب‌شده‌ها", en: "Delete selected" },
  open: { fa: "باز کردن", en: "Open" },
  download: { fa: "دانلود", en: "Download" },
  share: { fa: "لینک اشتراک", en: "Share link" },
  rename: { fa: "تغییر نام یا جابه‌جایی", en: "Rename or move" },
  renameHint: { fa: "مسیر کامل را عوض کنید تا جابه‌جا شود. نام پوشه‌ها با «/» تمام می‌شود.", en: "Change the full path to move it. Folder names end with “/”." },
  newPath: { fa: "نام یا مسیر تازه", en: "New name or path" },
  save: { fa: "ذخیره", en: "Save" },
  delete: { fa: "پاک کردن", en: "Delete" },
  deleteFileTitle: { fa: "فایل «{name}» پاک شود؟", en: "Delete “{name}”?" },
  deleteFileBody: { fa: "این فایل برای همیشه پاک می‌شود.", en: "This file is deleted for good." },
  deleteManyTitle: { fa: "{n} مورد پاک شود؟", en: "Delete {n} items?" },
  deleteManyBody: { fa: "همه موارد انتخاب‌شده برای همیشه پاک می‌شوند.", en: "Every selected item is deleted for good." },
  deleteFolderTitle: { fa: "پوشه «{name}» با همه محتوایش پاک شود؟", en: "Delete folder “{name}” and everything in it?" },
  deleteFolderBody: { fa: "{n} فایل با حجم {size} برای همیشه پاک می‌شوند.", en: "{n} files ({size}) are deleted for good." },
  counting: { fa: "در حال شمردن محتوای پوشه…", en: "Counting what's in the folder…" },
  deleted: { fa: "{n} مورد پاک شد.", en: "{n} items deleted." },
  deleteErrors: { fa: "{n} مورد پاک نشد. یک بار دیگر امتحان کنید.", en: "{n} items weren't deleted. Try once more." },
  moved: { fa: "جابه‌جا شد.", en: "Moved." },
  folderCreated: { fa: "پوشه «{name}» ساخته شد.", en: "Folder “{name}” created." },
  uploads: { fa: "آپلودها", en: "Uploads" },
  cancel: { fa: "لغو", en: "Cancel" },
  clearDone: { fa: "پاک کردن تمام‌شده‌ها از فهرست", en: "Clear finished" },
  uploadDone: { fa: "تمام شد", en: "Done" },
  uploadFailed: { fa: "آپلود نشد", en: "Not uploaded" },
  uploadCancelled: { fa: "لغو شد", en: "Cancelled" },
  uploadQueued: { fa: "در نوبت", en: "Waiting" },
  shareTitle: { fa: "لینک اشتراک موقت برای «{name}»", en: "Temporary share link for “{name}”" },
  expires: { fa: "لینک تا کی کار کند؟", en: "How long should the link work?" },
  e_3600: { fa: "۱ ساعت", en: "1 hour" },
  e_86400: { fa: "۱ روز", en: "1 day" },
  e_604800: { fa: "۷ روز", en: "7 days" },
  makeLink: { fa: "ساخت لینک", en: "Create link" },
  making: { fa: "در حال ساخت…", en: "Creating…" },
  link: { fa: "لینک", en: "Link" },
  expiresAt: { fa: "این لینک {time} از کار می‌افتد.", en: "This link stops working {time}." },
  shareWarning: { fa: "آدرس عمومی فضای فایل تنظیم نشده؛ این لینک فقط از داخل شبکه همین سرور باز می‌شود.", en: "The public address isn't set, so this link only opens from inside this server's network." },
  shareNote: { fa: "هر کسی این لینک را داشته باشد، تا وقتی اعتبار دارد می‌تواند فایل را دانلود کند.", en: "Anyone with this link can download the file until it expires." },
  close: { fa: "بستن", en: "Close" },
  name: { fa: "نام", en: "Name" },
  size: { fa: "حجم", en: "Size" },
  modified: { fa: "آخرین تغییر", en: "Last changed" },
  type: { fa: "نوع فایل", en: "Content type" },
  path: { fa: "مسیر کامل", en: "Full path" },
  folder: { fa: "پوشه", en: "Folder" },
  listLabel: { fa: "فایل‌ها و پوشه‌ها", en: "Files and folders" }
} satisfies Record<string, Bi>;

function iconFor(key: string, contentType?: string | null): SvgIconComponent {
  const type = contentType ?? "";
  const ext = key.split(".").pop()?.toLowerCase() ?? "";
  if (type.startsWith("image/") || ["png", "jpg", "jpeg", "gif", "webp", "svg", "bmp"].includes(ext)) return ImageRoundedIcon;
  if (type.startsWith("video/") || ["mp4", "mkv", "webm", "mov", "avi"].includes(ext)) return MovieRoundedIcon;
  if (type.startsWith("audio/") || ["mp3", "wav", "ogg", "flac", "m4a"].includes(ext)) return AudiotrackRoundedIcon;
  if (type === "application/pdf" || ext === "pdf") return PictureAsPdfRoundedIcon;
  if (["zip", "gz", "tgz", "tar", "bz2", "xz", "7z", "rar", "zst"].includes(ext)) return FolderZipRoundedIcon;
  if (type.startsWith("text/") || ["txt", "md", "json", "yaml", "yml", "log", "csv", "xml", "toml", "ini", "sql"].includes(ext)) return DescriptionRoundedIcon;
  return InsertDriveFileRoundedIcon;
}

function baseName(key: string) {
  const trimmed = key.endsWith("/") ? key.slice(0, -1) : key;
  return trimmed.slice(trimmed.lastIndexOf("/") + 1);
}

function downloadHref(bucket: string, key: string) {
  return `${BASE}/${encodeURIComponent(bucket)}/objects/download?key=${encodeURIComponent(key)}`;
}

function startDownload(bucket: string, key: string) {
  const anchor = document.createElement("a");
  anchor.href = downloadHref(bucket, key);
  anchor.download = baseName(key);
  document.body.appendChild(anchor);
  anchor.click();
  anchor.remove();
}

function listingUrl(bucket: string, target: string, continuation: string | null | undefined, delimiter: boolean) {
  const params = new URLSearchParams({ prefix: target, limit: String(delimiter ? PAGE : 1000) });
  if (delimiter) params.set("delimiter", "/");
  if (continuation) params.set("continuation", continuation);
  return `${BASE}/${encodeURIComponent(bucket)}/objects?${params.toString()}`;
}

function sendFile(url: string, file: File, onProgress: (loaded: number) => void, register: (xhr: XMLHttpRequest) => void): Promise<void> {
  return new Promise((resolve, reject) => {
    const xhr = new XMLHttpRequest();
    register(xhr);
    xhr.open("POST", url);
    xhr.setRequestHeader("Accept", "application/json");
    xhr.setRequestHeader("X-CSRF-Token", getCsrfToken());
    xhr.setRequestHeader("Content-Type", file.type || "application/octet-stream");
    xhr.upload.onprogress = (event) => onProgress(event.loaded);
    xhr.onload = () => {
      if (xhr.status >= 200 && xhr.status < 300) {
        resolve();
        return;
      }
      let code = "";
      let detail = "";
      try {
        const payload = JSON.parse(xhr.responseText) as { error?: { code?: string; message?: string } };
        code = payload.error?.code ?? "";
        detail = payload.error?.message ?? "";
      } catch {
        // non-JSON body
      }
      reject(new ApiError(xhr.status, code, detail));
    };
    xhr.onerror = () => reject(new TypeError("network"));
    xhr.onabort = () => reject(new DOMException("aborted", "AbortError"));
    xhr.send(file);
  });
}

function ShareDialog({ bucket, objectKey, onClose }: { bucket: string; objectKey: string; onClose: () => void }) {
  const { language } = useKit();
  const theme = useTheme();
  const fullScreen = useMediaQuery(theme.breakpoints.down("sm"));
  const [expires, setExpires] = useState<3600 | 86400 | 604800>(86400);
  const [busy, setBusy] = useState(false);
  const [share, setShare] = useState<Share | null>(null);
  const [error, setError] = useState<unknown>(null);

  const create = async () => {
    setBusy(true);
    setError(null);
    try {
      setShare(await mutateJson<Share>(`${BASE}/${encodeURIComponent(bucket)}/share`, { method: "POST", body: { key: objectKey, expires_seconds: expires } }));
    } catch (caught) {
      if (!(caught instanceof ApiError && caught.status === 401)) setError(caught);
    } finally {
      setBusy(false);
    }
  };

  return (
    <Dialog open onClose={busy ? undefined : onClose} fullScreen={fullScreen} fullWidth maxWidth="sm" aria-labelledby="mrk-share-title">
      <DialogTitle id="mrk-share-title">{say(language, T.shareTitle, { name: baseName(objectKey) })}</DialogTitle>
      <DialogContent>
        <Stack spacing={2} sx={{ pt: 0.5 }}>
          <Box>
            <Typography variant="body2" sx={{ mb: 0.75 }} id="mrk-share-expiry">{pick(language, T.expires)}</Typography>
            <ToggleButtonGroup
              size="small"
              exclusive
              value={expires}
              onChange={(_event, value: 3600 | 86400 | 604800 | null) => {
                if (value) {
                  setExpires(value);
                  setShare(null);
                }
              }}
              aria-labelledby="mrk-share-expiry"
            >
              {([3600, 86400, 604800] as const).map((value) => (
                <ToggleButton key={value} value={value} sx={{ px: 2, minHeight: 44 }}>{pick(language, T[`e_${value}`])}</ToggleButton>
              ))}
            </ToggleButtonGroup>
          </Box>
          <Typography variant="body2" color="text.secondary">{pick(language, T.shareNote)}</Typography>
          {share && (
            <>
              {share.warning && <Notice tone="warning">{pick(language, T.shareWarning)}</Notice>}
              <CopyField label={pick(language, T.link)} value={share.url} />
              <Typography variant="caption" color="text.secondary">
                {pick(language, T.expiresAt).split("{time}")[0]}
                <RelativeTime value={share.expires_at} />
                {pick(language, T.expiresAt).split("{time}")[1]}
              </Typography>
            </>
          )}
          {error !== null && <FriendlyError error={error} onRetry={() => void create()} />}
        </Stack>
      </DialogContent>
      <DialogActions sx={{ px: 3, pb: 2 }}>
        <Button onClick={onClose} disabled={busy} sx={{ minHeight: 44 }}>{pick(language, T.close)}</Button>
        {!share && (
          <Button variant="contained" onClick={() => void create()} disabled={busy} startIcon={busy ? <CircularProgress size={16} color="inherit" /> : <ShareRoundedIcon />} sx={{ minHeight: 44 }}>
            {pick(language, busy ? T.making : T.makeLink)}
          </Button>
        )}
      </DialogActions>
    </Dialog>
  );
}

export function S3FileManager({ bucket, language, canWrite }: { bucket: string; language: Language; canWrite: boolean }) {
  const { isAdvanced } = useKit();
  const { ask, dialog } = useConfirmAction();
  const { notify, snackbar } = useUndoSnackbar();
  const t = (bi: Bi, params?: Record<string, string | number>) => say(language, bi, params);
  const [prefix, setPrefix] = useState("");
  const [folders, setFolders] = useState<string[]>([]);
  const [objects, setObjects] = useState<S3Object[]>([]);
  const [next, setNext] = useState<string | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<unknown>(null);
  const [partial, setPartial] = useState<string[] | null>(null);
  const [busyNote, setBusyNote] = useState<string | null>(null);
  const [selected, setSelected] = useState<Set<string>>(new Set());
  const [filter, setFilter] = useState("");
  const [uploads, setUploads] = useState<Upload[]>([]);
  const [dragging, setDragging] = useState(false);
  const [shareKey, setShareKey] = useState<string | null>(null);
  const [naming, setNaming] = useState<{ mode: "folder" } | { mode: "rename"; key: string } | null>(null);
  const [working, setWorking] = useState(false);
  const fileInput = useRef<HTMLInputElement | null>(null);
  const controller = useRef<AbortController | null>(null);
  const xhrs = useRef(new Map<number, XMLHttpRequest>());
  const queue = useRef<Array<{ upload: Upload; file: File }>>([]);
  const running = useRef(false);
  const nextId = useRef(1);
  const prefixRef = useRef(prefix);
  prefixRef.current = prefix;

  const load = useCallback(async (target: string, continuation: string | null = null) => {
    controller.current?.abort();
    const current = new AbortController();
    controller.current = current;
    setLoading(true);
    try {
      const page = await getJson<Listing>(listingUrl(bucket, target, continuation, true), current.signal);
      const ownObjects = (page.objects ?? []).filter((item) => item.key !== target);
      setFolders((previous) => (continuation ? [...previous, ...(page.prefixes ?? [])] : page.prefixes ?? []));
      setObjects((previous) => (continuation ? [...previous, ...ownObjects] : ownObjects));
      setNext(page.next_continuation ?? null);
      setError(null);
      if (!continuation) setSelected(new Set());
    } catch (caught) {
      if (isAbortError(caught) || (caught instanceof ApiError && caught.status === 401)) return;
      setError(caught);
    } finally {
      if (controller.current === current) setLoading(false);
    }
  }, [bucket]);

  useEffect(() => {
    void load(prefix);
  }, [load, prefix]);

  useEffect(() => () => {
    controller.current?.abort();
    for (const xhr of xhrs.current.values()) xhr.abort();
    queue.current = [];
  }, []);

  const patchUpload = (id: number, patch: Partial<Upload>) => setUploads((list) => list.map((item) => (item.id === id ? { ...item, ...patch } : item)));

  const pump = async () => {
    if (running.current) return;
    running.current = true;
    while (queue.current.length) {
      const { upload, file } = queue.current.shift()!;
      patchUpload(upload.id, { state: "uploading" });
      const url = `${BASE}/${encodeURIComponent(bucket)}/objects?key=${encodeURIComponent(upload.key)}`;
      const attempt = () => sendFile(url, file, (loaded) => patchUpload(upload.id, { loaded }), (xhr) => xhrs.current.set(upload.id, xhr));
      try {
        try {
          await attempt();
        } catch (caught) {
          if (caught instanceof ApiError && caught.code === "csrf_failed" && (await refreshCsrf())) await attempt();
          else throw caught;
        }
        patchUpload(upload.id, { state: "done", loaded: upload.size });
      } catch (caught) {
        if (isAbortError(caught)) patchUpload(upload.id, { state: "cancelled" });
        else patchUpload(upload.id, { state: "failed", error: errorSentence(language, caught) });
      } finally {
        xhrs.current.delete(upload.id);
      }
    }
    running.current = false;
    void load(prefixRef.current);
  };

  const enqueue = (files: File[]) => {
    if (!canWrite || files.length === 0) return;
    const added = files.map((file) => {
      const relative = (file as File & { webkitRelativePath?: string }).webkitRelativePath || file.name;
      const upload: Upload = { id: nextId.current++, name: relative, key: `${prefix}${relative}`, size: file.size, loaded: 0, state: "queued" };
      queue.current.push({ upload, file });
      return upload;
    });
    setUploads((list) => [...list, ...added]);
    void pump();
  };

  const cancelUpload = (id: number) => {
    const xhr = xhrs.current.get(id);
    if (xhr) xhr.abort();
    else {
      queue.current = queue.current.filter((item) => item.upload.id !== id);
      patchUpload(id, { state: "cancelled" });
    }
  };

  const onFiles = (event: ChangeEvent<HTMLInputElement>) => {
    enqueue(Array.from(event.target.files ?? []));
    event.target.value = "";
  };
  const onDrop = (event: DragEvent) => {
    event.preventDefault();
    setDragging(false);
    enqueue(Array.from(event.dataTransfer.files ?? []));
  };

  const deleteKeys = async (keys: string[]) => {
    let deleted = 0;
    const failures: string[] = [];
    for (let index = 0; index < keys.length; index += 1000) {
      const batch = keys.slice(index, index + 1000);
      const result = await mutateJson<{ deleted?: string[] | number; errors?: Array<{ key: string; code?: string; message?: string }> }>(`${BASE}/${encodeURIComponent(bucket)}/objects`, { method: "DELETE", body: { keys: batch } });
      deleted += Array.isArray(result?.deleted) ? result.deleted.length : typeof result?.deleted === "number" ? result.deleted : batch.length;
      for (const item of result?.errors ?? []) failures.push(item.code ? `${item.key} (${item.code})` : item.key);
    }
    return { deleted, failures };
  };

  const report = ({ deleted, failures }: { deleted: number; failures: string[] }) => {
    notify({ message: t(T.deleted, { n: formatNumber(deleted, language) }) });
    setPartial(failures.length ? failures : null);
  };

  /** Every key under a folder (no delimiter), capped to keep the browser responsive. */
  const collectFolder = async (folder: string) => {
    const keys: string[] = [];
    let bytes = 0;
    let continuation: string | null = null;
    do {
      const page: Listing = await getJson<Listing>(listingUrl(bucket, folder, continuation, false));
      for (const item of page.objects ?? []) {
        keys.push(item.key);
        bytes += item.size ?? 0;
      }
      continuation = page.next_continuation ?? null;
    } while (continuation && keys.length < 50_000);
    if (!keys.includes(folder)) keys.push(folder);
    return { keys, bytes };
  };

  const run = async (action: () => Promise<void>) => {
    setWorking(true);
    setError(null);
    setPartial(null);
    try {
      await action();
    } catch (caught) {
      if (!(caught instanceof ApiError && caught.status === 401)) setError(caught);
    } finally {
      setWorking(false);
      setBusyNote(null);
    }
  };

  const deleteFile = (key: string) => run(async () => {
    const ok = await ask({ title: t(T.deleteFileTitle, { name: baseName(key) }), body: pick(language, T.deleteFileBody), severity: "destructive", undoable: false });
    if (!ok) return;
    report(await deleteKeys([key]));
    await load(prefix);
  });

  const deleteFolder = (folder: string) => run(async () => {
    setBusyNote(pick(language, T.counting));
    const { keys, bytes } = await collectFolder(folder);
    setBusyNote(null);
    const name = baseName(folder);
    const ok = await ask({
      title: t(T.deleteFolderTitle, { name }),
      body: t(T.deleteFolderBody, { n: formatNumber(keys.length, language), size: formatBytes(bytes, language) }),
      severity: "destructive",
      undoable: false,
      typed: nameConfirmation(name, name)
    });
    if (!ok) return;
    report(await deleteKeys(keys));
    await load(prefix);
  });

  const deleteSelected = () => run(async () => {
    const chosen = Array.from(selected);
    const chosenFolders = chosen.filter((key) => key.endsWith("/"));
    const keys = chosen.filter((key) => !key.endsWith("/"));
    if (chosenFolders.length) setBusyNote(pick(language, T.counting));
    for (const folder of chosenFolders) keys.push(...(await collectFolder(folder)).keys);
    setBusyNote(null);
    const ok = await ask({
      title: t(T.deleteManyTitle, { n: formatNumber(keys.length, language) }),
      body: pick(language, T.deleteManyBody),
      severity: "destructive",
      undoable: false,
      typed: keys.length > 20 || chosenFolders.length ? deleteConfirmation("DELETE") : undefined
    });
    if (!ok) return;
    report(await deleteKeys(keys));
    await load(prefix);
  });

  const toggle = (key: string) => setSelected((current) => {
    const nextSet = new Set(current);
    if (nextSet.has(key)) nextSet.delete(key);
    else nextSet.add(key);
    return nextSet;
  });

  const needle = filter.trim().toLowerCase();
  const entries: Entry[] = useMemo(() => [
    ...folders.filter((item) => !needle || baseName(item).toLowerCase().includes(needle)).map((key): Entry => ({ kind: "folder", key })),
    ...objects.filter((item) => !needle || baseName(item.key).toLowerCase().includes(needle)).map((object): Entry => ({ kind: "file", key: object.key, object }))
  ], [folders, objects, needle]);
  const allKeys = entries.map((entry) => entry.key);
  const allSelected = allKeys.length > 0 && allKeys.every((key) => selected.has(key));
  const crumbs = prefix.split("/").filter(Boolean);
  const activeUploads = uploads.filter((item) => item.state === "queued" || item.state === "uploading").length;
  const selectable = canWrite && isAdvanced;

  const entryName = (entry: Entry) => {
    const Icon = entry.kind === "folder" ? FolderRoundedIcon : iconFor(entry.key, entry.object.content_type);
    return (
      <Stack direction="row" spacing={1} alignItems="center" sx={{ minWidth: 0 }}>
        {selectable && (
          <Checkbox
            size="small"
            checked={selected.has(entry.key)}
            onClick={(event) => event.stopPropagation()}
            onChange={() => toggle(entry.key)}
            slotProps={{ input: { "aria-label": baseName(entry.key) } }}
          />
        )}
        <Icon aria-hidden sx={{ color: entry.kind === "folder" ? "#f59e0b" : "action.active" }} />
        <Typography variant="body2" fontWeight={entry.kind === "folder" ? 650 : 500} noWrap title={entry.key} sx={{ minWidth: 0 }}>
          <Ltr>{baseName(entry.key)}{entry.kind === "folder" ? "/" : ""}</Ltr>
        </Typography>
      </Stack>
    );
  };

  const columns: ListColumn<Entry>[] = [
    { key: "name", header: pick(language, T.name), render: entryName },
    { key: "size", header: pick(language, T.size), align: "end", render: (entry) => (entry.kind === "file" ? formatBytes(entry.object.size, language) : "—") },
    { key: "modified", header: pick(language, T.modified), render: (entry) => (entry.kind === "file" ? <RelativeTime value={entry.object.last_modified ?? null} /> : "—") },
    { key: "type", header: pick(language, T.type), advancedOnly: true, ltr: true, render: (entry) => (entry.kind === "file" && entry.object.content_type ? <Ltr mono>{entry.object.content_type}</Ltr> : "—") },
    { key: "path", header: pick(language, T.path), advancedOnly: true, ltr: true, hideOnCard: true, render: (entry) => <Ltr mono>{entry.key}</Ltr> }
  ];

  const actions: RowAction<Entry>[] = [
    { key: "open", label: pick(language, T.open), icon: FolderOpenRoundedIcon, hidden: (entry) => entry.kind !== "folder", onClick: (entry) => setPrefix(entry.key) },
    { key: "download", label: pick(language, T.download), icon: DownloadRoundedIcon, hidden: (entry) => entry.kind !== "file", onClick: (entry) => startDownload(bucket, entry.key) },
    { key: "share", label: pick(language, T.share), icon: ShareRoundedIcon, hidden: (entry) => entry.kind !== "file" || !canWrite, onClick: (entry) => setShareKey(entry.key) },
    { key: "rename", label: pick(language, T.rename), icon: DriveFileRenameOutlineRoundedIcon, advancedOnly: true, hidden: () => !canWrite, disabled: () => working, onClick: (entry) => setNaming({ mode: "rename", key: entry.key }) },
    {
      key: "delete",
      label: pick(language, T.delete),
      icon: DeleteOutlineRoundedIcon,
      danger: true,
      hidden: () => !canWrite,
      disabled: () => working,
      onClick: (entry) => void (entry.kind === "folder" ? deleteFolder(entry.key) : deleteFile(entry.key))
    }
  ];

  return (
    <Box
      onDragOver={(event) => {
        if (canWrite) {
          event.preventDefault();
          setDragging(true);
        }
      }}
      onDragLeave={(event) => {
        if (event.currentTarget === event.target) setDragging(false);
      }}
      onDrop={canWrite ? onDrop : undefined}
      sx={{ position: "relative" }}
    >
      <Stack spacing={1.5}>
        <Stack direction={{ xs: "column", md: "row" }} spacing={1} justifyContent="space-between" alignItems={{ md: "center" }}>
          <Breadcrumbs aria-label={pick(language, T.folder)} sx={{ minWidth: 0, "& ol": { flexWrap: "wrap" } }}>
            <Link component="button" type="button" underline="hover" onClick={() => setPrefix("")}><Ltr>{bucket}</Ltr></Link>
            {crumbs.map((part, index) => {
              const target = `${crumbs.slice(0, index + 1).join("/")}/`;
              return index === crumbs.length - 1
                ? <Typography key={target} color="text.primary"><Ltr>{part}</Ltr></Typography>
                : <Link key={target} component="button" type="button" underline="hover" onClick={() => setPrefix(target)}><Ltr>{part}</Ltr></Link>;
            })}
          </Breadcrumbs>
          <Stack direction="row" spacing={1} flexWrap="wrap" useFlexGap>
            {canWrite && <Button variant="contained" startIcon={<UploadRoundedIcon />} onClick={() => fileInput.current?.click()} sx={{ minHeight: 44 }}>{pick(language, T.upload)}</Button>}
            {canWrite && <Button variant="outlined" startIcon={<CreateNewFolderRoundedIcon />} disabled={working} onClick={() => setNaming({ mode: "folder" })} sx={{ minHeight: 44 }}>{pick(language, T.newFolder)}</Button>}
            <IconButton aria-label={pick(language, { fa: "تازه کردن", en: "Refresh" })} disabled={loading} onClick={() => void load(prefix)} sx={{ width: 44, height: 44 }}>
              {loading ? <CircularProgress size={18} /> : <RefreshRoundedIcon />}
            </IconButton>
          </Stack>
        </Stack>
        <input ref={fileInput} type="file" multiple hidden onChange={onFiles} aria-hidden tabIndex={-1} />
        {!canWrite && <NoAccess needs="s3:write" />}
        {error !== null && <FriendlyError error={error} onRetry={() => void load(prefix)} onClose={() => setError(null)} />}
        {partial && (
          <Notice tone="warning">
            {t(T.deleteErrors, { n: formatNumber(partial.length, language) })}
            {isAdvanced && <Box component="span" sx={{ display: "block", mt: 0.5 }}><Ltr mono>{partial.slice(0, 5).join(" · ")}</Ltr></Box>}
          </Notice>
        )}
        {busyNote && <Notice>{busyNote}</Notice>}

        {uploads.length > 0 && (
          <Paper variant="outlined" sx={{ p: 1.25, borderRadius: 1 }}>
            <Stack direction="row" justifyContent="space-between" alignItems="center">
              <Typography variant="subtitle2">{pick(language, T.uploads)}{activeUploads ? ` · ${formatNumber(activeUploads, language)}` : ""}</Typography>
              <Button size="small" onClick={() => setUploads((list) => list.filter((item) => item.state === "queued" || item.state === "uploading"))}>{pick(language, T.clearDone)}</Button>
            </Stack>
            <Stack spacing={0.75} sx={{ mt: 0.5, maxHeight: 220, overflow: "auto" }}>
              {uploads.map((item) => {
                const percent = item.size > 0 ? (item.loaded / item.size) * 100 : item.state === "done" ? 100 : 0;
                const stateText = item.state === "uploading"
                  ? `${formatBytes(item.loaded, language)} / ${formatBytes(item.size, language)}`
                  : pick(language, item.state === "done" ? T.uploadDone : item.state === "failed" ? T.uploadFailed : item.state === "cancelled" ? T.uploadCancelled : T.uploadQueued);
                return (
                  <Box key={item.id}>
                    <Stack direction="row" spacing={1} alignItems="center">
                      <Typography variant="caption" noWrap sx={{ flex: 1, minWidth: 0 }} title={item.key}><Ltr>{item.name}</Ltr></Typography>
                      <Typography variant="caption" color={item.state === "failed" ? "error.main" : "text.secondary"} sx={{ flexShrink: 0 }}>{stateText}</Typography>
                      {(item.state === "queued" || item.state === "uploading") && (
                        <IconButton size="small" aria-label={`${pick(language, T.cancel)} · ${item.name}`} onClick={() => cancelUpload(item.id)}><CloseRoundedIcon fontSize="small" /></IconButton>
                      )}
                    </Stack>
                    {(item.state === "uploading" || item.state === "queued") && (
                      <LinearProgress variant={item.state === "queued" ? "indeterminate" : "determinate"} value={Math.min(100, percent)} aria-label={item.name} sx={{ height: 4, borderRadius: 2 }} />
                    )}
                    {item.error && <Typography variant="caption" color="error.main" display="block">{item.error}</Typography>}
                  </Box>
                );
              })}
            </Stack>
          </Paper>
        )}

        <Stack direction={{ xs: "column", sm: "row" }} spacing={1} alignItems={{ sm: "center" }}>
          <TextField
            size="small"
            value={filter}
            onChange={(event) => setFilter(event.target.value)}
            placeholder={pick(language, T.filter)}
            slotProps={{ htmlInput: { "aria-label": pick(language, T.filter), dir: "auto" }, input: { startAdornment: <InputAdornment position="start"><SearchRoundedIcon fontSize="small" /></InputAdornment> } }}
            sx={{ minWidth: { sm: 260 } }}
          />
          {selectable && allKeys.length > 0 && (
            <Button size="small" onClick={() => setSelected(allSelected ? new Set() : new Set(allKeys))}>{pick(language, T.selectAll)}</Button>
          )}
          {selectable && selected.size > 0 && (
            <Stack direction="row" spacing={1} alignItems="center">
              <Chip label={t(T.selected, { n: formatNumber(selected.size, language) })} onDelete={() => setSelected(new Set())} />
              <Button size="small" color="error" startIcon={<DeleteOutlineRoundedIcon />} disabled={working} onClick={() => void deleteSelected()}>{pick(language, T.deleteSelected)}</Button>
            </Stack>
          )}
        </Stack>

        <Box sx={{ border: 1, borderRadius: 1, borderStyle: dragging ? "dashed" : "solid", borderColor: dragging ? "primary.main" : "divider", overflow: "hidden" }}>
          {loading && <LinearProgress />}
          <ResponsiveList
            label={pick(language, T.listLabel)}
            rows={entries}
            rowKey={(entry) => entry.key}
            columns={columns}
            card={{
              title: entryName,
              meta: (entry) => (entry.kind === "file" ? <>{formatBytes(entry.object.size, language)} · <RelativeTime value={entry.object.last_modified ?? null} /></> : null)
            }}
            actions={actions}
            onRowClick={(entry) => (entry.kind === "folder" ? setPrefix(entry.key) : startDownload(bucket, entry.key))}
            dense
            empty={loading ? null : needle ? (
              <EmptyState compact icon={SearchRoundedIcon} title={t(T.noMatchTitle, { q: filter.trim() })} body={pick(language, T.noMatchBody)} action={<Button onClick={() => setFilter("")}>{pick(language, { fa: "پاک کردن جست‌وجو", en: "Clear search" })}</Button>} />
            ) : (
              <EmptyState
                compact
                icon={FolderOpenRoundedIcon}
                title={pick(language, T.emptyTitle)}
                body={pick(language, canWrite ? T.emptyBody : T.emptyReadOnly)}
                action={canWrite ? <Button variant="contained" startIcon={<UploadRoundedIcon />} onClick={() => fileInput.current?.click()}>{pick(language, T.upload)}</Button> : undefined}
              />
            )}
          />
          {next && (
            <Box sx={{ p: 1, textAlign: "center" }}>
              <Button disabled={loading} onClick={() => void load(prefix, next)} sx={{ minHeight: 44 }}>{pick(language, T.loadMore)}</Button>
            </Box>
          )}
        </Box>
      </Stack>
      {dragging && (
        <Box aria-hidden sx={{ position: "absolute", inset: 0, display: "grid", placeItems: "center", bgcolor: "rgba(45,212,191,.12)", border: 2, borderStyle: "dashed", borderColor: "primary.main", borderRadius: 1, pointerEvents: "none" }}>
          <Typography fontWeight={760}>{pick(language, T.dropHere)}</Typography>
        </Box>
      )}
      {shareKey && <ShareDialog bucket={bucket} objectKey={shareKey} onClose={() => setShareKey(null)} />}
      {naming?.mode === "folder" && (
        <NameDialog
          title={pick(language, T.folderTitle)}
          hint={t(T.folderHint, { place: prefix ? baseName(prefix) : bucket })}
          label={pick(language, T.folderName)}
          saveLabel={pick(language, T.create)}
          validate={(value) => (value.replace(/^\/+|\/+$/g, "").includes("/") ? pick(language, T.folderRule) : null)}
          onClose={() => setNaming(null)}
          onSubmit={async (value) => {
            const clean = value.replace(/^\/+|\/+$/g, "");
            await mutateJson(`${BASE}/${encodeURIComponent(bucket)}/folders`, { method: "POST", body: { prefix: `${prefix}${clean}/` } });
            setNaming(null);
            notify({ message: t(T.folderCreated, { name: clean }) });
            await load(prefix);
          }}
        />
      )}
      {naming?.mode === "rename" && (
        <NameDialog
          title={pick(language, T.rename)}
          hint={pick(language, T.renameHint)}
          label={pick(language, T.newPath)}
          initial={naming.key}
          saveLabel={pick(language, T.save)}
          onClose={() => setNaming(null)}
          onSubmit={async (target) => {
            const key = naming.key;
            if (target === key) {
              setNaming(null);
              return;
            }
            const to = key.endsWith("/") && !target.endsWith("/") ? `${target}/` : target;
            await mutateJson(`${BASE}/${encodeURIComponent(bucket)}/objects/move`, { method: "POST", body: { from: key, to } });
            setNaming(null);
            notify({ message: pick(language, T.moved) });
            await load(prefix);
          }}
        />
      )}
      {dialog}
      {snackbar}
    </Box>
  );
}
