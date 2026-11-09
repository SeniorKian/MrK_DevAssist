"use strict";
/**
 * Pre-publish size quota for «My space» npm scopes (docs/43 §0.1).
 *
 * Verdaccio middleware plugin (no dependencies). It runs after Verdaccio's JSON
 * body parser and before the publish routes, so a publish is refused before any
 * file is written. The control plane writes the limits into tenancy.json:
 *   {"scopes": [{"scope": "@acme", "quota_bytes": 1048576 | null, ...}]}
 * A PUT under a limited scope that carries tarballs is refused with HTTP 413 and
 * `quota_exceeded: ...` (npm prints the `error` field) when
 *   bytes already stored for the scope + tarball bytes (+ publishes in flight)
 * would go over the limit.
 */
const fs = require("node:fs");
const path = require("node:path");

const SCOPE = /^@[a-z0-9][a-z0-9-]{1,30}[a-z0-9]$/;

function dirBytes(root) {
  let total = 0;
  let entries;
  try {
    entries = fs.readdirSync(root, { withFileTypes: true });
  } catch {
    return 0;
  }
  for (const entry of entries) {
    const full = path.join(root, entry.name);
    if (entry.isDirectory()) total += dirBytes(full);
    else if (entry.isFile()) {
      try {
        total += fs.statSync(full).size;
      } catch {
        // removed meanwhile
      }
    }
  }
  return total;
}

function base64Bytes(data) {
  if (typeof data !== "string") return 0;
  const clean = data.replace(/\s+/g, "");
  const padding = clean.endsWith("==") ? 2 : clean.endsWith("=") ? 1 : 0;
  return Math.max(0, Math.floor((clean.length * 3) / 4) - padding);
}

/** Tarball bytes a request adds: JSON attachments, or a raw body's length. */
function incomingBytes(req) {
  const body = req.body;
  if (body && typeof body === "object" && !Buffer.isBuffer(body)) {
    let total = 0;
    for (const item of Object.values(body._attachments || {})) {
      if (item && typeof item === "object") total += base64Bytes(item.data);
    }
    return total;
  }
  const length = Number(req.headers["content-length"]);
  return Number.isFinite(length) && length > 0 ? length : 0;
}

/** "@scope" of a PUT path like /@scope%2fname or /@scope/name/-rev/1-abc. */
function scopeOf(urlPath) {
  let decoded;
  try {
    decoded = decodeURIComponent(urlPath.replace(/^\/+/, ""));
  } catch {
    return null;
  }
  const scope = decoded.split("/", 1)[0];
  return SCOPE.test(scope) ? scope : null;
}

function createQuota(options) {
  const tenancyFile = options.tenancyFile;
  const storage = options.storage;
  const inFlight = new Map();
  let cache = { key: null, limits: new Map() };

  function limits() {
    let stat;
    try {
      stat = fs.statSync(tenancyFile);
    } catch {
      return new Map();
    }
    const key = `${stat.mtimeMs}:${stat.size}`;
    if (cache.key === key) return cache.limits;
    try {
      const payload = JSON.parse(fs.readFileSync(tenancyFile, "utf8"));
      const next = new Map();
      for (const item of (payload && payload.scopes) || []) {
        if (!item || !SCOPE.test(String(item.scope))) continue;
        const value = item.quota_bytes;
        if (Number.isInteger(value) && value >= 0) next.set(item.scope, value);
      }
      cache = { key, limits: next };
    } catch {
      // Written atomically by the control plane: keep the last good copy.
    }
    return cache.limits;
  }

  function handle(req, res, next) {
    if (req.method !== "PUT") return next();
    const scope = scopeOf(req.path || req.url || "");
    if (!scope) return next();
    const limit = limits().get(scope);
    if (limit === undefined) return next();
    const incoming = incomingBytes(req);
    if (incoming <= 0) return next();
    const used = dirBytes(path.join(storage, scope)) + (inFlight.get(scope) || 0);
    if (used + incoming > limit) {
      res.status(413).json({
        error:
          `quota_exceeded: this publish (${incoming} bytes) would put ${scope} over its ` +
          `storage limit (${used} of ${limit} bytes used). Delete old versions in My space, ` +
          "or ask for a larger plan.",
        code: "quota_exceeded",
        limit,
        used,
        incoming
      });
      return undefined;
    }
    inFlight.set(scope, (inFlight.get(scope) || 0) + incoming);
    let released = false;
    const release = () => {
      if (released) return;
      released = true;
      const left = (inFlight.get(scope) || 0) - incoming;
      if (left > 0) inFlight.set(scope, left);
      else inFlight.delete(scope);
    };
    res.on("finish", release);
    res.on("close", release);
    return next();
  }

  return { handle };
}

function MrkQuotaPlugin(config) {
  const tenancyFile = config.tenancy_file || "/data/npm/config/tenancy.json";
  const storage = config.storage_dir || config.storage || "/data/npm/storage";
  const quota = createQuota({ tenancyFile, storage });
  return {
    register_middlewares(app) {
      app.use(quota.handle);
    }
  };
}

module.exports = MrkQuotaPlugin;
module.exports.createQuota = createQuota;
module.exports.scopeOf = scopeOf;
module.exports.incomingBytes = incomingBytes;
