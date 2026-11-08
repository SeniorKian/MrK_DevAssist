#!/usr/bin/env node
/**
 * check-copy: keeps Persian copy free of machine-like text (docs/33 §2, §3 "Process rule").
 *
 * For every Persian string in src/**\/*.ts(x) (string literals, template literals, JSX text) it reports:
 *   - latin:      a Latin word that is not a brand/product name (src/copy/latin-allowlist.json → brands),
 *                 not a technical literal (contains . / : @ _ = # or a digit: hostnames, paths, versions,
 *                 env names), not inside «…» quotes (examples the user types), and not a glossary term
 *                 inside (parentheses) (allowlist → parenthetical).
 *   - permission: a raw permission id such as `upstream:write` (users must see role/permission NAMES).
 *
 * Escape hatches (use sparingly, reviewers check them):
 *   - a `copy-ok` comment on the same line or the line above skips that line;
 *   - values of object keys starting with `adv_` (Advanced-only technical copy) are skipped.
 *
 * Usage:
 *   node scripts/check-copy.mjs                 # counts per file; warning only (exit 0)
 *   npm run check:copy                          # = --strict --list (CI gate): lists and fails on any finding
 *   node scripts/check-copy.mjs --list          # also print every finding
 *   node scripts/check-copy.mjs --only kit,copy,nav   # only those areas; fails (exit 1) on any finding
 *   node scripts/check-copy.mjs --strict        # fail on any finding anywhere
 *   node scripts/check-copy.mjs --json          # machine-readable output
 * Areas for --only: kit (src/kit/**), copy (src/copy/**), nav (src/nav.ts), or any path prefix under src/.
 */
import { readFileSync, readdirSync, statSync } from "node:fs";
import { dirname, join, relative, sep } from "node:path";
import { fileURLToPath } from "node:url";

const ROOT = join(dirname(fileURLToPath(import.meta.url)), "..");
const SRC = join(ROOT, "src");
const allowlist = JSON.parse(readFileSync(join(SRC, "copy", "latin-allowlist.json"), "utf8"));
const BRANDS = new Set(allowlist.brands.map((word) => word.toLowerCase()));
const PARENTHETICAL = new Set(allowlist.parenthetical.map((word) => word.toLowerCase()));

const args = process.argv.slice(2);
const flag = (name) => args.includes(name);
const onlyIndex = args.indexOf("--only");
const onlyAreas = onlyIndex >= 0 ? (args[onlyIndex + 1] ?? "").split(",").map((item) => item.trim()).filter(Boolean) : null;
const AREA_PREFIX = { kit: "kit/", copy: "copy/", nav: "nav.ts" };
const listAll = flag("--list") || flag("--verbose") || Boolean(onlyAreas);
const strict = flag("--strict") || Boolean(onlyAreas);
const asJson = flag("--json");

const PERSIAN = /[؀-ۿﭐ-﷿ﹰ-﻿]/;
const PERMISSION = /\b[a-z]+:[a-z]+(?::[a-z]+)*\b/g;
// A Latin word, including leading/trailing technical characters so "/data" or "v1.2" stay one token.
const LATIN_TOKEN = /[A-Za-z0-9+#._/:@=\-]*[A-Za-z][A-Za-z0-9+#._/:@=\-']*/g;

function walk(dir, out = []) {
  for (const name of readdirSync(dir)) {
    const full = join(dir, name);
    const stat = statSync(full);
    if (stat.isDirectory()) {
      if (name === "node_modules" || name.startsWith(".")) continue;
      walk(full, out);
    } else if (/\.(ts|tsx)$/.test(name) && !name.endsWith(".d.ts")) {
      out.push(full);
    }
  }
  return out;
}

/** Extract text segments that may be user-visible: string/template literals and JSX text. */
function extractSegments(source, isTsx) {
  const segments = [];
  let i = 0;
  const n = source.length;
  let lastSignificant = "";
  const push = (text, start, kind) => {
    if (PERSIAN.test(text)) segments.push({ text, start, kind });
  };
  const regexAllowedAfter = new Set(["", "(", ",", "=", ":", "[", "!", "&", "|", "?", "{", "}", ";", "+", "-", "*", "%", "~", "^", "\n"]);

  function readQuoted(quote) {
    const start = i;
    i++;
    let text = "";
    while (i < n && source[i] !== quote) {
      if (source[i] === "\\") {
        text += source[i] + (source[i + 1] ?? "");
        i += 2;
        continue;
      }
      if (source[i] === "\n") break;
      text += source[i];
      i++;
    }
    i++;
    push(text, start + 1, "string");
  }

  function readTemplate() {
    i++; // skip `
    let text = "";
    let textStart = i;
    while (i < n) {
      const ch = source[i];
      if (ch === "\\") {
        text += ch + (source[i + 1] ?? "");
        i += 2;
        continue;
      }
      if (ch === "`") {
        i++;
        break;
      }
      if (ch === "$" && source[i + 1] === "{") {
        // Placeholder: keep a neutral marker so word boundaries survive, then skip the expression.
        text += " {x} ";
        i += 2;
        readCode(1);
        continue;
      }
      text += ch;
      i++;
    }
    push(text, textStart, "template");
  }

  /** Read code until the brace depth returns to zero (for template expressions) or EOF. */
  function readCode(depth) {
    while (i < n) {
      const ch = source[i];
      const next = source[i + 1];
      if (ch === "/" && next === "/") {
        while (i < n && source[i] !== "\n") i++;
        continue;
      }
      if (ch === "/" && next === "*") {
        const end = source.indexOf("*/", i + 2);
        i = end < 0 ? n : end + 2;
        continue;
      }
      if (ch === "'" || ch === '"') {
        readQuoted(ch);
        lastSignificant = "a";
        continue;
      }
      if (ch === "`") {
        readTemplate();
        lastSignificant = "a";
        continue;
      }
      if (ch === "/" && next !== ">" && lastSignificant !== "<" && (regexAllowedAfter.has(lastSignificant) || /\b(return|typeof|case|in|of)$/.test(source.slice(Math.max(0, i - 8), i).trimEnd()))) {
        // Regex literal.
        i++;
        let inClass = false;
        while (i < n) {
          const c = source[i];
          if (c === "\\") {
            i += 2;
            continue;
          }
          if (c === "\n") break;
          if (c === "[") inClass = true;
          else if (c === "]") inClass = false;
          else if (c === "/" && !inClass) break;
          i++;
        }
        i++;
        while (i < n && /[a-z]/i.test(source[i])) i++;
        lastSignificant = "a";
        continue;
      }
      if (ch === "{") depth++;
      if (ch === "}") {
        depth--;
        if (depth === 0) {
          i++;
          return;
        }
      }
      if (isTsx && PERSIAN.test(ch)) {
        // JSX text: extend to the surrounding <, >, {, } on this line.
        let start = i;
        while (start > 0 && !"<>{}\n".includes(source[start - 1])) start--;
        let end = i;
        while (end < n && !"<>{}\n".includes(source[end])) end++;
        push(source.slice(start, end), start, "jsx");
        i = end;
        lastSignificant = "a";
        continue;
      }
      if (!/\s/.test(ch)) lastSignificant = /[A-Za-z0-9_$)\]]/.test(ch) ? "a" : ch;
      i++;
    }
  }

  readCode(Number.POSITIVE_INFINITY);
  return segments;
}

function lineStarts(source) {
  const starts = [0];
  for (let index = 0; index < source.length; index++) if (source[index] === "\n") starts.push(index + 1);
  return starts;
}

function lineOf(starts, offset) {
  let lo = 0;
  let hi = starts.length - 1;
  while (lo < hi) {
    const mid = (lo + hi + 1) >> 1;
    if (starts[mid] <= offset) lo = mid;
    else hi = mid - 1;
  }
  return lo + 1;
}

/** Remove parts that are allowed to contain Latin: {placeholders}, «quoted examples». */
function maskAllowed(text) {
  return text.replace(/\{[A-Za-z_][A-Za-z0-9_]*\}/g, " ").replace(/«[^»]*»/g, (match) => (PERSIAN.test(match) ? match : " "));
}

function isTechnical(token) {
  return /[./:@_=#]|\d/.test(token);
}

function insideParens(text, index) {
  const open = text.lastIndexOf("(", index);
  const close = text.lastIndexOf(")", index);
  if (open <= close) return false;
  const after = text.indexOf(")", index);
  return after >= 0;
}

function checkText(text) {
  const findings = [];
  for (const match of text.matchAll(PERMISSION)) findings.push({ type: "permission", word: match[0] });
  const masked = maskAllowed(text).replace(PERMISSION, " ");
  for (const match of masked.matchAll(LATIN_TOKEN)) {
    const word = match[0].replace(/[.:,;'\-]+$/, "");
    if (!word) continue;
    const lower = word.toLowerCase();
    if (BRANDS.has(lower)) continue;
    if (isTechnical(word)) continue;
    if (PARENTHETICAL.has(lower) && insideParens(masked, match.index)) continue;
    // "Docker Hub" style compounds where every part is a brand are fine; single letters (e.g. "A") too.
    if (word.length === 1) continue;
    findings.push({ type: "latin", word });
  }
  return findings;
}

const files = walk(SRC).sort();
const report = [];
for (const file of files) {
  const rel = relative(SRC, file).split(sep).join("/");
  if (onlyAreas && !onlyAreas.some((area) => rel.startsWith(AREA_PREFIX[area] ?? area))) continue;
  const source = readFileSync(file, "utf8");
  const starts = lineStarts(source);
  const lines = source.split("\n");
  const findings = [];
  for (const segment of extractSegments(source, file.endsWith(".tsx"))) {
    const line = lineOf(starts, segment.start);
    const lineText = lines[line - 1] ?? "";
    const prevText = lines[line - 2] ?? "";
    if (/copy-ok/.test(lineText) || /copy-ok/.test(prevText)) continue;
    const before = source.slice(Math.max(0, segment.start - 80), segment.start - 1);
    if (/\badv_\w*\s*[:=]\s*$/.test(before)) continue;
    for (const finding of checkText(segment.text)) {
      findings.push({ ...finding, line, snippet: segment.text.trim().slice(0, 90) });
    }
  }
  if (findings.length) report.push({ file: rel, findings });
}

const total = report.reduce((sum, item) => sum + item.findings.length, 0);
if (asJson) {
  console.log(JSON.stringify({ total, files: report }, null, 2));
} else {
  const scope = onlyAreas ? ` (only: ${onlyAreas.join(", ")})` : "";
  if (total === 0) {
    console.log(`check-copy: no machine-like text in Persian copy${scope}.`);
  } else {
    console.log(`check-copy: ${total} finding(s) in ${report.length} file(s)${scope}`);
    const width = Math.max(...report.map((item) => item.file.length));
    for (const item of [...report].sort((a, b) => b.findings.length - a.findings.length)) {
      const latin = item.findings.filter((f) => f.type === "latin").length;
      const perm = item.findings.length - latin;
      console.log(`  ${item.file.padEnd(width)}  ${String(item.findings.length).padStart(4)}   latin ${latin}${perm ? `, permission ids ${perm}` : ""}`);
    }
    if (listAll) {
      console.log("");
      for (const item of report) {
        for (const finding of item.findings) {
          console.log(`src/${item.file}:${finding.line}  [${finding.type}] "${finding.word}"  ← ${finding.snippet}`);
        }
      }
    } else {
      console.log("\nRun with --list to see every finding. Allowlist: src/copy/latin-allowlist.json");
    }
  }
}
process.exit(strict && total > 0 ? 1 : 0);
