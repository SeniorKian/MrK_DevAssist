# MRK admin kit: how to build a page

The owner's brief: *so simple a 5-year-old can use it; no machine-like text; Advanced is complete.*
Every Phase 1 page is built from this kit (`src/kit`) and the shared copy (`src/copy`), and its
nav entry lives in `src/nav.ts`. Plan: `docs/33-ux-redesign-plan.md` (§1 IA, §2 writing guide, §4 Simple/Advanced, §6 kit).

```ts
import { PageHeader, GroupTabs, SectionCard, StatusPill, EmptyState, FriendlyError, useKit } from "./kit";
import { pick, commonWords, errorSentence, term, statusWord, humanizeAudit, roleName, CONFIRM_WORDS } from "./copy";
```

Import from `./kit` and `./copy` only (barrels). Don't deep-import, and don't copy kit code into a page.
If you need a change to the kit, keep a small local component in your own file and flag it in your report, so it can be promoted later.

---

## 1. Page anatomy

```tsx
export default function PackagesPage({ user }: { user: AuthUser }) {
  const { language, isAdvanced, c } = useKit();          // c = generic words («ذخیره», «تازه کردن», …)
  const tab = useGroupTab("packages", "search");          // follows #/packages/<tab>
  return (
    <>
      <PageHeader
        title={pick(language, { fa: "بسته‌ها", en: "Packages" })}
        subtitle={pick(language, { fa: "بسته‌هایی که روی این سرور ذخیره شده‌اند را پیدا کنید.", en: "Find packages stored on this server." })}
        icon={Inventory2RoundedIcon}
        primaryAction={<Button variant="contained">…one verb…</Button>}
        tabs={<GroupTabs group="packages" permissions={user.permissions} />}
      />
      {tab === "search" && <SearchTab />}
      …
    </>
  );
}
```

Rules:

- **One primary verb per view** (`PageHeader.primaryAction`). It becomes a sticky full-width bottom button on phones.
- Content goes in `SectionCard`s. Lists use `ResponsiveList` (a table on desktop, cards on phones).
- **Empty lists use `EmptyState`**: «هنوز … ندارید» + why it helps + one button. Never write «داده‌ای یافت نشد».
- **Errors use `FriendlyError`** (or `errorSentence()` in toasts). Never print `error.code`, `error.detail`, an HTTP status, a task id or `last_error` in Simple mode.
- **Statuses use `StatusPill status="running"`**. Never print `item.status` raw. Unknown values become «نامشخص».
- **Permissions**: hide or disable with `PermissionGate` / `useCan`, and explain with `NoAccess`, which names the role («این کار از «مدیر» به بالا برمی‌آید»). Never show `upstream:write`.
- Dangerous actions go through `ConfirmAction` / `useConfirmAction`, inside a `⋮` menu or a `DangerZone`. Reversible actions don't confirm: they use `useUndoSnackbar`.
- Anything with more than 3 fields is an `ActionWizard` (one step per screen on phones, with a "test before save" step).
- Show a secret once with `OneTimeSecret` (the user must tick «کپی کردم» before they can close it).
- A page's «every setting of this section» block is `<RegistrySettings groups={["server.resources"]} exclude={[…keys the page edits itself]} permissions={…} title={…} />` (Advanced only; `keys` picks single keys). Don't write your own registry adapter.
- Helper/module states (server helper not connected, not answering, part missing on this server version) use `HelperNotice` / `helperProblem(error)`.

## 2. Simple vs Advanced

The mode is presentation only. RBAC, confirmations and audit are identical in both modes.

| Simple keeps | Advanced adds |
|---|---|
| 1–3 everyday, safe, reversible verbs per tab | extra columns, raw ids, technical keys (LTR, muted) |
| presets («هر شب», «۸ ساعت») | raw cron, seconds, JSON/regex editors |
| plain sentences | collapsed «جزئیات فنی» (code, status, backend message) in `FriendlyError` |
| relative times («۱۰ دقیقه پیش») | absolute Jalali times (`RelativeTime` switches automatically) |
| | every tunable of the module (`SettingsForm`), `DangerZone`, advanced-only tabs (`nav.ts advancedOnly`) |

Tools: `isAdvanced` from `useKit()`, `<AdvancedOnly>`, `<AdvancedSection>`, `SectionCard advanced`,
`ResponsiveList` columns with `advancedOnly`, and `KeyValueList` items with `advancedOnly`.

## 3. Writing rules (short version of docs/33 §2)

1. **Natural, polite-informal Persian.** «پشتیبان گرفته شد», «می‌خواهید ادامه دهید؟». Not «عملیات با موفقیت انجام گردید».
2. **What happened + why it matters + what to do.** Never a bare «ناموفق بود» or «نامعتبر است». State the rule instead: «پورت باید عددی بین ۱ تا ۶۵۵۳۵ باشد».
3. **Active voice, named subject, never blame the user.** «MRK نتوانست به Dokploy وصل شود». «این نام قبلاً گرفته شده؛ نام دیگری بنویسید».
4. **≤ 15 words per sentence** in Simple mode. Put details behind `HelpTip` or «چرا؟».
5. **No English in Persian copy** except brand and product names (npm, PyPI, Docker, Dokploy, S3, DNS, MRK …; see `copy/latin-allowlist.json`). Technical literals such as hostnames, paths, versions and commands stay Latin and are wrapped in `<Ltr>`. A glossary term may appear in parentheses on its first use on a page: `<Term k="upstream" first />` → «منبع دریافت (upstream)». Never put English in a button or a pill.
6. **Use the glossary** (`copy/glossary.ts`, `term(language, "bucket")`): منبع دریافت, پوشه اصلی, دستیار سرور, کلید برنامه, پشتیبان, کار …
7. **One word per meaning**: «تازه کردن» = refresh; «به‌روزرسانی» = update to a new version; «پشتیبان» = backup (never «بکاپ»); «کار» = background job; «روشن/خاموش» for features; «فعال/غیرفعال» for accounts.
8. **Buttons are verbs naming the result**: «ساخت پشتیبان», «وصل کن», «امتحان اتصال». In-progress: «در حال ساخت…». Success toast: past tense + object: «پشتیبان "DB اصلی" ساخته شد».
9. **Numbers and dates**: Persian digits in fa (`Num`, `Bytes`, `Percent`, `Duration`, `formatNumber`). Dates are relative, with the absolute Jalali date in a tooltip (`RelativeTime`). Never show `28800`: use `Duration` («۸ ساعت»).
10. **Confirmations**: the title is a question naming the object («پشتیبان "DB اصلی" پاک شود؟»). The body says what happens, whether it can be undone, and who is affected. Buttons: «بله، پاک کن» / «نه، بماند». Typed confirmations use a word any keyboard can type («پاک کن», «قطع کن», «فعال کن», or the object's name); the page sends the backend token (`CONFIRM_WORDS.prune.token`).
11. **Internal words are banned**: gate, control plane / کنترل‌پلین, appliance / اپلاینس, payload, seed, envelope, RBAC.

`npm run check:copy` reports Latin words and permission ids in Persian strings, per file.
`npm run check:copy:kit` (`--only kit,copy,nav`) must stay at zero. In Phase 1, run
`node scripts/check-copy.mjs --only <yourFile.tsx>` (any path prefix under `src/` works) and reach zero for the files you own.
The escape hatches (`// copy-ok` on the line, or object keys starting with `adv_` for Advanced-only technical copy) are reviewed. Don't use them for normal copy.

## 4. Components (props)

All components read the language and mode from `useKit()` (built on `uiMode.tsx`), so pages don't pass `language`.

| Component | Props | Notes |
|---|---|---|
| `useKit()` | → `{ language, mode, setMode, isAdvanced, isFa, dir, c }` | `c` = `commonWords(language)` |
| `PageHeader` | `title, subtitle?, icon?, primaryAction?, secondaryActions?, tabs?, level?` | one h1 per page; on phones it is sticky and the primary action moves to a bottom bar (respects `--mrk-bottom-nav-height`) |
| `GroupTabs` | `group, permissions, value?, onChange?` | hash-synced `#/group/tab`; filters by permission and mode; scrollable; hidden when only 1 tab |
| `useGroupTab(group, fallback)` | → current tab key | follows `hashchange` |
| `SectionCard` | `title?, hint?, action?, status?, children, collapsible?, defaultCollapsed?, advanced?, flush?, tone?` | `advanced` → renders only in Advanced; `tone="danger"\|"warning"` adds an accent border |
| `StatusPill` | `status?` *or* `tone? + label?`, `size?` | dot + word (never colour alone); `busy` tone shows a spinner; words from `copy/kinds STATUS_WORDS` |
| `EmptyState` | `title, body?, icon?, action?, compact?` | |
| `FriendlyError` | `error, title?, onRetry?, onAction?, noAction?, severity?, onClose?, inline?, scope?` | sentence + one action button (`retry/reload/signIn/askAdmin/pairAgent/connectDokploy/fixFields/refreshList`); Advanced: collapsed technical details with a copy button |
| `ConfirmAction` | `open, title, body?, consequences?, undoable?, severity?("disruptive"\|"destructive"), typed?: ConfirmWord, confirmLabel?, cancelLabel?, busy?, error?, children?, confirmDisabled?, onConfirm, onClose` | the destructive button never has default focus; typed matching ignores spaces, half-spaces, ي/ی, digits and case; full screen on phones |
| `useConfirmAction()` | → `{ ask(options): Promise<boolean>, dialog }` | render `{dialog}` once in the page; no provider needed |
| `ActionWizard` | `open, title, steps: WizardStep[], onFinish, onClose, finishLabel?, done?` | `WizardStep = { key, title, hint?, render, validate?() → string\|null, onNext?(): Promise, nextLabel?, optional? }`; throw from `onNext`/`onFinish` to show a FriendlyError and stay on the step; `done` = content shown after success |
| `OneTimeSecret` (`SecretOnce`) | `open, title, body?, items: {label, value, ltr?, multiline?}[], message?: {label, value}, onClose` | it can't be closed until «کپی کردم» is ticked |
| `ResponsiveList<T>` | `rows, rowKey, columns: ListColumn<T>[], card: {title, meta?, status?}, actions?: RowAction<T>[], label, empty?, onRowClick?, dense?` | `ListColumn = {key, header, render, advancedOnly?, ltr?, align?, width?, hideOnCard?}`; `RowAction = {key, label, icon?, onClick, danger?, disabled?, hidden?, advancedOnly?}` in a `⋮` menu (44 px targets) |
| `KeyValueList` | `items: {label, value, ltr?, copy?, advancedOnly?, hint?}[], dense?` | `<dl>`; 2 columns ≥ sm |
| `CopyField` | `label, value, ltr?(true), multiline?, helperText?, masked?` | read-only + copy + “copied” feedback |
| `CopyButton` / `useCopy()` | `value, label?, size?` / → `[copy, copied, failed]` | |
| `StatTile` / `StatGrid` | `label, value, caption?, icon?, meter?(0–100), tone?, onClick?, href?` / `columns?` | |
| `DangerZone` | `title?, hint?, items: {title, description, action}[], simpleToo?` | Advanced only by default |
| `HelpTip` | `children?` or `term?: GlossaryKey`, `label?, learnMoreHref?` | (i) popover, keyboard accessible |
| `Term` | `k: GlossaryKey, first?, withHelp?` | the glossary word, with English in parentheses on first use |
| `NoAccess` | `needs: string\|string[], ask?, variant?("inline"\|"card")` | names the lowest role that can do it |
| `PermissionGate` | `permissions, anyOf, children, fallback?(node\|true), ask?` | `fallback={true}` → standard NoAccess |
| `useCan(permissions)` | → `(permission) => boolean` | |
| `useUndoSnackbar()` | → `{ notify({message, onUndo?, tone?}), snackbar }` | 6 s with «برگرداندن»; render `{snackbar}` once |
| `TestResult` | `outcome: {state:"idle"\|"running"} \| {state:"ok", latencyMs?, message?} \| {state:"fail", error?, code?, message?}`, `slowMs?` | the one way to show «امتحان اتصال» results |
| `Notice` | `tone?, children, action?` | calm one-line Alert |
| `AttentionList` | `items: {id, severity("critical"\|"warning"\|"info"), title, why?, action?: {label, onClick?, href?}}[], title?` | sorted by severity; hidden when empty |
| `Verdict` | `greeting, verdict, tone("ok"\|"warn"\|"error")` | Home greeting line |
| `QuickActionTile` / `QuickActionGrid` | `icon, label, hint?, onClick?, href?` | filter by permission before rendering |
| `ChecklistCard` | `steps: {key, label, done, optional?, onClick?}[], onDismiss?, title?` | hidden when all steps are done; persisting is the page's job |
| `Ltr` | `children, mono?` | `<bdi dir="ltr">` for paths, URLs and commands inside Persian text |
| `Num` / `Percent` / `Bytes` / `Duration` / `WithUnit` / `DateTime` / `RelativeTime` | `value` (`seconds` for Duration) | Persian digits, Jalali (`fa-IR-u-ca-persian`) |
| `NumberInput` | `label, value, onChange, min?, max?, integer?, unit?, helperText?, error?, disabled?` | accepts Persian digits; the range is explained in words |
| `DurationInput` | `label, value (seconds), onChange, min?, max?, units?, helperText?, error?` | number + unit select |
| `BytesInput` | `label, value (bytes), onChange, min?, max?` | number + KB/MB/GB/TB |
| `ListInput` | `label, value: string[], onChange, validate?, max?, ltr?, suggestions?` | chips; Enter, comma or paste |
| `PercentSlider` | `label, value, onChange, min?, max?, step?` | |
| `SchedulePicker` | `value (cron), onChange, label?, validateCron?` | presets (nightly/weekly/monthly/hourly) + hour; raw cron only in Advanced «سفارشی»; `describeSchedule(cron, lang)` → «هر شب ساعت ۲» |
| `TimezonePicker` | `label?, value, onChange` | «تهران» first |
| `SettingsForm` | `specs: SettingSpec[], permissions, onSave?(changes) → {results?}, groups?, title?, hint?, searchable?` | see below |
| `RegistrySettings` | `groups?, keys?, exclude?, permissions, title?, hint?, legacy?, simpleToo?` | the registry (docs/34 §3) filtered to a section, rendered by `SettingsForm`; Advanced only by default; shows `RestartNotice` for its keys; fixture fallback on old servers (404/405), saved through `legacy` when given |
| `useRegistrySettings(filter)` | `{groups?, keys?, exclude?, elsewhere?("hide"\|"list"), legacy?, enabled?}` → `{specs, groups, elsewhere, status, error, restart, save?, reload, refreshRestart, labelOf}` | `save` = `PUT` per key, `DELETE` when an overridden value goes back to its default; `registryItemToSpec(item)` for one item |
| `RestartNotice` | `restart, labelOf?, onlyKeys?` | «چند تغییر پس از راه‌اندازی دوباره اعمال می‌شود» + the restart command |
| `CardMenu` | `label, items: {key, label, icon?, danger?, disabled?, onClick}[]` | the ⋮ menu on a card; hidden when empty |
| `ChoiceCards<K>` | `options: {key, icon?, title, body?, badges?, disabled?, tone?}[], value: K\|null, onChange, label` | big tappable radio cards |
| `NameDialog` | `title, hint?, label, initial?, saveLabel, validate?, onSubmit (throw → FriendlyError), onClose, ltr?` | one text field dialog |
| `RangeToggle<K>` | `value, options, labelOf, onChange, label` | compact single-choice toggle (time ranges) |
| `HelperNotice` | `error, onRetry?, noPairAction?, overrides?, onClose?` | not paired → «وصل کردن دستیار سرور»; helper down / module missing → calm Notice; anything else → `FriendlyError`. Also `helperProblem(error)`, `helperProblemText(lang, error)`, `helperSentence(lang, state)`, `PAIR_AGENT_HREF` |

### SettingsForm

- Each `SettingSpec` (`kit/settings/types.ts`, same shape as BE1) renders as one row: plain name, the technical key + env (Advanced, LTR), HelpTip (description), source / restart / danger badges, the generated control (`bool`→Switch, `int/float`→NumberInput with unit, `duration`→DurationInput, `bytes`→BytesInput, `enum`→Select with plain labels, `list/cidr_list`→ListInput, `time`, `timezone`, `secret` (write-only), `json/map` (Advanced editor), `string/url/path` (LTR)), the default, and «بازگشت به پیش‌فرض».
- `source: "startup"` rows are read-only and show the effective value (a secret shows «تنظیم شده») plus «کپی خط Compose» (`MRK_X=value`). `constant` → «هنوز قابل تغییر نیست». `build` → info. `locked_by_env` → read-only, with a note. A missing `requires` permission → read-only + `NoAccess`.
- `depends_on` disables a control until its parent has the given value.
- With more than 8 rows you get search (fa/en name, key, env) and filter chips: «قابل تغییر از پنل», «فقط از فایل Compose», «نیاز به راه‌اندازی دوباره», «تغییر یافته از پیش‌فرض», «خطرناک».
- Save flow: a sticky bar shows «n تغییر ذخیره نشده» → a diff preview in `ConfirmAction` (destructive style if any change is high or critical danger) → `onSave(changes)`. Return `{ results: { key: { ok, error_code?, field_message_fa?, field_message_en? } } }` to show per-field errors. Saved values stay on screen until you pass fresh `specs`.
- Values use the spec's own unit (a `duration` with `unit: "minutes"` stores minutes). The form converts for display.

## 5. Copy modules (`src/copy`)

| Module | API |
|---|---|
| `text.ts` | `Bi = {fa, en}`, `pick(lang, bi)`, `fill(template, params, lang)` (localizes numbers), `say(lang, bi, params)`, `persianDigits(s)`, `normalizeTyped(s)` |
| `common.ts` | `COMMON` (Bi dict), `commonWords(lang)` → `{ save, cancel, refresh («تازه کردن»), retry, test («امتحان اتصال»), copy, copied, technicalDetails, resetToDefault, restartRequired, … }` |
| `glossary.ts` | `GLOSSARY[key] = {word: Bi, term, english: "first"\|"advanced"\|"never"\|"keep", hint?}`, `term(lang, key)`, `termWithEnglish(lang, key)`, `termHint(lang, key)` |
| `errors.ts` | `ERROR_CATALOG[code] = {fa, en, action?, field?}` (every backend error code), `FALLBACK_ERRORS`, `REASON_CATALOG` (BE4 `error.reason`), `describeError(lang, err)` → `{message, action, field, known, technical}`, `errorSentence(lang, err)`, `reasonFor(lang, code)` for stored `error_code`s (jobs, runs, deliveries), `ERROR_ACTION_LABEL`, `technicalSummary()` |
| `audit.ts` | `AUDIT_ACTIONS[action] = Bi` template (`{actor}`, `{target}`, `[optional part]`), `TASK_KIND_WORDS`, `AUDIT_RESULTS`, `humanizeAudit(lang, event, {actorName?, targetName?})` → `{sentence, result: {tone, label}, known}` |
| `roles.ts` | `ROLES[role]` (card: name, oneLiner, can/cannot, note, color), `PERMISSIONS[id]` (group, plain name, danger, requires), `ROLE_PERMISSIONS`, `ROLE_ORDER`, `PERMISSION_GROUP_NAMES`, `DANGER_WORDS`, `roleName(lang, role, customLabel?)`, `permissionName(lang, id)`, `lowestRoleWith(id)`, `noAccessSentence(lang, ids, ask?)`, `withDependencies(ids)` |
| `confirm.ts` | `CONFIRM_WORDS` (`prune`, `disconnect`, `enforce`, `unblockAll`, `unpair`, `stoppedMrk`, `confirm`: `{word: Bi, token}`), `CONFIRM_TOKENS.purge(eco, name)` / `.trashDelete(id)` / `.applyRestore(id)`, `nameConfirmation(name, token)`, `deleteConfirmation(token)`, `matchesConfirmation(typed, word, lang)`, `CONFIRM_COPY` |
| `kinds.ts` | `STATUS_WORDS` + `statusWord(lang, status)`, `SEVERITY_WORDS` + `severityWord`, `OUTBOUND_KIND_WORDS` + `outboundKindWord`, `CHANNEL_KIND_WORDS`, `ECOSYSTEM_WORDS`, `PROXY_TYPE_WORDS`, `EVENT_FAMILY_WORDS` (alert-rule checkboxes → patterns) |

`api.ts errorMessage(language, error)` now delegates to `errorSentence`. Existing panels get the new wording automatically, and the backend English `detail` is no longer appended.

Catalog sentences are context-neutral. If one module needs its own wording for a shared code, add `"<scope>:<code>"` to `ERROR_CATALOG` (e.g. `"firewall:invalid_rule"`) and pass `scope` (`<FriendlyError scope="firewall" />`, `errorSentence(lang, error, "firewall")`). Don't keep local error maps in pages.

`ApiError` (from `getJson`, `mutateJson`, `ensureOk`) carries the whole envelope: `code`, `detail`, `fields` (`[{field, reason_code, params}]`, read with `fieldMessages(language, error)`), `users` (`role_in_use`), `permissions` (`permission_escalation`), `requestId` (shown in «جزئیات فنی») and `extra`.

## 6. Navigation (`src/nav.ts`)

- `NAV_GROUPS`: 7 groups × tabs `{key, label, hint, anyOf, advancedOnly?, panel, keywords?}`. `NAV_UTILITIES` (settings, about). `MOBILE_PRIMARY_GROUPS`.
- Routes: `#/<group>/<tab>`. `parseHash`, `routeHref`, `utilityHref`, `resolveRoute(hash, permissions, mode)` → `{route, href, redirected}` (use `history.replaceState` when `redirected`). `visibleGroups`, `visibleTabs`, `isTabVisible`, and `searchNav(query, lang, permissions, mode)` for Ctrl+K.
- `LEGACY_ROUTES` maps the old flat hashes (`#upstreams`, `#s3`, …) to the new routes.
- `#/__kit` resolves only in dev builds. Mount it with `lazy(() => import("./kit/KitDemo"))`; it is a live gallery of every component.
- `ROUTE_ALIASES` maps other spellings (backend Home links such as `#/files/maintenance`, `#/access/people`, settings-registry `nav` values) to real tabs.
- A `?query` after the route is kept (`#/files/app-backups?new=1`). Read it with `hashQuery()` to open a wizard or filter straight away.
- The shell (`src/AppShell.tsx`) lazy-loads one page per group (`NavGroup.page`: `PackagesPage`, `ServerPage`, …, default export) and passes `ShellPageProps` = `{ user, language, permissions, tab, onUnauthorized }`. Pages render their own `PageHeader` + `GroupTabs`.

## 7. Example: a list tab

```tsx
function SourcesTab({ user }: { user: AuthUser }) {
  const { language, c } = useKit();
  const { ask, dialog } = useConfirmAction();
  const [rows, setRows] = useState<Upstream[] | null>(null);
  const [error, setError] = useState<unknown>(null);
  const can = useCan(user.permissions);
  const load = useCallback(() => getJson<{ items: Upstream[] }>("/api/v1/upstreams").then((r) => setRows(r.items), setError), []);
  useEffect(() => void load(), [load]);

  if (error) return <FriendlyError error={error} onRetry={load} />;
  return (
    <SectionCard title={term(language, "upstream")} hint={…} action={<HelpTip term="upstream" />} flush>
      <ResponsiveList
        label={…}
        rows={rows ?? []}
        rowKey={(row) => row.id}
        columns={[
          { key: "name", header: …, render: (row) => row.name },
          { key: "url", header: …, render: (row) => <Ltr>{row.url}</Ltr>, ltr: true },
          { key: "id", header: "ID", render: (row) => <Ltr mono>{row.id}</Ltr>, advancedOnly: true }
        ]}
        card={{ title: (row) => row.name, meta: (row) => <Ltr>{row.url}</Ltr>, status: (row) => <StatusPill status={row.enabled ? "enabled" : "disabled"} /> }}
        actions={can("upstream:write") ? [{
          key: "delete", label: c.remove, danger: true,
          onClick: async (row) => {
            if (!(await ask({ title: …, severity: "destructive", undoable: false }))) return;
            …
          }
        }] : undefined}
        empty={<EmptyState title={…} body={…} action={<Button variant="contained">…</Button>} />}
      />
      {!can("upstream:write") && <NoAccess needs="upstream:write" />}
      {dialog}
    </SectionCard>
  );
}
```

## 8. Quality checklist (definition of done, docs/33 §7)

- [ ] Simple mode: no Latin words except product names, no codes or ids (`check-copy --only <file>` = 0).
- [ ] Every async action has a friendly success message and a `FriendlyError` failure.
- [ ] Every empty state has an action.
- [ ] Works at 375 px (cards, sticky primary button, full-screen dialogs, 44 px targets) and at 1280 px.
- [ ] Every setting of the module is reachable in Advanced (inline `SettingsForm` or All settings).
- [ ] Every "no access" text names a role (`NoAccess`).
- [ ] Keyboard: every action is reachable with Tab, dialogs close with Escape (destructive ones are never focused by default), and icon buttons have an `aria-label`.
- [ ] Light and dark both checked; RTL and LTR both checked.
