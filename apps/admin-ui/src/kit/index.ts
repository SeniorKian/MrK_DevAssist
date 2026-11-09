/**
 * MRK shared component kit (docs/33 §6). Read ./README.md before building a page.
 * Import from "./kit" (or "../kit") only; do not deep-import kit files.
 */
export { useKit } from "./useKit";
export { PageHeader, type PageHeaderProps } from "./PageHeader";
export { GroupTabs, useGroupTab, type GroupTabsProps } from "./GroupTabs";
export { SectionCard, type SectionCardProps } from "./SectionCard";
export { StatusPill, type StatusPillProps } from "./StatusPill";
export { EmptyState, type EmptyStateProps } from "./EmptyState";
export { ActionWizard, type ActionWizardProps, type WizardStep } from "./ActionWizard";
export { ConfirmAction, useConfirmAction, type ConfirmActionProps, type ConfirmSeverity, type ConfirmRequestOptions } from "./ConfirmAction";
export { HelpTip, Term, type HelpTipProps, type TermProps } from "./HelpTip";
export { FriendlyError, type FriendlyErrorProps } from "./FriendlyError";
export { OneTimeSecret, SecretOnce, type OneTimeSecretProps, type SecretItem } from "./OneTimeSecret";
export { ResponsiveList, type ResponsiveListProps, type ListColumn, type RowAction } from "./ResponsiveList";
export { KeyValueList, type KeyValueItem } from "./KeyValueList";
export { CopyField, CopyButton, useCopy, type CopyFieldProps } from "./CopyField";
export { QrCode } from "./QrCode";
export { StatTile, StatGrid, type StatTileProps } from "./StatTile";
export { DangerZone, type DangerZoneProps, type DangerAction } from "./DangerZone";
export { useUndoSnackbar, TestResult, Notice, type UndoToast, type TestOutcome } from "./Feedback";
export { CardMenu, ChoiceCards, NameDialog, RangeToggle, type CardMenuItem, type ChoiceCardOption, type NameDialogProps, type RangeToggleProps } from "./Pickers";
export { HelperNotice, helperProblem, helperProblemText, helperSentence, PAIR_AGENT_HREF, type HelperProblem, type HelperNoticeProps } from "./HelperNotice";
export { NoAccess, PermissionGate, useCan, type NoAccessProps, type PermissionGateProps } from "./NoAccess";
export {
  AttentionList, Verdict, QuickActionTile, QuickActionGrid, ChecklistCard,
  type AttentionItem, type AttentionSeverity, type QuickActionTileProps, type ChecklistStep
} from "./Home";
export { Ltr, Num, Percent, Bytes, Duration, WithUnit, RelativeTime, DateTime } from "./Formatted";
export {
  NumberInput, DurationInput, BytesInput, ListInput, PercentSlider, SchedulePicker, TimezonePicker,
  parseLocalizedNumber, numberProblem, presetToCron, cronToPreset, describeSchedule,
  type NumberInputProps, type DurationInputProps, type BytesInputProps, type ListInputProps, type SchedulePickerProps, type SchedulePreset
} from "./inputs";
export { formatAbsolute, formatClock, formatRelative, formatDuration, formatSize, formatWithUnit, unitWord, dateLocale, type UnitKey } from "./formatters";
export { SettingsForm, displaySettingValue, composeLine, type SettingsFormProps } from "./settings/SettingsForm";
export type {
  SettingSpec, SettingType, SettingSource, SettingDanger, SettingUnit, SettingValue, SettingEnumOption,
  SettingsGroupInfo, SettingsRegistry, SettingResult, SettingsSaveResult
} from "./settings/types";
export { SETTINGS_FIXTURE, SETTINGS_FIXTURE_GROUPS } from "./settings/fixture";
export {
  useRegistrySettings, registryItemToSpec, registryItemLabel, registryGroupInfo, registryEditHref, saveRegistryChanges, settingResultFromError,
  REGISTRY_ENUM_WORDS,
  type RegistryFilter, type RegistrySettingsState, type RegistryElsewhereItem, type RegistryRawItem, type RegistryRawGroup, type RegistryPayload,
  type RestartStatus, type LegacySettingsAdapter
} from "./settings/registry";
export { RegistrySettings, RestartNotice, type RegistrySettingsProps, type RestartNoticeProps } from "./settings/RegistrySettings";
export { AdvancedOnly, AdvancedSection, UiModeToggle } from "../uiMode";
