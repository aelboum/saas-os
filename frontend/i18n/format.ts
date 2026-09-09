import type { SupportedLocale } from "./locales";

// Thin, locale-driven wrappers over the platform's built-in Intl APIs
// (Phase 10.1 Architecture Requirements: prefer Intl over custom formatting
// logic). No formatting convention is ever hard-coded — the active locale
// is always the caller-supplied parameter, never assumed.
export function formatDate(
  date: Date,
  locale: SupportedLocale,
  options?: Intl.DateTimeFormatOptions,
): string {
  return new Intl.DateTimeFormat(locale, options).format(date);
}

export function formatNumber(
  value: number,
  locale: SupportedLocale,
  options?: Intl.NumberFormatOptions,
): string {
  return new Intl.NumberFormat(locale, options).format(value);
}
