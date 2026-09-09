// Supported-locale registry. Single source of truth for which locales the
// SaaS-OS frontend platform supports — every other i18n module (resolution,
// dictionaries, direction, formatting) derives from this list rather than
// hard-coding locale values, so adding a locale is a config addition here,
// not a scattered business-logic change (Phase 10.1 Definition of Done #11).

export const SUPPORTED_LOCALES = ["en", "fr", "ar"] as const;

export type SupportedLocale = (typeof SUPPORTED_LOCALES)[number];

export const DEFAULT_LOCALE: SupportedLocale = "en";

// Deterministic fallback chain for missing translations: try the active
// locale, then this locale, then the raw key. Kept distinct from
// DEFAULT_LOCALE in shape (even though they're equal today) because a future
// per-market default locale must not silently change fallback behavior.
export const FALLBACK_LOCALE: SupportedLocale = "en";

export function isSupportedLocale(value: string | null | undefined): value is SupportedLocale {
  return (SUPPORTED_LOCALES as readonly string[]).includes(value ?? "");
}
