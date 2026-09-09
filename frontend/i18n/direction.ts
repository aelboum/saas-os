import type { SupportedLocale } from "./locales";

export type TextDirection = "ltr" | "rtl";

const RTL_LOCALES: ReadonlySet<SupportedLocale> = new Set(["ar"]);

// Pure locale -> direction mapping. Only accepts a typed SupportedLocale, so
// an unsupported/unvalidated string can never reach this function and
// produce an invalid `dir` value at the type level; resolve-locale.ts is
// responsible for validating any raw input before it becomes a
// SupportedLocale in the first place.
export function getTextDirection(locale: SupportedLocale): TextDirection {
  return RTL_LOCALES.has(locale) ? "rtl" : "ltr";
}
