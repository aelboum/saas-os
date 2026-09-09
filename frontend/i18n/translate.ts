import type { SupportedLocale } from "./locales";
import type { Dictionary, PluralTranslationKey, TranslationKey } from "./dictionaries/types";

export type TranslationParams = Record<string, string | number>;

function getPath(dictionary: Dictionary, path: string): string | undefined {
  const value = path.split(".").reduce<unknown>((node, segment) => {
    if (node && typeof node === "object" && segment in node) {
      return (node as Record<string, unknown>)[segment];
    }
    return undefined;
  }, dictionary);
  return typeof value === "string" ? value : undefined;
}

// Replaces `{{param}}` tokens. Renders through React text content (never
// dangerouslySetInnerHTML), so interpolated values are always
// React-escaped — no HTML injection path through a translation string
// (Phase 10.1 Security Requirements).
export function interpolate(template: string, params?: TranslationParams): string {
  if (!params) return template;
  return template.replace(/\{\{\s*(\w+)\s*\}\}/g, (match, name: string) => {
    const value = params[name];
    return value === undefined ? match : String(value);
  });
}

/**
 * Deterministic missing-translation behavior: active locale's dictionary,
 * then the fallback locale's dictionary, then the raw key itself (never a
 * blank string, never a thrown error). A dev-only console warning surfaces
 * the gap without affecting rendered output.
 */
export function t(
  dictionary: Dictionary,
  fallbackDictionary: Dictionary,
  key: TranslationKey,
  params?: TranslationParams,
): string {
  const value = getPath(dictionary, key) ?? getPath(fallbackDictionary, key);
  if (value === undefined) {
    if (process.env.NODE_ENV !== "production") {
      console.warn(`[i18n] missing translation key: "${key}"`);
    }
    return key;
  }
  return interpolate(value, params);
}

/**
 * Plural-aware lookup. Selects a CLDR plural category via Intl.PluralRules
 * for the given locale/count, looks up "<baseKey>_<category>", and falls
 * back to "<baseKey>_other" for any category a locale's dictionary doesn't
 * define a dedicated variant for (every dictionary always defines
 * "_other" — see Dictionary's type). `count` is merged into params so
 * "{{count}}" can be used directly in the translated string.
 */
export function tPlural(
  dictionary: Dictionary,
  fallbackDictionary: Dictionary,
  baseKey: PluralTranslationKey,
  count: number,
  locale: SupportedLocale,
  params?: TranslationParams,
): string {
  const category = new Intl.PluralRules(locale).select(count);
  const candidateKey = `${baseKey}_${category}` as TranslationKey;
  const otherKey = `${baseKey}_other` as TranslationKey;

  const mergedParams: TranslationParams = { ...params, count };
  const value =
    getPath(dictionary, candidateKey) ??
    getPath(dictionary, otherKey) ??
    getPath(fallbackDictionary, candidateKey) ??
    getPath(fallbackDictionary, otherKey);

  if (value === undefined) {
    if (process.env.NODE_ENV !== "production") {
      console.warn(`[i18n] missing plural translation key: "${baseKey}"`);
    }
    return baseKey;
  }
  return interpolate(value, mergedParams);
}
