"use client";

import {
  createContext,
  useCallback,
  useContext,
  useMemo,
  useState,
  type ReactNode,
} from "react";
import { useRouter } from "next/navigation";
import {
  FALLBACK_LOCALE,
  SUPPORTED_LOCALES,
  isSupportedLocale,
  type SupportedLocale,
} from "./locales";
import { getTextDirection, type TextDirection } from "./direction";
import type { Dictionary, PluralTranslationKey, TranslationKey } from "./dictionaries/types";
import { loadDictionary } from "./dictionaries/load";
import enFallbackDictionary from "./dictionaries/en";
import { t as translate, tPlural as translatePlural, type TranslationParams } from "./translate";
import { formatDate as formatDateIntl, formatNumber as formatNumberIntl } from "./format";
import { LOCALE_COOKIE_MAX_AGE_SECONDS, LOCALE_COOKIE_NAME } from "./cookie";

// This module hard-codes the "en" dictionary as the fallback resource so it
// is always available synchronously (no locale should ever be one network
// chunk away from having *any* fallback text). Guarded so a future change to
// FALLBACK_LOCALE in locales.ts can't silently desync from this import.
if (FALLBACK_LOCALE !== "en") {
  throw new Error(
    "i18n/context.tsx imports the 'en' dictionary as the fallback; update this import to match FALLBACK_LOCALE.",
  );
}

interface I18nContextValue {
  locale: SupportedLocale;
  direction: TextDirection;
  supportedLocales: readonly SupportedLocale[];
  setLocale: (locale: SupportedLocale) => void;
  t: (key: TranslationKey, params?: TranslationParams) => string;
  tPlural: (baseKey: PluralTranslationKey, count: number, params?: TranslationParams) => string;
  formatDate: (date: Date, options?: Intl.DateTimeFormatOptions) => string;
  formatNumber: (value: number, options?: Intl.NumberFormatOptions) => string;
}

const I18nContext = createContext<I18nContextValue | null>(null);

interface I18nProviderProps {
  initialLocale: SupportedLocale;
  initialDictionary: Dictionary;
  children: ReactNode;
}

/**
 * Client-side locale/translation state, seeded from server-resolved props
 * so the first client render matches the server-rendered markup exactly
 * (no hydration mismatch). Locale switching loads the target dictionary
 * before committing the new locale, so `locale` and `dictionary` always
 * change together — no interval where formatting/direction reflect one
 * locale while translated text reflects another.
 */
export function I18nProvider({ initialLocale, initialDictionary, children }: I18nProviderProps) {
  const router = useRouter();
  const [locale, setLocaleState] = useState<SupportedLocale>(initialLocale);
  const [dictionary, setDictionary] = useState<Dictionary>(initialDictionary);

  const setLocale = useCallback(
    (next: SupportedLocale) => {
      if (!isSupportedLocale(next) || next === locale) return;

      void loadDictionary(next).then((nextDictionary) => {
        // Locale preference only — not session/auth state, so a plain
        // client-writable cookie is sufficient (see ./cookie.ts).
        document.cookie = `${LOCALE_COOKIE_NAME}=${next}; path=/; max-age=${LOCALE_COOKIE_MAX_AGE_SECONDS}; samesite=lax`;
        setDictionary(nextDictionary);
        setLocaleState(next);
        // Re-renders server components (root layout's <html lang/dir>) with
        // the new cookie value. Not a full page reload/navigation, so
        // existing client component state is preserved.
        router.refresh();
      });
    },
    [locale, router],
  );

  const value = useMemo<I18nContextValue>(
    () => ({
      locale,
      direction: getTextDirection(locale),
      supportedLocales: SUPPORTED_LOCALES,
      setLocale,
      t: (key, params) => translate(dictionary, enFallbackDictionary, key, params),
      tPlural: (baseKey, count, params) =>
        translatePlural(dictionary, enFallbackDictionary, baseKey, count, locale, params),
      formatDate: (date, options) => formatDateIntl(date, locale, options),
      formatNumber: (value, options) => formatNumberIntl(value, locale, options),
    }),
    [locale, dictionary, setLocale],
  );

  return <I18nContext.Provider value={value}>{children}</I18nContext.Provider>;
}

export function useI18n(): I18nContextValue {
  const ctx = useContext(I18nContext);
  if (!ctx) {
    throw new Error("useI18n must be used within an I18nProvider");
  }
  return ctx;
}
