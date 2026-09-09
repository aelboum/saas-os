"use client";

import type { ChangeEvent } from "react";
import { useI18n } from "@/i18n/context";

// Language autonyms (each language's name in itself), not translatable
// content — "Français" is always "Français" regardless of the active UI
// locale, so these deliberately live outside the Dictionary/translation
// system rather than as a translation key.
const LOCALE_LABELS: Record<string, string> = {
  en: "English",
  fr: "Français",
  ar: "العربية",
};

/**
 * A native <select> rather than a custom widget: keyboard operability
 * (Tab/Arrow keys/typeahead) and screen-reader semantics come free from the
 * browser, and only supported locales are ever offered as options — no
 * color/icon-only control (Phase 10.1 Accessibility Requirements).
 */
export function LanguageSwitcher() {
  const { locale, supportedLocales, setLocale, t } = useI18n();

  const handleChange = (event: ChangeEvent<HTMLSelectElement>) => {
    setLocale(event.target.value as typeof locale);
  };

  return (
    <label>
      <span>{t("a11y.languageSwitcherLabel")}</span>
      <select
        aria-label={t("a11y.languageSwitcherLabel")}
        value={locale}
        onChange={handleChange}
      >
        {supportedLocales.map((code) => (
          <option key={code} value={code}>
            {LOCALE_LABELS[code] ?? code}
          </option>
        ))}
      </select>
    </label>
  );
}
