// Server-only synchronous dictionary access. Statically imports every
// locale's resource module, which is fine here because this file is meant
// to be imported only by server components (e.g. app/layout.tsx) — Next.js
// never ships server-component-only code to the client bundle. Client code
// must use `./load` (loadDictionary) instead, which dynamically imports one
// locale at a time so the client bundle only ever carries the active
// locale's resources (Phase 10.1 Performance Requirements).
import type { SupportedLocale } from "../locales";
import type { Dictionary } from "./types";
import en from "./en";
import fr from "./fr";
import ar from "./ar";

const DICTIONARIES: Record<SupportedLocale, Dictionary> = { en, fr, ar };

export function getDictionary(locale: SupportedLocale): Dictionary {
  return DICTIONARIES[locale];
}

export type { Dictionary } from "./types";
export type { TranslationKey, PluralTranslationKey } from "./types";
