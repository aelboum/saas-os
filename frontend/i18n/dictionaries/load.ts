// Client-side lazy dictionary loading. Deliberately contains no static
// import of any locale module — each case below is a separate dynamic
// import() so the bundler code-splits per locale, and only the active
// locale's resource ever ships to a given client (Phase 10.1 Performance
// Requirements: no loading every supported locale for every request).
import type { SupportedLocale } from "../locales";
import type { Dictionary } from "./types";

const cache = new Map<SupportedLocale, Dictionary>();

export async function loadDictionary(locale: SupportedLocale): Promise<Dictionary> {
  const cached = cache.get(locale);
  if (cached) return cached;

  let dictionary: Dictionary;
  switch (locale) {
    case "en":
      dictionary = (await import("./en")).default;
      break;
    case "fr":
      dictionary = (await import("./fr")).default;
      break;
    case "ar":
      dictionary = (await import("./ar")).default;
      break;
    default: {
      const unreachable: never = locale;
      throw new Error(`Unsupported locale: ${String(unreachable)}`);
    }
  }

  cache.set(locale, dictionary);
  return dictionary;
}
