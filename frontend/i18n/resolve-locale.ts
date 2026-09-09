import { cookies, headers } from "next/headers";
import { DEFAULT_LOCALE, isSupportedLocale, type SupportedLocale } from "./locales";
import { LOCALE_COOKIE_NAME } from "./cookie";

/**
 * Parses an `Accept-Language` header down to a supported locale, or `null`
 * if none of the browser's preferences are supported. Only ever resolves to
 * a value already in SUPPORTED_LOCALES — an unsupported/malformed header
 * value can never become trusted application state (Phase 10.1 Security
 * Requirements).
 */
export function parseAcceptLanguage(header: string | null): SupportedLocale | null {
  if (!header) return null;

  const candidates = header
    .split(",")
    .map((part) => part.split(";")[0]?.trim().toLowerCase())
    .filter((value): value is string => Boolean(value));

  for (const candidate of candidates) {
    if (isSupportedLocale(candidate)) return candidate;
    const base = candidate.split("-")[0];
    if (isSupportedLocale(base)) return base;
  }
  return null;
}

/**
 * Deterministic server-side locale resolution order (Phase 10.1 Locale
 * Selection): validated persisted cookie -> negotiated Accept-Language ->
 * configured default. Each step is validated against SUPPORTED_LOCALES
 * before being trusted; nothing here can produce an unsupported locale.
 */
export async function resolveServerLocale(): Promise<SupportedLocale> {
  const cookieStore = await cookies();
  const cookieValue = cookieStore.get(LOCALE_COOKIE_NAME)?.value;
  if (isSupportedLocale(cookieValue)) {
    return cookieValue;
  }

  const headerStore = await headers();
  const negotiated = parseAcceptLanguage(headerStore.get("accept-language"));
  if (negotiated) {
    return negotiated;
  }

  return DEFAULT_LOCALE;
}
