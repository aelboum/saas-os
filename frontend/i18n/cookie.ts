// Locale preference is a UI-only setting, not session/auth state, so it is
// stored in a plain (non-httpOnly) cookie the client can read/write itself
// for instant switching — no new backend endpoint or session-storage change
// is introduced merely to persist it (Phase 10.1 Locale Selection scope).
export const LOCALE_COOKIE_NAME = "saas_os_locale";
export const LOCALE_COOKIE_MAX_AGE_SECONDS = 60 * 60 * 24 * 365;
