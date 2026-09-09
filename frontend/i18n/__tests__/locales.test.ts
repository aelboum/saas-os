import { describe, expect, it } from "vitest";
import { DEFAULT_LOCALE, FALLBACK_LOCALE, SUPPORTED_LOCALES, isSupportedLocale } from "../locales";

describe("locale registry", () => {
  it("accepts every supported locale", () => {
    for (const locale of SUPPORTED_LOCALES) {
      expect(isSupportedLocale(locale)).toBe(true);
    }
  });

  it("rejects an unsupported locale value", () => {
    expect(isSupportedLocale("xx")).toBe(false);
    expect(isSupportedLocale("de-DE")).toBe(false);
  });

  it("rejects null/undefined/empty without throwing", () => {
    expect(isSupportedLocale(null)).toBe(false);
    expect(isSupportedLocale(undefined)).toBe(false);
    expect(isSupportedLocale("")).toBe(false);
  });

  it("default and fallback locales are themselves supported", () => {
    expect(isSupportedLocale(DEFAULT_LOCALE)).toBe(true);
    expect(isSupportedLocale(FALLBACK_LOCALE)).toBe(true);
  });
});
