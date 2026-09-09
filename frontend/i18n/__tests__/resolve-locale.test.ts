import { beforeEach, describe, expect, it, vi } from "vitest";
import { DEFAULT_LOCALE } from "../locales";
import { LOCALE_COOKIE_NAME } from "../cookie";

const cookiesMock = vi.fn();
const headersMock = vi.fn();

vi.mock("next/headers", () => ({
  cookies: () => cookiesMock(),
  headers: () => headersMock(),
}));

const { parseAcceptLanguage, resolveServerLocale } = await import("../resolve-locale");

function fakeCookies(value?: string) {
  return {
    get: (name: string) => (name === LOCALE_COOKIE_NAME && value ? { value } : undefined),
  };
}

function fakeHeaders(acceptLanguage: string | null) {
  return { get: (name: string) => (name === "accept-language" ? acceptLanguage : null) };
}

describe("parseAcceptLanguage", () => {
  it("returns null for no header", () => {
    expect(parseAcceptLanguage(null)).toBeNull();
  });

  it("matches a supported locale from a weighted header", () => {
    expect(parseAcceptLanguage("fr-CA,fr;q=0.9,en;q=0.8")).toBe("fr");
  });

  it("falls back through base-language matching", () => {
    expect(parseAcceptLanguage("ar-EG")).toBe("ar");
  });

  it("returns null when nothing supported is present (never invents a locale)", () => {
    expect(parseAcceptLanguage("de-DE,ja;q=0.9")).toBeNull();
  });
});

describe("resolveServerLocale", () => {
  beforeEach(() => {
    cookiesMock.mockReset();
    headersMock.mockReset();
  });

  it("prefers a validated persisted cookie over Accept-Language", async () => {
    cookiesMock.mockReturnValue(fakeCookies("fr"));
    headersMock.mockReturnValue(fakeHeaders("ar"));
    await expect(resolveServerLocale()).resolves.toBe("fr");
  });

  it("rejects an unsupported persisted cookie value and falls through", async () => {
    cookiesMock.mockReturnValue(fakeCookies("xx-not-real"));
    headersMock.mockReturnValue(fakeHeaders("ar"));
    await expect(resolveServerLocale()).resolves.toBe("ar");
  });

  it("falls back to negotiated Accept-Language when no cookie is set", async () => {
    cookiesMock.mockReturnValue(fakeCookies());
    headersMock.mockReturnValue(fakeHeaders("fr-FR,en;q=0.5"));
    await expect(resolveServerLocale()).resolves.toBe("fr");
  });

  it("falls back to the default locale when nothing resolves", async () => {
    cookiesMock.mockReturnValue(fakeCookies());
    headersMock.mockReturnValue(fakeHeaders(null));
    await expect(resolveServerLocale()).resolves.toBe(DEFAULT_LOCALE);
  });
});
