import { describe, expect, it, vi } from "vitest";
import { interpolate, t, tPlural } from "../translate";
import en from "../dictionaries/en";
import fr from "../dictionaries/fr";
import ar from "../dictionaries/ar";
import type { Dictionary } from "../dictionaries/types";
import type { TranslationKey } from "../dictionaries/types";

describe("interpolate", () => {
  it("substitutes parameters", () => {
    expect(interpolate("Hello, {{name}}!", { name: "Ada" })).toBe("Hello, Ada!");
  });

  it("leaves an unmatched token untouched rather than throwing", () => {
    expect(interpolate("Hello, {{name}}!")).toBe("Hello, {{name}}!");
  });
});

describe("t", () => {
  it("resolves a known nested key", () => {
    expect(t(en, en, "common.actions.save")).toBe("Save");
  });

  it("resolves and interpolates a parameterized key", () => {
    expect(t(en, en, "home.greeting", { name: "Ada" })).toBe("Hello, Ada!");
  });

  it("falls back to the fallback dictionary when the active dictionary is missing a key", () => {
    const incomplete = { ...fr, home: { ...fr.home } } as Dictionary;
    // Simulate a locale dictionary that hasn't caught up with a new key yet.
    // @ts-expect-error deliberately constructing an incomplete dictionary for the test
    delete incomplete.home.title;
    expect(t(incomplete, en, "home.title")).toBe(en.home.title);
  });

  it("falls back to the raw key, without throwing, when no dictionary has it", () => {
    const warnSpy = vi.spyOn(console, "warn").mockImplementation(() => {});
    expect(t(en, en, "nonexistent.key" as TranslationKey)).toBe("nonexistent.key");
    warnSpy.mockRestore();
  });

  it("warns (dev-only) on a missing key rather than failing silently or crashing", () => {
    const warnSpy = vi.spyOn(console, "warn").mockImplementation(() => {});
    t(en, en, "nonexistent.key" as TranslationKey);
    expect(warnSpy).toHaveBeenCalledTimes(1);
    warnSpy.mockRestore();
  });
});

describe("tPlural", () => {
  it("selects the 'one' category for count === 1 in English", () => {
    expect(tPlural(en, en, "home.itemCount", 1, "en")).toBe("1 item");
  });

  it("selects the 'other' category for count > 1 in English", () => {
    expect(tPlural(en, en, "home.itemCount", 3, "en")).toBe("3 items");
  });

  it("uses the target locale's own plural strings", () => {
    expect(tPlural(fr, en, "home.itemCount", 1, "fr")).toBe("1 élément");
  });

  it("falls back to '_other' for a CLDR category the dictionary has no dedicated variant for", () => {
    // Arabic's plural rules include "few"/"many"/"zero"/"two" categories that
    // this foundation's dictionaries don't define dedicated strings for;
    // tPlural must still return the "_other" string deterministically
    // rather than an undefined/blank result.
    expect(tPlural(ar, en, "home.itemCount", 11, "ar")).toBe(ar.home.itemCount_other.replace("{{count}}", "11"));
  });
});
