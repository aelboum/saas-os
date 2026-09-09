import { describe, expect, it } from "vitest";
import { formatDate, formatNumber } from "../format";

describe("formatDate", () => {
  it("is locale-aware (month name differs between locales)", () => {
    const date = new Date(Date.UTC(2026, 0, 15));
    const en = formatDate(date, "en", { month: "long", timeZone: "UTC" });
    const fr = formatDate(date, "fr", { month: "long", timeZone: "UTC" });
    expect(en).toBe("January");
    expect(fr).toBe("janvier");
    expect(en).not.toBe(fr);
  });
});

describe("formatNumber", () => {
  it("is locale-aware (decimal separator differs between locales)", () => {
    const en = formatNumber(1234.5, "en");
    const fr = formatNumber(1234.5, "fr");
    expect(en).toBe("1,234.5");
    // French uses a comma decimal separator and a non-breaking-space-family
    // group separator; assert the comma decimal marker specifically rather
    // than the exact (locale-data-version-sensitive) group separator glyph.
    expect(fr).toContain(",5");
    expect(en).not.toBe(fr);
  });
});
