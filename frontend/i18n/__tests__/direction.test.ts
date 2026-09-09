import { describe, expect, it } from "vitest";
import { getTextDirection } from "../direction";
import { SUPPORTED_LOCALES } from "../locales";

describe("getTextDirection", () => {
  it("resolves LTR locales to 'ltr'", () => {
    expect(getTextDirection("en")).toBe("ltr");
    expect(getTextDirection("fr")).toBe("ltr");
  });

  it("resolves the RTL locale to 'rtl'", () => {
    expect(getTextDirection("ar")).toBe("rtl");
  });

  it("every supported locale resolves to a valid direction", () => {
    for (const locale of SUPPORTED_LOCALES) {
      expect(["ltr", "rtl"]).toContain(getTextDirection(locale));
    }
  });
});
