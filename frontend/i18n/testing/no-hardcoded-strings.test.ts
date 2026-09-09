import { describe, expect, it } from "vitest";
import { readFileSync } from "node:fs";
import { join } from "node:path";
import { findHardcodedStrings } from "./no-hardcoded-strings";

describe("findHardcodedStrings", () => {
  it("is non-vacuous: a deliberately-introduced hard-coded string is caught", () => {
    const violatingSource = `
      export default function Example() {
        return <p>Hello World</p>;
      }
    `;
    expect(findHardcodedStrings(violatingSource)).toContain("Hello World");
  });

  it("does not flag text rendered entirely through a translation call", () => {
    const cleanSource = `
      export default function Example() {
        return <p>{t("home.title")}</p>;
      }
    `;
    expect(findHardcodedStrings(cleanSource)).toEqual([]);
  });

  it("does not flag whitespace-only or non-letter JSX text", () => {
    const source = `
      export default function Example() {
        return <p>  123  </p>;
      }
    `;
    expect(findHardcodedStrings(source)).toEqual([]);
  });
});

describe("localized application surfaces contain no hard-coded user-facing string", () => {
  const LOCALIZED_SURFACES = [
    join(__dirname, "..", "..", "app", "page.tsx"),
    join(__dirname, "..", "..", "components", "LanguageSwitcher.tsx"),
  ];

  it.each(LOCALIZED_SURFACES)("%s has no raw JSX text left un-translated", (filePath) => {
    const source = readFileSync(filePath, "utf-8");
    expect(findHardcodedStrings(source)).toEqual([]);
  });
});
