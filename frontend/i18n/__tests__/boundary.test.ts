import { describe, expect, it } from "vitest";
import { readFileSync } from "node:fs";
import { join } from "node:path";

// Non-vacuous architecture-boundary check for Phase 10.1 §10: the i18n
// foundation must stay frontend-owned, with translation resources and
// utilities carrying no dependency on Core, Infrastructure, the AI Control
// Plane, a database driver, Redis, or an AI/LLM provider SDK. This is a
// static-source check (not a runtime one) precisely because none of these
// modules should ever import such a thing in the first place -- there is
// nothing to sandbox against at runtime.
const I18N_DIR = join(__dirname, "..");

const FORBIDDEN_IMPORT_PATTERNS: RegExp[] = [
  /from\s+["']@?core/,
  /from\s+["']@?infra/,
  /from\s+["']@?control-plane/,
  /from\s+["'](pg|postgres|mysql2|mongodb)["']/,
  /from\s+["']ioredis["']/,
  /from\s+["'](openai|@anthropic-ai|langchain)/,
];

const FILES_TO_CHECK = [
  "locales.ts",
  "direction.ts",
  "translate.ts",
  "format.ts",
  "cookie.ts",
  "resolve-locale.ts",
  "context.tsx",
  "dictionaries/types.ts",
  "dictionaries/en.ts",
  "dictionaries/fr.ts",
  "dictionaries/ar.ts",
  "dictionaries/index.ts",
  "dictionaries/load.ts",
];

describe("i18n frontend-ownership boundary", () => {
  it.each(FILES_TO_CHECK)("%s imports nothing outside the frontend i18n boundary", (relativePath) => {
    const source = readFileSync(join(I18N_DIR, relativePath), "utf-8");
    for (const pattern of FORBIDDEN_IMPORT_PATTERNS) {
      expect(source).not.toMatch(pattern);
    }
  });

  it("the check itself is non-vacuous: a forbidden import is actually caught", () => {
    const violatingSource = 'import { pool } from "infra/db";\nexport const x = 1;\n';
    const isCaught = FORBIDDEN_IMPORT_PATTERNS.some((pattern) => pattern.test(violatingSource));
    expect(isCaught).toBe(true);
  });

  it("translation resources (dictionaries) contain no secret-shaped values", () => {
    for (const dict of ["dictionaries/en.ts", "dictionaries/fr.ts", "dictionaries/ar.ts"]) {
      const source = readFileSync(join(I18N_DIR, dict), "utf-8");
      expect(source).not.toMatch(/(api[_-]?key|secret|password|token)\s*[:=]/i);
    }
  });
});
