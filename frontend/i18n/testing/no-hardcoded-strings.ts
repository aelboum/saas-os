/**
 * Heuristic detector for raw (non-translated) literal text sitting directly
 * in JSX markup, e.g. `<p>Hello World</p>` instead of `<p>{t("key")}</p>`.
 *
 * Scope/limitation, deliberately: this looks for JSX text nodes that are
 * pure literal text between tags. It does not parse a full JSX AST, so
 * mixed literal+expression content (e.g. `<p>Hello {name}</p>`) is not
 * flagged — building a complete AST-based i18n lint rule is out of scope
 * for this phase (Phase 10.1 asks for a check proving the architecture,
 * not a production lint tool). Any text wrapped entirely in a `{...}`
 * expression (the pattern every component in this codebase uses to render
 * translated strings) is correctly never flagged.
 */
export function findHardcodedStrings(source: string): string[] {
  const JSX_TEXT_NODE = />([^<>{}]*[A-Za-z]{2,}[^<>{}]*)</g;
  const found: string[] = [];

  let match: RegExpExecArray | null;
  while ((match = JSX_TEXT_NODE.exec(source)) !== null) {
    const text = match[1].trim();
    if (text.length > 0) {
      found.push(text);
    }
  }
  return found;
}
