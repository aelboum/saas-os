// Canonical translation-resource shape. Every locale dictionary must satisfy
// this interface exactly (checked at compile time via `satisfies` in each
// locale file) so a locale can never silently ship with missing keys.
//
// Namespaced by feature area (common/a11y/home), not by component, so
// resources stay meaningful independent of where a component happens to
// live. `_one`/`_other` suffixed keys are plural-count variants selected via
// Intl.PluralRules (see ../translate.ts). This foundation covers the
// one/other categories every supported locale's current vocabulary needs;
// a locale requiring additional CLDR categories (zero/two/few/many) is a
// translate.ts lookup-fallback extension, not a Dictionary redesign —
// tPlural() already falls back to "_other" for any unmatched category.
export interface Dictionary {
  common: {
    actions: {
      save: string;
      cancel: string;
    };
    loading: string;
    error: {
      generic: string;
    };
  };
  a11y: {
    languageSwitcherLabel: string;
  };
  home: {
    title: string;
    description: string;
    greeting: string;
    itemCount_one: string;
    itemCount_other: string;
    todayLabel: string;
    visitsLabel: string;
  };
}

// Dot-path translation keys, e.g. "common.actions.save" or "home.greeting".
// Derived structurally so a typo in a call site is a type error, not a
// silent runtime miss.
type Join<K extends string, V> = V extends string
  ? K
  : V extends Record<string, unknown>
    ? { [P in keyof V & string]: Join<`${K}.${P}`, V[P]> }[keyof V & string]
    : never;

export type TranslationKey = {
  [K in keyof Dictionary & string]: Join<K, Dictionary[K]>;
}[keyof Dictionary & string];

// Keys usable with the plural-aware lookup (translate.ts's `tPlural`) are
// derived from every "<base>_other" key already present in the dictionary —
// one list, no separately maintained registry to fall out of sync.
type ExtractPluralBase<T> = T extends `${infer Base}_other` ? Base : never;
export type PluralTranslationKey = ExtractPluralBase<TranslationKey>;
