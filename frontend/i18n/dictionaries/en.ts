import type { Dictionary } from "./types";

const en = {
  common: {
    actions: {
      save: "Save",
      cancel: "Cancel",
    },
    loading: "Loading…",
    error: {
      generic: "Something went wrong.",
    },
  },
  a11y: {
    languageSwitcherLabel: "Choose language",
  },
  home: {
    title: "SaaS OS",
    description: "Frontend foundation. No product UI implemented yet.",
    greeting: "Hello, {{name}}!",
    itemCount_one: "{{count}} item",
    itemCount_other: "{{count}} items",
    todayLabel: "Today is {{date}}",
    visitsLabel: "You have {{count}} visits",
  },
} satisfies Dictionary;

export default en;
