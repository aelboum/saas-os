import type { Dictionary } from "./types";

const fr = {
  common: {
    actions: {
      save: "Enregistrer",
      cancel: "Annuler",
    },
    loading: "Chargement…",
    error: {
      generic: "Une erreur est survenue.",
    },
  },
  a11y: {
    languageSwitcherLabel: "Choisir la langue",
  },
  home: {
    title: "SaaS OS",
    description: "Fondation frontend. Aucune interface produit encore implémentée.",
    greeting: "Bonjour, {{name}} !",
    itemCount_one: "{{count}} élément",
    itemCount_other: "{{count}} éléments",
    todayLabel: "Aujourd'hui, nous sommes le {{date}}",
    visitsLabel: "Vous avez {{count}} visites",
  },
} satisfies Dictionary;

export default fr;
