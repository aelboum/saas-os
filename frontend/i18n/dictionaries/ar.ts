import type { Dictionary } from "./types";

const ar = {
  common: {
    actions: {
      save: "حفظ",
      cancel: "إلغاء",
    },
    loading: "جارٍ التحميل…",
    error: {
      generic: "حدث خطأ ما.",
    },
  },
  a11y: {
    languageSwitcherLabel: "اختر اللغة",
  },
  home: {
    title: "SaaS OS",
    description: "أساس الواجهة الأمامية. لم يتم بعد تنفيذ واجهة منتج.",
    greeting: "مرحبًا، {{name}}!",
    itemCount_one: "عنصر واحد ({{count}})",
    itemCount_other: "{{count}} عناصر",
    todayLabel: "اليوم هو {{date}}",
    visitsLabel: "لديك {{count}} زيارة",
  },
} satisfies Dictionary;

export default ar;
