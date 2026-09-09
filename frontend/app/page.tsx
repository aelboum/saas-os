"use client";

// Placeholder foundation page, now the proof surface for the frontend i18n
// foundation (docs/IMPLEMENTATION-ROADMAP.md Phase 10.1). Still no product,
// dashboard, auth, billing, or tenant UI implemented.
import { useI18n } from "@/i18n/context";
import { LanguageSwitcher } from "@/components/LanguageSwitcher";

export default function Home() {
  const { t, tPlural, formatDate, formatNumber, locale } = useI18n();

  return (
    <main>
      <h1>{t("home.title")}</h1>
      <p>{t("home.description")}</p>
      <p>{t("home.greeting", { name: "Ada" })}</p>
      <p>{tPlural("home.itemCount", 3)}</p>
      <p>{t("home.todayLabel", { date: formatDate(new Date(2026, 0, 1), { dateStyle: "long" }) })}</p>
      <p>{t("home.visitsLabel", { count: formatNumber(1234) })}</p>
      <p aria-live="polite">{locale}</p>
      <LanguageSwitcher />
    </main>
  );
}
