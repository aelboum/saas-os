import type { Metadata } from "next";
import type { ReactNode } from "react";
import { resolveServerLocale } from "@/i18n/resolve-locale";
import { getDictionary } from "@/i18n/dictionaries";
import { getTextDirection } from "@/i18n/direction";
import { I18nProvider } from "@/i18n/context";

export const metadata: Metadata = {
  title: "SaaS OS",
  description: "SaaS OS platform foundation.",
};

export default async function RootLayout({ children }: { children: ReactNode }) {
  const locale = await resolveServerLocale();
  const dictionary = getDictionary(locale);
  const direction = getTextDirection(locale);

  return (
    <html lang={locale} dir={direction}>
      <body>
        <I18nProvider initialLocale={locale} initialDictionary={dictionary}>
          {children}
        </I18nProvider>
      </body>
    </html>
  );
}
