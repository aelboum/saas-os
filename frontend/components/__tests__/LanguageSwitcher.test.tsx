import { describe, expect, it, vi } from "vitest";
import { render, screen, fireEvent, waitFor } from "@testing-library/react";
import { LanguageSwitcher } from "../LanguageSwitcher";
import { I18nProvider } from "@/i18n/context";
import en from "@/i18n/dictionaries/en";

const refresh = vi.fn();
vi.mock("next/navigation", () => ({
  useRouter: () => ({ refresh }),
}));

function renderSwitcher() {
  return render(
    <I18nProvider initialLocale="en" initialDictionary={en}>
      <LanguageSwitcher />
    </I18nProvider>,
  );
}

describe("LanguageSwitcher", () => {
  it("is a real, keyboard-operable form control with an accessible name", () => {
    renderSwitcher();
    const select = screen.getByRole("combobox", { name: "Choose language" });
    expect(select.tagName).toBe("SELECT");
    expect(select.hasAttribute("disabled")).toBe(false);
    expect((select as HTMLSelectElement).tabIndex).not.toBe(-1);
  });

  it("offers only supported locales as options", () => {
    renderSwitcher();
    const options = screen.getAllByRole("option").map((option) => (option as HTMLOptionElement).value);
    expect(options).toEqual(["en", "fr", "ar"]);
  });

  it("switches locale on selection and reflects it back as the select's value", async () => {
    renderSwitcher();
    const select = screen.getByRole("combobox", { name: "Choose language" }) as HTMLSelectElement;

    fireEvent.change(select, { target: { value: "fr" } });

    await waitFor(() => {
      expect(screen.getByRole("combobox", { name: "Choisir la langue" })).toBeTruthy();
    });
    expect((screen.getByRole("combobox") as HTMLSelectElement).value).toBe("fr");
  });

  it("persists the choice in a client-readable cookie and refreshes server data, not a full reload", async () => {
    renderSwitcher();
    const select = screen.getByRole("combobox") as HTMLSelectElement;

    fireEvent.change(select, { target: { value: "ar" } });

    await waitFor(() => {
      expect(document.cookie).toContain("saas_os_locale=ar");
    });
    expect(refresh).toHaveBeenCalled();
  });
});
