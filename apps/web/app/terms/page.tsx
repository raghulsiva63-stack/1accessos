import type { Metadata } from "next";
import { LegalPage } from "@/components/legal/legal-page";
import { TERMS } from "@/lib/legal/content";

export const metadata: Metadata = {
  title: "Terms of Service — Passkey-X",
  description: "The terms for using Passkey-X, including accounts, plans, payments and acceptable use.",
};

export default function Page() {
  return <LegalPage document={TERMS} />;
}
